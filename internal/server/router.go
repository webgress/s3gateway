package server

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/webgress/s3gateway/internal/auth"
	"github.com/webgress/s3gateway/internal/handler"
	"github.com/webgress/s3gateway/internal/s3response"
	"github.com/webgress/s3gateway/internal/storage"
)

func (s *Server) newRouter() *mux.Router {
	r := mux.NewRouter()

	fs := storage.NewFilesystem(s.cfg.DataDir)

	bucketH := handler.NewBucketHandler(fs)
	objectH := handler.NewObjectHandler(fs, s.cfg.Credentials)
	listH := handler.NewListHandler(fs)
	multipartH := handler.NewMultipartHandler(fs)

	// Middleware
	r.Use(s.loggingMiddleware)
	r.Use(s.commonHeadersMiddleware)
	r.Use(s.authMiddleware)

	// Health check (no auth)
	r.HandleFunc("/healthz", s.healthCheck).Methods(http.MethodGet)

	// Route registration order is CRITICAL — see CLAUDE.md
	// Multipart query-parameterized routes MUST come before plain object routes

	objectPath := "/{bucket}/{object:(?s).+}"

	// 1. UploadPart: PUT /{bucket}/{object}?partNumber=N&uploadId=X
	r.HandleFunc(objectPath, multipartH.UploadPart).
		Methods(http.MethodPut).
		Queries("partNumber", "{partNumber}", "uploadId", "{uploadId}")

	// 2. CompleteMultipart: POST /{bucket}/{object}?uploadId=X
	r.HandleFunc(objectPath, multipartH.CompleteMultipartUpload).
		Methods(http.MethodPost).
		Queries("uploadId", "{uploadId}")

	// 3. CreateMultipart: POST /{bucket}/{object}?uploads
	r.HandleFunc(objectPath, multipartH.CreateMultipartUpload).
		Methods(http.MethodPost).
		Queries("uploads", "")

	// 4. AbortMultipart: DELETE /{bucket}/{object}?uploadId=X
	r.HandleFunc(objectPath, multipartH.AbortMultipartUpload).
		Methods(http.MethodDelete).
		Queries("uploadId", "{uploadId}")

	// 5. ListParts: GET /{bucket}/{object}?uploadId=X
	r.HandleFunc(objectPath, multipartH.ListParts).
		Methods(http.MethodGet).
		Queries("uploadId", "{uploadId}")

	// 6. ListMultipartUploads: GET /{bucket}?uploads
	r.HandleFunc("/{bucket}", multipartH.ListMultipartUploads).
		Methods(http.MethodGet).
		Queries("uploads", "")

	// 7. HeadObject: HEAD /{bucket}/{object}
	r.HandleFunc(objectPath, objectH.HeadObject).
		Methods(http.MethodHead)

	// 8. GetObject: GET /{bucket}/{object}
	r.HandleFunc(objectPath, objectH.GetObject).
		Methods(http.MethodGet)

	// 9. PutObject: PUT /{bucket}/{object}
	r.HandleFunc(objectPath, objectH.PutObject).
		Methods(http.MethodPut)

	// 10. DeleteObject: DELETE /{bucket}/{object}
	r.HandleFunc(objectPath, objectH.DeleteObject).
		Methods(http.MethodDelete)

	// 11. ListObjectsV2: GET /{bucket}
	r.HandleFunc("/{bucket}", listH.ListObjectsV2).
		Methods(http.MethodGet)

	// 12. HeadBucket: HEAD /{bucket}
	r.HandleFunc("/{bucket}", bucketH.HeadBucket).
		Methods(http.MethodHead)

	// 13. CreateBucket: PUT /{bucket}
	r.HandleFunc("/{bucket}", bucketH.CreateBucket).
		Methods(http.MethodPut)

	// 14. DeleteBucket: DELETE /{bucket}
	r.HandleFunc("/{bucket}", bucketH.DeleteBucket).
		Methods(http.MethodDelete)

	// 15. ListBuckets: GET /
	r.HandleFunc("/", bucketH.ListBuckets).
		Methods(http.MethodGet)

	return r
}

func (s *Server) healthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		duration := time.Since(start)

		slog.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"query", r.URL.RawQuery,
			"status", sw.status,
			"duration_ms", duration.Milliseconds(),
			"remote_addr", r.RemoteAddr,
			"content_length", r.ContentLength,
		)
	})
}

func (s *Server) commonHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("x-amz-request-id", uuid.New().String())
		w.Header().Set("Server", "S3Gateway")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip auth for health check
		if r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}

		// Check if request has auth
		authHeader := r.Header.Get("Authorization")
		hasPresigned := r.URL.Query().Get("X-Amz-Algorithm") != ""

		if authHeader == "" && !hasPresigned {
			// No auth provided — reject
			s3response.WriteError(w, r, s3response.ErrAccessDenied)
			return
		}

		// For streaming uploads, we verify the seed signature
		contentSHA256 := r.Header.Get("X-Amz-Content-Sha256")
		if contentSHA256 == auth.StreamingPayload {
			// Verify seed signature
			_, _, err := auth.ComputeSeedSignature(r, s.cfg.Credentials, s.cfg.Region)
			if err != nil {
				if strings.Contains(err.Error(), "invalid access key") {
					s3response.WriteError(w, r, s3response.ErrInvalidAccessKeyID)
				} else if strings.Contains(err.Error(), "signature does not match") {
					s3response.WriteError(w, r, s3response.ErrSignatureDoesNotMatch)
				} else if strings.Contains(err.Error(), "skewed") {
					s3response.WriteError(w, r, s3response.ErrRequestTimeTooSkewed)
				} else {
					s3response.WriteError(w, r, s3response.ErrAccessDenied)
				}
				return
			}
			next.ServeHTTP(w, r)
			return
		}

		// Regular auth verification
		_, err := auth.VerifyRequest(r, s.cfg.Credentials, s.cfg.Region)
		if err != nil {
			if strings.Contains(err.Error(), "invalid access key") {
				s3response.WriteError(w, r, s3response.ErrInvalidAccessKeyID)
			} else if strings.Contains(err.Error(), "signature does not match") {
				s3response.WriteError(w, r, s3response.ErrSignatureDoesNotMatch)
			} else if strings.Contains(err.Error(), "skewed") {
				s3response.WriteError(w, r, s3response.ErrRequestTimeTooSkewed)
			} else {
				s3response.WriteError(w, r, s3response.ErrAccessDenied)
			}
			return
		}

		next.ServeHTTP(w, r)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

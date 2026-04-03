package handler

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
	"github.com/webgress/s3gateway/internal/auth"
	"github.com/webgress/s3gateway/internal/s3response"
	"github.com/webgress/s3gateway/internal/storage"
)

type ObjectHandler struct {
	fs    *storage.Filesystem
	creds *auth.CredentialStore
}

func NewObjectHandler(fs *storage.Filesystem, creds *auth.CredentialStore) *ObjectHandler {
	return &ObjectHandler{fs: fs, creds: creds}
}

func (h *ObjectHandler) PutObject(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	key := vars["object"]

	// Check bucket exists
	if err := h.fs.HeadBucket(bucket); err != nil {
		if err == storage.ErrBucketNotFound {
			s3response.WriteError(w, r, s3response.ErrNoSuchBucket)
			return
		}
		s3response.WriteError(w, r, s3response.ErrInternalError)
		return
	}

	// Determine body reader — handle chunked transfer encoding
	var body io.Reader = r.Body
	contentSHA256 := r.Header.Get("X-Amz-Content-Sha256")
	if contentSHA256 == auth.StreamingPayload {
		// AWS chunked transfer encoding
		decodedLenStr := r.Header.Get("X-Amz-Decoded-Content-Length")
		if decodedLenStr != "" {
			// Use chunked reader to decode
			body = auth.NewChunkedReader(r.Body, "", "", "us-east-1", "s3", "")
		}
	}

	contentType := r.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	// Collect user metadata
	userMeta := make(map[string]string)
	for k, v := range r.Header {
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, "x-amz-meta-") && len(v) > 0 {
			userMeta[lk] = v[0]
		}
	}

	etag, err := h.fs.PutObject(bucket, key, body, contentType, userMeta)
	if err != nil {
		switch err {
		case storage.ErrBucketNotFound:
			s3response.WriteError(w, r, s3response.ErrNoSuchBucket)
		case storage.ErrPathTraversal:
			s3response.WriteError(w, r, s3response.ErrInvalidArgument)
		default:
			s3response.WriteError(w, r, s3response.ErrInternalError)
		}
		return
	}

	w.Header().Set("ETag", etag)
	w.WriteHeader(http.StatusOK)
}

func (h *ObjectHandler) GetObject(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	key := vars["object"]

	result, err := h.fs.GetObject(bucket, key)
	if err != nil {
		switch err {
		case storage.ErrObjectNotFound:
			s3response.WriteError(w, r, s3response.ErrNoSuchKey)
		case storage.ErrBucketNotFound:
			s3response.WriteError(w, r, s3response.ErrNoSuchBucket)
		case storage.ErrPathTraversal:
			s3response.WriteError(w, r, s3response.ErrInvalidArgument)
		default:
			s3response.WriteError(w, r, s3response.ErrInternalError)
		}
		return
	}
	defer result.Body.Close()

	meta := result.Metadata
	w.Header().Set("Content-Type", meta.ContentType)
	w.Header().Set("Content-Length", strconv.FormatInt(meta.ContentLength, 10))
	w.Header().Set("ETag", meta.ETag)
	w.Header().Set("Last-Modified", meta.LastModified.UTC().Format(http.TimeFormat))

	// Set user metadata headers — use direct map assignment to preserve lowercase
	for k, v := range meta.UserMetadata {
		w.Header()[http.CanonicalHeaderKey(k)] = []string{v}
	}
	if meta.ContentDisposition != "" {
		w.Header().Set("Content-Disposition", meta.ContentDisposition)
	}
	if meta.ContentEncoding != "" {
		w.Header().Set("Content-Encoding", meta.ContentEncoding)
	}
	if meta.CacheControl != "" {
		w.Header().Set("Cache-Control", meta.CacheControl)
	}

	w.Header().Set("Accept-Ranges", "bytes")

	// Handle Range requests
	rangeHeader := r.Header.Get("Range")
	if rangeHeader != "" {
		if seeker, ok := result.Body.(io.ReadSeeker); ok {
			h.handleRangeRequest(w, seeker, meta.ContentLength, rangeHeader)
			return
		}
	}

	w.WriteHeader(http.StatusOK)
	io.Copy(w, result.Body)
}

func (h *ObjectHandler) handleRangeRequest(w http.ResponseWriter, body io.ReadSeeker, totalSize int64, rangeHeader string) {
	// Parse "bytes=start-end"
	if !strings.HasPrefix(rangeHeader, "bytes=") {
		w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
		return
	}
	rangeSpec := strings.TrimPrefix(rangeHeader, "bytes=")
	parts := strings.SplitN(rangeSpec, "-", 2)
	if len(parts) != 2 {
		w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
		return
	}

	var start, end int64

	if parts[0] == "" {
		// Suffix range: -500 means last 500 bytes
		suffix, err := strconv.ParseInt(parts[1], 10, 64)
		if err != nil || suffix <= 0 {
			w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
			return
		}
		start = totalSize - suffix
		if start < 0 {
			start = 0
		}
		end = totalSize - 1
	} else {
		var err error
		start, err = strconv.ParseInt(parts[0], 10, 64)
		if err != nil {
			w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
			return
		}
		if parts[1] == "" {
			end = totalSize - 1
		} else {
			end, err = strconv.ParseInt(parts[1], 10, 64)
			if err != nil {
				w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
				return
			}
		}
	}

	if start > end || start >= totalSize {
		w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
		return
	}
	if end >= totalSize {
		end = totalSize - 1
	}

	if seeker, ok := body.(io.Seeker); ok {
		seeker.Seek(start, io.SeekStart)
	}

	length := end - start + 1
	w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, totalSize))
	w.Header().Set("Content-Length", strconv.FormatInt(length, 10))
	w.Header().Set("Accept-Ranges", "bytes")
	w.WriteHeader(http.StatusPartialContent)
	io.CopyN(w, body, length)
}

func (h *ObjectHandler) HeadObject(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	key := vars["object"]

	meta, err := h.fs.HeadObject(bucket, key)
	if err != nil {
		switch err {
		case storage.ErrObjectNotFound:
			w.WriteHeader(http.StatusNotFound)
		case storage.ErrBucketNotFound:
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Content-Type", meta.ContentType)
	w.Header().Set("Content-Length", strconv.FormatInt(meta.ContentLength, 10))
	w.Header().Set("ETag", meta.ETag)
	w.Header().Set("Last-Modified", meta.LastModified.UTC().Format(http.TimeFormat))
	w.Header().Set("Accept-Ranges", "bytes")

	for k, v := range meta.UserMetadata {
		w.Header().Set(k, v)
	}

	w.WriteHeader(http.StatusOK)
}

func (h *ObjectHandler) DeleteObject(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	key := vars["object"]

	h.fs.DeleteObject(bucket, key)
	w.WriteHeader(http.StatusNoContent)
}

package handler

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/webgress/s3gateway/internal/s3response"
	"github.com/webgress/s3gateway/internal/storage"
)

type BucketHandler struct {
	fs *storage.Filesystem
}

func NewBucketHandler(fs *storage.Filesystem) *BucketHandler {
	return &BucketHandler{fs: fs}
}

func (h *BucketHandler) CreateBucket(w http.ResponseWriter, r *http.Request) {
	bucket := mux.Vars(r)["bucket"]

	err := h.fs.CreateBucket(bucket)
	if err != nil {
		switch err {
		case storage.ErrBucketExists:
			s3response.WriteError(w, r, s3response.ErrBucketAlreadyOwnedByYou)
		case storage.ErrInvalidBucket:
			s3response.WriteError(w, r, s3response.ErrInvalidBucketName)
		default:
			s3response.WriteError(w, r, s3response.ErrInternalError)
		}
		return
	}

	w.Header().Set("Location", "/"+bucket)
	w.WriteHeader(http.StatusOK)
}

func (h *BucketHandler) HeadBucket(w http.ResponseWriter, r *http.Request) {
	bucket := mux.Vars(r)["bucket"]

	err := h.fs.HeadBucket(bucket)
	if err != nil {
		if err == storage.ErrBucketNotFound {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *BucketHandler) DeleteBucket(w http.ResponseWriter, r *http.Request) {
	bucket := mux.Vars(r)["bucket"]

	err := h.fs.DeleteBucket(bucket)
	if err != nil {
		switch err {
		case storage.ErrBucketNotFound:
			s3response.WriteError(w, r, s3response.ErrNoSuchBucket)
		case storage.ErrBucketNotEmpty:
			s3response.WriteError(w, r, s3response.ErrBucketNotEmpty)
		default:
			s3response.WriteError(w, r, s3response.ErrInternalError)
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *BucketHandler) ListBuckets(w http.ResponseWriter, r *http.Request) {
	buckets, err := h.fs.ListBuckets()
	if err != nil {
		s3response.WriteError(w, r, s3response.ErrInternalError)
		return
	}

	result := s3response.ListAllMyBucketsResult{
		Owner: s3response.Owner{ID: "s3gateway", DisplayName: "s3gateway"},
	}
	for _, b := range buckets {
		result.Buckets.Bucket = append(result.Buckets.Bucket, s3response.BucketEntry{
			Name:         b.Name,
			CreationDate: s3response.FormatTime(b.CreationDate),
		})
	}

	s3response.WriteXML(w, http.StatusOK, result)
}

package handler

import (
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/webgress/s3gateway/internal/s3response"
	"github.com/webgress/s3gateway/internal/storage"
)

type ListHandler struct {
	fs *storage.Filesystem
}

func NewListHandler(fs *storage.Filesystem) *ListHandler {
	return &ListHandler{fs: fs}
}

func (h *ListHandler) ListObjectsV2(w http.ResponseWriter, r *http.Request) {
	bucket := mux.Vars(r)["bucket"]

	// Check bucket exists
	if err := h.fs.HeadBucket(bucket); err != nil {
		if err == storage.ErrBucketNotFound {
			s3response.WriteError(w, r, s3response.ErrNoSuchBucket)
			return
		}
		s3response.WriteError(w, r, s3response.ErrInternalError)
		return
	}

	prefix := r.URL.Query().Get("prefix")
	delimiter := r.URL.Query().Get("delimiter")
	startAfter := r.URL.Query().Get("start-after")
	continuationToken := r.URL.Query().Get("continuation-token")

	maxKeys := 1000
	if mk := r.URL.Query().Get("max-keys"); mk != "" {
		v, err := strconv.Atoi(mk)
		if err == nil && v >= 0 {
			maxKeys = v
		}
	}

	input := storage.ListObjectsInput{
		Bucket:            bucket,
		Prefix:            prefix,
		Delimiter:         delimiter,
		MaxKeys:           maxKeys,
		StartAfter:        startAfter,
		ContinuationToken: continuationToken,
	}

	output, err := h.fs.ListObjects(input)
	if err != nil {
		s3response.WriteError(w, r, s3response.ErrInternalError)
		return
	}

	result := s3response.ListBucketResultV2{
		Name:                  bucket,
		Prefix:                prefix,
		Delimiter:             delimiter,
		MaxKeys:               maxKeys,
		IsTruncated:           output.IsTruncated,
		KeyCount:              len(output.Objects) + len(output.CommonPrefixes),
		StartAfter:            startAfter,
		ContinuationToken:     continuationToken,
		NextContinuationToken: output.NextContinuationToken,
	}

	for _, obj := range output.Objects {
		result.Contents = append(result.Contents, s3response.ObjectEntry{
			Key:          obj.Key,
			LastModified: s3response.FormatTime(obj.LastModified),
			ETag:         obj.ETag,
			Size:         obj.Size,
			StorageClass: "STANDARD",
		})
	}

	for _, p := range output.CommonPrefixes {
		result.CommonPrefixes = append(result.CommonPrefixes, s3response.CommonPrefix{
			Prefix: p,
		})
	}

	s3response.WriteXML(w, http.StatusOK, result)
}

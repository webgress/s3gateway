package handler

import (
	"encoding/xml"
	"io"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/webgress/s3gateway/internal/s3response"
	"github.com/webgress/s3gateway/internal/storage"
)

type MultipartHandler struct {
	fs *storage.Filesystem
}

func NewMultipartHandler(fs *storage.Filesystem) *MultipartHandler {
	return &MultipartHandler{fs: fs}
}

func (h *MultipartHandler) CreateMultipartUpload(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	key := vars["object"]

	contentType := r.Header.Get("Content-Type")

	uploadID, err := h.fs.CreateMultipartUpload(bucket, key, contentType)
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

	result := s3response.InitiateMultipartUploadResult{
		Bucket:   bucket,
		Key:      key,
		UploadId: uploadID,
	}
	s3response.WriteXML(w, http.StatusOK, result)
}

func (h *MultipartHandler) UploadPart(w http.ResponseWriter, r *http.Request) {
	uploadID := r.URL.Query().Get("uploadId")
	partNumberStr := r.URL.Query().Get("partNumber")

	partNumber, err := strconv.Atoi(partNumberStr)
	if err != nil || partNumber < 1 {
		s3response.WriteError(w, r, s3response.ErrInvalidArgument)
		return
	}

	etag, err := h.fs.UploadPart(uploadID, partNumber, r.Body)
	if err != nil {
		if err == storage.ErrNoSuchUpload {
			s3response.WriteError(w, r, s3response.ErrNoSuchUpload)
			return
		}
		s3response.WriteError(w, r, s3response.ErrInternalError)
		return
	}

	w.Header().Set("ETag", etag)
	w.WriteHeader(http.StatusOK)
}

func (h *MultipartHandler) CompleteMultipartUpload(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	key := vars["object"]
	uploadID := r.URL.Query().Get("uploadId")

	body, err := io.ReadAll(r.Body)
	if err != nil {
		s3response.WriteError(w, r, s3response.ErrInternalError)
		return
	}

	var req s3response.CompleteMultipartUpload
	if err := xml.Unmarshal(body, &req); err != nil {
		s3response.WriteError(w, r, s3response.ErrMalformedXML)
		return
	}

	var parts []storage.CompletePart
	for _, p := range req.Parts {
		parts = append(parts, storage.CompletePart{
			PartNumber: p.PartNumber,
			ETag:       p.ETag,
		})
	}

	etag, err := h.fs.CompleteMultipartUpload(uploadID, parts)
	if err != nil {
		switch err {
		case storage.ErrNoSuchUpload:
			s3response.WriteError(w, r, s3response.ErrNoSuchUpload)
		case storage.ErrInvalidPartOrder:
			s3response.WriteError(w, r, s3response.ErrInvalidPartOrder)
		case storage.ErrInvalidPart:
			s3response.WriteError(w, r, s3response.ErrInvalidPart)
		default:
			s3response.WriteError(w, r, s3response.ErrInternalError)
		}
		return
	}

	result := s3response.CompleteMultipartUploadResult{
		Bucket: bucket,
		Key:    key,
		ETag:   etag,
	}
	s3response.WriteXML(w, http.StatusOK, result)
}

func (h *MultipartHandler) AbortMultipartUpload(w http.ResponseWriter, r *http.Request) {
	uploadID := r.URL.Query().Get("uploadId")

	err := h.fs.AbortMultipartUpload(uploadID)
	if err != nil {
		if err == storage.ErrNoSuchUpload {
			s3response.WriteError(w, r, s3response.ErrNoSuchUpload)
			return
		}
		s3response.WriteError(w, r, s3response.ErrInternalError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *MultipartHandler) ListMultipartUploads(w http.ResponseWriter, r *http.Request) {
	bucket := mux.Vars(r)["bucket"]

	uploads, err := h.fs.ListMultipartUploads(bucket)
	if err != nil {
		s3response.WriteError(w, r, s3response.ErrInternalError)
		return
	}

	result := s3response.ListMultipartUploadsResult{
		Bucket:     bucket,
		MaxUploads: 1000,
	}
	for _, u := range uploads {
		result.Uploads = append(result.Uploads, s3response.UploadEntry{
			Key:       u.Key,
			UploadId:  u.UploadID,
			Initiated: s3response.FormatTime(u.Initiated),
		})
	}

	s3response.WriteXML(w, http.StatusOK, result)
}

func (h *MultipartHandler) ListParts(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	key := vars["object"]
	uploadID := r.URL.Query().Get("uploadId")

	parts, err := h.fs.ListParts(uploadID)
	if err != nil {
		if err == storage.ErrNoSuchUpload {
			s3response.WriteError(w, r, s3response.ErrNoSuchUpload)
			return
		}
		s3response.WriteError(w, r, s3response.ErrInternalError)
		return
	}

	result := s3response.ListPartsResult{
		Bucket:   bucket,
		Key:      key,
		UploadId: uploadID,
	}
	for _, p := range parts {
		result.Parts = append(result.Parts, s3response.PartEntry{
			PartNumber: p.PartNumber,
			ETag:       p.ETag,
			Size:       p.Size,
		})
	}

	s3response.WriteXML(w, http.StatusOK, result)
}

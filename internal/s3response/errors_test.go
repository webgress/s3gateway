package s3response

import (
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAllErrorCodesHaveHTTPStatus(t *testing.T) {
	codes := []ErrorCode{
		ErrAccessDenied, ErrBucketAlreadyExists, ErrBucketAlreadyOwnedByYou,
		ErrBucketNotEmpty, ErrInternalError, ErrInvalidBucketName,
		ErrInvalidPart, ErrInvalidPartOrder, ErrMalformedXML,
		ErrNoSuchBucket, ErrNoSuchKey, ErrNoSuchUpload,
		ErrSignatureDoesNotMatch, ErrRequestTimeTooSkewed, ErrInvalidAccessKeyID,
		ErrMissingFields, ErrMethodNotAllowed, ErrInvalidArgument,
	}
	for _, code := range codes {
		apiErr := GetAPIError(code)
		if apiErr.HTTPStatusCode == 0 {
			t.Errorf("error code %d has no HTTP status", code)
		}
		if apiErr.Code == "" {
			t.Errorf("error code %d has no error code string", code)
		}
	}
}

func TestStatusCodes(t *testing.T) {
	tests := []struct {
		code   ErrorCode
		status int
	}{
		{ErrAccessDenied, http.StatusForbidden},
		{ErrBucketNotEmpty, http.StatusConflict},
		{ErrNoSuchBucket, http.StatusNotFound},
		{ErrNoSuchKey, http.StatusNotFound},
		{ErrNoSuchUpload, http.StatusNotFound},
		{ErrInternalError, http.StatusInternalServerError},
		{ErrInvalidBucketName, http.StatusBadRequest},
		{ErrBucketAlreadyExists, http.StatusConflict},
		{ErrSignatureDoesNotMatch, http.StatusForbidden},
		{ErrInvalidPartOrder, http.StatusBadRequest},
		{ErrMethodNotAllowed, http.StatusMethodNotAllowed},
	}
	for _, tt := range tests {
		apiErr := GetAPIError(tt.code)
		if apiErr.HTTPStatusCode != tt.status {
			t.Errorf("error %d: status = %d, want %d", tt.code, apiErr.HTTPStatusCode, tt.status)
		}
	}
}

func TestErrorXMLNoNamespace(t *testing.T) {
	errResp := S3ErrorResponse{
		Code:      "NoSuchKey",
		Message:   "The specified key does not exist.",
		Resource:  "/bucket/key",
		RequestID: "test-id",
	}

	data, err := xml.Marshal(errResp)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	xmlStr := string(data)
	// Error element should NOT have a namespace
	if strings.Contains(xmlStr, "xmlns") {
		t.Errorf("Error XML should not have namespace: %s", xmlStr)
	}
	if !strings.Contains(xmlStr, "<Error>") {
		t.Errorf("should contain <Error>: %s", xmlStr)
	}
	if !strings.Contains(xmlStr, "<Code>NoSuchKey</Code>") {
		t.Errorf("should contain Code: %s", xmlStr)
	}
}

func TestListAllMyBucketsResultXML(t *testing.T) {
	result := ListAllMyBucketsResult{
		Owner: Owner{ID: "owner-id", DisplayName: "owner"},
		Buckets: Buckets{
			Bucket: []BucketEntry{
				{Name: "bucket1", CreationDate: "2024-01-01T00:00:00Z"},
			},
		},
	}

	data, err := xml.Marshal(result)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	xmlStr := string(data)
	if !strings.Contains(xmlStr, "http://s3.amazonaws.com/doc/2006-03-01/") {
		t.Errorf("ListAllMyBucketsResult should have S3 namespace: %s", xmlStr)
	}
	if !strings.Contains(xmlStr, "<Name>bucket1</Name>") {
		t.Errorf("should contain bucket name: %s", xmlStr)
	}
}

func TestListBucketResultV2XML(t *testing.T) {
	result := ListBucketResultV2{
		Name:        "test-bucket",
		Prefix:      "photos/",
		MaxKeys:     1000,
		IsTruncated: false,
		KeyCount:    2,
		Contents: []ObjectEntry{
			{Key: "photos/cat.jpg", Size: 100, ETag: "\"abc\"", StorageClass: "STANDARD"},
			{Key: "photos/dog.jpg", Size: 200, ETag: "\"def\"", StorageClass: "STANDARD"},
		},
		CommonPrefixes: []CommonPrefix{
			{Prefix: "photos/2024/"},
		},
	}

	data, err := xml.Marshal(result)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	xmlStr := string(data)
	if !strings.Contains(xmlStr, "http://s3.amazonaws.com/doc/2006-03-01/") {
		t.Errorf("ListBucketResult should have S3 namespace: %s", xmlStr)
	}
	if !strings.Contains(xmlStr, "<Key>photos/cat.jpg</Key>") {
		t.Errorf("should contain key: %s", xmlStr)
	}
	if !strings.Contains(xmlStr, "<Prefix>photos/2024/</Prefix>") {
		t.Errorf("should contain common prefix: %s", xmlStr)
	}
}

func TestWriteError(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/bucket/key", nil)

	WriteError(w, r, ErrNoSuchKey)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNotFound)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/xml" {
		t.Errorf("Content-Type = %q", ct)
	}
	if w.Header().Get("x-amz-request-id") == "" {
		t.Error("missing x-amz-request-id")
	}
	if w.Header().Get("Server") != "S3Gateway" {
		t.Errorf("Server = %q", w.Header().Get("Server"))
	}

	body := w.Body.String()
	if !strings.Contains(body, "<Code>NoSuchKey</Code>") {
		t.Errorf("body should contain NoSuchKey: %s", body)
	}
}

func TestWriteXML(t *testing.T) {
	w := httptest.NewRecorder()
	result := InitiateMultipartUploadResult{
		Bucket:   "mybucket",
		Key:      "mykey",
		UploadId: "test-upload-id",
	}

	WriteXML(w, http.StatusOK, result)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "<?xml") {
		t.Error("should contain xml header")
	}
	if !strings.Contains(body, "<UploadId>test-upload-id</UploadId>") {
		t.Errorf("body = %s", body)
	}
}

package handler

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/webgress/s3gateway/internal/s3response"
	"github.com/webgress/s3gateway/internal/storage"
)

// helper: create a test filesystem + router with direct handler calls (no auth)
func setupTest(t *testing.T) (*storage.Filesystem, *mux.Router) {
	t.Helper()
	dir := t.TempDir()
	fs := storage.NewFilesystem(dir)

	r := mux.NewRouter()

	bucketH := NewBucketHandler(fs)
	objectH := NewObjectHandler(fs, nil)
	listH := NewListHandler(fs)
	multipartH := NewMultipartHandler(fs)

	objectPath := "/{bucket}/{object:(?s).+}"

	r.HandleFunc(objectPath, multipartH.UploadPart).Methods(http.MethodPut).Queries("partNumber", "{partNumber}", "uploadId", "{uploadId}")
	r.HandleFunc(objectPath, multipartH.CompleteMultipartUpload).Methods(http.MethodPost).Queries("uploadId", "{uploadId}")
	r.HandleFunc(objectPath, multipartH.CreateMultipartUpload).Methods(http.MethodPost).Queries("uploads", "")
	r.HandleFunc(objectPath, multipartH.AbortMultipartUpload).Methods(http.MethodDelete).Queries("uploadId", "{uploadId}")
	r.HandleFunc(objectPath, multipartH.ListParts).Methods(http.MethodGet).Queries("uploadId", "{uploadId}")
	r.HandleFunc("/{bucket}", multipartH.ListMultipartUploads).Methods(http.MethodGet).Queries("uploads", "")
	r.HandleFunc(objectPath, objectH.HeadObject).Methods(http.MethodHead)
	r.HandleFunc(objectPath, objectH.GetObject).Methods(http.MethodGet)
	r.HandleFunc(objectPath, objectH.PutObject).Methods(http.MethodPut)
	r.HandleFunc(objectPath, objectH.DeleteObject).Methods(http.MethodDelete)
	r.HandleFunc("/{bucket}", listH.ListObjectsV2).Methods(http.MethodGet)
	r.HandleFunc("/{bucket}", bucketH.HeadBucket).Methods(http.MethodHead)
	r.HandleFunc("/{bucket}", bucketH.CreateBucket).Methods(http.MethodPut)
	r.HandleFunc("/{bucket}", bucketH.DeleteBucket).Methods(http.MethodDelete)
	r.HandleFunc("/", bucketH.ListBuckets).Methods(http.MethodGet)

	return fs, r
}

func doRequest(router *mux.Router, method, path string, body io.Reader) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, body)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

// ---- Bucket handler tests ----

func TestCreateBucketHandler(t *testing.T) {
	_, r := setupTest(t)
	w := doRequest(r, http.MethodPut, "/test-bucket", nil)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestCreateBucketDuplicate(t *testing.T) {
	_, r := setupTest(t)
	doRequest(r, http.MethodPut, "/test-bucket", nil)
	w := doRequest(r, http.MethodPut, "/test-bucket", nil)
	if w.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409", w.Code)
	}
}

func TestHeadBucketExisting(t *testing.T) {
	_, r := setupTest(t)
	doRequest(r, http.MethodPut, "/test-bucket", nil)
	w := doRequest(r, http.MethodHead, "/test-bucket", nil)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestHeadBucketMissing(t *testing.T) {
	_, r := setupTest(t)
	w := doRequest(r, http.MethodHead, "/nonexistent", nil)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestListBucketsEmpty(t *testing.T) {
	_, r := setupTest(t)
	w := doRequest(r, http.MethodGet, "/", nil)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d", w.Code)
	}
}

func TestListBucketsMultiple(t *testing.T) {
	_, r := setupTest(t)
	doRequest(r, http.MethodPut, "/alpha", nil)
	doRequest(r, http.MethodPut, "/beta", nil)
	doRequest(r, http.MethodPut, "/gamma", nil)

	w := doRequest(r, http.MethodGet, "/", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}

	var result s3response.ListAllMyBucketsResult
	xml.Unmarshal(w.Body.Bytes(), &result)
	if len(result.Buckets.Bucket) != 3 {
		t.Errorf("expected 3 buckets, got %d", len(result.Buckets.Bucket))
	}
}

func TestDeleteEmptyBucketHandler(t *testing.T) {
	_, r := setupTest(t)
	doRequest(r, http.MethodPut, "/test-bucket", nil)
	w := doRequest(r, http.MethodDelete, "/test-bucket", nil)
	if w.Code != http.StatusNoContent {
		t.Errorf("status = %d, want 204", w.Code)
	}
}

func TestDeleteNonEmptyBucketHandler(t *testing.T) {
	_, r := setupTest(t)
	doRequest(r, http.MethodPut, "/test-bucket", nil)
	doRequest(r, http.MethodPut, "/test-bucket/file.txt", strings.NewReader("data"))
	w := doRequest(r, http.MethodDelete, "/test-bucket", nil)
	if w.Code != http.StatusConflict {
		t.Errorf("status = %d, want 409", w.Code)
	}
}

// ---- Object handler tests ----

func TestPutGetObjectHandler(t *testing.T) {
	_, r := setupTest(t)
	doRequest(r, http.MethodPut, "/mybucket", nil)

	// PUT
	pw := doRequest(r, http.MethodPut, "/mybucket/hello.txt", strings.NewReader("hello world"))
	if pw.Code != http.StatusOK {
		t.Fatalf("PUT status = %d", pw.Code)
	}
	etag := pw.Header().Get("ETag")
	if etag == "" {
		t.Error("missing ETag")
	}

	// GET
	gw := doRequest(r, http.MethodGet, "/mybucket/hello.txt", nil)
	if gw.Code != http.StatusOK {
		t.Fatalf("GET status = %d", gw.Code)
	}
	if gw.Body.String() != "hello world" {
		t.Errorf("body = %q", gw.Body.String())
	}
	if gw.Header().Get("ETag") != etag {
		t.Errorf("ETag mismatch")
	}
}

func TestPutObjectContentType(t *testing.T) {
	_, r := setupTest(t)
	doRequest(r, http.MethodPut, "/mybucket", nil)

	req := httptest.NewRequest(http.MethodPut, "/mybucket/page.html", strings.NewReader("<html>"))
	req.Header.Set("Content-Type", "text/html")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	gw := doRequest(r, http.MethodGet, "/mybucket/page.html", nil)
	if ct := gw.Header().Get("Content-Type"); ct != "text/html" {
		t.Errorf("Content-Type = %q", ct)
	}
}

func TestPutObjectUserMetadata(t *testing.T) {
	_, r := setupTest(t)
	doRequest(r, http.MethodPut, "/mybucket", nil)

	req := httptest.NewRequest(http.MethodPut, "/mybucket/doc.txt", strings.NewReader("data"))
	req.Header.Set("X-Amz-Meta-Author", "alice")
	req.Header.Set("X-Amz-Meta-Year", "2024")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("PUT status = %d", w.Code)
	}

	gw := doRequest(r, http.MethodGet, "/mybucket/doc.txt", nil)
	if gw.Header().Get("X-Amz-Meta-Author") != "alice" {
		t.Errorf("missing x-amz-meta-author, headers=%v", gw.Header())
	}
}

func TestHeadObjectHandler(t *testing.T) {
	_, r := setupTest(t)
	doRequest(r, http.MethodPut, "/mybucket", nil)
	doRequest(r, http.MethodPut, "/mybucket/file.txt", strings.NewReader("content"))

	w := doRequest(r, http.MethodHead, "/mybucket/file.txt", nil)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d", w.Code)
	}
	if w.Header().Get("Content-Length") != "7" {
		t.Errorf("Content-Length = %q", w.Header().Get("Content-Length"))
	}
	if w.Header().Get("ETag") == "" {
		t.Error("missing ETag")
	}
}

func TestDeleteThenGetObject(t *testing.T) {
	_, r := setupTest(t)
	doRequest(r, http.MethodPut, "/mybucket", nil)
	doRequest(r, http.MethodPut, "/mybucket/file.txt", strings.NewReader("data"))
	doRequest(r, http.MethodDelete, "/mybucket/file.txt", nil)

	w := doRequest(r, http.MethodGet, "/mybucket/file.txt", nil)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestGetNonExistentObject(t *testing.T) {
	_, r := setupTest(t)
	doRequest(r, http.MethodPut, "/mybucket", nil)

	w := doRequest(r, http.MethodGet, "/mybucket/nope.txt", nil)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
	if !strings.Contains(w.Body.String(), "NoSuchKey") {
		t.Errorf("body should contain NoSuchKey: %s", w.Body.String())
	}
}

func TestPutToNonExistentBucket(t *testing.T) {
	_, r := setupTest(t)
	w := doRequest(r, http.MethodPut, "/nonexistent/file.txt", strings.NewReader("data"))
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
	if !strings.Contains(w.Body.String(), "NoSuchBucket") {
		t.Errorf("body = %s", w.Body.String())
	}
}

// ---- List handler tests ----

func TestListObjectsAll(t *testing.T) {
	_, r := setupTest(t)
	doRequest(r, http.MethodPut, "/mybucket", nil)

	for i := 0; i < 10; i++ {
		doRequest(r, http.MethodPut, fmt.Sprintf("/mybucket/key%02d", i), strings.NewReader("data"))
	}

	w := doRequest(r, http.MethodGet, "/mybucket?list-type=2", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}

	var result s3response.ListBucketResultV2
	xml.Unmarshal(w.Body.Bytes(), &result)
	if len(result.Contents) != 10 {
		t.Errorf("expected 10 objects, got %d", len(result.Contents))
	}
}

func TestListObjectsPrefix(t *testing.T) {
	_, r := setupTest(t)
	doRequest(r, http.MethodPut, "/mybucket", nil)
	doRequest(r, http.MethodPut, "/mybucket/photos/cat.jpg", strings.NewReader("cat"))
	doRequest(r, http.MethodPut, "/mybucket/photos/dog.jpg", strings.NewReader("dog"))
	doRequest(r, http.MethodPut, "/mybucket/docs/readme.txt", strings.NewReader("readme"))

	w := doRequest(r, http.MethodGet, "/mybucket?list-type=2&prefix=photos/", nil)
	var result s3response.ListBucketResultV2
	xml.Unmarshal(w.Body.Bytes(), &result)
	if len(result.Contents) != 2 {
		t.Errorf("expected 2, got %d", len(result.Contents))
	}
}

func TestListObjectsDelimiter(t *testing.T) {
	_, r := setupTest(t)
	doRequest(r, http.MethodPut, "/mybucket", nil)
	doRequest(r, http.MethodPut, "/mybucket/photos/cat.jpg", strings.NewReader("cat"))
	doRequest(r, http.MethodPut, "/mybucket/photos/dog.jpg", strings.NewReader("dog"))
	doRequest(r, http.MethodPut, "/mybucket/root.txt", strings.NewReader("root"))

	w := doRequest(r, http.MethodGet, "/mybucket?list-type=2&delimiter=/", nil)
	var result s3response.ListBucketResultV2
	xml.Unmarshal(w.Body.Bytes(), &result)

	if len(result.Contents) != 1 {
		t.Errorf("expected 1 object, got %d", len(result.Contents))
	}
	if len(result.CommonPrefixes) != 1 || result.CommonPrefixes[0].Prefix != "photos/" {
		t.Errorf("CommonPrefixes = %+v", result.CommonPrefixes)
	}
}

func TestListObjectsPagination(t *testing.T) {
	_, r := setupTest(t)
	doRequest(r, http.MethodPut, "/mybucket", nil)

	for i := 0; i < 10; i++ {
		doRequest(r, http.MethodPut, fmt.Sprintf("/mybucket/key%02d", i), strings.NewReader("data"))
	}

	// First page
	w1 := doRequest(r, http.MethodGet, "/mybucket?list-type=2&max-keys=3", nil)
	var r1 s3response.ListBucketResultV2
	xml.Unmarshal(w1.Body.Bytes(), &r1)
	if len(r1.Contents) != 3 {
		t.Fatalf("page 1: expected 3, got %d", len(r1.Contents))
	}
	if !r1.IsTruncated {
		t.Fatal("expected IsTruncated=true")
	}
	if r1.NextContinuationToken == "" {
		t.Fatal("missing NextContinuationToken")
	}

	// Second page
	w2 := doRequest(r, http.MethodGet, "/mybucket?list-type=2&max-keys=3&continuation-token="+r1.NextContinuationToken, nil)
	var r2 s3response.ListBucketResultV2
	xml.Unmarshal(w2.Body.Bytes(), &r2)
	if len(r2.Contents) != 3 {
		t.Fatalf("page 2: expected 3, got %d", len(r2.Contents))
	}
}

func TestListObjectsStartAfter(t *testing.T) {
	_, r := setupTest(t)
	doRequest(r, http.MethodPut, "/mybucket", nil)
	doRequest(r, http.MethodPut, "/mybucket/aaa", strings.NewReader("a"))
	doRequest(r, http.MethodPut, "/mybucket/bbb", strings.NewReader("b"))
	doRequest(r, http.MethodPut, "/mybucket/ccc", strings.NewReader("c"))

	w := doRequest(r, http.MethodGet, "/mybucket?list-type=2&start-after=aaa", nil)
	var result s3response.ListBucketResultV2
	xml.Unmarshal(w.Body.Bytes(), &result)
	if len(result.Contents) != 2 {
		t.Errorf("expected 2 after start-after, got %d", len(result.Contents))
	}
}

func TestListObjectsEmptyBucket(t *testing.T) {
	_, r := setupTest(t)
	doRequest(r, http.MethodPut, "/mybucket", nil)

	w := doRequest(r, http.MethodGet, "/mybucket?list-type=2", nil)
	var result s3response.ListBucketResultV2
	xml.Unmarshal(w.Body.Bytes(), &result)
	if len(result.Contents) != 0 {
		t.Errorf("expected 0 objects, got %d", len(result.Contents))
	}
}

// ---- Multipart handler tests ----

func TestMultipartCreateUploadComplete(t *testing.T) {
	_, r := setupTest(t)
	doRequest(r, http.MethodPut, "/mybucket", nil)

	// Create multipart upload
	w1 := doRequest(r, http.MethodPost, "/mybucket/bigfile.bin?uploads", nil)
	if w1.Code != http.StatusOK {
		t.Fatalf("create multipart status = %d", w1.Code)
	}

	var initResult s3response.InitiateMultipartUploadResult
	xml.Unmarshal(w1.Body.Bytes(), &initResult)
	uploadID := initResult.UploadId
	if uploadID == "" {
		t.Fatal("empty upload ID")
	}

	// Upload 3 parts
	part1Data := bytes.Repeat([]byte("A"), 1024)
	part2Data := bytes.Repeat([]byte("B"), 1024)
	part3Data := bytes.Repeat([]byte("C"), 512)

	etags := make([]string, 3)
	for i, data := range [][]byte{part1Data, part2Data, part3Data} {
		pw := doRequest(r, http.MethodPut, fmt.Sprintf("/mybucket/bigfile.bin?partNumber=%d&uploadId=%s", i+1, uploadID), bytes.NewReader(data))
		if pw.Code != http.StatusOK {
			t.Fatalf("upload part %d status = %d", i+1, pw.Code)
		}
		etags[i] = pw.Header().Get("ETag")
	}

	// Complete multipart
	completeXML := fmt.Sprintf(`<CompleteMultipartUpload>
		<Part><PartNumber>1</PartNumber><ETag>%s</ETag></Part>
		<Part><PartNumber>2</PartNumber><ETag>%s</ETag></Part>
		<Part><PartNumber>3</PartNumber><ETag>%s</ETag></Part>
	</CompleteMultipartUpload>`, etags[0], etags[1], etags[2])

	cw := doRequest(r, http.MethodPost, "/mybucket/bigfile.bin?uploadId="+uploadID, strings.NewReader(completeXML))
	if cw.Code != http.StatusOK {
		t.Fatalf("complete multipart status = %d, body = %s", cw.Code, cw.Body.String())
	}

	// Verify assembled content
	gw := doRequest(r, http.MethodGet, "/mybucket/bigfile.bin", nil)
	expected := append(append(part1Data, part2Data...), part3Data...)
	if !bytes.Equal(gw.Body.Bytes(), expected) {
		t.Error("assembled content mismatch")
	}
}

func TestMultipartAbort(t *testing.T) {
	_, r := setupTest(t)
	doRequest(r, http.MethodPut, "/mybucket", nil)

	w1 := doRequest(r, http.MethodPost, "/mybucket/abort.bin?uploads", nil)
	var initResult s3response.InitiateMultipartUploadResult
	xml.Unmarshal(w1.Body.Bytes(), &initResult)

	doRequest(r, http.MethodPut, fmt.Sprintf("/mybucket/abort.bin?partNumber=1&uploadId=%s", initResult.UploadId), strings.NewReader("data"))

	aw := doRequest(r, http.MethodDelete, fmt.Sprintf("/mybucket/abort.bin?uploadId=%s", initResult.UploadId), nil)
	if aw.Code != http.StatusNoContent {
		t.Errorf("abort status = %d", aw.Code)
	}
}

func TestMultipartListUploads(t *testing.T) {
	_, r := setupTest(t)
	doRequest(r, http.MethodPut, "/mybucket", nil)

	doRequest(r, http.MethodPost, "/mybucket/file1.bin?uploads", nil)
	doRequest(r, http.MethodPost, "/mybucket/file2.bin?uploads", nil)

	w := doRequest(r, http.MethodGet, "/mybucket?uploads", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}

	var result s3response.ListMultipartUploadsResult
	xml.Unmarshal(w.Body.Bytes(), &result)
	if len(result.Uploads) != 2 {
		t.Errorf("expected 2 uploads, got %d", len(result.Uploads))
	}
}

func TestMultipartInvalidPartOrder(t *testing.T) {
	_, r := setupTest(t)
	doRequest(r, http.MethodPut, "/mybucket", nil)

	w1 := doRequest(r, http.MethodPost, "/mybucket/file.bin?uploads", nil)
	var initResult s3response.InitiateMultipartUploadResult
	xml.Unmarshal(w1.Body.Bytes(), &initResult)
	uploadID := initResult.UploadId

	doRequest(r, http.MethodPut, fmt.Sprintf("/mybucket/file.bin?partNumber=1&uploadId=%s", uploadID), strings.NewReader("a"))
	pw2 := doRequest(r, http.MethodPut, fmt.Sprintf("/mybucket/file.bin?partNumber=2&uploadId=%s", uploadID), strings.NewReader("b"))
	etag2 := pw2.Header().Get("ETag")
	pw1 := doRequest(r, http.MethodPut, fmt.Sprintf("/mybucket/file.bin?partNumber=1&uploadId=%s", uploadID), strings.NewReader("a"))
	etag1 := pw1.Header().Get("ETag")

	// Wrong order: 2 before 1
	completeXML := fmt.Sprintf(`<CompleteMultipartUpload>
		<Part><PartNumber>2</PartNumber><ETag>%s</ETag></Part>
		<Part><PartNumber>1</PartNumber><ETag>%s</ETag></Part>
	</CompleteMultipartUpload>`, etag2, etag1)

	cw := doRequest(r, http.MethodPost, "/mybucket/file.bin?uploadId="+uploadID, strings.NewReader(completeXML))
	if cw.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", cw.Code)
	}
}

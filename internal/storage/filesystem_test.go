package storage

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
)

func newTestFS(t *testing.T) *Filesystem {
	t.Helper()
	return NewFilesystem(t.TempDir())
}

// ---- Bucket tests ----

func TestCreateBucket(t *testing.T) {
	fs := newTestFS(t)
	if err := fs.CreateBucket("test-bucket"); err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}
}

func TestCreateBucketDuplicate(t *testing.T) {
	fs := newTestFS(t)
	fs.CreateBucket("test-bucket")
	err := fs.CreateBucket("test-bucket")
	if err != ErrBucketExists {
		t.Fatalf("expected ErrBucketExists, got %v", err)
	}
}

func TestDeleteEmptyBucket(t *testing.T) {
	fs := newTestFS(t)
	fs.CreateBucket("test-bucket")
	if err := fs.DeleteBucket("test-bucket"); err != nil {
		t.Fatalf("DeleteBucket: %v", err)
	}
	if err := fs.HeadBucket("test-bucket"); err != ErrBucketNotFound {
		t.Fatalf("expected ErrBucketNotFound after delete, got %v", err)
	}
}

func TestDeleteNonEmptyBucket(t *testing.T) {
	fs := newTestFS(t)
	fs.CreateBucket("test-bucket")
	fs.PutObject("test-bucket", "file.txt", strings.NewReader("data"), "text/plain", nil)
	err := fs.DeleteBucket("test-bucket")
	if err != ErrBucketNotEmpty {
		t.Fatalf("expected ErrBucketNotEmpty, got %v", err)
	}
}

func TestListBuckets(t *testing.T) {
	fs := newTestFS(t)
	fs.CreateBucket("alpha")
	fs.CreateBucket("beta")
	fs.CreateBucket("gamma")
	buckets, err := fs.ListBuckets()
	if err != nil {
		t.Fatalf("ListBuckets: %v", err)
	}
	if len(buckets) != 3 {
		t.Fatalf("expected 3 buckets, got %d", len(buckets))
	}
}

func TestInvalidBucketNames(t *testing.T) {
	tests := []string{
		"ab",                        // too short
		strings.Repeat("a", 64),     // too long
		"UPPERCASE",                 // uppercase
		"has space",                 // space
		".startdot",                 // starts with dot
		"-starthyphen",              // starts with hyphen
		"enddot.",                   // ends with dot
		"endhyphen-",                // ends with hyphen
		"two..dots",                 // adjacent dots
		"xn--prefix",               // xn-- prefix
		"something-s3alias",         // -s3alias suffix
		"192.168.1.1",              // IP address
	}
	fs := newTestFS(t)
	for _, name := range tests {
		if err := fs.CreateBucket(name); err == nil {
			t.Errorf("expected error for bucket name %q", name)
		}
	}
}

// ---- Object tests ----

func TestPutGetRoundTrip(t *testing.T) {
	fs := newTestFS(t)
	fs.CreateBucket("mybucket")

	content := "hello world"
	etag, err := fs.PutObject("mybucket", "greeting.txt", strings.NewReader(content), "text/plain", nil)
	if err != nil {
		t.Fatalf("PutObject: %v", err)
	}

	// Verify ETag is correct MD5
	h := md5.Sum([]byte(content))
	expected := fmt.Sprintf("\"%s\"", hex.EncodeToString(h[:]))
	if etag != expected {
		t.Errorf("ETag = %q, want %q", etag, expected)
	}

	result, err := fs.GetObject("mybucket", "greeting.txt")
	if err != nil {
		t.Fatalf("GetObject: %v", err)
	}
	defer result.Body.Close()

	got, _ := io.ReadAll(result.Body)
	if string(got) != content {
		t.Errorf("content = %q, want %q", string(got), content)
	}
	if result.Metadata.ContentType != "text/plain" {
		t.Errorf("ContentType = %q, want text/plain", result.Metadata.ContentType)
	}
}

func TestPutGetLargeStreaming(t *testing.T) {
	fs := newTestFS(t)
	fs.CreateBucket("mybucket")

	// 1MB test (not 50MB to keep test fast, but tests streaming path)
	size := 1024 * 1024
	data := make([]byte, size)
	rand.Read(data)

	etag, err := fs.PutObject("mybucket", "large.bin", bytes.NewReader(data), "application/octet-stream", nil)
	if err != nil {
		t.Fatalf("PutObject: %v", err)
	}
	if etag == "" {
		t.Fatal("empty etag")
	}

	result, err := fs.GetObject("mybucket", "large.bin")
	if err != nil {
		t.Fatalf("GetObject: %v", err)
	}
	defer result.Body.Close()

	got, _ := io.ReadAll(result.Body)
	if len(got) != size {
		t.Fatalf("size = %d, want %d", len(got), size)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("content mismatch")
	}
}

func TestOverwriteObject(t *testing.T) {
	fs := newTestFS(t)
	fs.CreateBucket("mybucket")

	fs.PutObject("mybucket", "file.txt", strings.NewReader("v1"), "text/plain", nil)
	fs.PutObject("mybucket", "file.txt", strings.NewReader("v2"), "text/plain", nil)

	result, _ := fs.GetObject("mybucket", "file.txt")
	defer result.Body.Close()
	got, _ := io.ReadAll(result.Body)
	if string(got) != "v2" {
		t.Errorf("got %q, want v2", string(got))
	}
}

func TestHeadObject(t *testing.T) {
	fs := newTestFS(t)
	fs.CreateBucket("mybucket")

	meta := map[string]string{"x-amz-meta-color": "red"}
	fs.PutObject("mybucket", "item.txt", strings.NewReader("data"), "text/html", meta)

	got, err := fs.HeadObject("mybucket", "item.txt")
	if err != nil {
		t.Fatalf("HeadObject: %v", err)
	}
	if got.ContentType != "text/html" {
		t.Errorf("ContentType = %q", got.ContentType)
	}
	if got.ContentLength != 4 {
		t.Errorf("ContentLength = %d", got.ContentLength)
	}
	if got.UserMetadata["x-amz-meta-color"] != "red" {
		t.Errorf("user metadata missing")
	}
}

func TestDeleteObject(t *testing.T) {
	fs := newTestFS(t)
	fs.CreateBucket("mybucket")
	fs.PutObject("mybucket", "file.txt", strings.NewReader("data"), "", nil)
	fs.DeleteObject("mybucket", "file.txt")

	_, err := fs.GetObject("mybucket", "file.txt")
	if err != ErrObjectNotFound {
		t.Fatalf("expected ErrObjectNotFound, got %v", err)
	}
}

func TestGetObjectNonExistent(t *testing.T) {
	fs := newTestFS(t)
	fs.CreateBucket("mybucket")

	_, err := fs.GetObject("mybucket", "no-such-key")
	if err != ErrObjectNotFound {
		t.Fatalf("expected ErrObjectNotFound, got %v", err)
	}
}

func TestGetObjectNonExistentBucket(t *testing.T) {
	fs := newTestFS(t)
	_, err := fs.GetObject("nonexistent", "key")
	if err != ErrBucketNotFound {
		t.Fatalf("expected ErrBucketNotFound, got %v", err)
	}
}

func TestContentTypePreserved(t *testing.T) {
	fs := newTestFS(t)
	fs.CreateBucket("mybucket")

	fs.PutObject("mybucket", "page.html", strings.NewReader("<html>"), "text/html; charset=utf-8", nil)
	result, _ := fs.GetObject("mybucket", "page.html")
	defer result.Body.Close()
	if result.Metadata.ContentType != "text/html; charset=utf-8" {
		t.Errorf("ContentType = %q", result.Metadata.ContentType)
	}
}

func TestUserMetadataPreserved(t *testing.T) {
	fs := newTestFS(t)
	fs.CreateBucket("mybucket")

	meta := map[string]string{
		"x-amz-meta-author": "alice",
		"x-amz-meta-year":   "2024",
	}
	fs.PutObject("mybucket", "doc.txt", strings.NewReader("data"), "", meta)

	result, _ := fs.GetObject("mybucket", "doc.txt")
	defer result.Body.Close()
	if result.Metadata.UserMetadata["x-amz-meta-author"] != "alice" {
		t.Error("missing x-amz-meta-author")
	}
	if result.Metadata.UserMetadata["x-amz-meta-year"] != "2024" {
		t.Error("missing x-amz-meta-year")
	}
}

func TestZeroByteFile(t *testing.T) {
	fs := newTestFS(t)
	fs.CreateBucket("mybucket")

	etag, err := fs.PutObject("mybucket", "empty", strings.NewReader(""), "", nil)
	if err != nil {
		t.Fatalf("PutObject: %v", err)
	}
	// MD5 of empty string
	expected := "\"d41d8cd98f00b204e9800998ecf8427e\""
	if etag != expected {
		t.Errorf("ETag = %q, want %q", etag, expected)
	}

	result, _ := fs.GetObject("mybucket", "empty")
	defer result.Body.Close()
	got, _ := io.ReadAll(result.Body)
	if len(got) != 0 {
		t.Errorf("expected empty file, got %d bytes", len(got))
	}
}

// ---- Path security ----

func TestPathTraversalRejected(t *testing.T) {
	fs := newTestFS(t)
	fs.CreateBucket("mybucket")

	_, err := fs.PutObject("mybucket", "../escape", strings.NewReader("bad"), "", nil)
	if err != ErrPathTraversal {
		t.Errorf("expected ErrPathTraversal for ../, got %v", err)
	}

	_, err = fs.PutObject("mybucket", "foo/../../escape", strings.NewReader("bad"), "", nil)
	if err != ErrPathTraversal {
		t.Errorf("expected ErrPathTraversal for nested ../, got %v", err)
	}
}

func TestNullByteRejected(t *testing.T) {
	fs := newTestFS(t)
	fs.CreateBucket("mybucket")

	_, err := fs.PutObject("mybucket", "file\x00evil", strings.NewReader("bad"), "", nil)
	if err != ErrPathTraversal {
		t.Errorf("expected ErrPathTraversal for null byte, got %v", err)
	}
}

func TestUnicodeKeys(t *testing.T) {
	fs := newTestFS(t)
	fs.CreateBucket("mybucket")

	key := "日本語/ファイル.txt"
	fs.PutObject("mybucket", key, strings.NewReader("data"), "", nil)

	result, err := fs.GetObject("mybucket", key)
	if err != nil {
		t.Fatalf("GetObject unicode key: %v", err)
	}
	defer result.Body.Close()
	got, _ := io.ReadAll(result.Body)
	if string(got) != "data" {
		t.Errorf("content = %q", string(got))
	}
}

func TestDeeplyNestedKeys(t *testing.T) {
	fs := newTestFS(t)
	fs.CreateBucket("mybucket")

	key := "a/b/c/d/e/f/g/h/deep.txt"
	fs.PutObject("mybucket", key, strings.NewReader("deep"), "", nil)

	result, err := fs.GetObject("mybucket", key)
	if err != nil {
		t.Fatalf("GetObject deep key: %v", err)
	}
	defer result.Body.Close()
	got, _ := io.ReadAll(result.Body)
	if string(got) != "deep" {
		t.Errorf("content = %q", string(got))
	}
}

func TestKeysWithSpaces(t *testing.T) {
	fs := newTestFS(t)
	fs.CreateBucket("mybucket")

	key := "my folder/my file.txt"
	fs.PutObject("mybucket", key, strings.NewReader("spaced"), "", nil)

	result, err := fs.GetObject("mybucket", key)
	if err != nil {
		t.Fatalf("GetObject spaced key: %v", err)
	}
	defer result.Body.Close()
	got, _ := io.ReadAll(result.Body)
	if string(got) != "spaced" {
		t.Errorf("content = %q", string(got))
	}
}

// ---- Listing tests ----

func TestListPrefix(t *testing.T) {
	fs := newTestFS(t)
	fs.CreateBucket("mybucket")

	fs.PutObject("mybucket", "photos/cat.jpg", strings.NewReader("cat"), "", nil)
	fs.PutObject("mybucket", "photos/dog.jpg", strings.NewReader("dog"), "", nil)
	fs.PutObject("mybucket", "docs/readme.txt", strings.NewReader("readme"), "", nil)

	out, err := fs.ListObjects(ListObjectsInput{Bucket: "mybucket", Prefix: "photos/"})
	if err != nil {
		t.Fatalf("ListObjects: %v", err)
	}
	if len(out.Objects) != 2 {
		t.Fatalf("expected 2, got %d", len(out.Objects))
	}
}

func TestListDelimiter(t *testing.T) {
	fs := newTestFS(t)
	fs.CreateBucket("mybucket")

	fs.PutObject("mybucket", "photos/cat.jpg", strings.NewReader("cat"), "", nil)
	fs.PutObject("mybucket", "photos/dog.jpg", strings.NewReader("dog"), "", nil)
	fs.PutObject("mybucket", "root.txt", strings.NewReader("root"), "", nil)

	out, err := fs.ListObjects(ListObjectsInput{Bucket: "mybucket", Delimiter: "/"})
	if err != nil {
		t.Fatalf("ListObjects: %v", err)
	}
	if len(out.Objects) != 1 {
		t.Errorf("expected 1 object (root.txt), got %d", len(out.Objects))
	}
	if len(out.CommonPrefixes) != 1 || out.CommonPrefixes[0] != "photos/" {
		t.Errorf("CommonPrefixes = %v, want [photos/]", out.CommonPrefixes)
	}
}

func TestListPagination(t *testing.T) {
	fs := newTestFS(t)
	fs.CreateBucket("mybucket")

	for i := 0; i < 10; i++ {
		fs.PutObject("mybucket", fmt.Sprintf("key%02d", i), strings.NewReader("data"), "", nil)
	}

	// First page
	out, _ := fs.ListObjects(ListObjectsInput{Bucket: "mybucket", MaxKeys: 3})
	if len(out.Objects) != 3 {
		t.Fatalf("page1: expected 3, got %d", len(out.Objects))
	}
	if !out.IsTruncated {
		t.Fatal("expected IsTruncated=true")
	}

	// Second page
	out2, _ := fs.ListObjects(ListObjectsInput{Bucket: "mybucket", MaxKeys: 3, ContinuationToken: out.NextContinuationToken})
	if len(out2.Objects) != 3 {
		t.Fatalf("page2: expected 3, got %d", len(out2.Objects))
	}
}

func TestListEmptyBucket(t *testing.T) {
	fs := newTestFS(t)
	fs.CreateBucket("mybucket")

	out, err := fs.ListObjects(ListObjectsInput{Bucket: "mybucket"})
	if err != nil {
		t.Fatalf("ListObjects: %v", err)
	}
	if len(out.Objects) != 0 {
		t.Errorf("expected 0 objects, got %d", len(out.Objects))
	}
	if out.IsTruncated {
		t.Error("expected IsTruncated=false")
	}
}

func TestListMaxKeys(t *testing.T) {
	fs := newTestFS(t)
	fs.CreateBucket("mybucket")

	for i := 0; i < 5; i++ {
		fs.PutObject("mybucket", fmt.Sprintf("key%d", i), strings.NewReader("data"), "", nil)
	}

	out, _ := fs.ListObjects(ListObjectsInput{Bucket: "mybucket", MaxKeys: 2})
	if len(out.Objects) != 2 {
		t.Errorf("expected 2 objects, got %d", len(out.Objects))
	}
	if !out.IsTruncated {
		t.Error("expected IsTruncated=true")
	}
}

// ---- Multipart tests ----

func TestMultipartRoundTrip(t *testing.T) {
	fs := newTestFS(t)
	fs.CreateBucket("mybucket")

	uploadID, err := fs.CreateMultipartUpload("mybucket", "assembled.bin", "application/octet-stream")
	if err != nil {
		t.Fatalf("CreateMultipartUpload: %v", err)
	}

	part1Data := bytes.Repeat([]byte("A"), 1024)
	part2Data := bytes.Repeat([]byte("B"), 1024)
	part3Data := bytes.Repeat([]byte("C"), 512)

	etag1, _ := fs.UploadPart(uploadID, 1, bytes.NewReader(part1Data))
	etag2, _ := fs.UploadPart(uploadID, 2, bytes.NewReader(part2Data))
	etag3, _ := fs.UploadPart(uploadID, 3, bytes.NewReader(part3Data))

	compositeETag, err := fs.CompleteMultipartUpload(uploadID, []CompletePart{
		{PartNumber: 1, ETag: etag1},
		{PartNumber: 2, ETag: etag2},
		{PartNumber: 3, ETag: etag3},
	})
	if err != nil {
		t.Fatalf("CompleteMultipartUpload: %v", err)
	}

	// Verify composite ETag format: "hexmd5-3"
	if !strings.HasSuffix(strings.Trim(compositeETag, "\""), "-3") {
		t.Errorf("composite ETag should end with -3: %s", compositeETag)
	}

	// Verify assembled content
	result, err := fs.GetObject("mybucket", "assembled.bin")
	if err != nil {
		t.Fatalf("GetObject: %v", err)
	}
	defer result.Body.Close()
	got, _ := io.ReadAll(result.Body)
	expected := append(append(part1Data, part2Data...), part3Data...)
	if !bytes.Equal(got, expected) {
		t.Fatal("assembled content mismatch")
	}
}

func TestMultipartAbort(t *testing.T) {
	fs := newTestFS(t)
	fs.CreateBucket("mybucket")

	uploadID, _ := fs.CreateMultipartUpload("mybucket", "abort.bin", "")
	fs.UploadPart(uploadID, 1, strings.NewReader("data"))

	if err := fs.AbortMultipartUpload(uploadID); err != nil {
		t.Fatalf("AbortMultipartUpload: %v", err)
	}

	// Verify upload is gone
	if err := fs.AbortMultipartUpload(uploadID); err != ErrNoSuchUpload {
		t.Fatalf("expected ErrNoSuchUpload after abort, got %v", err)
	}
}

func TestListMultipartUploads(t *testing.T) {
	fs := newTestFS(t)
	fs.CreateBucket("mybucket")

	fs.CreateMultipartUpload("mybucket", "file1.bin", "")
	fs.CreateMultipartUpload("mybucket", "file2.bin", "")

	uploads, err := fs.ListMultipartUploads("mybucket")
	if err != nil {
		t.Fatalf("ListMultipartUploads: %v", err)
	}
	if len(uploads) != 2 {
		t.Errorf("expected 2 uploads, got %d", len(uploads))
	}
}

func TestListParts(t *testing.T) {
	fs := newTestFS(t)
	fs.CreateBucket("mybucket")

	uploadID, _ := fs.CreateMultipartUpload("mybucket", "file.bin", "")
	fs.UploadPart(uploadID, 1, strings.NewReader("part1"))
	fs.UploadPart(uploadID, 3, strings.NewReader("part3"))

	parts, err := fs.ListParts(uploadID)
	if err != nil {
		t.Fatalf("ListParts: %v", err)
	}
	if len(parts) != 2 {
		t.Fatalf("expected 2 parts, got %d", len(parts))
	}
	if parts[0].PartNumber != 1 || parts[1].PartNumber != 3 {
		t.Errorf("parts = %v", parts)
	}
}

func TestPartOverwrite(t *testing.T) {
	fs := newTestFS(t)
	fs.CreateBucket("mybucket")

	uploadID, _ := fs.CreateMultipartUpload("mybucket", "file.bin", "")
	fs.UploadPart(uploadID, 1, strings.NewReader("original"))
	etag2, _ := fs.UploadPart(uploadID, 1, strings.NewReader("replaced"))

	parts, _ := fs.ListParts(uploadID)
	if len(parts) != 1 {
		t.Fatalf("expected 1 part, got %d", len(parts))
	}
	if parts[0].ETag != etag2 {
		t.Errorf("part etag should match second upload")
	}
}

func TestInvalidPartOrder(t *testing.T) {
	fs := newTestFS(t)
	fs.CreateBucket("mybucket")

	uploadID, _ := fs.CreateMultipartUpload("mybucket", "file.bin", "")
	etag1, _ := fs.UploadPart(uploadID, 1, strings.NewReader("a"))
	etag2, _ := fs.UploadPart(uploadID, 2, strings.NewReader("b"))

	_, err := fs.CompleteMultipartUpload(uploadID, []CompletePart{
		{PartNumber: 2, ETag: etag2},
		{PartNumber: 1, ETag: etag1},
	})
	if err != ErrInvalidPartOrder {
		t.Fatalf("expected ErrInvalidPartOrder, got %v", err)
	}
}

func TestWrongETagOnComplete(t *testing.T) {
	fs := newTestFS(t)
	fs.CreateBucket("mybucket")

	uploadID, _ := fs.CreateMultipartUpload("mybucket", "file.bin", "")
	fs.UploadPart(uploadID, 1, strings.NewReader("data"))

	_, err := fs.CompleteMultipartUpload(uploadID, []CompletePart{
		{PartNumber: 1, ETag: "\"0000000000000000000000000000dead\""},
	})
	if err != ErrInvalidPart {
		t.Fatalf("expected ErrInvalidPart for wrong etag, got %v", err)
	}
}

// ---- Concurrent tests ----

func TestConcurrentPutDifferentKeys(t *testing.T) {
	fs := newTestFS(t)
	fs.CreateBucket("mybucket")

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			key := fmt.Sprintf("concurrent-%d", n)
			_, err := fs.PutObject("mybucket", key, strings.NewReader(fmt.Sprintf("data-%d", n)), "", nil)
			if err != nil {
				t.Errorf("PutObject(%s): %v", key, err)
			}
		}(i)
	}
	wg.Wait()

	// Verify all exist
	for i := 0; i < 20; i++ {
		key := fmt.Sprintf("concurrent-%d", i)
		_, err := fs.GetObject("mybucket", key)
		if err != nil {
			t.Errorf("GetObject(%s): %v", key, err)
		}
	}
}

func TestConcurrentPutGetSameKey(t *testing.T) {
	fs := newTestFS(t)
	fs.CreateBucket("mybucket")

	var wg sync.WaitGroup
	// Writers
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			fs.PutObject("mybucket", "shared-key", strings.NewReader(fmt.Sprintf("v%d", n)), "", nil)
		}(i)
	}
	// Readers
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := fs.GetObject("mybucket", "shared-key")
			if err != nil {
				return // might not exist yet
			}
			defer result.Body.Close()
			io.ReadAll(result.Body)
		}()
	}
	wg.Wait()
}

package storage

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWriteReadMetadata(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.s3meta")

	meta := ObjectMetadata{
		ContentType:        "text/plain",
		ContentLength:      42,
		ETag:               "\"abc123\"",
		LastModified:       time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		UserMetadata:       map[string]string{"color": "blue", "size": "large"},
		ContentDisposition: "attachment",
		ContentEncoding:    "gzip",
		CacheControl:       "max-age=3600",
	}

	if err := WriteMetadata(path, meta); err != nil {
		t.Fatalf("WriteMetadata: %v", err)
	}

	got, err := ReadMetadata(path)
	if err != nil {
		t.Fatalf("ReadMetadata: %v", err)
	}

	if got.ContentType != meta.ContentType {
		t.Errorf("ContentType = %q, want %q", got.ContentType, meta.ContentType)
	}
	if got.ContentLength != meta.ContentLength {
		t.Errorf("ContentLength = %d, want %d", got.ContentLength, meta.ContentLength)
	}
	if got.ETag != meta.ETag {
		t.Errorf("ETag = %q, want %q", got.ETag, meta.ETag)
	}
	if !got.LastModified.Equal(meta.LastModified) {
		t.Errorf("LastModified = %v, want %v", got.LastModified, meta.LastModified)
	}
	if got.ContentDisposition != meta.ContentDisposition {
		t.Errorf("ContentDisposition = %q, want %q", got.ContentDisposition, meta.ContentDisposition)
	}
	if got.ContentEncoding != meta.ContentEncoding {
		t.Errorf("ContentEncoding = %q, want %q", got.ContentEncoding, meta.ContentEncoding)
	}
	if got.CacheControl != meta.CacheControl {
		t.Errorf("CacheControl = %q, want %q", got.CacheControl, meta.CacheControl)
	}
	for k, v := range meta.UserMetadata {
		if got.UserMetadata[k] != v {
			t.Errorf("UserMetadata[%q] = %q, want %q", k, got.UserMetadata[k], v)
		}
	}
}

func TestMetadataEmptyOptionalFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.s3meta")

	meta := ObjectMetadata{
		ContentType:   "application/octet-stream",
		ContentLength: 0,
		ETag:          "\"d41d8cd98f00b204e9800998ecf8427e\"",
		LastModified:  time.Now().UTC(),
	}

	if err := WriteMetadata(path, meta); err != nil {
		t.Fatalf("WriteMetadata: %v", err)
	}

	got, err := ReadMetadata(path)
	if err != nil {
		t.Fatalf("ReadMetadata: %v", err)
	}
	if got.ContentDisposition != "" {
		t.Errorf("ContentDisposition should be empty, got %q", got.ContentDisposition)
	}
	if got.UserMetadata != nil {
		t.Errorf("UserMetadata should be nil, got %v", got.UserMetadata)
	}
}

func TestReadMetadataCorruptJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.s3meta")
	os.WriteFile(path, []byte("{invalid json!!!"), 0644)

	_, err := ReadMetadata(path)
	if err == nil {
		t.Fatal("expected error for corrupt JSON")
	}
}

func TestReadMetadataMissingFile(t *testing.T) {
	_, err := ReadMetadata("/nonexistent/path/meta.s3meta")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

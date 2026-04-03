package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

type ObjectMetadata struct {
	ContentType        string            `json:"content_type"`
	ContentLength      int64             `json:"content_length"`
	ETag               string            `json:"etag"`
	LastModified       time.Time         `json:"last_modified"`
	UserMetadata       map[string]string `json:"user_metadata,omitempty"`
	ContentDisposition string            `json:"content_disposition,omitempty"`
	ContentEncoding    string            `json:"content_encoding,omitempty"`
	CacheControl       string            `json:"cache_control,omitempty"`
}

func WriteMetadata(path string, meta ObjectMetadata) error {
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return fmt.Errorf("write metadata temp: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("rename metadata: %w", err)
	}
	return nil
}

func ReadMetadata(path string) (ObjectMetadata, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return ObjectMetadata{}, fmt.Errorf("read metadata: %w", err)
	}
	var meta ObjectMetadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return ObjectMetadata{}, fmt.Errorf("parse metadata: %w", err)
	}
	return meta, nil
}

package auth

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadValidCredentials(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "creds.json")
	os.WriteFile(path, []byte(`{
		"credentials": [
			{"accessKeyId": "AKID1", "secretAccessKey": "SECRET1"},
			{"accessKeyId": "AKID2", "secretAccessKey": "SECRET2"}
		]
	}`), 0644)

	store, err := LoadCredentials(path)
	if err != nil {
		t.Fatalf("LoadCredentials: %v", err)
	}

	c, found := store.Lookup("AKID1")
	if !found {
		t.Fatal("AKID1 not found")
	}
	if c.SecretAccessKey != "SECRET1" {
		t.Errorf("SecretAccessKey = %q", c.SecretAccessKey)
	}

	c2, found := store.Lookup("AKID2")
	if !found {
		t.Fatal("AKID2 not found")
	}
	if c2.SecretAccessKey != "SECRET2" {
		t.Errorf("SecretAccessKey = %q", c2.SecretAccessKey)
	}
}

func TestLoadEmptyCredentials(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "creds.json")
	os.WriteFile(path, []byte(`{"credentials": []}`), 0644)

	_, err := LoadCredentials(path)
	if err == nil {
		t.Fatal("expected error for empty credentials")
	}
}

func TestLoadMissingFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "creds.json")
	os.WriteFile(path, []byte(`{"credentials": [{"accessKeyId": "AKID"}]}`), 0644)

	_, err := LoadCredentials(path)
	if err == nil {
		t.Fatal("expected error for missing secretAccessKey")
	}
}

func TestLookupNotFound(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "creds.json")
	os.WriteFile(path, []byte(`{"credentials": [{"accessKeyId": "AKID", "secretAccessKey": "SEC"}]}`), 0644)

	store, _ := LoadCredentials(path)
	_, found := store.Lookup("NONEXISTENT")
	if found {
		t.Fatal("should not find nonexistent key")
	}
}

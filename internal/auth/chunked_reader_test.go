package auth

import (
	"bytes"
	"io"
	"testing"
)

func TestChunkedReaderSingleChunk(t *testing.T) {
	// Format: {hex-size};chunk-signature={sig}\r\n{data}\r\n0;chunk-signature={sig}\r\n\r\n
	data := "5;chunk-signature=abc123\r\nhello\r\n0;chunk-signature=def456\r\n\r\n"
	reader := NewChunkedReader(bytes.NewReader([]byte(data)), "", "", "us-east-1", "s3", "")

	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != "hello" {
		t.Errorf("got %q, want \"hello\"", string(got))
	}
}

func TestChunkedReaderMultipleChunks(t *testing.T) {
	data := "5;chunk-signature=aaa\r\nhello\r\n6;chunk-signature=bbb\r\n world\r\n0;chunk-signature=ccc\r\n\r\n"
	reader := NewChunkedReader(bytes.NewReader([]byte(data)), "", "", "us-east-1", "s3", "")

	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != "hello world" {
		t.Errorf("got %q, want \"hello world\"", string(got))
	}
}

func TestChunkedReaderUnsigned(t *testing.T) {
	// Unsigned chunks have no signature extension
	data := "5\r\nhello\r\n0\r\n\r\n"
	reader := NewChunkedReader(bytes.NewReader([]byte(data)), "", "", "us-east-1", "s3", "")

	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != "hello" {
		t.Errorf("got %q, want \"hello\"", string(got))
	}
}

func TestChunkedReaderLargeChunk(t *testing.T) {
	// 1024 bytes of data
	payload := bytes.Repeat([]byte("X"), 1024)
	var buf bytes.Buffer
	buf.WriteString("400;chunk-signature=sig1\r\n") // 400 hex = 1024
	buf.Write(payload)
	buf.WriteString("\r\n0;chunk-signature=sig2\r\n\r\n")

	reader := NewChunkedReader(&buf, "", "", "us-east-1", "s3", "")
	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(got) != 1024 {
		t.Errorf("got %d bytes, want 1024", len(got))
	}
}

func TestParseHexUint(t *testing.T) {
	tests := []struct {
		input string
		want  uint64
	}{
		{"0", 0},
		{"5", 5},
		{"a", 10},
		{"ff", 255},
		{"400", 1024},
		{"10000", 65536},
	}
	for _, tt := range tests {
		got, err := parseHexUint([]byte(tt.input))
		if err != nil {
			t.Errorf("parseHexUint(%q): %v", tt.input, err)
			continue
		}
		if got != tt.want {
			t.Errorf("parseHexUint(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestParseChunkExtension(t *testing.T) {
	size, sig := parseChunkExtension([]byte("400;chunk-signature=abc123"))
	if string(size) != "400" {
		t.Errorf("size = %q", string(size))
	}
	if string(sig) != "abc123" {
		t.Errorf("sig = %q", string(sig))
	}

	// No signature
	size2, sig2 := parseChunkExtension([]byte("400"))
	if string(size2) != "400" {
		t.Errorf("size = %q", string(size2))
	}
	if sig2 != nil {
		t.Errorf("sig should be nil, got %q", string(sig2))
	}
}

func TestHashSHA256(t *testing.T) {
	got := HashSHA256([]byte(""))
	if got != EmptySHA256 {
		t.Errorf("HashSHA256(\"\") = %q, want %q", got, EmptySHA256)
	}
}

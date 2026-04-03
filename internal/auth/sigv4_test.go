package auth

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGetSigningKey(t *testing.T) {
	// AWS test vector: known inputs should produce deterministic output
	key := GetSigningKey("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "20130524", "us-east-1", "s3")
	if len(key) != 32 {
		t.Fatalf("signing key length = %d, want 32", len(key))
	}
}

func TestGetSignature(t *testing.T) {
	key := GetSigningKey("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "20130524", "us-east-1", "s3")
	sig := GetSignature(key, "test string to sign")
	if sig == "" {
		t.Fatal("empty signature")
	}
	if len(sig) != 64 {
		t.Fatalf("signature length = %d, want 64 hex chars", len(sig))
	}
}

func TestCompareSignatures(t *testing.T) {
	if !CompareSignatures("abc123", "abc123") {
		t.Error("identical signatures should match")
	}
	if CompareSignatures("abc123", "abc124") {
		t.Error("different signatures should not match")
	}
	if CompareSignatures("abc123", "abc12") {
		t.Error("different length should not match")
	}
}

func TestParseSignV4Valid(t *testing.T) {
	header := "AWS4-HMAC-SHA256 Credential=AKID/20240101/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"

	sv, err := ParseSignV4(header)
	if err != nil {
		t.Fatalf("ParseSignV4: %v", err)
	}
	if sv.Credential.AccessKey != "AKID" {
		t.Errorf("AccessKey = %q", sv.Credential.AccessKey)
	}
	if sv.Credential.Region != "us-east-1" {
		t.Errorf("Region = %q", sv.Credential.Region)
	}
	if sv.Credential.Service != "s3" {
		t.Errorf("Service = %q", sv.Credential.Service)
	}
	if len(sv.SignedHeaders) != 2 {
		t.Errorf("SignedHeaders = %v", sv.SignedHeaders)
	}
	if sv.Signature != "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890" {
		t.Errorf("Signature = %q", sv.Signature)
	}
}

func TestParseSignV4Malformed(t *testing.T) {
	tests := []string{
		"",
		"Basic abc",
		"AWS4-HMAC-SHA256",
		"AWS4-HMAC-SHA256 Credential=bad",
		"AWS4-HMAC-SHA256 Credential=a/b/c, SignedHeaders=host, Signature=abc",
	}
	for _, h := range tests {
		_, err := ParseSignV4(h)
		if err == nil {
			t.Errorf("expected error for %q", h)
		}
	}
}

func TestParseCredentialValue(t *testing.T) {
	cred, err := ParseCredentialValue("AKID/20240315/eu-west-1/s3/aws4_request")
	if err != nil {
		t.Fatalf("ParseCredentialValue: %v", err)
	}
	if cred.AccessKey != "AKID" {
		t.Errorf("AccessKey = %q", cred.AccessKey)
	}
	if cred.Region != "eu-west-1" {
		t.Errorf("Region = %q", cred.Region)
	}
}

func TestEncodePathSimple(t *testing.T) {
	if got := EncodePath("/bucket/key"); got != "/bucket/key" {
		t.Errorf("EncodePath simple = %q", got)
	}
}

func TestEncodePathSpecialChars(t *testing.T) {
	got := EncodePath("/bucket/hello world")
	if !strings.Contains(got, "%20") {
		t.Errorf("EncodePath should encode space: %q", got)
	}
}

func TestEncodePathUnicode(t *testing.T) {
	got := EncodePath("/bucket/日本語")
	if got == "/bucket/日本語" {
		t.Error("EncodePath should encode unicode characters")
	}
	if !strings.Contains(got, "%") {
		t.Errorf("encoded path should contain percent-encoding: %q", got)
	}
}

func TestGetCanonicalRequest(t *testing.T) {
	headers := make(http.Header)
	headers.Set("host", "examplebucket.s3.amazonaws.com")
	headers.Set("x-amz-date", "20130524T000000Z")

	cr := GetCanonicalRequest("GET", "/test.txt", "", headers, EmptySHA256)
	// Canonical request format:
	// METHOD\n
	// PATH\n
	// QUERY\n
	// header1:value\nheader2:value\n\n  (headers end with \n, then blank line)
	// signed-headers\n
	// payload
	if !strings.HasPrefix(cr, "GET\n/test.txt\n") {
		t.Errorf("canonical request should start with GET\\n/test.txt\\n, got: %q", cr[:30])
	}
	if !strings.HasSuffix(cr, EmptySHA256) {
		t.Error("canonical request should end with payload hash")
	}
	if !strings.Contains(cr, "host:") {
		t.Error("canonical request should contain host header")
	}
}

func TestGetStringToSign(t *testing.T) {
	date, _ := time.Parse(iso8601Format, "20130524T000000Z")
	sts := GetStringToSign("canonical-request", date, "20130524/us-east-1/s3/aws4_request")
	if !strings.HasPrefix(sts, SignV4Algorithm) {
		t.Error("string to sign should start with algorithm")
	}
	lines := strings.Split(sts, "\n")
	if len(lines) != 4 {
		t.Fatalf("expected 4 lines, got %d", len(lines))
	}
}

// Test full request signing and verification round-trip
func TestSignAndVerifyRoundTrip(t *testing.T) {
	dir := t.TempDir()
	credPath := filepath.Join(dir, "creds.json")
	os.WriteFile(credPath, []byte(`{"credentials":[{"accessKeyId":"test-access-key","secretAccessKey":"test-secret-key"}]}`), 0644)
	store, _ := LoadCredentials(credPath)

	accessKey := "test-access-key"
	secretKey := "test-secret-key"
	region := "us-east-1"
	service := "s3"
	now := time.Now().UTC()

	// Build a request
	req := httptest.NewRequest(http.MethodGet, "http://localhost:8333/test-bucket", nil)
	req.Header.Set("Host", "localhost:8333")
	req.Header.Set("X-Amz-Date", now.Format(iso8601Format))
	req.Header.Set("X-Amz-Content-Sha256", EmptySHA256)

	// Sign the request
	signedHeaders := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	extracted := extractSignedHeaders(signedHeaders, req)

	urlPath := req.URL.EscapedPath()
	queryStr := req.URL.Query().Encode()

	canonicalRequest := GetCanonicalRequest(req.Method, urlPath, queryStr, extracted, EmptySHA256)
	scope := GetScope(now, region, service)
	stringToSign := GetStringToSign(canonicalRequest, now, scope)
	signingKey := GetSigningKey(secretKey, now.Format(yyyymmdd), region, service)
	signature := GetSignature(signingKey, stringToSign)

	// Build Authorization header
	credentialStr := accessKey + "/" + now.Format(yyyymmdd) + "/" + region + "/" + service + "/aws4_request"
	authHeader := SignV4Algorithm + " Credential=" + credentialStr + ", SignedHeaders=" + strings.Join(signedHeaders, ";") + ", Signature=" + signature
	req.Header.Set("Authorization", authHeader)

	// Verify
	result, err := VerifyRequest(req, store, region)
	if err != nil {
		t.Fatalf("VerifyRequest: %v", err)
	}
	if result.AccessKeyID != accessKey {
		t.Errorf("AccessKeyID = %q", result.AccessKeyID)
	}
}

func TestClockSkewRejected(t *testing.T) {
	dir := t.TempDir()
	credPath := filepath.Join(dir, "creds.json")
	os.WriteFile(credPath, []byte(`{"credentials":[{"accessKeyId":"AKID","secretAccessKey":"SECRET"}]}`), 0644)
	store, _ := LoadCredentials(credPath)

	// Request from 20 minutes ago
	oldTime := time.Now().UTC().Add(-20 * time.Minute)

	req := httptest.NewRequest(http.MethodGet, "http://localhost:8333/bucket", nil)
	req.Header.Set("Host", "localhost:8333")
	req.Header.Set("X-Amz-Date", oldTime.Format(iso8601Format))
	req.Header.Set("X-Amz-Content-Sha256", EmptySHA256)

	signedHeaders := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	extracted := extractSignedHeaders(signedHeaders, req)
	canonicalRequest := GetCanonicalRequest(req.Method, "/bucket", "", extracted, EmptySHA256)
	scope := GetScope(oldTime, "us-east-1", "s3")
	stringToSign := GetStringToSign(canonicalRequest, oldTime, scope)
	signingKey := GetSigningKey("SECRET", oldTime.Format(yyyymmdd), "us-east-1", "s3")
	signature := GetSignature(signingKey, stringToSign)

	credStr := "AKID/" + oldTime.Format(yyyymmdd) + "/us-east-1/s3/aws4_request"
	authHeader := SignV4Algorithm + " Credential=" + credStr + ", SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=" + signature
	req.Header.Set("Authorization", authHeader)

	_, err := VerifyRequest(req, store, "us-east-1")
	if err == nil {
		t.Fatal("expected clock skew error")
	}
	if !strings.Contains(err.Error(), "skewed") {
		t.Errorf("error = %q, want clock skew", err.Error())
	}
}

func TestInvalidAccessKeyRejected(t *testing.T) {
	dir := t.TempDir()
	credPath := filepath.Join(dir, "creds.json")
	os.WriteFile(credPath, []byte(`{"credentials":[{"accessKeyId":"AKID","secretAccessKey":"SECRET"}]}`), 0644)
	store, _ := LoadCredentials(credPath)

	now := time.Now().UTC()
	req := httptest.NewRequest(http.MethodGet, "http://localhost:8333/bucket", nil)
	req.Header.Set("Host", "localhost:8333")
	req.Header.Set("X-Amz-Date", now.Format(iso8601Format))
	req.Header.Set("X-Amz-Content-Sha256", EmptySHA256)

	credStr := "WRONG-KEY/" + now.Format(yyyymmdd) + "/us-east-1/s3/aws4_request"
	authHeader := SignV4Algorithm + " Credential=" + credStr + ", SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=0000000000000000000000000000000000000000000000000000000000000000"
	req.Header.Set("Authorization", authHeader)

	_, err := VerifyRequest(req, store, "us-east-1")
	if err == nil {
		t.Fatal("expected invalid access key error")
	}
	if !strings.Contains(err.Error(), "invalid access key") {
		t.Errorf("error = %q", err.Error())
	}
}

func TestInvalidSignatureRejected(t *testing.T) {
	dir := t.TempDir()
	credPath := filepath.Join(dir, "creds.json")
	os.WriteFile(credPath, []byte(`{"credentials":[{"accessKeyId":"AKID","secretAccessKey":"SECRET"}]}`), 0644)
	store, _ := LoadCredentials(credPath)

	now := time.Now().UTC()
	req := httptest.NewRequest(http.MethodGet, "http://localhost:8333/bucket", nil)
	req.Header.Set("Host", "localhost:8333")
	req.Header.Set("X-Amz-Date", now.Format(iso8601Format))
	req.Header.Set("X-Amz-Content-Sha256", EmptySHA256)

	credStr := "AKID/" + now.Format(yyyymmdd) + "/us-east-1/s3/aws4_request"
	authHeader := SignV4Algorithm + " Credential=" + credStr + ", SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=badbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadb"
	req.Header.Set("Authorization", authHeader)

	_, err := VerifyRequest(req, store, "us-east-1")
	if err == nil {
		t.Fatal("expected signature mismatch")
	}
	if !strings.Contains(err.Error(), "signature does not match") {
		t.Errorf("error = %q", err.Error())
	}
}

func TestGetScope(t *testing.T) {
	date, _ := time.Parse(yyyymmdd, "20240101")
	scope := GetScope(date, "us-east-1", "s3")
	if scope != "20240101/us-east-1/s3/aws4_request" {
		t.Errorf("scope = %q", scope)
	}
}

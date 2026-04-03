package auth

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	SignV4Algorithm     = "AWS4-HMAC-SHA256"
	iso8601Format      = "20060102T150405Z"
	yyyymmdd           = "20060102"
	EmptySHA256        = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	UnsignedPayload    = "UNSIGNED-PAYLOAD"
	StreamingPayload   = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
	maxClockSkew       = 15 * time.Minute
)

type SignV4Values struct {
	Credential    CredentialHeader
	SignedHeaders []string
	Signature     string
}

type CredentialHeader struct {
	AccessKey string
	Date      time.Time
	Region    string
	Service   string
	Request   string
}

func (c CredentialHeader) GetScope() string {
	return strings.Join([]string{
		c.Date.Format(yyyymmdd),
		c.Region,
		c.Service,
		c.Request,
	}, "/")
}

type AuthResult struct {
	AccessKeyID string
	Credential  Credential
}

// VerifyRequest verifies an incoming HTTP request's SigV4 signature.
func VerifyRequest(r *http.Request, store *CredentialStore, region string) (*AuthResult, error) {
	if isPresigned(r) {
		return verifyPresigned(r, store, region)
	}
	return verifyHeader(r, store, region)
}

func isPresigned(r *http.Request) bool {
	return r.URL.Query().Get("X-Amz-Algorithm") != ""
}

func verifyHeader(r *http.Request, store *CredentialStore, region string) (*AuthResult, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, fmt.Errorf("missing Authorization header")
	}

	sv, err := ParseSignV4(authHeader)
	if err != nil {
		return nil, err
	}

	// Parse date
	t, err := parseRequestDate(r)
	if err != nil {
		return nil, err
	}

	// Check clock skew
	now := time.Now().UTC()
	if now.Sub(t) > maxClockSkew || t.Sub(now) > maxClockSkew {
		return nil, fmt.Errorf("request time too skewed")
	}

	// Lookup credentials
	cred, found := store.Lookup(sv.Credential.AccessKey)
	if !found {
		return nil, fmt.Errorf("invalid access key")
	}

	// Get payload hash
	hashedPayload := getContentSHA256(r)

	// Extract signed headers
	extractedHeaders := extractSignedHeaders(sv.SignedHeaders, r)

	// Build canonical request
	queryStr := r.URL.Query().Encode()
	urlPath := r.URL.EscapedPath()
	if urlPath == "" {
		urlPath = "/"
	}

	canonicalRequest := GetCanonicalRequest(r.Method, urlPath, queryStr, extractedHeaders, hashedPayload)
	scope := sv.Credential.GetScope()
	stringToSign := GetStringToSign(canonicalRequest, t, scope)
	signingKey := GetSigningKey(cred.SecretAccessKey, t.Format(yyyymmdd), sv.Credential.Region, sv.Credential.Service)
	calculatedSig := GetSignature(signingKey, stringToSign)

	if !CompareSignatures(calculatedSig, sv.Signature) {
		return nil, fmt.Errorf("signature does not match")
	}

	return &AuthResult{
		AccessKeyID: sv.Credential.AccessKey,
		Credential:  cred,
	}, nil
}

func verifyPresigned(r *http.Request, store *CredentialStore, region string) (*AuthResult, error) {
	query := r.URL.Query()

	algo := query.Get("X-Amz-Algorithm")
	if algo != SignV4Algorithm {
		return nil, fmt.Errorf("unsupported algorithm: %s", algo)
	}

	dateStr := query.Get("X-Amz-Date")
	if dateStr == "" {
		return nil, fmt.Errorf("missing X-Amz-Date")
	}
	t, err := time.Parse(iso8601Format, dateStr)
	if err != nil {
		return nil, fmt.Errorf("malformed date: %w", err)
	}

	expiresStr := query.Get("X-Amz-Expires")
	if expiresStr == "" {
		return nil, fmt.Errorf("missing X-Amz-Expires")
	}
	expires, err := strconv.ParseInt(expiresStr, 10, 64)
	if err != nil || expires < 0 || expires > 604800 {
		return nil, fmt.Errorf("invalid expires value")
	}
	if time.Now().UTC().After(t.Add(time.Duration(expires) * time.Second)) {
		return nil, fmt.Errorf("presigned request expired")
	}

	credStr := query.Get("X-Amz-Credential")
	credHeader, err := ParseCredentialValue(credStr)
	if err != nil {
		return nil, err
	}

	cred, found := store.Lookup(credHeader.AccessKey)
	if !found {
		return nil, fmt.Errorf("invalid access key")
	}

	signedHeaders := strings.Split(query.Get("X-Amz-SignedHeaders"), ";")
	providedSig := query.Get("X-Amz-Signature")

	hashedPayload := query.Get("X-Amz-Content-Sha256")
	if hashedPayload == "" {
		hashedPayload = UnsignedPayload
	}

	extractedHeaders := extractSignedHeaders(signedHeaders, r)

	// For presigned URLs, exclude X-Amz-Signature from query string
	queryForCanonical := make(url.Values)
	for k, v := range query {
		if k != "X-Amz-Signature" {
			queryForCanonical[k] = v
		}
	}
	queryStr := queryForCanonical.Encode()

	urlPath := r.URL.EscapedPath()
	if urlPath == "" {
		urlPath = "/"
	}

	canonicalRequest := GetCanonicalRequest(r.Method, urlPath, queryStr, extractedHeaders, hashedPayload)
	scope := credHeader.GetScope()
	stringToSign := GetStringToSign(canonicalRequest, t, scope)
	signingKey := GetSigningKey(cred.SecretAccessKey, t.Format(yyyymmdd), credHeader.Region, credHeader.Service)
	calculatedSig := GetSignature(signingKey, stringToSign)

	if !CompareSignatures(calculatedSig, providedSig) {
		return nil, fmt.Errorf("signature does not match")
	}

	return &AuthResult{
		AccessKeyID: credHeader.AccessKey,
		Credential:  cred,
	}, nil
}

// ParseSignV4 parses the Authorization header value.
func ParseSignV4(v4Auth string) (SignV4Values, error) {
	v4Auth = strings.ReplaceAll(v4Auth, " ", "")
	if v4Auth == "" {
		return SignV4Values{}, fmt.Errorf("empty auth header")
	}
	if !strings.HasPrefix(v4Auth, SignV4Algorithm) {
		return SignV4Values{}, fmt.Errorf("unsupported signature version")
	}

	v4Auth = strings.TrimPrefix(v4Auth, SignV4Algorithm)
	fields := strings.Split(v4Auth, ",")
	if len(fields) != 3 {
		return SignV4Values{}, fmt.Errorf("malformed auth header: expected 3 fields, got %d", len(fields))
	}

	credHeader, err := parseCredentialField(fields[0])
	if err != nil {
		return SignV4Values{}, err
	}

	signedHeaders, err := parseSignedHeadersField(fields[1])
	if err != nil {
		return SignV4Values{}, err
	}

	signature, err := parseSignatureField(fields[2])
	if err != nil {
		return SignV4Values{}, err
	}

	return SignV4Values{
		Credential:    credHeader,
		SignedHeaders: signedHeaders,
		Signature:     signature,
	}, nil
}

func parseCredentialField(s string) (CredentialHeader, error) {
	parts := strings.SplitN(strings.TrimSpace(s), "=", 2)
	if len(parts) != 2 || parts[0] != "Credential" {
		return CredentialHeader{}, fmt.Errorf("missing Credential tag")
	}
	return ParseCredentialValue(parts[1])
}

func ParseCredentialValue(s string) (CredentialHeader, error) {
	elems := strings.Split(strings.TrimSpace(s), "/")
	if len(elems) != 5 {
		return CredentialHeader{}, fmt.Errorf("malformed credential: expected 5 elements, got %d", len(elems))
	}
	date, err := time.Parse(yyyymmdd, elems[1])
	if err != nil {
		return CredentialHeader{}, fmt.Errorf("malformed credential date: %w", err)
	}
	return CredentialHeader{
		AccessKey: elems[0],
		Date:      date,
		Region:    elems[2],
		Service:   elems[3],
		Request:   elems[4],
	}, nil
}

func parseSignedHeadersField(s string) ([]string, error) {
	parts := strings.SplitN(strings.TrimSpace(s), "=", 2)
	if len(parts) != 2 || parts[0] != "SignedHeaders" {
		return nil, fmt.Errorf("missing SignedHeaders tag")
	}
	if parts[1] == "" {
		return nil, fmt.Errorf("empty signed headers")
	}
	return strings.Split(parts[1], ";"), nil
}

func parseSignatureField(s string) (string, error) {
	parts := strings.SplitN(strings.TrimSpace(s), "=", 2)
	if len(parts) != 2 || parts[0] != "Signature" {
		return "", fmt.Errorf("missing Signature tag")
	}
	if parts[1] == "" {
		return "", fmt.Errorf("empty signature")
	}
	return parts[1], nil
}

func parseRequestDate(r *http.Request) (time.Time, error) {
	if xamz := r.Header.Get("X-Amz-Date"); xamz != "" {
		return time.Parse(iso8601Format, xamz)
	}
	if ds := r.Header.Get("Date"); ds != "" {
		return http.ParseTime(ds)
	}
	return time.Time{}, fmt.Errorf("missing date header")
}

func getContentSHA256(r *http.Request) string {
	if v := r.Header.Get("X-Amz-Content-Sha256"); v != "" {
		return v
	}
	return EmptySHA256
}

func extractSignedHeaders(signedHeaders []string, r *http.Request) http.Header {
	extracted := make(http.Header)
	for _, h := range signedHeaders {
		lh := strings.ToLower(h)
		if lh == "host" {
			extracted.Set(lh, r.Host)
			continue
		}
		if vals, ok := r.Header[http.CanonicalHeaderKey(h)]; ok {
			extracted[lh] = vals
		}
	}
	return extracted
}

// GetCanonicalRequest builds the canonical request string.
func GetCanonicalRequest(method, urlPath, queryString string, signedHeaders http.Header, hashedPayload string) string {
	rawQuery := strings.ReplaceAll(queryString, "+", "%20")
	encoded := EncodePath(urlPath)
	return strings.Join([]string{
		method,
		encoded,
		rawQuery,
		getCanonicalHeaders(signedHeaders),
		getSignedHeadersList(signedHeaders),
		hashedPayload,
	}, "\n")
}

// GetStringToSign creates the string to sign.
func GetStringToSign(canonicalRequest string, t time.Time, scope string) string {
	hash := sha256.Sum256([]byte(canonicalRequest))
	return SignV4Algorithm + "\n" +
		t.Format(iso8601Format) + "\n" +
		scope + "\n" +
		hex.EncodeToString(hash[:])
}

// GetSigningKey computes the HMAC signing key chain.
func GetSigningKey(secretKey, dateStr, region, service string) []byte {
	date := sumHMAC([]byte("AWS4"+secretKey), []byte(dateStr))
	regionKey := sumHMAC(date, []byte(region))
	serviceKey := sumHMAC(regionKey, []byte(service))
	return sumHMAC(serviceKey, []byte("aws4_request"))
}

// GetSignature returns the hex-encoded HMAC-SHA256 signature.
func GetSignature(signingKey []byte, stringToSign string) string {
	return hex.EncodeToString(sumHMAC(signingKey, []byte(stringToSign)))
}

// CompareSignatures does constant-time comparison.
func CompareSignatures(sig1, sig2 string) bool {
	return subtle.ConstantTimeCompare([]byte(sig1), []byte(sig2)) == 1
}

// GetScope builds the credential scope string.
func GetScope(t time.Time, region, service string) string {
	return strings.Join([]string{
		t.Format(yyyymmdd),
		region,
		service,
		"aws4_request",
	}, "/")
}

func sumHMAC(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func getCanonicalHeaders(headers http.Header) string {
	// Collect and sort header keys
	var keys []string
	vals := make(http.Header)
	for k, vv := range headers {
		lk := strings.ToLower(k)
		vals[lk] = vv
		keys = append(keys, lk)
	}
	sort.Strings(keys)

	var buf bytes.Buffer
	for _, k := range keys {
		buf.WriteString(k)
		buf.WriteByte(':')
		for i, v := range vals[k] {
			if i > 0 {
				buf.WriteByte(',')
			}
			buf.WriteString(trimAll(v))
		}
		buf.WriteByte('\n')
	}
	return buf.String()
}

func getSignedHeadersList(headers http.Header) string {
	var keys []string
	for k := range headers {
		keys = append(keys, strings.ToLower(k))
	}
	sort.Strings(keys)
	return strings.Join(keys, ";")
}

func trimAll(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

var reservedObjectNames = regexp.MustCompile("^[a-zA-Z0-9-_.~/]+$")

// EncodePath encodes the URL path with proper percent-encoding for SigV4.
func EncodePath(pathName string) string {
	if reservedObjectNames.MatchString(pathName) {
		return pathName
	}
	var buf strings.Builder
	for _, r := range pathName {
		if ('A' <= r && r <= 'Z') || ('a' <= r && r <= 'z') || ('0' <= r && r <= '9') {
			buf.WriteRune(r)
		} else {
			switch r {
			case '-', '_', '.', '~', '/':
				buf.WriteRune(r)
			default:
				runeLen := utf8.RuneLen(r)
				if runeLen < 0 {
					return pathName
				}
				u := make([]byte, runeLen)
				utf8.EncodeRune(u, r)
				for _, b := range u {
					buf.WriteString("%" + strings.ToUpper(hex.EncodeToString([]byte{b})))
				}
			}
		}
	}
	return buf.String()
}

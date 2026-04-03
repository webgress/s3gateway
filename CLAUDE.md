# S3 Gateway — Build Instructions for Claude

You are building a production-quality S3-compatible gateway in Go. This file contains everything you need. Do NOT ask the user any questions — all decisions are made here.

## What to Build

A single Go binary that exposes an S3-compatible HTTP API and stores objects as plain files on the local filesystem. Standard S3 clients (aws-cli, boto3, AWS Go SDK v2) must work without special configuration beyond `--endpoint-url`.

- **Module**: `github.com/webgress/s3gateway`
- **License**: Apache 2.0 (already in repo)
- **Go version**: 1.22+ (use whatever is installed)
- **External dependencies**: only `github.com/gorilla/mux` v1.8.1 and `github.com/google/uuid`

## Repository Layout

```
cmd/s3gateway/main.go                          # Entry point
internal/
  server/server.go                              # HTTP/HTTPS server, graceful shutdown
  server/router.go                              # gorilla/mux route registration, middleware
  auth/credentials.go                           # Load static credentials from JSON
  auth/credentials_test.go
  auth/sigv4.go                                 # AWS SigV4 signature verification
  auth/sigv4_test.go
  auth/chunked_reader.go                        # Chunked transfer reader for streaming uploads
  auth/chunked_reader_test.go
  handler/bucket.go                             # CreateBucket, HeadBucket, DeleteBucket, ListBuckets
  handler/bucket_test.go
  handler/object.go                             # PutObject, GetObject, HeadObject, DeleteObject
  handler/object_test.go
  handler/list.go                               # ListObjectsV2
  handler/list_test.go
  handler/multipart.go                          # Multipart upload operations
  handler/multipart_test.go
  storage/filesystem.go                         # All filesystem I/O
  storage/filesystem_test.go
  storage/metadata.go                           # .s3meta JSON sidecar files
  storage/metadata_test.go
  s3response/xml.go                             # S3 XML response structs
  s3response/errors.go                          # S3 error codes and responses
  s3response/errors_test.go
config/example-credentials.json                 # Example config
scripts/test-s3.sh                              # aws-cli integration tests
scripts/test-s3-boto3.py                        # boto3 integration tests
scripts/test-s3-go/main.go                      # Go SDK integration tests (separate go.mod)
scripts/test-s3-go/go.mod
scripts/test-s3-go/go.sum
Makefile
README.md
TESTING.md
```

## CLI Flags

```
-port           int     HTTP listen port (default: 8333)
-data-dir       string  Root directory for object storage (required)
-credentials    string  Path to credentials JSON (default: credentials.json)
-tls-cert       string  TLS certificate file (enables HTTPS)
-tls-key        string  TLS private key file
-region         string  AWS region for SigV4 (default: us-east-1)
-log-level      string  Log level: debug, info, warn, error (default: info)
```

## Credentials Config Format

```json
{
    "credentials": [
        {
            "accessKeyId": "test-access-key",
            "secretAccessKey": "test-secret-key"
        }
    ]
}
```

## Storage Layout on Disk

```
{data-dir}/
  {bucket}/
    {key}                    # actual file content
    {key}.s3meta             # JSON metadata sidecar
  .multipart/
    {upload-id}/
      meta.json              # {bucket, key, upload_id, initiated, content_type, metadata}
      parts/
        00001                # part data (zero-padded part numbers)
        00002
```

## S3 Operations to Implement

### Bucket
- **CreateBucket**: PUT /{bucket} → create directory, validate S3 naming rules
- **HeadBucket**: HEAD /{bucket} → check directory exists, 200 or 404
- **DeleteBucket**: DELETE /{bucket} → remove empty directory, 204 or 409 BucketNotEmpty
- **ListBuckets**: GET / → list directories, return XML

### Object
- **PutObject**: PUT /{bucket}/{key} → stream body to temp file, rename atomically, write .s3meta
- **GetObject**: GET /{bucket}/{key} → stream file to response, set headers from .s3meta
- **HeadObject**: HEAD /{bucket}/{key} → return headers from .s3meta, no body
- **DeleteObject**: DELETE /{bucket}/{key} → remove file and .s3meta, always 204

### Listing
- **ListObjectsV2**: GET /{bucket}?list-type=2 → filepath.WalkDir, filter by prefix/delimiter, paginate with continuation-token, max-keys (default 1000)

### Multipart Upload
- **CreateMultipartUpload**: POST /{bucket}/{key}?uploads → generate UUID, create .multipart/{id}/ dir
- **UploadPart**: PUT /{bucket}/{key}?partNumber=N&uploadId=X → stream part to .multipart/{id}/parts/{N}
- **CompleteMultipartUpload**: POST /{bucket}/{key}?uploadId=X → validate parts, assemble by sequential copy, compute composite ETag, cleanup
- **AbortMultipartUpload**: DELETE /{bucket}/{key}?uploadId=X → os.RemoveAll the upload dir
- **ListMultipartUploads**: GET /{bucket}?uploads → scan .multipart/ dir

## SigV4 Authentication

Port the verification logic from the SeaweedFS reference (see below). Our simplified version needs:

1. **Header-based auth**: Parse `Authorization: AWS4-HMAC-SHA256 Credential=.../.../.../s3/aws4_request, SignedHeaders=..., Signature=...`
2. **Presigned URL auth**: Parse `X-Amz-Algorithm`, `X-Amz-Credential`, `X-Amz-Date`, `X-Amz-Expires`, `X-Amz-SignedHeaders`, `X-Amz-Signature` query params
3. **Streaming chunked payload**: Handle `x-amz-content-sha256: STREAMING-AWS4-HMAC-SHA256-PAYLOAD` — aws-cli uses this for `s3 cp`. Read chunked format: `{hex-size};chunk-signature={sig}\r\n{data}\r\n`
4. **Unsigned payload**: Accept `x-amz-content-sha256: UNSIGNED-PAYLOAD`
5. **Clock skew**: Reject requests >15 minutes old

Core functions needed:
- `parseSignV4(authHeader) → credential, signedHeaders, signature`
- `getCanonicalRequest(method, path, queryString, headers, payloadHash) → string`
- `getStringToSign(canonicalRequest, time, scope) → string`
- `getSigningKey(secretKey, date, region, service) → []byte` (HMAC chain)
- `getSignature(signingKey, stringToSign) → hex string`
- Constant-time signature comparison

**Reference files** (Apache 2.0, in ~/git/seaweedfs/):
- `weed/s3api/auth_signature_v4.go` — core SigV4 logic, parseSignV4, canonical request, signing key, signature computation
- `weed/s3api/chunked_reader_v4.go` — chunked transfer reader
- `weed/s3api/s3err/s3api_errors.go` — error code mapping
- `weed/s3api/s3api_server.go` — router registration pattern (line 572+)
- `weed/s3api/s3bucket/s3api_bucket.go` — bucket name validation

You may read and reference these files. They are Apache 2.0 licensed.

## Critical Implementation Details

### 1. Atomic Writes
Always write to `{path}.tmp.{uuid}`, then `os.Rename()`. This ensures crash safety.

### 2. Streaming I/O
Use `io.CopyBuffer` with a 256KB buffer. Use `io.TeeReader` to compute MD5 while streaming to disk. NEVER read entire file into memory.

### 3. ETag Format
- Single-part upload: `"hex-md5"` (with quotes, they are part of the value)
- Multipart: `"hex(md5(binary_md5_1 + binary_md5_2 + ...))-N"` where N = number of parts, binary_md5 = raw 16-byte digest

### 4. Chunked Upload Content-Length
When `x-amz-content-sha256: STREAMING-AWS4-HMAC-SHA256-PAYLOAD`, the `Content-Length` header is the chunked-encoded size (larger). The actual content size is in `x-amz-decoded-content-length`.

### 5. Route Registration Order (CRITICAL)
Multipart query-parameterized routes MUST come before plain object routes. Object routes before bucket routes. Use `/{object:(?s).+}` pattern ((?s) matches newlines).

```
1. UploadPart:      PUT    /{bucket}/{object}?partNumber=N&uploadId=X
2. CompleteMultipart: POST /{bucket}/{object}?uploadId=X
3. CreateMultipart: POST   /{bucket}/{object}?uploads
4. AbortMultipart:  DELETE /{bucket}/{object}?uploadId=X
5. ListParts:       GET    /{bucket}/{object}?uploadId=X
6. ListMultipartUploads: GET /{bucket}?uploads
7. HeadObject:      HEAD   /{bucket}/{object}
8. GetObject:       GET    /{bucket}/{object}
9. PutObject:       PUT    /{bucket}/{object}
10. DeleteObject:   DELETE /{bucket}/{object}
11. ListObjectsV2:  GET    /{bucket}
12. HeadBucket:     HEAD   /{bucket}
13. CreateBucket:   PUT    /{bucket}
14. DeleteBucket:   DELETE /{bucket}
15. ListBuckets:    GET    /
```

### 6. XML Namespaces
- Success responses: use `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ElementName"`
- Error responses: NO namespace on `<Error>` element

### 7. S3 Error Response Format
```xml
<?xml version="1.0" encoding="UTF-8"?>
<Error>
  <Code>NoSuchKey</Code>
  <Message>The specified key does not exist.</Message>
  <Resource>/bucket/key</Resource>
  <RequestId>uuid</RequestId>
</Error>
```

### 8. Path Traversal Prevention
Reject keys containing `..`, null bytes, or that resolve outside the bucket directory after `filepath.Clean`.

### 9. Bucket Name Validation (S3 Rules)
- Length 3-63 chars
- Only lowercase letters, numbers, dots, hyphens
- Must start/end with letter or number
- No adjacent periods, not an IP address
- No `xn--` prefix, no `-s3alias` suffix

### 10. Health Check
GET /healthz → 200 OK with body `{"status":"ok"}`

### 11. Logging
Use `log/slog` with JSON handler. Log every request: method, path, status, duration_ms, remote_addr, content_length.

### 12. Common Response Headers
Every response should include: `x-amz-request-id` (UUID), `Server: S3Gateway`

## Implementation Order

Execute phases in this order. After each phase, run `go vet ./...` and `go test ./... -race` and fix any issues before proceeding.

1. **Phase 1**: Project skeleton — go.mod, directories, Makefile, main.go
2. **Phase 2**: Storage layer — filesystem.go, metadata.go + tests → verify `go test ./internal/storage/...`
3. **Phase 3**: Auth — credentials.go, sigv4.go, chunked_reader.go + tests → verify `go test ./internal/auth/...`
4. **Phase 4**: S3 response layer — xml.go, errors.go + tests → verify `go test ./internal/s3response/...`
5. **Phase 5**: Server + routing — server.go, router.go
6. **Phase 6**: Handlers — bucket.go, object.go, list.go, multipart.go + tests → verify `go test ./...`
7. **Phase 7**: Integration tests — install aws-cli/boto3, start server, run test scripts
8. **Phase 8**: Documentation — README.md, TESTING.md
9. **Phase 9**: Commit and push

## Integration Testing

### Install Dependencies
```bash
# aws-cli
pip3 install awscli boto3 || pip install awscli boto3

# Go SDK test module
cd scripts/test-s3-go && go mod tidy && cd ../..
```

### Run Tests
```bash
# Start server in background
./bin/s3gateway -data-dir /tmp/s3gateway-test -credentials config/example-credentials.json &
SERVER_PID=$!
sleep 2

# Run aws-cli tests
bash scripts/test-s3.sh

# Run boto3 tests
python3 scripts/test-s3-boto3.py

# Run Go SDK tests
cd scripts/test-s3-go && go run . && cd ../..

# Stop server
kill $SERVER_PID
```

### Test Coverage Requirements
- Bucket CRUD
- Object CRUD (small files)
- Large file multipart upload (100MB via aws-cli, 15MB via boto3)
- Unicode keys
- Nested keys with delimiter listing
- User metadata round-trip
- Error conditions (NoSuchBucket, NoSuchKey, SignatureDoesNotMatch)
- Concurrent operations (Go SDK test)

## README.md Content Guide

Write a clean README. Do NOT mention "appliance" anywhere. Frame it as:
> "Lightweight, S3-compatible object storage gateway for local filesystem storage. Single binary, zero external dependencies, stores objects as plain files."

Sections: Overview, Features, Quick Start, Configuration, Supported Operations, Storage Layout, TLS Setup, Examples, License.

## TESTING.md Content Guide

Write a test plan document for a human engineering team. Sections:

1. **Unit Tests** — how to run, what they cover
2. **Integration Tests** — setup, the three test scripts, what they validate
3. **Performance Testing** — procedures for: 10GB file upload/download, concurrent uploads, throughput measurement with `dd` + `aws s3 cp`
4. **Edge Case Checklist** — unicode, empty files, deep paths, special chars, max key length
5. **Reliability Testing** — power-pull test (kill -9 during upload, verify no corruption), disk-full test, restart-during-multipart test
6. **S3 Client Compatibility Matrix** — aws-cli versions to test, boto3 versions, Go SDK versions, rclone
7. **Monitoring** — what to watch in logs, disk space, file descriptors
8. **Known Limitations** — what we don't implement (versioning, ACLs, lifecycle, etc.)

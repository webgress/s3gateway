# S3 Gateway — Test Plan

## 1. Unit Tests

### Running

```bash
go test ./... -race -v
```

### Coverage by Package

| Package | Tests | Coverage |
|---------|-------|----------|
| `internal/storage` | 37 | Bucket CRUD, object CRUD, listing, multipart, path security, concurrency |
| `internal/auth` | 26 | Credentials loading, SigV4 signing/verification, chunked reader, clock skew |
| `internal/s3response` | 7 | Error codes, XML serialization, namespaces |
| `internal/handler` | 25 | HTTP handler round-trips for all operations |

### What They Cover

- **Storage**: Create/delete/list buckets, put/get/head/delete objects, streaming I/O, metadata sidecars, multipart upload lifecycle, path traversal prevention, unicode keys, concurrent access
- **Auth**: Credential file parsing, SigV4 signature computation and verification, presigned URL validation, clock skew rejection, malformed header handling
- **S3Response**: Error code to HTTP status mapping, XML namespace correctness (S3 namespace on success responses, no namespace on Error), serialization of all response types
- **Handler**: Full HTTP request/response cycle for each operation via httptest

## 2. Integration Tests

### Prerequisites

```bash
pip3 install awscli boto3
cd scripts/test-s3-go && go mod tidy && cd ../..
```

### Running

```bash
# Start the server
./bin/s3gateway -data-dir /tmp/s3gateway-test -credentials config/example-credentials.json &
sleep 2

# AWS CLI tests (24 tests)
bash scripts/test-s3.sh

# boto3 tests (18 tests)
python3 scripts/test-s3-boto3.py

# Go SDK tests (8 tests)
cd scripts/test-s3-go && go run . && cd ../..

# Stop server
pkill -f s3gateway
```

### What They Validate

- **aws-cli**: Bucket CRUD, object upload/download, unicode keys, nested keys, delimiter listing, user metadata, large file multipart upload (10MB), error conditions
- **boto3**: Same operations via Python SDK, 15MB multipart upload, metadata round-trip, error code verification
- **Go SDK**: Basic operations, concurrent uploads (10 goroutines), 5MB file integrity check

## 3. Performance Testing

### Large File Upload/Download

```bash
# Generate a 10GB test file
dd if=/dev/urandom of=/tmp/test-10gb.bin bs=1M count=10240

# Upload
time aws --endpoint-url http://localhost:8333 s3 cp /tmp/test-10gb.bin s3://perf-bucket/10gb.bin

# Download
time aws --endpoint-url http://localhost:8333 s3 cp s3://perf-bucket/10gb.bin /tmp/test-10gb-dl.bin

# Verify
md5sum /tmp/test-10gb.bin /tmp/test-10gb-dl.bin
```

### Concurrent Upload Throughput

```bash
# Upload 100 x 10MB files concurrently
for i in $(seq 1 100); do
    aws --endpoint-url http://localhost:8333 s3 cp /tmp/test-10mb.bin s3://perf-bucket/file-$i.bin &
done
wait
```

### Throughput with dd

```bash
# Measure raw write throughput
dd if=/dev/zero bs=1M count=1024 | aws --endpoint-url http://localhost:8333 s3 cp - s3://perf-bucket/zeros.bin

# Measure raw read throughput
aws --endpoint-url http://localhost:8333 s3 cp s3://perf-bucket/zeros.bin - | dd of=/dev/null bs=1M
```

## 4. Edge Case Checklist

- [ ] Empty file (0 bytes) upload and download
- [ ] Unicode keys (CJK, emoji, accented characters)
- [ ] Keys with spaces
- [ ] Keys with special characters: `!@#$%^&*()+=`
- [ ] Deeply nested keys: `a/b/c/d/e/f/g/h/i/j/deep.txt`
- [ ] Key at maximum S3 length (1024 bytes)
- [ ] Bucket names at min (3 chars) and max (63 chars) length
- [ ] Adjacent dots in bucket name (rejected)
- [ ] IP address as bucket name (rejected)
- [ ] xn-- prefix bucket name (rejected)
- [ ] Path traversal attempts: `../`, `..%2F`, null bytes
- [ ] Overwriting an existing object
- [ ] Deleting a non-existent object (should return 204)
- [ ] Listing an empty bucket
- [ ] ListObjectsV2 with max-keys=0

## 5. Reliability Testing

### Power-Pull Test (Kill During Upload)

```bash
# Start a large upload
aws --endpoint-url http://localhost:8333 s3 cp /tmp/test-1gb.bin s3://test-bucket/crash.bin &
UPLOAD_PID=$!
sleep 2
kill -9 $UPLOAD_PID

# Verify: no partial files, no corruption
ls -la /data/s3/test-bucket/
# Should NOT have crash.bin (atomic write uses temp + rename)
```

### Disk-Full Test

```bash
# Create a small tmpfs
sudo mount -t tmpfs -o size=10M tmpfs /tmp/s3-smalldisk
./bin/s3gateway -data-dir /tmp/s3-smalldisk -credentials config/example-credentials.json &

# Try to upload more than 10MB
dd if=/dev/urandom of=/tmp/test-20mb.bin bs=1M count=20
aws --endpoint-url http://localhost:8333 s3 cp /tmp/test-20mb.bin s3://test/big.bin
# Should return error, not crash
```

### Restart During Multipart

```bash
# Start multipart upload
UPLOAD_ID=$(aws --endpoint-url http://localhost:8333 s3api create-multipart-upload --bucket test --key restart.bin --query UploadId --output text)
aws --endpoint-url http://localhost:8333 s3api upload-part --bucket test --key restart.bin --upload-id $UPLOAD_ID --part-number 1 --body /tmp/part1.bin

# Kill and restart server
pkill -f s3gateway
./bin/s3gateway -data-dir /data/s3 -credentials config/example-credentials.json &

# Upload should still be listable and completable
aws --endpoint-url http://localhost:8333 s3api list-multipart-uploads --bucket test
```

## 6. S3 Client Compatibility Matrix

| Client | Version | Status |
|--------|---------|--------|
| aws-cli v1 | 1.44+ | Tested, passing |
| boto3 | 1.42+ | Tested, passing |
| AWS Go SDK v2 | 1.30+ | Tested, passing |
| rclone | | Not tested — expected to work with `--s3-provider Other` |
| MinIO Client (mc) | | Not tested — expected to work |
| s3cmd | | Not tested |

## 7. Monitoring

### What to Watch in Logs

- `"status":5xx` — Internal server errors
- `"status":403` — Authentication failures (clock skew, bad credentials)
- `"duration_ms"` > 30000 — Slow requests (may indicate disk I/O issues)
- `"method":"PUT"` with `"content_length"` > 5GB — Very large uploads

### System Resources

- **Disk space**: `df -h {data-dir}` — objects stored as plain files
- **File descriptors**: `ls /proc/$(pgrep s3gateway)/fd | wc -l` — one per concurrent request
- **Memory**: Should stay flat regardless of file size (streaming I/O)

## 8. Known Limitations

The following S3 features are **not implemented**:

- Versioning
- ACLs and bucket policies
- Lifecycle rules
- Cross-region replication
- Server-side encryption (SSE)
- Object locking / legal hold
- Tagging
- CORS configuration
- Bucket notifications
- Select (SQL queries on objects)
- Batch operations
- Virtual-hosted-style addressing (only path-style)
- DeleteObjects (batch delete)
- CopyObject
- ListParts pagination
- Per-chunk signature verification in streaming uploads (seed signature is verified)

Note: Go's net/http canonicalizes HTTP header names, so user metadata keys like `x-amz-meta-color` will be returned as `X-Amz-Meta-Color`. Most S3 SDKs handle this correctly.

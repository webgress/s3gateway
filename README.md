# S3 Gateway

Lightweight, S3-compatible object storage gateway for local filesystem storage. Single binary, zero external dependencies, stores objects as plain files.

## Features

- Full S3-compatible HTTP API (path-style)
- AWS SigV4 authentication
- Streaming I/O with 256KB buffers — never loads files into memory
- Atomic writes using temp files + rename
- Multipart upload support
- ListObjectsV2 with prefix, delimiter, and pagination
- Metadata sidecar files (.s3meta) for content-type, ETag, user metadata
- Structured JSON logging via `log/slog`
- TLS support
- Graceful shutdown
- Works with aws-cli, boto3, AWS Go SDK v2, and any S3-compatible client

## Quick Start

```bash
# Build
make build

# Run
./bin/s3gateway -data-dir /data/s3 -credentials config/example-credentials.json

# Test with aws-cli
export AWS_ACCESS_KEY_ID=test-access-key
export AWS_SECRET_ACCESS_KEY=test-secret-key
aws --endpoint-url http://localhost:8333 s3 mb s3://my-bucket
aws --endpoint-url http://localhost:8333 s3 cp myfile.txt s3://my-bucket/
aws --endpoint-url http://localhost:8333 s3 ls s3://my-bucket/
```

## Configuration

### CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-port` | 8333 | HTTP listen port |
| `-data-dir` | (required) | Root directory for object storage |
| `-credentials` | credentials.json | Path to credentials JSON |
| `-tls-cert` | | TLS certificate file (enables HTTPS) |
| `-tls-key` | | TLS private key file |
| `-region` | us-east-1 | AWS region for SigV4 |
| `-log-level` | info | Log level: debug, info, warn, error |

### Credentials File

```json
{
    "credentials": [
        {
            "accessKeyId": "your-access-key",
            "secretAccessKey": "your-secret-key"
        }
    ]
}
```

Multiple credentials can be configured for different users/applications.

## Supported Operations

### Bucket Operations
- `PUT /{bucket}` — CreateBucket
- `HEAD /{bucket}` — HeadBucket
- `DELETE /{bucket}` — DeleteBucket
- `GET /` — ListBuckets

### Object Operations
- `PUT /{bucket}/{key}` — PutObject (streaming, with Content-Type and x-amz-meta-* support)
- `GET /{bucket}/{key}` — GetObject (with Range request support)
- `HEAD /{bucket}/{key}` — HeadObject
- `DELETE /{bucket}/{key}` — DeleteObject

### Listing
- `GET /{bucket}?list-type=2` — ListObjectsV2 (prefix, delimiter, max-keys, continuation-token, start-after)

### Multipart Upload
- `POST /{bucket}/{key}?uploads` — CreateMultipartUpload
- `PUT /{bucket}/{key}?partNumber=N&uploadId=X` — UploadPart
- `POST /{bucket}/{key}?uploadId=X` — CompleteMultipartUpload
- `DELETE /{bucket}/{key}?uploadId=X` — AbortMultipartUpload
- `GET /{bucket}?uploads` — ListMultipartUploads

### Other
- `GET /healthz` — Health check endpoint (no auth required)

## Storage Layout

Objects are stored as plain files on the filesystem:

```
{data-dir}/
  {bucket}/
    {key}                    # actual file content
    {key}.s3meta             # JSON metadata sidecar
  .multipart/
    {upload-id}/
      meta.json              # upload metadata
      parts/
        00001                # part data files
        00002
```

## TLS Setup

To enable HTTPS:

```bash
# Generate self-signed cert for testing
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes

# Run with TLS
./bin/s3gateway -data-dir /data/s3 -credentials credentials.json -tls-cert cert.pem -tls-key key.pem
```

Then use `--endpoint-url https://localhost:8333 --no-verify-ssl` with aws-cli.

## Examples

### boto3

```python
import boto3
from botocore.config import Config

s3 = boto3.client(
    "s3",
    endpoint_url="http://localhost:8333",
    aws_access_key_id="test-access-key",
    aws_secret_access_key="test-secret-key",
    config=Config(s3={"addressing_style": "path"}),
)

s3.create_bucket(Bucket="my-bucket")
s3.put_object(Bucket="my-bucket", Key="hello.txt", Body=b"Hello, World!")
resp = s3.get_object(Bucket="my-bucket", Key="hello.txt")
print(resp["Body"].read())
```

### AWS Go SDK v2

```go
cfg, _ := config.LoadDefaultConfig(ctx,
    config.WithRegion("us-east-1"),
    config.WithCredentialsProvider(
        credentials.NewStaticCredentialsProvider("test-access-key", "test-secret-key", ""),
    ),
)
client := s3.NewFromConfig(cfg, func(o *s3.Options) {
    o.BaseEndpoint = aws.String("http://localhost:8333")
    o.UsePathStyle = true
})
```

## License

Apache 2.0

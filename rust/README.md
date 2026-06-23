# s3gateway-rs

A max-throughput, S3-compatible object storage gateway in Rust — thread-per-core,
NIC-offloaded TLS (kTLS), and a Direct-IO storage path, storing objects as plain
files on the local filesystem.

## Overview

`s3gateway-rs` exposes an S3-compatible HTTP API and persists objects as ordinary
files on disk. Standard S3 clients (aws-cli, boto3, the AWS Go SDK) work against
it with nothing more than `--endpoint-url`.

It is a separate, performance-focused reimplementation of the Go gateway that
lives in the repository root. The two are independent binaries and share the same
on-disk conventions (a file per object plus a `.s3meta` JSON sidecar), so a data
directory written by one is readable by the other for the operations both support.

How it differs from the Go implementation:

- **Scope is intentionally narrow.** The hot path is GET / PUT / LIST. Bucket
  operations and multipart exist so real S3 clients work end to end, not as a
  goal in themselves. There is no broad feature surface beyond that.
- **Multipart objects are not reassembled on write.** Parts are kept on disk and
  the completed object's sidecar carries an ordered part manifest; the object is
  reassembled on the fly during GET. This removes a full data rewrite at
  `CompleteMultipartUpload` time.
- **The runtime is built for one machine profile.** It uses a thread-per-core,
  shared-nothing model, kernel-TLS offload to a SmartNIC, and a Direct-IO storage
  pool. These choices target a specific high-throughput box rather than broad
  portability; on commodity hardware it still runs (with automatic fallbacks),
  but the design payoff is on the target profile below.

**Target hardware profile.** The design assumes, and is tuned for:

- 12-core Intel Xeon Silver 4310 (single NUMA node)
- NVIDIA/Mellanox ConnectX-7 NIC (80 Gbps verified, kTLS hardware offload capable)
- Encrypted ZFS (native AES) on a 24-NVMe RaidZ3 pool

## Why it's fast

- **Thread-per-core, shared-nothing.** One pinned current-thread tokio runtime
  per core (`--workers`, default = CPU count), each with its own
  `SO_REUSEPORT` listener. The kernel load-balances accepts across the per-core
  listeners; connections never migrate between cores, so there is no cross-core
  locking, no work-stealing, and minimal cache-line bouncing.
- **kTLS NIC offload.** TLS records are encrypted/decrypted by the ConnectX-7
  inline, off the CPU. After the rustls handshake the socket is handed to the
  kernel TLS stack (`ktls` crate); bulk crypto leaves the application path
  entirely. Software fallback stays available if the kernel/NIC can't offload.
- **Direct IO.** The storage path uses `O_DIRECT` with page-aligned buffers,
  bypassing the page cache and the ARC→userspace copy on the read side. It falls
  back to buffered IO automatically on filesystems that reject `O_DIRECT`.
- **One-pass MD5.** PUT and UploadPart compute the S3 ETag in a single
  read→`md5.update`→write loop over a reused aligned buffer. The payload is never
  fully held in memory, and the byte stream is touched by the CPU exactly once.
  GET requires no re-hash.
- **Multipart reassemble-on-read.** Completing a multipart upload writes a
  manifest, not a concatenated file — no write-time data rewrite. GET streams the
  part files back-to-back as one logical body.

## Quick Start

### Build

```bash
cd rust
cargo build --release
# binary at target/release/s3gateway-rs
```

### Run (plaintext — local testing)

```bash
cat > credentials.json <<'EOF'
{"credentials":[{"accessKeyId":"test-access-key","secretAccessKey":"test-secret-key"}]}
EOF

./target/release/s3gateway-rs \
  --data-dir /srv/s3data \
  --credentials credentials.json \
  --port 8333
```

### Run (TLS + kTLS — production)

```bash
./target/release/s3gateway-rs \
  --data-dir /srv/s3data \
  --credentials credentials.json \
  --port 8443 \
  --tls-cert /etc/s3gateway/tls/fullchain.pem \
  --tls-key  /etc/s3gateway/tls/privkey.pem \
  --ktls true \
  --workers 12
```

See [TUNING.md](TUNING.md) for the full bring-up on the target box (ZFS settings,
kTLS verification, IRQ affinity, benchmarking) and [DESIGN.md](DESIGN.md) for the
architecture rationale.

## Configuration

### CLI flags

| Flag            | Type   | Default           | Description                                                        |
| --------------- | ------ | ----------------- | ------------------------------------------------------------------ |
| `--port`        | int    | `8333`            | HTTP/HTTPS listen port.                                            |
| `--data-dir`    | string | (required)        | Root directory for object storage.                                 |
| `--credentials` | string | `credentials.json`| Path to the credentials JSON.                                     |
| `--tls-cert`    | string | (none)            | TLS certificate file. Enables HTTPS (requires `--tls-key`).        |
| `--tls-key`     | string | (none)            | TLS private key file.                                              |
| `--region`      | string | `us-east-1`       | AWS region used for SigV4 verification.                            |
| `--log-level`   | string | `info`            | `debug`, `info`, `warn`, or `error`.                               |
| `--workers`     | int    | num CPUs          | Number of pinned per-core tokio runtimes (thread-per-core count).  |
| `--ktls`        | bool   | `true`            | Use kernel-TLS offload. When `false`, stays in userspace rustls.   |

TLS is active only when both `--tls-cert` and `--tls-key` are supplied.

### Credentials format

```json
{
  "credentials": [
    { "accessKeyId": "test-access-key", "secretAccessKey": "test-secret-key" }
  ]
}
```

Multiple credentials may be listed; each is looked up by access key id during
SigV4 verification. An empty list or an entry missing either field is rejected at
startup.

## Supported Operations

**Bucket**

- CreateBucket (`PUT /{bucket}`) — validates S3 bucket-naming rules
- HeadBucket (`HEAD /{bucket}`)
- DeleteBucket (`DELETE /{bucket}`) — fails if the bucket is non-empty
- ListBuckets (`GET /`)

**Object**

- PutObject (`PUT /{bucket}/{key}`) — streaming, one-pass MD5, atomic rename
- GetObject (`GET /{bucket}/{key}`) — streaming, HTTP `Range` supported
- HeadObject (`HEAD /{bucket}/{key}`)
- DeleteObject (`DELETE /{bucket}/{key}`) — idempotent

**Listing**

- ListObjectsV2 (`GET /{bucket}?list-type=2`) — `prefix`, `delimiter`,
  `max-keys`, `start-after`, `continuation-token`

**Multipart**

- CreateMultipartUpload, UploadPart, CompleteMultipartUpload,
  AbortMultipartUpload, ListMultipartUploads, ListParts

**Authentication.** AWS SigV4: header-based and presigned-URL, streaming chunked
payloads (`STREAMING-AWS4-HMAC-SHA256-PAYLOAD`), `UNSIGNED-PAYLOAD`, and a
15-minute clock-skew window.

## Storage Layout on Disk

```
{data-dir}/
  {bucket}/
    {key}                      # object content (single-part objects)
    {key}.s3meta               # JSON metadata sidecar
    {key}.parts/               # per-object part store (multipart objects)
      00001
      00002
  .multipart/
    {upload-id}/
      meta.json                # {bucket, key, upload_id, initiated, content_type, user_metadata}
      parts/
        00001                  # in-progress part data (zero-padded part numbers)
        00002
```

- Every single-part object is one plain file plus a `.s3meta` sidecar.
- A multipart upload writes parts under `.multipart/{upload-id}/parts/`. On
  `CompleteMultipartUpload` the parts are moved into a per-object `{key}.parts/`
  directory, a placeholder `{key}` file is written, and the `.s3meta` sidecar
  records the ordered part manifest (path, size, MD5 per part). GET keys off the
  sidecar and reassembles the parts on read; no concatenated copy is ever made.
- `.s3meta` is written atomically (temp file + rename); object and part data are
  written to a temp sibling, fsynced, then atomically renamed into place.

## TLS & kTLS Offload

`s3gateway-rs` terminates TLS with rustls and, when `--ktls` is set (default),
hands the established connection to the kernel TLS stack so bulk record crypto is
performed by the ConnectX-7 NIC rather than the CPU. The TLS handshake itself
stays in userspace (negligible cost); only bulk data transfer is offloaded.

To enable offload on the target box:

```bash
# Kernel modules
sudo modprobe tls
sudo modprobe tls_device

# Enable TLS offload on the physical mlx5 interface
sudo ethtool -K <iface> tls-hw-tx-offload on tls-hw-rx-offload on

# Confirm the NIC advertises the capability
ethtool -k <iface> | grep tls
```

Requirements and constraints:

- **Cipher/version:** AES-GCM-128/256 only. TLS 1.2 is always offloadable; TLS
  1.3 hardware offload needs a recent kernel — fall back to TLS 1.2 AES-GCM on
  older kernels.
- **Bind to the physical NIC.** RX offload does not work over bonds, `veth`, or
  tunnels; serve directly on the mlx5 interface.
- **Verify it's live** under load:

  ```bash
  watch -n1 'ethtool -S <iface> | grep -E \
    "tx_tls_encrypted_bytes|tx_tls_ctx|rx_tls_decrypted_bytes|tx_tls_ooo|tx_tls_drop"'
  ```

  Rising `tx_tls_ctx` means hardware contexts are installed; climbing
  `*_encrypted_bytes` / `*_decrypted_bytes` means the NIC is doing the crypto.

Full bring-up and verification is documented in [TUNING.md](TUNING.md).

## Examples

```bash
export AWS_ACCESS_KEY_ID=test-access-key
export AWS_SECRET_ACCESS_KEY=test-secret-key
ENDPOINT=http://localhost:8333

# Create a bucket
aws --endpoint-url $ENDPOINT s3 mb s3://my-bucket

# Upload (large files go multipart automatically)
aws --endpoint-url $ENDPOINT s3 cp ./bigfile.bin s3://my-bucket/bigfile.bin

# List
aws --endpoint-url $ENDPOINT s3 ls s3://my-bucket/

# Download
aws --endpoint-url $ENDPOINT s3 cp s3://my-bucket/bigfile.bin ./out.bin

# Delete
aws --endpoint-url $ENDPOINT s3 rm s3://my-bucket/bigfile.bin
```

Against an HTTPS endpoint, use `--endpoint-url https://host:8443` (add
`--no-verify-ssl` for self-signed certs in testing).

## Limitations

Out of scope by design — this gateway favors throughput on a narrow API surface:

- No versioning, ACLs, bucket policies, lifecycle, tagging, or CORS
- No server-side encryption at the gateway layer (ZFS provides at-rest AES)
- No batch/`DeleteObjects` multi-delete
- Path-style addressing only (no virtual-hosted-style)
- Single-region SigV4; no STS / temporary credentials

## License

Apache License 2.0. See [LICENSE](../LICENSE) at the repository root.

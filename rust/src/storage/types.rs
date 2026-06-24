//! Shared storage types and bucket-name validation.
//!
//! These types are the storage layer's public, handler-facing contract:
//! `StorageError`, the listing/multipart/object info structs, `GetObjectResult`,
//! and `validate_bucket_name`. They were originally defined in the (now removed)
//! `filesystem.rs` and consumed by both that impl and the handlers; the
//! content-addressed `cas.rs` impl now owns the behavior, so the shared *types*
//! live here in their own module — independent of any one storage impl.

use std::collections::BTreeMap;
use std::io::{self, Read};

use super::reader::ByteRange;
use crate::storage::metadata::ObjectMetadata;

pub type Result<T> = std::result::Result<T, StorageError>;

/// E7: hard cap on the number of uploads ListMultipartUploads returns in one
/// response (mirrors S3's default/maximum `max-uploads`). Bounds memory/response
/// size regardless of the client-supplied `max-uploads`.
pub const MAX_UPLOADS_CAP: usize = 1000;

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("bucket not found")]
    BucketNotFound,
    #[error("bucket not empty")]
    BucketNotEmpty,
    #[error("bucket already exists")]
    BucketExists,
    #[error("object not found")]
    ObjectNotFound,
    #[error("invalid bucket name")]
    InvalidBucket,
    #[error("path traversal detected")]
    PathTraversal,
    #[error("no such upload")]
    NoSuchUpload,
    #[error("invalid part order")]
    InvalidPartOrder,
    #[error("invalid part")]
    InvalidPart,
    /// C3: the requested byte range is unsatisfiable for the object's actual size.
    /// Carries the object's total size so the handler can emit the required
    /// `Content-Range: bytes */{size}` on the 416 response. Resolved under the
    /// SAME manifest snapshot as the object, so the 416's size matches the object
    /// the GET would have served (no head/get TOCTOU).
    #[error("range not satisfiable")]
    RangeNotSatisfiable { size: u64 },
    /// The upload BODY stream ended in a client-side framing problem — the
    /// de-framed aws-chunked byte total did not match `x-amz-decoded-content-length`,
    /// or the chunk framing was malformed (an `InvalidData` io error raised by
    /// `ChunkedReader` while reading the request body). This is DEDICATED to the
    /// body-streaming read so it maps to 400 `IncompleteBody`; server-side
    /// `InvalidData` (e.g. a corrupt manifest/`upload.json`) stays in `Io` and maps
    /// to 500 `InternalError`. See `map_storage_error`.
    #[error("incomplete request body")]
    IncompleteBody,
    #[error("io error: {0}")]
    Io(#[from] io::Error),
}

#[derive(Debug, Clone)]
pub struct BucketInfo {
    pub name: String,
    /// Creation/modification time as Unix seconds.
    pub creation_unix: i64,
}

#[derive(Debug, Clone)]
pub struct ObjectInfo {
    pub key: String,
    pub size: i64,
    /// ETag including quotes.
    pub etag: String,
    pub last_modified_unix: i64,
}

#[derive(Debug, Default, Clone)]
pub struct ListObjectsInput {
    pub bucket: String,
    pub prefix: String,
    pub delimiter: String,
    /// `None` = the `max-keys` param was ABSENT (defaults to 1000). `Some(0)` is
    /// an EXPLICIT request for an empty page (returns 0 keys, `is_truncated=true`
    /// when more exist). `Some(n)` caps the page at `n`. Distinguishing absent
    /// from 0 matters for S3 conformance (F14).
    pub max_keys: Option<i32>,
    pub start_after: String,
    pub continuation_token: String,
}

#[derive(Debug, Default)]
pub struct ListObjectsOutput {
    pub objects: Vec<ObjectInfo>,
    pub common_prefixes: Vec<String>,
    pub is_truncated: bool,
    pub next_continuation_token: String,
}

/// Streaming result of GetObject: metadata + a boxed blocking reader.
///
/// C3: every field here is taken from ONE consistent snapshot — the same manifest
/// read + body open. The handler builds ALL response headers from this single
/// result and never does a separate `head_object` for the GET path, so a
/// concurrent overwrite can no longer pair headers from one version with a body
/// from another.
pub struct GetObjectResult {
    pub metadata: ObjectMetadata,
    pub body: Box<dyn Read + Send>,
    /// The range actually served, resolved against THIS object's size (None =
    /// full object).
    pub resolved_range: Option<ByteRange>,
    /// Full object size (regardless of range).
    pub total_size: u64,
}

/// Multipart upload metadata sidecar (`arriving/{id}/upload.json`).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MultipartUpload {
    pub upload_id: String,
    pub bucket: String,
    pub key: String,
    pub initiated_unix: i64,
    #[serde(default)]
    pub content_type: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub user_metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct PartInfo {
    pub part_number: i32,
    pub size: i64,
    pub etag: String,
    pub last_modified_unix: i64,
}

/// A part the client claims in CompleteMultipartUpload.
#[derive(Debug, Clone)]
pub struct CompletePart {
    pub part_number: i32,
    pub etag: String,
}

/// Validate an S3 bucket name against the standard naming rules.
pub fn validate_bucket_name(name: &str) -> Result<()> {
    let bytes = name.as_bytes();
    let n = bytes.len();
    if !(3..=63).contains(&n) {
        return Err(StorageError::InvalidBucket);
    }
    for (i, &c) in bytes.iter().enumerate() {
        let ok = c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'.' || c == b'-';
        if !ok {
            return Err(StorageError::InvalidBucket);
        }
        if i > 0 && c == b'.' && bytes[i - 1] == b'.' {
            return Err(StorageError::InvalidBucket);
        }
    }
    let first = bytes[0];
    let last = bytes[n - 1];
    if !(first.is_ascii_lowercase() || first.is_ascii_digit()) {
        return Err(StorageError::InvalidBucket);
    }
    if !(last.is_ascii_lowercase() || last.is_ascii_digit()) {
        return Err(StorageError::InvalidBucket);
    }
    if name.starts_with("xn--") {
        return Err(StorageError::InvalidBucket);
    }
    if name.ends_with("-s3alias") {
        return Err(StorageError::InvalidBucket);
    }
    if is_ipv4(name) {
        return Err(StorageError::InvalidBucket);
    }
    Ok(())
}

/// True if `name` looks like a dotted IPv4 address (a.b.c.d, 0-255 octets).
fn is_ipv4(name: &str) -> bool {
    let parts: Vec<&str> = name.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts.iter().all(|p| {
        !p.is_empty()
            && p.len() <= 3
            && p.bytes().all(|b| b.is_ascii_digit())
            && p.parse::<u16>().map(|v| v <= 255).unwrap_or(false)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_name_validation() {
        assert!(validate_bucket_name("abc").is_ok());
        assert!(validate_bucket_name("my-bucket.example").is_ok());
        assert!(validate_bucket_name("a1b2").is_ok());
        // too short / long
        assert!(validate_bucket_name("ab").is_err());
        assert!(validate_bucket_name(&"a".repeat(64)).is_err());
        // uppercase
        assert!(validate_bucket_name("MyBucket").is_err());
        // start/end with non-alnum
        assert!(validate_bucket_name("-abc").is_err());
        assert!(validate_bucket_name("abc-").is_err());
        assert!(validate_bucket_name(".abc").is_err());
        // adjacent dots
        assert!(validate_bucket_name("a..b").is_err());
        // ip address
        assert!(validate_bucket_name("192.168.0.1").is_err());
        // xn-- prefix, -s3alias suffix
        assert!(validate_bucket_name("xn--abc").is_err());
        assert!(validate_bucket_name("mybucket-s3alias").is_err());
        // invalid char
        assert!(validate_bucket_name("under_score").is_err());
    }
}

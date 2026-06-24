//! HTTP handlers for S3 operations.
//!
//! Handlers are intentionally thin: they translate a parsed [`HandlerRequest`]
//! into calls on the BLOCKING [`crate::storage::CasStore`] (run via
//! `spawn_blocking`) and map results/errors back to hyper responses. The router
//! (see [`crate::server::router`]) does auth, route selection, and request
//! adaptation before calling these.

pub mod bucket;
pub mod list;
pub mod multipart;
pub mod object;

use std::collections::BTreeMap;
use std::sync::Arc;

use bytes::Bytes;
use futures_util::TryStreamExt;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, BodyStream, Full};
use hyper::body::Incoming;
use hyper::{Response, StatusCode};
use tokio::io::AsyncRead;
use tokio_util::io::{StreamReader, SyncIoBridge};

use crate::auth::CredentialStore;
use crate::s3response::{render_error_xml, S3ErrorCode};
use crate::storage::{CasStore, StorageError};

/// Boxed, unified response body type used by every handler.
pub type RespBody = BoxBody<Bytes, std::io::Error>;

/// A streaming response body backed by a bounded mpsc channel. Used by GET to
/// pump chunks off a blocking reader without buffering the whole object. Keeps
/// memory bounded via the channel's capacity.
pub struct ChannelBody {
    rx: tokio::sync::mpsc::Receiver<Result<Bytes, std::io::Error>>,
}

impl ChannelBody {
    pub fn new(rx: tokio::sync::mpsc::Receiver<Result<Bytes, std::io::Error>>) -> Self {
        ChannelBody { rx }
    }
}

impl hyper::body::Body for ChannelBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        match self.rx.poll_recv(cx) {
            std::task::Poll::Ready(Some(Ok(bytes))) => {
                std::task::Poll::Ready(Some(Ok(hyper::body::Frame::data(bytes))))
            }
            std::task::Poll::Ready(Some(Err(e))) => std::task::Poll::Ready(Some(Err(e))),
            std::task::Poll::Ready(None) => std::task::Poll::Ready(None),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

/// Shared, cheaply-cloneable handler context (one logical instance per process,
/// shared across all per-core runtimes; `CasStore` is stateless/`Clone`).
#[derive(Clone)]
pub struct Ctx {
    pub fs: CasStore,
    pub creds: Arc<CredentialStore>,
    pub region: String,
}

/// A request as seen by handlers: method, the decoded bucket/key, the decoded
/// query map, the lowercased header map, and the raw hyper body (for PUTs).
pub struct HandlerRequest {
    pub method: hyper::Method,
    pub bucket: String,
    /// Object key (already percent-decoded). Empty for bucket-level ops.
    pub key: String,
    pub query: BTreeMap<String, Vec<String>>,
    /// Lowercased header name -> values.
    pub headers: BTreeMap<String, Vec<String>>,
    pub body: Incoming,
    /// The full escaped request path (used for error <Resource>).
    pub resource: String,
}

impl HandlerRequest {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(name)
            .and_then(|v| v.first())
            .map(|s| s.as_str())
    }

    pub fn query1(&self, name: &str) -> Option<&str> {
        self.query
            .get(name)
            .and_then(|v| v.first())
            .map(|s| s.as_str())
    }

    /// Collect `x-amz-meta-*` headers into a user-metadata map.
    pub fn user_metadata(&self) -> BTreeMap<String, String> {
        extract_user_metadata(&self.headers)
    }
}

/// Whether the request body is aws-chunked framed and must be de-framed by
/// [`crate::auth::ChunkedReader`] before storage.
///
/// AWS clients use several flavors:
///   - `x-amz-content-sha256: STREAMING-AWS4-HMAC-SHA256-PAYLOAD` (classic, per-chunk signed)
///   - `STREAMING-UNSIGNED-PAYLOAD-TRAILER` / `STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER`
///     (newer, used when a checksum trailer is sent — common over TLS)
///   - `Content-Encoding: aws-chunked` as a fallback signal
///
/// All of these wrap the payload in the same `{hex};chunk-signature=...\r\n...`
/// framing that `ChunkedReader` strips (trailers after the 0-chunk are ignored).
pub fn is_chunked_upload(headers: &BTreeMap<String, Vec<String>>) -> bool {
    let sha = headers
        .get("x-amz-content-sha256")
        .and_then(|v| v.first())
        .map(|s| s.as_str())
        .unwrap_or("");
    if sha.starts_with("STREAMING-") {
        return true;
    }
    headers
        .get("content-encoding")
        .and_then(|v| v.first())
        .map(|s| s.to_ascii_lowercase().contains("aws-chunked"))
        .unwrap_or(false)
}

/// E4/E5: parse `x-amz-decoded-content-length` — the REAL (de-framed) payload
/// size that the SigV4 signature covers for an aws-chunked body. Returns
/// `Some(len)` when the header is present and a valid non-negative integer,
/// `None` when absent, and `Err(InvalidArgument)` when present but malformed.
/// Callers thread the `Some(len)` into `ChunkedReader` so the de-framed byte
/// count is verified at EOF.
pub fn decoded_content_length(
    headers: &BTreeMap<String, Vec<String>>,
) -> Result<Option<u64>, S3ErrorCode> {
    match headers
        .get("x-amz-decoded-content-length")
        .and_then(|v| v.first())
    {
        None => Ok(None),
        Some(s) => s
            .trim()
            .parse::<u64>()
            .map(Some)
            .map_err(|_| S3ErrorCode::InvalidArgument),
    }
}

/// Collect `x-amz-meta-*` headers (lowercased keys) into a user-metadata map.
pub fn extract_user_metadata(headers: &BTreeMap<String, Vec<String>>) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    for (k, vals) in headers {
        if k.starts_with("x-amz-meta-") {
            if let Some(v) = vals.first() {
                m.insert(k.clone(), v.clone());
            }
        }
    }
    m
}

/// Bridge a hyper `Incoming` request body into a BLOCKING `std::io::Read`,
/// suitable for `spawn_blocking` storage calls.
///
/// Path: `BodyStream` (Stream of Frames) -> data-only `Bytes` -> `StreamReader`
/// (AsyncRead) -> `SyncIoBridge` (blocking Read). The stream is boxed+pinned so
/// the resulting `AsyncRead` is `Unpin` (required by `SyncIoBridge`). Nothing is
/// buffered: bytes flow chunk-by-chunk.
pub fn body_to_blocking_read(
    body: Incoming,
) -> SyncIoBridge<std::pin::Pin<Box<dyn AsyncRead + Send>>> {
    let data_stream = BodyStream::new(body)
        .try_filter_map(|frame| async move { Ok(frame.into_data().ok()) })
        .map_err(std::io::Error::other);
    let async_read: std::pin::Pin<Box<dyn AsyncRead + Send>> =
        Box::pin(StreamReader::new(data_stream));
    SyncIoBridge::new(async_read)
}

/// Build a body from owned bytes.
pub fn full_body(bytes: impl Into<Bytes>) -> RespBody {
    Full::new(bytes.into())
        .map_err(|never| match never {})
        .boxed()
}

/// Empty response body.
pub fn empty_body() -> RespBody {
    full_body(Bytes::new())
}

/// Build an S3 error XML response.
pub fn error_response(code: S3ErrorCode, resource: &str, request_id: &str) -> Response<RespBody> {
    let xml = render_error_xml(code, resource, request_id);
    let status =
        StatusCode::from_u16(code.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut resp = Response::new(full_body(Bytes::from(xml)));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        "application/xml".parse().unwrap(),
    );
    resp
}

/// Map a storage error to the appropriate S3 error code.
pub fn map_storage_error(e: &StorageError) -> S3ErrorCode {
    match e {
        StorageError::BucketNotFound => S3ErrorCode::NoSuchBucket,
        StorageError::BucketNotEmpty => S3ErrorCode::BucketNotEmpty,
        StorageError::BucketExists => S3ErrorCode::BucketAlreadyOwnedByYou,
        StorageError::ObjectNotFound => S3ErrorCode::NoSuchKey,
        StorageError::InvalidBucket => S3ErrorCode::InvalidBucketName,
        // The CAS store rejects a reserved-suffix / traversal / NUL key up front as
        // PathTraversal → 400 InvalidArgument (the old `ReservedKey`/`KeyPrefixConflict`
        // variants are gone: the reserved `MANIFEST_SUFFIX` makes the key↔path map a
        // collision-free bijection, so the prefix-conflict 409 is structurally
        // impossible — see REDESIGN §7.2/§7.3).
        StorageError::PathTraversal => S3ErrorCode::InvalidArgument,
        StorageError::NoSuchUpload => S3ErrorCode::NoSuchUpload,
        StorageError::InvalidPartOrder => S3ErrorCode::InvalidPartOrder,
        StorageError::InvalidPart => S3ErrorCode::InvalidPart,
        // C3: the GET handler intercepts this BEFORE mapping (it needs the size to
        // build the 416 `Content-Range`); this mapping is the exhaustive fallback.
        StorageError::RangeNotSatisfiable { .. } => S3ErrorCode::InvalidRange,
        // E4/E5 (scoped by bracket follow-up): a CLIENT body framing problem — the
        // de-framed aws-chunked length mismatched x-amz-decoded-content-length, or
        // the chunk framing was malformed — surfaces as the DEDICATED
        // `IncompleteBody` variant (raised ONLY on the upload body-streaming read),
        // mapped to 400 IncompleteBody. Generic `Io(InvalidData)` is NOT special-
        // cased: it is also produced SERVER-SIDE by corrupt-sidecar/meta.json reads
        // (read_metadata / assert_upload_matches, reached by GET/HEAD/LIST/complete),
        // so it must stay a 500 InternalError — not be mis-reported as a client error.
        StorageError::IncompleteBody => S3ErrorCode::IncompleteBody,
        StorageError::Io(_) => S3ErrorCode::InternalError,
    }
}

/// Convenience: serialize a `to_xml()` success body into a 200 XML response.
pub fn xml_ok(xml: String) -> Response<RespBody> {
    let mut resp = Response::new(full_body(Bytes::from(xml)));
    resp.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        "application/xml".parse().unwrap(),
    );
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_error_mapping() {
        assert_eq!(
            map_storage_error(&StorageError::BucketNotFound),
            S3ErrorCode::NoSuchBucket
        );
        assert_eq!(
            map_storage_error(&StorageError::ObjectNotFound),
            S3ErrorCode::NoSuchKey
        );
        assert_eq!(
            map_storage_error(&StorageError::BucketNotEmpty),
            S3ErrorCode::BucketNotEmpty
        );
        assert_eq!(
            map_storage_error(&StorageError::NoSuchUpload),
            S3ErrorCode::NoSuchUpload
        );
        assert_eq!(
            map_storage_error(&StorageError::InvalidPartOrder),
            S3ErrorCode::InvalidPartOrder
        );
        assert_eq!(
            map_storage_error(&StorageError::PathTraversal),
            S3ErrorCode::InvalidArgument
        );
        assert_eq!(
            map_storage_error(&StorageError::Io(std::io::Error::other("x"))),
            S3ErrorCode::InternalError
        );
        // Bracket follow-up to ee593ba: ONLY the dedicated IncompleteBody variant
        // (upload-body decoded-length mismatch) maps to the 400 IncompleteBody.
        assert_eq!(
            map_storage_error(&StorageError::IncompleteBody),
            S3ErrorCode::IncompleteBody
        );
        // A generic Io(InvalidData) — e.g. a corrupt-sidecar read server-side — is
        // NOT a client error: it stays InternalError (500), not IncompleteBody.
        assert_eq!(
            map_storage_error(&StorageError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "corrupt sidecar"
            ))),
            S3ErrorCode::InternalError
        );
    }

    #[test]
    fn error_response_status_and_xml() {
        let resp = error_response(S3ErrorCode::NoSuchKey, "/b/k", "req-1");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            resp.headers().get(hyper::header::CONTENT_TYPE).unwrap(),
            "application/xml"
        );
    }

    #[test]
    fn chunked_upload_detection() {
        let mk = |pairs: &[(&str, &str)]| -> BTreeMap<String, Vec<String>> {
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), vec![v.to_string()]))
                .collect()
        };
        // Classic per-chunk-signed streaming.
        assert!(is_chunked_upload(&mk(&[(
            "x-amz-content-sha256",
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
        )])));
        // Newer unsigned-trailer streaming (used over TLS with checksums).
        assert!(is_chunked_upload(&mk(&[(
            "x-amz-content-sha256",
            "STREAMING-UNSIGNED-PAYLOAD-TRAILER"
        )])));
        // Signed-trailer variant.
        assert!(is_chunked_upload(&mk(&[(
            "x-amz-content-sha256",
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER"
        )])));
        // aws-chunked content-encoding fallback signal.
        assert!(is_chunked_upload(&mk(&[(
            "content-encoding",
            "aws-chunked"
        )])));
        // Plain upload: a real hex sha256 -> not chunked.
        assert!(!is_chunked_upload(&mk(&[(
            "x-amz-content-sha256",
            "5bf93aba889ca5a8a596fb9080bdabfa944fa0b6b6b72447bd08857c166b1000"
        )])));
        // UNSIGNED-PAYLOAD (whole body, not framed) -> not chunked.
        assert!(!is_chunked_upload(&mk(&[(
            "x-amz-content-sha256",
            "UNSIGNED-PAYLOAD"
        )])));
        assert!(!is_chunked_upload(&BTreeMap::new()));
    }

    #[test]
    fn user_metadata_extraction() {
        let mut headers: BTreeMap<String, Vec<String>> = BTreeMap::new();
        headers.insert("content-type".into(), vec!["text/plain".into()]);
        headers.insert("x-amz-meta-foo".into(), vec!["bar".into()]);
        headers.insert("x-amz-meta-baz".into(), vec!["qux".into()]);
        let m = extract_user_metadata(&headers);
        assert_eq!(m.len(), 2);
        assert_eq!(m.get("x-amz-meta-foo").unwrap(), "bar");
        assert_eq!(m.get("x-amz-meta-baz").unwrap(), "qux");
    }
}

//! Object handlers: PutObject, GetObject, HeadObject, DeleteObject.
//!
//! These carry the async<->blocking bridge:
//!   - PUT: hyper body -> StreamReader -> SyncIoBridge -> blocking Read, fed to
//!     `Filesystem::put_object` inside spawn_blocking. STREAMING-AWS4 bodies are
//!     wrapped in `auth::ChunkedReader` first, sized by x-amz-decoded-content-length.
//!   - GET: `Filesystem::get_object` returns a blocking `Box<dyn Read>`; we pump
//!     ~1 MiB chunks through a bounded mpsc channel into a hyper StreamBody so the
//!     full object is never buffered.

use std::io::Read;

use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::header::{HeaderName, HeaderValue};
use hyper::{Response, StatusCode};

use crate::auth::ChunkedReader;
use crate::s3response::{render_error_xml, S3ErrorCode};
use crate::storage::{ObjectMetadata, StorageError};

use super::{empty_body, full_body, map_storage_error, ChannelBody, Ctx, HandlerRequest, RespBody};

/// Chunk size for streaming GET bodies off the blocking reader.
const GET_CHUNK: usize = 1024 * 1024;

/// PUT /{bucket}/{key} — PutObject.
pub async fn put_object(ctx: &Ctx, req: HandlerRequest) -> Result<Response<RespBody>, S3ErrorCode> {
    let bucket = req.bucket.clone();
    let key = req.key.clone();
    let content_type = req.header("content-type").unwrap_or("").to_string();
    let user_meta = req.user_metadata();

    let is_streaming = super::is_chunked_upload(&req.headers);

    // E4: the de-framed payload size the signature covers. For a STREAMING-*
    // (aws-chunked) body the header is REQUIRED — without it we cannot verify the
    // body wasn't truncated/padded relative to what was signed, so reject as
    // InvalidArgument. `ChunkedReader` then enforces the count at EOF.
    let expected_len = super::decoded_content_length(&req.headers)?;
    if is_streaming && expected_len.is_none() {
        return Err(S3ErrorCode::InvalidArgument);
    }

    // Turn the hyper Incoming body into a blocking std::io::Read:
    //   BodyStream (Stream of Frames) -> data-only bytes -> StreamReader
    //   (AsyncRead) -> SyncIoBridge (blocking Read).
    let bridge = super::body_to_blocking_read(req.body);

    let fs = ctx.fs.clone();
    let etag = tokio::task::spawn_blocking(move || -> Result<String, StorageError> {
        if is_streaming {
            // De-frame the SigV4 chunked payload before storing, verifying the
            // de-framed byte total matches x-amz-decoded-content-length (E4).
            let reader = ChunkedReader::new(bridge, expected_len);
            fs.put_object(&bucket, &key, reader, &content_type, user_meta)
        } else {
            fs.put_object(&bucket, &key, bridge, &content_type, user_meta)
        }
    })
    .await
    .map_err(|_| S3ErrorCode::InternalError)?
    .map_err(|e| map_storage_error(&e))?;

    let mut resp = Response::new(empty_body());
    resp.headers_mut()
        .insert(hyper::header::ETAG, HeaderValue::from_str(&etag).unwrap());
    Ok(resp)
}

/// GET /{bucket}/{key} — GetObject (supports Range).
pub async fn get_object(ctx: &Ctx, req: HandlerRequest) -> Result<Response<RespBody>, S3ErrorCode> {
    object_response(ctx, req, true).await
}

/// HEAD /{bucket}/{key} — HeadObject (no body).
pub async fn head_object(
    ctx: &Ctx,
    req: HandlerRequest,
) -> Result<Response<RespBody>, S3ErrorCode> {
    object_response(ctx, req, false).await
}

/// Shared GET/HEAD logic. When `with_body` is false (HEAD) we still resolve
/// metadata and headers but send no body.
async fn object_response(
    ctx: &Ctx,
    req: HandlerRequest,
    with_body: bool,
) -> Result<Response<RespBody>, S3ErrorCode> {
    let bucket = req.bucket.clone();
    let key = req.key.clone();
    let range_header = req.header("range").map(|s| s.to_string());

    if !with_body {
        // HEAD: only need metadata.
        let fs = ctx.fs.clone();
        let (b, k) = (bucket.clone(), key.clone());
        let meta = tokio::task::spawn_blocking(move || fs.head_object(&b, &k))
            .await
            .map_err(|_| S3ErrorCode::InternalError)?
            .map_err(|e| map_storage_error(&e))?;
        let mut resp = Response::new(empty_body());
        apply_object_headers(resp.headers_mut(), &meta);
        return Ok(resp);
    }

    // GET: take a SINGLE consistent snapshot (C3). `get_object` reads the sidecar,
    // resolves the Range against THIS object's size, and opens the body — all
    // under one snapshot — so metadata, total size, resolved range, and body are
    // mutually consistent. We do NOT call `head_object` on the GET path, which
    // closes the head/get TOCTOU. An unsatisfiable range surfaces as
    // `RangeNotSatisfiable { size }`, which we turn into a 416 carrying the
    // object's own size.
    let fs = ctx.fs.clone();
    let (b, k) = (bucket.clone(), key.clone());
    let rh = range_header.clone();
    let result = match tokio::task::spawn_blocking(move || fs.get_object(&b, &k, rh.as_deref()))
        .await
        .map_err(|_| S3ErrorCode::InternalError)?
    {
        Ok(r) => r,
        Err(StorageError::RangeNotSatisfiable { size }) => {
            return Ok(range_not_satisfiable(&req.resource, size));
        }
        Err(e) => return Err(map_storage_error(&e)),
    };

    let meta = result.metadata;
    let total_size = result.total_size;
    let served_range = result.resolved_range;
    let mut reader = result.body;

    // Compute Content-Length for the served portion.
    let content_len = match served_range {
        Some(r) => r.len(),
        None => total_size,
    };

    // Bounded channel: pump ~1 MiB chunks off the blocking reader into a
    // streaming hyper body. Channel depth is small to keep memory bounded.
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(4);
    tokio::task::spawn_blocking(move || {
        // Read directly into a reused BytesMut, then `split_to(n).freeze()` to
        // hand each chunk's bytes to the body with NO extra userspace copy
        // (the freed half-range stays owned by the body; we reserve afresh).
        let mut buf = bytes::BytesMut::with_capacity(GET_CHUNK);
        loop {
            // Ensure room for a full chunk without reallocating live bytes.
            buf.resize(GET_CHUNK, 0);
            match reader.read(&mut buf[..GET_CHUNK]) {
                Ok(0) => break,
                Ok(n) => {
                    let chunk = buf.split_to(n).freeze();
                    if tx.blocking_send(Ok(chunk)).is_err() {
                        break; // receiver dropped (client gone)
                    }
                }
                Err(e) => {
                    let _ = tx.blocking_send(Err(e));
                    break;
                }
            }
        }
    });

    let body = ChannelBody::new(rx).boxed();

    let mut resp = Response::new(body);
    apply_object_headers(resp.headers_mut(), &meta);
    // Override Content-Length with the served length.
    resp.headers_mut().insert(
        hyper::header::CONTENT_LENGTH,
        HeaderValue::from_str(&content_len.to_string()).unwrap(),
    );

    if let Some(r) = served_range {
        *resp.status_mut() = StatusCode::PARTIAL_CONTENT;
        resp.headers_mut().insert(
            hyper::header::ACCEPT_RANGES,
            HeaderValue::from_static("bytes"),
        );
        resp.headers_mut().insert(
            hyper::header::CONTENT_RANGE,
            HeaderValue::from_str(&format!("bytes {}-{}/{}", r.start, r.end, total_size)).unwrap(),
        );
    } else {
        resp.headers_mut().insert(
            hyper::header::ACCEPT_RANGES,
            HeaderValue::from_static("bytes"),
        );
    }
    Ok(resp)
}

/// DELETE /{bucket}/{key} — DeleteObject. 204 on success (idempotent for a
/// missing key in an existing bucket); NoSuchBucket if the bucket is missing (C7).
pub async fn delete_object(
    ctx: &Ctx,
    req: HandlerRequest,
) -> Result<Response<RespBody>, S3ErrorCode> {
    let bucket = req.bucket.clone();
    let key = req.key.clone();
    let fs = ctx.fs.clone();
    tokio::task::spawn_blocking(move || fs.delete_object(&bucket, &key))
        .await
        .map_err(|_| S3ErrorCode::InternalError)?
        .map_err(|e| map_storage_error(&e))?;
    let mut resp = Response::new(empty_body());
    *resp.status_mut() = StatusCode::NO_CONTENT;
    Ok(resp)
}

/// Build a 416 Range Not Satisfiable response carrying the required
/// `Content-Range: bytes */<total-size>` header (RFC 7233 §4.4 / S3) plus the
/// standard `InvalidRange` error XML body.
fn range_not_satisfiable(resource: &str, total_size: u64) -> Response<RespBody> {
    let xml = render_error_xml(S3ErrorCode::InvalidRange, resource, "");
    let mut resp = Response::new(full_body(Bytes::from(xml)));
    *resp.status_mut() = StatusCode::RANGE_NOT_SATISFIABLE;
    resp.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        HeaderValue::from_static("application/xml"),
    );
    resp.headers_mut().insert(
        hyper::header::CONTENT_RANGE,
        HeaderValue::from_str(&format!("bytes */{}", total_size)).unwrap(),
    );
    resp
}

/// Set Content-Type, Content-Length, ETag, Last-Modified, and x-amz-meta-*.
fn apply_object_headers(headers: &mut hyper::HeaderMap, meta: &ObjectMetadata) {
    if let Ok(v) = HeaderValue::from_str(&meta.content_type) {
        headers.insert(hyper::header::CONTENT_TYPE, v);
    }
    headers.insert(
        hyper::header::CONTENT_LENGTH,
        HeaderValue::from_str(&meta.content_length.to_string()).unwrap(),
    );
    if let Ok(v) = HeaderValue::from_str(&meta.etag) {
        headers.insert(hyper::header::ETAG, v);
    }
    // Last-Modified in HTTP date format.
    let lm = http_date(meta.last_modified);
    if let Ok(v) = HeaderValue::from_str(&lm) {
        headers.insert(hyper::header::LAST_MODIFIED, v);
    }
    if !meta.content_encoding.is_empty() {
        if let Ok(v) = HeaderValue::from_str(&meta.content_encoding) {
            headers.insert(hyper::header::CONTENT_ENCODING, v);
        }
    }
    if !meta.content_disposition.is_empty() {
        if let Ok(v) = HeaderValue::from_str(&meta.content_disposition) {
            headers.insert(hyper::header::CONTENT_DISPOSITION, v);
        }
    }
    if !meta.cache_control.is_empty() {
        if let Ok(v) = HeaderValue::from_str(&meta.cache_control) {
            headers.insert(hyper::header::CACHE_CONTROL, v);
        }
    }
    for (k, v) in &meta.user_metadata {
        // k is already the full `x-amz-meta-...` name (lowercased on ingest).
        if let (Ok(name), Ok(val)) = (
            HeaderName::from_bytes(k.as_bytes()),
            HeaderValue::from_str(v),
        ) {
            headers.insert(name, val);
        }
    }
}

/// Format Unix seconds as an RFC 7231 IMF-fixdate (HTTP Last-Modified).
fn http_date(secs: i64) -> String {
    // Reuse the civil-time math; produce e.g. "Sun, 06 Nov 1994 08:49:37 GMT".
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (hh, mm, ss) = (rem / 3600, (rem % 3600) / 60, rem % 60);

    // Day of week: 1970-01-01 was a Thursday (=4, with Sun=0).
    let dow = (((days % 7) + 7 + 4) % 7) as usize;
    let wd = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"][dow];

    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    let mon = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ][(m - 1) as usize];

    format!(
        "{}, {:02} {} {:04} {:02}:{:02}:{:02} GMT",
        wd, d, mon, year, hh, mm, ss
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    #[tokio::test]
    async fn range_not_satisfiable_has_content_range() {
        // Regression: a 416 must carry `Content-Range: bytes */<total-size>`
        // (RFC 7233 §4.4 / S3) plus the InvalidRange error body.
        let total = 4096u64;
        let resp = range_not_satisfiable("/buck/obj", total);
        assert_eq!(resp.status(), StatusCode::RANGE_NOT_SATISFIABLE);
        let cr = resp
            .headers()
            .get(hyper::header::CONTENT_RANGE)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(cr, format!("bytes */{}", total));
        assert_eq!(
            resp.headers().get(hyper::header::CONTENT_TYPE).unwrap(),
            "application/xml"
        );
        // Body is the InvalidRange error XML.
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let xml = String::from_utf8_lossy(&body);
        assert!(xml.contains("<Code>InvalidRange</Code>"), "got: {xml}");
        assert!(xml.contains("/buck/obj"));
    }
}

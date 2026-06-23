//! Request routing + auth middleware.
//!
//! `dispatch` is the single hyper service entry point. It:
//!   1. Adapts the hyper request into the structures the lib needs (decoded
//!      path/query/headers).
//!   2. Verifies SigV4 (header or presigned) unless the path is `/healthz`.
//!   3. Selects a handler using the exact Go router ordering (multipart query
//!      routes before plain object routes; object before bucket).
//!   4. Adds common response headers (x-amz-request-id, Server) and logs.

use std::collections::BTreeMap;
use std::time::Instant;

use bytes::Bytes;
use hyper::body::Incoming;
use hyper::header::HeaderValue;
use hyper::{Method, Request, Response};
use uuid::Uuid;

use crate::auth::{verify_request, SignableRequest, SigV4Error};
use crate::s3response::S3ErrorCode;

use crate::handler::{
    bucket, error_response, full_body, list, multipart, object, Ctx, HandlerRequest, RespBody,
};

/// Top-level dispatch for one HTTP request. Never returns Err (errors become S3
/// error XML responses).
pub async fn dispatch(
    ctx: Ctx,
    remote_addr: String,
    req: Request<Incoming>,
) -> Result<Response<RespBody>, std::convert::Infallible> {
    let start = Instant::now();
    let request_id = Uuid::new_v4().to_string();

    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let raw_query = req.uri().query().unwrap_or("").to_string();
    let content_length = req
        .headers()
        .get(hyper::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let mut resp = route(ctx, &request_id, req).await;

    // Common response headers on every response.
    let headers = resp.headers_mut();
    headers.insert(
        "x-amz-request-id",
        HeaderValue::from_str(&request_id).unwrap_or(HeaderValue::from_static("unknown")),
    );
    headers.insert("server", HeaderValue::from_static("S3Gateway"));

    let status = resp.status().as_u16();
    let duration_ms = start.elapsed().as_millis();
    tracing::info!(
        method = %method,
        path = %path,
        query = %raw_query,
        status = status,
        duration_ms = duration_ms as u64,
        remote_addr = %remote_addr,
        content_length = %content_length,
        "request"
    );
    Ok(resp)
}

/// Route + auth + dispatch, returning a fully-formed response (errors as XML).
async fn route(ctx: Ctx, request_id: &str, req: Request<Incoming>) -> Response<RespBody> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let escaped_path = req.uri().path().to_string();
    let raw_query = req.uri().query().unwrap_or("").to_string();

    // Health check: unauthenticated.
    if path == "/healthz" && method == Method::GET {
        let mut resp = Response::new(full_body(Bytes::from_static(b"{\"status\":\"ok\"}")));
        resp.headers_mut().insert(
            hyper::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        return resp;
    }

    // Decode query into a map of name -> values (URL-decoded).
    let query = parse_query(&raw_query);

    // Build a lowercased header map.
    let headers = collect_headers(req.headers());

    // Host for the host signed header.
    let host = req
        .headers()
        .get(hyper::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    // --- Auth (skip only /healthz, handled above) ---
    let auth_header = headers.get("authorization").and_then(|v| v.first());
    let has_presigned = query.contains_key("X-Amz-Algorithm");
    if auth_header.is_none() && !has_presigned {
        return error_response(S3ErrorCode::AccessDenied, &escaped_path, request_id);
    }

    let signable = SignableRequest {
        method: method.as_str(),
        escaped_path: &escaped_path,
        query: &query,
        headers: &headers,
        host: &host,
    };
    let now = crate::auth::time::now_unix();
    // Note: for STREAMING-AWS4-HMAC-SHA256-PAYLOAD uploads the seed-signature is
    // verified here (the canonical request uses the literal content-sha256 value);
    // per-chunk signatures are intentionally not re-verified (see ChunkedReader).
    if let Err(e) = verify_request(&signable, &ctx.creds, &ctx.region, now) {
        return error_response(map_auth_error(&e), &escaped_path, request_id);
    }

    // --- Decode bucket + key from the path ---
    let (bucket, key) = split_bucket_key(&path);

    let handler_req = HandlerRequest {
        method: method.clone(),
        bucket: bucket.clone(),
        key: key.clone(),
        query: query.clone(),
        headers,
        body: req.into_body(),
        resource: escaped_path.clone(),
    };

    let result = select_and_run(&ctx, &method, &bucket, &key, &query, handler_req).await;

    match result {
        Ok(resp) => resp,
        Err(code) => error_response(code, &escaped_path, request_id),
    }
}

/// Select the handler per the Go router ordering and run it.
async fn select_and_run(
    ctx: &Ctx,
    method: &Method,
    bucket: &str,
    key: &str,
    query: &BTreeMap<String, Vec<String>>,
    req: HandlerRequest,
) -> Result<Response<RespBody>, S3ErrorCode> {
    let has_key = !key.is_empty();
    let q = |name: &str| query.contains_key(name);

    // Root: ListBuckets (GET /).
    if bucket.is_empty() {
        return match *method {
            Method::GET => bucket::list_buckets(ctx, req).await,
            _ => Err(S3ErrorCode::MethodNotAllowed),
        };
    }

    if has_key {
        // Object-level routes. Multipart query-param routes first.
        // 1. UploadPart: PUT ?partNumber&uploadId
        if *method == Method::PUT && q("partNumber") && q("uploadId") {
            return multipart::upload_part(ctx, req).await;
        }
        // 2. CompleteMultipart: POST ?uploadId
        if *method == Method::POST && q("uploadId") {
            return multipart::complete_multipart_upload(ctx, req).await;
        }
        // 3. CreateMultipart: POST ?uploads
        if *method == Method::POST && q("uploads") {
            return multipart::create_multipart_upload(ctx, req).await;
        }
        // 4. AbortMultipart: DELETE ?uploadId
        if *method == Method::DELETE && q("uploadId") {
            return multipart::abort_multipart_upload(ctx, req).await;
        }
        // 5. ListParts: GET ?uploadId
        if *method == Method::GET && q("uploadId") {
            return multipart::list_parts(ctx, req).await;
        }
        // 7-10. Plain object ops.
        return match *method {
            Method::HEAD => object::head_object(ctx, req).await,
            Method::GET => object::get_object(ctx, req).await,
            Method::PUT => object::put_object(ctx, req).await,
            Method::DELETE => object::delete_object(ctx, req).await,
            _ => Err(S3ErrorCode::MethodNotAllowed),
        };
    }

    // Bucket-level routes.
    // 6. ListMultipartUploads: GET ?uploads
    if *method == Method::GET && q("uploads") {
        return multipart::list_multipart_uploads(ctx, req).await;
    }
    match *method {
        // 11. ListObjectsV2 (with or without list-type=2).
        Method::GET => list::list_objects_v2(ctx, req).await,
        // 12. HeadBucket
        Method::HEAD => bucket::head_bucket(ctx, req).await,
        // 13. CreateBucket
        Method::PUT => bucket::create_bucket(ctx, req).await,
        // 14. DeleteBucket
        Method::DELETE => bucket::delete_bucket(ctx, req).await,
        _ => Err(S3ErrorCode::MethodNotAllowed),
    }
}

/// Map a SigV4 verification error to the proper S3 error code.
fn map_auth_error(e: &SigV4Error) -> S3ErrorCode {
    match e {
        SigV4Error::InvalidAccessKey => S3ErrorCode::InvalidAccessKeyId,
        SigV4Error::SignatureMismatch => S3ErrorCode::SignatureDoesNotMatch,
        SigV4Error::Skewed => S3ErrorCode::RequestTimeTooSkewed,
        SigV4Error::Expired => S3ErrorCode::AccessDenied,
        SigV4Error::MissingAuthHeader
        | SigV4Error::MissingDate
        | SigV4Error::MissingQueryParam(_) => S3ErrorCode::AccessDenied,
        SigV4Error::MalformedDate
        | SigV4Error::MalformedAuth(_)
        | SigV4Error::UnsupportedVersion
        | SigV4Error::UnsupportedAlgorithm(_)
        | SigV4Error::InvalidExpires => S3ErrorCode::InvalidArgument,
    }
}

/// Split a request path `/bucket/key...` into (bucket, decoded-key).
/// The key is the full remainder after the bucket (matches Go's `(?s).+`).
fn split_bucket_key(path: &str) -> (String, String) {
    let trimmed = path.strip_prefix('/').unwrap_or(path);
    if trimmed.is_empty() {
        return (String::new(), String::new());
    }
    match trimmed.split_once('/') {
        Some((b, k)) => (percent_decode(b), percent_decode(k)),
        None => (percent_decode(trimmed), String::new()),
    }
}

/// Parse a raw query string into a decoded multimap.
fn parse_query(raw: &str) -> BTreeMap<String, Vec<String>> {
    let mut map: BTreeMap<String, Vec<String>> = BTreeMap::new();
    if raw.is_empty() {
        return map;
    }
    for pair in raw.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = match pair.split_once('=') {
            Some((k, v)) => (percent_decode(k), percent_decode(v)),
            None => (percent_decode(pair), String::new()),
        };
        map.entry(k).or_default().push(v);
    }
    map
}

/// Collect hyper headers into a lowercased-name multimap.
fn collect_headers(h: &hyper::HeaderMap) -> BTreeMap<String, Vec<String>> {
    let mut map: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (name, value) in h {
        if let Ok(v) = value.to_str() {
            map.entry(name.as_str().to_ascii_lowercase())
                .or_default()
                .push(v.to_string());
        }
    }
    map
}

/// Minimal percent-decoder (handles `%XX` and `+` -> space in query context is
/// NOT applied here; AWS does not `+`-encode spaces in paths/keys).
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hi = hex_val(bytes[i + 1]);
                let lo = hex_val(bytes[i + 2]);
                match (hi, lo) {
                    (Some(h), Some(l)) => {
                        out.push((h << 4) | l);
                        i += 3;
                    }
                    _ => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::SigV4Error;

    #[test]
    fn split_bucket_key_cases() {
        assert_eq!(split_bucket_key("/"), (String::new(), String::new()));
        assert_eq!(
            split_bucket_key("/mybucket"),
            ("mybucket".to_string(), String::new())
        );
        assert_eq!(
            split_bucket_key("/mybucket/key.txt"),
            ("mybucket".to_string(), "key.txt".to_string())
        );
        // Key keeps the full remainder including slashes (Go's (?s).+).
        assert_eq!(
            split_bucket_key("/b/a/b/c/deep.txt"),
            ("b".to_string(), "a/b/c/deep.txt".to_string())
        );
        // Percent-decoding of bucket + key.
        assert_eq!(
            split_bucket_key("/b/hello%20world.txt"),
            ("b".to_string(), "hello world.txt".to_string())
        );
        // Unicode key (percent-encoded by client).
        assert_eq!(
            split_bucket_key("/b/%E6%97%A5%E6%9C%AC%E8%AA%9E"),
            ("b".to_string(), "日本語".to_string())
        );
    }

    #[test]
    fn parse_query_cases() {
        let q = parse_query("");
        assert!(q.is_empty());

        let q = parse_query("list-type=2&prefix=foo%2Fbar&max-keys=3");
        assert_eq!(q.get("list-type").unwrap(), &vec!["2".to_string()]);
        assert_eq!(q.get("prefix").unwrap(), &vec!["foo/bar".to_string()]);
        assert_eq!(q.get("max-keys").unwrap(), &vec!["3".to_string()]);

        // Flag-style param with no value (e.g. ?uploads).
        let q = parse_query("uploads");
        assert_eq!(q.get("uploads").unwrap(), &vec![String::new()]);

        // Multiple values for one key.
        let q = parse_query("k=a&k=b");
        assert_eq!(q.get("k").unwrap(), &vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn percent_decode_cases() {
        assert_eq!(percent_decode("hello"), "hello");
        assert_eq!(percent_decode("hello%20world"), "hello world");
        assert_eq!(percent_decode("a%2Fb"), "a/b");
        // Malformed escape is passed through verbatim.
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("%zz"), "%zz");
        // Unicode round-trip.
        assert_eq!(percent_decode("%E6%97%A5"), "日");
    }

    #[test]
    fn auth_error_mapping() {
        assert_eq!(
            map_auth_error(&SigV4Error::InvalidAccessKey),
            S3ErrorCode::InvalidAccessKeyId
        );
        assert_eq!(
            map_auth_error(&SigV4Error::SignatureMismatch),
            S3ErrorCode::SignatureDoesNotMatch
        );
        assert_eq!(
            map_auth_error(&SigV4Error::Skewed),
            S3ErrorCode::RequestTimeTooSkewed
        );
        assert_eq!(
            map_auth_error(&SigV4Error::MissingAuthHeader),
            S3ErrorCode::AccessDenied
        );
        assert_eq!(
            map_auth_error(&SigV4Error::MalformedDate),
            S3ErrorCode::InvalidArgument
        );
    }
}

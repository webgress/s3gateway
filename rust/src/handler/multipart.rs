//! Multipart upload handlers: Create, UploadPart, Complete, Abort, ListParts,
//! ListMultipartUploads.

use http_body_util::{BodyExt, Limited};
use hyper::header::HeaderValue;
use hyper::Response;

use crate::auth::ChunkedReader;
use crate::s3response::{
    format_time, CompleteMultipartUpload, CompleteMultipartUploadResult,
    InitiateMultipartUploadResult, ListMultipartUploadsResult, ListPartsResult, PartEntry,
    S3ErrorCode, UploadEntry,
};
use crate::storage::{CompletePart, StorageError};

use super::{empty_body, map_storage_error, xml_ok, Ctx, HandlerRequest, RespBody};

/// Max accepted CompleteMultipartUpload request-body size (F9). 8 MiB comfortably
/// holds the manifest for the S3 maximum of 10,000 parts.
const COMPLETE_BODY_LIMIT: usize = 8 * 1024 * 1024;

/// POST /{bucket}/{key}?uploads — CreateMultipartUpload.
pub async fn create_multipart_upload(
    ctx: &Ctx,
    req: HandlerRequest,
) -> Result<Response<RespBody>, S3ErrorCode> {
    let bucket = req.bucket.clone();
    let key = req.key.clone();
    let content_type = req.header("content-type").unwrap_or("").to_string();
    let user_meta = req.user_metadata();

    let fs = ctx.fs.clone();
    let (b, k) = (bucket.clone(), key.clone());
    let upload_id = tokio::task::spawn_blocking(move || {
        fs.create_multipart_upload(&b, &k, &content_type, user_meta)
    })
    .await
    .map_err(|_| S3ErrorCode::InternalError)?
    .map_err(|e| map_storage_error(&e))?;

    let result = InitiateMultipartUploadResult {
        bucket,
        key,
        upload_id,
    };
    Ok(xml_ok(result.to_xml()))
}

/// PUT /{bucket}/{key}?partNumber=N&uploadId=X — UploadPart.
pub async fn upload_part(
    ctx: &Ctx,
    req: HandlerRequest,
) -> Result<Response<RespBody>, S3ErrorCode> {
    let upload_id = req
        .query1("uploadId")
        .ok_or(S3ErrorCode::InvalidArgument)?
        .to_string();
    let part_number: i32 = req
        .query1("partNumber")
        .and_then(|s| s.parse().ok())
        .ok_or(S3ErrorCode::InvalidArgument)?;

    let is_streaming = super::is_chunked_upload(&req.headers);
    let bucket = req.bucket.clone();
    let key = req.key.clone();

    // E5: same decoded-length enforcement as PutObject. Required for STREAMING-*
    // part bodies; threaded into ChunkedReader so the de-framed part byte count is
    // verified against x-amz-decoded-content-length at EOF.
    let expected_len = super::decoded_content_length(&req.headers)?;
    if is_streaming && expected_len.is_none() {
        return Err(S3ErrorCode::InvalidArgument);
    }

    let bridge = super::body_to_blocking_read(req.body);

    let fs = ctx.fs.clone();
    let etag = tokio::task::spawn_blocking(move || -> Result<String, StorageError> {
        if is_streaming {
            let reader = ChunkedReader::new(bridge, expected_len);
            fs.upload_part(&bucket, &key, &upload_id, part_number, reader)
        } else {
            fs.upload_part(&bucket, &key, &upload_id, part_number, bridge)
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

/// POST /{bucket}/{key}?uploadId=X — CompleteMultipartUpload.
pub async fn complete_multipart_upload(
    ctx: &Ctx,
    req: HandlerRequest,
) -> Result<Response<RespBody>, S3ErrorCode> {
    let upload_id = req
        .query1("uploadId")
        .ok_or(S3ErrorCode::InvalidArgument)?
        .to_string();
    let bucket = req.bucket.clone();
    let key = req.key.clone();

    // F9: the Complete body is a small parts manifest. Bound it so a hostile or
    // buggy client cannot stream an unbounded body into memory (OOM). 8 MiB is
    // ample headroom for the max 10,000 parts (~70 bytes each). Over-cap bodies
    // are rejected as EntityTooLarge rather than buffered.
    let body_bytes = Limited::new(req.body, COMPLETE_BODY_LIMIT)
        .collect()
        .await
        .map_err(|_| S3ErrorCode::EntityTooLarge)?
        .to_bytes();
    let body_str = std::str::from_utf8(&body_bytes).map_err(|_| S3ErrorCode::MalformedXML)?;
    let parsed =
        CompleteMultipartUpload::from_xml(body_str).map_err(|_| S3ErrorCode::MalformedXML)?;

    let parts: Vec<CompletePart> = parsed
        .parts
        .into_iter()
        .map(|p| CompletePart {
            part_number: p.part_number,
            etag: p.etag,
        })
        .collect();

    let fs = ctx.fs.clone();
    let uid = upload_id.clone();
    let (cb, ck) = (bucket.clone(), key.clone());
    let etag =
        tokio::task::spawn_blocking(move || fs.complete_multipart_upload(&cb, &ck, &uid, &parts))
            .await
            .map_err(|_| S3ErrorCode::InternalError)?
            .map_err(|e| map_storage_error(&e))?;

    let result = CompleteMultipartUploadResult {
        location: format!("/{}/{}", bucket, key),
        bucket,
        key,
        etag,
    };
    Ok(xml_ok(result.to_xml()))
}

/// DELETE /{bucket}/{key}?uploadId=X — AbortMultipartUpload.
pub async fn abort_multipart_upload(
    ctx: &Ctx,
    req: HandlerRequest,
) -> Result<Response<RespBody>, S3ErrorCode> {
    let upload_id = req
        .query1("uploadId")
        .ok_or(S3ErrorCode::InvalidArgument)?
        .to_string();
    let bucket = req.bucket.clone();
    let key = req.key.clone();
    let fs = ctx.fs.clone();
    tokio::task::spawn_blocking(move || fs.abort_multipart_upload(&bucket, &key, &upload_id))
        .await
        .map_err(|_| S3ErrorCode::InternalError)?
        .map_err(|e| map_storage_error(&e))?;
    let mut resp = Response::new(empty_body());
    *resp.status_mut() = hyper::StatusCode::NO_CONTENT;
    Ok(resp)
}

/// GET /{bucket}/{key}?uploadId=X — ListParts.
pub async fn list_parts(ctx: &Ctx, req: HandlerRequest) -> Result<Response<RespBody>, S3ErrorCode> {
    let upload_id = req
        .query1("uploadId")
        .ok_or(S3ErrorCode::InvalidArgument)?
        .to_string();
    let bucket = req.bucket.clone();
    let key = req.key.clone();

    let fs = ctx.fs.clone();
    let uid = upload_id.clone();
    let (lb, lk) = (bucket.clone(), key.clone());
    let parts = tokio::task::spawn_blocking(move || fs.list_parts(&lb, &lk, &uid))
        .await
        .map_err(|_| S3ErrorCode::InternalError)?
        .map_err(|e| map_storage_error(&e))?;

    let result = ListPartsResult {
        bucket,
        key,
        upload_id,
        parts: parts
            .into_iter()
            .map(|p| PartEntry {
                part_number: p.part_number,
                last_modified: format_time(p.last_modified_unix),
                etag: p.etag,
                size: p.size,
            })
            .collect(),
    };
    Ok(xml_ok(result.to_xml()))
}

/// Default `max-uploads` when the client omits it (also the hard cap). Mirrors
/// S3 and the storage-layer `MAX_UPLOADS_CAP`.
const DEFAULT_MAX_UPLOADS: i32 = 1000;

/// GET /{bucket}?uploads — ListMultipartUploads.
///
/// E7: honors the `max-uploads` query param (absent -> default; negative or
/// non-numeric -> 400 InvalidArgument; otherwise hard-capped at
/// [`DEFAULT_MAX_UPLOADS`], mirroring the `max-keys` validation), caps the
/// returned entries, and sets `IsTruncated` from the storage layer so
/// memory/response are bounded even with a huge `arriving/` working dir.
pub async fn list_multipart_uploads(
    ctx: &Ctx,
    req: HandlerRequest,
) -> Result<Response<RespBody>, S3ErrorCode> {
    let bucket = req.bucket.clone();

    // Parse max-uploads: absent -> default; present must be a non-negative int
    // (negative/garbage -> InvalidArgument); clamp to the hard cap.
    let max_uploads: i32 = match req.query1("max-uploads") {
        None => DEFAULT_MAX_UPLOADS,
        Some(s) => {
            let n: i32 = s.trim().parse().map_err(|_| S3ErrorCode::InvalidArgument)?;
            if n < 0 {
                return Err(S3ErrorCode::InvalidArgument);
            }
            n.min(DEFAULT_MAX_UPLOADS)
        }
    };

    let fs = ctx.fs.clone();
    let b = bucket.clone();
    let cap = max_uploads as usize;
    let (uploads, is_truncated) =
        tokio::task::spawn_blocking(move || fs.list_multipart_uploads(&b, cap))
            .await
            .map_err(|_| S3ErrorCode::InternalError)?
            .map_err(|e| map_storage_error(&e))?;

    let result = ListMultipartUploadsResult {
        bucket,
        key_marker: String::new(),
        max_uploads,
        is_truncated,
        uploads: uploads
            .into_iter()
            .map(|u| UploadEntry {
                key: u.key,
                upload_id: u.upload_id,
                initiated: format_time(u.initiated_unix),
            })
            .collect(),
    };
    Ok(xml_ok(result.to_xml()))
}

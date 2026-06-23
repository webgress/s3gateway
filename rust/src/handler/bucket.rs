//! Bucket-level handlers: Create, Head, Delete, ListBuckets.

use bytes::Bytes;
use hyper::{Response, StatusCode};

use crate::s3response::{format_time, BucketEntry, ListAllMyBucketsResult, Owner, S3ErrorCode};
use crate::storage::{validate_bucket_name, StorageError};

use super::{empty_body, map_storage_error, xml_ok, Ctx, HandlerRequest, RespBody};

/// PUT /{bucket} — CreateBucket.
pub async fn create_bucket(
    ctx: &Ctx,
    req: HandlerRequest,
) -> Result<Response<RespBody>, S3ErrorCode> {
    let bucket = req.bucket.clone();
    // Validate the name up front so we can return InvalidBucketName cleanly.
    if validate_bucket_name(&bucket).is_err() {
        return Err(S3ErrorCode::InvalidBucketName);
    }
    let fs = ctx.fs.clone();
    let res = tokio::task::spawn_blocking(move || fs.create_bucket(&bucket))
        .await
        .map_err(|_| S3ErrorCode::InternalError)?;
    match res {
        Ok(()) => {
            let mut resp = Response::new(empty_body());
            // S3 returns the bucket location header on create.
            resp.headers_mut().insert(
                hyper::header::LOCATION,
                format!("/{}", req.bucket).parse().unwrap(),
            );
            Ok(resp)
        }
        // Idempotent create for the same owner: S3 returns 200 here.
        Err(StorageError::BucketExists) => {
            let mut resp = Response::new(empty_body());
            resp.headers_mut().insert(
                hyper::header::LOCATION,
                format!("/{}", req.bucket).parse().unwrap(),
            );
            Ok(resp)
        }
        Err(StorageError::InvalidBucket) => Err(S3ErrorCode::InvalidBucketName),
        Err(e) => Err(map_storage_error(&e)),
    }
}

/// HEAD /{bucket} — HeadBucket.
pub async fn head_bucket(
    ctx: &Ctx,
    req: HandlerRequest,
) -> Result<Response<RespBody>, S3ErrorCode> {
    let bucket = req.bucket.clone();
    let fs = ctx.fs.clone();
    let res = tokio::task::spawn_blocking(move || fs.head_bucket(&bucket))
        .await
        .map_err(|_| S3ErrorCode::InternalError)?;
    match res {
        Ok(()) => Ok(Response::new(empty_body())),
        Err(e) => Err(map_storage_error(&e)),
    }
}

/// DELETE /{bucket} — DeleteBucket.
pub async fn delete_bucket(
    ctx: &Ctx,
    req: HandlerRequest,
) -> Result<Response<RespBody>, S3ErrorCode> {
    let bucket = req.bucket.clone();
    let fs = ctx.fs.clone();
    let res = tokio::task::spawn_blocking(move || fs.delete_bucket(&bucket))
        .await
        .map_err(|_| S3ErrorCode::InternalError)?;
    match res {
        Ok(()) => {
            let mut resp = Response::new(empty_body());
            *resp.status_mut() = StatusCode::NO_CONTENT;
            Ok(resp)
        }
        Err(e) => Err(map_storage_error(&e)),
    }
}

/// GET / — ListBuckets.
pub async fn list_buckets(
    ctx: &Ctx,
    _req: HandlerRequest,
) -> Result<Response<RespBody>, S3ErrorCode> {
    let fs = ctx.fs.clone();
    let buckets = tokio::task::spawn_blocking(move || fs.list_buckets())
        .await
        .map_err(|_| S3ErrorCode::InternalError)?
        .map_err(|e| map_storage_error(&e))?;

    let result = ListAllMyBucketsResult {
        owner: Owner {
            id: "s3gateway".to_string(),
            display_name: "s3gateway".to_string(),
        },
        buckets: buckets
            .into_iter()
            .map(|b| BucketEntry {
                name: b.name,
                creation_date: format_time(b.creation_unix),
            })
            .collect(),
    };
    let _ = Bytes::new();
    Ok(xml_ok(result.to_xml()))
}

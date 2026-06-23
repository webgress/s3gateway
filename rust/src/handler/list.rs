//! ListObjectsV2 handler: GET /{bucket}?list-type=2 (and plain GET /{bucket}).

use hyper::Response;

use crate::s3response::{format_time, ListBucketResultV2, ObjectEntry, S3ErrorCode};
use crate::storage::ListObjectsInput;

use super::{map_storage_error, xml_ok, Ctx, HandlerRequest, RespBody};

/// GET /{bucket} (with or without list-type=2) — ListObjectsV2.
pub async fn list_objects_v2(
    ctx: &Ctx,
    req: HandlerRequest,
) -> Result<Response<RespBody>, S3ErrorCode> {
    let prefix = req.query1("prefix").unwrap_or("").to_string();
    let delimiter = req.query1("delimiter").unwrap_or("").to_string();
    let start_after = req.query1("start-after").unwrap_or("").to_string();
    let continuation_token = req.query1("continuation-token").unwrap_or("").to_string();
    // F14: preserve ABSENT vs explicit value. `None` -> storage defaults to 1000;
    // `Some(0)` -> empty page with IsTruncated. The wire `max-keys` echoed back in
    // the response uses the effective value (1000 when absent).
    let max_keys: Option<i32> = req.query1("max-keys").and_then(|s| s.parse().ok());
    let effective_max_keys = max_keys.unwrap_or(1000);

    let input = ListObjectsInput {
        bucket: req.bucket.clone(),
        prefix: prefix.clone(),
        delimiter: delimiter.clone(),
        max_keys,
        start_after: start_after.clone(),
        continuation_token: continuation_token.clone(),
    };

    let fs = ctx.fs.clone();
    let out = tokio::task::spawn_blocking(move || fs.list_objects(&input))
        .await
        .map_err(|_| S3ErrorCode::InternalError)?
        .map_err(|e| map_storage_error(&e))?;

    let key_count = (out.objects.len() + out.common_prefixes.len()) as i32;
    let result = ListBucketResultV2 {
        name: req.bucket.clone(),
        prefix,
        delimiter,
        max_keys: effective_max_keys,
        is_truncated: out.is_truncated,
        key_count,
        start_after,
        continuation_token,
        next_continuation_token: out.next_continuation_token,
        contents: out
            .objects
            .into_iter()
            .map(|o| ObjectEntry {
                key: o.key,
                last_modified: format_time(o.last_modified_unix),
                etag: o.etag,
                size: o.size,
                storage_class: "STANDARD".to_string(),
            })
            .collect(),
        common_prefixes: out.common_prefixes,
    };

    Ok(xml_ok(result.to_xml()))
}

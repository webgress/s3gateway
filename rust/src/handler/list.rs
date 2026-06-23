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
    // F14/D6: preserve ABSENT vs explicit value. `None` -> storage defaults to
    // 1000; `Some(0)` -> empty page with IsTruncated; `Some(n)` caps the page.
    // D6: a PRESENT-but-invalid max-keys (non-numeric or < 0) is InvalidArgument
    // (400), matching AWS — it must NOT silently fall back to the 1000 default.
    let max_keys: Option<i32> = parse_max_keys(req.query1("max-keys"))?;
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

/// D6: parse the optional `max-keys` query value into the storage layer's
/// `Option<i32>` contract, validating per AWS:
///   - ABSENT (`None`)        -> `Ok(None)` (storage defaults to 1000)
///   - explicit `0`           -> `Ok(Some(0))` (empty page, IsTruncated; F14)
///   - explicit `n > 0`       -> `Ok(Some(n))`
///   - PRESENT but non-numeric OR `< 0` -> `Err(InvalidArgument)` (400)
///
/// The pre-D6 code used `.parse().ok()`, which silently mapped a non-numeric
/// value to `None` (the 1000 default) and let storage clamp negatives to 0 — both
/// of which AWS rejects as `InvalidArgument`.
fn parse_max_keys(raw: Option<&str>) -> Result<Option<i32>, S3ErrorCode> {
    match raw {
        None => Ok(None),
        Some(s) => match s.parse::<i64>() {
            Ok(n) if (0..=i32::MAX as i64).contains(&n) => Ok(Some(n as i32)),
            // Non-numeric, negative, or out of i32 range -> InvalidArgument.
            _ => Err(S3ErrorCode::InvalidArgument),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::parse_max_keys;
    use crate::s3response::S3ErrorCode;

    #[test]
    fn max_keys_validation() {
        // D6: absent -> None (storage defaults to 1000).
        assert_eq!(parse_max_keys(None), Ok(None));
        // Explicit 0 -> Some(0) (empty page, F14 behavior preserved).
        assert_eq!(parse_max_keys(Some("0")), Ok(Some(0)));
        // Positive -> Some(n).
        assert_eq!(parse_max_keys(Some("1000")), Ok(Some(1000)));
        assert_eq!(parse_max_keys(Some("7")), Ok(Some(7)));
        // Non-numeric -> InvalidArgument (was silently None/1000 before D6).
        assert_eq!(
            parse_max_keys(Some("abc")),
            Err(S3ErrorCode::InvalidArgument)
        );
        assert_eq!(parse_max_keys(Some("")), Err(S3ErrorCode::InvalidArgument));
        assert_eq!(
            parse_max_keys(Some("1.5")),
            Err(S3ErrorCode::InvalidArgument)
        );
        // Negative -> InvalidArgument (was silently clamped to 0 before D6).
        assert_eq!(
            parse_max_keys(Some("-1")),
            Err(S3ErrorCode::InvalidArgument)
        );
        assert_eq!(
            parse_max_keys(Some("-1000")),
            Err(S3ErrorCode::InvalidArgument)
        );
        // Out of i32 range -> InvalidArgument.
        assert_eq!(
            parse_max_keys(Some("99999999999")),
            Err(S3ErrorCode::InvalidArgument)
        );
    }
}

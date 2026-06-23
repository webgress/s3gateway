//! S3 error code -> (HTTP status, S3 code, message) mapping and error XML rendering.
//!
//! Ported from the Go `internal/s3response/errors.go`. The `<Error>` element
//! deliberately carries NO XML namespace (matches AWS S3 + the Go impl).

use std::fmt;

/// S3 API error codes. Each maps to an HTTP status, an S3 string code, and a
/// human-readable message via [`S3ErrorCode::api_error`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S3ErrorCode {
    AccessDenied,
    BucketAlreadyExists,
    BucketAlreadyOwnedByYou,
    BucketNotEmpty,
    InternalError,
    InvalidBucketName,
    InvalidPart,
    InvalidPartOrder,
    MalformedXML,
    NoSuchBucket,
    NoSuchKey,
    NoSuchUpload,
    SignatureDoesNotMatch,
    RequestTimeTooSkewed,
    InvalidAccessKeyId,
    MissingFields,
    MethodNotAllowed,
    InvalidArgument,
    InvalidRequest,
    /// F1: a PUT/CompleteMultipartUpload targets a key that already exists as a
    /// DIRECTORY (because a nested key made it a prefix dir). AWS returns 409
    /// Conflict for this object/prefix-name collision; we map it to a dedicated
    /// 409 code rather than silently orphaning the nested children.
    KeyPrefixConflict,
    EntityTooLarge,
    InvalidRange,
    /// E4/E5: the request body's actual size did not match what was declared/signed
    /// (e.g. de-framed aws-chunked bytes != x-amz-decoded-content-length, or a
    /// truncated body).
    IncompleteBody,
}

/// Resolved error metadata: S3 string code, message, and HTTP status code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiError {
    pub code: &'static str,
    pub message: &'static str,
    pub http_status: u16,
}

impl S3ErrorCode {
    /// Resolve this error code to its S3 string code, message, and HTTP status.
    pub fn api_error(self) -> ApiError {
        use S3ErrorCode::*;
        match self {
            AccessDenied => ApiError {
                code: "AccessDenied",
                message: "Access Denied.",
                http_status: 403,
            },
            BucketAlreadyExists => ApiError {
                code: "BucketAlreadyExists",
                message: "The requested bucket name is not available.",
                http_status: 409,
            },
            BucketAlreadyOwnedByYou => ApiError {
                code: "BucketAlreadyOwnedByYou",
                message: "Your previous request to create the named bucket succeeded and you already own it.",
                http_status: 409,
            },
            BucketNotEmpty => ApiError {
                code: "BucketNotEmpty",
                message: "The bucket you tried to delete is not empty.",
                http_status: 409,
            },
            InternalError => ApiError {
                code: "InternalError",
                message: "We encountered an internal error, please try again.",
                http_status: 500,
            },
            InvalidBucketName => ApiError {
                code: "InvalidBucketName",
                message: "The specified bucket is not valid.",
                http_status: 400,
            },
            InvalidPart => ApiError {
                code: "InvalidPart",
                message: "One or more of the specified parts could not be found.",
                http_status: 400,
            },
            InvalidPartOrder => ApiError {
                code: "InvalidPartOrder",
                message: "The list of parts was not in ascending order.",
                http_status: 400,
            },
            MalformedXML => ApiError {
                code: "MalformedXML",
                message: "The XML you provided was not well-formed.",
                http_status: 400,
            },
            NoSuchBucket => ApiError {
                code: "NoSuchBucket",
                message: "The specified bucket does not exist.",
                http_status: 404,
            },
            NoSuchKey => ApiError {
                code: "NoSuchKey",
                message: "The specified key does not exist.",
                http_status: 404,
            },
            NoSuchUpload => ApiError {
                code: "NoSuchUpload",
                message: "The specified multipart upload does not exist.",
                http_status: 404,
            },
            SignatureDoesNotMatch => ApiError {
                code: "SignatureDoesNotMatch",
                message: "The request signature we calculated does not match the signature you provided.",
                http_status: 403,
            },
            RequestTimeTooSkewed => ApiError {
                code: "RequestTimeTooSkewed",
                message: "The difference between the request time and the server's time is too large.",
                http_status: 403,
            },
            InvalidAccessKeyId => ApiError {
                code: "InvalidAccessKeyId",
                message: "The AWS access key ID you provided does not exist in our records.",
                http_status: 403,
            },
            MissingFields => ApiError {
                code: "MissingFields",
                message: "Missing required fields in the request.",
                http_status: 400,
            },
            MethodNotAllowed => ApiError {
                code: "MethodNotAllowed",
                message: "The specified method is not allowed against this resource.",
                http_status: 405,
            },
            InvalidArgument => ApiError {
                code: "InvalidArgument",
                message: "Invalid argument.",
                http_status: 400,
            },
            InvalidRequest => ApiError {
                code: "InvalidRequest",
                message: "Invalid request.",
                http_status: 400,
            },
            KeyPrefixConflict => ApiError {
                code: "KeyPrefixConflict",
                message: "The specified key conflicts with an existing object-name prefix.",
                http_status: 409,
            },
            EntityTooLarge => ApiError {
                code: "EntityTooLarge",
                message: "Your proposed upload exceeds the maximum allowed size.",
                http_status: 400,
            },
            InvalidRange => ApiError {
                code: "InvalidRange",
                message: "The requested range is not satisfiable.",
                http_status: 416,
            },
            IncompleteBody => ApiError {
                code: "IncompleteBody",
                message: "You did not provide the number of bytes specified by the Content-Length HTTP header.",
                http_status: 400,
            },
        }
    }

    pub fn http_status(self) -> u16 {
        self.api_error().http_status
    }

    pub fn code_str(self) -> &'static str {
        self.api_error().code
    }
}

impl fmt::Display for S3ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.code_str())
    }
}

impl std::error::Error for S3ErrorCode {}

/// Render an S3 error as XML. The `<Error>` element has NO namespace, matching
/// AWS S3 wire behavior. Hand-rolled (not serde) so we control exact byte
/// layout and XML-escape the resource path.
pub fn render_error_xml(err: S3ErrorCode, resource: &str, request_id: &str) -> String {
    let api = err.api_error();
    let mut out = String::with_capacity(256);
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
    out.push_str("<Error>");
    out.push_str("<Code>");
    xml_escape_into(api.code, &mut out);
    out.push_str("</Code>");
    out.push_str("<Message>");
    xml_escape_into(api.message, &mut out);
    out.push_str("</Message>");
    out.push_str("<Resource>");
    xml_escape_into(resource, &mut out);
    out.push_str("</Resource>");
    out.push_str("<RequestId>");
    xml_escape_into(request_id, &mut out);
    out.push_str("</RequestId>");
    out.push_str("</Error>");
    out
}

/// Minimal XML text escaping for ELEMENT CONTENT. Only `&`, `<`, `>` require
/// escaping in text nodes (quotes are only special inside attribute values, and
/// S3 ETags carry literal `"` in element text — matching Go's `encoding/xml`).
pub(crate) fn xml_escape_into(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            _ => out.push(c),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_mapping() {
        assert_eq!(S3ErrorCode::NoSuchBucket.http_status(), 404);
        assert_eq!(S3ErrorCode::NoSuchKey.http_status(), 404);
        assert_eq!(S3ErrorCode::BucketAlreadyExists.http_status(), 409);
        assert_eq!(S3ErrorCode::BucketAlreadyOwnedByYou.http_status(), 409);
        assert_eq!(S3ErrorCode::BucketNotEmpty.http_status(), 409);
        assert_eq!(S3ErrorCode::SignatureDoesNotMatch.http_status(), 403);
        assert_eq!(S3ErrorCode::InvalidAccessKeyId.http_status(), 403);
        assert_eq!(S3ErrorCode::AccessDenied.http_status(), 403);
        assert_eq!(S3ErrorCode::InvalidArgument.http_status(), 400);
        assert_eq!(S3ErrorCode::InvalidRequest.http_status(), 400);
        // F1: key/prefix (directory) conflict is a 409 Conflict.
        assert_eq!(S3ErrorCode::KeyPrefixConflict.http_status(), 409);
        assert_eq!(
            S3ErrorCode::KeyPrefixConflict.code_str(),
            "KeyPrefixConflict"
        );
        assert_eq!(S3ErrorCode::InternalError.http_status(), 500);
        assert_eq!(S3ErrorCode::RequestTimeTooSkewed.http_status(), 403);
        assert_eq!(S3ErrorCode::MethodNotAllowed.http_status(), 405);
        assert_eq!(S3ErrorCode::InvalidRange.http_status(), 416);
    }

    #[test]
    fn code_strings() {
        assert_eq!(S3ErrorCode::NoSuchKey.code_str(), "NoSuchKey");
        assert_eq!(
            S3ErrorCode::SignatureDoesNotMatch.code_str(),
            "SignatureDoesNotMatch"
        );
    }

    #[test]
    fn error_xml_no_namespace() {
        let xml = render_error_xml(S3ErrorCode::NoSuchKey, "/bucket/key", "req-123");
        // <Error> must NOT have an xmlns attribute.
        assert!(xml.contains("<Error>"));
        assert!(!xml.contains("xmlns"));
        assert!(xml.contains("<Code>NoSuchKey</Code>"));
        assert!(xml.contains("<Message>The specified key does not exist.</Message>"));
        assert!(xml.contains("<Resource>/bucket/key</Resource>"));
        assert!(xml.contains("<RequestId>req-123</RequestId>"));
        assert!(xml.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
    }

    #[test]
    fn error_xml_escapes_resource() {
        let xml = render_error_xml(S3ErrorCode::NoSuchKey, "/bucket/a&b<c>", "r");
        assert!(xml.contains("/bucket/a&amp;b&lt;c&gt;"));
    }
}

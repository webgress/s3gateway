//! S3 response layer: error code mapping + XML response/parse types.

pub mod errors;
pub mod xml;

pub use errors::{render_error_xml, ApiError, S3ErrorCode};
pub use xml::{
    format_time, BucketEntry, CompleteMultipartUpload, CompleteMultipartUploadResult,
    CompleteUploadPart, InitiateMultipartUploadResult, ListAllMyBucketsResult, ListBucketResultV2,
    ListMultipartUploadsResult, ListPartsResult, ObjectEntry, Owner, PartEntry, UploadEntry, S3_NS,
};

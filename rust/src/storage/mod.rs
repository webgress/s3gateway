//! Storage layer: aligned Direct-IO file primitives, metadata sidecars,
//! bucket/object/list/multipart operations, and streaming readers.

pub mod aligned;
pub mod directio;
pub mod filesystem;
pub mod metadata;
pub mod reader;

pub use aligned::{AlignedBuf, ALIGN, DEFAULT_BUF_SIZE};
pub use directio::{fsync_dir, rename, DioFile};
pub use filesystem::{
    validate_bucket_name, BucketInfo, CompletePart, Filesystem, GetObjectResult, ListObjectsInput,
    ListObjectsOutput, MultipartUpload, ObjectInfo, PartInfo, StorageError, META_SUFFIX,
    MULTIPART_DIR,
};
pub use metadata::{
    read_metadata, write_metadata, write_metadata_durable, ObjectMetadata, PartRef,
};
pub use reader::{parse_range, ByteRange, MultipartReader, PlainFileReader};

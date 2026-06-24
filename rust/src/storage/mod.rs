//! Storage layer: aligned Direct-IO file primitives, metadata sidecars,
//! bucket/object/list/multipart operations, and streaming readers.

pub mod aligned;
pub mod blob;
pub mod cas;
pub mod directio;
pub mod manifest;
pub mod metadata;
pub mod reader;
pub mod types;

pub use aligned::{AlignedBuf, ALIGN, DEFAULT_BUF_SIZE};
pub use directio::{fsync_dir, rename, DioFile};
pub use metadata::{
    commit_metadata_temp, read_metadata, write_metadata, write_metadata_durable,
    write_metadata_temp, write_metadata_temp_durable, ObjectMetadata, PartRef,
};
pub use reader::{parse_range, ByteRange, MultipartReader, PlainFileReader};

// Shared storage types and bucket-name validation — the handler-facing contract,
// independent of any one storage impl.
pub use types::{
    validate_bucket_name, BucketInfo, CompletePart, GetObjectResult, ListObjectsInput,
    ListObjectsOutput, MultipartUpload, ObjectInfo, PartInfo, StorageError, MAX_UPLOADS_CAP,
};

// Content-addressed storage: the live object/bucket/multipart implementation.
pub use blob::{blob_path, is_valid_blob_id, open_blob, reclaim_blob, write_blob, BlobInfo};
pub use cas::{CasStore, Journal, JournalMode, PartRefFile, ReclaimStats, RecoveryStats};
pub use manifest::{
    decode_relpath_to_key, escape_key_to_relpath, manifest_path, read_manifest,
    write_manifest_temp, Manifest, ManifestPartRef, MANIFEST_SUFFIX,
};

//! Storage layer: aligned Direct-IO file primitives, metadata sidecars,
//! bucket/object/list/multipart operations, and streaming readers.

pub mod aligned;
pub mod blob;
pub mod cas;
pub mod directio;
pub mod filesystem;
pub mod manifest;
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
    commit_metadata_temp, read_metadata, write_metadata, write_metadata_durable,
    write_metadata_temp, write_metadata_temp_durable, ObjectMetadata, PartRef,
};
pub use reader::{parse_range, ByteRange, MultipartReader, PlainFileReader};

// Content-addressed storage rewrite (Phase A). The NEW storage implementation,
// coexisting with `filesystem.rs`; not yet wired into the handlers. Re-exported
// here so it compiles as part of the public storage surface (no dead-code
// warnings) ahead of the later wiring phase.
pub use blob::{blob_path, is_valid_blob_id, open_blob, reclaim_blob, write_blob, BlobInfo};
pub use cas::{CasStore, Journal, JournalMode, PartRefFile, ReclaimStats, RecoveryStats};
pub use manifest::{
    decode_relpath_to_key, escape_key_to_relpath, manifest_path, read_manifest,
    write_manifest_temp, Manifest, ManifestPartRef,
};

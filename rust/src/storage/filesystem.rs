//! Filesystem storage layer: bucket/object/list/multipart operations.
//!
//! Ported from the Go `internal/storage/filesystem.go`, with two deliberate
//! optimizations called out inline:
//!   1. ONE-PASS MD5 on PutObject/UploadPart: a single read->md5.update->write
//!      loop over a reused buffer; the object is never held in memory.
//!   2. MULTIPART STORE-PARTS / REASSEMBLE-ON-READ: CompleteMultipartUpload does
//!      NOT concatenate parts into one file. It records an ordered part manifest
//!      in the `.s3meta` sidecar; GetObject reassembles on read via
//!      [`crate::storage::reader::MultipartReader`].
//!
//! Blocking helpers are intended to run inside `tokio::task::spawn_blocking`.

use std::collections::BTreeMap;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use md5::{Digest, Md5};
use uuid::Uuid;

use super::aligned::{AlignedBuf, DEFAULT_BUF_SIZE};
use super::directio::{self, DioFile};
use super::metadata::{read_metadata, write_metadata, ObjectMetadata, PartRef};
use super::reader::{ByteRange, MultipartReader, PlainFileReader};

pub const META_SUFFIX: &str = ".s3meta";
pub const MULTIPART_DIR: &str = ".multipart";

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("bucket not found")]
    BucketNotFound,
    #[error("bucket not empty")]
    BucketNotEmpty,
    #[error("bucket already exists")]
    BucketExists,
    #[error("object not found")]
    ObjectNotFound,
    #[error("invalid bucket name")]
    InvalidBucket,
    #[error("path traversal detected")]
    PathTraversal,
    #[error("no such upload")]
    NoSuchUpload,
    #[error("invalid part order")]
    InvalidPartOrder,
    #[error("invalid part")]
    InvalidPart,
    #[error("io error: {0}")]
    Io(#[from] io::Error),
}

pub type Result<T> = std::result::Result<T, StorageError>;

/// Root-anchored filesystem store.
#[derive(Debug, Clone)]
pub struct Filesystem {
    root: PathBuf,
}

#[derive(Debug, Clone)]
pub struct BucketInfo {
    pub name: String,
    /// Creation/modification time as Unix seconds.
    pub creation_unix: i64,
}

#[derive(Debug, Clone)]
pub struct ObjectInfo {
    pub key: String,
    pub size: i64,
    /// ETag including quotes.
    pub etag: String,
    pub last_modified_unix: i64,
}

#[derive(Debug, Default, Clone)]
pub struct ListObjectsInput {
    pub bucket: String,
    pub prefix: String,
    pub delimiter: String,
    pub max_keys: i32,
    pub start_after: String,
    pub continuation_token: String,
}

#[derive(Debug, Default)]
pub struct ListObjectsOutput {
    pub objects: Vec<ObjectInfo>,
    pub common_prefixes: Vec<String>,
    pub is_truncated: bool,
    pub next_continuation_token: String,
}

/// Streaming result of GetObject: metadata + a boxed blocking reader.
pub struct GetObjectResult {
    pub metadata: ObjectMetadata,
    pub body: Box<dyn Read + Send>,
    /// The range actually served (None = full object).
    pub range: Option<ByteRange>,
    /// Full object size (regardless of range).
    pub total_size: u64,
}

/// Multipart upload metadata sidecar (`.multipart/{id}/meta.json`).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MultipartUpload {
    pub upload_id: String,
    pub bucket: String,
    pub key: String,
    pub initiated_unix: i64,
    #[serde(default)]
    pub content_type: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub user_metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct PartInfo {
    pub part_number: i32,
    pub size: i64,
    pub etag: String,
    pub last_modified_unix: i64,
}

/// A part the client claims in CompleteMultipartUpload.
#[derive(Debug, Clone)]
pub struct CompletePart {
    pub part_number: i32,
    pub etag: String,
}

fn now_unix() -> i64 {
    crate::auth::time::now_unix()
}

impl Filesystem {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Filesystem { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    // ---- Bucket operations ----

    pub fn create_bucket(&self, name: &str) -> Result<()> {
        validate_bucket_name(name)?;
        let path = self.root.join(name);
        match std::fs::create_dir(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Err(StorageError::BucketExists),
            Err(e) => Err(e.into()),
        }
    }

    pub fn head_bucket(&self, name: &str) -> Result<()> {
        self.validate_bucket_component(name)?;
        let path = self.root.join(name);
        match std::fs::metadata(&path) {
            Ok(m) if m.is_dir() => Ok(()),
            Ok(_) => Err(StorageError::BucketNotFound),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Err(StorageError::BucketNotFound),
            Err(e) => Err(e.into()),
        }
    }

    pub fn delete_bucket(&self, name: &str) -> Result<()> {
        self.validate_bucket_component(name)?;
        let path = self.root.join(name);
        match std::fs::metadata(&path) {
            Ok(m) if m.is_dir() => {}
            Ok(_) => return Err(StorageError::BucketNotFound),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(StorageError::BucketNotFound)
            }
            Err(e) => return Err(e.into()),
        }
        // Empty iff it contains nothing but a (per-bucket) .multipart dir.
        for entry in std::fs::read_dir(&path)? {
            let entry = entry?;
            if entry.file_name() != MULTIPART_DIR {
                return Err(StorageError::BucketNotEmpty);
            }
        }
        let _ = std::fs::remove_dir_all(path.join(MULTIPART_DIR));
        std::fs::remove_dir(&path)?;
        Ok(())
    }

    pub fn list_buckets(&self) -> Result<Vec<BucketInfo>> {
        let mut out = Vec::new();
        let rd = match std::fs::read_dir(&self.root) {
            Ok(rd) => rd,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(e.into()),
        };
        for entry in rd {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') {
                continue;
            }
            let md = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            if !md.is_dir() {
                continue;
            }
            out.push(BucketInfo {
                name,
                creation_unix: mtime_unix(&md),
            });
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    // ---- Object operations ----

    /// PutObject: stream `body` to a temp file with a ONE-PASS MD5, fsync,
    /// atomic rename, write `.s3meta`. Returns the quoted ETag.
    pub fn put_object<R: Read>(
        &self,
        bucket: &str,
        key: &str,
        mut body: R,
        content_type: &str,
        user_meta: BTreeMap<String, String>,
    ) -> Result<String> {
        self.validate_object_path(bucket, key)?;
        self.head_bucket(bucket)?;

        let obj_path = self.root.join(bucket).join(key);
        if let Some(parent) = obj_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let tmp_path = tmp_sibling(&obj_path);
        // Cleanup guard: remove the temp file on any early return.
        let mut guard = TmpGuard::new(tmp_path.clone());

        let file = DioFile::create_write(&tmp_path)?;
        let mut buf = AlignedBuf::new(DEFAULT_BUF_SIZE);
        let mut hasher = Md5::new();
        let mut written: u64 = 0;
        let cap = buf.capacity();
        loop {
            // ONE-PASS: read a block, fold it into MD5, then write the same
            // block out. The payload is never fully materialized in memory.
            let n = read_full(&mut body, &mut buf[..cap])?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            write_all_at(&file, &buf[..n], written)?;
            written += n as u64;
        }
        file.fsync()?;
        drop(file);

        let etag = format!("\"{}\"", hex::encode(hasher.finalize()));

        directio::rename(&tmp_path, &obj_path)?;
        guard.disarm();

        let ct = if content_type.is_empty() {
            "application/octet-stream"
        } else {
            content_type
        };
        let meta = ObjectMetadata {
            content_type: ct.to_string(),
            content_length: written as i64,
            etag: etag.clone(),
            last_modified: now_unix(),
            user_metadata: user_meta,
            content_disposition: String::new(),
            content_encoding: String::new(),
            cache_control: String::new(),
            multipart: None,
        };
        write_metadata(&meta_path(&obj_path), &meta)?;
        // A single-part PUT over a prior multipart object must drop the old
        // `{key}.parts` store (the new `.s3meta` already has `multipart: None`,
        // so GetObject reads the single file; the stale parts would just leak).
        let _ = std::fs::remove_dir_all(parts_store_dir(&obj_path));
        Ok(etag)
    }

    /// GetObject: returns metadata + a streaming body reader. Transparently uses
    /// the plain file reader for single-part objects and the reassemble-on-read
    /// [`MultipartReader`] for multipart objects. Supports a byte range.
    pub fn get_object(
        &self,
        bucket: &str,
        key: &str,
        range: Option<ByteRange>,
    ) -> Result<GetObjectResult> {
        self.validate_object_path(bucket, key)?;
        let obj_path = self.root.join(bucket).join(key);
        let mp = meta_path(&obj_path);

        let meta = match read_metadata(&mp) {
            Ok(m) => m,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                // No sidecar: treat as missing object (after bucket check).
                self.head_bucket(bucket)?;
                return Err(StorageError::ObjectNotFound);
            }
            Err(e) => return Err(e.into()),
        };

        if let Some(parts) = &meta.multipart {
            let total: u64 = parts.iter().map(|p| p.size).sum();
            let body = MultipartReader::new(parts.clone(), range);
            return Ok(GetObjectResult {
                metadata: meta,
                body: Box::new(body),
                range,
                total_size: total,
            });
        }

        // Single-part object.
        match PlainFileReader::open(&obj_path, range) {
            Ok(reader) => {
                let total = meta.content_length as u64;
                Ok(GetObjectResult {
                    metadata: meta,
                    body: Box::new(reader),
                    range,
                    total_size: total,
                })
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                self.head_bucket(bucket)?;
                Err(StorageError::ObjectNotFound)
            }
            Err(e) => Err(e.into()),
        }
    }

    pub fn head_object(&self, bucket: &str, key: &str) -> Result<ObjectMetadata> {
        self.validate_object_path(bucket, key)?;
        let obj_path = self.root.join(bucket).join(key);
        match read_metadata(&meta_path(&obj_path)) {
            Ok(m) => Ok(m),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                self.head_bucket(bucket)?;
                Err(StorageError::ObjectNotFound)
            }
            Err(e) => Err(e.into()),
        }
    }

    /// DeleteObject: idempotent removal of file + sidecar; prunes empty parents.
    /// For multipart objects, also removes the `{key}.parts` store directory that
    /// holds the reassemble-on-read part files (otherwise they leak and block
    /// bucket deletion).
    pub fn delete_object(&self, bucket: &str, key: &str) -> Result<()> {
        self.validate_object_path(bucket, key)?;
        let obj_path = self.root.join(bucket).join(key);
        let _ = std::fs::remove_file(&obj_path);
        let _ = std::fs::remove_file(meta_path(&obj_path));
        // Multipart objects store their parts in a sibling `{key}.parts` dir.
        let _ = std::fs::remove_dir_all(parts_store_dir(&obj_path));

        let bucket_path = self.root.join(bucket);
        let mut dir = obj_path.parent().map(PathBuf::from);
        while let Some(d) = dir {
            if d == bucket_path {
                break;
            }
            if std::fs::remove_dir(&d).is_err() {
                break; // not empty / other error
            }
            dir = d.parent().map(PathBuf::from);
        }
        Ok(())
    }

    // ---- Listing ----

    pub fn list_objects(&self, input: &ListObjectsInput) -> Result<ListObjectsOutput> {
        self.head_bucket(&input.bucket)?;
        let bucket_path = self.root.join(&input.bucket);
        let max_keys = if input.max_keys <= 0 { 1000 } else { input.max_keys };

        let mut all_keys: Vec<ObjectInfo> = Vec::new();
        let mut prefix_set: BTreeMap<String, ()> = BTreeMap::new();

        walk_dir(&bucket_path, &mut |path: &Path| -> io::Result<()> {
            let file_name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
            // Skip sidecars and temp files.
            if file_name.ends_with(META_SUFFIX) || file_name.contains(".tmp.") {
                return Ok(());
            }
            let rel = path.strip_prefix(&bucket_path).unwrap();
            let key = rel.to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/");

            if !input.prefix.is_empty() && !key.starts_with(&input.prefix) {
                return Ok(());
            }
            if !input.delimiter.is_empty() {
                let after = &key[input.prefix.len()..];
                if let Some(idx) = after.find(&input.delimiter) {
                    let cp = format!("{}{}", input.prefix, &after[..idx + input.delimiter.len()]);
                    prefix_set.insert(cp, ());
                    return Ok(());
                }
            }
            let md = std::fs::metadata(path)?;
            // Prefer the `.s3meta` sidecar when present: it carries the TRUE
            // size/etag/last-modified. This matters for completed multipart
            // objects, whose on-disk data file is a 0-byte placeholder (the
            // real bytes live in the `{key}.parts` store, with the size in the
            // sidecar's content_length).
            let (size, etag, last_modified_unix) = match read_metadata(&meta_path(path)) {
                Ok(m) => (m.content_length, m.etag, m.last_modified),
                Err(_) => (md.len() as i64, String::new(), mtime_unix(&md)),
            };
            all_keys.push(ObjectInfo {
                key,
                size,
                etag,
                last_modified_unix,
            });
            Ok(())
        })?;

        all_keys.sort_by(|a, b| a.key.cmp(&b.key));
        let mut common_prefixes: Vec<String> = prefix_set.into_keys().collect();
        common_prefixes.sort();

        // start-after / continuation-token (token wins).
        let start_after = if !input.continuation_token.is_empty() {
            input.continuation_token.as_str()
        } else {
            input.start_after.as_str()
        };
        if !start_after.is_empty() {
            all_keys.retain(|o| o.key.as_str() > start_after);
            common_prefixes.retain(|p| p.as_str() > start_after);
        }

        // Merge-paginate objects+prefixes, both counting against max_keys.
        let mut out = ListObjectsOutput::default();
        let mut count = 0i32;
        let mut oi = 0;
        let mut pi = 0;
        while count < max_keys && (oi < all_keys.len() || pi < common_prefixes.len()) {
            let use_obj = if oi < all_keys.len() && pi < common_prefixes.len() {
                all_keys[oi].key <= common_prefixes[pi]
            } else {
                oi < all_keys.len()
            };
            if use_obj {
                out.objects.push(all_keys[oi].clone());
                oi += 1;
            } else {
                out.common_prefixes.push(common_prefixes[pi].clone());
                pi += 1;
            }
            count += 1;
        }

        if oi < all_keys.len() || pi < common_prefixes.len() {
            out.is_truncated = true;
            if let Some(o) = out.objects.last() {
                out.next_continuation_token = o.key.clone();
            } else if let Some(p) = out.common_prefixes.last() {
                out.next_continuation_token = p.clone();
            }
        }
        Ok(out)
    }

    // ---- Multipart ----

    pub fn create_multipart_upload(
        &self,
        bucket: &str,
        key: &str,
        content_type: &str,
        user_meta: BTreeMap<String, String>,
    ) -> Result<String> {
        self.validate_object_path(bucket, key)?;
        self.head_bucket(bucket)?;

        let upload_id = Uuid::new_v4().to_string();
        let upload_dir = self.upload_dir(&upload_id);
        std::fs::create_dir_all(upload_dir.join("parts"))?;

        let meta = MultipartUpload {
            upload_id: upload_id.clone(),
            bucket: bucket.to_string(),
            key: key.to_string(),
            initiated_unix: now_unix(),
            content_type: content_type.to_string(),
            user_metadata: user_meta,
        };
        let data =
            serde_json::to_vec_pretty(&meta).map_err(io::Error::other)?;
        std::fs::write(upload_dir.join("meta.json"), data)?;
        Ok(upload_id)
    }

    /// UploadPart: stream the part to `parts/{NNNNN}` with a ONE-PASS MD5.
    /// Part MD5s are independent, so concurrent UploadPart requests parallelize.
    pub fn upload_part<R: Read>(
        &self,
        upload_id: &str,
        part_number: i32,
        mut body: R,
    ) -> Result<String> {
        let upload_dir = self.upload_dir(upload_id);
        if !upload_dir.join("meta.json").exists() {
            return Err(StorageError::NoSuchUpload);
        }
        let part_path = upload_dir.join("parts").join(format!("{:05}", part_number));
        let tmp_path = tmp_sibling(&part_path);
        let mut guard = TmpGuard::new(tmp_path.clone());

        let file = DioFile::create_write(&tmp_path)?;
        let mut buf = AlignedBuf::new(DEFAULT_BUF_SIZE);
        let mut hasher = Md5::new();
        let mut written: u64 = 0;
        let cap = buf.capacity();
        loop {
            let n = read_full(&mut body, &mut buf[..cap])?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            write_all_at(&file, &buf[..n], written)?;
            written += n as u64;
        }
        file.fsync()?;
        drop(file);

        let etag = format!("\"{}\"", hex::encode(hasher.finalize()));
        directio::rename(&tmp_path, &part_path)?;
        guard.disarm();
        Ok(etag)
    }

    /// CompleteMultipartUpload: validate the claimed parts against stored part
    /// MD5s, compute the COMPOSITE ETag, and write the object's `.s3meta` with a
    /// part MANIFEST. Parts are NOT concatenated; the object is reassembled on
    /// read. Returns the composite ETag.
    pub fn complete_multipart_upload(
        &self,
        upload_id: &str,
        parts: &[CompletePart],
    ) -> Result<String> {
        let upload_dir = self.upload_dir(upload_id);
        let meta_raw = match std::fs::read(upload_dir.join("meta.json")) {
            Ok(d) => d,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(StorageError::NoSuchUpload)
            }
            Err(e) => return Err(e.into()),
        };
        let upload: MultipartUpload = serde_json::from_slice(&meta_raw)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        // Re-validate the recorded bucket/key before joining (defense in depth:
        // the manifest is trusted, but the containment check also covers the
        // `{key}.parts` store dir we create below).
        self.validate_object_path(&upload.bucket, &upload.key)?;

        // Parts must be strictly ascending by number.
        for w in parts.windows(2) {
            if w[1].part_number <= w[0].part_number {
                return Err(StorageError::InvalidPartOrder);
            }
        }

        self.head_bucket(&upload.bucket)?;

        // Validate each part exists + ETag matches; build the manifest.
        let mut manifest: Vec<PartRef> = Vec::with_capacity(parts.len());
        let mut md5_concat: Vec<u8> = Vec::with_capacity(parts.len() * 16);
        let mut total: u64 = 0;
        for p in parts {
            let part_path = upload_dir.join("parts").join(format!("{:05}", p.part_number));
            let md = match std::fs::metadata(&part_path) {
                Ok(m) => m,
                Err(_) => return Err(StorageError::InvalidPart),
            };
            // Compute the part MD5 by streaming (avoids loading into memory).
            let (digest, _size) = md5_file(&part_path)?;
            let hex_md5 = hex::encode(digest);
            if !p.etag.is_empty() {
                let provided = p.etag.trim_matches('"');
                if provided != hex_md5 {
                    return Err(StorageError::InvalidPart);
                }
            }
            md5_concat.extend_from_slice(&digest);
            total += md.len();
            manifest.push(PartRef {
                part_number: p.part_number,
                path: part_path.to_string_lossy().into_owned(),
                size: md.len(),
                md5_hex: hex_md5,
            });
        }

        // Composite ETag: md5(concat of raw 16-byte part digests)-N.
        let composite = Md5::digest(&md5_concat);
        let etag = format!("\"{}-{}\"", hex::encode(composite), parts.len());

        // Persist the part files to a stable location keyed by the object so the
        // upload dir can be cleaned. We MOVE parts into a per-object store dir
        // and rewrite the manifest paths. This keeps "store parts, reassemble on
        // read" while making the object durable independent of .multipart/{id}.
        let obj_path = self.root.join(&upload.bucket).join(&upload.key);
        if let Some(parent) = obj_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let parts_store = parts_store_dir(&obj_path);
        // Clear any pre-existing part store (e.g. overwriting a 3-part object
        // with a 2-part one) so stale parts like `00003` don't orphan.
        match std::fs::remove_dir_all(&parts_store) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        std::fs::create_dir_all(&parts_store)?;
        for pr in manifest.iter_mut() {
            let dest = parts_store.join(format!("{:05}", pr.part_number));
            directio::rename(Path::new(&pr.path), &dest)?;
            pr.path = dest.to_string_lossy().into_owned();
        }
        // The reassembled-on-read object has no single data file; we write a
        // zero-byte placeholder at obj_path so existence checks behave, then the
        // sidecar carries the manifest. (GetObject keys off the sidecar.)
        let _ = std::fs::write(&obj_path, b"");

        let ct = if upload.content_type.is_empty() {
            "application/octet-stream"
        } else {
            &upload.content_type
        };
        let meta = ObjectMetadata {
            content_type: ct.to_string(),
            content_length: total as i64,
            etag: etag.clone(),
            last_modified: now_unix(),
            user_metadata: upload.user_metadata.clone(),
            content_disposition: String::new(),
            content_encoding: String::new(),
            cache_control: String::new(),
            multipart: Some(manifest),
        };
        write_metadata(&meta_path(&obj_path), &meta)?;

        // Cleanup the upload working dir.
        let _ = std::fs::remove_dir_all(&upload_dir);
        Ok(etag)
    }

    pub fn abort_multipart_upload(&self, upload_id: &str) -> Result<()> {
        let upload_dir = self.upload_dir(upload_id);
        if !upload_dir.join("meta.json").exists() {
            return Err(StorageError::NoSuchUpload);
        }
        std::fs::remove_dir_all(&upload_dir)?;
        Ok(())
    }

    pub fn list_multipart_uploads(&self, bucket: &str) -> Result<Vec<MultipartUpload>> {
        let mp_dir = self.root.join(MULTIPART_DIR);
        let rd = match std::fs::read_dir(&mp_dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        let mut out = Vec::new();
        for entry in rd {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let meta_path = entry.path().join("meta.json");
            let data = match std::fs::read(&meta_path) {
                Ok(d) => d,
                Err(_) => continue,
            };
            if let Ok(u) = serde_json::from_slice::<MultipartUpload>(&data) {
                if bucket.is_empty() || u.bucket == bucket {
                    out.push(u);
                }
            }
        }
        out.sort_by(|a, b| a.key.cmp(&b.key));
        Ok(out)
    }

    pub fn list_parts(&self, upload_id: &str) -> Result<Vec<PartInfo>> {
        let upload_dir = self.upload_dir(upload_id);
        if !upload_dir.join("meta.json").exists() {
            return Err(StorageError::NoSuchUpload);
        }
        let parts_dir = upload_dir.join("parts");
        let mut out = Vec::new();
        for entry in std::fs::read_dir(&parts_dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if entry.file_type()?.is_dir() || name.contains(".tmp.") {
                continue;
            }
            let part_num: i32 = match name.trim_start_matches('0').parse() {
                Ok(n) => n,
                Err(_) => match name.parse() {
                    // "00000" -> 0
                    Ok(n) => n,
                    Err(_) => continue,
                },
            };
            let md = entry.metadata()?;
            let (digest, _) = md5_file(&entry.path())?;
            out.push(PartInfo {
                part_number: part_num,
                size: md.len() as i64,
                etag: format!("\"{}\"", hex::encode(digest)),
                last_modified_unix: mtime_unix(&md),
            });
        }
        out.sort_by_key(|p| p.part_number);
        Ok(out)
    }

    // ---- helpers ----

    fn upload_dir(&self, upload_id: &str) -> PathBuf {
        self.root.join(MULTIPART_DIR).join(upload_id)
    }

    /// Validate the bucket NAME as a path component: reject `..`, `.`, empty,
    /// embedded separators / null bytes, and anything failing S3 bucket-name
    /// rules. This must run BEFORE the bucket is ever joined onto `self.root`,
    /// otherwise a bucket of `..` escapes the data root.
    fn validate_bucket_component(&self, bucket: &str) -> Result<()> {
        if bucket.is_empty()
            || bucket == "."
            || bucket == ".."
            || bucket.contains('/')
            || bucket.contains('\\')
            || bucket.contains('\0')
        {
            return Err(StorageError::PathTraversal);
        }
        // Full S3 bucket-name rules (lowercase, length, no IP, etc.).
        validate_bucket_name(bucket).map_err(|_| StorageError::PathTraversal)?;
        Ok(())
    }

    /// Reject keys with `..`, null bytes, absolute paths, or that escape the
    /// bucket dir — AND reject malicious bucket components before joining.
    /// After building the final path, assert it is strictly a descendant of
    /// `self.root` (never equal to root's parent / root itself).
    fn validate_object_path(&self, bucket: &str, key: &str) -> Result<()> {
        self.validate_bucket_component(bucket)?;
        if key.contains("..") || key.contains('\0') {
            return Err(StorageError::PathTraversal);
        }
        // Reject absolute keys that resolve outside (join of absolute replaces).
        if Path::new(key).is_absolute() {
            return Err(StorageError::PathTraversal);
        }
        let bucket_path = self.root.join(bucket);
        let full = bucket_path.join(key);
        let base = normalize(&bucket_path);
        let cleaned = normalize(&full);
        if cleaned != base && !cleaned.starts_with(&base) {
            return Err(StorageError::PathTraversal);
        }
        // Containment: the resolved path must be strictly inside the data root.
        self.assert_within_root(&cleaned)?;
        Ok(())
    }

    /// Assert `path` (already lexically normalized) is a strict descendant of
    /// `self.root` — i.e. inside the data dir, never root's parent or above.
    fn assert_within_root(&self, path: &Path) -> Result<()> {
        let root = normalize(&self.root);
        if path == root || !path.starts_with(&root) {
            return Err(StorageError::PathTraversal);
        }
        Ok(())
    }
}

/// RAII cleanup for a temp file: removes it on drop unless disarmed (which the
/// caller does immediately after a successful atomic rename moves it away).
struct TmpGuard {
    path: PathBuf,
    armed: bool,
}
impl TmpGuard {
    fn new(path: PathBuf) -> Self {
        TmpGuard { path, armed: true }
    }
    fn disarm(&mut self) {
        self.armed = false;
    }
}
impl Drop for TmpGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

fn meta_path(obj_path: &Path) -> PathBuf {
    let mut s = obj_path.as_os_str().to_owned();
    s.push(META_SUFFIX);
    PathBuf::from(s)
}

fn parts_store_dir(obj_path: &Path) -> PathBuf {
    let mut s = obj_path.as_os_str().to_owned();
    s.push(".parts");
    PathBuf::from(s)
}

fn tmp_sibling(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(format!(".tmp.{}", Uuid::new_v4()));
    PathBuf::from(s)
}

/// Read up to `buf.len()` bytes, looping until the buffer is full or EOF.
fn read_full<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut total = 0;
    while total < buf.len() {
        match r.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(total)
}

/// Write the entire buffer at `offset` (handles short pwrites).
fn write_all_at(file: &DioFile, mut buf: &[u8], mut offset: u64) -> io::Result<()> {
    while !buf.is_empty() {
        let n = file.pwrite_at(buf, offset)?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "pwrite wrote 0"));
        }
        offset += n as u64;
        buf = &buf[n..];
    }
    Ok(())
}

/// Stream a file through MD5; returns (16-byte digest, size).
fn md5_file(path: &Path) -> io::Result<([u8; 16], u64)> {
    let f = DioFile::open_read(path)?;
    let mut buf = AlignedBuf::new(DEFAULT_BUF_SIZE);
    let mut hasher = Md5::new();
    let mut off = 0u64;
    let cap = buf.capacity();
    loop {
        let n = f.pread_at(&mut buf[..cap], off)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        off += n as u64;
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&hasher.finalize());
    Ok((out, off))
}

/// Recursively walk a bucket directory, calling `cb` for each regular file.
/// Skips the `.multipart` dir and any `.parts` part-store directories.
fn walk_dir(dir: &Path, cb: &mut dyn FnMut(&Path) -> io::Result<()>) -> io::Result<()> {
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    for entry in rd {
        let entry = entry?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        let ft = entry.file_type()?;
        if ft.is_dir() {
            if name_str == MULTIPART_DIR || name_str.ends_with(".parts") {
                continue;
            }
            walk_dir(&entry.path(), cb)?;
        } else if ft.is_file() {
            cb(&entry.path())?;
        }
    }
    Ok(())
}

/// Pure lexical path normalization (no fs access), resolving `.`/`..`.
fn normalize(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in p.components() {
        use std::path::Component::*;
        match comp {
            CurDir => {}
            ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn mtime_unix(md: &std::fs::Metadata) -> i64 {
    md.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Validate an S3 bucket name (Go `ValidateBucketName` + CLAUDE.md rules).
pub fn validate_bucket_name(name: &str) -> Result<()> {
    let bytes = name.as_bytes();
    let n = bytes.len();
    if !(3..=63).contains(&n) {
        return Err(StorageError::InvalidBucket);
    }
    for (i, &c) in bytes.iter().enumerate() {
        let ok = c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'.' || c == b'-';
        if !ok {
            return Err(StorageError::InvalidBucket);
        }
        if i > 0 && c == b'.' && bytes[i - 1] == b'.' {
            return Err(StorageError::InvalidBucket);
        }
    }
    let first = bytes[0];
    let last = bytes[n - 1];
    if !(first.is_ascii_lowercase() || first.is_ascii_digit()) {
        return Err(StorageError::InvalidBucket);
    }
    if !(last.is_ascii_lowercase() || last.is_ascii_digit()) {
        return Err(StorageError::InvalidBucket);
    }
    if name.starts_with("xn--") {
        return Err(StorageError::InvalidBucket);
    }
    if name.ends_with("-s3alias") {
        return Err(StorageError::InvalidBucket);
    }
    if is_ipv4(name) {
        return Err(StorageError::InvalidBucket);
    }
    Ok(())
}

/// True if `name` looks like a dotted IPv4 address (a.b.c.d, 0-255 octets).
fn is_ipv4(name: &str) -> bool {
    let parts: Vec<&str> = name.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts.iter().all(|p| {
        !p.is_empty()
            && p.len() <= 3
            && p.bytes().all(|b| b.is_ascii_digit())
            && p.parse::<u16>().map(|v| v <= 255).unwrap_or(false)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fs() -> (tempfile::TempDir, Filesystem) {
        let dir = tempfile::tempdir().unwrap();
        let f = Filesystem::new(dir.path());
        (dir, f)
    }

    fn um() -> BTreeMap<String, String> {
        BTreeMap::new()
    }

    // ---- bucket ----

    #[test]
    fn bucket_lifecycle() {
        let (_d, f) = fs();
        f.create_bucket("my-bucket").unwrap();
        assert!(matches!(
            f.create_bucket("my-bucket"),
            Err(StorageError::BucketExists)
        ));
        f.head_bucket("my-bucket").unwrap();
        assert!(matches!(
            f.head_bucket("nope"),
            Err(StorageError::BucketNotFound)
        ));
        let buckets = f.list_buckets().unwrap();
        assert_eq!(buckets.len(), 1);
        f.delete_bucket("my-bucket").unwrap();
        assert!(matches!(
            f.head_bucket("my-bucket"),
            Err(StorageError::BucketNotFound)
        ));
    }

    #[test]
    fn delete_non_empty_bucket_fails() {
        let (_d, f) = fs();
        f.create_bucket("bkt").unwrap();
        f.put_object("bkt", "k", &b"data"[..], "text/plain", um())
            .unwrap();
        assert!(matches!(
            f.delete_bucket("bkt"),
            Err(StorageError::BucketNotEmpty)
        ));
    }

    #[test]
    fn bucket_name_validation() {
        assert!(validate_bucket_name("abc").is_ok());
        assert!(validate_bucket_name("my-bucket.example").is_ok());
        assert!(validate_bucket_name("a1b2").is_ok());
        // too short / long
        assert!(validate_bucket_name("ab").is_err());
        assert!(validate_bucket_name(&"a".repeat(64)).is_err());
        // uppercase
        assert!(validate_bucket_name("MyBucket").is_err());
        // start/end with non-alnum
        assert!(validate_bucket_name("-abc").is_err());
        assert!(validate_bucket_name("abc-").is_err());
        assert!(validate_bucket_name(".abc").is_err());
        // adjacent dots
        assert!(validate_bucket_name("a..b").is_err());
        // ip address
        assert!(validate_bucket_name("192.168.0.1").is_err());
        // xn-- prefix, -s3alias suffix
        assert!(validate_bucket_name("xn--abc").is_err());
        assert!(validate_bucket_name("mybucket-s3alias").is_err());
        // invalid char
        assert!(validate_bucket_name("under_score").is_err());
    }

    // ---- object round trips ----

    #[test]
    fn put_get_head_delete_small() {
        let (_d, f) = fs();
        f.create_bucket("buck").unwrap();
        let data = b"hello, world";
        let etag = f
            .put_object("buck", "greeting.txt", &data[..], "text/plain", um())
            .unwrap();
        // ETag = quoted md5
        let expected = format!("\"{}\"", hex::encode(Md5::digest(data)));
        assert_eq!(etag, expected);

        // head
        let meta = f.head_object("buck", "greeting.txt").unwrap();
        assert_eq!(meta.content_length, data.len() as i64);
        assert_eq!(meta.content_type, "text/plain");
        assert_eq!(meta.etag, expected);

        // get
        let mut res = f.get_object("buck", "greeting.txt", None).unwrap();
        let mut got = Vec::new();
        res.body.read_to_end(&mut got).unwrap();
        assert_eq!(got, data);
        assert_eq!(res.total_size, data.len() as u64);

        // delete -> gone
        f.delete_object("buck", "greeting.txt").unwrap();
        assert!(matches!(
            f.get_object("buck", "greeting.txt", None),
            Err(StorageError::ObjectNotFound)
        ));
        // delete is idempotent
        f.delete_object("buck", "greeting.txt").unwrap();
    }

    #[test]
    fn user_metadata_preserved() {
        let (_d, f) = fs();
        f.create_bucket("buck").unwrap();
        let mut m = BTreeMap::new();
        m.insert("x-amz-meta-foo".to_string(), "bar".to_string());
        f.put_object("buck", "k", &b"x"[..], "", m.clone()).unwrap();
        let meta = f.head_object("buck", "k").unwrap();
        assert_eq!(meta.user_metadata.get("x-amz-meta-foo").unwrap(), "bar");
        assert_eq!(meta.content_type, "application/octet-stream");
    }

    #[test]
    fn zero_byte_object() {
        let (_d, f) = fs();
        f.create_bucket("buck").unwrap();
        let etag = f.put_object("buck", "empty", &b""[..], "", um()).unwrap();
        assert_eq!(etag, format!("\"{}\"", hex::encode(Md5::digest(b""))));
        let mut res = f.get_object("buck", "empty", None).unwrap();
        let mut got = Vec::new();
        res.body.read_to_end(&mut got).unwrap();
        assert!(got.is_empty());
    }

    #[test]
    fn streaming_50mb_round_trip() {
        let (_d, f) = fs();
        f.create_bucket("buck").unwrap();
        let size = 50 * 1024 * 1024 + 12345; // not a page multiple
        let data: Vec<u8> = (0..size).map(|i| (i as u8).wrapping_mul(31)).collect();
        let etag = f.put_object("buck", "big", &data[..], "", um()).unwrap();
        assert_eq!(etag, format!("\"{}\"", hex::encode(Md5::digest(&data))));
        let mut res = f.get_object("buck", "big", None).unwrap();
        let mut got = Vec::new();
        res.body.read_to_end(&mut got).unwrap();
        assert_eq!(got.len(), data.len());
        assert_eq!(got, data);
    }

    #[test]
    fn get_range_on_single_part() {
        let (_d, f) = fs();
        f.create_bucket("buck").unwrap();
        let data: Vec<u8> = (0..5000).map(|i| (i % 256) as u8).collect();
        f.put_object("buck", "k", &data[..], "", um()).unwrap();
        let r = ByteRange { start: 1000, end: 1999 };
        let mut res = f.get_object("buck", "k", Some(r)).unwrap();
        let mut got = Vec::new();
        res.body.read_to_end(&mut got).unwrap();
        assert_eq!(got, data[1000..=1999]);
    }

    #[test]
    fn unicode_and_nested_keys() {
        let (_d, f) = fs();
        f.create_bucket("buck").unwrap();
        f.put_object("buck", "日本語/ファイル.txt", &b"u"[..], "", um())
            .unwrap();
        f.put_object("buck", "a/b/c/deep.txt", &b"d"[..], "", um())
            .unwrap();
        let mut r = f.get_object("buck", "日本語/ファイル.txt", None).unwrap();
        let mut got = Vec::new();
        r.body.read_to_end(&mut got).unwrap();
        assert_eq!(got, b"u");
    }

    #[test]
    fn key_with_spaces() {
        let (_d, f) = fs();
        f.create_bucket("buck").unwrap();
        f.put_object("buck", "my file name.txt", &b"s"[..], "", um())
            .unwrap();
        let meta = f.head_object("buck", "my file name.txt").unwrap();
        assert_eq!(meta.content_length, 1);
    }

    #[test]
    fn put_to_missing_bucket() {
        let (_d, f) = fs();
        assert!(matches!(
            f.put_object("nope", "k", &b"x"[..], "", um()),
            Err(StorageError::BucketNotFound)
        ));
    }

    #[test]
    fn path_traversal_rejected() {
        let (_d, f) = fs();
        f.create_bucket("buck").unwrap();
        assert!(matches!(
            f.put_object("buck", "../escape", &b"x"[..], "", um()),
            Err(StorageError::PathTraversal)
        ));
        assert!(matches!(
            f.put_object("buck", "a/../../escape", &b"x"[..], "", um()),
            Err(StorageError::PathTraversal)
        ));
        assert!(matches!(
            f.head_object("buck", "/etc/passwd"),
            Err(StorageError::PathTraversal)
        ));
        assert!(matches!(
            f.head_object("buck", "with\0null"),
            Err(StorageError::PathTraversal)
        ));
    }

    #[test]
    fn malicious_bucket_name_rejected_on_all_ops() {
        // Regression: a bucket of `..` (or anything failing S3 rules) must be
        // rejected BEFORE it is joined onto the data root, on every op that
        // builds a path. Otherwise `GET /../secret/x` escapes the data dir.
        let (_d, f) = fs();
        for bucket in ["..", ".", "", "/", "a/b", "with\0null", "../escape"] {
            assert!(
                matches!(
                    f.get_object(bucket, "k", None),
                    Err(StorageError::PathTraversal)
                ),
                "get_object should reject bucket {bucket:?}"
            );
            assert!(
                matches!(
                    f.put_object(bucket, "k", &b"x"[..], "", um()),
                    Err(StorageError::PathTraversal)
                ),
                "put_object should reject bucket {bucket:?}"
            );
            assert!(
                matches!(
                    f.delete_object(bucket, "k"),
                    Err(StorageError::PathTraversal)
                ),
                "delete_object should reject bucket {bucket:?}"
            );
            assert!(
                matches!(
                    f.list_objects(&ListObjectsInput {
                        bucket: bucket.to_string(),
                        ..Default::default()
                    }),
                    Err(StorageError::PathTraversal)
                ),
                "list_objects should reject bucket {bucket:?}"
            );
            assert!(
                matches!(f.head_object(bucket, "k"), Err(StorageError::PathTraversal)),
                "head_object should reject bucket {bucket:?}"
            );
        }
        // The traversal key `../x` is also rejected within a valid bucket.
        f.create_bucket("valid-bucket").unwrap();
        assert!(matches!(
            f.get_object("valid-bucket", "../x", None),
            Err(StorageError::PathTraversal)
        ));
        assert!(matches!(
            f.put_object("valid-bucket", "../x", &b"x"[..], "", um()),
            Err(StorageError::PathTraversal)
        ));
        // A deep legit nested key still works end-to-end.
        f.put_object("valid-bucket", "a/b/c/d/e/deep.txt", &b"deep"[..], "", um())
            .unwrap();
        let mut r = f.get_object("valid-bucket", "a/b/c/d/e/deep.txt", None).unwrap();
        let mut got = Vec::new();
        r.body.read_to_end(&mut got).unwrap();
        assert_eq!(got, b"deep");
    }

    #[test]
    fn malicious_bucket_does_not_escape_data_root_on_disk() {
        // End-to-end: a `..` bucket write must NOT create a file outside root.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let f = Filesystem::new(&root);
        // PUT /../target/pwned.txt style attempt.
        assert!(matches!(
            f.put_object("..", "target/pwned.txt", &b"pwned"[..], "", um()),
            Err(StorageError::PathTraversal)
        ));
        // Nothing was written in the parent of the data root.
        let parent = root.parent().unwrap();
        assert!(!parent.join("target").join("pwned.txt").exists());
    }

    // ---- listing ----

    #[test]
    fn list_prefix_delimiter_pagination() {
        let (_d, f) = fs();
        f.create_bucket("buck").unwrap();
        for i in 0..10 {
            f.put_object("buck", &format!("file{:02}", i), &b"x"[..], "", um())
                .unwrap();
        }
        f.put_object("buck", "dir/a", &b"x"[..], "", um()).unwrap();
        f.put_object("buck", "dir/b", &b"x"[..], "", um()).unwrap();

        // list all
        let out = f
            .list_objects(&ListObjectsInput {
                bucket: "buck".into(),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(out.objects.len(), 12);
        assert!(!out.is_truncated);

        // prefix filter
        let out = f
            .list_objects(&ListObjectsInput {
                bucket: "buck".into(),
                prefix: "file0".into(),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(out.objects.len(), 10);

        // delimiter grouping
        let out = f
            .list_objects(&ListObjectsInput {
                bucket: "buck".into(),
                delimiter: "/".into(),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(out.common_prefixes, vec!["dir/".to_string()]);
        assert_eq!(out.objects.len(), 10); // the file00..file09 (no slash)

        // pagination: max-keys 3
        let out = f
            .list_objects(&ListObjectsInput {
                bucket: "buck".into(),
                prefix: "file".into(),
                max_keys: 3,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(out.objects.len(), 3);
        assert!(out.is_truncated);
        assert_eq!(out.next_continuation_token, "file02");

        // continue
        let out2 = f
            .list_objects(&ListObjectsInput {
                bucket: "buck".into(),
                prefix: "file".into(),
                max_keys: 100,
                continuation_token: out.next_continuation_token.clone(),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(out2.objects.len(), 7);
        assert_eq!(out2.objects[0].key, "file03");
    }

    #[test]
    fn list_empty_bucket() {
        let (_d, f) = fs();
        f.create_bucket("buck").unwrap();
        let out = f
            .list_objects(&ListObjectsInput {
                bucket: "buck".into(),
                ..Default::default()
            })
            .unwrap();
        assert!(out.objects.is_empty());
        assert!(!out.is_truncated);
    }

    #[test]
    fn list_start_after() {
        let (_d, f) = fs();
        f.create_bucket("buck").unwrap();
        for k in ["a", "buck", "c", "d"] {
            f.put_object("buck", k, &b"x"[..], "", um()).unwrap();
        }
        let out = f
            .list_objects(&ListObjectsInput {
                bucket: "buck".into(),
                start_after: "buck".into(),
                ..Default::default()
            })
            .unwrap();
        let keys: Vec<_> = out.objects.iter().map(|o| o.key.as_str()).collect();
        assert_eq!(keys, vec!["c", "d"]);
    }

    // ---- multipart ----

    #[test]
    fn multipart_full_round_trip() {
        let (_d, f) = fs();
        f.create_bucket("buck").unwrap();
        let uid = f
            .create_multipart_upload("buck", "big.bin", "application/octet-stream", um())
            .unwrap();

        // 3 parts of varied sizes.
        let p1 = vec![1u8; 5 * 1024 * 1024];
        let p2 = vec![2u8; 5 * 1024 * 1024];
        let p3 = vec![3u8; 1234];
        let e1 = f.upload_part(&uid, 1, &p1[..]).unwrap();
        let e2 = f.upload_part(&uid, 2, &p2[..]).unwrap();
        let e3 = f.upload_part(&uid, 3, &p3[..]).unwrap();
        assert_eq!(e1, format!("\"{}\"", hex::encode(Md5::digest(&p1))));

        // list parts
        let parts = f.list_parts(&uid).unwrap();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0].part_number, 1);

        // list uploads
        let ups = f.list_multipart_uploads("buck").unwrap();
        assert_eq!(ups.len(), 1);
        assert_eq!(ups[0].key, "big.bin");

        // complete
        let etag = f
            .complete_multipart_upload(
                &uid,
                &[
                    CompletePart { part_number: 1, etag: e1.clone() },
                    CompletePart { part_number: 2, etag: e2.clone() },
                    CompletePart { part_number: 3, etag: e3.clone() },
                ],
            )
            .unwrap();

        // composite ETag format: "<hex>-3"
        let mut concat = Vec::new();
        concat.extend_from_slice(&Md5::digest(&p1));
        concat.extend_from_slice(&Md5::digest(&p2));
        concat.extend_from_slice(&Md5::digest(&p3));
        let expected = format!("\"{}-3\"", hex::encode(Md5::digest(&concat)));
        assert_eq!(etag, expected);

        // reassemble-on-read produces the exact concatenation
        let mut res = f.get_object("buck", "big.bin", None).unwrap();
        assert!(res.metadata.is_multipart());
        let mut got = Vec::new();
        res.body.read_to_end(&mut got).unwrap();
        let mut full = p1.clone();
        full.extend_from_slice(&p2);
        full.extend_from_slice(&p3);
        assert_eq!(got.len(), full.len());
        assert_eq!(got, full);

        // range read across reassembled object
        let r = ByteRange { start: 5 * 1024 * 1024 - 2, end: 5 * 1024 * 1024 + 2 };
        let mut res = f.get_object("buck", "big.bin", Some(r)).unwrap();
        let mut got = Vec::new();
        res.body.read_to_end(&mut got).unwrap();
        assert_eq!(got, &full[(5 * 1024 * 1024 - 2)..=(5 * 1024 * 1024 + 2)]);

        // upload dir cleaned up
        assert!(matches!(
            f.list_parts(&uid),
            Err(StorageError::NoSuchUpload)
        ));
    }

    #[test]
    fn list_reports_multipart_real_size_and_composite_etag() {
        // Regression: completed multipart objects are a 0-byte placeholder on
        // disk; listing must report the TRUE size + composite ETag from the
        // `.s3meta` sidecar, not the placeholder's 0 length.
        let (_d, f) = fs();
        f.create_bucket("buck").unwrap();
        let uid = f
            .create_multipart_upload("buck", "mp.bin", "", um())
            .unwrap();
        let p1 = vec![7u8; 5 * 1024 * 1024];
        let p2 = vec![9u8; 4096];
        let e1 = f.upload_part(&uid, 1, &p1[..]).unwrap();
        let e2 = f.upload_part(&uid, 2, &p2[..]).unwrap();
        let composite = f
            .complete_multipart_upload(
                &uid,
                &[
                    CompletePart { part_number: 1, etag: e1 },
                    CompletePart { part_number: 2, etag: e2 },
                ],
            )
            .unwrap();
        let real_size = (p1.len() + p2.len()) as i64;

        let out = f
            .list_objects(&ListObjectsInput {
                bucket: "buck".into(),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(out.objects.len(), 1);
        let obj = &out.objects[0];
        assert_eq!(obj.key, "mp.bin");
        assert_eq!(obj.size, real_size, "listed size must be the real object size");
        assert_eq!(obj.etag, composite, "listed etag must be the composite -N");
        assert!(obj.etag.ends_with("-2\""), "composite etag should end with -2");
    }

    #[test]
    fn multipart_wrong_etag_rejected() {
        let (_d, f) = fs();
        f.create_bucket("buck").unwrap();
        let uid = f.create_multipart_upload("buck", "k", "", um()).unwrap();
        f.upload_part(&uid, 1, &b"hello"[..]).unwrap();
        let err = f.complete_multipart_upload(
            &uid,
            &[CompletePart { part_number: 1, etag: "\"deadbeef\"".into() }],
        );
        assert!(matches!(err, Err(StorageError::InvalidPart)));
    }

    #[test]
    fn multipart_wrong_order_rejected() {
        let (_d, f) = fs();
        f.create_bucket("buck").unwrap();
        let uid = f.create_multipart_upload("buck", "k", "", um()).unwrap();
        f.upload_part(&uid, 1, &b"a"[..]).unwrap();
        f.upload_part(&uid, 2, &b"b"[..]).unwrap();
        let err = f.complete_multipart_upload(
            &uid,
            &[
                CompletePart { part_number: 2, etag: String::new() },
                CompletePart { part_number: 1, etag: String::new() },
            ],
        );
        assert!(matches!(err, Err(StorageError::InvalidPartOrder)));
    }

    #[test]
    fn multipart_abort_cleans_up() {
        let (_d, f) = fs();
        f.create_bucket("buck").unwrap();
        let uid = f.create_multipart_upload("buck", "k", "", um()).unwrap();
        f.upload_part(&uid, 1, &b"a"[..]).unwrap();
        f.abort_multipart_upload(&uid).unwrap();
        assert!(matches!(
            f.list_parts(&uid),
            Err(StorageError::NoSuchUpload)
        ));
        assert!(matches!(
            f.abort_multipart_upload(&uid),
            Err(StorageError::NoSuchUpload)
        ));
    }

    #[test]
    fn upload_part_overwrite() {
        let (_d, f) = fs();
        f.create_bucket("buck").unwrap();
        let uid = f.create_multipart_upload("buck", "k", "", um()).unwrap();
        f.upload_part(&uid, 1, &b"first"[..]).unwrap();
        let e = f.upload_part(&uid, 1, &b"second-version"[..]).unwrap();
        assert_eq!(e, format!("\"{}\"", hex::encode(Md5::digest(b"second-version"))));
        let parts = f.list_parts(&uid).unwrap();
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].size, "second-version".len() as i64);
    }

    #[test]
    fn delete_multipart_object_cleans_parts_and_allows_bucket_delete() {
        let (_d, f) = fs();
        f.create_bucket("buck").unwrap();
        let uid = f
            .create_multipart_upload("buck", "obj.bin", "", um())
            .unwrap();
        let p1 = vec![1u8; 5 * 1024 * 1024];
        let p2 = vec![2u8; 1024];
        let e1 = f.upload_part(&uid, 1, &p1[..]).unwrap();
        let e2 = f.upload_part(&uid, 2, &p2[..]).unwrap();
        f.complete_multipart_upload(
            &uid,
            &[
                CompletePart { part_number: 1, etag: e1 },
                CompletePart { part_number: 2, etag: e2 },
            ],
        )
        .unwrap();
        // Delete the object; the `.parts` store dir must be removed too.
        f.delete_object("buck", "obj.bin").unwrap();
        assert!(matches!(
            f.get_object("buck", "obj.bin", None),
            Err(StorageError::ObjectNotFound)
        ));
        // Bucket must now be empty and deletable.
        f.delete_bucket("buck").unwrap();
        assert!(matches!(
            f.head_bucket("buck"),
            Err(StorageError::BucketNotFound)
        ));
    }

    #[test]
    fn complete_over_prior_multipart_clears_stale_parts() {
        // Regression: completing a 2-part upload over a prior 3-part object must
        // not leave the old `00003` part orphaned, and GET returns the new bytes.
        let (_d, f) = fs();
        f.create_bucket("buck").unwrap();
        let key = "obj.bin";

        // First: a 3-part object.
        let uid3 = f.create_multipart_upload("buck", key, "", um()).unwrap();
        let a1 = vec![1u8; 5 * 1024 * 1024];
        let a2 = vec![2u8; 5 * 1024 * 1024];
        let a3 = vec![3u8; 1234];
        let e1 = f.upload_part(&uid3, 1, &a1[..]).unwrap();
        let e2 = f.upload_part(&uid3, 2, &a2[..]).unwrap();
        let e3 = f.upload_part(&uid3, 3, &a3[..]).unwrap();
        f.complete_multipart_upload(
            &uid3,
            &[
                CompletePart { part_number: 1, etag: e1 },
                CompletePart { part_number: 2, etag: e2 },
                CompletePart { part_number: 3, etag: e3 },
            ],
        )
        .unwrap();
        let parts_dir = parts_store_dir(&f.root().join("buck").join(key));
        assert!(parts_dir.join("00003").exists(), "3-part object has 00003");

        // Now: overwrite with a 2-part object.
        let uid2 = f.create_multipart_upload("buck", key, "", um()).unwrap();
        let b1 = vec![4u8; 5 * 1024 * 1024];
        let b2 = vec![5u8; 4321];
        let f1 = f.upload_part(&uid2, 1, &b1[..]).unwrap();
        let f2 = f.upload_part(&uid2, 2, &b2[..]).unwrap();
        f.complete_multipart_upload(
            &uid2,
            &[
                CompletePart { part_number: 1, etag: f1 },
                CompletePart { part_number: 2, etag: f2 },
            ],
        )
        .unwrap();

        // No stale 00003 remains.
        assert!(!parts_dir.join("00003").exists(), "stale 00003 must be gone");
        assert!(parts_dir.join("00001").exists());
        assert!(parts_dir.join("00002").exists());

        // GET returns the new 2-part bytes.
        let mut res = f.get_object("buck", key, None).unwrap();
        let mut got = Vec::new();
        res.body.read_to_end(&mut got).unwrap();
        let mut expected = b1.clone();
        expected.extend_from_slice(&b2);
        assert_eq!(got.len(), expected.len());
        assert_eq!(got, expected);
    }

    #[test]
    fn single_part_put_over_multipart_drops_parts() {
        // Regression: a single-part PUT over a multipart object must remove the
        // old `{key}.parts` dir, and GET must return the single-part bytes.
        let (_d, f) = fs();
        f.create_bucket("buck").unwrap();
        let key = "obj.bin";

        let uid = f.create_multipart_upload("buck", key, "", um()).unwrap();
        let p1 = vec![1u8; 5 * 1024 * 1024];
        let p2 = vec![2u8; 2048];
        let e1 = f.upload_part(&uid, 1, &p1[..]).unwrap();
        let e2 = f.upload_part(&uid, 2, &p2[..]).unwrap();
        f.complete_multipart_upload(
            &uid,
            &[
                CompletePart { part_number: 1, etag: e1 },
                CompletePart { part_number: 2, etag: e2 },
            ],
        )
        .unwrap();
        let parts_dir = parts_store_dir(&f.root().join("buck").join(key));
        assert!(parts_dir.exists(), "multipart object has a .parts dir");

        // Overwrite with a single-part PUT.
        let new_bytes = b"just a small single-part object";
        f.put_object("buck", key, &new_bytes[..], "", um()).unwrap();

        // .parts dir is gone and the sidecar no longer references a manifest.
        assert!(!parts_dir.exists(), ".parts must be removed after single PUT");
        let meta = f.head_object("buck", key).unwrap();
        assert!(!meta.is_multipart(), "sidecar must not be multipart anymore");

        // GET returns the single-part bytes.
        let mut res = f.get_object("buck", key, None).unwrap();
        let mut got = Vec::new();
        res.body.read_to_end(&mut got).unwrap();
        assert_eq!(got, new_bytes);
    }

    #[test]
    fn upload_part_no_such_upload() {
        let (_d, f) = fs();
        f.create_bucket("buck").unwrap();
        assert!(matches!(
            f.upload_part("does-not-exist", 1, &b"x"[..]),
            Err(StorageError::NoSuchUpload)
        ));
    }
}

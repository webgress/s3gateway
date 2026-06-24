//! Content-addressed store: the single-object lifecycle on the immutable-blob +
//! manifest + commit/journal model (REDESIGN Phases 1+2+3).
//!
//! This module is the NEW storage implementation. It COEXISTS with the old
//! `filesystem.rs` impl during Phase A — handlers are NOT rewired here. It holds
//! the public object API (`put_object`/`get_object`/`head_object`/`delete_object`)
//! with signatures identical to today's `Filesystem`, plus the bucket-infra
//! creation and the commit/journal protocol that is the heart of the rewrite.
//!
//! Deferred to later phases (stubbed/omitted here): multipart, ListObjectsV2,
//! the full `recover()` sweep wiring, and the handler rewiring + old-impl
//! deletion. The reclaim/journal PRIMITIVES (and a deterministic test-only fault
//! hook) are implemented now so crash-recovery can be unit-tested.

use std::collections::BTreeMap;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use md5::Digest as _;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::blob;
use super::filesystem::{
    validate_bucket_name, BucketInfo, CompletePart, GetObjectResult, ListObjectsInput,
    ListObjectsOutput, MultipartUpload, ObjectInfo, PartInfo, StorageError, MAX_UPLOADS_CAP,
};
use super::manifest::{
    self, Manifest, ManifestPartRef, ARRIVING_DIR, CURRENT_DIR, DELETED_DIR, META_SUFFIX,
};
use super::metadata::ObjectMetadata;
use super::reader::{parse_range, ByteRange, MultipartReader, PlainFileReader};

pub type Result<T> = std::result::Result<T, StorageError>;

/// Number of shards in the per-key publish lock table (mirrors `filesystem.rs`).
const KEY_LOCK_SHARDS: usize = 256;

/// A reclaim journal: a durable to-delete list keyed to a specific commit, with a
/// `commit_nonce` the sweep uses to decide whether the corresponding commit
/// actually landed (REDESIGN §3.2 / §4).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Journal {
    /// "publish" (supersede) or "delete".
    pub mode: JournalMode,
    /// Escaped-key-independent: the object key whose live manifest decides
    /// executability (the key being superseded/deleted).
    pub supersedes_key: String,
    /// For `publish`: the NEW version's `commit_nonce`. The sweep deletes the
    /// listed (OLD) blobs IFF the live manifest at `supersedes_key` carries
    /// exactly this nonce. For `delete`: ignored (the rule is "K absent").
    pub commit_nonce: String,
    /// Fast pre-filter (REDESIGN §3.2): the NEW version's etag. Authoritative
    /// check is the nonce.
    #[serde(default)]
    pub expected_new_etag: String,
    /// OLD blob ids to reclaim once the commit/delete is confirmed.
    pub blobs: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JournalMode {
    Publish,
    Delete,
}

/// One `.ref`-file-per-part record under `arriving/{upload_id}/parts/{NNNNN}.ref`
/// (REDESIGN §6 / §13.6). UploadPart writes its OWN ref (no shared file), so
/// concurrent uploads of different part numbers never contend; Complete reads the
/// dir to assemble the ordered manifest. Tiny JSON.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PartRefFile {
    pub part_number: u32,
    /// The immutable part blob's id (`blobs/xx/yy/{blob_id}`).
    pub blob_id: String,
    pub size: u64,
    /// Hex MD5 of the part blob's bytes (no quotes) — the part ETag and a Complete
    /// validation input.
    pub md5_hex: String,
}

/// Test-only deterministic fault-injection points within the commit/delete
/// protocol, so a unit test can simulate a crash BETWEEN any two steps and then
/// assert the on-disk state matches the REDESIGN §3.1 / §4 table. Mirrors the
/// existing `FORCE_SIDECAR_FAIL` thread-local discipline (no cross-test leakage).
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultPoint {
    /// Crash after the blob is written but before staging the manifest.
    BeforeStage,
    /// Crash after staging the arriving manifest, before writing the journal.
    BeforeJournal,
    /// Crash after writing the journal, before the commit rename.
    BeforeCommit,
    /// Crash after the commit rename, before reclaiming old blobs.
    BeforeReclaim,
    /// Crash after reclaiming old blobs, before deleting the journal.
    BeforeJournalCleanup,
}

#[cfg(test)]
thread_local! {
    static FORCE_FAULT: std::cell::Cell<Option<FaultPoint>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
pub(crate) fn set_fault(p: Option<FaultPoint>) {
    FORCE_FAULT.with(|c| c.set(p));
}

/// True when a simulated crash is armed for protocol point `_p`. In test builds
/// this consults the thread-local fault; in production it is a compile-time
/// `false` (the parameter is unused), so the commit protocol has ZERO fault-check
/// cost in release builds.
#[inline(always)]
#[cfg(test)]
fn fault_armed(p: FaultPoint) -> bool {
    FORCE_FAULT.with(|c| c.get()) == Some(p)
}

#[cfg(test)]
fn simulated_crash() -> StorageError {
    StorageError::Io(io::Error::other("simulated crash (test fault injection)"))
}

/// Content-addressed store rooted at `root` (the data dir).
#[derive(Debug, Clone)]
pub struct CasStore {
    root: PathBuf,
    /// Gates manifest/journal/dir fsyncs (data-blob fsync is always on). Mirrors
    /// `Filesystem::fsync` / the `--fsync` flag.
    fsync: bool,
    key_locks: std::sync::Arc<Vec<std::sync::RwLock<()>>>,
}

/// Snapshot of a reclaim outcome (for tests / future recover()).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ReclaimStats {
    pub blobs_deleted: usize,
    pub journals_removed: usize,
}

impl CasStore {
    /// Create a store with durable publication enabled (fsync), like `Filesystem::new`.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self::with_fsync(root, true)
    }

    /// Create a store with an explicit durability mode (mirrors `with_fsync`).
    pub fn with_fsync(root: impl Into<PathBuf>, fsync: bool) -> Self {
        let mut locks = Vec::with_capacity(KEY_LOCK_SHARDS);
        for _ in 0..KEY_LOCK_SHARDS {
            locks.push(std::sync::RwLock::new(()));
        }
        CasStore {
            root: root.into(),
            fsync,
            key_locks: std::sync::Arc::new(locks),
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    // ---- locking (mirrors filesystem.rs: FNV-1a sharded per {bucket}/{key}) ----

    fn key_lock_shard(bucket: &str, key: &str) -> usize {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for byte in bucket
            .bytes()
            .chain(std::iter::once(b'/'))
            .chain(key.bytes())
        {
            h ^= byte as u64;
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        (h as usize) & (KEY_LOCK_SHARDS - 1)
    }

    fn lock_key(&self, bucket: &str, key: &str) -> std::sync::RwLockWriteGuard<'_, ()> {
        let idx = Self::key_lock_shard(bucket, key);
        self.key_locks[idx]
            .write()
            .unwrap_or_else(|p| p.into_inner())
    }

    fn rlock_key(&self, bucket: &str, key: &str) -> std::sync::RwLockReadGuard<'_, ()> {
        let idx = Self::key_lock_shard(bucket, key);
        self.key_locks[idx].read().unwrap_or_else(|p| p.into_inner())
    }

    // ---- bucket infra ----

    fn bucket_root(&self, bucket: &str) -> PathBuf {
        self.root.join(bucket)
    }
    fn current_root(&self, bucket: &str) -> PathBuf {
        self.bucket_root(bucket).join(CURRENT_DIR)
    }
    fn arriving_root(&self, bucket: &str) -> PathBuf {
        self.bucket_root(bucket).join(ARRIVING_DIR)
    }
    fn deleted_root(&self, bucket: &str) -> PathBuf {
        self.bucket_root(bucket).join(DELETED_DIR)
    }

    /// Create the bucket directory and its four infra subdirs (current/ arriving/
    /// blobs/ deleted/). Idempotent for the infra dirs; the bucket dir itself must
    /// not already exist (S3 BucketExists semantics).
    pub fn create_bucket(&self, name: &str) -> Result<()> {
        validate_bucket_name(name)?;
        let path = self.bucket_root(name);
        match std::fs::create_dir(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                return Err(StorageError::BucketExists)
            }
            Err(e) => return Err(e.into()),
        }
        self.ensure_infra(name)?;
        Ok(())
    }

    /// Lazily create the infra subdirs (used by create_bucket and defensively by
    /// the object path before staging).
    fn ensure_infra(&self, bucket: &str) -> io::Result<()> {
        std::fs::create_dir_all(self.current_root(bucket))?;
        std::fs::create_dir_all(self.arriving_root(bucket))?;
        std::fs::create_dir_all(self.bucket_root(bucket).join(blob::BLOBS_DIR))?;
        std::fs::create_dir_all(self.deleted_root(bucket))?;
        Ok(())
    }

    /// HeadBucket: the bucket must be a real directory (symlink-aware), mirroring
    /// `Filesystem::head_bucket`.
    pub fn head_bucket(&self, name: &str) -> Result<()> {
        self.validate_bucket_component(name)?;
        let path = self.bucket_root(name);
        match std::fs::symlink_metadata(&path) {
            Ok(m) if m.file_type().is_dir() => Ok(()),
            Ok(_) => Err(StorageError::BucketNotFound),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Err(StorageError::BucketNotFound),
            Err(e) => Err(e.into()),
        }
    }

    // ---- object: PUT (single-part) ----

    /// PutObject (single-part): stream `body` to a fresh blob with a ONE-PASS MD5,
    /// then PUBLISH a 1-part manifest via the commit/journal protocol. Returns the
    /// quoted single-part ETag. Signature identical to `Filesystem::put_object`.
    pub fn put_object<R: Read>(
        &self,
        bucket: &str,
        key: &str,
        body: R,
        content_type: &str,
        user_meta: BTreeMap<String, String>,
    ) -> Result<String> {
        self.validate_object_path(bucket, key)?;
        self.head_bucket(bucket)?;
        self.ensure_infra(bucket)?;

        let bucket_root = self.bucket_root(bucket);

        // Stream the body to a blob (lock-free; one-pass MD5; fsync). This is the
        // big work and runs BEFORE the per-key publish lock is taken.
        let info = blob::write_blob(&bucket_root, body).map_err(body_or_io)?;

        let etag = format!("\"{}\"", info.md5_hex);
        let ct = if content_type.is_empty() {
            "application/octet-stream"
        } else {
            content_type
        };
        let now = now_unix();
        let manifest = Manifest {
            key: key.to_string(),
            content_type: ct.to_string(),
            content_length: info.size,
            etag: etag.clone(),
            last_modified: now,
            created: now,
            user_metadata: user_meta,
            content_disposition: String::new(),
            content_encoding: String::new(),
            cache_control: String::new(),
            parts: vec![ManifestPartRef {
                part_number: 1,
                blob_id: info.blob_id.clone(),
                size: info.size,
                md5_hex: info.md5_hex.clone(),
            }],
            commit_nonce: Manifest::new_nonce(),
        };

        // Commit under the per-key WRITE lock. On any pre-commit failure, delete
        // the one new blob we wrote (it is referenced by nothing live).
        let _guard = self.lock_key(bucket, key);
        match self.publish(bucket, key, &manifest) {
            Ok(()) => Ok(etag),
            Err(e) => {
                // Pre-commit rollback: our new blob is an orphan -> delete it.
                let _ = blob::reclaim_blob(&bucket_root, &info.blob_id);
                Err(e)
            }
        }
    }

    /// The §3 PUBLISH sequence. Precondition: all new blobs already written+fsynced
    /// to `blobs/`; the per-key WRITE lock is held by the caller.
    ///
    /// Steps (each gated by a test fault hook to simulate a crash BETWEEN steps):
    ///   1. stage    arriving/{uuid}.meta  (fsync if --fsync)
    ///   2. journal  deleted/{uuid}.journal listing OLD blobs (if K exists)
    ///   3. COMMIT   rename(arriving -> current/K.meta) + best-effort parent fsync
    ///   4. reclaim  delete OLD blobs
    ///   5. cleanup  delete the journal
    ///
    /// IMPORTANT: a pre-commit failure (steps 1/2/3) returns `Err` so the caller
    /// rolls back its NEW blob. A POST-commit failure (after step 3 rename) is NOT
    /// a publish failure — the new version is live — so we swallow reclaim/cleanup
    /// errors and return `Ok(())`; the leftover journal is finished by recover().
    fn publish(&self, bucket: &str, key: &str, new_manifest: &Manifest) -> Result<()> {
        let current_root = self.current_root(bucket);
        let bucket_root = self.bucket_root(bucket);
        let k = manifest::manifest_path(&current_root, key);

        // ---- step 1: stage the new manifest in arriving/ ----
        let staged_id = Uuid::new_v4().to_string();
        let staged = self.arriving_root(bucket).join(format!("{staged_id}{META_SUFFIX}"));
        manifest::write_manifest_temp(&staged, new_manifest, self.fsync)?;
        let mut staged_guard = FileGuard::new(staged.clone());
        #[cfg(test)]
        if fault_armed(FaultPoint::BeforeStage) {
            // crash BEFORE step 1's effect persists: the FileGuard drops the staged
            // file, modelling "blob written, nothing staged".
            return Err(simulated_crash());
        }
        #[cfg(test)]
        if fault_armed(FaultPoint::BeforeJournal) {
            // crash AFTER stage, BEFORE journal: leave the arriving orphan on disk.
            staged_guard.disarm();
            return Err(simulated_crash());
        }

        // ---- step 2: journal the OLD manifest's blob ids (only if K exists) ----
        let old_manifest = match manifest::read_manifest(&k) {
            Ok(m) => Some(m),
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.into()),
        };
        let journal_path = if let Some(old) = &old_manifest {
            let jpath = self.deleted_root(bucket).join(format!("{}.journal", Uuid::new_v4()));
            let journal = Journal {
                mode: JournalMode::Publish,
                supersedes_key: key.to_string(),
                commit_nonce: new_manifest.commit_nonce.clone(),
                expected_new_etag: new_manifest.etag.clone(),
                blobs: old.blob_ids(),
            };
            self.write_journal(&jpath, &journal)?;
            Some((jpath, journal))
        } else {
            None
        };
        #[cfg(test)]
        if fault_armed(FaultPoint::BeforeCommit) {
            // crash AFTER journal, BEFORE commit rename: leave arriving + journal.
            staged_guard.disarm();
            return Err(simulated_crash());
        }

        // ---- step 3: COMMIT = atomic rename(arriving -> current/K.meta) ----
        if let Some(parent) = k.parent() {
            std::fs::create_dir_all(parent)?;
        }
        super::directio::rename(&staged, &k)?;
        staged_guard.disarm(); // moved away; no longer ours to clean.
        // Best-effort durability of the rename (post-commit, never rolled back).
        if self.fsync {
            if let Some(parent) = k.parent() {
                if let Err(e) = super::directio::fsync_dir(parent) {
                    tracing::warn!(path = %k.display(), error = %e,
                        "post-commit directory fsync failed; object published, entry may not be crash-durable");
                }
            }
        }
        #[cfg(test)]
        if fault_armed(FaultPoint::BeforeReclaim) {
            // POST-commit crash: new version live, journal still present. Recovery
            // (recover()) finishes the reclaim. NOT a publish failure.
            return Ok(());
        }

        // ---- step 4: reclaim OLD blobs (idempotent) ----
        if let Some((jpath, journal)) = &journal_path {
            for blob_id in &journal.blobs {
                let _ = blob::reclaim_blob(&bucket_root, blob_id);
            }
            #[cfg(test)]
            if fault_armed(FaultPoint::BeforeJournalCleanup) {
                return Ok(());
            }
            // ---- step 5: cleanup the journal ----
            let _ = std::fs::remove_file(jpath);
        }
        Ok(())
    }

    // ---- object: DELETE ----

    /// DeleteObject: journal the manifest's blob ids -> remove the manifest ->
    /// reclaim blobs -> delete journal (the mirror of commit, REDESIGN §4).
    /// Idempotent. Signature identical to `Filesystem::delete_object`.
    pub fn delete_object(&self, bucket: &str, key: &str) -> Result<()> {
        self.validate_object_path(bucket, key)?;
        self.head_bucket(bucket)?;
        self.ensure_infra(bucket)?;

        let bucket_root = self.bucket_root(bucket);
        let current_root = self.current_root(bucket);
        let k = manifest::manifest_path(&current_root, key);

        let _guard = self.lock_key(bucket, key);

        // K absent -> idempotent success (after head_bucket above, mirrors C7).
        let old = match manifest::read_manifest(&k) {
            Ok(m) => m,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.into()),
        };

        // step: journal the to-delete blobs.
        let jpath = self.deleted_root(bucket).join(format!("{}.journal", Uuid::new_v4()));
        let journal = Journal {
            mode: JournalMode::Delete,
            supersedes_key: key.to_string(),
            commit_nonce: String::new(), // unused for delete
            expected_new_etag: String::new(),
            blobs: old.blob_ids(),
        };
        self.write_journal(&jpath, &journal)?;

        // COMMIT: remove the manifest (+ best-effort parent fsync).
        match std::fs::remove_file(&k) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        if self.fsync {
            if let Some(parent) = k.parent() {
                let _ = super::directio::fsync_dir(parent);
            }
        }

        // reclaim + cleanup.
        for blob_id in &journal.blobs {
            let _ = blob::reclaim_blob(&bucket_root, blob_id);
        }
        let _ = std::fs::remove_file(&jpath);

        // prune now-empty ancestor dirs in current/ up to (not incl.) current/.
        let mut dir = k.parent().map(PathBuf::from);
        while let Some(d) = dir {
            if d == current_root {
                break;
            }
            if std::fs::remove_dir(&d).is_err() {
                break;
            }
            dir = d.parent().map(PathBuf::from);
        }
        Ok(())
    }

    // ---- object: GET / HEAD ----

    /// GetObject: read the current manifest as an atomic snapshot, resolve the
    /// range, and return a streaming reader over the referenced blob(s). Signature
    /// identical to `Filesystem::get_object`.
    pub fn get_object(
        &self,
        bucket: &str,
        key: &str,
        range_header: Option<&str>,
    ) -> Result<GetObjectResult> {
        self.validate_object_path(bucket, key)?;
        let current_root = self.current_root(bucket);
        let k = manifest::manifest_path(&current_root, key);

        // Belt-and-suspenders: hold the read lock for the single manifest read
        // (atomic rename + immutable blobs already guarantee a consistent
        // snapshot; this is NOT required for correctness — REDESIGN §9). The lock
        // is dropped before the body streams.
        let manifest = {
            let _snap = self.rlock_key(bucket, key);
            match manifest::read_manifest(&k) {
                Ok(m) => m,
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    self.head_bucket(bucket)?;
                    return Err(StorageError::ObjectNotFound);
                }
                Err(e) => return Err(e.into()),
            }
        };

        let total = manifest.content_length;
        let resolved_range = match range_header {
            Some(h) => match parse_range(h, total) {
                Ok(r) => r,
                Err(()) => return Err(StorageError::RangeNotSatisfiable { size: total }),
            },
            None => None,
        };

        let bucket_root = self.bucket_root(bucket);
        let metadata = manifest.to_object_metadata();
        let body = self.open_body(&bucket_root, &manifest, resolved_range)?;
        Ok(GetObjectResult {
            metadata,
            body,
            resolved_range,
            total_size: total,
        })
    }

    /// HeadObject: read the current manifest and return its header bundle.
    /// Signature identical to `Filesystem::head_object`.
    pub fn head_object(&self, bucket: &str, key: &str) -> Result<ObjectMetadata> {
        self.validate_object_path(bucket, key)?;
        let k = manifest::manifest_path(&self.current_root(bucket), key);
        match manifest::read_manifest(&k) {
            Ok(m) => Ok(m.to_object_metadata()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                self.head_bucket(bucket)?;
                Err(StorageError::ObjectNotFound)
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Open a streaming reader over a manifest's blobs. Single-part uses the
    /// `PlainFileReader` fast path (one blob, fd pins the inode); multipart uses
    /// the reassemble-on-read `MultipartReader` over the blob paths. A missing
    /// blob surfaces as an io error that truncates the stream (fail-fast, §5).
    fn open_body(
        &self,
        bucket_root: &Path,
        manifest: &Manifest,
        resolved_range: Option<ByteRange>,
    ) -> Result<Box<dyn Read + Send>> {
        // [LOW] Validate every part's blob_id syntactically BEFORE it is fed to
        // `blob::blob_path`. A blob_id is supposed to be a bare uuid resolved through
        // the fanout; a corrupt or crafted `.meta` whose blob_id contained `/` or
        // `..` would otherwise build an escaping path. Reject up front as
        // `Io(InvalidData)` (a malformed on-disk manifest is a server-side data
        // problem, not a missing object) so no escaping path is ever constructed.
        for p in &manifest.parts {
            if !blob::is_valid_blob_id(&p.blob_id) {
                return Err(StorageError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "manifest part references a malformed blob_id",
                )));
            }
        }
        if manifest.parts.len() == 1 {
            let p = blob::blob_path(bucket_root, &manifest.parts[0].blob_id);
            match PlainFileReader::open(&p, resolved_range) {
                Ok(r) => Ok(Box::new(r)),
                // A missing single blob -> object effectively gone -> truncate.
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    Err(StorageError::ObjectNotFound)
                }
                Err(e) => Err(e.into()),
            }
        } else {
            // Multipart: build PartRef list pointing at blob paths so the existing
            // MultipartReader streams them back-to-back. (Phase A never WRITES a
            // multipart manifest, but the read path is kept compatible.)
            let parts = manifest
                .parts
                .iter()
                .map(|p| super::metadata::PartRef {
                    part_number: p.part_number as i32,
                    path: blob::blob_path(bucket_root, &p.blob_id)
                        .to_string_lossy()
                        .into_owned(),
                    size: p.size,
                    md5_hex: p.md5_hex.clone(),
                })
                .collect::<Vec<_>>();
            Ok(Box::new(MultipartReader::new(parts, resolved_range)))
        }
    }

    // ---- journal / reclaim primitives (used by tests now; recover() later) ----

    fn write_journal(&self, path: &Path, journal: &Journal) -> io::Result<()> {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        let data = serde_json::to_vec(journal).map_err(io::Error::other)?;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        f.write_all(&data)?;
        if self.fsync {
            f.sync_all()?;
            // fsync the deleted/ dir so the new journal entry is durable.
            if let Some(parent) = path.parent() {
                let _ = super::directio::fsync_dir(parent);
            }
        }
        Ok(())
    }

    fn read_journal(path: &Path) -> io::Result<Journal> {
        use std::io::Read as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut f = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        let mut data = Vec::new();
        f.read_to_end(&mut data)?;
        serde_json::from_slice(&data).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// Apply one reclaim journal under the REDESIGN §3.2 / §4 nonce rule, then
    /// remove the journal. This is the per-journal sweep primitive (recover() will
    /// iterate `deleted/*.journal` over this in a later phase).
    ///
    ///  - publish: delete blobs IFF the live manifest at `supersedes_key` carries
    ///    exactly `commit_nonce` (the commit landed). Otherwise leave the blobs
    ///    (still-live-old or owned by a later journal) and just remove the journal.
    ///  - delete:  delete blobs IFF the live manifest is ABSENT.
    ///
    /// Returns the reclaim outcome. Deletes are idempotent (unlink-missing == ok),
    /// so this is safe to re-run.
    pub fn apply_journal(&self, bucket: &str, journal_path: &Path) -> Result<ReclaimStats> {
        let journal = match Self::read_journal(journal_path) {
            Ok(j) => j,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(ReclaimStats::default()),
            Err(e) => return Err(e.into()),
        };
        let bucket_root = self.bucket_root(bucket);
        let k = manifest::manifest_path(&self.current_root(bucket), &journal.supersedes_key);
        let live = match manifest::read_manifest(&k) {
            Ok(m) => Some(m),
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.into()),
        };

        let execute = match journal.mode {
            JournalMode::Publish => live
                .as_ref()
                .map(|m| m.commit_nonce == journal.commit_nonce)
                .unwrap_or(false),
            JournalMode::Delete => live.is_none(),
        };

        let mut stats = ReclaimStats::default();
        if execute {
            for blob_id in &journal.blobs {
                if blob::blob_path(&bucket_root, blob_id).exists() {
                    let _ = blob::reclaim_blob(&bucket_root, blob_id);
                    stats.blobs_deleted += 1;
                }
            }
        }
        // Always remove the journal: either we executed it, or the live manifest
        // shows the commit/delete didn't land (the blobs are still-live-old or a
        // later journal owns them, and the fallback GC backstops genuine orphans).
        match std::fs::remove_file(journal_path) {
            Ok(()) => stats.journals_removed += 1,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        Ok(stats)
    }

    /// Remove an uncommitted staged manifest in `arriving/` (REDESIGN §6.1). The
    /// per-upload blob orphan it may reference is reclaimed by the fallback GC (a
    /// later phase) — for a single PUT the pre-commit rollback already deleted it.
    pub fn cleanup_arriving(&self, bucket: &str) -> Result<usize> {
        let arriving = self.arriving_root(bucket);
        let rd = match std::fs::read_dir(&arriving) {
            Ok(rd) => rd,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(e.into()),
        };
        let mut removed = 0;
        for entry in rd {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.ends_with(META_SUFFIX) && std::fs::remove_file(entry.path()).is_ok() {
                removed += 1;
            }
        }
        Ok(removed)
    }

    // ---- validation (ported from filesystem.rs, with the .meta reserved rule) ----

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
        validate_bucket_name(bucket).map_err(|_| StorageError::PathTraversal)?;
        Ok(())
    }

    /// Reject keys with `..`, NUL, absolute paths, or whose final segment collides
    /// with the only structural reservation left in the CAS layout: the `.meta`
    /// manifest suffix. (The escape in `manifest.rs` makes a literal `.meta` key
    /// storable, but we still reject keys that would directly NAME a manifest with
    /// our internal escape bytes — impossible since NUL is rejected here.) Then
    /// assert lexical containment within the data root.
    fn validate_object_path(&self, bucket: &str, key: &str) -> Result<()> {
        self.validate_bucket_component(bucket)?;
        if key.is_empty() {
            return Err(StorageError::PathTraversal);
        }
        if key.contains("..") || key.contains('\0') {
            return Err(StorageError::PathTraversal);
        }
        if Path::new(key).is_absolute() {
            return Err(StorageError::PathTraversal);
        }
        // [REJECT — data loss] Empty-segment key collision. `escape_key_to_relpath`
        // builds the manifest relpath by `PathBuf::push`-ing each `/`-split segment,
        // and `push("")` is a no-op that COLLAPSES empty segments — so keys `a` and
        // `a/`, `a/b` and `a/b/`, `a//b` and `a/b` would all map to the SAME manifest
        // path → silent overwrite / data loss. Reject any key containing an empty
        // path segment (a leading/trailing `/` or an internal `//`) up front. Maps to
        // 400 InvalidArgument via `PathTraversal`. KNOWN LIMITATION: a filesystem-
        // backed gateway cannot faithfully represent trailing- or empty-segment keys
        // (real S3 treats `a` and `a/` as distinct objects); we reject them rather
        // than risk collapsing them onto one manifest.
        if key.split('/').any(|s| s.is_empty()) {
            return Err(StorageError::PathTraversal);
        }
        // The four infra dir names are under the bucket root and never collide
        // with a key (keys live under current/), so no key-segment reservation is
        // needed for them. The `.meta` suffix IS handled by escaping, so a key
        // ending in `.meta` is ALLOWED (and round-trips). We only reject the
        // impossible NUL-escape collision, already covered by the NUL check above.
        let bucket_path = self.bucket_root(bucket);
        let current = bucket_path.join(CURRENT_DIR);
        let full = manifest::manifest_path(&current, key);
        let base = normalize(&current);
        let cleaned = normalize(&full);
        if !cleaned.starts_with(&base) {
            return Err(StorageError::PathTraversal);
        }
        self.assert_real_parent_within_root(&full)?;
        Ok(())
    }

    /// Canonicalize the deepest EXISTING ancestor of `target` (following symlinks)
    /// and assert it stays inside the canonical data root. Ported verbatim from
    /// `filesystem.rs` (catches a symlinked intermediate dir escape).
    fn assert_real_parent_within_root(&self, target: &Path) -> Result<()> {
        let real_root = match std::fs::canonicalize(&self.root) {
            Ok(r) => r,
            Err(_) => return Ok(()),
        };
        let mut probe = target.parent();
        while let Some(dir) = probe {
            match std::fs::canonicalize(dir) {
                Ok(real) => {
                    if real != real_root && !real.starts_with(&real_root) {
                        return Err(StorageError::PathTraversal);
                    }
                    return Ok(());
                }
                Err(_) => probe = dir.parent(),
            }
        }
        Ok(())
    }

    // ---- multipart (REDESIGN §6 / §9 / §14 Phase 4) ----
    //
    // Parts are IMMUTABLE blobs in `blobs/`, referenced via one `.ref`-file-per-part
    // under the upload working dir `arriving/{upload_id}/parts/{NNNNN}.ref`. This
    // keeps UploadPart lock-free and fully parallel (each part writes its own blob +
    // its own ref, no shared manifest mutation), and lets Complete build the ordered
    // manifest by simply REFERENCING the existing part blobs — no copy/concat, no
    // second pass over the data.

    /// Working dir for an in-flight upload: `arriving/{upload_id}/`. Validates the
    /// upload_id is a well-formed uuid FIRST (a crafted id would otherwise join
    /// outside `arriving/`), and — once the dir exists — rejects a symlinked or
    /// out-of-root upload dir (the §11 arriving analog of the old F3 upload-dir
    /// hardening). A not-yet-created dir is fine (create_multipart_upload makes it).
    fn upload_dir(&self, bucket: &str, upload_id: &str) -> Result<PathBuf> {
        Uuid::parse_str(upload_id).map_err(|_| StorageError::NoSuchUpload)?;
        let dir = self.arriving_root(bucket).join(upload_id);
        match std::fs::symlink_metadata(&dir) {
            Ok(m) => {
                if m.file_type().is_symlink() {
                    return Err(StorageError::NoSuchUpload);
                }
                if !m.file_type().is_dir() {
                    return Err(StorageError::NoSuchUpload);
                }
                if let (Ok(real_dir), Ok(real_root)) =
                    (std::fs::canonicalize(&dir), std::fs::canonicalize(&self.root))
                {
                    if !real_dir.starts_with(&real_root) {
                        return Err(StorageError::NoSuchUpload);
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        Ok(dir)
    }

    /// Load the upload's `upload.json` and require its stored bucket/key match the
    /// REQUEST path (preserves the B4 fix: a valid upload_id addressed via a
    /// different object path is `NoSuchUpload`). Read with O_NOFOLLOW so a symlinked
    /// upload.json is not followed (preserves D5). Also the existence check (missing
    /// -> NoSuchUpload). Returns the parsed upload on success.
    fn assert_upload_matches(
        &self,
        upload_dir: &Path,
        bucket: &str,
        key: &str,
    ) -> Result<MultipartUpload> {
        let raw = match read_nofollow(&upload_dir.join("upload.json")) {
            Ok(d) => d,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(StorageError::NoSuchUpload),
            Err(e) => return Err(e.into()),
        };
        let upload: MultipartUpload = serde_json::from_slice(&raw)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        if upload.bucket != bucket || upload.key != key {
            return Err(StorageError::NoSuchUpload);
        }
        Ok(upload)
    }

    /// CreateMultipartUpload: generate a v4 upload_id, create `arriving/{id}/parts/`,
    /// and persist the upload meta (`upload.json`) so Complete can verify the request
    /// bucket/key match the upload (B4). Signature identical to
    /// `Filesystem::create_multipart_upload`.
    pub fn create_multipart_upload(
        &self,
        bucket: &str,
        key: &str,
        content_type: &str,
        user_meta: BTreeMap<String, String>,
    ) -> Result<String> {
        self.validate_object_path(bucket, key)?;
        self.head_bucket(bucket)?;
        self.ensure_infra(bucket)?;

        let upload_id = Uuid::new_v4().to_string();
        let upload_dir = self.arriving_root(bucket).join(&upload_id);
        std::fs::create_dir_all(upload_dir.join("parts"))?;

        let meta = MultipartUpload {
            upload_id: upload_id.clone(),
            bucket: bucket.to_string(),
            key: key.to_string(),
            initiated_unix: now_unix(),
            content_type: content_type.to_string(),
            user_metadata: user_meta,
        };
        let data = serde_json::to_vec_pretty(&meta).map_err(io::Error::other)?;
        write_nofollow(&upload_dir.join("upload.json"), &data, self.fsync)?;
        Ok(upload_id)
    }

    /// UploadPart: stream the part body to a fresh IMMUTABLE blob (Direct-IO,
    /// one-pass MD5), then write a `parts/{NNNNN}.ref` recording the part's blob_id /
    /// size / md5. Returns the quoted part ETag (`"md5"`). Signature identical to
    /// `Filesystem::upload_part`.
    ///
    /// Parallel-safe: each UploadPart writes its OWN blob + its OWN ref — no shared
    /// manifest/part-file mutation, so concurrent UploadParts (even to one upload_id)
    /// never contend. Overwriting a part (same number) atomically replaces its `.ref`
    /// and immediately reclaims the superseded blob (it is referenced by nothing).
    pub fn upload_part<R: Read>(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
        part_number: i32,
        body: R,
    ) -> Result<String> {
        // F/B5: S3 part numbers are 1..=10000. Reject out-of-range BEFORE formatting
        // a path (a negative would format as e.g. `-0001`).
        if !(1..=10_000).contains(&part_number) {
            return Err(StorageError::InvalidPart);
        }
        let upload_dir = self.upload_dir(bucket, upload_id)?;
        self.assert_upload_matches(&upload_dir, bucket, key)?;

        let bucket_root = self.bucket_root(bucket);
        // Stream the part to a fresh immutable blob (lock-free; one-pass MD5; fsync).
        let info = blob::write_blob(&bucket_root, body).map_err(body_or_io)?;
        let etag = format!("\"{}\"", info.md5_hex);

        // Atomically install the part ref. If a previous ref for this number existed,
        // capture its blob_id so we can reclaim the now-orphaned old blob.
        let ref_path = upload_dir.join("parts").join(format!("{part_number:05}.ref"));
        let prev_blob = match read_nofollow(&ref_path) {
            Ok(d) => serde_json::from_slice::<PartRefFile>(&d).ok().map(|p| p.blob_id),
            Err(_) => None,
        };
        let pref = PartRefFile {
            part_number: part_number as u32,
            blob_id: info.blob_id.clone(),
            size: info.size,
            md5_hex: info.md5_hex.clone(),
        };
        let data = serde_json::to_vec(&pref).map_err(io::Error::other)?;
        // Write the ref to a temp sibling then atomic-rename it into place so a
        // concurrent reader/Complete never sees a half-written ref.
        let tmp_ref = upload_dir
            .join("parts")
            .join(format!("{part_number:05}.ref.tmp.{}", Uuid::new_v4()));
        let mut guard = FileGuard::new(tmp_ref.clone());
        if let Err(e) = write_nofollow(&tmp_ref, &data, self.fsync) {
            // Roll back our new blob (referenced by nothing).
            let _ = blob::reclaim_blob(&bucket_root, &info.blob_id);
            return Err(e.into());
        }
        if let Err(e) = super::directio::rename(&tmp_ref, &ref_path) {
            let _ = blob::reclaim_blob(&bucket_root, &info.blob_id);
            return Err(e.into());
        }
        guard.disarm();
        // The superseded part's blob (if any) is now unreferenced -> reclaim it.
        if let Some(old) = prev_blob {
            if old != info.blob_id {
                let _ = blob::reclaim_blob(&bucket_root, &old);
            }
        }
        Ok(etag)
    }

    /// Read all valid `parts/{NNNNN}.ref` entries in an upload dir, keyed by part
    /// number. Skips temp (`.ref.tmp.`) and unparseable entries.
    fn read_part_refs(upload_dir: &Path) -> io::Result<std::collections::BTreeMap<u32, PartRefFile>> {
        let mut out = std::collections::BTreeMap::new();
        let parts_dir = upload_dir.join("parts");
        let rd = match std::fs::read_dir(&parts_dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(e),
        };
        for entry in rd {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if !name.ends_with(".ref") || name.contains(".tmp.") {
                continue;
            }
            let data = match read_nofollow(&entry.path()) {
                Ok(d) => d,
                Err(_) => continue,
            };
            if let Ok(p) = serde_json::from_slice::<PartRefFile>(&data) {
                out.insert(p.part_number, p);
            }
        }
        Ok(out)
    }

    /// CompleteMultipartUpload: validate the claimed parts against the stored part
    /// refs (md5/order), build an ordered manifest REFERENCING the part blobs, and
    /// PUBLISH via the §3 commit path (atomic rename + journal the OLD key's blobs if
    /// overwriting). Returns the composite ETag. Signature identical to
    /// `Filesystem::complete_multipart_upload`.
    ///
    /// E2 (retryable failed Complete): the part blobs and refs are NOT touched until
    /// AFTER the commit succeeds. Any pre-commit failure leaves the upload fully
    /// intact so the client can retry Complete. No data is copied/concatenated.
    pub fn complete_multipart_upload(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
        parts: &[CompletePart],
    ) -> Result<String> {
        let upload_dir = self.upload_dir(bucket, upload_id)?;
        // B4: cross-check the request path matches the upload.
        let upload = self.assert_upload_matches(&upload_dir, bucket, key)?;
        // Defense in depth: re-validate the upload's stored bucket/key.
        self.validate_object_path(&upload.bucket, &upload.key)?;

        // F/B5: empty parts list is not a valid completion.
        if parts.is_empty() {
            return Err(StorageError::InvalidPart);
        }
        // F/B5: every claimed part number must be in 1..=10000.
        for p in parts {
            if !(1..=10_000).contains(&p.part_number) {
                return Err(StorageError::InvalidPart);
            }
        }
        // Parts must be strictly ascending by number.
        for w in parts.windows(2) {
            if w[1].part_number <= w[0].part_number {
                return Err(StorageError::InvalidPartOrder);
            }
        }

        self.head_bucket(&upload.bucket)?;

        // Load the stored part refs (the immutable blobs each .ref points at). Take
        // the per-key WRITE lock around validate->build->commit, keyed by the
        // upload's STORED bucket/key — this serializes Complete vs a concurrent
        // Delete/Complete on the same key (E3 is structurally gone since part blobs
        // are immutable at unique paths, but the lock still serializes the manifest
        // swap + journal creation, §9).
        let _guard = self.lock_key(&upload.bucket, &upload.key);
        let stored = Self::read_part_refs(&upload_dir)?;

        // Validate each claimed part against its stored ref; build the ordered
        // manifest parts referencing the part blobs.
        let mut manifest_parts: Vec<ManifestPartRef> = Vec::with_capacity(parts.len());
        let mut md5_concat: Vec<u8> = Vec::with_capacity(parts.len() * 16);
        let mut total: u64 = 0;
        for p in parts {
            let stored_ref = match stored.get(&(p.part_number as u32)) {
                Some(r) => r,
                None => return Err(StorageError::InvalidPart),
            };
            // F15: an empty client ETag is NOT a free pass — reject it, then compare.
            let provided = p.etag.trim_matches('"');
            if provided.is_empty() || provided != stored_ref.md5_hex {
                return Err(StorageError::InvalidPart);
            }
            // The blob backing the ref must be a syntactically valid uuid (it always
            // is when written by UploadPart; this guards a hand-tampered ref).
            if !blob::is_valid_blob_id(&stored_ref.blob_id) {
                return Err(StorageError::InvalidPart);
            }
            let raw = hex::decode(&stored_ref.md5_hex)
                .map_err(|_| StorageError::InvalidPart)?;
            md5_concat.extend_from_slice(&raw);
            total += stored_ref.size;
            manifest_parts.push(ManifestPartRef {
                part_number: p.part_number as u32,
                blob_id: stored_ref.blob_id.clone(),
                size: stored_ref.size,
                md5_hex: stored_ref.md5_hex.clone(),
            });
        }

        // Composite ETag: md5(concat of raw 16-byte part digests)-N. Identical format
        // to the old impl.
        let composite = md5::Md5::digest(&md5_concat);
        let etag = format!("\"{}-{}\"", hex::encode(composite), parts.len());

        let ct = if upload.content_type.is_empty() {
            "application/octet-stream"
        } else {
            &upload.content_type
        };
        let now = now_unix();
        let manifest = Manifest {
            key: upload.key.clone(),
            content_type: ct.to_string(),
            content_length: total,
            etag: etag.clone(),
            last_modified: now,
            created: now,
            user_metadata: upload.user_metadata.clone(),
            content_disposition: String::new(),
            content_encoding: String::new(),
            cache_control: String::new(),
            parts: manifest_parts,
            commit_nonce: Manifest::new_nonce(),
        };

        // COMMIT via the §3 publish path. The part blobs already live in `blobs/`
        // (written+fsynced by UploadPart), so publish just stages+journals+renames
        // the manifest — no part data is copied. A pre-commit failure here returns
        // Err WITHOUT touching the upload's blobs/refs -> the upload stays RETRYABLE
        // (E2). We do NOT roll back the part blobs (unlike single-PUT) because they
        // are owned by the still-live upload, not by this attempt.
        self.publish(&upload.bucket, &upload.key, &manifest)?;

        // Success: remove the upload working dir. The part blobs are now owned by the
        // committed manifest; only the refs + upload.json are discarded.
        let _ = std::fs::remove_dir_all(&upload_dir);
        Ok(etag)
    }

    /// AbortMultipartUpload: delete the upload's part blobs (from the stored refs)
    /// and remove the working dir. Signature identical to
    /// `Filesystem::abort_multipart_upload`.
    pub fn abort_multipart_upload(&self, bucket: &str, key: &str, upload_id: &str) -> Result<()> {
        let upload_dir = self.upload_dir(bucket, upload_id)?;
        self.assert_upload_matches(&upload_dir, bucket, key)?;
        let bucket_root = self.bucket_root(bucket);
        // Reclaim each part blob (immutable; owned exclusively by this upload).
        if let Ok(refs) = Self::read_part_refs(&upload_dir) {
            for r in refs.values() {
                let _ = blob::reclaim_blob(&bucket_root, &r.blob_id);
            }
        }
        std::fs::remove_dir_all(&upload_dir)?;
        Ok(())
    }

    /// ListParts: the stored part refs as `PartInfo`, sorted by part number.
    /// Signature identical to `Filesystem::list_parts`.
    pub fn list_parts(&self, bucket: &str, key: &str, upload_id: &str) -> Result<Vec<PartInfo>> {
        let upload_dir = self.upload_dir(bucket, upload_id)?;
        self.assert_upload_matches(&upload_dir, bucket, key)?;
        let refs = Self::read_part_refs(&upload_dir)?;
        // last_modified from each ref file's mtime (best-effort; 0 if unavailable).
        let mut out = Vec::with_capacity(refs.len());
        for (num, r) in refs {
            let ref_path = upload_dir.join("parts").join(format!("{num:05}.ref"));
            let lm = std::fs::metadata(&ref_path)
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            out.push(PartInfo {
                part_number: num as i32,
                size: r.size as i64,
                etag: format!("\"{}\"", r.md5_hex),
                last_modified_unix: lm,
            });
        }
        out.sort_by_key(|p| p.part_number);
        Ok(out)
    }

    /// ListMultipartUploads for `bucket`, BOUNDED by `max_uploads` (E7: hard-capped
    /// at [`MAX_UPLOADS_CAP`], returns `is_truncated`). Scans `arriving/{uuid}/
    /// upload.json`. Signature identical to `Filesystem::list_multipart_uploads`.
    pub fn list_multipart_uploads(
        &self,
        bucket: &str,
        max_uploads: usize,
    ) -> Result<(Vec<MultipartUpload>, bool)> {
        self.head_bucket(bucket)?;
        let cap = max_uploads.min(MAX_UPLOADS_CAP);
        let arriving = self.arriving_root(bucket);
        let rd = match std::fs::read_dir(&arriving) {
            Ok(rd) => rd,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok((Vec::new(), false)),
            Err(e) => return Err(e.into()),
        };
        let mut out = Vec::new();
        for entry in rd {
            let entry = entry?;
            // Only `{uuid}/` working dirs are uploads; staged `{uuid}.meta` manifests
            // (single-PUT/Complete temps) are not.
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let meta_path = entry.path().join("upload.json");
            let data = match read_nofollow(&meta_path) {
                Ok(d) => d,
                Err(_) => continue,
            };
            if let Ok(u) = serde_json::from_slice::<MultipartUpload>(&data) {
                out.push(u);
            }
        }
        out.sort_by(|a, b| a.key.cmp(&b.key).then_with(|| a.upload_id.cmp(&b.upload_id)));
        let is_truncated = out.len() > cap;
        if is_truncated {
            out.truncate(cap);
        }
        Ok((out, is_truncated))
    }

    // ---- listing (REDESIGN §7 — the manifest key-tree) ----

    /// ListObjectsV2 over the CAS manifest tree. Walk `current/`; for each `.meta`
    /// FILE, decode its path back to the object key (the exact inverse of
    /// `manifest_path`: strip exactly one trailing `.meta` from the final segment,
    /// rejoin `/`-separated). Then apply S3 ListObjectsV2 semantics — `prefix`
    /// (with subtree pruning), `delimiter`→CommonPrefixes, `start-after`,
    /// `continuation-token`, `max-keys` — in lexicographic key order. Per-object
    /// Size/ETag/LastModified are read from each EMITTED key's manifest only (after
    /// pagination), so manifests outside the page are never read.
    ///
    /// The walk-and-buffer-then-paginate approach has the same memory profile as the
    /// old `filesystem.rs` impl (listing memory scales with bucket size). The
    /// flat-bucket caveat (millions of keys with no `/` → one giant `current/` dir)
    /// is an accepted documented non-goal for the single-machine target (REDESIGN
    /// §7.2).
    ///
    /// Signature identical to `Filesystem::list_objects`.
    pub fn list_objects(&self, input: &ListObjectsInput) -> Result<ListObjectsOutput> {
        self.head_bucket(&input.bucket)?;
        let current_root = self.current_root(&input.bucket);

        // F14: absent max-keys defaults to 1000; an EXPLICIT Some(0) means an empty
        // page (IsTruncated=true if anything matches). Negatives clamp to 0.
        let max_keys = match input.max_keys {
            None => 1000,
            Some(n) => n.max(0),
        };

        // Prune the walk to the relevant subtree where the prefix names a directory
        // boundary. A prefix like `a/b/` is wholly within `current/a/b/`, so we can
        // root the walk there and skip unrelated siblings. Any prefix WITHOUT a
        // trailing `/` may still match keys across multiple files/dirs at the parent
        // level (e.g. prefix `a/b` matches both `a/bcd.meta` and `a/b/…`), so we root
        // at the deepest fully-`/`-terminated ancestor and keep the per-key
        // `starts_with(prefix)` filter below for the partial-segment tail.
        let (walk_root, walk_prefix_strip) = self.prefix_walk_root(&current_root, &input.prefix);

        // Phase 1: walk the tree, collect matching KEYS (no manifest reads yet) and
        // group delimiter-collapsed keys into CommonPrefixes.
        let mut keys: Vec<String> = Vec::new();
        let mut prefix_set: BTreeMap<String, ()> = BTreeMap::new();

        walk_dir_files(&walk_root, &mut |path: &Path| -> io::Result<()> {
            let file_name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
            // Under current/ the only files are committed `.meta` manifests; defensively
            // skip anything that is not a manifest or that looks like a staged temp (a
            // temp never lives here, but be robust).
            if !file_name.ends_with(META_SUFFIX) || file_name.contains(".tmp.") {
                return Ok(());
            }
            // Decode the path (relative to current/) back to the object key — the
            // exact inverse of `manifest_path`.
            let rel = match path.strip_prefix(&walk_prefix_strip) {
                Ok(r) => r,
                Err(_) => return Ok(()),
            };
            let key = match manifest::decode_relpath_to_key(rel) {
                Some(k) => k,
                None => return Ok(()), // not a manifest filename (no trailing .meta)
            };

            if !input.prefix.is_empty() && !key.starts_with(&input.prefix) {
                return Ok(());
            }
            // Delimiter grouping: collapse keys that have the delimiter AFTER the
            // prefix into a CommonPrefix up to (and including) the first delimiter.
            if !input.delimiter.is_empty() {
                let after = &key[input.prefix.len()..];
                if let Some(idx) = after.find(&input.delimiter) {
                    let cp = format!("{}{}", input.prefix, &after[..idx + input.delimiter.len()]);
                    prefix_set.insert(cp, ());
                    return Ok(());
                }
            }
            keys.push(key);
            Ok(())
        })?;

        keys.sort();
        let mut common_prefixes: Vec<String> = prefix_set.into_keys().collect();
        common_prefixes.sort();

        // start-after / continuation-token (token wins). Both apply to the merged
        // object-key + common-prefix space (REDESIGN C6).
        let start_after = if !input.continuation_token.is_empty() {
            input.continuation_token.as_str()
        } else {
            input.start_after.as_str()
        };
        if !start_after.is_empty() {
            keys.retain(|k| k.as_str() > start_after);
            common_prefixes.retain(|p| p.as_str() > start_after);
        }

        // Phase 2: merge-paginate object keys + common-prefixes, both counting
        // against max_keys, in lexicographic order. The C6 continuation token is the
        // LAST item EMITTED (an object KEY or a CommonPrefix STRING, whichever was
        // pushed last) — never derived from `objects.last()`, which would be wrong
        // when the final emitted item was a CommonPrefix (the next page would
        // duplicate that prefix and/or skip objects sorting between it and the last
        // emitted object).
        let mut emitted_keys: Vec<String> = Vec::new();
        let mut out = ListObjectsOutput::default();
        let mut count = 0i32;
        let mut oi = 0;
        let mut pi = 0;
        let mut last_emitted: Option<String> = None;
        while count < max_keys && (oi < keys.len() || pi < common_prefixes.len()) {
            let use_obj = if oi < keys.len() && pi < common_prefixes.len() {
                keys[oi] <= common_prefixes[pi]
            } else {
                oi < keys.len()
            };
            if use_obj {
                last_emitted = Some(keys[oi].clone());
                emitted_keys.push(keys[oi].clone());
                oi += 1;
            } else {
                last_emitted = Some(common_prefixes[pi].clone());
                out.common_prefixes.push(common_prefixes[pi].clone());
                pi += 1;
            }
            count += 1;
        }

        let more = oi < keys.len() || pi < common_prefixes.len();
        if more {
            out.is_truncated = true;
            if let Some(tok) = last_emitted {
                out.next_continuation_token = tok;
            }
        }

        // Phase 3: read the manifest for EACH EMITTED object key (only the page) to
        // fill Size/ETag/LastModified. A key with an unreadable/corrupt manifest is
        // SKIPPED (it raced a concurrent DELETE, or is a corrupt sidecar) rather than
        // failing the whole listing — the same fail-soft posture as the old impl's E1
        // sidecar check. (In CAS a manifest IS the object, so there is no phantom-
        // sidecarless entry; a skip here only happens on a genuine concurrent
        // delete/corruption.)
        for key in emitted_keys {
            let mp = manifest::manifest_path(&current_root, &key);
            match manifest::read_manifest(&mp) {
                Ok(m) => out.objects.push(ObjectInfo {
                    key,
                    size: m.content_length as i64,
                    etag: m.etag,
                    last_modified_unix: m.last_modified,
                }),
                Err(_) => continue,
            }
        }

        Ok(out)
    }

    /// Compute the deepest existing directory to root the listing walk at, given a
    /// `prefix`, plus the path the relpath-decode must strip (always `current_root`,
    /// since `decode_relpath_to_key` expects a path relative to `current/`). We root
    /// the walk at `current/{prefix-up-to-last-slash}` when that directory exists —
    /// e.g. prefix `a/b/c` walks `current/a/b/` — pruning unrelated subtrees. If that
    /// dir does not exist we still root at `current_root` (the walk simply finds
    /// nothing). The returned strip base is ALWAYS `current_root` so the decode sees
    /// the full key-relative path.
    fn prefix_walk_root(&self, current_root: &Path, prefix: &str) -> (PathBuf, PathBuf) {
        if prefix.is_empty() {
            return (current_root.to_path_buf(), current_root.to_path_buf());
        }
        // Root at current/{dir-portion-of-prefix} where the dir portion is the prefix
        // up to and including its last `/`. The tail after the last `/` is a partial
        // file/dir-name match handled by the per-key `starts_with` filter.
        let dir_portion = match prefix.rfind('/') {
            Some(idx) => &prefix[..idx], // segments before the last slash
            None => "",
        };
        let mut root = current_root.to_path_buf();
        if !dir_portion.is_empty() {
            for seg in dir_portion.split('/') {
                root.push(seg);
            }
        }
        // Only prune to the subtree if it actually exists as a directory; otherwise
        // fall back to current_root (avoids a NotFound that would still be handled,
        // but keeps the walk well-rooted).
        if root.is_dir() {
            (root, current_root.to_path_buf())
        } else {
            (current_root.to_path_buf(), current_root.to_path_buf())
        }
    }

    /// ListBuckets: the top-level bucket directories under the data root, sorted by
    /// name. Uses `DirEntry::metadata()` which does NOT follow symlinks (F4/E8), so a
    /// SYMLINKED entry under the data root is reported as a symlink and skipped — it
    /// is never listed as a bucket. Creation date is the dir's mtime.
    /// Signature identical to `Filesystem::list_buckets`.
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
            // Skip hidden/infra-ish entries defensively.
            if name.starts_with('.') {
                continue;
            }
            // `DirEntry::metadata()` does NOT traverse a symlink (it stats the link
            // itself), so a symlinked bucket entry has `is_dir() == false` here and is
            // skipped — the load-bearing F4/E8 correctness. (Using `fs::metadata(path)`
            // here would follow the link and WRONGLY list a symlinked dir as a bucket.)
            let md = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            if md.file_type().is_symlink() || !md.is_dir() {
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
}

/// RAII cleanup for a temp file (arriving staged manifest): remove on drop unless
/// disarmed after a successful rename moves it away.
struct FileGuard {
    path: PathBuf,
    armed: bool,
}
impl FileGuard {
    fn new(path: PathBuf) -> Self {
        FileGuard { path, armed: true }
    }
    fn disarm(&mut self) {
        self.armed = false;
    }
}
impl Drop for FileGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Classify an io error from a blob/body write: an `InvalidData` kind is a client
/// framing problem (aws-chunked length mismatch surfaced by ChunkedReader) ->
/// `IncompleteBody`; anything else stays `Io`. Mirrors `filesystem::body_read_error`.
fn body_or_io(e: io::Error) -> StorageError {
    if e.kind() == io::ErrorKind::InvalidData {
        StorageError::IncompleteBody
    } else {
        StorageError::Io(e)
    }
}

fn now_unix() -> i64 {
    crate::auth::time::now_unix()
}

/// Read a small file with O_NOFOLLOW so a planted symlink at the path is rejected
/// (ELOOP) rather than followed (`std::fs::read` would follow it). Used for
/// `upload.json` and `parts/{NNNNN}.ref`.
fn read_nofollow(path: &Path) -> io::Result<Vec<u8>> {
    use std::io::Read as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let mut data = Vec::new();
    f.read_to_end(&mut data)?;
    Ok(data)
}

/// Write a small file with O_NOFOLLOW (so a planted symlink is not followed),
/// truncating any existing content. When `durable`, fsync the file bytes before
/// returning. Used for `upload.json` and the staged `parts/{NNNNN}.ref.tmp.*`.
fn write_nofollow(path: &Path, data: &[u8], durable: bool) -> io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    f.write_all(data)?;
    if durable {
        f.sync_all()?;
    }
    Ok(())
}

/// Recursively walk `dir`, invoking `cb` for every regular FILE found. Under a
/// bucket's `current/` tree the only files are committed `.meta` manifests and the
/// only subdirectories are object-key path components, so — unlike the old
/// `filesystem.rs::walk_dir` — there is NO `.parts`/`.multipart` skip-set: blobs,
/// arriving uploads, and journals all live in SEPARATE sibling dirs (`blobs/`,
/// `arriving/`, `deleted/`) that are never under `current/`. Symlinked entries are
/// not followed (`entry.file_type()` does not traverse). A missing root is `Ok` (an
/// empty / freshly-created bucket).
fn walk_dir_files(dir: &Path, cb: &mut dyn FnMut(&Path) -> io::Result<()>) -> io::Result<()> {
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    for entry in rd {
        let entry = entry?;
        let ft = entry.file_type()?;
        if ft.is_dir() {
            walk_dir_files(&entry.path(), cb)?;
        } else if ft.is_file() {
            cb(&entry.path())?;
        }
        // symlinks and other types: ignored (never created under current/).
    }
    Ok(())
}

/// Dir mtime as Unix seconds (best-effort; 0 if unavailable). Mirrors
/// `filesystem::mtime_unix`.
fn mtime_unix(md: &std::fs::Metadata) -> i64 {
    md.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, CasStore) {
        let dir = tempfile::tempdir().unwrap();
        let fs = CasStore::new(dir.path());
        fs.create_bucket("bkt").unwrap();
        (dir, fs)
    }

    fn read_all(mut r: Box<dyn Read + Send>) -> Vec<u8> {
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        out
    }

    fn list_dir(p: &Path) -> Vec<String> {
        match std::fs::read_dir(p) {
            Ok(rd) => rd
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    fn count_blobs(bucket_root: &Path) -> usize {
        fn walk(p: &Path, n: &mut usize) {
            if let Ok(rd) = std::fs::read_dir(p) {
                for e in rd.flatten() {
                    let path = e.path();
                    if path.is_dir() {
                        walk(&path, n);
                    } else {
                        *n += 1;
                    }
                }
            }
        }
        let mut n = 0;
        walk(&bucket_root.join("blobs"), &mut n);
        n
    }

    #[test]
    fn create_bucket_makes_infra_dirs() {
        let (dir, _fs) = store();
        let bk = dir.path().join("bkt");
        assert!(bk.join("current").is_dir());
        assert!(bk.join("arriving").is_dir());
        assert!(bk.join("blobs").is_dir());
        assert!(bk.join("deleted").is_dir());
    }

    #[test]
    fn put_get_head_round_trip_single_part() {
        let (dir, fs) = store();
        let body = b"hello content-addressed world".to_vec();
        let mut um = BTreeMap::new();
        um.insert("x-amz-meta-foo".into(), "bar".into());
        let etag = fs
            .put_object("bkt", "a/b/c.txt", &body[..], "text/plain", um.clone())
            .unwrap();
        let expected = format!("\"{}\"", {
            use md5::{Digest, Md5};
            hex::encode(Md5::digest(&body))
        });
        assert_eq!(etag, expected);

        // HEAD
        let meta = fs.head_object("bkt", "a/b/c.txt").unwrap();
        assert_eq!(meta.content_length, body.len() as i64);
        assert_eq!(meta.etag, expected);
        assert_eq!(meta.content_type, "text/plain");
        assert_eq!(meta.user_metadata.get("x-amz-meta-foo").unwrap(), "bar");

        // GET
        let res = fs.get_object("bkt", "a/b/c.txt", None).unwrap();
        assert_eq!(res.total_size, body.len() as u64);
        assert_eq!(read_all(res.body), body);

        // Exactly one blob on disk.
        assert_eq!(count_blobs(&dir.path().join("bkt")), 1);

        let _ = dir;
    }

    #[test]
    fn get_missing_object_is_not_found() {
        let (_dir, fs) = store();
        match fs.get_object("bkt", "nope", None) {
            Err(StorageError::ObjectNotFound) => {}
            Err(other) => panic!("expected ObjectNotFound, got {other:?}"),
            Ok(_) => panic!("expected ObjectNotFound"),
        }
        let err = fs.head_object("bkt", "nope").unwrap_err();
        assert!(matches!(err, StorageError::ObjectNotFound));
    }

    #[test]
    fn overwrite_writes_new_blob_reclaims_old_deletes_journal() {
        let (dir, fs) = store();
        let bk = dir.path().join("bkt");
        fs.put_object("bkt", "k", &b"first version"[..], "", BTreeMap::new())
            .unwrap();
        assert_eq!(count_blobs(&bk), 1);

        fs.put_object("bkt", "k", &b"second version, longer"[..], "", BTreeMap::new())
            .unwrap();
        // Old blob reclaimed -> still exactly one.
        assert_eq!(count_blobs(&bk), 1);
        // Journal deleted (steps 4+5 ran fully).
        assert!(list_dir(&bk.join("deleted")).is_empty());
        // GET returns the NEW bytes.
        let res = fs.get_object("bkt", "k", None).unwrap();
        assert_eq!(read_all(res.body), b"second version, longer");
    }

    #[test]
    fn delete_reclaims_blobs_and_manifest() {
        let (dir, fs) = store();
        let bk = dir.path().join("bkt");
        fs.put_object("bkt", "x/y", &b"to be deleted"[..], "", BTreeMap::new())
            .unwrap();
        assert_eq!(count_blobs(&bk), 1);
        fs.delete_object("bkt", "x/y").unwrap();
        assert_eq!(count_blobs(&bk), 0);
        assert!(list_dir(&bk.join("deleted")).is_empty());
        assert!(matches!(
            fs.head_object("bkt", "x/y").unwrap_err(),
            StorageError::ObjectNotFound
        ));
        // Idempotent re-delete.
        fs.delete_object("bkt", "x/y").unwrap();
        // Pruned the now-empty x/ dir.
        assert!(!bk.join("current").join("x").exists());
    }

    #[test]
    fn range_get_single_blob() {
        let (_dir, fs) = store();
        let data: Vec<u8> = (0..10_000u32).map(|i| (i % 256) as u8).collect();
        fs.put_object("bkt", "r", &data[..], "", BTreeMap::new())
            .unwrap();
        let res = fs.get_object("bkt", "r", Some("bytes=100-199")).unwrap();
        assert_eq!(res.resolved_range, Some(ByteRange { start: 100, end: 199 }));
        assert_eq!(read_all(res.body), data[100..=199].to_vec());

        // Unsatisfiable range -> 416 with size.
        match fs.get_object("bkt", "r", Some("bytes=99999-")) {
            Err(StorageError::RangeNotSatisfiable { size }) => assert_eq!(size, 10_000),
            Err(other) => panic!("expected RangeNotSatisfiable, got {other:?}"),
            Ok(_) => panic!("expected RangeNotSatisfiable"),
        }
    }

    #[test]
    fn missing_blob_makes_get_fail_fast() {
        let (dir, fs) = store();
        let bk = dir.path().join("bkt");
        fs.put_object("bkt", "k", &b"some bytes here"[..], "", BTreeMap::new())
            .unwrap();
        // Read the manifest to find the blob id, then delete the blob out from
        // under it to simulate a reclaim racing the GET.
        let mp = manifest::manifest_path(&bk.join("current"), "k");
        let m = manifest::read_manifest(&mp).unwrap();
        blob::reclaim_blob(&bk, &m.parts[0].blob_id).unwrap();
        // GET now fails (the single blob is gone) rather than returning bytes.
        match fs.get_object("bkt", "k", None) {
            Err(StorageError::ObjectNotFound) => {}
            Err(other) => panic!("expected ObjectNotFound, got {other:?}"),
            Ok(_) => panic!("expected GET to fail fast on a missing blob"),
        }
    }

    #[test]
    fn key_a_and_a_slash_b_coexist() {
        let (_dir, fs) = store();
        fs.put_object("bkt", "a", &b"i am a"[..], "", BTreeMap::new())
            .unwrap();
        fs.put_object("bkt", "a/b", &b"i am a slash b"[..], "", BTreeMap::new())
            .unwrap();
        assert_eq!(read_all(fs.get_object("bkt", "a", None).unwrap().body), b"i am a");
        assert_eq!(
            read_all(fs.get_object("bkt", "a/b", None).unwrap().body),
            b"i am a slash b"
        );
    }

    #[test]
    fn key_ending_in_meta_round_trips() {
        let (_dir, fs) = store();
        fs.put_object("bkt", "report.meta", &b"meta-keyed object"[..], "", BTreeMap::new())
            .unwrap();
        let res = fs.get_object("bkt", "report.meta", None).unwrap();
        assert_eq!(read_all(res.body), b"meta-keyed object");
    }

    #[test]
    fn invalid_keys_rejected() {
        let (_dir, fs) = store();
        for bad in ["../escape", "a/../../b", "with\0null", "/abs/key"] {
            let err = fs
                .put_object("bkt", bad, &b"x"[..], "", BTreeMap::new())
                .unwrap_err();
            assert!(matches!(err, StorageError::PathTraversal), "key {bad:?} -> {err:?}");
        }
    }

    // ---- crash-recovery primitives (fault injection) ----

    #[test]
    fn crash_before_rename_keeps_old_version_and_orphan_arriving() {
        let (dir, fs) = store();
        let bk = dir.path().join("bkt");
        fs.put_object("bkt", "k", &b"original"[..], "", BTreeMap::new())
            .unwrap();
        let orig_blob = {
            let m = manifest::read_manifest(&manifest::manifest_path(&bk.join("current"), "k")).unwrap();
            m.parts[0].blob_id.clone()
        };

        // Crash AFTER staging arriving, BEFORE the commit rename (and after the
        // journal is written, per the BeforeCommit point).
        set_fault(Some(FaultPoint::BeforeCommit));
        let res = fs.put_object("bkt", "k", &b"new attempt"[..], "", BTreeMap::new());
        set_fault(None);
        assert!(res.is_err());

        // OLD version still fully live (manifest + its blob intact).
        let m = manifest::read_manifest(&manifest::manifest_path(&bk.join("current"), "k")).unwrap();
        assert_eq!(m.parts[0].blob_id, orig_blob);
        assert!(blob::blob_path(&bk, &orig_blob).exists());
        let res = fs.get_object("bkt", "k", None).unwrap();
        assert_eq!(read_all(res.body), b"original");

        // An arriving orphan manifest is present (the failed publish's staged file).
        let arriving = list_dir(&bk.join("arriving"));
        assert_eq!(arriving.len(), 1, "expected one orphan arriving manifest: {arriving:?}");

        // recover()-style cleanup of arriving is deterministic.
        let removed = fs.cleanup_arriving("bkt").unwrap();
        assert_eq!(removed, 1);
        assert!(list_dir(&bk.join("arriving")).is_empty());
        // The NEW blob (written before the crash) is an orphan; the put's
        // pre-commit rollback already deleted it -> only the original remains.
        assert!(blob::blob_path(&bk, &orig_blob).exists());
        assert_eq!(count_blobs(&bk), 1);
    }

    #[test]
    fn crash_after_rename_before_reclaim_new_live_journal_present_then_recovered() {
        let (dir, fs) = store();
        let bk = dir.path().join("bkt");
        fs.put_object("bkt", "k", &b"v1-bytes"[..], "", BTreeMap::new())
            .unwrap();
        let v1_blob = {
            let m = manifest::read_manifest(&manifest::manifest_path(&bk.join("current"), "k")).unwrap();
            m.parts[0].blob_id.clone()
        };

        // Crash AFTER the commit rename, BEFORE reclaiming old blobs. publish()
        // returns Ok (new version is live) but leaves the journal + old blob.
        set_fault(Some(FaultPoint::BeforeReclaim));
        fs.put_object("bkt", "k", &b"v2-different"[..], "", BTreeMap::new())
            .unwrap();
        set_fault(None);

        // NEW version is live.
        let res = fs.get_object("bkt", "k", None).unwrap();
        assert_eq!(read_all(res.body), b"v2-different");
        // Old blob is still on disk (reclaim didn't run); journal present.
        assert!(blob::blob_path(&bk, &v1_blob).exists());
        let journals = list_dir(&bk.join("deleted"));
        assert_eq!(journals.len(), 1, "expected one journal: {journals:?}");
        assert_eq!(count_blobs(&bk), 2, "v1 + v2 blobs both present pre-recovery");

        // Apply the journal (recover() primitive): the live manifest's nonce
        // matches the journal -> old blob reclaimed, journal removed. Deterministic.
        let jpath = bk.join("deleted").join(&journals[0]);
        let stats = fs.apply_journal("bkt", &jpath).unwrap();
        assert_eq!(stats.blobs_deleted, 1);
        assert_eq!(stats.journals_removed, 1);
        assert!(!blob::blob_path(&bk, &v1_blob).exists());
        assert!(list_dir(&bk.join("deleted")).is_empty());
        assert_eq!(count_blobs(&bk), 1);

        // Re-applying the (now-removed) journal is a no-op (idempotent).
        let stats2 = fs.apply_journal("bkt", &jpath).unwrap();
        assert_eq!(stats2, ReclaimStats::default());
    }

    #[test]
    fn journal_nonce_mismatch_leaves_old_blobs() {
        // If a journal's commit_nonce does NOT match the live manifest (the commit
        // it described never landed, or a different version replaced it), the sweep
        // must NOT delete those blobs — they may be still-live-old.
        let (dir, fs) = store();
        let bk = dir.path().join("bkt");
        fs.put_object("bkt", "k", &b"live version"[..], "", BTreeMap::new())
            .unwrap();
        let live_blob = {
            let m = manifest::read_manifest(&manifest::manifest_path(&bk.join("current"), "k")).unwrap();
            m.parts[0].blob_id.clone()
        };
        // Hand-craft a stale publish journal that lists the LIVE blob but carries a
        // non-matching nonce (models "crash after journal, before rename" where the
        // commit never happened).
        let jpath = bk.join("deleted").join(format!("{}.journal", Uuid::new_v4()));
        let stale = Journal {
            mode: JournalMode::Publish,
            supersedes_key: "k".into(),
            commit_nonce: "does-not-match".into(),
            expected_new_etag: "\"whatever\"".into(),
            blobs: vec![live_blob.clone()],
        };
        fs.write_journal(&jpath, &stale).unwrap();

        let stats = fs.apply_journal("bkt", &jpath).unwrap();
        assert_eq!(stats.blobs_deleted, 0, "must not delete a still-live blob");
        assert_eq!(stats.journals_removed, 1);
        // Live blob untouched; object still readable.
        assert!(blob::blob_path(&bk, &live_blob).exists());
        assert_eq!(read_all(fs.get_object("bkt", "k", None).unwrap().body), b"live version");
    }

    #[test]
    fn crash_after_journal_before_journal_cleanup_recovers() {
        let (dir, fs) = store();
        let bk = dir.path().join("bkt");
        fs.put_object("bkt", "k", &b"vA"[..], "", BTreeMap::new())
            .unwrap();
        // Crash after reclaim ran but before the journal was removed: new live,
        // old blobs already gone, empty-work journal remains.
        set_fault(Some(FaultPoint::BeforeJournalCleanup));
        fs.put_object("bkt", "k", &b"vB-new"[..], "", BTreeMap::new())
            .unwrap();
        set_fault(None);
        let journals = list_dir(&bk.join("deleted"));
        assert_eq!(journals.len(), 1);
        // apply_journal re-runs the (now no-op) deletes and removes the journal.
        let jpath = bk.join("deleted").join(&journals[0]);
        let stats = fs.apply_journal("bkt", &jpath).unwrap();
        assert_eq!(stats.journals_removed, 1);
        assert!(list_dir(&bk.join("deleted")).is_empty());
        assert_eq!(read_all(fs.get_object("bkt", "k", None).unwrap().body), b"vB-new");
    }

    #[test]
    fn delete_journal_left_then_recovered() {
        // Simulate "delete committed (manifest gone) but reclaim/cleanup lost":
        // hand-craft a delete journal for an absent key listing an orphan blob.
        let (dir, fs) = store();
        let bk = dir.path().join("bkt");
        // Write a stray blob to act as the orphan the delete journal owns.
        let info = blob::write_blob(&bk, &b"orphaned by lost reclaim"[..]).unwrap();
        let jpath = bk.join("deleted").join(format!("{}.journal", Uuid::new_v4()));
        let j = Journal {
            mode: JournalMode::Delete,
            supersedes_key: "gone".into(),
            commit_nonce: String::new(),
            expected_new_etag: String::new(),
            blobs: vec![info.blob_id.clone()],
        };
        fs.write_journal(&jpath, &j).unwrap();
        // Key is absent -> delete journal executes -> orphan blob reclaimed.
        let stats = fs.apply_journal("bkt", &jpath).unwrap();
        assert_eq!(stats.blobs_deleted, 1);
        assert!(!blob::blob_path(&bk, &info.blob_id).exists());
    }

    // ---- PART 1 residual fixes (load-bearing) ----

    #[test]
    fn empty_segment_keys_rejected_no_collision() {
        // [REJECT — data loss] `a` and `a/` must NOT collapse onto one manifest.
        // PUT `a` succeeds; PUT `a/` is rejected (InvalidArgument via PathTraversal);
        // GET `a` still returns `a`'s bytes (no silent overwrite). This FAILS if the
        // empty-segment guard in `validate_object_path` is removed (then `a/` would
        // `push("")`-collapse to `current/a.meta` and overwrite `a`).
        let (_dir, fs) = store();
        fs.put_object("bkt", "a", &b"i am the real a"[..], "", BTreeMap::new())
            .unwrap();

        // Trailing slash -> empty final segment -> rejected.
        let err = fs
            .put_object("bkt", "a/", &b"impostor with trailing slash"[..], "", BTreeMap::new())
            .unwrap_err();
        assert!(matches!(err, StorageError::PathTraversal), "a/ -> {err:?}");

        // `a` is untouched: still its original bytes (proves no collision/overwrite).
        let res = fs.get_object("bkt", "a", None).unwrap();
        assert_eq!(read_all(res.body), b"i am the real a");

        // All other empty-segment shapes are rejected too.
        for bad in ["a//b", "/a", "a/", "/", "a/b/", "//"] {
            let err = fs
                .put_object("bkt", bad, &b"x"[..], "", BTreeMap::new())
                .unwrap_err();
            assert!(matches!(err, StorageError::PathTraversal), "key {bad:?} -> {err:?}");
        }

        // And `a//b` would otherwise alias `a/b` — confirm `a/b` is unaffected by the
        // rejected `a//b` write.
        fs.put_object("bkt", "a/b", &b"genuine a slash b"[..], "", BTreeMap::new())
            .unwrap();
        let err = fs
            .put_object("bkt", "a//b", &b"collision attempt"[..], "", BTreeMap::new())
            .unwrap_err();
        assert!(matches!(err, StorageError::PathTraversal));
        assert_eq!(
            read_all(fs.get_object("bkt", "a/b", None).unwrap().body),
            b"genuine a slash b"
        );
    }

    #[test]
    fn malformed_blob_id_in_manifest_errors_no_path_escape() {
        // [LOW] A corrupt/crafted `.meta` whose part blob_id contains `/`/`..` must
        // NOT be fed into `blob_path` (which would build an escaping path). GET errors
        // out (InvalidData) instead. FAILS if the `is_valid_blob_id` guard in
        // `open_body` is removed (then the malformed id would be path-joined and the
        // open would either escape or surface a different error class).
        let (dir, fs) = store();
        let bk = dir.path().join("bkt");
        fs.put_object("bkt", "k", &b"legit bytes"[..], "", BTreeMap::new())
            .unwrap();
        // Hand-corrupt the manifest's blob_id to a path-escaping string.
        let mp = manifest::manifest_path(&bk.join("current"), "k");
        let mut m = manifest::read_manifest(&mp).unwrap();
        m.parts[0].blob_id = "../../../../etc/passwd".to_string();
        manifest::write_manifest_temp(&mp, &m, false).unwrap();

        match fs.get_object("bkt", "k", None) {
            Err(StorageError::Io(e)) => assert_eq!(e.kind(), io::ErrorKind::InvalidData),
            Err(other) => panic!("expected Io(InvalidData) for malformed blob_id, got {other:?}"),
            Ok(_) => panic!("expected GET to error on a malformed blob_id, not succeed"),
        }
    }

    #[test]
    fn fsync_false_mode_still_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let fs = CasStore::with_fsync(dir.path(), false);
        fs.create_bucket("bkt").unwrap();
        fs.put_object("bkt", "k", &b"no-fsync path"[..], "", BTreeMap::new())
            .unwrap();
        assert_eq!(read_all(fs.get_object("bkt", "k", None).unwrap().body), b"no-fsync path");
        fs.delete_object("bkt", "k").unwrap();
        assert!(matches!(
            fs.head_object("bkt", "k").unwrap_err(),
            StorageError::ObjectNotFound
        ));
    }

    // ---- PART 2: multipart on the .ref-per-part model ----

    fn upload_3_parts(fs: &CasStore, bucket: &str, key: &str) -> (String, [Vec<u8>; 3], [String; 3]) {
        let upload_id = fs
            .create_multipart_upload(bucket, key, "application/octet-stream", BTreeMap::new())
            .unwrap();
        // Three differently-sized parts (deterministic bytes).
        let p1: Vec<u8> = (0..6_000_000u32).map(|i| (i % 256) as u8).collect();
        let p2: Vec<u8> = (0..7_000_000u32).map(|i| ((i / 3) % 256) as u8).collect();
        let p3: Vec<u8> = b"final small part".to_vec();
        let e1 = fs.upload_part(bucket, key, &upload_id, 1, &p1[..]).unwrap();
        let e2 = fs.upload_part(bucket, key, &upload_id, 2, &p2[..]).unwrap();
        let e3 = fs.upload_part(bucket, key, &upload_id, 3, &p3[..]).unwrap();
        (upload_id, [p1, p2, p3], [e1, e2, e3])
    }

    fn md5_hex(data: &[u8]) -> String {
        use md5::{Digest, Md5};
        hex::encode(Md5::digest(data))
    }

    #[test]
    fn multipart_create_upload_complete_round_trip() {
        let (dir, fs) = store();
        let bk = dir.path().join("bkt");
        let key = "big/object.bin";
        let (upload_id, parts, etags) = upload_3_parts(&fs, "bkt", key);

        // Part ETags are the per-part md5s.
        for (p, e) in parts.iter().zip(etags.iter()) {
            assert_eq!(*e, format!("\"{}\"", md5_hex(p)));
        }

        // ListParts shows 3 ascending parts with correct sizes/etags.
        let listed = fs.list_parts("bkt", key, &upload_id).unwrap();
        assert_eq!(listed.len(), 3);
        assert_eq!(listed[0].part_number, 1);
        assert_eq!(listed[0].size, parts[0].len() as i64);
        assert_eq!(listed[2].part_number, 3);

        // 3 part blobs on disk pre-complete.
        assert_eq!(count_blobs(&bk), 3);

        let complete = vec![
            CompletePart { part_number: 1, etag: etags[0].clone() },
            CompletePart { part_number: 2, etag: etags[1].clone() },
            CompletePart { part_number: 3, etag: etags[2].clone() },
        ];
        let composite = fs.complete_multipart_upload("bkt", key, &upload_id, &complete).unwrap();

        // Composite ETag = md5(concat of raw 16-byte part md5s)-3, exact format.
        let expected = {
            use md5::{Digest, Md5};
            let mut concat = Vec::new();
            for p in &parts {
                concat.extend_from_slice(&Md5::digest(p));
            }
            format!("\"{}-3\"", hex::encode(Md5::digest(&concat)))
        };
        assert_eq!(composite, expected);
        assert!(composite.ends_with("-3\""));

        // HEAD reports composite etag + total length.
        let total: usize = parts.iter().map(|p| p.len()).sum();
        let meta = fs.head_object("bkt", key).unwrap();
        assert_eq!(meta.etag, composite);
        assert_eq!(meta.content_length, total as i64);

        // GET reassembles the EXACT concatenated bytes.
        let mut want = Vec::new();
        for p in &parts {
            want.extend_from_slice(p);
        }
        let res = fs.get_object("bkt", key, None).unwrap();
        assert_eq!(res.total_size, total as u64);
        let got = read_all(res.body);
        assert_eq!(got.len(), want.len());
        assert_eq!(md5_hex(&got), md5_hex(&want));

        // Upload working dir removed; the 3 part blobs are now the live object's.
        assert!(!bk.join("arriving").join(&upload_id).exists());
        assert_eq!(count_blobs(&bk), 3);
        // No leftover journal (overwrite of a fresh key has no old blobs).
        assert!(list_dir(&bk.join("deleted")).is_empty());
    }

    #[test]
    fn multipart_range_get_spanning_part_boundary() {
        let (_dir, fs) = store();
        let key = "ranged";
        let (upload_id, parts, etags) = upload_3_parts(&fs, "bkt", key);
        let complete: Vec<CompletePart> = (0..3)
            .map(|i| CompletePart { part_number: (i + 1) as i32, etag: etags[i].clone() })
            .collect();
        fs.complete_multipart_upload("bkt", key, &upload_id, &complete).unwrap();

        let mut full = Vec::new();
        for p in &parts {
            full.extend_from_slice(p);
        }
        // A range straddling the part1/part2 boundary (part1 len = 6_000_000).
        let start = 6_000_000 - 100;
        let end = 6_000_000 + 200;
        let res = fs
            .get_object("bkt", key, Some(&format!("bytes={start}-{end}")))
            .unwrap();
        assert_eq!(res.resolved_range, Some(ByteRange { start, end }));
        let got = read_all(res.body);
        assert_eq!(got, full[start as usize..=end as usize]);
    }

    #[test]
    fn multipart_abort_cleans_up_blobs_and_dir() {
        let (dir, fs) = store();
        let bk = dir.path().join("bkt");
        let key = "to-abort";
        let (upload_id, _parts, _etags) = upload_3_parts(&fs, "bkt", key);
        assert_eq!(count_blobs(&bk), 3);
        assert!(bk.join("arriving").join(&upload_id).exists());

        fs.abort_multipart_upload("bkt", key, &upload_id).unwrap();
        // Part blobs + working dir gone.
        assert_eq!(count_blobs(&bk), 0);
        assert!(!bk.join("arriving").join(&upload_id).exists());
        // The object was never published.
        assert!(matches!(
            fs.head_object("bkt", key).unwrap_err(),
            StorageError::ObjectNotFound
        ));
    }

    #[test]
    fn multipart_overwrite_via_complete_reclaims_old_key_blobs() {
        let (dir, fs) = store();
        let bk = dir.path().join("bkt");
        let key = "overwritten";
        // v1: a single-part PUT.
        fs.put_object("bkt", key, &b"the original single-part value"[..], "", BTreeMap::new())
            .unwrap();
        let v1_blob = {
            let m = manifest::read_manifest(&manifest::manifest_path(&bk.join("current"), key)).unwrap();
            m.parts[0].blob_id.clone()
        };
        assert_eq!(count_blobs(&bk), 1);

        // v2: a multipart Complete to the SAME key.
        let (upload_id, parts, etags) = upload_3_parts(&fs, "bkt", key);
        // 1 (v1) + 3 (v2 parts) blobs present pre-complete.
        assert_eq!(count_blobs(&bk), 4);
        let complete: Vec<CompletePart> = (0..3)
            .map(|i| CompletePart { part_number: (i + 1) as i32, etag: etags[i].clone() })
            .collect();
        fs.complete_multipart_upload("bkt", key, &upload_id, &complete).unwrap();

        // OLD single-part blob journaled + reclaimed; only the 3 new part blobs live.
        assert!(!blob::blob_path(&bk, &v1_blob).exists(), "old key blob must be reclaimed");
        assert_eq!(count_blobs(&bk), 3);
        assert!(list_dir(&bk.join("deleted")).is_empty(), "journal cleaned");

        // GET returns the NEW (multipart) bytes.
        let mut want = Vec::new();
        for p in &parts {
            want.extend_from_slice(p);
        }
        let got = read_all(fs.get_object("bkt", key, None).unwrap().body);
        assert_eq!(md5_hex(&got), md5_hex(&want));
    }

    #[test]
    fn multipart_part_overwrite_uses_latest_blob() {
        let (dir, fs) = store();
        let bk = dir.path().join("bkt");
        let key = "reupload";
        let upload_id = fs
            .create_multipart_upload("bkt", key, "", BTreeMap::new())
            .unwrap();
        // Upload part 1 twice; the second supersedes (old blob reclaimed immediately).
        fs.upload_part("bkt", key, &upload_id, 1, &b"first attempt of part one"[..])
            .unwrap();
        assert_eq!(count_blobs(&bk), 1);
        let e1b = fs
            .upload_part("bkt", key, &upload_id, 1, &b"SECOND attempt, the real one"[..])
            .unwrap();
        // Superseded blob reclaimed -> still exactly one part blob.
        assert_eq!(count_blobs(&bk), 1);
        let e2 = fs.upload_part("bkt", key, &upload_id, 2, &b"part two"[..]).unwrap();

        let complete = vec![
            CompletePart { part_number: 1, etag: e1b },
            CompletePart { part_number: 2, etag: e2 },
        ];
        fs.complete_multipart_upload("bkt", key, &upload_id, &complete).unwrap();
        let got = read_all(fs.get_object("bkt", key, None).unwrap().body);
        assert_eq!(got, b"SECOND attempt, the real onepart two");
    }

    #[test]
    fn multipart_complete_rejects_bad_inputs() {
        let (_dir, fs) = store();
        let key = "validate";
        let (upload_id, _parts, etags) = upload_3_parts(&fs, "bkt", key);

        // Empty parts list.
        assert!(matches!(
            fs.complete_multipart_upload("bkt", key, &upload_id, &[]).unwrap_err(),
            StorageError::InvalidPart
        ));
        // Out-of-range part numbers.
        for bad in [0i32, -1, 10_001] {
            let err = fs
                .complete_multipart_upload(
                    "bkt",
                    key,
                    &upload_id,
                    &[CompletePart { part_number: bad, etag: etags[0].clone() }],
                )
                .unwrap_err();
            assert!(matches!(err, StorageError::InvalidPart), "part {bad} -> {err:?}");
        }
        // Empty ETag (F15).
        assert!(matches!(
            fs.complete_multipart_upload(
                "bkt", key, &upload_id,
                &[CompletePart { part_number: 1, etag: String::new() }],
            ).unwrap_err(),
            StorageError::InvalidPart
        ));
        // Mismatched ETag.
        assert!(matches!(
            fs.complete_multipart_upload(
                "bkt", key, &upload_id,
                &[CompletePart { part_number: 1, etag: "\"deadbeefdeadbeefdeadbeefdeadbeef\"".into() }],
            ).unwrap_err(),
            StorageError::InvalidPart
        ));
        // Wrong (descending / non-ascending) order.
        assert!(matches!(
            fs.complete_multipart_upload(
                "bkt", key, &upload_id,
                &[
                    CompletePart { part_number: 2, etag: etags[1].clone() },
                    CompletePart { part_number: 1, etag: etags[0].clone() },
                ],
            ).unwrap_err(),
            StorageError::InvalidPartOrder
        ));
        // A part number with no stored ref.
        assert!(matches!(
            fs.complete_multipart_upload(
                "bkt", key, &upload_id,
                &[CompletePart { part_number: 7, etag: etags[0].clone() }],
            ).unwrap_err(),
            StorageError::InvalidPart
        ));

        // None of those failures destroyed the upload: a correct Complete still works.
        let complete: Vec<CompletePart> = (0..3)
            .map(|i| CompletePart { part_number: (i + 1) as i32, etag: etags[i].clone() })
            .collect();
        assert!(fs.complete_multipart_upload("bkt", key, &upload_id, &complete).is_ok());
    }

    #[test]
    fn multipart_mismatched_bucket_or_key_is_no_such_upload() {
        let (_dir, fs) = store();
        fs.create_bucket("other").unwrap();
        let upload_id = fs
            .create_multipart_upload("bkt", "real-key", "", BTreeMap::new())
            .unwrap();
        let e1 = fs.upload_part("bkt", "real-key", &upload_id, 1, &b"data"[..]).unwrap();

        // upload_part to the wrong key.
        assert!(matches!(
            fs.upload_part("bkt", "wrong-key", &upload_id, 2, &b"x"[..]).unwrap_err(),
            StorageError::NoSuchUpload
        ));
        // complete to the wrong bucket.
        assert!(matches!(
            fs.complete_multipart_upload(
                "other", "real-key", &upload_id,
                &[CompletePart { part_number: 1, etag: e1.clone() }],
            ).unwrap_err(),
            StorageError::NoSuchUpload
        ));
        // abort to the wrong key.
        assert!(matches!(
            fs.abort_multipart_upload("bkt", "wrong-key", &upload_id).unwrap_err(),
            StorageError::NoSuchUpload
        ));
        // list_parts to the wrong key.
        assert!(matches!(
            fs.list_parts("bkt", "wrong-key", &upload_id).unwrap_err(),
            StorageError::NoSuchUpload
        ));
        // A bogus (non-uuid) upload id.
        assert!(matches!(
            fs.upload_part("bkt", "real-key", "../escape", 1, &b"x"[..]).unwrap_err(),
            StorageError::NoSuchUpload
        ));
    }

    #[test]
    fn multipart_upload_part_rejects_out_of_range_number() {
        let (_dir, fs) = store();
        let upload_id = fs
            .create_multipart_upload("bkt", "k", "", BTreeMap::new())
            .unwrap();
        for bad in [0i32, -1, 10_001] {
            assert!(matches!(
                fs.upload_part("bkt", "k", &upload_id, bad, &b"x"[..]).unwrap_err(),
                StorageError::InvalidPart
            ));
        }
    }

    #[test]
    fn multipart_failed_complete_is_retryable() {
        // Inject a pre-commit fault into publish (BeforeCommit) on Complete: the
        // commit must NOT land AND the upload's parts must survive so a SECOND
        // Complete (without the fault) succeeds (E2).
        let (dir, fs) = store();
        let bk = dir.path().join("bkt");
        let key = "retryable";
        let (upload_id, parts, etags) = upload_3_parts(&fs, "bkt", key);
        let complete: Vec<CompletePart> = (0..3)
            .map(|i| CompletePart { part_number: (i + 1) as i32, etag: etags[i].clone() })
            .collect();

        set_fault(Some(FaultPoint::BeforeCommit));
        let res = fs.complete_multipart_upload("bkt", key, &upload_id, &complete);
        set_fault(None);
        assert!(res.is_err(), "injected pre-commit fault must fail Complete");

        // The upload is intact: working dir + all 3 part blobs + 3 refs still present.
        assert!(bk.join("arriving").join(&upload_id).exists());
        assert_eq!(count_blobs(&bk), 3, "part blobs must survive a failed Complete");
        assert_eq!(fs.list_parts("bkt", key, &upload_id).unwrap().len(), 3);
        // Object not published.
        assert!(matches!(
            fs.head_object("bkt", key).unwrap_err(),
            StorageError::ObjectNotFound
        ));

        // Retry Complete (no fault) -> succeeds and reassembles correctly.
        let composite = fs.complete_multipart_upload("bkt", key, &upload_id, &complete).unwrap();
        assert!(composite.ends_with("-3\""));
        let mut want = Vec::new();
        for p in &parts {
            want.extend_from_slice(p);
        }
        let got = read_all(fs.get_object("bkt", key, None).unwrap().body);
        assert_eq!(md5_hex(&got), md5_hex(&want));
        assert!(!bk.join("arriving").join(&upload_id).exists());
    }

    #[test]
    fn list_multipart_uploads_bounded_and_truncated() {
        let (_dir, fs) = store();
        // Create 5 uploads across two keys.
        let mut ids = Vec::new();
        for i in 0..5 {
            let key = format!("k{}", i % 2);
            ids.push(fs.create_multipart_upload("bkt", &key, "", BTreeMap::new()).unwrap());
        }
        // Unbounded-ish (cap above count): all 5, not truncated.
        let (all, trunc) = fs.list_multipart_uploads("bkt", 100).unwrap();
        assert_eq!(all.len(), 5);
        assert!(!trunc);
        // Sorted by (key, upload-id): keys grouped.
        assert!(all.windows(2).all(|w| w[0].key <= w[1].key));

        // Bounded to 2 -> truncated.
        let (page, trunc) = fs.list_multipart_uploads("bkt", 2).unwrap();
        assert_eq!(page.len(), 2);
        assert!(trunc);

        // Missing bucket -> NoSuchBucket.
        assert!(matches!(
            fs.list_multipart_uploads("nope", 10).unwrap_err(),
            StorageError::BucketNotFound
        ));
    }

    #[test]
    fn parallel_upload_part_is_consistent() {
        // Concurrent UploadParts of DIFFERENT part numbers to one upload_id must all
        // land consistently (each writes its own blob + own ref; no shared mutation).
        use std::sync::Arc;
        let (dir, fs) = store();
        let bk = dir.path().join("bkt");
        let key = "concurrent";
        let upload_id = fs
            .create_multipart_upload("bkt", key, "", BTreeMap::new())
            .unwrap();
        let fs = Arc::new(fs);
        let upload_id = Arc::new(upload_id);

        let n = 16;
        let mut handles = Vec::new();
        for part in 1..=n {
            let fs = Arc::clone(&fs);
            let upload_id = Arc::clone(&upload_id);
            let key = key.to_string();
            handles.push(std::thread::spawn(move || {
                let body = vec![part as u8; 1000 + part as usize];
                let etag = fs.upload_part("bkt", &key, &upload_id, part, &body[..]).unwrap();
                (part, body, etag)
            }));
        }
        let mut results: Vec<(i32, Vec<u8>, String)> =
            handles.into_iter().map(|h| h.join().unwrap()).collect();
        results.sort_by_key(|r| r.0);

        // Every part landed: n distinct blobs, n refs.
        assert_eq!(count_blobs(&bk), n as usize);
        let listed = fs.list_parts("bkt", key, &upload_id).unwrap();
        assert_eq!(listed.len(), n as usize);

        // Complete with all parts -> reassembles in order.
        let complete: Vec<CompletePart> = results
            .iter()
            .map(|(p, _, e)| CompletePart { part_number: *p, etag: e.clone() })
            .collect();
        fs.complete_multipart_upload("bkt", key, &upload_id, &complete).unwrap();
        let mut want = Vec::new();
        for (_, body, _) in &results {
            want.extend_from_slice(body);
        }
        let got = read_all(fs.get_object("bkt", key, None).unwrap().body);
        assert_eq!(got, want);
    }

    // ---- PART 3: ListObjectsV2 + ListBuckets over the manifest key-tree ----

    use super::super::filesystem::ListObjectsInput;

    fn li(bucket: &str) -> ListObjectsInput {
        ListObjectsInput {
            bucket: bucket.to_string(),
            ..Default::default()
        }
    }

    fn put(fs: &CasStore, key: &str) {
        fs.put_object("bkt", key, format!("body-of-{key}").as_bytes(), "", BTreeMap::new())
            .unwrap();
    }

    fn keys_of(out: &ListObjectsOutput) -> Vec<String> {
        out.objects.iter().map(|o| o.key.clone()).collect()
    }

    #[test]
    fn list_ten_objects_sorted() {
        let (_dir, fs) = store();
        let mut want: Vec<String> = (0..10).map(|i| format!("obj-{i:02}")).collect();
        // Insert out of order to prove the impl sorts.
        for k in want.iter().rev() {
            put(&fs, k);
        }
        want.sort();
        let out = fs.list_objects(&li("bkt")).unwrap();
        assert_eq!(keys_of(&out), want);
        assert!(!out.is_truncated);
        assert!(out.common_prefixes.is_empty());
        // Per-object size/etag are real (from each manifest).
        for o in &out.objects {
            let expected_etag = {
                use md5::{Digest, Md5};
                format!("\"{}\"", hex::encode(Md5::digest(format!("body-of-{}", o.key).as_bytes())))
            };
            assert_eq!(o.etag, expected_etag);
            assert_eq!(o.size, format!("body-of-{}", o.key).len() as i64);
        }
    }

    #[test]
    fn list_empty_bucket() {
        let (_dir, fs) = store();
        let out = fs.list_objects(&li("bkt")).unwrap();
        assert!(out.objects.is_empty());
        assert!(out.common_prefixes.is_empty());
        assert!(!out.is_truncated);
        assert!(out.next_continuation_token.is_empty());
    }

    #[test]
    fn list_missing_bucket_is_no_such_bucket() {
        let (_dir, fs) = store();
        assert!(matches!(
            fs.list_objects(&li("nope")).unwrap_err(),
            StorageError::BucketNotFound
        ));
    }

    #[test]
    fn list_prefix_filter() {
        let (_dir, fs) = store();
        for k in ["alpha/1", "alpha/2", "beta/1", "gamma", "alphabet"] {
            put(&fs, k);
        }
        let mut input = li("bkt");
        input.prefix = "alpha".into();
        let out = fs.list_objects(&input).unwrap();
        // prefix `alpha` matches alpha/1, alpha/2, alphabet — NOT beta/gamma.
        assert_eq!(keys_of(&out), vec!["alpha/1", "alpha/2", "alphabet"]);

        // A directory-boundary prefix prunes to the subtree.
        let mut input2 = li("bkt");
        input2.prefix = "alpha/".into();
        let out2 = fs.list_objects(&input2).unwrap();
        assert_eq!(keys_of(&out2), vec!["alpha/1", "alpha/2"]);
    }

    #[test]
    fn list_delimiter_grouping_with_f1_coexistence() {
        // F1: object `a` (file a.meta) AND objects under `a/` must BOTH list. With
        // delimiter `/`, `a` is a KEY and `a/` is a CommonPrefix — both appear.
        let (_dir, fs) = store();
        for k in ["a", "a/b", "a/c", "d", "e/f"] {
            put(&fs, k);
        }
        let mut input = li("bkt");
        input.delimiter = "/".into();
        let out = fs.list_objects(&input).unwrap();
        // Top-level keys with no `/`: `a`, `d`. CommonPrefixes: `a/`, `e/`.
        assert_eq!(keys_of(&out), vec!["a", "d"]);
        assert_eq!(out.common_prefixes, vec!["a/".to_string(), "e/".to_string()]);
        assert!(!out.is_truncated);
    }

    #[test]
    fn list_delimiter_with_prefix() {
        let (_dir, fs) = store();
        for k in ["docs/2023/a", "docs/2023/b", "docs/2024/c", "docs/readme"] {
            put(&fs, k);
        }
        let mut input = li("bkt");
        input.prefix = "docs/".into();
        input.delimiter = "/".into();
        let out = fs.list_objects(&input).unwrap();
        // Under docs/: key `docs/readme`; CommonPrefixes `docs/2023/`, `docs/2024/`.
        assert_eq!(keys_of(&out), vec!["docs/readme"]);
        assert_eq!(
            out.common_prefixes,
            vec!["docs/2023/".to_string(), "docs/2024/".to_string()]
        );
    }

    #[test]
    fn list_start_after() {
        let (_dir, fs) = store();
        for k in ["a", "b", "c", "d"] {
            put(&fs, k);
        }
        let mut input = li("bkt");
        input.start_after = "b".into();
        let out = fs.list_objects(&input).unwrap();
        assert_eq!(keys_of(&out), vec!["c", "d"]);
    }

    #[test]
    fn list_max_keys_zero_empty_page_truncated() {
        let (_dir, fs) = store();
        put(&fs, "only");
        let mut input = li("bkt");
        input.max_keys = Some(0);
        let out = fs.list_objects(&input).unwrap();
        assert!(out.objects.is_empty());
        assert!(out.is_truncated, "Some(0) with more objects => IsTruncated");

        // Some(0) on an EMPTY bucket => not truncated.
        let (_d2, fs2) = store();
        let mut input2 = li("bkt");
        input2.max_keys = Some(0);
        let out2 = fs2.list_objects(&input2).unwrap();
        assert!(!out2.is_truncated);
        let _ = fs2;
    }

    #[test]
    fn list_pagination_no_dupes_no_skips() {
        // Page through with max-keys=3; concatenated pages must equal the full sorted
        // key set exactly once (no dupes, no skips).
        let (_dir, fs) = store();
        let mut want: Vec<String> = (0..10).map(|i| format!("k{i:02}")).collect();
        for k in &want {
            put(&fs, k);
        }
        want.sort();

        let mut seen: Vec<String> = Vec::new();
        let mut token = String::new();
        loop {
            let mut input = li("bkt");
            input.max_keys = Some(3);
            input.continuation_token = token.clone();
            let out = fs.list_objects(&input).unwrap();
            assert!(out.objects.len() <= 3);
            for o in &out.objects {
                seen.push(o.key.clone());
            }
            if !out.is_truncated {
                break;
            }
            token = out.next_continuation_token.clone();
            assert!(!token.is_empty(), "truncated page must yield a token");
        }
        assert_eq!(seen, want);
    }

    #[test]
    fn list_c6_pagination_objects_and_prefixes_sharing_a_page() {
        // The old C6 case: keys a,b,p/1,p/2,z with delimiter `/` and max-keys=3.
        // Listable items in sorted order are: a, b, p/ (CommonPrefix), z. With
        // max-keys=3 the first page is [a, b, p/] and the LAST EMITTED item is the
        // CommonPrefix `p/`. The token MUST be `p/` so the next page yields only `z`
        // — never re-emitting `p/` and never skipping `z`.
        let (_dir, fs) = store();
        for k in ["a", "b", "p/1", "p/2", "z"] {
            put(&fs, k);
        }
        let mut input = li("bkt");
        input.delimiter = "/".into();
        input.max_keys = Some(3);
        let page1 = fs.list_objects(&input).unwrap();
        assert_eq!(keys_of(&page1), vec!["a", "b"]);
        assert_eq!(page1.common_prefixes, vec!["p/".to_string()]);
        assert!(page1.is_truncated);
        // C6: token is the LAST EMITTED item = the CommonPrefix `p/`, NOT the last
        // object `b`. (If it were derived from objects.last() == "b", the next page
        // would re-emit `p/` and the test below would see a duplicate.)
        assert_eq!(page1.next_continuation_token, "p/");

        let mut input2 = li("bkt");
        input2.delimiter = "/".into();
        input2.max_keys = Some(3);
        input2.continuation_token = page1.next_continuation_token.clone();
        let page2 = fs.list_objects(&input2).unwrap();
        assert_eq!(keys_of(&page2), vec!["z"]);
        assert!(page2.common_prefixes.is_empty(), "p/ must not be re-emitted");
        assert!(!page2.is_truncated);

        // Concatenation across pages: a, b, p/ (prefix), z — each exactly once.
        let mut all_keys: Vec<String> = keys_of(&page1);
        all_keys.extend(keys_of(&page2));
        assert_eq!(all_keys, vec!["a", "b", "z"]);
        let mut all_prefixes: Vec<String> = page1.common_prefixes.clone();
        all_prefixes.extend(page2.common_prefixes.clone());
        assert_eq!(all_prefixes, vec!["p/".to_string()]);
    }

    #[test]
    fn list_deep_and_unicode_keys() {
        let (_dir, fs) = store();
        for k in [
            "deeply/nested/path/to/the/object.bin",
            "café/résumé.txt",
            "emoji/😀/file",
            "plain",
        ] {
            put(&fs, k);
        }
        let out = fs.list_objects(&li("bkt")).unwrap();
        let mut want = vec![
            "café/résumé.txt".to_string(),
            "deeply/nested/path/to/the/object.bin".to_string(),
            "emoji/😀/file".to_string(),
            "plain".to_string(),
        ];
        want.sort();
        assert_eq!(keys_of(&out), want);
        // The deep key GETs back correctly (round-trip through the tree).
        let got = read_all(
            fs.get_object("bkt", "deeply/nested/path/to/the/object.bin", None)
                .unwrap()
                .body,
        );
        assert_eq!(got, b"body-of-deeply/nested/path/to/the/object.bin");
    }

    #[test]
    fn list_key_ending_in_meta_round_trips_through_listing() {
        // The double-suffix encoding (report.meta -> report.meta.meta) must DECODE
        // back to `report.meta` during listing, not `report` and not `report.meta.meta`.
        let (_dir, fs) = store();
        for k in ["report.meta", "a.meta.meta", "a.meta/b", "normal.txt"] {
            put(&fs, k);
        }
        let out = fs.list_objects(&li("bkt")).unwrap();
        let mut want = vec![
            "a.meta.meta".to_string(),
            "a.meta/b".to_string(),
            "normal.txt".to_string(),
            "report.meta".to_string(),
        ];
        want.sort();
        assert_eq!(keys_of(&out), want);
    }

    #[test]
    fn list_multipart_object_has_composite_etag_and_real_size() {
        let (_dir, fs) = store();
        let key = "mp/big";
        let (upload_id, parts, etags) = upload_3_parts(&fs, "bkt", key);
        let complete: Vec<CompletePart> = (0..3)
            .map(|i| CompletePart { part_number: (i + 1) as i32, etag: etags[i].clone() })
            .collect();
        let composite = fs.complete_multipart_upload("bkt", key, &upload_id, &complete).unwrap();
        let total: u64 = parts.iter().map(|p| p.len() as u64).sum();

        // Also a plain object, to confirm listing mixes both.
        put(&fs, "plain");

        let out = fs.list_objects(&li("bkt")).unwrap();
        let mp = out.objects.iter().find(|o| o.key == key).unwrap();
        assert_eq!(mp.etag, composite);
        assert!(mp.etag.ends_with("-3\""));
        assert_eq!(mp.size, total as i64);
        // The plain object is also listed with its real (single-part) etag/size.
        let pl = out.objects.iter().find(|o| o.key == "plain").unwrap();
        assert_eq!(pl.size, "body-of-plain".len() as i64);
    }

    #[test]
    fn list_skips_corrupt_manifest_for_emitted_key() {
        // A key whose manifest is corrupt (e.g. raced a partial write) is SKIPPED in
        // the output rather than failing the whole listing.
        let (dir, fs) = store();
        let bk = dir.path().join("bkt");
        put(&fs, "good");
        put(&fs, "bad");
        // Corrupt `bad`'s manifest in place.
        let mp = manifest::manifest_path(&bk.join("current"), "bad");
        std::fs::write(&mp, b"{ this is not valid json").unwrap();
        let out = fs.list_objects(&li("bkt")).unwrap();
        // `good` listed; `bad` skipped (unreadable manifest).
        assert_eq!(keys_of(&out), vec!["good"]);
    }

    // ---- ListBuckets ----

    #[test]
    fn list_buckets_sorted() {
        let dir = tempfile::tempdir().unwrap();
        let fs = CasStore::new(dir.path());
        for b in ["zeta", "alpha", "mid-bucket"] {
            fs.create_bucket(b).unwrap();
        }
        let buckets = fs.list_buckets().unwrap();
        let names: Vec<String> = buckets.iter().map(|b| b.name.clone()).collect();
        assert_eq!(names, vec!["alpha", "mid-bucket", "zeta"]);
    }

    #[test]
    fn list_buckets_empty_root() {
        let dir = tempfile::tempdir().unwrap();
        let fs = CasStore::new(dir.path());
        assert!(fs.list_buckets().unwrap().is_empty());
    }

    #[test]
    fn list_buckets_skips_symlinked_entry() {
        // LOAD-BEARING (F4/E8): a symlink under the data root that POINTS AT a real
        // directory must NOT be listed as a bucket. This relies on
        // `DirEntry::metadata()` NOT following the symlink. If the impl used
        // `fs::metadata(path)` (which follows links), the symlink would resolve to a
        // dir and be WRONGLY listed — this test would then fail.
        let dir = tempfile::tempdir().unwrap();
        let fs = CasStore::new(dir.path());
        fs.create_bucket("real-bucket").unwrap();

        // Create a real directory OUTSIDE the data root, then symlink to it from
        // inside the data root with a bucket-like name.
        let external = dir.path().join("external-target-dir");
        std::fs::create_dir(&external).unwrap();
        // Put a file inside so the target is unambiguously a non-empty real dir.
        std::fs::write(external.join("x"), b"y").unwrap();
        // external-target-dir is a sibling of the symlink under root; both are under
        // the data root, but the symlink ITSELF must be skipped.
        let link = dir.path().join("aaa-symlinked-bucket");
        std::os::unix::fs::symlink(&external, &link).unwrap();

        let buckets = fs.list_buckets().unwrap();
        let names: Vec<String> = buckets.iter().map(|b| b.name.clone()).collect();
        // The symlink (aaa-symlinked-bucket) must NOT appear despite sorting first.
        assert!(
            !names.contains(&"aaa-symlinked-bucket".to_string()),
            "symlinked entry was wrongly listed: {names:?}"
        );
        // The real bucket and the (real, non-symlink) external target dir ARE listed.
        assert!(names.contains(&"real-bucket".to_string()));
        assert!(names.contains(&"external-target-dir".to_string()));
    }

    // ---- key <-> path round-trip for the listing decode over tricky keys ----

    #[test]
    fn listing_decode_is_exact_inverse_of_manifest_path() {
        let cur = Path::new("/data/bk/current");
        for key in [
            "a",
            "a/b",
            "report.meta",
            "a.meta.meta",
            "a.meta/b",
            "deeply/nested/path/to/object.bin",
            "café/résumé.txt",
            "emoji/😀/file",
            "trailing.dot.",
            "x.metameta",
        ] {
            let p = manifest::manifest_path(cur, key);
            let rel = p.strip_prefix(cur).unwrap();
            let decoded = manifest::decode_relpath_to_key(rel)
                .unwrap_or_else(|| panic!("decode failed for key {key:?}"));
            assert_eq!(decoded, key, "round-trip mismatch for key {key:?}");
        }
    }
}

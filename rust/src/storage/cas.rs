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

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::blob;
use super::filesystem::{validate_bucket_name, GetObjectResult, StorageError};
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
}

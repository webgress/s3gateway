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
use super::manifest::{
    self, Manifest, ManifestPartRef, ARRIVING_DIR, CURRENT_DIR, DELETED_DIR, MANIFEST_SUFFIX,
};
use super::metadata::ObjectMetadata;
use super::reader::{parse_range, ByteRange, MultipartReader, PlainFileReader};
use super::types::{
    validate_bucket_name, BucketInfo, CompletePart, GetObjectResult, ListObjectsInput,
    ListObjectsOutput, MultipartUpload, ObjectInfo, PartInfo, StorageError, MAX_UPLOADS_CAP,
};

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

/// Test-only, DETERMINISTIC injection points that let a test reproduce the exact
/// two-writer interleaving the per-key publish lock (`lock_key`) exists to
/// prevent — without any sleeps or timing races. Ported from the (removed)
/// `filesystem.rs` so the CAS publish lock keeps a load-bearing regression.
///
/// Two cooperating hooks, both armed for one specific `{bucket}/{key}`:
///  * [`PauseHook::pause`] — called at the publish CRITICAL WINDOW (after the new
///    manifest is staged + journaled, immediately BEFORE the commit rename). The
///    FIRST matching writer to arrive (writer A) parks here and blocks until the
///    test releases it. With the lock held, writer B cannot reach this window at
///    all (it blocks on `lock_key` first).
///  * [`PauseHook::note_lock_contention`] — called from `lock_key` when a thread is
///    about to BLOCK on an already-held per-key lock. With the real lock, writer B
///    hits this before ever reaching the window. With the lock removed/neutered, B
///    feels no contention and instead reaches the window itself (a SECOND `pause`
///    arrival, which passes straight through and records `second_window`).
///
/// The test waits for EXACTLY ONE of {B-blocked-on-lock, B-reached-window} to fire
/// — that single event deterministically distinguishes a real lock from a neutered
/// one, and tells the test how to drive the rest without deadlocking.
///
/// The whole mechanism is `#[cfg(test)]` only: in non-test builds both call sites
/// (`publish_window_pause`, the probe in `lock_key`) compile out entirely, so there
/// is ZERO effect on, and ZERO cost in, the production hot path.
#[cfg(test)]
mod publish_pause {
    use std::sync::{Condvar, Mutex, OnceLock};

    pub(super) struct PauseHook {
        pub key: String,
        state: Mutex<State>,
        cv: Condvar,
    }

    #[derive(Default)]
    struct State {
        window_arrived: bool,
        released: bool,
        second_window: bool,
        lock_contended: bool,
    }

    static HOOK: OnceLock<Mutex<Option<&'static PauseHook>>> = OnceLock::new();

    fn slot() -> &'static Mutex<Option<&'static PauseHook>> {
        HOOK.get_or_init(|| Mutex::new(None))
    }

    // There is a SINGLE global hook slot, so tests that arm it must not overlap (they
    // would clobber each other's armed key). This process-wide guard serializes them.
    static SERIAL: OnceLock<Mutex<()>> = OnceLock::new();

    /// Acquire the process-wide serialization guard for a hook-using test. Held for
    /// the test's duration (poison-tolerant). Returns the guard; drop ends the
    /// exclusive section.
    pub(super) fn serialize_test() -> std::sync::MutexGuard<'static, ()> {
        SERIAL
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|p| p.into_inner())
    }

    impl PauseHook {
        /// Arm a fresh hook for `key` (returns a leaked `'static` ref so the
        /// publishing/locking threads can read it without lifetime gymnastics —
        /// test-only, so the one-shot leak is harmless).
        pub(super) fn arm(key: &str) -> &'static PauseHook {
            let hook: &'static PauseHook = Box::leak(Box::new(PauseHook {
                key: key.to_string(),
                state: Mutex::new(State::default()),
                cv: Condvar::new(),
            }));
            *slot().lock().unwrap() = Some(hook);
            hook
        }

        pub(super) fn disarm() {
            *slot().lock().unwrap() = None;
        }

        /// Block until writer A has parked at the critical window.
        pub(super) fn wait_window_arrived(&self) {
            let mut st = self.state.lock().unwrap();
            while !st.window_arrived {
                st = self.cv.wait(st).unwrap();
            }
        }

        /// Block until EITHER writer B blocked on the real lock OR writer B reached
        /// the window itself (no lock). `true` iff B blocked on the lock.
        pub(super) fn wait_b_disposition(&self) -> bool {
            let mut st = self.state.lock().unwrap();
            while !st.lock_contended && !st.second_window {
                st = self.cv.wait(st).unwrap();
            }
            st.lock_contended
        }

        /// Like [`wait_b_disposition`] but bounded by `timeout`. `Some(blocked_on_lock)`
        /// if a disposition was observed, or `None` on timeout — used by the PUT-vs-
        /// DELETE test (a DELETE never reaches the window, so a MISSING lock yields no
        /// contention signal and would otherwise hang; a timeout surfaces it as a clean
        /// assertion failure instead).
        pub(super) fn wait_b_disposition_timeout(
            &self,
            timeout: std::time::Duration,
        ) -> Option<bool> {
            let deadline = std::time::Instant::now() + timeout;
            let mut st = self.state.lock().unwrap();
            while !st.lock_contended && !st.second_window {
                let now = std::time::Instant::now();
                if now >= deadline {
                    return None;
                }
                let (g, res) = self.cv.wait_timeout(st, deadline - now).unwrap();
                st = g;
                if res.timed_out() && !st.lock_contended && !st.second_window {
                    return None;
                }
            }
            Some(st.lock_contended)
        }

        /// Release the parked writer (writer A).
        pub(super) fn release(&self) {
            let mut st = self.state.lock().unwrap();
            st.released = true;
            self.cv.notify_all();
        }
    }

    /// Publish critical-window hook: the first matching writer parks and blocks
    /// until released; a second matching writer (only reachable without the lock)
    /// records `second_window` and passes straight through.
    pub(super) fn pause(bucket: &str, key: &str) {
        let hook = { *slot().lock().unwrap() };
        let Some(hook) = hook else { return };
        if hook.key != format!("{bucket}/{key}") {
            return;
        }
        let mut st = hook.state.lock().unwrap();
        if st.window_arrived {
            st.second_window = true;
            hook.cv.notify_all();
            return;
        }
        st.window_arrived = true;
        hook.cv.notify_all();
        while !st.released {
            st = hook.cv.wait(st).unwrap();
        }
    }

    /// Lock-contention hook: record that a writer is about to block on the
    /// already-held per-key lock for this key (proof the lock is serializing).
    pub(super) fn note_lock_contention(bucket: &str, key: &str) {
        let hook = { *slot().lock().unwrap() };
        let Some(hook) = hook else { return };
        if hook.key != format!("{bucket}/{key}") {
            return;
        }
        let mut st = hook.state.lock().unwrap();
        st.lock_contended = true;
        hook.cv.notify_all();
    }
}

/// Publish critical-window pause point (after stage+journal, before the commit
/// rename). No-op outside tests; see [`publish_pause`] for the deterministic hook.
#[inline(always)]
fn publish_window_pause(_bucket: &str, _key: &str) {
    #[cfg(test)]
    publish_pause::pause(_bucket, _key);
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

/// Aggregate outcome of a [`CasStore::recover`] sweep across all buckets
/// (REDESIGN §6). All counts are cumulative over every bucket swept.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RecoveryStats {
    /// Buckets the sweep visited.
    pub buckets: usize,
    /// Uncommitted staged single-PUT/Complete manifests removed from `arriving/`
    /// (6.1). Multipart upload working dirs are KEPT (resumable; see `recover`).
    pub arriving_manifests_removed: usize,
    /// Reclaim journals processed (executed-or-discarded then unlinked) (6.2).
    pub journals_processed: usize,
    /// Blobs reclaimed while applying journals (6.2).
    pub journal_blobs_reclaimed: usize,
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
        // Test-only contention probe: if the shard is already held, record that this
        // writer is about to BLOCK on the per-key lock (proof the lock is
        // serializing) before we actually block. Compiled out in production — the
        // real acquire below is unchanged.
        #[cfg(test)]
        {
            if self.key_locks[idx].try_write().is_err() {
                publish_pause::note_lock_contention(bucket, key);
            }
        }
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

    /// DeleteBucket: remove an EMPTY bucket. "Empty" means BOTH (a) the `current/`
    /// manifest tree holds no live object AND (b) there is no in-flight multipart
    /// upload (`arriving/{uuid}/` working dir). This matches S3, which refuses to
    /// delete a bucket that still has in-progress multipart uploads — they would
    /// otherwise be silently torn down with the bucket. A bucket failing either
    /// check is `BucketNotEmpty` (409). The infra dirs themselves (`current/`,
    /// `arriving/`, `blobs/`, `deleted/`), orphan blobs, staged single-PUT/Complete
    /// `{uuid}.manifest` temps, and spent journals are NOT objects and do not block
    /// deletion. Symlink-aware existence check (mirrors `head_bucket`), so a planted
    /// `data-dir/bucket -> /external` symlink is rejected as `BucketNotFound` rather
    /// than having its contents scanned/removed (and `remove_dir_all` never traverses
    /// the link target).
    pub fn delete_bucket(&self, name: &str) -> Result<()> {
        self.validate_bucket_component(name)?;
        self.head_bucket(name)?;
        let path = self.bucket_root(name);

        // (a) Empty iff the current/ tree contains no committed manifest.
        let mut has_object = false;
        walk_dir_files(&self.current_root(name), &mut |p: &Path| -> io::Result<()> {
            let fname = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
            if fname.ends_with(MANIFEST_SUFFIX) && !fname.contains(".tmp.") {
                has_object = true;
            }
            Ok(())
        })?;
        if has_object {
            return Err(StorageError::BucketNotEmpty);
        }

        // (b) S3 fidelity: an in-flight multipart upload also makes the bucket
        // non-empty. An upload is an `arriving/{uuid}/` DIRECTORY (the per-upload
        // working dir created by CreateMultipartUpload); staged single-PUT/Complete
        // temps are `arriving/{uuid}.manifest` FILES and do NOT count. Until the
        // client calls CompleteMultipartUpload or AbortMultipartUpload, the upload is
        // live and DeleteBucket must refuse with BucketNotEmpty.
        if self.has_in_flight_upload(name)? {
            return Err(StorageError::BucketNotEmpty);
        }

        // Empty: tear down the whole bucket (infra dirs + any orphan blobs / staged
        // temps / spent journals included).
        std::fs::remove_dir_all(&path)?;
        Ok(())
    }

    /// True iff the bucket has at least one in-flight multipart upload — an
    /// `arriving/{uuid}/` working DIRECTORY (validated by a readable `upload.json`).
    /// Subdirectory entries that are NOT a live upload (no `upload.json`) are ignored
    /// so a stray dir does not wedge DeleteBucket forever.
    fn has_in_flight_upload(&self, bucket: &str) -> Result<bool> {
        let arriving = self.arriving_root(bucket);
        let rd = match std::fs::read_dir(&arriving) {
            Ok(rd) => rd,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(e.into()),
        };
        for entry in rd {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue; // staged {uuid}.manifest temps are not uploads.
            }
            if read_nofollow(&entry.path().join("upload.json")).is_ok() {
                return Ok(true);
            }
        }
        Ok(false)
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
    ///   1. stage    arriving/{uuid}.manifest  (fsync if --fsync)
    ///   2. journal  deleted/{uuid}.journal listing OLD blobs (if K exists)
    ///   3. COMMIT   rename(arriving -> current/K.s3gw-live.meta) + best-effort parent fsync
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

        // No runtime key/prefix collision check is needed under the CAS encode v2
        // reserved-suffix scheme. The only structural collision — a key `a` (FILE
        // `current/a.s3gw-live.meta`) vs a key `a.s3gw-live.meta/b` (which would need
        // DIRECTORY `current/a.s3gw-live.meta/`) — is IMPOSSIBLE because any key with
        // a `/`-segment ending in `MANIFEST_SUFFIX` is rejected up front by
        // `validate_object_path`. So `a` + `a/b` and `a` + `a.meta/b` freely coexist
        // at distinct paths; the old `detect_prefix_conflict`/`KeyPrefixConflict`/409
        // machinery is gone (the conflict can no longer occur at runtime).

        // ---- step 1: stage the new manifest in arriving/ ----
        // Staged manifests are uuid-named (`arriving/{uuid}.manifest`), NOT key-
        // derived, so they do NOT use MANIFEST_SUFFIX.
        let staged_id = Uuid::new_v4().to_string();
        let staged = self.arriving_root(bucket).join(format!("{staged_id}.manifest"));
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

        // Deterministic concurrency test hook: park the FIRST writer in the publish
        // critical window (manifest staged + journaled, NOT yet committed) so a test
        // can drive the exact two-writer interleaving the per-key lock prevents. The
        // caller holds the per-key WRITE lock across this whole function, so under the
        // real lock a second same-key writer can never reach this point concurrently.
        // No-op in production.
        publish_window_pause(bucket, key);

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

        // No prefix-conflict check needed (CAS encode v2): the reserved-suffix
        // rejection in `validate_object_path` makes a key whose manifest path is a
        // DIRECTORY impossible (that would require a sibling key with a segment
        // ending in `MANIFEST_SUFFIX`, which is rejected up front). `read_manifest`/
        // `remove_file` therefore always see a FILE-or-absent manifest path here.

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
        // READ path: lexical-only validation (no per-request canonicalize). Symlink
        // containment is upheld by O_NOFOLLOW on the manifest/blob opens + the lexical
        // check (see `validate_object_path` rationale).
        self.validate_object_path_lexical(bucket, key)?;
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
        // READ path: lexical-only validation (no per-request canonicalize), same
        // rationale as `get_object`.
        self.validate_object_path_lexical(bucket, key)?;
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

    /// Remove an uncommitted staged manifest in `arriving/` (REDESIGN §6.1). Staged
    /// manifests are uuid-named `arriving/{uuid}.manifest` (NOT key-derived, so they
    /// do not use `MANIFEST_SUFFIX`); only the FILE entries are reaped, the `{uuid}/`
    /// multipart working DIRS are kept. The per-upload blob orphan a staged manifest
    /// may reference is reclaimed by the fallback GC — for a single PUT the
    /// pre-commit rollback already deleted it.
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
            if name.ends_with(".manifest") && std::fs::remove_file(entry.path()).is_ok() {
                removed += 1;
            }
        }
        Ok(removed)
    }

    // ---- crash-recovery sweep (REDESIGN §6) ----

    /// Crash-recovery sweep, run at STARTUP before the listener binds (REDESIGN
    /// §6). It makes crash cleanup deterministic and is **idempotent** — re-running
    /// it causes no harm. It performs, for every bucket:
    ///
    ///  - **6.1 `arriving/` sweep.** Delete each staged `{uuid}.manifest` — an
    ///    uncommitted single-PUT/Complete manifest. A committed object lives in
    ///    `current/`, so a manifest still sitting in `arriving/` is, by definition,
    ///    a publish that never committed and is always safe to delete on startup.
    ///    The new blob such a manifest may reference is an orphan reclaimed by the
    ///    fallback GC (single-PUT pre-commit rollback already deleted it in the
    ///    common path). **Multipart upload working dirs `arriving/{uuid}/` are
    ///    KEPT** — see the retention rule below.
    ///
    ///  - **6.2 `deleted/` journals.** Apply each `*.journal` via the §3.2/§4 nonce
    ///    rule ([`apply_journal`]): a *publish* journal deletes its OLD blobs IFF
    ///    the live manifest carries the journal's `commit_nonce` (the commit
    ///    landed); a *delete* journal deletes its blobs IFF the live manifest is
    ///    absent. Either way the journal is then unlinked. Deletes are idempotent
    ///    (unlink-missing == no-op), so a crash mid-reclaim replays cleanly.
    ///
    /// **Multipart-upload-dir retention rule (the deliberate choice, REDESIGN
    /// §6.1/§6.4):** `recover()` does NOT delete `arriving/{uuid}/` multipart
    /// working dirs. An in-flight multipart upload is *resumable* — it lives until
    /// the client calls AbortMultipartUpload or an explicit expiry policy reaps it.
    /// We cannot tell a "crashed mid-Complete" upload apart from a "client paused
    /// between UploadPart and Complete" one on a normal restart, so the SAFE rule is
    /// to keep them: nuking them would destroy valid in-flight uploads. A
    /// crashed-mid-Complete upload simply stays Completable/Abortable after restart
    /// (the part blobs are immutable and intact). Their part blobs are therefore
    /// treated as REFERENCED by [`gc_orphan_blobs`] so the full GC never reaps a
    /// live upload's parts. (A staged single `{uuid}.manifest` is unambiguous — it is
    /// a failed publish — so 6.1 deletes those; only the `{uuid}/` dirs are kept.)
    ///
    /// The full O(blobs) fallback GC (§6.3) is intentionally NOT run here — it is
    /// the opt-in [`gc_orphan_blobs`], called only on explicit request (decision
    /// #4), never automatically on startup.
    ///
    /// Errors reading one bucket's `arriving/`/`deleted/` do not abort the whole
    /// sweep mid-bucket beyond that bucket; a hard io error is propagated.
    pub fn recover(&self) -> Result<RecoveryStats> {
        let mut stats = RecoveryStats::default();
        let rd = match std::fs::read_dir(&self.root) {
            Ok(rd) => rd,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(stats),
            Err(e) => return Err(e.into()),
        };
        for entry in rd {
            let entry = entry?;
            // Only real bucket directories (skip symlinks/files/hidden infra).
            let md = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            if md.file_type().is_symlink() || !md.is_dir() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') {
                continue;
            }
            stats.buckets += 1;
            self.recover_bucket(&name, &mut stats)?;
        }
        Ok(stats)
    }

    /// Sweep one bucket's `arriving/` (6.1: drop staged manifests, keep upload
    /// dirs) and `deleted/` (6.2: apply+remove journals).
    fn recover_bucket(&self, bucket: &str, stats: &mut RecoveryStats) -> Result<()> {
        // 6.1: delete staged single-PUT/Complete manifests; keep `{uuid}/` dirs.
        stats.arriving_manifests_removed += self.cleanup_arriving(bucket)?;

        // 6.2: apply each reclaim journal, then remove it.
        let deleted = self.deleted_root(bucket);
        let rd = match std::fs::read_dir(&deleted) {
            Ok(rd) => rd,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        // Collect first so applying (which unlinks) does not perturb the iterator.
        let mut journals: Vec<PathBuf> = Vec::new();
        for entry in rd {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.ends_with(".journal") {
                journals.push(entry.path());
            }
        }
        for jpath in journals {
            let s = self.apply_journal(bucket, &jpath)?;
            stats.journal_blobs_reclaimed += s.blobs_deleted;
            stats.journals_processed += s.journals_removed;
        }
        Ok(())
    }

    /// FALLBACK full GC (REDESIGN §6.3, Defense B) — **opt-in / manual ONLY**, never
    /// run automatically by [`recover`] or on a periodic timer (decision #4). This
    /// is the O(total blobs) backstop that reclaims blobs orphaned by a LOST journal
    /// (e.g. the filesystem lost a `deleted/` entry): it scans every LIVE manifest in
    /// `current/` (and every in-flight `arriving/{uuid}/parts/*.ref`) to build the
    /// set of REFERENCED blob ids, then deletes every blob under `blobs/` whose id is
    /// not in that set.
    ///
    /// SAFETY (the load-bearing invariant): a blob referenced by ANY live manifest —
    /// or by ANY in-flight multipart upload's part ref — is treated as referenced
    /// and is NEVER deleted. This is what makes blob deletion monotonically safe
    /// regardless of journal integrity. Because in-flight upload dirs are KEPT by
    /// `recover()` (see its retention rule) and their part refs are scanned here, the
    /// GC never reaps a live upload's parts.
    ///
    /// CONCURRENCY: this is intended to run at startup (no live traffic) or as an
    /// offline maintenance op. Running it under live traffic risks reaping a blob a
    /// concurrent in-flight PUT has just written to `blobs/` but not yet recorded in
    /// any manifest/ref — callers must run it only when that hazard is excluded
    /// (REDESIGN §6.4). It is per-bucket; returns the number of blobs reclaimed.
    pub fn gc_orphan_blobs(&self, bucket: &str) -> Result<usize> {
        self.head_bucket(bucket)?;
        let bucket_root = self.bucket_root(bucket);

        // 1. Build the referenced-id set from all live manifests in current/.
        let mut referenced: std::collections::HashSet<String> = std::collections::HashSet::new();
        let current_root = self.current_root(bucket);
        walk_dir_files(&current_root, &mut |path: &Path| -> io::Result<()> {
            let fname = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
            if !fname.ends_with(MANIFEST_SUFFIX) || fname.contains(".tmp.") {
                return Ok(());
            }
            // A corrupt manifest cannot be trusted to enumerate its blobs; to stay on
            // the safe side (never delete a possibly-referenced blob) we abort the GC
            // for this bucket rather than under-count references. Propagate the read
            // error so the caller knows the GC did not run to completion.
            let m = manifest::read_manifest(path)?;
            for id in m.blob_ids() {
                referenced.insert(id);
            }
            Ok(())
        })?;

        // 2. Also treat blobs referenced by in-flight multipart uploads as live (the
        //    upload dirs are KEPT by recover(); reaping their parts would corrupt a
        //    resumable upload). Scan arriving/{uuid}/parts/*.ref.
        let arriving = self.arriving_root(bucket);
        if let Ok(rd) = std::fs::read_dir(&arriving) {
            for entry in rd.flatten() {
                let ft = match entry.file_type() {
                    Ok(ft) => ft,
                    Err(_) => continue,
                };
                if !ft.is_dir() {
                    continue; // staged {uuid}.manifest files reference no kept blob.
                }
                if let Ok(refs) = Self::read_part_refs(&entry.path()) {
                    for r in refs.values() {
                        referenced.insert(r.blob_id.clone());
                    }
                }
            }
        }

        // 3. Walk blobs/xx/yy/{id}; delete any id not in `referenced`.
        let blobs_root = bucket_root.join(blob::BLOBS_DIR);
        let mut reclaimed = 0usize;
        walk_dir_files(&blobs_root, &mut |path: &Path| -> io::Result<()> {
            let id = match path.file_name().and_then(|s| s.to_str()) {
                Some(s) => s,
                None => return Ok(()),
            };
            // Only consider syntactically valid blob ids (defensive; everything under
            // blobs/ is uuid-named). An unreferenced valid blob is an orphan.
            if blob::is_valid_blob_id(id)
                && !referenced.contains(id)
                && std::fs::remove_file(path).is_ok()
            {
                reclaimed += 1;
            }
            Ok(())
        })?;
        Ok(reclaimed)
    }

    /// AGE-BASED abandoned-multipart-upload reaper (S3's AbortIncompleteMultipartUpload
    /// concept). Removes every in-flight upload working dir `arriving/{uuid}/` —
    /// AND reclaims its part blobs — whose age exceeds `max_age`, across every
    /// bucket. Returns the number of upload dirs reaped.
    ///
    /// This is OPT-IN: it is NOT run by [`recover`] (which deliberately KEEPS all
    /// in-flight uploads so a normal restart never destroys a resumable upload), and
    /// runs only when the operator enables it via `--abort-incomplete-uploads-after`.
    ///
    /// Age is measured from the upload dir's `upload.json` mtime (the create time;
    /// UploadParts do not touch it), falling back to the dir's own mtime. An upload
    /// YOUNGER than `max_age` is left strictly untouched. A subdir lacking a readable
    /// `upload.json` is NOT a live upload and is skipped (left for `gc_orphan_blobs`
    /// / `recover`), so a half-created or already-aborted dir is never mistaken for an
    /// abandoned upload. Part blobs are reclaimed from the stored `.ref` files BEFORE
    /// the dir is removed (the same teardown as AbortMultipartUpload).
    ///
    /// CONCURRENCY: like `gc_orphan_blobs`, intended for startup (no live traffic) or
    /// an offline maintenance window. The `max_age` floor means it will not reap an
    /// upload a client is actively writing to within the window.
    pub fn gc_abandoned_uploads(&self, max_age: std::time::Duration) -> Result<usize> {
        let now = std::time::SystemTime::now();
        let mut reaped = 0usize;
        let rd = match std::fs::read_dir(&self.root) {
            Ok(rd) => rd,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(e.into()),
        };
        for entry in rd {
            let entry = entry?;
            let md = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            // Only real bucket dirs (skip symlinks/files/hidden infra).
            if md.file_type().is_symlink() || !md.is_dir() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') {
                continue;
            }
            reaped += self.gc_abandoned_uploads_bucket(&name, now, max_age)?;
        }
        Ok(reaped)
    }

    /// Reap abandoned upload dirs in ONE bucket (helper for [`gc_abandoned_uploads`]).
    fn gc_abandoned_uploads_bucket(
        &self,
        bucket: &str,
        now: std::time::SystemTime,
        max_age: std::time::Duration,
    ) -> Result<usize> {
        let bucket_root = self.bucket_root(bucket);
        let arriving = self.arriving_root(bucket);
        let rd = match std::fs::read_dir(&arriving) {
            Ok(rd) => rd,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(e.into()),
        };
        let mut reaped = 0usize;
        for entry in rd {
            let entry = entry?;
            // Only `{uuid}/` working dirs are uploads; staged `{uuid}.manifest` FILEs
            // are crash debris handled by cleanup_arriving — leave them here.
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let upload_path = entry.path();
            let upload_json = upload_path.join("upload.json");
            // Require a readable upload.json — only a genuine in-flight upload is
            // eligible (a half-created/aborted dir is not "abandoned"; skip it).
            let json_md = match std::fs::metadata(&upload_json) {
                Ok(m) => m,
                Err(_) => continue,
            };
            // Age = now - (upload.json mtime, else the dir's own mtime). Skip if we
            // cannot determine an mtime, or if it is younger than the threshold.
            let mtime = json_md
                .modified()
                .or_else(|_| entry.metadata().and_then(|m| m.modified()));
            let age = match mtime {
                Ok(t) => match now.duration_since(t) {
                    Ok(a) => a,
                    Err(_) => continue, // mtime in the future -> treat as fresh.
                },
                Err(_) => continue,
            };
            if age < max_age {
                continue; // younger than the threshold -> strictly untouched.
            }
            // Abandoned: reclaim its part blobs, then remove the dir (== Abort).
            if let Ok(refs) = Self::read_part_refs(&upload_path) {
                for r in refs.values() {
                    let _ = blob::reclaim_blob(&bucket_root, &r.blob_id);
                }
            }
            if std::fs::remove_dir_all(&upload_path).is_ok() {
                reaped += 1;
            }
        }
        Ok(reaped)
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

    /// PURELY LEXICAL key validation — NO filesystem syscalls. Rejects keys with
    /// `..`, NUL, absolute paths, empty segments, or — the single structural
    /// reservation of the CAS encode v2 layout — ANY `/`-split segment ending in
    /// `MANIFEST_SUFFIX`, then asserts lexical containment of the computed manifest
    /// path within the bucket's `current/` tree. This is the READ-path validator
    /// (GET/HEAD/LIST): combined with O_NOFOLLOW on the manifest and blob opens it
    /// upholds symlink-containment without a per-request `canonicalize` (see
    /// [`validate_object_path`] for why this is sufficient for reads).
    ///
    /// **Reserved-suffix rejection (load-bearing).** The manifest for key `K` is the
    /// FILE `{leaf}{MANIFEST_SUFFIX}` under `current/`, and every NON-leaf segment of
    /// `K` becomes a raw DIRECTORY name. If any segment (leaf OR ancestor) ended in
    /// `MANIFEST_SUFFIX`, a raw directory or a sibling manifest file could collide
    /// (e.g. key `a.s3gw-live.meta/b` would need `current/a.s3gw-live.meta/` as a dir
    /// while key `a` stores a FILE at exactly that path). Rejecting ALL such segments
    /// up front makes the key↔path map collision-free by construction, which is why
    /// no runtime `KeyPrefixConflict`/409 check is needed anymore. Maps to 400
    /// InvalidArgument (`PathTraversal`). KNOWN LIMITATION: an object key may not
    /// contain a `/`-segment ending in `MANIFEST_SUFFIX`.
    fn validate_object_path_lexical(&self, bucket: &str, key: &str) -> Result<()> {
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
        // [RESERVED SUFFIX — load-bearing] Reject any key with a `/`-segment ending
        // in `MANIFEST_SUFFIX`. Not just the leaf: a non-leaf segment becomes a raw
        // directory, and a raw dir ending in the suffix would collide with a manifest
        // file. This single rejection is what makes the key↔path encoding collision-
        // free (replacing the old `.meta`-double-suffix + `KeyPrefixConflict`/409
        // scheme). An ordinary `.meta` key is fine: `report.meta` ->
        // `current/report.meta.s3gw-live.meta`.
        if key.split('/').any(|s| s.ends_with(MANIFEST_SUFFIX)) {
            return Err(StorageError::PathTraversal);
        }
        // The four infra dir names are under the bucket root and never collide with a
        // key (keys live under current/), so no key-segment reservation is needed for
        // them.
        let bucket_path = self.bucket_root(bucket);
        let current = bucket_path.join(CURRENT_DIR);
        let full = manifest::manifest_path(&current, key);
        let base = normalize(&current);
        let cleaned = normalize(&full);
        if !cleaned.starts_with(&base) {
            return Err(StorageError::PathTraversal);
        }
        Ok(())
    }

    /// FULL key validation = the lexical checks PLUS the expensive `canonicalize`
    /// containment of the deepest existing ancestor (`assert_real_parent_within_root`).
    /// Reserved for paths that CREATE a new directory/file under `current/` (PUT,
    /// CompleteMultipartUpload via the upload's stored key, CreateMultipartUpload):
    /// those `create_dir_all`/rename a new path into the tree, so a symlinked
    /// intermediate directory must be caught BEFORE the create can write through it.
    ///
    /// **Why reads use only the lexical check (PERF — the throughput goal).** The
    /// old hot path ran one `canonicalize` (a readlink/stat per path component) on
    /// EVERY GET/HEAD/LIST. For a max-throughput gateway that per-request syscall
    /// storm is pure overhead, because reads never CREATE a path component — they
    /// only OPEN an existing manifest/blob. Symlink-containment on the read path is
    /// instead upheld by:
    ///   1. the LEXICAL containment check ([`validate_object_path_lexical`]) — rejects
    ///      `..`, absolute, and any escape that is visible without touching the fs; and
    ///   2. **O_NOFOLLOW** on the actual opens: `read_manifest` opens
    ///      `current/{…}.s3gw-live.meta` with O_NOFOLLOW (a symlinked manifest leaf →
    ///      ELOOP), and `DioFile::open_read` opens each `blobs/xx/yy/{uuid}` blob with
    ///      O_NOFOLLOW (a symlinked blob leaf → ELOOP). Blob ids are bare uuids resolved
    ///      through a fixed 2×2 fanout, so a blob path has NO client-controlled
    ///      intermediate component to symlink.
    ///
    /// The only residual a read does not canonicalize is a symlinked INTERMEDIATE
    /// directory under `current/` (e.g. `current/a` → /external). But directories
    /// under `current/` are created ONLY by the gateway's own WRITE path — which DOES
    /// canonicalize — never by a client; a client cannot plant a symlink through the
    /// S3 API. So such a symlink can only be introduced out-of-band on the host
    /// filesystem, exactly the same trust boundary the write-path canonicalize
    /// assumes. A read through it would land on a manifest/blob open that O_NOFOLLOW
    /// guards at the leaf, and a relocated subtree still cannot escape the lexical
    /// containment of the key. (F3/F5/D4/D5-class containment preserved.)
    fn validate_object_path(&self, bucket: &str, key: &str) -> Result<()> {
        self.validate_object_path_lexical(bucket, key)?;
        let current = self.bucket_root(bucket).join(CURRENT_DIR);
        let full = manifest::manifest_path(&current, key);
        self.assert_real_parent_within_root(&full)?;
        Ok(())
    }

    /// Canonicalize the deepest EXISTING ancestor of `target` (following symlinks)
    /// and assert it stays inside the canonical data root. Ported verbatim from
    /// `filesystem.rs` (catches a symlinked intermediate dir escape). Used ONLY by the
    /// write/create paths now — see [`validate_object_path`].
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
        let upload = self.assert_upload_matches(&upload_dir, bucket, key)?;

        let bucket_root = self.bucket_root(bucket);
        // Stream the part to a fresh immutable blob (lock-free; one-pass MD5; fsync).
        // The big I/O happens BEFORE the per-key lock is taken — no lock is ever held
        // across a streaming body read.
        let info = blob::write_blob(&bucket_root, body).map_err(body_or_io)?;
        let etag = format!("\"{}\"", info.md5_hex);

        // Take the per-key WRITE lock around the .ref install (read-prev + tmp-write
        // + rename + reclaim), keyed by the upload's STORED bucket/key — the SAME key
        // `complete_multipart_upload` locks on. This serializes a part's ref swap
        // against a concurrent Complete's read_part_refs+commit so Complete never
        // observes a half-swapped ref set (e.g. a number whose blob was just reclaimed
        // but whose ref still pointed at it). The lock is NOT held across the body
        // stream above; only the tiny ref-file critical section is serialized.
        let _guard = self.lock_key(&upload.bucket, &upload.key);

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
    ///
    /// Defense-in-depth (item #6): cross-check that the `part_number` RECORDED inside
    /// each `.ref` matches the number encoded in its FILENAME (`{NNNNN}.ref`). A
    /// mismatch means a tampered/corrupt ref (its body claims a different part than
    /// its name), so the entry is DROPPED — Complete then reports `InvalidPart` for
    /// that claimed number rather than assembling a part under the wrong index. (Under
    /// normal operation UploadPart always writes a ref whose body number == filename
    /// number, so this never fires.)
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
            // The filename's numeric stem (`{NNNNN}.ref` -> NNNNN).
            let fname_num: Option<u32> = name
                .strip_suffix(".ref")
                .and_then(|stem| stem.parse::<u32>().ok());
            let data = match read_nofollow(&entry.path()) {
                Ok(d) => d,
                Err(_) => continue,
            };
            if let Ok(p) = serde_json::from_slice::<PartRefFile>(&data) {
                // Cross-check filename number == recorded number. A mismatch (or an
                // unparseable filename) is a tampered/foreign ref -> drop it.
                if fname_num != Some(p.part_number) {
                    continue;
                }
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
            // Only `{uuid}/` working dirs are uploads; staged `{uuid}.manifest`
            // files (single-PUT/Complete temps) are not.
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
            // Under current/ the only files are committed manifests; defensively
            // skip anything that is not a manifest or that looks like a staged temp (a
            // temp never lives here, but be robust).
            if !file_name.ends_with(MANIFEST_SUFFIX) || file_name.contains(".tmp.") {
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
/// `IncompleteBody`; anything else stays `Io` (mapped to 500 by the handler).
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

/// Dir mtime as Unix seconds (best-effort; 0 if unavailable).
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

    /// Test helper: set a file's atime+mtime to `when` (for the abandoned-upload
    /// reaper's age test). Uses `libc::utimes` directly (no extra crate).
    fn set_mtime(path: &Path, when: std::time::SystemTime) {
        use std::os::unix::ffi::OsStrExt as _;
        let secs = when
            .duration_since(std::time::UNIX_EPOCH)
            .expect("mtime before epoch")
            .as_secs() as libc::time_t;
        let tv = libc::timeval { tv_sec: secs, tv_usec: 0 };
        let times = [tv, tv];
        let mut c = path.as_os_str().as_bytes().to_vec();
        c.push(0);
        let rc = unsafe { libc::utimes(c.as_ptr() as *const libc::c_char, times.as_ptr()) };
        assert_eq!(rc, 0, "utimes failed for {path:?}");
    }

    /// Assert the LIVE object at `bucket/key` is internally consistent: its manifest
    /// is readable, every referenced blob exists with the recorded size, the sum of
    /// part sizes equals `content_length`, and the manifest ETag matches the actual
    /// blob bytes (single-part: quoted md5 of the one blob; multipart: composite
    /// `md5(concat raw digests)-N`). A torn / cross-paired publish (a manifest from
    /// one writer paired with a blob that was reclaimed/replaced by another) trips
    /// this — that is the load-bearing check the concurrency tests rely on.
    fn assert_object_consistent(fs: &CasStore, bucket: &str, key: &str) -> std::result::Result<(), String> {
        use md5::{Digest, Md5};
        let bk = fs.root().join(bucket);
        let mp = manifest::manifest_path(&bk.join("current"), key);
        let m = manifest::read_manifest(&mp).map_err(|e| format!("manifest unreadable: {e}"))?;
        let mut total = 0u64;
        let mut concat: Vec<u8> = Vec::new();
        for part in &m.parts {
            let bp = blob::blob_path(&bk, &part.blob_id);
            let bytes = std::fs::read(&bp)
                .map_err(|e| format!("blob {} for part {} missing: {e}", part.blob_id, part.part_number))?;
            if bytes.len() as u64 != part.size {
                return Err(format!(
                    "part {} size mismatch: manifest={} actual={}",
                    part.part_number, part.size, bytes.len()
                ));
            }
            let actual_md5 = hex::encode(Md5::digest(&bytes));
            if actual_md5 != part.md5_hex {
                return Err(format!(
                    "part {} md5 mismatch: manifest={} actual={}",
                    part.part_number, part.md5_hex, actual_md5
                ));
            }
            total += part.size;
            concat.extend_from_slice(&hex::decode(&part.md5_hex).map_err(|e| format!("bad md5 hex: {e}"))?);
        }
        if total != m.content_length {
            return Err(format!(
                "content_length mismatch: manifest={} sum(parts)={total}",
                m.content_length
            ));
        }
        let expected_etag = if m.parts.len() == 1 {
            format!("\"{}\"", m.parts[0].md5_hex)
        } else {
            format!("\"{}-{}\"", hex::encode(Md5::digest(&concat)), m.parts.len())
        };
        if expected_etag != m.etag {
            return Err(format!(
                "etag mismatch (cross-pair): manifest.etag={} recomputed-from-blobs={expected_etag}",
                m.etag
            ));
        }
        // GET must stream exactly content_length bytes (no torn reader).
        let got = read_all(fs.get_object(bucket, key, None).map_err(|e| format!("get failed: {e:?}"))?.body);
        if got.len() as u64 != m.content_length {
            return Err(format!(
                "GET length mismatch: got={} manifest={}",
                got.len(),
                m.content_length
            ));
        }
        Ok(())
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

    // ---- delete_bucket coverage (items #2 + #3) ----

    #[test]
    fn delete_bucket_empty_succeeds() {
        let (dir, fs) = store();
        let bk = dir.path().join("bkt");
        // Freshly-created bucket has only the four infra dirs -> empty -> Ok.
        fs.delete_bucket("bkt").unwrap();
        assert!(!bk.exists(), "bucket dir should be removed");
        // And it is gone from HeadBucket / ListBuckets.
        assert!(matches!(
            fs.head_bucket("bkt").unwrap_err(),
            StorageError::BucketNotFound
        ));
    }

    #[test]
    fn delete_bucket_with_top_level_object_is_not_empty() {
        // LOAD-BEARING: a bucket with a top-level object must be BucketNotEmpty. If a
        // regression dropped the emptiness walk (and just `remove_dir_all`'d), this
        // would WRONGLY succeed and silently destroy the object.
        let (dir, fs) = store();
        let bk = dir.path().join("bkt");
        fs.put_object("bkt", "top.txt", &b"data"[..], "", BTreeMap::new())
            .unwrap();
        assert!(matches!(
            fs.delete_bucket("bkt").unwrap_err(),
            StorageError::BucketNotEmpty
        ));
        // The bucket and its object are untouched.
        assert!(bk.exists());
        assert_eq!(read_all(fs.get_object("bkt", "top.txt", None).unwrap().body), b"data");
    }

    #[test]
    fn delete_bucket_with_nested_object_is_not_empty() {
        // LOAD-BEARING: a NESTED object (`a/b/c`) lives several dirs deep under
        // current/; the emptiness check must RECURSE (walk_dir_files) to find it. A
        // shallow-only check would miss it and wrongly delete the bucket.
        let (dir, fs) = store();
        let bk = dir.path().join("bkt");
        fs.put_object("bkt", "a/b/c", &b"nested"[..], "", BTreeMap::new())
            .unwrap();
        assert!(matches!(
            fs.delete_bucket("bkt").unwrap_err(),
            StorageError::BucketNotEmpty
        ));
        assert!(bk.exists());
        assert_eq!(read_all(fs.get_object("bkt", "a/b/c", None).unwrap().body), b"nested");
    }

    #[test]
    fn delete_bucket_absent_is_not_found() {
        let (_dir, fs) = store();
        assert!(matches!(
            fs.delete_bucket("no-such-bucket").unwrap_err(),
            StorageError::BucketNotFound
        ));
    }

    #[test]
    fn delete_bucket_symlinked_dir_is_not_found_and_target_untouched() {
        // LOAD-BEARING (symlink containment): a `data-dir/{name}` entry that is a
        // SYMLINK to an external directory must be rejected as BucketNotFound — never
        // followed — and the external target must be untouched (no remove_dir_all
        // traversal through the link). Relies on head_bucket's symlink_metadata check.
        let dir = tempfile::tempdir().unwrap();
        let fs = CasStore::new(dir.path());

        // A real external dir OUTSIDE the data root, with a file inside.
        let external = tempfile::tempdir().unwrap();
        std::fs::write(external.path().join("secret"), b"keep me").unwrap();

        // Plant a symlink inside the data root with a bucket-like name pointing at it.
        let link = dir.path().join("evil-bucket");
        std::os::unix::fs::symlink(external.path(), &link).unwrap();

        match fs.delete_bucket("evil-bucket") {
            Err(StorageError::BucketNotFound) => {}
            other => panic!("expected BucketNotFound for symlinked bucket dir, got {other:?}"),
        }
        // The symlink and the external target+contents are intact.
        assert!(link.symlink_metadata().unwrap().file_type().is_symlink());
        assert_eq!(std::fs::read(external.path().join("secret")).unwrap(), b"keep me");
    }

    #[test]
    fn delete_bucket_blocks_on_in_flight_multipart_then_allows_after_abort() {
        // LOAD-BEARING (item #3, S3 fidelity): a bucket with an in-flight multipart
        // upload is BucketNotEmpty. After the upload is aborted, delete succeeds. If
        // the in-flight check were dropped, DeleteBucket would tear down the live
        // upload (and its part blobs) — exactly what S3 forbids.
        let (dir, fs) = store();
        let bk = dir.path().join("bkt");
        let upload_id = fs
            .create_multipart_upload("bkt", "big.bin", "", BTreeMap::new())
            .unwrap();
        // Upload a part so the working dir is non-trivially live.
        fs.upload_part("bkt", "big.bin", &upload_id, 1, &vec![7u8; 1024][..])
            .unwrap();

        assert!(matches!(
            fs.delete_bucket("bkt").unwrap_err(),
            StorageError::BucketNotEmpty
        ));
        assert!(bk.exists());

        // Abort the upload -> bucket is now empty -> delete succeeds.
        fs.abort_multipart_upload("bkt", "big.bin", &upload_id).unwrap();
        fs.delete_bucket("bkt").unwrap();
        assert!(!bk.exists());
    }

    #[test]
    fn delete_bucket_ignores_staged_manifest_temps() {
        // A staged single-PUT/Complete temp is an `arriving/{uuid}.manifest` FILE, not
        // an upload dir; it must NOT block DeleteBucket (it is crash debris, not a live
        // object/upload). Simulate one via a crash-in-publish, then delete.
        let (dir, fs) = store();
        let bk = dir.path().join("bkt");
        set_fault(Some(FaultPoint::BeforeJournal));
        let _ = fs.put_object("bkt", "k", &b"orphan attempt"[..], "", BTreeMap::new());
        set_fault(None);
        // An orphan staged manifest is present, but no live object/upload.
        assert!(!list_dir(&bk.join("arriving")).is_empty());
        fs.delete_bucket("bkt").unwrap();
        assert!(!bk.exists());
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
    fn read_path_rejects_symlinked_manifest_and_lexical_escape() {
        // Item #4 (GET-path perf): the read path no longer runs `canonicalize`, but
        // symlink-containment MUST still hold via (1) lexical checks and (2) O_NOFOLLOW
        // on the manifest open. This test plants a SYMLINKED manifest leaf pointing at
        // an external "manifest" that, if followed, would let GET stream a foreign blob
        // — and asserts GET does NOT follow it. It also asserts the lexical check still
        // rejects a `..` escape on the read path.
        //
        // Mutation evidence: remove O_NOFOLLOW from `read_manifest`'s open and this
        // test FAILS (GET would read the symlinked external manifest and serve it).
        let dir = tempfile::tempdir().unwrap();
        let fs = CasStore::new(dir.path());
        fs.create_bucket("bkt").unwrap();
        let bk = dir.path().join("bkt");

        // Stage a real, valid manifest OUTSIDE the bucket's current/ tree so that, if
        // the symlink were followed, GET would happily parse it and try to stream.
        let outside = tempfile::tempdir().unwrap();
        let foreign_blob = blob::write_blob(&bk, &b"FOREIGN BYTES"[..]).unwrap();
        let external_manifest = Manifest {
            key: "evil".into(),
            content_type: "text/plain".into(),
            content_length: foreign_blob.size,
            etag: format!("\"{}\"", foreign_blob.md5_hex),
            last_modified: now_unix(),
            created: now_unix(),
            user_metadata: BTreeMap::new(),
            content_disposition: String::new(),
            content_encoding: String::new(),
            cache_control: String::new(),
            parts: vec![ManifestPartRef {
                part_number: 1,
                blob_id: foreign_blob.blob_id.clone(),
                size: foreign_blob.size,
                md5_hex: foreign_blob.md5_hex.clone(),
            }],
            commit_nonce: Manifest::new_nonce(),
        };
        let ext_path = outside.path().join("external.manifest");
        manifest::write_manifest_temp(&ext_path, &external_manifest, false).unwrap();

        // Plant the live-manifest path for key "evil" as a SYMLINK to that external
        // manifest (current/evil.s3gw-live.meta -> /outside/external.manifest).
        let link = manifest::manifest_path(&bk.join("current"), "evil");
        std::fs::create_dir_all(link.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&ext_path, &link).unwrap();

        // GET must NOT follow the symlinked manifest leaf (O_NOFOLLOW → ELOOP). It
        // surfaces as an error, never the FOREIGN bytes.
        match fs.get_object("bkt", "evil", None) {
            Err(_) => { /* O_NOFOLLOW rejected the symlinked manifest leaf — correct. */ }
            Ok(res) => {
                let got = read_all(res.body);
                assert_ne!(got, b"FOREIGN BYTES", "read followed a symlinked manifest");
            }
        }
        // The external manifest file is intact (GET did not write through the link).
        assert!(ext_path.exists());

        // The lexical read-path check still rejects `..` escapes with no syscall.
        assert!(matches!(
            fs.get_object("bkt", "../escape", None),
            Err(StorageError::PathTraversal)
        ));
        assert!(matches!(
            fs.head_object("bkt", "a/../../etc/passwd").unwrap_err(),
            StorageError::PathTraversal
        ));
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

    // ---- CAS encode v2: `a` + `a.meta/b` coexist; reserved suffix rejected. ----

    #[test]
    fn key_and_a_meta_slash_b_coexist() {
        // LOAD-BEARING (encode v2). Under the OLD `.meta` suffix, PUT `a` then PUT
        // `a.meta/b` collided on `current/a.meta` and raised KeyPrefixConflict/409.
        // Under the reserved-suffix scheme `a` -> current/a.s3gw-live.meta (FILE) and
        // `a.meta/b` -> current/a.meta/b.s3gw-live.meta (raw dir a.meta/) are DISTINCT
        // paths, so BOTH succeed and BOTH round-trip — no error, no overwrite.
        let (_dir, fs) = store();
        fs.put_object("bkt", "a", &b"i am a"[..], "", BTreeMap::new())
            .unwrap();
        fs.put_object("bkt", "a.meta/b", &b"child under a.meta dir"[..], "", BTreeMap::new())
            .unwrap();
        assert_eq!(read_all(fs.get_object("bkt", "a", None).unwrap().body), b"i am a");
        assert_eq!(
            read_all(fs.get_object("bkt", "a.meta/b", None).unwrap().body),
            b"child under a.meta dir"
        );
    }

    #[test]
    fn a_meta_slash_b_then_key_coexist_either_order() {
        // The reverse order also coexists (no KeyPrefixConflict): PUT `a.meta/b`
        // first, then PUT `a`. Both readable.
        let (_dir, fs) = store();
        fs.put_object("bkt", "a.meta/b", &b"child first"[..], "", BTreeMap::new())
            .unwrap();
        fs.put_object("bkt", "a", &b"now a too"[..], "", BTreeMap::new())
            .unwrap();
        assert_eq!(read_all(fs.get_object("bkt", "a", None).unwrap().body), b"now a too");
        assert_eq!(
            read_all(fs.get_object("bkt", "a.meta/b", None).unwrap().body),
            b"child first"
        );
    }

    #[test]
    fn complete_multipart_over_a_meta_prefix_succeeds() {
        // The multipart Complete publish path also coexists: PUT `a.meta/b`, then a
        // multipart Complete targeting key `a` SUCCEEDS (distinct paths), and both
        // objects are readable.
        let (dir, fs) = store();
        let bk = dir.path().join("bkt");
        fs.put_object("bkt", "a.meta/b", &b"child first"[..], "", BTreeMap::new())
            .unwrap();
        let (upload_id, parts, etags) = upload_3_parts(&fs, "bkt", "a");
        let complete: Vec<CompletePart> = (0..3)
            .map(|i| CompletePart { part_number: (i + 1) as i32, etag: etags[i].clone() })
            .collect();
        fs.complete_multipart_upload("bkt", "a", &upload_id, &complete)
            .unwrap();
        // Upload dir consumed by the successful Complete.
        assert!(!bk.join("arriving").join(&upload_id).exists());
        // Both objects intact.
        let mut want = Vec::new();
        for p in &parts {
            want.extend_from_slice(p);
        }
        assert_eq!(md5_hex(&read_all(fs.get_object("bkt", "a", None).unwrap().body)), md5_hex(&want));
        assert_eq!(
            read_all(fs.get_object("bkt", "a.meta/b", None).unwrap().body),
            b"child first"
        );
    }

    #[test]
    fn delete_key_while_a_meta_dir_exists_is_idempotent() {
        // With current/a.meta/ a raw directory (from `a.meta/b`), key `a` simply does
        // not exist (its manifest is current/a.s3gw-live.meta, a FILE that was never
        // written), so DELETE `a` is an idempotent no-op success and must NOT remove
        // the `a.meta/b` child.
        let (_dir, fs) = store();
        fs.put_object("bkt", "a.meta/b", &b"keep me"[..], "", BTreeMap::new())
            .unwrap();
        fs.delete_object("bkt", "a").unwrap();
        assert_eq!(
            read_all(fs.get_object("bkt", "a.meta/b", None).unwrap().body),
            b"keep me"
        );
    }

    #[test]
    fn reserved_manifest_suffix_key_is_rejected() {
        // LOAD-BEARING (reserved suffix). A key with ANY `/`-segment ending in
        // MANIFEST_SUFFIX (`.s3gw-live.meta`) is rejected with 400 InvalidArgument
        // (StorageError::PathTraversal) — leaf OR ancestor segment. This is what
        // makes the key↔path encoding collision-free (it prevents the only residual
        // `K` vs `K.s3gw-live.meta/...` clash). FAIL-WITHOUT-FIX: removing the
        // reserved-suffix check in `validate_object_path` lets these through and a
        // raw dir/file collision (Io/500) or silent clash can occur.
        let (_dir, fs) = store();
        for bad in [
            "report.s3gw-live.meta",        // leaf segment ends in the suffix
            "dir/report.s3gw-live.meta",    // nested leaf
            "a.s3gw-live.meta/b",           // ANCESTOR segment ends in the suffix
            "x/a.s3gw-live.meta/y",         // deep ancestor segment
        ] {
            let err = fs
                .put_object("bkt", bad, &b"x"[..], "", BTreeMap::new())
                .unwrap_err();
            assert!(
                matches!(err, StorageError::PathTraversal),
                "reserved-suffix key {bad:?} must be rejected, got {err:?}"
            );
        }
        // An ordinary `.meta` key is NOT reserved and round-trips fine.
        fs.put_object("bkt", "report.meta", &b"ordinary meta key"[..], "", BTreeMap::new())
            .unwrap();
        assert_eq!(
            read_all(fs.get_object("bkt", "report.meta", None).unwrap().body),
            b"ordinary meta key"
        );
    }

    #[test]
    fn normal_nested_keys_coexist_not_rejected() {
        // Ordinary nested keys all coexist: `a`, `a/b`, `a/b/c` and the `a` + `a/b`
        // pair (their manifest paths never collide).
        let (_dir, fs) = store();
        for k in ["a", "a/b", "a/b/c"] {
            fs.put_object("bkt", k, format!("body-{k}").as_bytes(), "", BTreeMap::new())
                .unwrap();
        }
        for k in ["a", "a/b", "a/b/c"] {
            assert_eq!(
                read_all(fs.get_object("bkt", k, None).unwrap().body),
                format!("body-{k}").as_bytes()
            );
        }
        // Order independence: a/b/c first, then a/b, then a — still all coexist.
        let (_dir2, fs2) = store();
        for k in ["x/y/z", "x/y", "x"] {
            fs2.put_object("bkt", k, format!("v-{k}").as_bytes(), "", BTreeMap::new())
                .unwrap();
        }
        for k in ["x", "x/y", "x/y/z"] {
            assert_eq!(
                read_all(fs2.get_object("bkt", k, None).unwrap().body),
                format!("v-{k}").as_bytes()
            );
        }
        let _ = fs2;
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

    // ---- F: per-key publish-lock LOAD-BEARING concurrency regressions ----

    #[test]
    fn publish_lock_prevents_lost_blob_on_concurrent_overwrite_deterministic() {
        // LOAD-BEARING regression for the per-key WRITE lock around `publish`. It
        // forces the exact interleaving the lock exists to prevent and is
        // DETERMINISTIC (Condvar handshakes, no sleeps).
        //
        // CAS makes a TORN object (manifest-of-A + body-of-B) impossible by
        // construction — blobs are immutable + content-addressed and a version is
        // published by a single atomic rename, so the live manifest always names
        // blobs that exist and match it. What the lock DOES protect on concurrent
        // OVERWRITES of one key is the journal/reclaim bookkeeping: each publish reads
        // the CURRENT manifest to journal the OLD version's blobs for reclaim. If two
        // overwrites race, the loser's blob is never journaled by anyone and LEAKS
        // (an orphan blob that no live manifest references and no journal reclaims) —
        // a real correctness defect (unbounded space leak; the fallback GC is opt-in).
        //
        // Interleaving (seed V0=blobX already live):
        //   A: write blobA; stage manifest-A(blobA); read old V0 -> journal [blobX].
        //      PARK here (pre-commit-rename) holding the per-key lock.
        //   B: write blobB; then take the per-key lock.
        //      - real lock  => B BLOCKS on lock_key (note_lock_contention). Release A:
        //        A commits + reclaims blobX, frees lock. B then reads old = manifest-A,
        //        journals [blobA], commits manifest-B(blobB), RECLAIMS blobA. Final:
        //        exactly ONE blob (blobB). No leak.
        //      - lock gone  => B reaches the window itself (second_window). Join B
        //        first: B reads old V0, journals [blobX], commits manifest-B, reclaims
        //        blobX. Release A: A commits manifest-A on top, reclaims blobX (gone).
        //        Final: manifest-A(blobA) live, but blobB is ORPHANED -> TWO blobs.
        //
        // THE LOAD-BEARING ASSERTION: exactly one blob remains. With the lock => 1
        // (loser's blob reclaimed); without => 2 (loser's blob leaked).
        //
        // Fail-without-fix evidence: neuter `lock_key` to hand out a guard on a fresh
        // throwaway `RwLock` each call (no mutual exclusion) and this test FAILS with
        // "blob leaked" (count==2); the real shared Arc<Vec<RwLock>> makes it PASS.
        use std::sync::Arc;
        let _serial = publish_pause::serialize_test(); // single global hook slot.
        let dir = tempfile::tempdir().unwrap();
        let fs = Arc::new(CasStore::with_fsync(dir.path(), false));
        fs.create_bucket("bkt").unwrap();
        let bk = dir.path().join("bkt");
        let key = "hot.key";

        // Seed the live version V0 so each overwrite journals an OLD blob.
        fs.put_object("bkt", key, &b"v0-seed"[..], "text/v0", BTreeMap::new())
            .unwrap();
        assert_eq!(count_blobs(&bk), 1);

        // Distinctive, different-length payloads so the survivor is unambiguous.
        let data_a = vec![0xAAu8; 8192];
        let data_b = vec![0xBBu8; 4096 + 7];

        let hook = publish_pause::PauseHook::arm(&format!("bkt/{key}"));

        let fa = Arc::clone(&fs);
        let da = data_a.clone();
        let a = std::thread::spawn(move || fa.put_object("bkt", key, &da[..], "text/a", BTreeMap::new()));

        // Wait until A is parked in the critical window (manifest-A staged+journaled,
        // not yet committed) while holding the per-key lock.
        hook.wait_window_arrived();

        let fb = Arc::clone(&fs);
        let db = data_b.clone();
        let b = std::thread::spawn(move || fb.put_object("bkt", key, &db[..], "text/b", BTreeMap::new()));

        let b_blocked_on_lock = hook.wait_b_disposition();
        let (ra, rb) = if b_blocked_on_lock {
            hook.release();
            (a.join().unwrap(), b.join().unwrap())
        } else {
            // Lock neutered: B raced into the window. Join B first (it fully published
            // + reclaimed blobX), THEN release A so A commits manifest-A on top —
            // leaking blobB.
            let rb = b.join().unwrap();
            hook.release();
            (a.join().unwrap(), rb)
        };
        publish_pause::PauseHook::disarm();
        assert!(ra.is_ok(), "writer A failed: {ra:?}");
        assert!(rb.is_ok(), "writer B failed: {rb:?}");

        // The published object is always internally consistent (CAS guarantees this
        // regardless of the lock) and is EXACTLY one writer's object.
        assert_object_consistent(&fs, "bkt", key)
            .unwrap_or_else(|e| panic!("published object inconsistent: {e}"));
        use md5::{Digest, Md5};
        let head = fs.head_object("bkt", key).unwrap();
        let body = read_all(fs.get_object("bkt", key, None).unwrap().body);
        let etag_a = format!("\"{}\"", hex::encode(Md5::digest(&data_a)));
        let etag_b = format!("\"{}\"", hex::encode(Md5::digest(&data_b)));
        let is_a = body == data_a && head.etag == etag_a && head.content_type == "text/a";
        let is_b = body == data_b && head.etag == etag_b && head.content_type == "text/b";
        assert!(is_a || is_b, "survivor is not a clean A or B: etag={}", head.etag);

        // LOAD-BEARING: no orphan blob. Exactly the survivor's single blob remains.
        // Without the per-key lock the loser's blob is never journaled -> it leaks and
        // this is 2.
        assert_eq!(
            count_blobs(&bk),
            1,
            "the per-key publish lock did not serialize the overwrites — the loser's \
             blob leaked (orphan); expected exactly the survivor's 1 blob"
        );
        // And no journal is left dangling.
        assert!(list_dir(&bk.join("deleted")).is_empty());
    }

    #[test]
    fn publish_lock_serializes_put_vs_delete_deterministic() {
        // LOAD-BEARING: a PUT (overwrite) and a DELETE of the SAME key must serialize
        // on the per-key lock. We park a PUT (writer A) in the publish window (holding
        // the lock), then fire a concurrent DELETE (writer B), DETERMINISTICALLY
        // (Condvar handshakes, no sleeps).
        //
        // Interleaving (seed V0=blobX already live):
        //   A: write blobA; stage manifest-A(blobA); read old V0 -> journal [blobX].
        //      PARK (pre-commit-rename) holding the per-key lock.
        //   B (DELETE): take the per-key lock.
        //     - real lock => B BLOCKS on lock_key. Release A: A commits manifest-A,
        //       reclaims blobX. B then reads the LIVE manifest-A, journals [blobA],
        //       removes the manifest, reclaims blobA. Final: object ABSENT, 0 blobs.
        //     - lock gone => B reaches the window region itself; join B FIRST: B reads
        //       V0, journals [blobX], REMOVES the manifest, reclaims blobX. Release A:
        //       A's commit-rename RE-CREATES the manifest (manifest-A) on top of the
        //       just-deleted key. Final: object PRESENT — the client's DELETE was LOST.
        //
        // THE LOAD-BEARING ASSERTION: under the real lock the deterministic outcome is
        // ABSENT (DELETE always runs after the PUT commits). Without the lock the
        // DELETE is lost and the object is PRESENT — so asserting absence FAILS.
        //
        // Fail-without-fix evidence: neuter `lock_key` (throwaway RwLock per call) and
        // this test FAILS with "DELETE was lost"; the real shared lock makes it PASS.
        use std::sync::Arc;
        let _serial = publish_pause::serialize_test(); // single global hook slot.
        let dir = tempfile::tempdir().unwrap();
        let fs = Arc::new(CasStore::with_fsync(dir.path(), false));
        fs.create_bucket("bkt").unwrap();
        let key = "hot.key";
        let bk = dir.path().join("bkt");

        // Seed an initial version so the overwriting PUT's publish() writes a journal
        // listing the OLD blob — exactly the blob a racing DELETE would also target.
        fs.put_object("bkt", key, &b"v0-original"[..], "text/v0", BTreeMap::new())
            .unwrap();

        let data_a = vec![0xCCu8; 5000];
        let hook = publish_pause::PauseHook::arm(&format!("bkt/{key}"));

        let fa = Arc::clone(&fs);
        let da = data_a.clone();
        let a = std::thread::spawn(move || fa.put_object("bkt", key, &da[..], "text/a", BTreeMap::new()));
        hook.wait_window_arrived();

        let fb = Arc::clone(&fs);
        let b = std::thread::spawn(move || fb.delete_object("bkt", key));

        // A DELETE never reaches the window pause, so with the lock MISSING there is no
        // contention signal — bound the wait so a neutered lock fails cleanly (None)
        // instead of hanging. `Some(true)` = B blocked on the real lock.
        let (ra, rb) = match hook.wait_b_disposition_timeout(std::time::Duration::from_secs(5)) {
            Some(true) => {
                // Real lock: B is parked on lock_key. Release A; it commits + frees the
                // lock, then B deletes the now-live object.
                hook.release();
                (a.join().unwrap(), b.join().unwrap())
            }
            _ => {
                // Lock missing/neutered (or, defensively, a second_window): B raced the
                // DELETE ahead unsynchronized. Join B first (it removed the manifest),
                // THEN release A so its commit re-creates the manifest — the LOST delete.
                let rb = b.join().unwrap();
                hook.release();
                (a.join().unwrap(), rb)
            }
        };
        publish_pause::PauseHook::disarm();
        assert!(ra.is_ok(), "PUT failed: {ra:?}");
        assert!(rb.is_ok(), "DELETE failed: {rb:?}");

        // Deterministic under the real lock: DELETE runs AFTER the PUT commits, so the
        // object is ABSENT with no residual blobs and no dangling journal. If the lock
        // is gone, the DELETE is lost (object PRESENT) and this fails.
        match fs.head_object("bkt", key) {
            Err(StorageError::ObjectNotFound) => {}
            Ok(_) => panic!(
                "PUT-vs-DELETE: the DELETE was LOST (object still present) — the \
                 per-key lock did not serialize the PUT commit against the DELETE"
            ),
            Err(other) => panic!("unexpected head_object error: {other:?}"),
        }
        assert_eq!(count_blobs(&bk), 0, "serialized DELETE must leave no blobs");
        assert!(list_dir(&bk.join("deleted")).is_empty(), "no dangling journal");
    }

    #[test]
    fn upload_part_lock_serializes_against_complete_deterministic() {
        // LOAD-BEARING: `upload_part` takes the per-key WRITE lock around its
        // read-prev-ref + ref-swap + blob-reclaim, keyed by the upload's STORED
        // bucket/key — the SAME key `complete_multipart_upload` holds across
        // read_part_refs -> manifest-build -> publish. This serializes a same-key
        // re-UploadPart's ref-swap (which RECLAIMS the superseded part blob) against
        // Complete's manifest build/commit. Without it, the re-UploadPart can reclaim
        // a blob the in-flight Complete already captured into its manifest, committing
        // a manifest that references a just-deleted blob (a torn multipart object).
        //
        // Interleaving (one upload of key K; part 1 = blob B1, part 2 = blob Bp2):
        //   A (Complete[part1=etagB1, part2=etagBp2]): take per-key lock; read_part_refs
        //      -> manifest references B1+Bp2; publish stages+journals the manifest, then
        //      PARKS at the publish critical window (pre-commit-rename) STILL HOLDING
        //      the lock.
        //   B (UploadPart K, part 1, new bytes): write blob B2 (lock-free), then take
        //      the per-key lock around the ref-swap + reclaim.
        //     - real lock => B BLOCKS on lock_key (note_lock_contention fires). Release
        //       A: A commits manifest(B1+Bp2) and removes the upload dir, frees the
        //       lock. B then resumes but the upload dir/ref is GONE -> it never reclaims
        //       B1 (it errors out and rolls back its own B2). The committed manifest's
        //       B1 is intact; GET reassembles the correct bytes.
        //     - lock gone => B does NOT block (it never calls lock_key); concurrently
        //       with A parked in the window it reads the prev ref (B1 still present),
        //       swaps in B2, and RECLAIMS B1. Release A: A commits manifest(B1+Bp2) on
        //       top of a DELETED B1 -> torn object (GET errors / blob missing).
        //
        // THE LOAD-BEARING ASSERTION: B blocks on the per-key lock, and the completed
        // object is internally consistent — its parts reference intact blobs B1+Bp2,
        // GET returns exactly the concatenated part bytes, and count_blobs shows no
        // missing blob.
        //
        // Fail-without-fix evidence: remove the `lock_key` acquisition from
        // `upload_part` and this test FAILS — B never blocks on the lock (the
        // disposition wait TIMES OUT, asserted as a clean failure) and, having
        // reclaimed B1 mid-Complete, the committed manifest references a missing blob
        // (assert_object_consistent / GET fail). With the lock it PASSES. Uses the
        // deterministic Condvar handshake (no sleeps); stable across repeated runs.
        use std::sync::Arc;
        let _serial = publish_pause::serialize_test(); // single global hook slot.
        let dir = tempfile::tempdir().unwrap();
        let fs = Arc::new(CasStore::with_fsync(dir.path(), false));
        fs.create_bucket("bkt").unwrap();
        let bk = dir.path().join("bkt");
        let key = "hot.mpu";

        // Create the upload and upload two parts. Part 1 -> blob B1 is the blob
        // Complete captures into its manifest and a racing re-UploadPart would reclaim.
        // A second part keeps the completed manifest multipart (composite ETag), which
        // is what `assert_object_consistent` validates.
        let upload_id = fs
            .create_multipart_upload("bkt", key, "text/mpu", BTreeMap::new())
            .unwrap();
        let part1 = vec![0xA1u8; 9000];
        let part2 = vec![0xC3u8; 5000 + 3];
        let etag1 = fs.upload_part("bkt", key, &upload_id, 1, &part1[..]).unwrap();
        let etag2 = fs.upload_part("bkt", key, &upload_id, 2, &part2[..]).unwrap();
        assert_eq!(count_blobs(&bk), 2, "exactly B1+Bp2 after the two part uploads");

        // Distinct re-upload bytes (different length) for the racing UploadPart -> B2.
        let part1b = vec![0xB2u8; 4000 + 5];

        let hook = publish_pause::PauseHook::arm(&format!("bkt/{key}"));

        // Writer A: Complete. It parks in the publish window holding the per-key lock,
        // with a staged manifest referencing B1+Bp2.
        let fa = Arc::clone(&fs);
        let uid_a = upload_id.clone();
        let a = std::thread::spawn(move || {
            fa.complete_multipart_upload(
                "bkt",
                key,
                &uid_a,
                &[
                    CompletePart { part_number: 1, etag: etag1 },
                    CompletePart { part_number: 2, etag: etag2 },
                ],
            )
        });
        // Wait until A is parked in the critical window (manifest staged, lock held).
        hook.wait_window_arrived();

        // Writer B: re-UploadPart of part 1 with new bytes. With the lock it blocks on
        // lock_key; without it, it reclaims B1 lock-free.
        let fb = Arc::clone(&fs);
        let uid_b = upload_id.clone();
        let p1b = part1b.clone();
        let b = std::thread::spawn(move || {
            fb.upload_part("bkt", key, &uid_b, 1, &p1b[..])
        });

        // A blocked UploadPart fires note_lock_contention; a lock-free one produces no
        // signal (UploadPart never reaches the publish window), so bound the wait — a
        // timeout (None) means the lock is MISSING and surfaces as a clean failure
        // instead of a hang. `Some(true)` = B blocked on the real lock.
        let disposition = hook.wait_b_disposition_timeout(std::time::Duration::from_secs(5));

        let (ra, rb) = match disposition {
            Some(true) => {
                // Real lock: B is parked on lock_key. Release A; it commits manifest(B1)
                // and removes the upload dir, then B resumes (finds the dir gone).
                hook.release();
                (a.join().unwrap(), b.join().unwrap())
            }
            _ => {
                // Lock missing/neutered: B raced the ref-swap + B1 reclaim ahead
                // unsynchronized. Join B first (it reclaimed B1), THEN release A so its
                // commit lands a manifest referencing the now-deleted B1.
                let rb = b.join().unwrap();
                hook.release();
                (a.join().unwrap(), rb)
            }
        };
        publish_pause::PauseHook::disarm();

        // LOAD-BEARING #1: the re-UploadPart must have BLOCKED on the per-key lock.
        // Without `upload_part`'s lock_key this is None (timeout) and fails here.
        assert_eq!(
            disposition,
            Some(true),
            "the racing UploadPart did NOT block on the per-key lock — `upload_part` \
             is not serializing its ref-swap/reclaim against the in-flight Complete"
        );

        // Complete must have succeeded.
        assert!(ra.is_ok(), "Complete failed: {ra:?}");
        // B, resuming after the upload dir was removed by Complete, errors out and rolls
        // back its own B2 — it must NOT have reclaimed B1.
        assert!(
            rb.is_err(),
            "re-UploadPart unexpectedly succeeded after the upload was completed: {rb:?}"
        );

        // LOAD-BEARING #2: the committed object is internally consistent — its manifest
        // references only intact, existing blobs (no reference to a reclaimed B1). With
        // the lock removed, B reclaimed B1 mid-Complete and this trips ("blob missing").
        assert_object_consistent(&fs, "bkt", key)
            .unwrap_or_else(|e| panic!("completed multipart object inconsistent: {e}"));

        // GET reassembles exactly part1 ++ part2 (the intact B1+Bp2), and the composite
        // multipart ETag matches.
        let head = fs.head_object("bkt", key).unwrap();
        assert_eq!(head.content_type, "text/mpu");
        let body = read_all(fs.get_object("bkt", key, None).unwrap().body);
        let mut want = part1.clone();
        want.extend_from_slice(&part2);
        assert_eq!(body, want, "GET must return the intact part1++part2 (B1+Bp2) bytes");
        use md5::{Digest, Md5};
        let mut concat = Md5::digest(&part1).to_vec();
        concat.extend_from_slice(&Md5::digest(&part2));
        let composite = format!("\"{}-2\"", hex::encode(Md5::digest(&concat)));
        assert_eq!(head.etag, composite, "composite multipart ETag");

        // Exactly the committed manifest's two blobs (B1+Bp2) remain; B2 was rolled
        // back, and no blob is missing/dangling. Without the lock B2 leaks and/or B1 is
        // gone -> not 2.
        assert_eq!(
            count_blobs(&bk),
            2,
            "exactly the committed manifest's two blobs (B1+Bp2) must remain; B2 rolled back"
        );
        assert!(list_dir(&bk.join("deleted")).is_empty(), "no dangling journal");
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

    // ---- D2: recover() crash-recovery sweep (REDESIGN §6) ----

    #[test]
    fn recover_removes_orphan_arriving_manifest_keeps_live_object() {
        // (i) An orphaned arriving/{uuid}.manifest + the blob it would have referenced.
        // recover() removes the staged manifest; the live object is untouched. The
        // orphan blob is left for gc_orphan_blobs (recover does NOT do the full GC).
        let (dir, fs) = store();
        let bk = dir.path().join("bkt");
        fs.put_object("bkt", "live", &b"the live object"[..], "", BTreeMap::new())
            .unwrap();
        let live_blob = {
            let m = manifest::read_manifest(&manifest::manifest_path(&bk.join("current"), "live")).unwrap();
            m.parts[0].blob_id.clone()
        };

        // Crash a PUT to a DIFFERENT key after staging arriving, before commit (this
        // leaves an orphan arriving manifest AND its new blob — the pre-commit
        // rollback deletes the blob, so to model a TRULY-leaked blob too we write one
        // by hand and reference it from a hand-staged orphan manifest).
        set_fault(Some(FaultPoint::BeforeJournal));
        let _ = fs.put_object("bkt", "doomed", &b"never commits"[..], "", BTreeMap::new());
        set_fault(None);
        let arriving = list_dir(&bk.join("arriving"));
        assert_eq!(arriving.len(), 1, "one orphan arriving manifest: {arriving:?}");

        // Also leave a leaked blob that a lost staged manifest would have owned.
        let leaked = blob::write_blob(&bk, &b"leaked by a lost arriving manifest"[..]).unwrap();
        assert!(blob::blob_path(&bk, &leaked.blob_id).exists());

        let stats = fs.recover().unwrap();
        assert_eq!(stats.arriving_manifests_removed, 1);
        // The staged manifest is gone; the live object is intact.
        assert!(list_dir(&bk.join("arriving")).is_empty());
        assert!(blob::blob_path(&bk, &live_blob).exists());
        assert_eq!(read_all(fs.get_object("bkt", "live", None).unwrap().body), b"the live object");
        // recover() does NOT run the full GC, so the leaked blob is still present.
        assert!(blob::blob_path(&bk, &leaked.blob_id).exists());

        // (iv) Idempotent: a second recover() changes nothing and does not error.
        let stats2 = fs.recover().unwrap();
        assert_eq!(stats2.arriving_manifests_removed, 0);
        assert_eq!(stats2.journals_processed, 0);
        assert!(blob::blob_path(&bk, &live_blob).exists());
    }

    #[test]
    fn recover_finishes_committed_swap_journal_reclaims_old_blobs() {
        // (ii) A deleted/{uuid}.journal from a COMMITTED swap (post-commit crash via
        // BeforeReclaim): recover() finishes the reclaim (nonce matches the live
        // manifest), removes the journal, and the live object's blobs are untouched.
        let (dir, fs) = store();
        let bk = dir.path().join("bkt");
        fs.put_object("bkt", "k", &b"v1-bytes-old"[..], "", BTreeMap::new())
            .unwrap();
        let v1_blob = {
            let m = manifest::read_manifest(&manifest::manifest_path(&bk.join("current"), "k")).unwrap();
            m.parts[0].blob_id.clone()
        };
        // Post-commit crash: new version live, old blob + journal left behind.
        set_fault(Some(FaultPoint::BeforeReclaim));
        fs.put_object("bkt", "k", &b"v2-bytes-new-and-longer"[..], "", BTreeMap::new())
            .unwrap();
        set_fault(None);
        let v2_blob = {
            let m = manifest::read_manifest(&manifest::manifest_path(&bk.join("current"), "k")).unwrap();
            m.parts[0].blob_id.clone()
        };
        assert_eq!(list_dir(&bk.join("deleted")).len(), 1, "journal present pre-recovery");
        assert_eq!(count_blobs(&bk), 2, "v1 + v2 both present pre-recovery");

        let stats = fs.recover().unwrap();
        assert_eq!(stats.journals_processed, 1);
        assert_eq!(stats.journal_blobs_reclaimed, 1, "v1 (old) blob reclaimed");
        // Journal gone; v1 reclaimed; v2 (the live object's blob) untouched.
        assert!(list_dir(&bk.join("deleted")).is_empty());
        assert!(!blob::blob_path(&bk, &v1_blob).exists());
        assert!(blob::blob_path(&bk, &v2_blob).exists());
        assert_eq!(read_all(fs.get_object("bkt", "k", None).unwrap().body), b"v2-bytes-new-and-longer");

        // (iv) Idempotent re-run.
        let stats2 = fs.recover().unwrap();
        assert_eq!(stats2.journals_processed, 0);
        assert_eq!(stats2.journal_blobs_reclaimed, 0);
        assert!(blob::blob_path(&bk, &v2_blob).exists());
    }

    #[test]
    fn recover_nonce_mismatch_journal_keeps_live_blobs() {
        // (iii) A publish journal whose commit_nonce does NOT match the live manifest
        // (the described commit never landed). recover() must NOT delete those blobs
        // (they are still-live-old) — only remove the journal.
        let (dir, fs) = store();
        let bk = dir.path().join("bkt");
        fs.put_object("bkt", "k", &b"still the live version"[..], "", BTreeMap::new())
            .unwrap();
        let live_blob = {
            let m = manifest::read_manifest(&manifest::manifest_path(&bk.join("current"), "k")).unwrap();
            m.parts[0].blob_id.clone()
        };
        // Hand-craft a stale publish journal listing the LIVE blob with a wrong nonce.
        let jpath = bk.join("deleted").join(format!("{}.journal", Uuid::new_v4()));
        fs.write_journal(
            &jpath,
            &Journal {
                mode: JournalMode::Publish,
                supersedes_key: "k".into(),
                commit_nonce: "nonce-that-never-committed".into(),
                expected_new_etag: "\"x\"".into(),
                blobs: vec![live_blob.clone()],
            },
        )
        .unwrap();

        let stats = fs.recover().unwrap();
        assert_eq!(stats.journals_processed, 1);
        assert_eq!(stats.journal_blobs_reclaimed, 0, "must NOT delete a still-live blob");
        assert!(list_dir(&bk.join("deleted")).is_empty(), "journal removed");
        // Live blob and object intact.
        assert!(blob::blob_path(&bk, &live_blob).exists());
        assert_eq!(read_all(fs.get_object("bkt", "k", None).unwrap().body), b"still the live version");

        // (iv) Idempotent.
        let stats2 = fs.recover().unwrap();
        assert_eq!(stats2, RecoveryStats { buckets: 1, ..Default::default() });
    }

    #[test]
    fn recover_keeps_in_progress_multipart_upload_dir() {
        // (v) recover() must NOT delete a valid in-progress multipart upload working
        // dir (the retention rule) — its parts survive a restart and Complete still
        // works afterward.
        let (dir, fs) = store();
        let bk = dir.path().join("bkt");
        let key = "mp/in-flight";
        let (upload_id, parts, etags) = upload_3_parts(&fs, "bkt", key);
        assert!(bk.join("arriving").join(&upload_id).exists());
        assert_eq!(count_blobs(&bk), 3);

        let stats = fs.recover().unwrap();
        // The upload dir is a {uuid}/ dir, NOT a staged {uuid}.manifest -> NOT removed.
        assert_eq!(stats.arriving_manifests_removed, 0);
        assert!(
            bk.join("arriving").join(&upload_id).exists(),
            "in-progress multipart upload dir must survive recover()"
        );
        assert_eq!(count_blobs(&bk), 3, "part blobs survive recover()");
        assert_eq!(fs.list_parts("bkt", key, &upload_id).unwrap().len(), 3);

        // Complete still works after recovery.
        let complete: Vec<CompletePart> = (0..3)
            .map(|i| CompletePart { part_number: (i + 1) as i32, etag: etags[i].clone() })
            .collect();
        fs.complete_multipart_upload("bkt", key, &upload_id, &complete).unwrap();
        let mut want = Vec::new();
        for p in &parts {
            want.extend_from_slice(p);
        }
        let got = read_all(fs.get_object("bkt", key, None).unwrap().body);
        assert_eq!(md5_hex(&got), md5_hex(&want));
    }

    #[test]
    fn gc_abandoned_uploads_reaps_old_keeps_young() {
        // Item #5 (abandoned-upload sweep): an upload older than max_age is reaped
        // (dir + part blobs gone); a YOUNGER upload is strictly untouched. We age one
        // upload by back-dating its upload.json mtime, leave another fresh, then sweep
        // with a 1-hour threshold.
        use std::time::{Duration, SystemTime};
        let (dir, fs) = store();
        let bk = dir.path().join("bkt");

        // OLD upload: create + one part, then back-date its upload.json by 2 hours.
        let old_id = fs.create_multipart_upload("bkt", "old/obj", "", BTreeMap::new()).unwrap();
        fs.upload_part("bkt", "old/obj", &old_id, 1, &vec![1u8; 2048][..]).unwrap();
        let old_json = bk.join("arriving").join(&old_id).join("upload.json");
        set_mtime(&old_json, SystemTime::now() - Duration::from_secs(2 * 3600));

        // YOUNG upload: just created (fresh mtime).
        let young_id = fs.create_multipart_upload("bkt", "young/obj", "", BTreeMap::new()).unwrap();
        fs.upload_part("bkt", "young/obj", &young_id, 1, &vec![2u8; 1024][..]).unwrap();

        assert_eq!(count_blobs(&bk), 2, "two part blobs before sweep");

        // Sweep with a 1-hour threshold: only the old upload qualifies.
        let reaped = fs.gc_abandoned_uploads(Duration::from_secs(3600)).unwrap();
        assert_eq!(reaped, 1, "exactly the old upload should be reaped");

        // OLD upload dir + its part blob are gone.
        assert!(!bk.join("arriving").join(&old_id).exists());
        // YOUNG upload is fully intact and still usable.
        assert!(bk.join("arriving").join(&young_id).exists());
        assert_eq!(fs.list_parts("bkt", "young/obj", &young_id).unwrap().len(), 1);
        assert_eq!(count_blobs(&bk), 1, "only the young upload's part blob remains");

        // A second sweep is a no-op (idempotent; the young one is still too fresh).
        assert_eq!(fs.gc_abandoned_uploads(Duration::from_secs(3600)).unwrap(), 0);
    }

    #[test]
    fn gc_abandoned_uploads_off_by_default_via_recover() {
        // recover() must NOT reap in-flight uploads (the keep-in-flight rule): the
        // reaper is a SEPARATE opt-in op. An old upload survives recover().
        use std::time::{Duration, SystemTime};
        let (dir, fs) = store();
        let bk = dir.path().join("bkt");
        let id = fs.create_multipart_upload("bkt", "k", "", BTreeMap::new()).unwrap();
        fs.upload_part("bkt", "k", &id, 1, &vec![9u8; 512][..]).unwrap();
        let json = bk.join("arriving").join(&id).join("upload.json");
        set_mtime(&json, SystemTime::now() - Duration::from_secs(10 * 86_400));

        fs.recover().unwrap();
        assert!(bk.join("arriving").join(&id).exists(), "recover() must keep in-flight uploads");

        // The explicit reaper does reap it.
        assert_eq!(fs.gc_abandoned_uploads(Duration::from_secs(86_400)).unwrap(), 1);
        assert!(!bk.join("arriving").join(&id).exists());
    }

    #[test]
    fn gc_orphan_blobs_deletes_unreferenced_keeps_referenced() {
        // (vi) gc_orphan_blobs deletes a truly-unreferenced blob but KEEPS every blob
        // referenced by a live manifest AND by an in-flight multipart upload.
        let (dir, fs) = store();
        let bk = dir.path().join("bkt");
        // A live single-part object.
        fs.put_object("bkt", "live", &b"referenced by a live manifest"[..], "", BTreeMap::new())
            .unwrap();
        let live_blob = {
            let m = manifest::read_manifest(&manifest::manifest_path(&bk.join("current"), "live")).unwrap();
            m.parts[0].blob_id.clone()
        };
        // An in-flight multipart upload (its parts must NOT be GC'd).
        let (upload_id, _parts, _etags) = upload_3_parts(&fs, "bkt", "mp/keep");
        let kept_part_ids: Vec<String> = {
            let refs = CasStore::read_part_refs(&bk.join("arriving").join(&upload_id)).unwrap();
            refs.values().map(|r| r.blob_id.clone()).collect()
        };
        assert_eq!(kept_part_ids.len(), 3);

        // A truly-orphaned blob (referenced by nothing — a lost-journal leak).
        let orphan = blob::write_blob(&bk, &b"orphan from a lost journal"[..]).unwrap();
        // Pre-GC: 1 (live) + 3 (upload parts) + 1 (orphan) = 5 blobs.
        assert_eq!(count_blobs(&bk), 5);

        let reclaimed = fs.gc_orphan_blobs("bkt").unwrap();
        assert_eq!(reclaimed, 1, "exactly the one orphan blob is reclaimed");
        assert!(!blob::blob_path(&bk, &orphan.blob_id).exists(), "orphan deleted");
        assert!(blob::blob_path(&bk, &live_blob).exists(), "live manifest blob kept");
        for id in &kept_part_ids {
            assert!(blob::blob_path(&bk, id).exists(), "in-flight upload part {id} must be kept");
        }
        // Live object + the still-resumable upload are both intact.
        assert_eq!(read_all(fs.get_object("bkt", "live", None).unwrap().body), b"referenced by a live manifest");
        assert_eq!(fs.list_parts("bkt", "mp/keep", &upload_id).unwrap().len(), 3);

        // Idempotent: a second GC reclaims nothing.
        assert_eq!(fs.gc_orphan_blobs("bkt").unwrap(), 0);
    }

    #[test]
    fn recover_sweeps_all_buckets() {
        // recover() iterates every bucket; per-bucket artifacts are each cleaned.
        let dir = tempfile::tempdir().unwrap();
        let fs = CasStore::new(dir.path());
        for b in ["bucket-one", "bucket-two"] {
            fs.create_bucket(b).unwrap();
            // Leave an orphan arriving manifest in each via a pre-commit crash.
            set_fault(Some(FaultPoint::BeforeJournal));
            let _ = fs.put_object(b, "doomed", &b"x"[..], "", BTreeMap::new());
            set_fault(None);
        }
        let stats = fs.recover().unwrap();
        assert_eq!(stats.buckets, 2);
        assert_eq!(stats.arriving_manifests_removed, 2);
        for b in ["bucket-one", "bucket-two"] {
            assert!(list_dir(&dir.path().join(b).join("arriving")).is_empty());
        }
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
    fn part_ref_filename_content_mismatch_is_dropped() {
        // Item #6 (defense-in-depth): a tampered `.ref` whose recorded part_number
        // disagrees with its FILENAME number must be dropped by read_part_refs, so
        // Complete cannot assemble a part under the wrong index. We hand-tamper part
        // 1's ref to claim part_number=2 while keeping the filename 00001.ref.
        let (dir, fs) = store();
        let bk = dir.path().join("bkt");
        let key = "tampered";
        let upload_id = fs.create_multipart_upload("bkt", key, "", BTreeMap::new()).unwrap();
        let e1 = fs.upload_part("bkt", key, &upload_id, 1, &b"the bytes"[..]).unwrap();

        // Rewrite parts/00001.ref so its body says part_number=2 (mismatch).
        let ref_path = bk.join("arriving").join(&upload_id).join("parts").join("00001.ref");
        let mut pref: PartRefFile =
            serde_json::from_slice(&std::fs::read(&ref_path).unwrap()).unwrap();
        pref.part_number = 2; // body now disagrees with the filename "00001"
        std::fs::write(&ref_path, serde_json::to_vec(&pref).unwrap()).unwrap();

        // read_part_refs drops the mismatched entry -> ListParts sees nothing.
        assert!(fs.list_parts("bkt", key, &upload_id).unwrap().is_empty());
        // Complete claiming part 1 -> InvalidPart (the ref was dropped).
        let err = fs
            .complete_multipart_upload(
                "bkt",
                key,
                &upload_id,
                &[CompletePart { part_number: 1, etag: e1 }],
            )
            .unwrap_err();
        assert!(matches!(err, StorageError::InvalidPart), "got {err:?}");
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

    use super::super::types::ListObjectsInput;

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
        // An ordinary `.meta` key (report.meta -> current/report.meta.s3gw-live.meta)
        // must DECODE back to `report.meta` during listing, not `report` and not the
        // on-disk filename. (Keys with a segment ending in MANIFEST_SUFFIX itself are
        // rejected upstream, so they never reach listing.)
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
        // encode∘decode == identity over tricky (but ACCEPTED) keys. A key with a
        // segment ending in MANIFEST_SUFFIX (e.g. `report.s3gw-live.meta`) is rejected
        // by `validate_object_path` and never stored, so it is not round-tripped here.
        let cur = Path::new("/data/bk/current");
        for key in [
            "a",
            "a/b",
            "report.meta",
            "a.meta.meta",
            "a.meta/b", // coexists with `a` (distinct paths)
            "deeply/nested/path/to/object.bin",
            "café/résumé.txt",
            "emoji/😀/file",
            "trailing.dot.",
            "x.s3gw-live.metameta", // does NOT end in the suffix -> accepted
        ] {
            let p = manifest::manifest_path(cur, key);
            let rel = p.strip_prefix(cur).unwrap();
            let decoded = manifest::decode_relpath_to_key(rel)
                .unwrap_or_else(|| panic!("decode failed for key {key:?}"));
            assert_eq!(decoded, key, "round-trip mismatch for key {key:?}");
        }
    }
}

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

/// Number of shards in the per-BUCKET lock table (A3). Sharded on the bucket NAME
/// alone, this serializes a `delete_bucket` (bucket WRITE lock) against any object
/// writer in that bucket (bucket READ lock) without serializing writers against
/// each other or against reads. Far fewer buckets than keys, so a small table
/// suffices.
const BUCKET_LOCK_SHARDS: usize = 64;

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

// B4 test hook: when armed, `upload_part`'s `parts/`-dir fsync (under `--fsync`)
// is forced to fail, so a test can prove the error is PROPAGATED (not swallowed)
// and the just-written part is rolled back. Thread-local — never leaks across the
// parallel test runner. Compiles out entirely in non-test builds.
#[cfg(test)]
thread_local! {
    static FORCE_PARTS_FSYNC_FAIL: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
pub(crate) fn set_force_parts_fsync_fail(v: bool) {
    FORCE_PARTS_FSYNC_FAIL.with(|c| c.set(v));
}

// D-2 test hook: when armed, force the previous-`.ref` RESTORE (inside the C4
// UploadPart-overwrite rollback) to fail, so a test can prove the restore-FAILS branch
// leaves the part referencing the VALID new blob (consistent) and does NOT reclaim it
// (no dangling/truncated ref). Independent of FORCE_PARTS_FSYNC_FAIL (which TRIGGERS the
// rollback); both are armed together so the rollback runs AND its restore then fails.
// Thread-local; compiles out in non-test builds.
#[cfg(test)]
thread_local! {
    static FORCE_PARTS_RESTORE_FAIL: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
pub(crate) fn set_force_parts_restore_fail(v: bool) {
    FORCE_PARTS_RESTORE_FAIL.with(|c| c.set(v));
}

// C6 test hook: when armed, `write_journal`'s `deleted/`-dir fsync (under --fsync) is
// forced to fail, so a test can prove the error is PROPAGATED (not swallowed). The
// `deleted/` dir is a real directory and the journal FILE write succeeds — only the
// dir-fsync fails — isolating exactly the C6 path. Thread-local; compiles out in
// non-test builds.
#[cfg(test)]
thread_local! {
    static FORCE_JOURNAL_DIR_FSYNC_FAIL: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
pub(crate) fn set_force_journal_dir_fsync_fail(v: bool) {
    FORCE_JOURNAL_DIR_FSYNC_FAIL.with(|c| c.set(v));
}

// C1-residual test hook: when armed, `put_object`'s pre-publish `fsync_blob_dir` (under
// --fsync) is forced to fail, so a test can prove the just-written blob is RECLAIMED
// (not leaked as an orphan) before the error is propagated. This fsync runs BEFORE the
// per-key lock + publish, so its error never reaches publish's rollback arm — the
// explicit reclaim in put_object is what prevents the orphan. Thread-local; compiles out
// in non-test builds.
#[cfg(test)]
thread_local! {
    static FORCE_PUT_BLOB_DIR_FSYNC_FAIL: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
pub(crate) fn set_force_put_blob_dir_fsync_fail(v: bool) {
    FORCE_PUT_BLOB_DIR_FSYNC_FAIL.with(|c| c.set(v));
}

// E-1/E-2 test hook: when armed, the post-commit `current/`-dir fsync in BOTH
// `publish` (after the commit rename) and `delete_object` (after the manifest
// unlink), under --fsync, is forced to fail — so a test can prove the error is
// PROPAGATED (not swallowed) BEFORE step-4 reclaim / step-5 journal-delete. The
// journal therefore survives, leaving the commit recoverable: recover()'s
// nonce/key rule settles to a consistent state (OLD version live OR NEW version
// live, never a dangling manifest / missing blob). Thread-local — never leaks
// across the parallel test runner. Compiles out entirely in non-test builds.
#[cfg(test)]
thread_local! {
    static FORCE_COMMIT_DIR_FSYNC_FAIL: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
pub(crate) fn set_force_commit_dir_fsync_fail(v: bool) {
    FORCE_COMMIT_DIR_FSYNC_FAIL.with(|c| c.set(v));
}

// Codex pass I test hook: a THREAD-LOCAL counter of the idempotent/already-done
// durability fsyncs added by pass I — the three sites where a success path that
// short-circuits BEFORE the op's normal durability fsync (delete of an absent
// key, create_bucket on an existing bucket, delete_bucket data-root) must STILL
// force the prior in-flight write durable on a retry. Each such site bumps this
// when it runs under --fsync, so a test can assert "the durability fsync ran on
// this idempotent path" (a crash itself is not unit-testable). THREAD-LOCAL (not
// process-wide): the pass-I sites run on the CALLING thread in unit tests, so a
// per-thread counter makes a before/after delta DETERMINISTIC and load-bearing —
// a parallel test bumping the same site on another thread cannot pollute this
// thread's count. Compiles out entirely in non-test builds.
#[cfg(test)]
thread_local! {
    static PASS_I_FSYNC_COUNT: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn bump_pass_i_fsync() {
    PASS_I_FSYNC_COUNT.with(|c| c.set(c.get() + 1));
}

#[cfg(test)]
pub(crate) fn pass_i_fsync_count() -> u64 {
    PASS_I_FSYNC_COUNT.with(|c| c.get())
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

/// C2 deterministic test hook: a single-barrier handshake that lets a test prove the
/// single-part GET opens its blob fd UNDER the per-key READ lock. [`pause`] is called
/// inside `get_object` AFTER the manifest snapshot read but BEFORE `open_body` — STILL
/// HOLDING the read lock. A test arms it for one `{bucket}/{key}`, parks the GET there
/// (read lock held), starts a concurrent overwrite (which must block on the per-key
/// WRITE lock, so it cannot reclaim the old blob yet), then releases the GET; the GET
/// opens the still-present old blob under the lock, drops the lock, and streams the old
/// bytes from the pinned fd even after the overwrite reclaims the old blob.
/// Compiled out entirely in non-test builds.
#[inline(always)]
fn get_open_pause(_bucket: &str, _key: &str) {
    #[cfg(test)]
    get_pause::pause(_bucket, _key);
}

#[cfg(test)]
mod get_pause {
    use std::sync::{Condvar, Mutex, OnceLock};

    pub(super) struct Hook {
        pub key: String,
        state: Mutex<State>,
        cv: Condvar,
    }
    #[derive(Default)]
    struct State {
        arrived: bool,
        released: bool,
        /// A concurrent writer hit the per-key WRITE lock while the GET held the READ
        /// lock — proof the GET's open is happening under the read lock (the C2 fix).
        writer_contended: bool,
    }

    static HOOK: OnceLock<Mutex<Option<&'static Hook>>> = OnceLock::new();
    static SERIAL: OnceLock<Mutex<()>> = OnceLock::new();

    fn slot() -> &'static Mutex<Option<&'static Hook>> {
        HOOK.get_or_init(|| Mutex::new(None))
    }

    pub(super) fn serialize_test() -> std::sync::MutexGuard<'static, ()> {
        SERIAL.get_or_init(|| Mutex::new(())).lock().unwrap_or_else(|e| e.into_inner())
    }

    impl Hook {
        pub(super) fn arm(key: &str) -> &'static Hook {
            let h = Box::leak(Box::new(Hook {
                key: key.to_string(),
                state: Mutex::new(State::default()),
                cv: Condvar::new(),
            }));
            *slot().lock().unwrap() = Some(h);
            h
        }
        pub(super) fn disarm() {
            *slot().lock().unwrap() = None;
        }
        pub(super) fn wait_arrived(&self) {
            let mut st = self.state.lock().unwrap();
            while !st.arrived {
                st = self.cv.wait(st).unwrap();
            }
        }
        /// Wait up to `timeout` for a concurrent writer to register WRITE-lock
        /// contention. Returns true iff contention fired (C2 fix in effect: the GET
        /// holds the read lock, so the overwrite blocks). A timeout (false) means the
        /// overwrite ran lock-free — the pre-C2 shape where the open is NOT under the
        /// read lock.
        pub(super) fn wait_writer_contended_timeout(&self, timeout: std::time::Duration) -> bool {
            let mut st = self.state.lock().unwrap();
            let deadline = std::time::Instant::now() + timeout;
            while !st.writer_contended {
                let now = std::time::Instant::now();
                if now >= deadline {
                    return st.writer_contended;
                }
                let (g, to) = self.cv.wait_timeout(st, deadline - now).unwrap();
                st = g;
                if to.timed_out() {
                    return st.writer_contended;
                }
            }
            true
        }
        pub(super) fn release(&self) {
            let mut st = self.state.lock().unwrap();
            st.released = true;
            self.cv.notify_all();
        }
    }

    /// Called from `lock_key` when a writer is about to block on the per-key WRITE
    /// lock; records contention so the C2 test can confirm the GET holds the READ lock.
    pub(super) fn note_lock_contention(bucket: &str, key: &str) {
        let hook = { *slot().lock().unwrap() };
        let Some(hook) = hook else { return };
        if hook.key != format!("{bucket}/{key}") {
            return;
        }
        let mut st = hook.state.lock().unwrap();
        st.writer_contended = true;
        hook.cv.notify_all();
    }

    pub(super) fn pause(bucket: &str, key: &str) {
        let hook = { *slot().lock().unwrap() };
        let Some(hook) = hook else { return };
        if hook.key != format!("{bucket}/{key}") {
            return;
        }
        let mut st = hook.state.lock().unwrap();
        st.arrived = true;
        hook.cv.notify_all();
        while !st.released {
            st = hook.cv.wait(st).unwrap();
        }
    }
}

/// A3 deterministic test hook: a second, independent Condvar handshake (separate
/// slot from [`publish_pause`]) that lets a test reproduce the delete_bucket-vs-writer
/// interleaving the per-BUCKET lock prevents — no sleeps.
///
///  * [`pause`] is called inside `delete_bucket` AFTER it acquires the bucket WRITE
///    lock but BEFORE the emptiness check + remove: the delete thread parks there
///    holding the WRITE lock until the test releases it.
///  * [`note_contention`] is called from `rlock_bucket` when a writer is about to
///    BLOCK on an already-WRITE-held bucket lock (proof the lock is serializing).
///
/// Compiled out entirely in non-test builds (the two call sites become no-ops), so
/// there is ZERO production effect/cost.
#[cfg(test)]
mod bucket_pause {
    use std::sync::{Condvar, Mutex, OnceLock};

    pub(super) struct Hook {
        pub bucket: String,
        state: Mutex<State>,
        cv: Condvar,
    }
    #[derive(Default)]
    struct State {
        delete_parked: bool,
        released: bool,
        writer_contended: bool,
    }

    static HOOK: OnceLock<Mutex<Option<&'static Hook>>> = OnceLock::new();
    static SERIAL: OnceLock<Mutex<()>> = OnceLock::new();

    fn slot() -> &'static Mutex<Option<&'static Hook>> {
        HOOK.get_or_init(|| Mutex::new(None))
    }

    /// Process-wide serialization for hook-using tests (single global slot).
    pub(super) fn serialize_test() -> std::sync::MutexGuard<'static, ()> {
        SERIAL
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|p| p.into_inner())
    }

    impl Hook {
        pub(super) fn arm(bucket: &str) -> &'static Hook {
            let hook: &'static Hook = Box::leak(Box::new(Hook {
                bucket: bucket.to_string(),
                state: Mutex::new(State::default()),
                cv: Condvar::new(),
            }));
            *slot().lock().unwrap() = Some(hook);
            hook
        }
        pub(super) fn disarm() {
            *slot().lock().unwrap() = None;
        }
        /// Block until the delete thread has parked holding the bucket WRITE lock.
        pub(super) fn wait_delete_parked(&self) {
            let mut st = self.state.lock().unwrap();
            while !st.delete_parked {
                st = self.cv.wait(st).unwrap();
            }
        }
        /// Block (bounded) until a writer reports it is about to block on the bucket
        /// lock. `Some(())` if observed; `None` on timeout (lock missing -> clean fail).
        pub(super) fn wait_writer_contention_timeout(
            &self,
            timeout: std::time::Duration,
        ) -> Option<()> {
            let deadline = std::time::Instant::now() + timeout;
            let mut st = self.state.lock().unwrap();
            while !st.writer_contended {
                let now = std::time::Instant::now();
                if now >= deadline {
                    return None;
                }
                let (g, res) = self.cv.wait_timeout(st, deadline - now).unwrap();
                st = g;
                if res.timed_out() && !st.writer_contended {
                    return None;
                }
            }
            Some(())
        }
        pub(super) fn release(&self) {
            let mut st = self.state.lock().unwrap();
            st.released = true;
            self.cv.notify_all();
        }
    }

    /// delete_bucket park point: the delete thread (already holding the bucket WRITE
    /// lock) parks here until released.
    pub(super) fn pause(bucket: &str) {
        let hook = { *slot().lock().unwrap() };
        let Some(hook) = hook else { return };
        if hook.bucket != bucket {
            return;
        }
        let mut st = hook.state.lock().unwrap();
        st.delete_parked = true;
        hook.cv.notify_all();
        while !st.released {
            st = hook.cv.wait(st).unwrap();
        }
    }

    /// bucket-lock contention probe: a writer is about to block on the WRITE-held
    /// bucket lock.
    pub(super) fn note_contention(bucket: &str) {
        let hook = { *slot().lock().unwrap() };
        let Some(hook) = hook else { return };
        if hook.bucket != bucket {
            return;
        }
        let mut st = hook.state.lock().unwrap();
        st.writer_contended = true;
        hook.cv.notify_all();
    }
}

/// delete_bucket park point (after acquiring the bucket WRITE lock, before the
/// emptiness check + remove). No-op outside tests.
#[inline(always)]
fn delete_bucket_pause(_bucket: &str) {
    #[cfg(test)]
    bucket_pause::pause(_bucket);
}

/// Codex pass F-3 deterministic test hook: a one-barrier handshake that parks
/// `upload_part` AFTER its pre-lock upload validation but BEFORE it takes the
/// bucket READ lock + calls `write_blob`. A test arms it for one `{bucket}`,
/// parks an in-flight upload_part there, then (deterministically) aborts the
/// upload + deletes the bucket, then releases upload_part. With the F-3 fix the
/// resumed upload_part re-checks `head_bucket` under the read lock and returns
/// NoSuchBucket WITHOUT recreating the torn-down bucket; without the fix it would
/// `write_blob` and recreate `bucket/blobs/...` (a phantom bucket). No-op outside
/// tests.
#[inline(always)]
fn upload_part_pre_lock_pause(_bucket: &str) {
    #[cfg(test)]
    upload_part_pause::pause(_bucket);
}

#[cfg(test)]
mod upload_part_pause {
    use std::sync::{Condvar, Mutex, OnceLock};

    pub(super) struct Hook {
        pub bucket: String,
        state: Mutex<State>,
        cv: Condvar,
    }
    #[derive(Default)]
    struct State {
        arrived: bool,
        released: bool,
    }

    static HOOK: OnceLock<Mutex<Option<&'static Hook>>> = OnceLock::new();
    static SERIAL: OnceLock<Mutex<()>> = OnceLock::new();

    fn slot() -> &'static Mutex<Option<&'static Hook>> {
        HOOK.get_or_init(|| Mutex::new(None))
    }

    pub(super) fn serialize_test() -> std::sync::MutexGuard<'static, ()> {
        SERIAL.get_or_init(|| Mutex::new(())).lock().unwrap_or_else(|p| p.into_inner())
    }

    impl Hook {
        pub(super) fn arm(bucket: &str) -> &'static Hook {
            let h = Box::leak(Box::new(Hook {
                bucket: bucket.to_string(),
                state: Mutex::new(State::default()),
                cv: Condvar::new(),
            }));
            *slot().lock().unwrap() = Some(h);
            h
        }
        pub(super) fn disarm() {
            *slot().lock().unwrap() = None;
        }
        /// Block until upload_part has parked at the pre-lock point.
        pub(super) fn wait_arrived(&self) {
            let mut st = self.state.lock().unwrap();
            while !st.arrived {
                st = self.cv.wait(st).unwrap();
            }
        }
        pub(super) fn release(&self) {
            let mut st = self.state.lock().unwrap();
            st.released = true;
            self.cv.notify_all();
        }
    }

    pub(super) fn pause(bucket: &str) {
        let hook = { *slot().lock().unwrap() };
        let Some(hook) = hook else { return };
        if hook.bucket != bucket {
            return;
        }
        let mut st = hook.state.lock().unwrap();
        st.arrived = true;
        hook.cv.notify_all();
        while !st.released {
            st = hook.cv.wait(st).unwrap();
        }
    }
}

/// Codex pass H deterministic test hook: a one-barrier handshake that parks
/// `complete_multipart_upload` AFTER its pre-lock upload validation
/// (`assert_upload_matches`) but BEFORE it takes the bucket READ + per-key locks and
/// calls `read_part_refs`. A test arms it for one `{bucket}/{key}`, parks an in-flight
/// Complete there, then (deterministically) ABORTS the upload (removing the upload
/// dir) in the exact window the H re-check guards, then releases Complete. With the H
/// fix the resumed Complete re-checks the upload UNDER the per-key lock, finds the dir
/// gone, and returns NoSuchUpload; without it `read_part_refs` returns an empty map and
/// Complete reports InvalidPart for the (now-missing) claimed parts. No-op outside tests.
#[inline(always)]
fn complete_pre_lock_pause(_bucket: &str, _key: &str) {
    #[cfg(test)]
    complete_pause::pause(_bucket, _key);
}

#[cfg(test)]
mod complete_pause {
    use std::sync::{Condvar, Mutex, OnceLock};

    pub(super) struct Hook {
        pub key: String,
        state: Mutex<State>,
        cv: Condvar,
    }
    #[derive(Default)]
    struct State {
        arrived: bool,
        released: bool,
    }

    static HOOK: OnceLock<Mutex<Option<&'static Hook>>> = OnceLock::new();
    static SERIAL: OnceLock<Mutex<()>> = OnceLock::new();

    fn slot() -> &'static Mutex<Option<&'static Hook>> {
        HOOK.get_or_init(|| Mutex::new(None))
    }

    pub(super) fn serialize_test() -> std::sync::MutexGuard<'static, ()> {
        SERIAL.get_or_init(|| Mutex::new(())).lock().unwrap_or_else(|p| p.into_inner())
    }

    impl Hook {
        pub(super) fn arm(bucket: &str, key: &str) -> &'static Hook {
            let h = Box::leak(Box::new(Hook {
                key: format!("{bucket}/{key}"),
                state: Mutex::new(State::default()),
                cv: Condvar::new(),
            }));
            *slot().lock().unwrap() = Some(h);
            h
        }
        pub(super) fn disarm() {
            *slot().lock().unwrap() = None;
        }
        /// Block until Complete has parked at the pre-lock point.
        pub(super) fn wait_arrived(&self) {
            let mut st = self.state.lock().unwrap();
            while !st.arrived {
                st = self.cv.wait(st).unwrap();
            }
        }
        pub(super) fn release(&self) {
            let mut st = self.state.lock().unwrap();
            st.released = true;
            self.cv.notify_all();
        }
    }

    pub(super) fn pause(bucket: &str, key: &str) {
        let hook = { *slot().lock().unwrap() };
        let Some(hook) = hook else { return };
        if hook.key != format!("{bucket}/{key}") {
            return;
        }
        let mut st = hook.state.lock().unwrap();
        st.arrived = true;
        hook.cv.notify_all();
        while !st.released {
            st = hook.cv.wait(st).unwrap();
        }
    }
}

/// Content-addressed store rooted at `root` (the data dir).
#[derive(Debug, Clone)]
pub struct CasStore {
    root: PathBuf,
    /// Gates manifest/journal/dir fsyncs (data-blob fsync is always on). Mirrors
    /// `Filesystem::fsync` / the `--fsync` flag.
    fsync: bool,
    key_locks: std::sync::Arc<Vec<std::sync::RwLock<()>>>,
    /// A3: per-BUCKET lock table (sharded on the bucket NAME alone). `delete_bucket`
    /// takes the WRITE lock across its emptiness check + remove_dir_all; every object
    /// WRITER (put/delete/create-mp/upload-part/complete) takes the READ lock around
    /// its infra-ensure + publish/create. Reads (GET/HEAD/LIST) take NO bucket lock.
    /// Shared via the same Arc-clone pattern as `key_locks`.
    bucket_locks: std::sync::Arc<Vec<std::sync::RwLock<()>>>,
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
        let mut bucket_locks = Vec::with_capacity(BUCKET_LOCK_SHARDS);
        for _ in 0..BUCKET_LOCK_SHARDS {
            bucket_locks.push(std::sync::RwLock::new(()));
        }
        CasStore {
            root: root.into(),
            fsync,
            key_locks: std::sync::Arc::new(locks),
            bucket_locks: std::sync::Arc::new(bucket_locks),
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
                get_pause::note_lock_contention(bucket, key);
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

    // ---- A3: per-BUCKET locking (FNV-1a sharded on the bucket NAME alone) ----
    //
    // LOCK-ORDERING INVARIANT (deadlock-freedom): a writer that needs BOTH locks ALWAYS
    // acquires the bucket lock FIRST, then the per-key lock — never the reverse. With a
    // single global lock order there is no cycle. `delete_bucket` takes only the bucket
    // WRITE lock; reads (GET/HEAD/LIST) and the multipart Abort path take neither bucket
    // lock. The bucket-name shard is independent of the {bucket}/{key} shard, so the two
    // tables never alias.

    fn bucket_lock_shard(bucket: &str) -> usize {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for byte in bucket.bytes() {
            h ^= byte as u64;
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        (h as usize) & (BUCKET_LOCK_SHARDS - 1)
    }

    /// Bucket WRITE lock (taken by `delete_bucket` and `create_bucket` — the two
    /// bucket-existence mutators — across their check + create/remove).
    fn lock_bucket(&self, bucket: &str) -> std::sync::RwLockWriteGuard<'_, ()> {
        let idx = Self::bucket_lock_shard(bucket);
        // Test-only contention probe: if the bucket lock is already held (a
        // delete_bucket/create_bucket parked holding it), record that this mutator is
        // about to BLOCK before we actually block. Compiled out in production. This is
        // what lets the E-3 create-vs-delete test prove create_bucket now serializes on
        // the per-bucket WRITE lock.
        #[cfg(test)]
        {
            if self.bucket_locks[idx].try_write().is_err() {
                bucket_pause::note_contention(bucket);
            }
        }
        self.bucket_locks[idx]
            .write()
            .unwrap_or_else(|p| p.into_inner())
    }

    /// Bucket READ lock (taken by every object writer around its infra-ensure +
    /// publish/create; many writers share it concurrently, but it excludes a
    /// `delete_bucket`'s WRITE lock).
    fn rlock_bucket(&self, bucket: &str) -> std::sync::RwLockReadGuard<'_, ()> {
        let idx = Self::bucket_lock_shard(bucket);
        // Test-only contention probe: if the bucket lock is already WRITE-held (a
        // delete_bucket parked holding it), record that this writer is about to BLOCK
        // before we actually block. Compiled out in production.
        #[cfg(test)]
        {
            if self.bucket_locks[idx].try_read().is_err() {
                bucket_pause::note_contention(bucket);
            }
        }
        self.bucket_locks[idx]
            .read()
            .unwrap_or_else(|p| p.into_inner())
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

        // E-3 [MED — concurrency]: take the per-bucket WRITE lock across the existence
        // mutation. create_bucket and delete_bucket are the two bucket-existence
        // mutators and MUST serialize on the same lock — otherwise a concurrent
        // Create+Delete of the same name can BOTH return Ok (lost update: the create's
        // dir survives a delete that scanned before it, or the create races a teardown).
        // WRITE (not READ): both mutate existence, so they must be mutually exclusive.
        // Deadlock-safe: create_bucket takes NO per-key lock, preserving the global
        // bucket-before-key lock order.
        let _bguard = self.lock_bucket(name);

        let path = self.bucket_root(name);
        match std::fs::create_dir(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                // Codex pass I (I-2) [MED — durability]: the bucket already exists, so
                // this is the IDEMPOTENT create path (the handler maps BucketExists ->
                // 200). But this short-circuit would otherwise return BEFORE the site-4
                // data-root fsync AND before ensure_infra, so a RETRY of a create whose
                // FIRST attempt's data-root fsync FAILED would ack 200 while the bucket
                // dirent is still non-durable. Make the durability HONEST on the retry:
                // re-run ensure_infra (idempotent; it fsyncs the bucket-root so the four
                // infra dirents are durable) and fsync the DATA-ROOT (so the bucket
                // dirent itself is durable). Both are cheap no-ops once durable. We then
                // STILL return BucketExists — the handler's 200 mapping is unchanged;
                // only the durability of the ack is fixed.
                if self.fsync {
                    self.ensure_infra(name)?;
                    super::directio::fsync_dir(&self.root)?;
                    #[cfg(test)]
                    bump_pass_i_fsync();
                }
                return Err(StorageError::BucketExists);
            }
            Err(e) => return Err(e.into()),
        }
        // Codex pass F site-4 [HIGH — durability]: under --fsync, make the new
        // `bucket/` DIRENT durable by fsyncing the DATA-ROOT (its parent). Without
        // this the first committed write into a fresh bucket can be lost after a
        // crash because the bucket directory entry itself was never on stable
        // storage. (This also makes `bucket_root` itself exist durably, so the
        // bucket-root fsync in ensure_infra below is well-defined.)
        if self.fsync {
            super::directio::fsync_dir(&self.root)?;
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
        // Codex pass F site-4 [HIGH — durability]: under --fsync, make the four
        // infra-dir DIRENTS (`current/`, `arriving/`, `blobs/`, `deleted/`)
        // durable by fsyncing the BUCKET-ROOT. Without this, the FIRST write to a
        // fresh bucket can commit a manifest/journal/blob into an infra dir whose
        // dirent is not yet on stable storage — a crash then loses the infra dir
        // (and everything committed under it). Making `bucket_root/blobs` and
        // `bucket_root/current` durable here is also what lets `fsync_dir_chain`
        // use them as already-durable `stop_at` boundaries (F-1 / F-2).
        if self.fsync {
            super::directio::fsync_dir(&self.bucket_root(bucket))?;
        }
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

        // A3: take the per-bucket WRITE lock across the ENTIRE emptiness-check +
        // remove_dir_all. Object writers (put/delete/create-mp/upload-part/complete)
        // hold this bucket's READ lock around their infra-ensure + publish/create, so
        // while we hold the WRITE lock no writer can be mid-publish: either it finished
        // before us (its manifest is visible to the emptiness scan -> BucketNotEmpty) or
        // it blocks until we are done (and then sees BucketNotFound). This closes the
        // lost-write / half-recreated-bucket race without serializing writers against
        // each other or against reads. (Lock order: bucket lock only; delete_bucket
        // never takes a per-key lock, so it cannot deadlock against a writer that holds
        // bucket-read then waits for a key lock.)
        let _bguard = self.lock_bucket(name);

        // Deterministic test hook: park here HOLDING the bucket WRITE lock so a test
        // can prove a concurrent writer blocks on the bucket lock. No-op in production.
        delete_bucket_pause(name);

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
        // Codex pass I (delete_bucket data-root, symmetric to create_bucket's site-4)
        // [MED — durability]: under --fsync, make the bucket-REMOVAL dirent durable by
        // fsyncing the DATA-ROOT (the bucket's parent) BEFORE we ack the 204. Without
        // this the removal is acked non-durably, so a crash can RESURRECT the just-
        // deleted bucket (resurrected-but-consistent; no corruption). Errors PROPAGATE
        // — a delete_bucket that cannot make the removal durable must not ack success.
        if self.fsync {
            super::directio::fsync_dir(&self.root)?;
            #[cfg(test)]
            bump_pass_i_fsync();
        }
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
            // A completed-but-not-yet-removed upload dir is no longer addressable via S3
            // (consistent with ListMultipartUploads and assert_upload_matches); it must not
            // wedge DeleteBucket with BucketNotEmpty.
            if entry.path().join("completed").exists() {
                continue;
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

        // A3: hold this bucket's READ lock across head_bucket + ensure_infra + publish,
        // so a concurrent delete_bucket (bucket WRITE lock) cannot tear the bucket down
        // between our head_bucket and our commit (lost write / half-recreated bucket).
        // Acquired BEFORE the per-key lock below (the global lock order: bucket -> key).
        // The heavy body stream happens under this read lock but BEFORE the per-key
        // lock; many writers share the read lock so this does not serialize writers.
        let _bguard = self.rlock_bucket(bucket);

        self.head_bucket(bucket)?;
        self.ensure_infra(bucket)?;

        let bucket_root = self.bucket_root(bucket);

        // Stream the body to a blob (lock-free; one-pass MD5; fsync). This is the
        // big work and runs BEFORE the per-key publish lock is taken.
        let info = blob::write_blob(&bucket_root, body).map_err(body_or_io)?;
        // C1 [HIGH — durability]: under --fsync, make the blob's fanout DIRENT durable
        // (write_blob fsyncs only the file) BEFORE the manifest that references it is
        // committed by publish() below — otherwise a crash could leave a durable
        // manifest pointing at a blob whose dirent was lost (a dangling live object).
        if self.fsync {
            // C1-residual [LOW — orphan leak]: this fsync runs BEFORE the per-key lock
            // + publish below, so its error returns WITHOUT reaching publish's rollback
            // arm — leaving the just-written blob as an orphan. Reclaim it (best-effort)
            // before propagating, matching the pre-commit rollback posture, so no orphan
            // is left. (It would otherwise be gc_orphan_blobs-reclaimable, but the
            // explicit reclaim avoids relying on the manual GC backstop.)
            let fsync_res = {
                #[cfg(test)]
                if FORCE_PUT_BLOB_DIR_FSYNC_FAIL.with(|c| c.get()) {
                    Err(io::Error::other("forced put blob-dir fsync failure (test)"))
                } else {
                    blob::fsync_blob_dir(&bucket_root, &info.blob_id)
                }
                #[cfg(not(test))]
                blob::fsync_blob_dir(&bucket_root, &info.blob_id)
            };
            if let Err(e) = fsync_res {
                let _ = blob::reclaim_blob(&bucket_root, &info.blob_id);
                return Err(StorageError::Io(e));
            }
        }

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
            // E-1: a `CommitNotDurable` means the manifest COMMITTED (rename landed,
            // new blob durable) but only the post-commit dir fsync failed. The new
            // version is LIVE, so we must NOT reclaim the new blob — doing so would
            // strand the live manifest on a missing blob. Propagate the not-acked error.
            Err(e @ StorageError::CommitNotDurable(_)) => Err(e),
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
        // E-1 [HIGH — data loss]: PROPAGATE the post-commit `current/`-dir fsync error
        // (do NOT swallow it) BEFORE step-4 reclaim / step-5 journal-delete. The new
        // blobs are already durable (write_blob fsynced them). Ordering is rename ->
        // dir-fsync(PROPAGATE) -> reclaim -> delete-journal: if the rename's dirent is
        // not yet durable we must NOT reclaim the OLD blobs / delete the journal, else a
        // crash could revert `current/K` to the OLD manifest whose blobs were already
        // gone -> a dangling live object / data loss. Returning Err here leaves the
        // journal in place, so recover() settles it via the §3.2 nonce rule: if the
        // rename landed, the new manifest's nonce matches -> OLD blobs reclaimed; if the
        // rename was lost, the nonce mismatches -> OLD blobs kept (OLD version fully
        // live). The commit is simply NOT acked; both crash branches stay consistent.
        //
        // Codex pass F-2 [HIGH — durability]: fsync NOT JUST `k.parent()` but the
        // WHOLE newly-created ancestor chain from `k.parent()` up to (and including)
        // `current/`. A nested key (`a/b/c`) `create_dir_all`s `current/a/b/`; if a
        // crash loses an intermediate dirent (`current/a/`) the committed manifest is
        // unreachable even though `current/a/b/` itself was fsynced. `current/` is
        // already made durable by ensure_infra (site-4), so it is the stop_at boundary.
        if self.fsync {
            if let Some(parent) = k.parent() {
                let fsync_res = {
                    #[cfg(test)]
                    if FORCE_COMMIT_DIR_FSYNC_FAIL.with(|c| c.get()) {
                        Err(io::Error::other("forced commit-dir fsync failure (test)"))
                    } else {
                        super::directio::fsync_dir_chain(parent, &current_root)
                    }
                    #[cfg(not(test))]
                    super::directio::fsync_dir_chain(parent, &current_root)
                };
                // POST-commit: the rename landed and the new blobs are already durable,
                // so this is NOT a pre-commit failure — return the DEDICATED
                // `CommitNotDurable` so the caller does NOT roll back the now-live new
                // blobs. The journal stays in place; recover()'s nonce rule settles it.
                if let Err(e) = fsync_res {
                    return Err(StorageError::CommitNotDurable(e));
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
            // B5 [blob leak]: track whether EVERY reclaim succeeded (Ok, incl. the
            // no-op on a missing/invalid id, which `reclaim_blob` reports as Ok). A
            // genuine unlink error (e.g. EIO) means the blob is NOT yet reclaimed; if
            // we still deleted the journal the blob would leak with nothing to retry it.
            // So: only remove the journal when ALL reclaims succeeded — otherwise LEAVE
            // it for `recover()` to retry (the §3.2 nonce rule keeps the retry safe).
            let mut all_reclaimed = true;
            for blob_id in &journal.blobs {
                if blob::reclaim_blob(&bucket_root, blob_id).is_err() {
                    all_reclaimed = false;
                }
            }
            #[cfg(test)]
            if fault_armed(FaultPoint::BeforeJournalCleanup) {
                return Ok(());
            }
            // ---- step 5: cleanup the journal (only if the reclaim fully landed) ----
            if all_reclaimed {
                let _ = std::fs::remove_file(jpath);
            }
        }
        Ok(())
    }

    // ---- object: DELETE ----

    /// DeleteObject: journal the manifest's blob ids -> remove the manifest ->
    /// reclaim blobs -> delete journal (the mirror of commit, REDESIGN §4).
    /// Idempotent. Signature identical to `Filesystem::delete_object`.
    pub fn delete_object(&self, bucket: &str, key: &str) -> Result<()> {
        self.validate_object_path(bucket, key)?;

        // A3: hold the bucket READ lock across head_bucket + ensure_infra + the
        // journal/remove commit (bucket -> key lock order). Excludes a concurrent
        // delete_bucket WRITE lock without serializing against other writers/reads.
        let _bguard = self.rlock_bucket(bucket);

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
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                // Codex pass I (I-1) [MED — durability]: this is the IDEMPOTENT
                // absent-key path — a delete of a key whose manifest is already gone
                // returns 204. But a RETRY of a delete whose FIRST attempt's unlink
                // SUCCEEDED while its post-unlink manifest-parent dir fsync FAILED would
                // ack 204 here WITHOUT ever making that earlier unlink durable -> a crash
                // could RESURRECT the acked-deleted object (resurrected-but-consistent;
                // no corruption). Make the durability HONEST on the retry: under --fsync,
                // fsync the manifest-parent dir before returning. A real fsync error
                // PROPAGATES (don't ack a non-durable delete); a NotFound on the dir
                // itself (a never-existed key, or the parent already pruned) is a no-op
                // -> Ok. Cheap no-op for a key that never existed; forces the prior
                // in-flight unlink durable on the retry.
                if self.fsync {
                    if let Some(parent) = k.parent() {
                        let fsync_res = {
                            #[cfg(test)]
                            if FORCE_COMMIT_DIR_FSYNC_FAIL.with(|c| c.get()) {
                                Err(io::Error::other("forced commit-dir fsync failure (test)"))
                            } else {
                                super::directio::fsync_dir(parent)
                            }
                            #[cfg(not(test))]
                            super::directio::fsync_dir(parent)
                        };
                        match fsync_res {
                            Ok(()) => {
                                #[cfg(test)]
                                bump_pass_i_fsync();
                            }
                            // The parent dir itself never existed / was already pruned:
                            // nothing to make durable, so the idempotent delete succeeds.
                            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                            Err(e) => return Err(e.into()),
                        }
                    }
                }
                return Ok(());
            }
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

        // COMMIT: remove the manifest, then PROPAGATE the parent dir fsync.
        match std::fs::remove_file(&k) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        // E-2 [HIGH — data loss]: PROPAGATE the post-remove manifest-parent dir fsync
        // (do NOT swallow it) BEFORE reclaiming the blobs / deleting the journal. If the
        // unlink's dirent is not yet durable a crash could RESURRECT the OLD manifest
        // with its blobs permanently gone. Returning Err here keeps the delete-journal in
        // place, so recover() settles it via the §4 rule: if the unlink landed (K absent)
        // the blobs are reclaimed; if it was lost (K present) reclaim is WITHHELD -> OLD
        // version stays fully live. The delete is simply NOT acked; both branches stay
        // consistent. (No blob reclaim / journal delete may run until this fsync lands.)
        if self.fsync {
            if let Some(parent) = k.parent() {
                let fsync_res = {
                    #[cfg(test)]
                    if FORCE_COMMIT_DIR_FSYNC_FAIL.with(|c| c.get()) {
                        Err(io::Error::other("forced commit-dir fsync failure (test)"))
                    } else {
                        super::directio::fsync_dir(parent)
                    }
                    #[cfg(not(test))]
                    super::directio::fsync_dir(parent)
                };
                fsync_res?;
            }
        }

        // reclaim + cleanup. B5: only remove the journal if EVERY blob was reclaimed
        // (Ok, incl. the missing/invalid no-op); a genuine unlink error (EIO) leaves
        // the journal so `recover()` retries the reclaim (the delete-mode rule "K
        // absent" stays true, so the retry is safe). Otherwise the blob would leak.
        let mut all_reclaimed = true;
        for blob_id in &journal.blobs {
            if blob::reclaim_blob(&bucket_root, blob_id).is_err() {
                all_reclaimed = false;
            }
        }
        if all_reclaimed {
            let _ = std::fs::remove_file(&jpath);
        }

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
        // check (see `validate_object_path` rationale), PLUS the A5 openat2
        // BENEATH|NO_SYMLINKS verification below (catches an INTERMEDIATE symlink).
        self.validate_object_path_lexical(bucket, key)?;
        let current_root = self.current_root(bucket);
        let k = manifest::manifest_path(&current_root, key);
        // A5: reject a manifest path with any planted intermediate/leaf symlink under
        // current/ (no-op on kernels lacking openat2).
        self.verify_read_beneath(bucket, &k)?;

        let bucket_root = self.bucket_root(bucket);

        // C2 [hardening]: read the manifest AND open the body UNDER the per-key READ
        // lock, then drop the lock before streaming. For a SINGLE-PART object this pins
        // the blob's inode (its fd is opened by `open_body` while the lock is held), so
        // a concurrent overwrite/delete — which must take the per-key WRITE lock to
        // reclaim — cannot unlink the blob between our manifest snapshot and our open
        // and produce a spurious ObjectNotFound. The open fd keeps the inode alive for
        // the whole stream (POSIX), so the body still streams correctly after the lock
        // drops. Multipart parts are opened LAZILY by MultipartReader and are NOT pinned
        // here — that remains the accepted §5 fail-on-change behavior (C3, documented),
        // and pinning up to 10k part fds is rejected (fd exhaustion).
        let (manifest, resolved_range, body) = {
            let _snap = self.rlock_key(bucket, key);
            let manifest = match manifest::read_manifest(&k) {
                Ok(m) => m,
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    drop(_snap);
                    self.head_bucket(bucket)?;
                    return Err(StorageError::ObjectNotFound);
                }
                Err(e) => return Err(e.into()),
            };
            let total = manifest.content_length;
            let resolved_range = match range_header {
                Some(h) => match parse_range(h, total) {
                    Ok(r) => r,
                    Err(()) => return Err(StorageError::RangeNotSatisfiable { size: total }),
                },
                None => None,
            };
            // C2 deterministic test hook: park here (read lock STILL HELD) so a test can
            // prove the open below happens under the read lock. No-op in production.
            get_open_pause(bucket, key);
            let body = self.open_body(&bucket_root, &manifest, resolved_range)?;
            (manifest, resolved_range, body)
        };

        let total = manifest.content_length;
        let metadata = manifest.to_object_metadata();
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
        // A5: reject a manifest path with a planted intermediate/leaf symlink.
        self.verify_read_beneath(bucket, &k)?;
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
            // A5: verify each blob path resolves beneath the bucket root with no symlink
            // in any component (catches a planted intermediate symlink under blobs/),
            // before the reader opens it. The blob relpath is `blobs/xx/yy/{uuid}`;
            // strip the bucket-root prefix for the openat2 check. No-op without openat2.
            let bp = blob::blob_path(bucket_root, &p.blob_id);
            if let Ok(rel) = bp.strip_prefix(bucket_root) {
                if super::directio::verify_beneath_no_symlinks(bucket_root, rel).is_err() {
                    return Err(StorageError::ObjectNotFound);
                }
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
            //
            // C3 [BY DESIGN — accepted fail-on-change, REDESIGN §5.1]: MultipartReader
            // opens these part blobs LAZILY (one fd at a time), so the part fds are NOT
            // pinned here the way the single-part C2 path pins its one fd under the read
            // lock. If a concurrent reclaim deletes a later, not-yet-opened part blob
            // mid-stream, that part's open fails ENOENT and the stream TRUNCATES at the
            // part boundary — a clean fail-fast short-read, never mixed bytes (each part
            // blob is an immutable uuid that is only unlinked, never overwritten).
            // Pinning all part fds up front is REJECTED: a multipart object can have up
            // to 10k parts, so holding 10k fds for the whole (possibly long) stream would
            // risk fd exhaustion under concurrent large GETs.
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
        // D-1 [MED — atomicity]: write the journal via temp+fsync+rename, matching the
        // manifest/blob atomic-write pattern. Writing directly to the final
        // `deleted/{uuid}.journal` path means a crash mid-write leaves a truncated /
        // half-serialized journal on disk; `apply_journal` would then read garbage. The
        // rename is atomic, so recover() only ever observes a journal that was fully
        // serialized (or no journal at all) — never a torn one.
        let data = serde_json::to_vec(journal).map_err(io::Error::other)?;
        let tmp = path.with_extension(format!("journal.tmp.{}", Uuid::new_v4()));
        // Clean up the temp on any error before the rename publishes it.
        let mut tmp_guard = FileGuard::new(tmp.clone());
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp)?;
        f.write_all(&data)?;
        if self.fsync {
            f.sync_all()?;
        }
        drop(f);
        super::directio::rename(&tmp, path)?;
        tmp_guard.disarm(); // renamed into place; no longer ours to clean.
        if self.fsync {
            // C6 [LOW — durability]: fsync the deleted/ dir so the new journal's DIRENT
            // is durable, and PROPAGATE the error (consistent with C1's posture) rather
            // than swallowing it. A lost journal dirent means recover() never replays the
            // reclaim and the superseded blobs leak; an overwrite/delete that cannot
            // durably journal its reclaim must FAIL rather than ack a non-durable commit.
            if let Some(parent) = path.parent() {
                #[cfg(test)]
                if FORCE_JOURNAL_DIR_FSYNC_FAIL.with(|c| c.get()) {
                    return Err(io::Error::other("forced deleted/ dir fsync failure (test)"));
                }
                super::directio::fsync_dir(parent)?;
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
            // D-1 [MED — resilience]: a corrupt/unreadable journal (truncated bytes from
            // a pre-D-1 crash mid-write, or planted garbage) must NOT abort recover().
            // SKIP it with a warning and leave it on disk; the superseded blobs it would
            // have reclaimed simply remain as orphans, recoverable by the fallback
            // `gc_orphan_blobs` backstop. Aborting recover() here would wedge startup
            // until a human cleaned the file by hand — a far worse failure mode than a
            // leaked-blob residual. `InvalidData` is the JSON-parse error from
            // `read_journal`; any other Io error (EIO, etc.) is also treated as
            // skip-and-warn for the same reason.
            Err(e) => {
                tracing::warn!(
                    journal = %journal_path.display(),
                    error = %e,
                    "skipping unreadable/corrupt reclaim journal during recover; \
                     superseded blobs (if any) remain gc_orphan_blobs-reclaimable"
                );
                return Ok(ReclaimStats::default());
            }
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
        // B5: track whether every ATTEMPTED reclaim actually landed. A genuine unlink
        // error (e.g. EIO) means the blob is NOT yet reclaimed; we then KEEP the journal
        // so a future `recover()` retries it, rather than deleting the journal and
        // leaking the blob with nothing to drive the retry.
        let mut all_reclaimed = true;
        if execute {
            for blob_id in &journal.blobs {
                // A4: a journal is on-disk data (a planted/corrupt one could carry a
                // `..`/absolute "blob_id"). Skip any id that is not a syntactic uuid
                // BEFORE touching the filesystem, so neither the `.exists()` probe nor
                // the unlink can ever escape the bucket. (reclaim_blob also guards this,
                // but skipping here keeps blobs_deleted accurate and the intent local.)
                if !blob::is_valid_blob_id(blob_id) {
                    continue;
                }
                if blob::blob_path(&bucket_root, blob_id).exists() {
                    match blob::reclaim_blob(&bucket_root, blob_id) {
                        Ok(()) => stats.blobs_deleted += 1,
                        // A real unlink failure: leave this blob + keep the journal.
                        Err(_) => all_reclaimed = false,
                    }
                }
            }
        }
        // Remove the journal UNLESS an executed reclaim genuinely failed. When `execute`
        // is false (commit/delete didn't land — blobs are still-live-old or a later
        // journal owns them) `all_reclaimed` stays true and we drop the journal as
        // before; the fallback GC backstops genuine orphans. When a reclaim errored we
        // KEEP the journal so `recover()` retries (B5).
        if all_reclaimed {
            match std::fs::remove_file(journal_path) {
                Ok(()) => stats.journals_removed += 1,
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
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
        if key.contains('\0') {
            return Err(StorageError::PathTraversal);
        }
        if Path::new(key).is_absolute() {
            return Err(StorageError::PathTraversal);
        }
        // [REJECT — data loss, A2/empty-segment] Dot- and empty-segment key collision.
        // `escape_key_to_relpath` builds the manifest relpath by `PathBuf::push`-ing
        // each `/`-split segment. TWO ways distinct S3 keys collapse onto one manifest
        // path:
        //   * `push("")` is a no-op that COLLAPSES empty segments — keys `a` and `a/`,
        //     `a/b` and `a/b/`, `a//b` and `a/b` would all map to the SAME manifest.
        //   * `push(".")` (Component::CurDir) is likewise dropped by path iteration —
        //     so `a/b` and `a/./b`, and `a` and `a/.`, map to the SAME manifest →
        //     silent overwrite / DATA LOSS. (`..`/ParentDir would `pop`, escaping the
        //     key's intended subtree.)
        // Reject any `/`-split segment that is empty, `.`, or `..` up front, so the
        // key↔path map stays a collision-free, containment-safe bijection. Maps to 400
        // InvalidArgument via `PathTraversal`. KNOWN LIMITATION: a filesystem-backed
        // gateway cannot faithfully represent trailing-/empty-/dot-segment keys (real
        // S3 treats `a`, `a/`, and `a/./b` as distinct); we reject them rather than
        // risk collapsing them onto one manifest. (Subsumes the old `key.contains("..")`
        // substring guard: a literal `..` SEGMENT is rejected here, while a `..`
        // SUBSTRING inside a real segment — e.g. `a..b` — is a legitimate distinct key.)
        if key.split('/').any(|s| s.is_empty() || s == "." || s == "..") {
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

    /// A5 read-path hardening: verify `full` (an absolute path UNDER the bucket root)
    /// resolves entirely beneath that root with NO symlink in ANY component, via
    /// `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS)`. This closes the residual gap
    /// O_NOFOLLOW leaves — a planted INTERMEDIATE symlink under `current/`/`blobs/`
    /// (O_NOFOLLOW only guards the final component). Gracefully degrades to a no-op on
    /// kernels without openat2 (the existing O_NOFOLLOW + lexical containment remain).
    /// A containment failure is surfaced as `ObjectNotFound` (a planted-symlink read is
    /// treated as "no such object", consistent with the def-in-depth posture).
    fn verify_read_beneath(&self, bucket: &str, full: &Path) -> Result<()> {
        let root = self.bucket_root(bucket);
        let rel = match full.strip_prefix(&root) {
            Ok(r) => r,
            // `full` is always built under the bucket root by our callers; if not, fail
            // closed.
            Err(_) => return Err(StorageError::ObjectNotFound),
        };
        match super::directio::verify_beneath_no_symlinks(&root, rel) {
            Ok(()) => Ok(()),
            Err(_) => Err(StorageError::ObjectNotFound),
        }
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
        // C5: a `completed` marker means a successful Complete already finalized this
        // upload (and its best-effort rmdir failed or has not run yet). Reject any
        // further UploadPart/Complete/ListParts/Abort with NoSuchUpload — the uploadId
        // is no longer addressable even though its dir survives.
        if upload_dir.join("completed").exists() {
            return Err(StorageError::NoSuchUpload);
        }
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

        // A3: hold the bucket READ lock across head_bucket + ensure_infra + the
        // upload-dir creation, so a concurrent delete_bucket cannot remove the bucket
        // out from under a freshly-created in-flight upload (half-recreated bucket).
        let _bguard = self.rlock_bucket(bucket);

        self.head_bucket(bucket)?;
        self.ensure_infra(bucket)?;

        let upload_id = Uuid::new_v4().to_string();
        let upload_dir = self.arriving_root(bucket).join(&upload_id);
        std::fs::create_dir_all(upload_dir.join("parts"))?;
        // A6: under --fsync, make the new directory ENTRIES durable, not just the
        // file bytes. fsync the `arriving/` dir (so the `{upload_id}/` entry survives a
        // crash) and the `{upload_id}/` dir (so its `parts/` + upload.json entries do).
        // Without this a crash can lose an acknowledged CreateMultipartUpload.
        if self.fsync {
            super::directio::fsync_dir(&self.arriving_root(bucket))?;
            super::directio::fsync_dir(&upload_dir)?;
        }

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
        // A6: fsync the upload dir so the upload.json directory ENTRY is durable.
        if self.fsync {
            super::directio::fsync_dir(&upload_dir)?;
        }
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
        // G [LOW — S3 error precedence]: prove the bucket exists BEFORE resolving the
        // upload dir, so a request against a MISSING bucket gets NoSuchBucket (not
        // NoSuchUpload), matching S3 and put_object/create_multipart_upload. head_bucket
        // takes NO lock (lock-free symlink_metadata), so it runs ahead of the per-bucket
        // / per-key locks below without touching the lock ordering. (The bucket may still
        // race away after this check; the F-3 head_bucket re-check UNDER the bucket READ
        // lock below remains the authority — this only fixes the FIRST error code.)
        self.head_bucket(bucket)?;
        let upload_dir = self.upload_dir(bucket, upload_id)?;
        let upload = self.assert_upload_matches(&upload_dir, bucket, key)?;

        // F-3 deterministic test hook: park here AFTER the pre-lock validation but
        // BEFORE acquiring the bucket READ lock, so a test can deterministically
        // abort the upload + delete the bucket in the window the F-3 re-check guards.
        // No-op in production.
        upload_part_pre_lock_pause(bucket);

        // A3: hold the bucket READ lock across the part-blob write + ref install, so a
        // concurrent delete_bucket cannot reclaim the bucket mid-upload. Acquired BEFORE
        // the per-key lock below (global order: bucket -> key); `upload.bucket == bucket`
        // (asserted above), so this is the same bucket the per-key lock keys on.
        let _bguard = self.rlock_bucket(bucket);

        // F-3 [MED — phantom bucket]: RE-CHECK head_bucket UNDER the bucket READ lock
        // BEFORE write_blob. The pre-lock validation above ran lock-free; an abort +
        // DeleteBucket straggler could have torn the bucket down in the window before
        // we took the read lock. Without this re-check, `write_blob`'s
        // `create_dir_all(bucket/blobs/...)` would RECREATE the deleted bucket (a
        // phantom bucket that list_buckets would then report). put_object /
        // create_multipart_upload already re-check head_bucket under the read lock; only
        // upload_part skipped it. Under the read lock a concurrent delete_bucket (bucket
        // WRITE lock) cannot be mid-teardown, so once this passes the bucket stays.
        self.head_bucket(bucket)?;

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

        // D-3 [LOW]: RE-CHECK the upload under the per-key lock before installing the
        // ref. We validated `assert_upload_matches` BEFORE streaming the body (lock-free,
        // for the big I/O); a concurrent Complete/Abort could have removed the upload dir
        // (or planted the `completed` marker) in the window between that check and now.
        // Without this re-check the ref install would fail with a raw Io error (ENOENT on
        // the missing parts/ dir) -> 500, instead of a clean NoSuchUpload (404). The
        // re-check runs under the SAME per-key lock Complete/Abort serialize on, so once
        // it passes the dir cannot disappear under us for the rest of this critical
        // section. Roll back the just-written (now-orphan) blob before returning.
        if let Err(e) = self.assert_upload_matches(&upload_dir, bucket, key) {
            let _ = blob::reclaim_blob(&bucket_root, &info.blob_id);
            return Err(e);
        }

        // Atomically install the part ref. If a previous ref for this number existed,
        // capture its FULL bytes + blob_id: the bytes so a failed re-upload can RESTORE
        // the prior ref (C4), the blob_id so a SUCCESSFUL overwrite can reclaim the now-
        // orphaned old blob.
        let ref_path = upload_dir.join("parts").join(format!("{part_number:05}.ref"));
        let prev_ref: Option<(Vec<u8>, String)> = match read_nofollow(&ref_path) {
            Ok(d) => serde_json::from_slice::<PartRefFile>(&d)
                .ok()
                .map(|p| (d, p.blob_id)),
            Err(_) => None,
        };
        let prev_blob = prev_ref.as_ref().map(|(_, id)| id.clone());
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
        // A6/B4: under --fsync, fsync the `parts/` dir so the renamed `.ref` directory
        // ENTRY is durable — otherwise a crash can lose an acknowledged part-ref while
        // its part blob (already fsynced) lingers as an orphan. B4: PROPAGATE this error
        // rather than swallowing it — an UploadPart that ACKs a part whose dir entry is
        // not confirmed durable is a false durability promise. On failure, roll back the
        // just-installed ref + its new blob (matching the failure-arm posture above) so
        // the part number is left in its prior state and the client can retry the part.
        if self.fsync {
            let fsync_res = {
                #[cfg(test)]
                if FORCE_PARTS_FSYNC_FAIL.with(|c| c.get()) {
                    Err(io::Error::other("forced parts/ dir fsync failure (test)"))
                } else {
                    super::directio::fsync_dir(&upload_dir.join("parts"))
                }
                #[cfg(not(test))]
                super::directio::fsync_dir(&upload_dir.join("parts"))
            };
            if let Err(e) = fsync_res {
                // C4 [MED]: roll back to EXACTLY the pre-upload state. The rename above
                // already replaced any previous `.ref`, so removing the new ref + new
                // blob is not enough on an OVERWRITE — it would lose the PREVIOUS part.
                match &prev_ref {
                    Some((prev_bytes, _)) => {
                        // D-2 [MED — consistency]: restore the previous ref ATOMICALLY
                        // (temp + rename), and reclaim the NEW blob ONLY AFTER the restore
                        // lands. The old code wrote `prev_bytes` to `ref_path` IN PLACE
                        // (best-effort, ignoring the result) and then reclaimed the new
                        // blob unconditionally — so if that in-place write was torn or
                        // failed, the part could end up truncated OR referencing the
                        // already-reclaimed new blob (a dangling ref that breaks Complete).
                        // The invariant: a failed overwrite leaves the part CONSISTENT —
                        // either the old part (restored) or the new part — never a torn /
                        // dangling ref.
                        let restore_tmp = upload_dir
                            .join("parts")
                            .join(format!("{part_number:05}.ref.tmp.{}", Uuid::new_v4()));
                        let mut restore_guard = FileGuard::new(restore_tmp.clone());
                        let restored = {
                            #[cfg(test)]
                            if FORCE_PARTS_RESTORE_FAIL.with(|c| c.get()) {
                                Err(io::Error::other("forced restore failure (test)"))
                            } else {
                                write_nofollow(&restore_tmp, prev_bytes, self.fsync)
                                    .and_then(|()| super::directio::rename(&restore_tmp, &ref_path))
                            }
                            #[cfg(not(test))]
                            write_nofollow(&restore_tmp, prev_bytes, self.fsync)
                                .and_then(|()| super::directio::rename(&restore_tmp, &ref_path))
                        };
                        if restored.is_ok() {
                            restore_guard.disarm();
                            // Old blob is referenced again by the restored ref; reclaim
                            // ONLY the new blob, which is now unreferenced.
                            let _ = blob::reclaim_blob(&bucket_root, &info.blob_id);
                        } else {
                            // Restore FAILED. Do NOT reclaim the new blob: the part still
                            // references it via the (valid) new ref installed by the
                            // earlier rename, so leaving it keeps the part consistent
                            // (the NEW part) rather than dangling. The previous blob may
                            // leak as an orphan (gc_orphan_blobs-reclaimable). Surface the
                            // original fsync error so the caller knows the part is not
                            // durability-confirmed and can retry.
                            tracing::warn!(
                                upload_id = %upload_id,
                                part_number = part_number,
                                "UploadPart overwrite rollback could not restore the previous \
                                 ref; leaving the part referencing the new blob (consistent) \
                                 and keeping the new blob"
                            );
                        }
                    }
                    None => {
                        // Fresh part (no previous ref): just remove the new ref + blob.
                        let _ = std::fs::remove_file(&ref_path);
                        let _ = blob::reclaim_blob(&bucket_root, &info.blob_id);
                    }
                }
                return Err(e.into());
            }
        }
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
        // G [LOW — S3 error precedence]: prove the bucket exists BEFORE resolving the
        // upload dir, so a MISSING bucket yields NoSuchBucket (not NoSuchUpload), matching
        // S3. head_bucket is lock-free, so it runs ahead of the bucket READ + per-key
        // locks below without touching the lock ordering. The authoritative re-check stays
        // the head_bucket UNDER the bucket READ lock below (A3); this only fixes the FIRST
        // error code for an absent bucket.
        self.head_bucket(bucket)?;
        let upload_dir = self.upload_dir(bucket, upload_id)?;
        // B4: cross-check the request path matches the upload.
        let upload = self.assert_upload_matches(&upload_dir, bucket, key)?;
        // Defense in depth: re-validate the upload's stored bucket/key.
        self.validate_object_path(&upload.bucket, &upload.key)?;

        // H deterministic test hook: park here AFTER the pre-lock validation but BEFORE
        // acquiring the bucket READ + per-key locks, so a test can deterministically
        // ABORT the upload (removing the upload dir) in the exact window the H re-check
        // below guards. No-op in production.
        complete_pre_lock_pause(&upload.bucket, &upload.key);

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

        // A3: hold the bucket READ lock across head_bucket + validate + publish, so a
        // concurrent delete_bucket cannot tear the bucket down between our head_bucket
        // and our commit. Acquired BEFORE the per-key lock (global order: bucket -> key);
        // `upload.bucket == bucket` (asserted by assert_upload_matches).
        let _bguard = self.rlock_bucket(bucket);

        self.head_bucket(&upload.bucket)?;

        // Load the stored part refs (the immutable blobs each .ref points at). Take
        // the per-key WRITE lock around validate->build->commit, keyed by the
        // upload's STORED bucket/key — this serializes Complete vs a concurrent
        // Delete/Complete on the same key (E3 is structurally gone since part blobs
        // are immutable at unique paths, but the lock still serializes the manifest
        // swap + journal creation, §9).
        let _guard = self.lock_key(&upload.bucket, &upload.key);

        // H [LOW — S3 error code on a concurrent race]: RE-CHECK the upload UNDER the
        // per-key lock before reading its part refs. The `assert_upload_matches` above
        // ran BEFORE this lock; a concurrent Abort/Complete on the SAME key (which holds
        // this very lock across its remove_dir_all) could have removed the upload dir in
        // the window between that validation and now. Without this re-check `read_part_refs`
        // would see the gone parts/ dir, return an EMPTY map, and the per-part lookup would
        // report `InvalidPart` — the wrong S3 error for a vanished upload. Re-running
        // `assert_upload_matches` under the lock maps a removed/completed upload to the
        // correct `NoSuchUpload`. Once it passes, the per-key lock keeps the dir present
        // for the rest of this critical section (the racing Abort/Complete must take the
        // SAME lock to remove it). A genuine upload with NO parts uploaded still passes
        // this re-check (the dir + upload.json exist) and falls through to the existing
        // `InvalidPart` path on the per-part lookup below — preserving that distinction.
        self.assert_upload_matches(&upload_dir, &upload.bucket, &upload.key)?;
        let stored = Self::read_part_refs(&upload_dir)?;
        let bucket_root = self.bucket_root(&upload.bucket);

        // B1 [HIGH — live data loss]: the committed manifest must own its part blobs
        // under FRESH ids that the upload's `.ref`s do NOT name. Otherwise the upload's
        // refs and the live manifest would share blob ids, so a surviving upload dir
        // (rmdir failed, or a crash after publish) lets a later abort/gc/Complete-RETRY
        // reclaim those shared ids — deleting the LIVE object's blobs (the commit_nonce
        // rule cannot protect this: old & new share ids). After A7's stat, we MOVE each
        // part blob to a new manifest-owned uuid via a same-filesystem `rename` (O(1),
        // NO data copy — the one-pass-MD5 / no-copy payload invariant is preserved); the
        // manifest references the NEW id and the surviving refs point at the moved-away
        // (now-ENOENT) OLD id, so any later reclaim through those refs is a no-op.
        //
        // `moved` records (new_manifest_id, original_ref_id) so a failure of a LATER
        // rename OR the commit can roll the moves back (move each blob to its original
        // ref id), leaving the upload intact and RETRYABLE (E2). A crash MID-rename is
        // acceptable: the manifest is not committed yet, so no live object is affected;
        // the partially-moved blobs become orphans the opt-in `gc_orphan_blobs` reclaims.
        let mut manifest_parts: Vec<ManifestPartRef> = Vec::with_capacity(parts.len());
        let mut md5_concat: Vec<u8> = Vec::with_capacity(parts.len() * 16);
        let mut total: u64 = 0;
        let mut moved: Vec<(String, String)> = Vec::with_capacity(parts.len());

        // Roll back any blobs already moved to manifest-owned ids, restoring them to
        // their original ref ids so the upload stays retryable. Best-effort on unwind.
        let rollback_moves = |moved: &[(String, String)]| {
            for (new_id, orig_id) in moved {
                let _ = blob::move_blob_back(&bucket_root, new_id, orig_id);
            }
        };

        for p in parts {
            let stored_ref = match stored.get(&(p.part_number as u32)) {
                Some(r) => r,
                None => {
                    rollback_moves(&moved);
                    return Err(StorageError::InvalidPart);
                }
            };
            // F15: an empty client ETag is NOT a free pass — reject it, then compare.
            let provided = p.etag.trim_matches('"');
            if provided.is_empty() || provided != stored_ref.md5_hex {
                rollback_moves(&moved);
                return Err(StorageError::InvalidPart);
            }
            // The blob backing the ref must be a syntactically valid uuid (it always
            // is when written by UploadPart; this guards a hand-tampered ref).
            if !blob::is_valid_blob_id(&stored_ref.blob_id) {
                rollback_moves(&moved);
                return Err(StorageError::InvalidPart);
            }
            // A7: do not trust the ref blindly — STAT the referenced blob before
            // committing. The ref records a size/md5, but the blob itself could be
            // MISSING or SHORT (e.g. the A1 abort-vs-complete race outcome, a partial
            // crash, or a tampered ref). Verify the blob exists as a regular file and
            // its on-disk size equals the ref's recorded size; otherwise reject the
            // whole completion as InvalidPart so a manifest is NEVER published pointing
            // at a missing/short part. symlink_metadata does not follow a symlinked
            // blob leaf (consistent with the O_NOFOLLOW read posture).
            let blob_p = blob::blob_path(&bucket_root, &stored_ref.blob_id);
            match std::fs::symlink_metadata(&blob_p) {
                Ok(m) if m.file_type().is_file() && m.len() == stored_ref.size => {}
                _ => {
                    rollback_moves(&moved);
                    return Err(StorageError::InvalidPart);
                }
            }
            // B1: hand the blob to a fresh manifest-owned id (no data copy). On failure
            // roll back the moves done so far and leave the upload intact.
            let new_id = match blob::move_blob_to_new_id(&bucket_root, &stored_ref.blob_id) {
                Ok(id) => id,
                Err(e) => {
                    rollback_moves(&moved);
                    return Err(e.into());
                }
            };
            moved.push((new_id.clone(), stored_ref.blob_id.clone()));
            // C1 [HIGH — durability]: under --fsync, make the moved blob's NEW fanout
            // DIRENT durable (move_blob_to_new_id renames into a possibly-fresh fanout
            // dir without fsyncing it) BEFORE publish() commits the manifest that
            // references this new id — same ordering rule as the single-PUT path. On
            // failure roll the moves back so the upload stays retryable (E2).
            if self.fsync {
                if let Err(e) = blob::fsync_blob_dir(&bucket_root, &new_id) {
                    rollback_moves(&moved);
                    return Err(StorageError::Io(e));
                }
            }

            let raw = hex::decode(&stored_ref.md5_hex)
                .map_err(|_| StorageError::InvalidPart)?;
            md5_concat.extend_from_slice(&raw);
            total += stored_ref.size;
            manifest_parts.push(ManifestPartRef {
                part_number: p.part_number as u32,
                blob_id: new_id,
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

        // COMMIT via the §3 publish path. The part blobs now live under FRESH manifest-
        // owned ids (moved above), so publish just stages+journals+renames the manifest
        // — no part data is copied. On a pre-commit failure we ROLL BACK the moves
        // (restoring the blobs to their original ref ids) and return Err WITHOUT having
        // removed the upload dir -> the upload stays RETRYABLE (E2).
        match self.publish(&upload.bucket, &upload.key, &manifest) {
            Ok(()) => {}
            // E-1: a `CommitNotDurable` means the manifest COMMITTED (rename landed; the
            // part blobs already live under their fresh manifest-owned ids) but only the
            // post-commit dir fsync failed. The new object is LIVE, so we must NOT
            // rollback_moves (restoring the blobs to their ref ids would strand the live
            // manifest on missing blobs). The upload dir is left intact; the write is not
            // acked and recover() settles it. Propagate the not-acked error.
            Err(e @ StorageError::CommitNotDurable(_)) => return Err(e),
            Err(e) => {
                rollback_moves(&moved);
                return Err(e);
            }
        }

        // C5 [S3 fidelity]: mark the upload COMPLETED before tearing it down. The rmdir
        // below is best-effort, so a surviving uploadId would otherwise stay addressable
        // (re-UploadPart/Complete/ListParts would still find a live-looking dir). Write a
        // `completed` marker FIRST: `assert_upload_matches` rejects any subsequent
        // mutation/list on a marked upload with `NoSuchUpload` even if the rmdir fails.
        // The marker is durable under --fsync so it survives a crash between marking and
        // a (failed/interrupted) rmdir.
        //
        // D-4 [LOW — hygiene]: the marker is the DURABLE backstop that makes a surviving
        // uploadId non-addressable, so its write failure must at least be LOGGED (the old
        // `let _ =` swallowed it silently). This is written POST-commit — the object is
        // already live — so we do NOT fail the Complete response if only the marker (or
        // rmdir) fails. Residual: if BOTH the marker write AND the rmdir fail, the
        // uploadId stays addressable until GC/recover cleans the dir; that is a GC/hygiene
        // residual (NOT corruption — the moved-away part blobs make any retry-reclaim a
        // harmless no-op), so it is acceptable as a LOW.
        if let Err(e) = write_nofollow(&upload_dir.join("completed"), b"1", self.fsync) {
            tracing::warn!(
                upload_id = %upload_id,
                error = %e,
                "could not write the multipart `completed` marker after a committed Complete; \
                 the uploadId may stay addressable until GC removes its dir (object is live)"
            );
        }

        // Pass J [LOW — dirent durability]: make the `completed` marker's DIRENT durable
        // (mirrors create_multipart_upload's fsync_dir at the upload.json site) so a crash
        // before the best-effort rmdir cannot lose the dirent and re-expose the completed
        // uploadId as in-flight. Non-fatal: the object is already durably published, so this
        // is a hygiene backstop, not a commit gate. MUST come BEFORE the remove_dir_all below
        // (the rmdir already tolerates a surviving dir).
        if self.fsync {
            #[cfg(test)]
            bump_pass_i_fsync();
            if let Err(e) = super::directio::fsync_dir(&upload_dir) {
                tracing::warn!(
                    upload_id = %upload_id,
                    error = %e,
                    "could not fsync the completed-marker dir (object is live)"
                );
            }
        }

        // Success: remove the upload working dir. This is now SAFE as best-effort — the
        // upload's `.ref`s point at the moved-away (ENOENT) original ids, so even if the
        // rmdir fails (or a crash hits here) any later abort/gc/Complete-RETRY reclaim
        // through those dangling refs is a harmless no-op that can never touch the live
        // object's freshly-id'd blobs.
        if let Err(e) = std::fs::remove_dir_all(&upload_dir) {
            if e.kind() != io::ErrorKind::NotFound {
                tracing::warn!(
                    upload_id = %upload_id,
                    error = %e,
                    "best-effort rmdir of the completed upload dir failed; the `completed` \
                     marker keeps the uploadId non-addressable, dir is GC-reclaimable"
                );
            }
        }
        Ok(etag)
    }

    /// AbortMultipartUpload: delete the upload's part blobs (from the stored refs)
    /// and remove the working dir. Signature identical to
    /// `Filesystem::abort_multipart_upload`.
    pub fn abort_multipart_upload(&self, bucket: &str, key: &str, upload_id: &str) -> Result<()> {
        // G [LOW — S3 error precedence]: prove the bucket exists BEFORE resolving the
        // upload dir, so a MISSING bucket yields NoSuchBucket (not NoSuchUpload), matching
        // S3. (Abort previously never called head_bucket at all.) head_bucket is lock-free,
        // so it runs ahead of the per-key lock below without touching the lock ordering.
        self.head_bucket(bucket)?;
        let upload_dir = self.upload_dir(bucket, upload_id)?;
        let upload = self.assert_upload_matches(&upload_dir, bucket, key)?;
        let bucket_root = self.bucket_root(bucket);

        // A1 [HIGH — abort-vs-complete race]: take the SAME per-key WRITE lock
        // `complete_multipart_upload` holds across read_part_refs -> manifest-build ->
        // publish, keyed by the upload's STORED bucket/key (the identical shard).
        // Without it, Abort could reclaim part blobs while a concurrent Complete has
        // already snapshotted those refs into a manifest it is about to publish —
        // committing a LIVE manifest that references just-deleted blobs (a torn object).
        // Holding the lock serializes the two: a Complete in flight finishes (publishing
        // intact blobs + removing the upload dir) before Abort reclaims, after which
        // Abort finds the dir gone and no-ops. No other locking op is invoked while this
        // guard is held, so there is no deadlock. (Lock-ordering invariant: Abort is not
        // a bucket-infra writer, so it takes no bucket lock — only the per-key lock.)
        let _guard = self.lock_key(&upload.bucket, &upload.key);

        // Re-read the refs UNDER the lock (a concurrent Complete that won the race has
        // already removed the dir; read_part_refs then returns an empty set and the
        // remove_dir_all below is a no-op).
        if let Ok(refs) = Self::read_part_refs(&upload_dir) {
            for r in refs.values() {
                let _ = blob::reclaim_blob(&bucket_root, &r.blob_id);
            }
        }
        match std::fs::remove_dir_all(&upload_dir) {
            Ok(()) => Ok(()),
            // A Complete that committed first already removed the dir -> idempotent.
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /// ListParts: the stored part refs as `PartInfo`, sorted by part number.
    /// Signature identical to `Filesystem::list_parts`.
    pub fn list_parts(&self, bucket: &str, key: &str, upload_id: &str) -> Result<Vec<PartInfo>> {
        // G [LOW — S3 error precedence]: prove the bucket exists BEFORE resolving the
        // upload dir, so a MISSING bucket yields NoSuchBucket (not NoSuchUpload), matching
        // S3. (ListParts previously never called head_bucket at all.) head_bucket is
        // lock-free; ListParts takes no other lock, so this changes no lock ordering.
        self.head_bucket(bucket)?;
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
    ///
    /// B2 [accepted-by-design]: this reads up to a bounded number of upload dirs
    /// BEFORE truncating to `cap`. The cost is bounded by the number of IN-FLIGHT
    /// uploads (operator-controlled — every dir scanned is a live CreateMultipartUpload
    /// that has not yet been Completed/Aborted/GC'd), exactly like the accepted whole-
    /// bucket [`list_objects`] walk that is bounded by the number of live objects. To
    /// keep a pathological `arriving/` (e.g. many never-finished uploads) from forcing
    /// an unbounded scan, we stop after a GENEROUS hard cap of `MAX_UPLOADS_CAP * 4`
    /// candidate dirs and report `is_truncated` — the page is still correct, just
    /// capped. Documented in REDESIGN.md §13.6.
    pub fn list_multipart_uploads(
        &self,
        bucket: &str,
        max_uploads: usize,
    ) -> Result<(Vec<MultipartUpload>, bool)> {
        self.head_bucket(bucket)?;
        let cap = max_uploads.min(MAX_UPLOADS_CAP);
        // Generous hard scan cap so a pathologically large `arriving/` cannot force an
        // unbounded readdir; well above any realistic in-flight-upload count.
        let scan_cap = MAX_UPLOADS_CAP.saturating_mul(4);
        let arriving = self.arriving_root(bucket);
        let rd = match std::fs::read_dir(&arriving) {
            Ok(rd) => rd,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok((Vec::new(), false)),
            Err(e) => return Err(e.into()),
        };
        let mut out = Vec::new();
        let mut scanned = 0usize;
        let mut scan_capped = false;
        for entry in rd {
            let entry = entry?;
            // Only `{uuid}/` working dirs are uploads; staged `{uuid}.manifest`
            // files (single-PUT/Complete temps) are not.
            if !entry.file_type()?.is_dir() {
                continue;
            }
            scanned += 1;
            if scanned > scan_cap {
                scan_capped = true;
                break;
            }
            // C5: a completed-but-not-yet-removed upload dir is no longer addressable;
            // do not list it (consistent with assert_upload_matches' NoSuchUpload).
            if entry.path().join("completed").exists() {
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
        let is_truncated = scan_capped || out.len() > cap;
        if out.len() > cap {
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
        // B3 [traversal/DoS]: the client prefix is UNTRUSTED. A dir-portion like
        // `../../x` (or an absolute path) would, if pushed verbatim, root the walk
        // OUTSIDE `current/` and make the server recursively readdir arbitrary host
        // directories (unbounded-I/O DoS; results are suppressed by the strip_prefix +
        // `starts_with(prefix)` filter, but the walk still happens). The prefix is only
        // a FILTER, never a path: if any dir-portion segment is `..`/`.`/empty, or the
        // dir-portion is absolute, we DROP the prune optimization and root at
        // `current_root`. The existing per-key `starts_with(prefix)` filter then matches
        // nothing for such an escaping prefix (correct, no 400). A clean prefix still
        // prunes to its subtree below.
        let dir_safe = !dir_portion.is_empty()
            && !Path::new(dir_portion).is_absolute()
            && dir_portion
                .split('/')
                .all(|seg| !seg.is_empty() && seg != "." && seg != "..");
        let mut root = current_root.to_path_buf();
        if dir_safe {
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
    fn delete_bucket_lock_serializes_against_put_deterministic() {
        // A3 [HIGH-ish], LOAD-BEARING. delete_bucket takes the per-BUCKET WRITE lock
        // across its emptiness check + remove_dir_all; an object writer (put_object)
        // takes the same bucket's READ lock around its head_bucket + ensure_infra +
        // publish. This serializes a writer against a concurrent delete_bucket without
        // serializing writers against each other or reads, closing the lost-write /
        // half-recreated-bucket race.
        //
        // Interleaving: a delete_bucket thread parks HOLDING the bucket WRITE lock
        // (deterministic hook) while the bucket is still empty. A concurrent put to that
        // bucket must BLOCK on the bucket READ lock (note_contention fires). Release the
        // delete: it sees an empty bucket and removes it; the put then resumes and fails
        // head_bucket with BucketNotFound. Final state is CONSISTENT — the bucket is
        // gone (not half-recreated) and the put was never acknowledged (no lost write).
        //
        // Fail-without-fix: remove the bucket READ lock from put_object (or the WRITE
        // lock from delete_bucket) and the put no longer blocks — the contention wait
        // TIMES OUT (None), asserted as a clean failure; and the put could race the
        // delete to recreate bucket infra (a half-recreated bucket). Uses the dedicated
        // `bucket_pause` Condvar handshake (no sleeps); stable across runs.
        use std::sync::Arc;
        let _serial = bucket_pause::serialize_test(); // single global hook slot.
        let dir = tempfile::tempdir().unwrap();
        let fs = Arc::new(CasStore::with_fsync(dir.path(), false));
        fs.create_bucket("bkt").unwrap();
        let bk = dir.path().join("bkt");

        let hook = bucket_pause::Hook::arm("bkt");

        // Thread A: delete_bucket. Parks holding the bucket WRITE lock (bucket empty).
        let fa = Arc::clone(&fs);
        let a = std::thread::spawn(move || fa.delete_bucket("bkt"));
        hook.wait_delete_parked();

        // Thread B: put to the same bucket. With the lock it BLOCKS on the bucket READ
        // lock; without it, it proceeds and races the delete.
        let fb = Arc::clone(&fs);
        let b = std::thread::spawn(move || {
            fb.put_object("bkt", "racy", &b"new body"[..], "", BTreeMap::new())
        });

        // A blocked put fires note_contention; a lock-free put never does, so a missing
        // lock TIMES OUT (None) -> clean failure rather than a hang.
        let contended = hook.wait_writer_contention_timeout(std::time::Duration::from_secs(5));

        let (ra, rb) = match contended {
            Some(()) => {
                // Real lock: B parked on the bucket READ lock. Release A; it removes the
                // (empty) bucket, frees the lock; B resumes and fails head_bucket.
                hook.release();
                (a.join().unwrap(), b.join().unwrap())
            }
            None => {
                // Lock missing: B raced ahead. Join B, then release A.
                let rb = b.join().unwrap();
                hook.release();
                (a.join().unwrap(), rb)
            }
        };
        bucket_pause::Hook::disarm();

        // LOAD-BEARING #1: the put must have BLOCKED on the bucket lock. Without the
        // lock pairing this is None (timeout) and fails here.
        assert!(
            contended.is_some(),
            "the racing put did NOT block on the per-bucket lock — put_object/delete_bucket \
             are not serialized; a writer can race a bucket teardown"
        );

        // LOAD-BEARING #2: final state is consistent.
        assert!(ra.is_ok(), "delete_bucket failed: {ra:?}");
        assert!(
            !bk.exists(),
            "bucket must be fully gone — not half-recreated by the racing put"
        );
        assert!(
            matches!(rb, Err(StorageError::BucketNotFound)),
            "the put that lost the race must fail BucketNotFound (no acknowledged lost write), got {rb:?}"
        );
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
    fn read_path_rejects_planted_intermediate_symlink_under_current() {
        // A5 [LOW — read-path hardening]. O_NOFOLLOW only guards the FINAL path
        // component, so a planted INTERMEDIATE directory symlink under `current/` could
        // redirect a manifest read. The A5 openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS)
        // verification (`verify_read_beneath`) rejects a symlink at ANY component.
        //
        // Setup: PUT a real object at key `realdir/secret` -> manifest at
        // current/realdir/secret.s3gw-live.meta (the LEAF is a real file). Then plant an
        // intermediate dir symlink current/linkdir -> realdir. A GET of key
        // `linkdir/secret` builds manifest path current/linkdir/secret.s3gw-live.meta:
        // O_NOFOLLOW does NOT catch the `linkdir` INTERMEDIATE symlink (the leaf is a
        // real file), so WITHOUT A5 the read would follow the symlink and serve the
        // object. WITH A5, openat2 rejects the intermediate symlink -> ObjectNotFound.
        //
        // Fail-without-fix: remove the `verify_read_beneath` calls and this test FAILS —
        // GET `linkdir/secret` returns the bytes via the intermediate symlink. (Skips
        // gracefully on a kernel without openat2: there `verify_beneath_no_symlinks`
        // no-ops and the read follows the symlink; we detect that and skip the assertion
        // so the test does not flake on old kernels.)
        let (dir, fs) = store();
        let bk = dir.path().join("bkt");
        fs.put_object("bkt", "realdir/secret", &b"SECRET BYTES"[..], "", BTreeMap::new())
            .unwrap();

        // Plant the intermediate dir symlink current/linkdir -> realdir (relative).
        let current = bk.join("current");
        std::os::unix::fs::symlink("realdir", current.join("linkdir")).unwrap();

        // Probe whether openat2 BENEATH|NO_SYMLINKS is actually enforced on this kernel
        // (a clean path must succeed; an intermediate symlink must be rejected). If the
        // syscall is unavailable, verify_beneath_no_symlinks no-ops -> skip the assertion.
        let rel = Path::new("current").join("linkdir").join("secret.s3gw-live.meta");
        let enforced =
            super::super::directio::verify_beneath_no_symlinks(&bk, &rel).is_err();
        if !enforced {
            eprintln!("openat2 BENEATH|NO_SYMLINKS not enforced on this kernel; skipping A5 assertion");
            return;
        }

        // WITH A5: GET via the intermediate symlink is rejected (treated as not-found),
        // never serving the bytes through the planted symlink.
        match fs.get_object("bkt", "linkdir/secret", None) {
            Err(StorageError::ObjectNotFound) => { /* A5 rejected the intermediate symlink */ }
            Err(e) => panic!("A5: expected ObjectNotFound, got error {e:?}"),
            Ok(res) => {
                let got = read_all(res.body);
                panic!(
                    "A5: GET followed a planted intermediate symlink and served {} bytes",
                    got.len()
                );
            }
        }
        // HEAD likewise.
        assert!(matches!(
            fs.head_object("bkt", "linkdir/secret"),
            Err(StorageError::ObjectNotFound)
        ));
        // The legitimate (non-symlinked) key still reads fine.
        assert_eq!(
            read_all(fs.get_object("bkt", "realdir/secret", None).unwrap().body),
            b"SECRET BYTES"
        );
    }

    #[test]
    fn dot_segment_key_collision_rejected_no_data_loss() {
        // A2 [HIGH — DATA LOSS], LOAD-BEARING. Path iteration drops a `.` (CurDir)
        // component, so `manifest_path("a/b") == manifest_path("a/./b")` and
        // `a == a/.` — two DISTINCT S3 keys would silently map onto ONE manifest →
        // the second PUT would overwrite the first. `validate_object_path_lexical`
        // must reject any `/`-split segment that is `.`, `..`, or empty, so this can
        // never happen on either the WRITE or the READ path.
        //
        // Fail-without-fix: delete the `s == "."`/`s == ".."` arm from the segment
        // check in `validate_object_path_lexical` and this test FAILS — PUT `a/./b`
        // would succeed (StorageError::PathTraversal no longer raised) and clobber the
        // body stored for `a/b`.
        let (_dir, fs) = store();

        // PUT the legitimate key `a/b`, then attempt the colliding `a/./b`.
        fs.put_object("bkt", "a/b", &b"FIRST body for a/b"[..], "", BTreeMap::new())
            .unwrap();
        let dot = fs.put_object("bkt", "a/./b", &b"SECOND body via a/./b"[..], "", BTreeMap::new());
        assert!(
            matches!(dot, Err(StorageError::PathTraversal)),
            "PUT a/./b must be rejected (400/PathTraversal), got {dot:?}"
        );
        // The FIRST body is intact — no silent overwrite.
        assert_eq!(
            read_all(fs.get_object("bkt", "a/b", None).unwrap().body),
            b"FIRST body for a/b",
            "the `.`-segment key must not have overwritten a/b"
        );
        // GET of the rejected key is itself rejected (read path inherits the check).
        assert!(matches!(
            fs.get_object("bkt", "a/./b", None),
            Err(StorageError::PathTraversal)
        ));

        // The other dot/dot-dot/empty-segment forms are all rejected, on PUT and GET.
        for bad in ["a/.", "./a", "a/../b", ".", "..", "a/", "/a", "a//b"] {
            assert!(
                matches!(
                    fs.put_object("bkt", bad, &b"x"[..], "", BTreeMap::new()),
                    Err(StorageError::PathTraversal)
                ),
                "PUT {bad:?} must be rejected"
            );
            assert!(
                matches!(fs.head_object("bkt", bad), Err(StorageError::PathTraversal)),
                "HEAD {bad:?} must be rejected"
            );
        }

        // Regression guard: a `..` SUBSTRING inside a real segment is a DISTINCT,
        // legitimate key (not a traversal) and must still round-trip — the fix
        // replaced the old over-broad `key.contains("..")` with a per-segment check.
        fs.put_object("bkt", "a..b", &b"double-dot substring"[..], "", BTreeMap::new())
            .unwrap();
        assert_eq!(
            read_all(fs.get_object("bkt", "a..b", None).unwrap().body),
            b"double-dot substring"
        );
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
    fn abort_lock_serializes_against_complete_deterministic() {
        // A1 [HIGH], LOAD-BEARING. `abort_multipart_upload` takes the SAME per-key
        // WRITE lock `complete_multipart_upload` holds across read_part_refs ->
        // manifest-build -> publish, keyed by the upload's STORED bucket/key. Without
        // it, a concurrent Abort can reclaim part blobs while Complete has already
        // snapshotted those refs into a manifest it is about to commit — publishing a
        // LIVE manifest that references just-deleted blobs (a torn object).
        //
        // Interleaving (one upload of key K; part1=blob B1, part2=blob B2):
        //   A (Complete): take the per-key lock; read_part_refs -> manifest references
        //      B1+B2; publish stages+journals, then PARKS at the publish critical window
        //      (pre-commit-rename) STILL HOLDING the lock.
        //   B (Abort same upload): take the per-key lock around its reclaim.
        //     - real lock => B BLOCKS on lock_key (note_lock_contention fires). Release
        //       A: A commits manifest(B1+B2) and removes the upload dir, frees the lock.
        //       B resumes, finds the dir GONE -> reclaims nothing, no-ops. The committed
        //       object references intact B1+B2.
        //     - lock gone => B does NOT block; concurrently with A parked in the window
        //       it reads the refs and RECLAIMS B1+B2. Release A: A commits manifest(B1+B2)
        //       on top of DELETED blobs -> torn object (GET errors / blobs missing).
        //
        // Fail-without-fix: remove the `lock_key` acquisition from `abort_multipart_upload`
        // and this test FAILS — B never blocks (disposition wait TIMES OUT, asserted as a
        // clean failure) and, having reclaimed B1+B2 mid-Complete, the committed manifest
        // references missing blobs (assert_object_consistent / GET fail). Uses the same
        // deterministic Condvar handshake as the UploadPart-vs-Complete test (no sleeps).
        use std::sync::Arc;
        let _serial = publish_pause::serialize_test(); // single global hook slot.
        let dir = tempfile::tempdir().unwrap();
        let fs = Arc::new(CasStore::with_fsync(dir.path(), false));
        fs.create_bucket("bkt").unwrap();
        let bk = dir.path().join("bkt");
        let key = "hot.mpu";

        let upload_id = fs
            .create_multipart_upload("bkt", key, "text/mpu", BTreeMap::new())
            .unwrap();
        let part1 = vec![0xA1u8; 9000];
        let part2 = vec![0xC3u8; 5003];
        let etag1 = fs.upload_part("bkt", key, &upload_id, 1, &part1[..]).unwrap();
        let etag2 = fs.upload_part("bkt", key, &upload_id, 2, &part2[..]).unwrap();
        assert_eq!(count_blobs(&bk), 2, "B1+B2 after the two part uploads");

        let hook = publish_pause::PauseHook::arm(&format!("bkt/{key}"));

        // Writer A: Complete. Parks in the publish window holding the per-key lock with a
        // staged manifest referencing B1+B2.
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
        hook.wait_window_arrived();

        // Writer B: Abort the SAME upload. With the lock it blocks on lock_key; without
        // it, it reclaims B1+B2 lock-free.
        let fb = Arc::clone(&fs);
        let uid_b = upload_id.clone();
        let b = std::thread::spawn(move || fb.abort_multipart_upload("bkt", key, &uid_b));

        // Abort blocked on the per-key lock fires note_lock_contention; a lock-free Abort
        // never reaches the publish window, so a missing lock yields NO signal -> the
        // bounded wait times out (None) and surfaces as a clean failure rather than a hang.
        let disposition = hook.wait_b_disposition_timeout(std::time::Duration::from_secs(5));

        let (ra, rb) = match disposition {
            Some(true) => {
                // Real lock: B parked on lock_key. Release A; it commits + removes the
                // upload dir, then B resumes (dir gone) and no-ops.
                hook.release();
                (a.join().unwrap(), b.join().unwrap())
            }
            _ => {
                // Lock missing/neutered: B raced its reclaim ahead unsynchronized. Join B
                // first (it reclaimed B1+B2), THEN release A so its commit lands a manifest
                // referencing the now-deleted blobs.
                let rb = b.join().unwrap();
                hook.release();
                (a.join().unwrap(), rb)
            }
        };
        publish_pause::PauseHook::disarm();

        // LOAD-BEARING #1: Abort must have BLOCKED on the per-key lock. Without abort's
        // lock_key this is None (timeout) and fails here.
        assert_eq!(
            disposition,
            Some(true),
            "the racing Abort did NOT block on the per-key lock — `abort_multipart_upload` \
             is not serializing its reclaim against the in-flight Complete"
        );

        assert!(ra.is_ok(), "Complete failed: {ra:?}");
        // Abort, resuming after the dir was removed by Complete, no-ops successfully.
        assert!(rb.is_ok(), "Abort should no-op after the upload completed: {rb:?}");

        // LOAD-BEARING #2: the committed object is internally consistent — its manifest
        // references only intact, existing blobs. With the lock removed, Abort reclaimed
        // B1+B2 mid-Complete and this trips ("blob missing").
        assert_object_consistent(&fs, "bkt", key)
            .unwrap_or_else(|e| panic!("completed multipart object inconsistent: {e}"));

        let body = read_all(fs.get_object("bkt", key, None).unwrap().body);
        let mut want = part1.clone();
        want.extend_from_slice(&part2);
        assert_eq!(body, want, "GET must return the intact part1++part2 (B1+B2) bytes");

        // Exactly the committed manifest's two blobs remain (no missing/dangling blob).
        assert_eq!(
            count_blobs(&bk),
            2,
            "exactly the committed manifest's two blobs (B1+B2) must remain"
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

    #[test]
    fn apply_journal_keeps_journal_when_reclaim_unlink_fails_then_recover_retries() {
        // B5 [LOW — blob leak], LOAD-BEARING for the keep-journal decision. The reclaim
        // step unlinks blobs then removes the journal. Before the fix the journal was
        // removed UNCONDITIONALLY (`let _ = reclaim_blob(...)`), so a transient unlink
        // error (e.g. EIO) leaked the blob with NO journal left to drive a retry. The
        // fix keeps the journal whenever any reclaim genuinely errored, so `recover()`
        // retries it.
        //
        // We force a real unlink error by making the blob's fanout PARENT directory
        // read-only (no write perm -> `remove_file` fails EACCES for a non-root user).
        //
        // Fail-without-fix: revert to unconditional `remove_file(journal)` and the
        // first assert (journal still present) FAILS.
        use std::os::unix::fs::PermissionsExt as _;
        let (dir, fs) = store();
        let bk = dir.path().join("bkt");
        let info = blob::write_blob(&bk, &b"blob whose unlink will fail"[..]).unwrap();
        let blob_p = blob::blob_path(&bk, &info.blob_id);
        let blob_parent = blob_p.parent().unwrap().to_path_buf();

        let jpath = bk.join("deleted").join(format!("{}.journal", Uuid::new_v4()));
        let j = Journal {
            mode: JournalMode::Delete,
            supersedes_key: "gone".into(), // absent key -> delete journal EXECUTES
            commit_nonce: String::new(),
            expected_new_etag: String::new(),
            blobs: vec![info.blob_id.clone()],
        };
        fs.write_journal(&jpath, &j).unwrap();

        // Make the blob un-unlinkable: drop write permission on its parent dir.
        let orig_mode = std::fs::metadata(&blob_parent).unwrap().permissions();
        std::fs::set_permissions(&blob_parent, std::fs::Permissions::from_mode(0o555)).unwrap();

        // apply_journal: the unlink fails -> the journal is KEPT (not removed), and the
        // blob is still present.
        let stats = fs.apply_journal("bkt", &jpath).unwrap();
        // Restore perms regardless of outcome so the temp dir cleans up.
        std::fs::set_permissions(&blob_parent, orig_mode).unwrap();

        assert_eq!(stats.blobs_deleted, 0, "the unlink failed -> nothing counted deleted");
        assert_eq!(stats.journals_removed, 0, "the journal must NOT be removed on reclaim failure");
        assert!(jpath.exists(), "journal must remain so recover() can retry the reclaim");
        assert!(blob_p.exists(), "the blob is still present (its unlink failed)");

        // recover() now retries (perms restored): the blob is reclaimed and the journal
        // removed.
        let rec = fs.recover().unwrap();
        assert!(rec.journals_processed >= 1, "recover() should have processed the kept journal");
        assert!(!blob_p.exists(), "recover() retry reclaims the blob");
        assert!(!jpath.exists(), "recover() retry removes the journal once the blob is gone");
    }

    #[test]
    fn planted_journal_with_escaping_blob_id_does_not_unlink_outside() {
        // A4 [HIGH], LOAD-BEARING. recover()/apply_journal unlinks blob ids listed in a
        // `deleted/{uuid}.journal`, which is ON-DISK data. A planted/corrupt journal
        // could list a `..`-laden or absolute "blob_id"; without validation `blob_path`
        // joins it onto the bucket root and the reclaim unlinks an arbitrary host file.
        // The fix skips any id that is not a syntactic uuid (in both apply_journal and
        // blob::reclaim_blob), so the outside target survives while a valid uuid in the
        // SAME journal is still reclaimed.
        //
        // Fail-without-fix: drop the `is_valid_blob_id` guards and this test FAILS —
        // recover() unlinks the planted outside file.
        let (dir, fs) = store();
        let bk = dir.path().join("bkt");

        // An external file the planted journal will try to unlink via traversal.
        let outside = tempfile::tempdir().unwrap();
        let victim = outside.path().join("DO-NOT-DELETE");
        std::fs::write(&victim, b"precious host file").unwrap();
        // A relative `..`-chain from blobs/{ab}/{cd}/ back out of the bucket to `victim`.
        // blob_path joins the WHOLE id after a 2x2 fanout of its first 4 chars, so the
        // on-disk resolution is blobs/<a><b>/<c><d>/<id>; climb 5 levels to escape
        // bucket_root then into the outside tmpdir.
        let victim_str = victim.to_string_lossy().into_owned();
        let escaping_id = format!("../../../../..{victim_str}"); // absolute-ish via leading ..
        let absolute_id = victim_str.clone(); // a bare absolute path as an "id"

        // A genuine orphan blob (valid uuid) that the SAME journal also lists — it MUST
        // still be reclaimed, proving the guard skips only the bad ids.
        let good = blob::write_blob(&bk, &b"genuinely orphaned"[..]).unwrap();

        let jpath = bk.join("deleted").join(format!("{}.journal", Uuid::new_v4()));
        let j = Journal {
            mode: JournalMode::Delete,
            supersedes_key: "gone".into(),
            commit_nonce: String::new(),
            expected_new_etag: String::new(),
            blobs: vec![escaping_id, absolute_id, good.blob_id.clone()],
        };
        fs.write_journal(&jpath, &j).unwrap();

        // recover() processes the planted journal across the whole store.
        let _ = fs.recover().unwrap();

        // The outside file is UNTOUCHED.
        assert!(victim.exists(), "recover() unlinked an outside file via a planted blob_id");
        assert_eq!(std::fs::read(&victim).unwrap(), b"precious host file");
        // The valid orphan WAS reclaimed.
        assert!(
            !blob::blob_path(&bk, &good.blob_id).exists(),
            "the valid orphan blob should still be reclaimed"
        );
        // The journal itself is consumed.
        assert!(!jpath.exists(), "journal should be removed after apply");
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
    fn complete_moves_part_blobs_so_surviving_refs_cannot_delete_live_object() {
        // B1 [HIGH — LIVE DATA LOSS], LOAD-BEARING. Reproduces the stale-`.ref` bug:
        // before the fix, CompleteMultipartUpload referenced the UPLOAD's part-blob ids
        // verbatim and only best-effort removed the upload dir. If the rmdir failed (or
        // a crash hit after publish) the surviving `arriving/{uuid}/parts/*.ref` pointed
        // at the LIVE committed object's blobs, so a later Abort / gc_abandoned_uploads /
        // Complete-RETRY would reclaim those shared ids and DELETE the live object's
        // blobs (GET -> ObjectNotFound). The fix MOVES each part blob to a fresh
        // manifest-owned uuid on Complete, so the surviving refs name moved-away (ENOENT)
        // ids and any reclaim through them is a harmless no-op.
        //
        // Fail-without-fix: revert the rename-on-complete and step (i)/(ii) below delete
        // the live object's blobs -> the GET / count_blobs / consistency asserts FAIL.
        let (dir, fs) = store();
        let bk = dir.path().join("bkt");
        let key = "live/object.bin";
        let (upload_id, parts, etags) = upload_3_parts(&fs, "bkt", key);

        // Snapshot the upload's part `.ref` BYTES (which name the part-blob ids) BEFORE
        // Complete, so we can recreate a SURVIVING upload dir afterward — modelling "the
        // best-effort rmdir failed / the refs lingered".
        let upload_dir = bk.join("arriving").join(&upload_id);
        let parts_dir = upload_dir.join("parts");
        let upload_json = std::fs::read(upload_dir.join("upload.json")).unwrap();
        let saved_refs: Vec<(String, Vec<u8>)> = std::fs::read_dir(&parts_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| {
                (
                    e.file_name().to_string_lossy().into_owned(),
                    std::fs::read(e.path()).unwrap(),
                )
            })
            .collect();

        // Complete the upload. With the fix this MOVES the 3 part blobs to fresh ids.
        let complete: Vec<CompletePart> = (0..3)
            .map(|i| CompletePart { part_number: (i + 1) as i32, etag: etags[i].clone() })
            .collect();
        let composite = fs
            .complete_multipart_upload("bkt", key, &upload_id, &complete)
            .unwrap();

        // The live object is intact: exactly 3 blobs, GET returns the exact bytes.
        let mut want = Vec::new();
        for p in &parts {
            want.extend_from_slice(p);
        }
        let live_blob_count = count_blobs(&bk);
        assert_eq!(live_blob_count, 3, "committed object owns exactly its 3 blobs");
        assert_object_consistent(&fs, "bkt", key).unwrap();
        let got = read_all(fs.get_object("bkt", key, None).unwrap().body);
        assert_eq!(md5_hex(&got), md5_hex(&want), "live object bytes after Complete");

        // Re-PLANT the surviving upload dir with the ORIGINAL refs (pointing at the
        // pre-Complete blob ids). Before the fix those ids are the live object's blobs;
        // with the fix they were moved away and no longer exist.
        std::fs::create_dir_all(&parts_dir).unwrap();
        std::fs::write(upload_dir.join("upload.json"), &upload_json).unwrap();
        for (name, data) in &saved_refs {
            std::fs::write(parts_dir.join(name), data).unwrap();
        }

        // (i) Abort that uploadId: it reclaims the blobs named by the surviving refs.
        fs.abort_multipart_upload("bkt", key, &upload_id).unwrap();
        assert_eq!(
            count_blobs(&bk),
            3,
            "Abort via the surviving refs must NOT touch the live object's blobs"
        );
        assert_object_consistent(&fs, "bkt", key)
            .unwrap_or_else(|e| panic!("live object damaged by stale-ref Abort: {e}"));
        let got = read_all(fs.get_object("bkt", key, None).unwrap().body);
        assert_eq!(md5_hex(&got), md5_hex(&want), "live object survives Abort");

        // (ii) gc_abandoned_uploads: re-plant the dir again (Abort removed it) and age
        // it past the threshold so the sweeper reaps it via the surviving refs.
        std::fs::create_dir_all(&parts_dir).unwrap();
        std::fs::write(upload_dir.join("upload.json"), &upload_json).unwrap();
        for (name, data) in &saved_refs {
            std::fs::write(parts_dir.join(name), data).unwrap();
        }
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(48 * 3600);
        set_mtime(&upload_dir.join("upload.json"), old);
        fs.gc_abandoned_uploads(std::time::Duration::from_secs(3600))
            .unwrap();
        assert_eq!(
            count_blobs(&bk),
            3,
            "gc_abandoned_uploads via the surviving refs must NOT touch the live blobs"
        );
        let got = read_all(fs.get_object("bkt", key, None).unwrap().body);
        assert_eq!(md5_hex(&got), md5_hex(&want), "live object survives GC");

        // (iii) A Complete RETRY for the same uploadId must not destroy the object.
        // Re-plant the dir; the retry either no-ops (blobs gone -> InvalidPart, upload
        // intact) or re-commits, but EITHER WAY the live object's bytes are preserved.
        std::fs::create_dir_all(&parts_dir).unwrap();
        std::fs::write(upload_dir.join("upload.json"), &upload_json).unwrap();
        for (name, data) in &saved_refs {
            std::fs::write(parts_dir.join(name), data).unwrap();
        }
        let _ = fs.complete_multipart_upload("bkt", key, &upload_id, &complete);
        assert_object_consistent(&fs, "bkt", key)
            .unwrap_or_else(|e| panic!("live object damaged by Complete RETRY: {e}"));
        let got = read_all(fs.get_object("bkt", key, None).unwrap().body);
        assert_eq!(
            md5_hex(&got),
            md5_hex(&want),
            "live object survives a Complete RETRY against the surviving upload dir"
        );
        // The HEAD etag is unchanged (still the composite from the first Complete).
        assert_eq!(fs.head_object("bkt", key).unwrap().etag, composite);
    }

    #[test]
    fn c2_single_part_get_pins_blob_under_read_lock_vs_overwrite() {
        // C2 [hardening], LOAD-BEARING. A single-part GET opens the blob fd UNDER the
        // per-key READ lock; a concurrent overwrite must take the per-key WRITE lock to
        // reclaim the old blob, so it cannot unlink between the GET's manifest snapshot
        // and its open. The open fd then pins the inode for the whole post-lock stream,
        // so the GET returns the consistent OLD bytes — NOT a spurious ObjectNotFound.
        //
        // Deterministic drive (no sleeps): the GET parks (read lock held) just before
        // open_body; we launch the overwrite (it blocks on the per-key WRITE lock); we
        // release the GET — it opens the still-present old blob under the lock, drops the
        // lock, and the overwrite then proceeds to reclaim the old blob. The GET streams
        // the OLD bytes from its pinned fd.
        //
        // Fail-without-fix: move open_body back OUTSIDE the locked block (the pre-C2
        // shape). Then the read lock drops BEFORE the open; the released overwrite
        // reclaims the old blob; the GET's open ENOENTs -> ObjectNotFound. This test then
        // FAILS (the body read errors / bytes mismatch).
        use std::sync::Arc;
        let _serial = get_pause::serialize_test();
        let dir = tempfile::tempdir().unwrap();
        let fs = Arc::new(CasStore::with_fsync(dir.path(), false));
        fs.create_bucket("bkt").unwrap();
        let bk = dir.path().join("bkt");
        let key = "c2/hot";

        let old_bytes = vec![0xABu8; 64 * 1024];
        fs.put_object("bkt", key, &old_bytes[..], "application/octet-stream", BTreeMap::new())
            .unwrap();
        assert_eq!(count_blobs(&bk), 1);

        let hook = get_pause::Hook::arm(&format!("bkt/{key}"));

        // Reader: GET parks at get_open_pause. With the C2 fix that pause is UNDER the
        // read lock (before open_body); pre-C2 it is AFTER the lock dropped.
        let fr = Arc::clone(&fs);
        let r = std::thread::spawn(move || {
            // ObjectNotFound would surface here in the broken (pre-C2) shape; capture it.
            fr.get_object("bkt", key, None).map(|res| read_all(res.body))
        });
        hook.wait_arrived(); // GET is parked.

        // Overwrite: a second PUT of NEW bytes. It must take the per-key WRITE lock to
        // commit + reclaim the old blob.
        let fw = Arc::clone(&fs);
        let new_bytes = vec![0xCDu8; 32 * 1024];
        let nb = new_bytes.clone();
        let mut w = Some(std::thread::spawn(move || {
            fw.put_object("bkt", key, &nb[..], "application/octet-stream", BTreeMap::new())
                .unwrap();
        }));

        // Distinguisher: does the overwrite BLOCK on the per-key WRITE lock?
        //  * C2 fix: the GET holds the READ lock at the pause -> the overwrite's
        //    lock_key contends -> note_lock_contention fires (true). Releasing the GET
        //    then lets it open the still-present old blob under the lock (pinned fd).
        //  * pre-C2: the GET already dropped the lock before the pause -> the overwrite
        //    runs LOCK-FREE to completion (reclaims the old blob). We JOIN it first so
        //    the old blob is gone, THEN release the GET -> its open ENOENTs.
        let contended =
            hook.wait_writer_contended_timeout(std::time::Duration::from_secs(5));
        if !contended {
            // Broken shape: let the overwrite finish reclaiming, then unpause the GET.
            w.take().unwrap().join().unwrap();
        }
        hook.release();
        let got = r.join().unwrap();
        if let Some(w) = w.take() {
            w.join().unwrap();
        }
        get_pause::Hook::disarm();

        // LOAD-BEARING: with the C2 fix the writer contended and the GET returned the
        // consistent OLD bytes from its pinned fd. Pre-C2 the GET ENOENTs (Err) -> this
        // asserts FAIL.
        assert!(
            contended,
            "C2: the overwrite must block on the per-key WRITE lock, proving the GET \
             opens its blob under the READ lock"
        );
        let got = got.expect("C2: single-part GET must not spuriously fail with ObjectNotFound");
        assert_eq!(got, old_bytes, "C2: single-part GET must return the consistent OLD bytes");
        // After both, the live object is the NEW version, with exactly one blob.
        let now = read_all(fs.get_object("bkt", key, None).unwrap().body);
        assert_eq!(now, new_bytes, "the overwrite is now live");
        assert_eq!(count_blobs(&bk), 1, "only the new version's blob remains");
    }

    #[test]
    fn c1_put_fsyncs_blob_fanout_dir_before_commit_and_round_trips() {
        // C1 [HIGH — durability], LOAD-BEARING under --fsync. A single-part PUT must
        // fsync the blob's fanout PARENT dir (so the blob's DIRENT — not just its file
        // bytes — is durable) BEFORE publish() commits the manifest that references it.
        // We assert (a) the fanout-dir fsync RAN (the C1 counter incremented) and (b)
        // the object round-trips. Fail-without-fix: drop the `fsync_blob_dir` call in
        // put_object and the counter stays 0 -> this asserts FAIL.
        let dir = tempfile::tempdir().unwrap();
        let fs = CasStore::with_fsync(dir.path(), true); // --fsync ON
        fs.create_bucket("bkt").unwrap();

        let _ = blob::take_fsync_dir_calls(); // reset on this thread
        let body = vec![7u8; 100_000];
        fs.put_object(
            "bkt",
            "c1/put/object.bin",
            &body[..],
            "application/octet-stream",
            BTreeMap::new(),
        )
        .unwrap();
        assert!(
            blob::take_fsync_dir_calls() >= 1,
            "PUT under --fsync must fsync the blob fanout dir (C1)"
        );
        let got = read_all(fs.get_object("bkt", "c1/put/object.bin", None).unwrap().body);
        assert_eq!(got, body, "C1 PUT must round-trip");

        // Sanity: with --fsync OFF the path is NOT taken (no fanout-dir fsync), but the
        // object still round-trips.
        let dir2 = tempfile::tempdir().unwrap();
        let fs2 = CasStore::with_fsync(dir2.path(), false);
        fs2.create_bucket("bkt").unwrap();
        let _ = blob::take_fsync_dir_calls();
        fs2.put_object("bkt", "k", &body[..], "", BTreeMap::new()).unwrap();
        assert_eq!(
            blob::take_fsync_dir_calls(),
            0,
            "no blob fanout-dir fsync should run without --fsync"
        );
        assert_eq!(read_all(fs2.get_object("bkt", "k", None).unwrap().body), body);
    }

    #[test]
    fn c1_complete_fsyncs_moved_blob_fanout_dir_before_commit_and_round_trips() {
        // C1 [HIGH — durability], LOAD-BEARING under --fsync. CompleteMultipartUpload
        // MOVES each part blob to a fresh manifest-owned id (rename into a possibly-new
        // fanout dir) and must fsync each moved blob's NEW fanout dir BEFORE publish()
        // commits the manifest. Assert (a) the fanout-dir fsync ran at least once per
        // moved part and (b) the assembled object round-trips bit-for-bit.
        let dir = tempfile::tempdir().unwrap();
        let fs = CasStore::with_fsync(dir.path(), true); // --fsync ON
        fs.create_bucket("bkt").unwrap();
        let key = "c1/mp/object.bin";
        let (upload_id, parts, etags) = upload_3_parts(&fs, "bkt", key);

        let _ = blob::take_fsync_dir_calls(); // reset right before Complete
        let complete: Vec<CompletePart> = (0..3)
            .map(|i| CompletePart { part_number: (i + 1) as i32, etag: etags[i].clone() })
            .collect();
        fs.complete_multipart_upload("bkt", key, &upload_id, &complete).unwrap();
        assert!(
            blob::take_fsync_dir_calls() >= 3,
            "Complete under --fsync must fsync the fanout dir of each moved part blob (C1)"
        );

        let mut want = Vec::new();
        for p in &parts {
            want.extend_from_slice(p);
        }
        let got = read_all(fs.get_object("bkt", key, None).unwrap().body);
        assert_eq!(got, want, "C1 Complete must round-trip the assembled object");
        assert_object_consistent(&fs, "bkt", key).unwrap();
    }

    #[test]
    fn c4_failed_part_reupload_leaves_previous_part_intact() {
        // C4 [MED], LOAD-BEARING. A forced parts/-dir fsync failure during a re-upload of
        // an EXISTING part must leave the upload EXACTLY as before: the OLD part's ref +
        // blob survive (and the object is GETtable on Complete with the OLD bytes), and
        // the NEW (failed) blob is reclaimed. Fail-without-fix: the old rollback only
        // removed the NEW ref + blob without restoring the PREVIOUS ref, so the part
        // would be LOST (Complete would then fail / the old bytes vanish).
        let dir = tempfile::tempdir().unwrap();
        let fs = CasStore::with_fsync(dir.path(), true); // --fsync ON (fsync rollback path)
        fs.create_bucket("bkt").unwrap();
        let bk = dir.path().join("bkt");
        let key = "c4/reupload";
        let upload_id = fs
            .create_multipart_upload("bkt", key, "application/octet-stream", BTreeMap::new())
            .unwrap();

        // First (good) upload of part 1.
        let old_bytes = vec![1u8; 8192];
        let old_etag = fs.upload_part("bkt", key, &upload_id, 1, &old_bytes[..]).unwrap();
        assert_eq!(count_blobs(&bk), 1);
        // Snapshot the ref bytes so we can prove they are restored unchanged.
        let ref_path = bk.join("arriving").join(&upload_id).join("parts").join("00001.ref");
        let ref_before = std::fs::read(&ref_path).unwrap();

        // Re-upload part 1 with DIFFERENT bytes, with the parts/-dir fsync forced to fail.
        let new_bytes = vec![2u8; 4096];
        set_force_parts_fsync_fail(true);
        let res = fs.upload_part("bkt", key, &upload_id, 1, &new_bytes[..]);
        set_force_parts_fsync_fail(false);
        assert!(
            matches!(res, Err(StorageError::Io(_))),
            "re-upload must fail on the forced parts/ fsync error, got {res:?}"
        );

        // The PREVIOUS ref is restored byte-for-byte; the NEW blob is reclaimed so only
        // the OLD part blob remains.
        let ref_after = std::fs::read(&ref_path).unwrap();
        assert_eq!(ref_after, ref_before, "C4: the previous part ref must be restored unchanged");
        assert_eq!(
            count_blobs(&bk),
            1,
            "C4: the new (failed) blob must be reclaimed, leaving only the old part blob"
        );

        // ListParts still shows exactly the OLD part (etag), and Complete yields the OLD
        // bytes — the failed re-upload did not mutate the upload.
        let listed = fs.list_parts("bkt", key, &upload_id).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].etag, old_etag);
        let complete = vec![CompletePart { part_number: 1, etag: old_etag.clone() }];
        fs.complete_multipart_upload("bkt", key, &upload_id, &complete).unwrap();
        let got = read_all(fs.get_object("bkt", key, None).unwrap().body);
        assert_eq!(got, old_bytes, "C4: Complete must yield the OLD part bytes");
    }

    #[test]
    fn d3_upload_part_rechecks_upload_under_lock_concurrent_abort() {
        // D-3 [LOW], LOAD-BEARING for the re-check. upload_part validates the upload
        // (assert_upload_matches) BEFORE streaming the body, then takes the per-key lock
        // for the ref install. A concurrent Complete/Abort that removes the upload dir in
        // that window would otherwise make the ref install fail with a raw Io error ->
        // 500. The D-3 fix RE-CHECKS the upload under the per-key lock before installing
        // the ref and returns a clean NoSuchUpload (404) instead.
        //
        // We make this deterministic with a body reader that REMOVES the upload dir
        // mid-stream — i.e. exactly while upload_part is between its first check and the
        // post-lock re-check — modelling a concurrent Abort that landed in the window.
        //
        // Fail-without-fix: drop the post-lock `assert_upload_matches` re-check and the
        // ref-install rename fails with `Err(StorageError::Io(_))` (ENOENT on the gone
        // parts/ dir) -> this test's NoSuchUpload assertion FAILS.
        struct AbortMidStream {
            upload_dir: PathBuf,
            data: std::io::Cursor<Vec<u8>>,
            fired: bool,
        }
        impl Read for AbortMidStream {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                if !self.fired {
                    // Simulate a concurrent Abort completing: remove the whole upload dir.
                    let _ = std::fs::remove_dir_all(&self.upload_dir);
                    self.fired = true;
                }
                self.data.read(buf)
            }
        }

        let (dir, fs) = store();
        let bk = dir.path().join("bkt");
        let key = "d3/object";
        let upload_id = fs
            .create_multipart_upload("bkt", key, "application/octet-stream", BTreeMap::new())
            .unwrap();
        let upload_dir = bk.join("arriving").join(&upload_id);

        let body = AbortMidStream {
            upload_dir: upload_dir.clone(),
            data: std::io::Cursor::new(vec![3u8; 4096]),
            fired: false,
        };
        let res = fs.upload_part("bkt", key, &upload_id, 1, body);
        assert!(
            matches!(res, Err(StorageError::NoSuchUpload)),
            "a concurrent Abort during upload_part must surface NoSuchUpload, not Io/500, got {res:?}"
        );

        // The orphan blob the rolled-back upload_part wrote must have been reclaimed by
        // the re-check's cleanup (no leaked blob).
        assert_eq!(
            count_blobs(&bk),
            0,
            "the part blob must be reclaimed when the post-lock re-check rejects the upload"
        );
    }

    #[test]
    fn d4_complete_writes_marker_before_rmdir() {
        // D-4 [LOW — hygiene], LOAD-BEARING for the marker-before-rmdir order. The
        // `completed` marker is the durable backstop that makes a surviving uploadId
        // non-addressable; complete() must write it BEFORE the best-effort rmdir. A normal
        // Complete removes the dir entirely (marker gone with it), so to OBSERVE the order
        // we BLOCK the rmdir by making the upload's `parts/` subdir read-only:
        // remove_dir_all(upload_dir) then fails (it cannot unlink the read-only parts/'s
        // children) and the upload dir SURVIVES — and the `completed` marker (written into
        // the still-writable upload dir) must be present, proving it was written first.
        // Complete itself must still SUCCEED: the object is committed (and publish stages
        // into the writable `arriving/` dir) before the marker/rmdir.
        //
        // Fail-without-fix: move the marker write AFTER the rmdir (or drop it) and the
        // surviving dir would have NO marker -> the marker assertion (and the C5 reject
        // assertions below) FAIL.
        let (dir, fs) = store();
        let bk = dir.path().join("bkt");
        let key = "d4/object";
        let (upload_id, parts, etags) = upload_3_parts(&fs, "bkt", key);
        let complete: Vec<CompletePart> = (0..3)
            .map(|i| CompletePart { part_number: (i + 1) as i32, etag: etags[i].clone() })
            .collect();

        // Make the upload's `parts/` subdir read-only so complete()'s best-effort
        // remove_dir_all FAILS on its children — the upload dir SURVIVES with the
        // `completed` marker that must have been written FIRST. (Complete itself still
        // succeeds: the object is committed and publish stages into the writable arriving/.)
        use std::os::unix::fs::PermissionsExt as _;
        let parts_dir = bk.join("arriving").join(&upload_id).join("parts");
        let orig = std::fs::metadata(&parts_dir).unwrap().permissions();
        std::fs::set_permissions(&parts_dir, std::fs::Permissions::from_mode(0o555)).unwrap();
        let etag = fs.complete_multipart_upload("bkt", key, &upload_id, &complete);
        std::fs::set_permissions(&parts_dir, orig).unwrap();
        etag.expect("Complete must succeed even if the marker/rmdir cannot run (object committed)");

        // The dir SURVIVED (rmdir blocked) and the `completed` marker WAS written before
        // the rmdir attempt — so it is present, making the uploadId non-addressable.
        let upload_dir = bk.join("arriving").join(&upload_id);
        assert!(upload_dir.exists(), "the rmdir was blocked, so the upload dir survives");
        assert!(
            upload_dir.join("completed").exists(),
            "the `completed` marker must be written BEFORE the (failed) rmdir"
        );

        // C5 invariant stays green: the marked, surviving uploadId rejects further ops.
        assert!(matches!(
            fs.upload_part("bkt", key, &upload_id, 1, &b"x"[..]),
            Err(StorageError::NoSuchUpload)
        ));
        assert!(matches!(
            fs.list_parts("bkt", key, &upload_id),
            Err(StorageError::NoSuchUpload)
        ));

        // And the object is live + consistent.
        let mut want = Vec::new();
        for p in &parts {
            want.extend_from_slice(p);
        }
        let got = read_all(fs.get_object("bkt", key, None).unwrap().body);
        assert_eq!(got, want, "the committed object must round-trip after Complete");
        assert_object_consistent(&fs, "bkt", key).unwrap();
    }

    #[test]
    fn c1_residual_put_reclaims_blob_on_blob_dir_fsync_error() {
        // C1-residual [LOW — orphan leak], LOAD-BEARING for the reclaim. In put_object the
        // pre-publish `fsync_blob_dir` (under --fsync) runs BEFORE the per-key lock +
        // publish, so its error returns WITHOUT reaching publish's rollback arm — leaking
        // the just-written blob as an orphan. The fix reclaims that blob (best-effort)
        // before propagating the error, so NO orphan is left.
        //
        // The FORCE_PUT_BLOB_DIR_FSYNC_FAIL hook forces ONLY that fsync to fail, so the
        // blob FILE is written but its fanout-dir fsync errors — isolating exactly the
        // C1-residual path.
        //
        // Fail-without-fix: revert to `blob::fsync_blob_dir(...)?` (no reclaim before the
        // `?`) and the post-condition (no orphan blob) FAILS — count_blobs would be 1.
        let dir = tempfile::tempdir().unwrap();
        let fs = CasStore::with_fsync(dir.path(), true); // --fsync ON (the C1-residual path)
        fs.create_bucket("bkt").unwrap();
        let bk = dir.path().join("bkt");

        set_force_put_blob_dir_fsync_fail(true);
        let res = fs.put_object("bkt", "k", &b"orphan-on-fsync-error"[..], "", BTreeMap::new());
        set_force_put_blob_dir_fsync_fail(false);

        assert!(
            matches!(res, Err(StorageError::Io(_))),
            "the blob-dir fsync error must propagate from put_object, got {res:?}"
        );
        // The just-written blob was RECLAIMED before the error returned -> no orphan left.
        assert_eq!(
            count_blobs(&bk),
            0,
            "C1-residual: the orphan blob must be reclaimed on a blob-dir fsync error"
        );
        // No live object was committed (publish never ran).
        assert!(matches!(
            fs.get_object("bkt", "k", None),
            Err(StorageError::ObjectNotFound)
        ));

        // A subsequent (un-armed) PUT succeeds and leaves exactly one blob.
        fs.put_object("bkt", "k", &b"hello"[..], "", BTreeMap::new()).unwrap();
        assert_eq!(count_blobs(&bk), 1);
    }

    #[test]
    fn d2_failed_part_reupload_rollback_is_atomic_and_consistent() {
        // D-2 [MED — consistency], LOAD-BEARING. The C4 rollback restores the PREVIOUS
        // `.ref` on a failed re-upload. D-2 hardens that restore to be ATOMIC (temp +
        // rename, not an in-place best-effort write) and to reclaim the NEW blob ONLY
        // AFTER the restore lands. The net invariant: after a forced rollback the part is
        // in a CONSISTENT state — Complete yields VALID bytes for that part, the ref is
        // neither truncated nor dangling, and no orphan blob breaks Complete.
        //
        // This drives the rollback via the existing FORCE_PARTS_FSYNC_FAIL hook on a
        // re-upload (the restore-succeeds branch, which now runs through the atomic
        // temp+rename restore), and asserts: (1) NO `.ref.tmp.*` restore temp is left
        // behind (atomic publish), (2) the restored ref re-reads as a VALID PartRefFile
        // pointing at the OLD blob, (3) exactly the old part blob remains (new blob
        // reclaimed AFTER the restore), and (4) Complete yields the OLD bytes intact.
        //
        // Fail-without-fix: revert to the in-place `write_nofollow(&ref_path, ...)` +
        // unconditional new-blob reclaim and assertion (1) (no temp leftover via the new
        // path) plus the atomic-publish guarantee no longer hold; more importantly a
        // torn in-place write could leave a ref that fails (2)/(4).
        let dir = tempfile::tempdir().unwrap();
        let fs = CasStore::with_fsync(dir.path(), true); // --fsync ON (drives the rollback)
        fs.create_bucket("bkt").unwrap();
        let bk = dir.path().join("bkt");
        let key = "d2/reupload";
        let upload_id = fs
            .create_multipart_upload("bkt", key, "application/octet-stream", BTreeMap::new())
            .unwrap();

        // Good first upload of part 1; remember its blob id and the exact ref bytes.
        let old_bytes = vec![7u8; 8192];
        let old_etag = fs.upload_part("bkt", key, &upload_id, 1, &old_bytes[..]).unwrap();
        let parts_dir = bk.join("arriving").join(&upload_id).join("parts");
        let ref_path = parts_dir.join("00001.ref");
        let ref_before = std::fs::read(&ref_path).unwrap();
        let old_blob = serde_json::from_slice::<PartRefFile>(&ref_before).unwrap().blob_id;
        assert_eq!(count_blobs(&bk), 1);

        // Re-upload part 1 with the parts/-dir fsync forced to fail -> rollback fires.
        set_force_parts_fsync_fail(true);
        let res = fs.upload_part("bkt", key, &upload_id, 1, &vec![8u8; 4096][..]);
        set_force_parts_fsync_fail(false);
        assert!(
            matches!(res, Err(StorageError::Io(_))),
            "re-upload must fail on the forced fsync error, got {res:?}"
        );

        // (1) The atomic restore left NO `.ref.tmp.*` temp behind.
        let leftovers = list_dir(&parts_dir);
        assert!(
            leftovers.iter().all(|n| !n.contains(".tmp.")),
            "no `.ref.tmp.*` temp may survive the atomic restore, saw {leftovers:?}"
        );

        // (2) The restored ref re-reads as a VALID PartRefFile pointing at the OLD blob
        //     (not truncated, not dangling), byte-identical to before.
        let ref_after = std::fs::read(&ref_path).unwrap();
        assert_eq!(ref_after, ref_before, "the previous ref must be restored byte-for-byte");
        let restored = serde_json::from_slice::<PartRefFile>(&ref_after)
            .expect("restored ref must parse (not truncated/torn)");
        assert_eq!(restored.blob_id, old_blob, "restored ref must point at the OLD blob");
        assert!(
            blob::blob_path(&bk, &restored.blob_id).exists(),
            "the OLD blob the restored ref points at must still exist (no dangling ref)"
        );

        // (3) New blob reclaimed AFTER the restore -> exactly the old part blob remains.
        assert_eq!(count_blobs(&bk), 1, "only the OLD part blob may remain (new blob reclaimed)");

        // (4) Complete succeeds and yields the OLD bytes intact — no orphan/dangling ref
        //     broke it.
        let complete = vec![CompletePart { part_number: 1, etag: old_etag }];
        fs.complete_multipart_upload("bkt", key, &upload_id, &complete).unwrap();
        let got = read_all(fs.get_object("bkt", key, None).unwrap().body);
        assert_eq!(got, old_bytes, "Complete must yield the OLD part bytes after the rollback");
    }

    #[test]
    fn d2_rollback_restore_failure_leaves_part_referencing_new_blob_not_dangling() {
        // D-2 [MED — consistency], LOAD-BEARING for the restore-FAILS branch (the part the
        // old code got WRONG). When the C4 rollback's previous-`.ref` restore itself FAILS,
        // the fix must NOT reclaim the new blob — the part still references the (valid) new
        // blob via the ref the earlier rename installed, so it stays CONSISTENT (the NEW
        // part) instead of dangling/truncated. We force BOTH the parts/-dir fsync (to
        // TRIGGER the rollback) AND the restore (to make the restore branch fail).
        //
        // Fail-without-fix: the OLD rollback reclaimed the new blob UNCONDITIONALLY after a
        // best-effort in-place restore — so a failed restore would leave the ref pointing
        // at a RECLAIMED blob (dangling), and Complete with the new etag would fail
        // (InvalidPart on the missing blob). This test asserts Complete SUCCEEDS with the
        // NEW bytes, which only holds with the fix.
        let dir = tempfile::tempdir().unwrap();
        let fs = CasStore::with_fsync(dir.path(), true); // --fsync ON
        fs.create_bucket("bkt").unwrap();
        let bk = dir.path().join("bkt");
        let key = "d2b/reupload";
        let upload_id = fs
            .create_multipart_upload("bkt", key, "application/octet-stream", BTreeMap::new())
            .unwrap();

        // Good first upload of part 1.
        let old_bytes = vec![5u8; 8192];
        fs.upload_part("bkt", key, &upload_id, 1, &old_bytes[..]).unwrap();
        assert_eq!(count_blobs(&bk), 1);

        // Re-upload part 1 with NEW bytes; fsync fails (triggers rollback) AND the restore
        // is forced to fail (exercises the restore-FAILS branch).
        let new_bytes = vec![6u8; 4096];
        let new_etag = format!("\"{}\"", md5_hex(&new_bytes));
        set_force_parts_fsync_fail(true);
        set_force_parts_restore_fail(true);
        let res = fs.upload_part("bkt", key, &upload_id, 1, &new_bytes[..]);
        set_force_parts_restore_fail(false);
        set_force_parts_fsync_fail(false);
        assert!(
            matches!(res, Err(StorageError::Io(_))),
            "the re-upload must surface the error, got {res:?}"
        );

        // The installed ref points at the NEW blob (the earlier rename), and that blob was
        // NOT reclaimed -> it still exists (no dangling ref). The OLD blob may now be an
        // orphan (gc-reclaimable), which is acceptable.
        let ref_path = bk.join("arriving").join(&upload_id).join("parts").join("00001.ref");
        let cur = serde_json::from_slice::<PartRefFile>(&std::fs::read(&ref_path).unwrap())
            .expect("the part ref must still parse (not truncated)");
        assert_eq!(cur.md5_hex, md5_hex(&new_bytes), "ref records the NEW part");
        assert!(
            blob::blob_path(&bk, &cur.blob_id).exists(),
            "the new blob the ref points at must NOT be reclaimed (no dangling ref)"
        );

        // Complete with the NEW etag SUCCEEDS and yields the NEW bytes — the part is the
        // consistent NEW part, not a dangling reference.
        let complete = vec![CompletePart { part_number: 1, etag: new_etag }];
        fs.complete_multipart_upload("bkt", key, &upload_id, &complete)
            .expect("Complete must succeed: the part references a valid (new) blob");
        let got = read_all(fs.get_object("bkt", key, None).unwrap().body);
        assert_eq!(got, new_bytes, "Complete yields the NEW part bytes (consistent state)");
    }

    #[test]
    fn c5_completed_upload_rejects_further_ops_even_if_dir_survives() {
        // C5 [S3 fidelity], LOAD-BEARING for the reject. After a successful Complete, a
        // second UploadPart/Complete/ListParts on the same uploadId must fail
        // NoSuchUpload — even when the upload dir SURVIVES (simulating a failed
        // best-effort rmdir) — because the `completed` marker backstops it.
        let (dir, fs) = store();
        let bk = dir.path().join("bkt");
        let key = "c5/object";
        let (upload_id, _parts, etags) = upload_3_parts(&fs, "bkt", key);
        let complete: Vec<CompletePart> = (0..3)
            .map(|i| CompletePart { part_number: (i + 1) as i32, etag: etags[i].clone() })
            .collect();
        fs.complete_multipart_upload("bkt", key, &upload_id, &complete).unwrap();

        // Simulate the rmdir having failed: re-create the upload dir with its upload.json
        // and the `completed` marker present (the marker is the backstop the C5 fix
        // writes BEFORE the rmdir).
        let upload_dir = bk.join("arriving").join(&upload_id);
        std::fs::create_dir_all(upload_dir.join("parts")).unwrap();
        std::fs::write(
            upload_dir.join("upload.json"),
            serde_json::to_vec(&MultipartUpload {
                upload_id: upload_id.clone(),
                bucket: "bkt".into(),
                key: key.into(),
                initiated_unix: now_unix(),
                content_type: "application/octet-stream".into(),
                user_metadata: BTreeMap::new(),
            })
            .unwrap(),
        )
        .unwrap();
        std::fs::write(upload_dir.join("completed"), b"1").unwrap();

        // Every further op on the completed (but surviving) uploadId is NoSuchUpload.
        assert!(matches!(
            fs.upload_part("bkt", key, &upload_id, 1, &b"x"[..]),
            Err(StorageError::NoSuchUpload)
        ));
        assert!(matches!(
            fs.complete_multipart_upload("bkt", key, &upload_id, &complete),
            Err(StorageError::NoSuchUpload)
        ));
        assert!(matches!(
            fs.list_parts("bkt", key, &upload_id),
            Err(StorageError::NoSuchUpload)
        ));
        // And it is no longer listed among in-flight uploads.
        let (uploads, _) = fs.list_multipart_uploads("bkt", 1000).unwrap();
        assert!(
            !uploads.iter().any(|u| u.upload_id == upload_id),
            "a completed upload must not appear in ListMultipartUploads"
        );
    }

    #[test]
    fn pass_k_delete_bucket_ignores_completed_upload_dir() {
        // Codex pass K [MEDIUM — consistency], LOAD-BEARING. A completed-but-not-yet-
        // removed `arriving/{uuid}/` dir (Complete committed durably + wrote the
        // `completed` marker, but its best-effort rmdir failed or the process crashed)
        // is no longer addressable via S3: it is NOT listed (ListMultipartUploads) and
        // NOT abortable (assert_upload_matches -> NoSuchUpload). Such a survivor must NOT
        // wedge DeleteBucket with BucketNotEmpty — has_in_flight_upload must skip it, the
        // same way the other two `arriving/{uuid}/` walkers honor the `completed` marker.
        //
        // Fail-without-fix: remove the `completed`-marker `continue` block in
        // has_in_flight_upload and this test FAILS (has_in_flight_upload -> true,
        // delete_bucket -> BucketNotEmpty).
        let (dir, fs) = store(); // creates an empty "bkt"
        let arriving = dir.path().join("bkt").join("arriving");

        // A marker-LESS upload dir (upload.json only) IS in-flight -> true.
        let live_id = "00000000-0000-0000-0000-0000000000aa";
        let live_dir = arriving.join(live_id);
        std::fs::create_dir_all(live_dir.join("parts")).unwrap();
        std::fs::write(
            live_dir.join("upload.json"),
            serde_json::to_vec(&MultipartUpload {
                upload_id: live_id.into(),
                bucket: "bkt".into(),
                key: "k/live".into(),
                initiated_unix: now_unix(),
                content_type: "application/octet-stream".into(),
                user_metadata: BTreeMap::new(),
            })
            .unwrap(),
        )
        .unwrap();
        assert!(
            fs.has_in_flight_upload("bkt").unwrap(),
            "a marker-less upload dir (upload.json only) is in-flight"
        );
        assert!(
            matches!(fs.delete_bucket("bkt"), Err(StorageError::BucketNotEmpty)),
            "DeleteBucket must refuse while a live upload exists"
        );

        // Add the `completed` marker (Complete finished, rmdir did not) -> no longer
        // in-flight. With only this completed survivor present, the predicate is false.
        std::fs::write(live_dir.join("completed"), b"1").unwrap();
        assert!(
            !fs.has_in_flight_upload("bkt").unwrap(),
            "a completed-marker upload dir is NOT in-flight (must not wedge DeleteBucket)"
        );

        // And DeleteBucket SUCCEEDS, tearing down the whole tree (including the survivor).
        fs.delete_bucket("bkt")
            .expect("DeleteBucket must clear once only completed-marker upload dirs remain");
        assert!(
            matches!(fs.head_bucket("bkt"), Err(StorageError::BucketNotFound)),
            "bucket is gone after a successful DeleteBucket"
        );
    }

    #[test]
    fn c6_write_journal_propagates_deleted_dir_fsync_error() {
        // C6 [LOW — durability], LOAD-BEARING. write_journal must PROPAGATE a deleted/-dir
        // fsync error under --fsync (not swallow it): a lost journal dirent means
        // recover() never replays the reclaim and superseded blobs leak, so an
        // overwrite/delete that cannot durably journal its reclaim must FAIL rather than
        // ack. The hook forces ONLY the deleted/-dir fsync to fail (the journal FILE
        // write still succeeds), isolating the C6 path.
        //
        // Fail-without-fix: revert the `?` to `let _ = fsync_dir(...)` and these ops
        // return Ok -> the asserts FAIL.
        let dir = tempfile::tempdir().unwrap();
        let fs = CasStore::with_fsync(dir.path(), true); // --fsync ON
        fs.create_bucket("bkt").unwrap();

        // First PUT creates the object (no journal: no prior version, so it succeeds even
        // with the hook armed — write_journal is not called on a first PUT).
        set_force_journal_dir_fsync_fail(true);
        fs.put_object("bkt", "k", &b"v1"[..], "", BTreeMap::new())
            .expect("first PUT writes no journal, so the hook does not fire");

        // The OVERWRITE must journal the old blob; the deleted/-dir fsync now fails and
        // the error must PROPAGATE out of publish() -> put_object.
        let res = fs.put_object("bkt", "k", &b"v2"[..], "", BTreeMap::new());
        // A DELETE also journals; it too must propagate.
        let res_del = fs.delete_object("bkt", "k");
        set_force_journal_dir_fsync_fail(false);
        assert!(
            matches!(res, Err(StorageError::Io(_))),
            "C6: an overwrite that cannot durably journal its reclaim must fail, got {res:?}"
        );
        assert!(
            matches!(res_del, Err(StorageError::Io(_))),
            "C6: a delete that cannot durably journal its reclaim must fail, got {res_del:?}"
        );
    }

    #[test]
    fn e1_publish_propagates_commit_dir_fsync_and_withholds_reclaim() {
        // E-1 [HIGH — data loss], LOAD-BEARING. On an OVERWRITE, publish does:
        //   rename(staged -> current/K) -> current/-dir fsync -> reclaim OLD blobs ->
        //   delete journal.
        // If the post-commit current/-dir fsync is SWALLOWED and execution falls through
        // to reclaim+delete-journal, a crash can revert current/K to the OLD manifest
        // whose blobs were already reclaimed and whose journal was already deleted -> a
        // dangling live object / data loss.
        //
        // The FORCE_COMMIT_DIR_FSYNC_FAIL hook forces ONLY that fsync to fail. The fix
        // PROPAGATES the error (return Err) BEFORE step-4 reclaim / step-5 journal-delete,
        // so: (1) publish returns Err, (2) the OLD object's blob is NOT reclaimed, (3) the
        // journal is NOT deleted -> recover() then settles via the §3.2 nonce rule to a
        // consistent state (OLD live OR NEW live, never a dangling manifest / missing
        // blob).
        //
        // Fail-without-fix: revert to the swallowed `tracing::warn!` (no `?`) and publish
        // returns Ok despite a non-durable rename; the OLD blob is reclaimed and the
        // journal deleted -> assertions (2)/(3) FAIL. (And in a real crash recover() could
        // no longer settle: the live manifest would dangle on a reclaimed blob.)
        let dir = tempfile::tempdir().unwrap();
        let fs = CasStore::with_fsync(dir.path(), true); // --fsync ON (the E-1 path)
        fs.create_bucket("bkt").unwrap();
        let bk = dir.path().join("bkt");

        // v1: the OLD version. Remember its blob id.
        fs.put_object("bkt", "k", &b"v1-old-bytes"[..], "", BTreeMap::new())
            .unwrap();
        let v1_blob = {
            let m = manifest::read_manifest(&manifest::manifest_path(&bk.join("current"), "k")).unwrap();
            m.parts[0].blob_id.clone()
        };
        assert_eq!(count_blobs(&bk), 1, "only v1 before the overwrite");

        // Overwrite (v2) with the commit-dir fsync forced to fail.
        set_force_commit_dir_fsync_fail(true);
        let res = fs.put_object("bkt", "k", &b"v2-new-and-longer-bytes"[..], "", BTreeMap::new());
        set_force_commit_dir_fsync_fail(false);

        // (1) The error PROPAGATES out of publish -> put_object as the DEDICATED
        //     post-commit `CommitNotDurable` (NOT a pre-commit Io error), so put_object
        //     does NOT roll back the now-live NEW blob.
        assert!(
            matches!(res, Err(StorageError::CommitNotDurable(_))),
            "E-1: an overwrite that cannot durably fsync its commit dir must fail \
             with CommitNotDurable, got {res:?}"
        );
        // (1b) The NEW blob must NOT be reclaimed (the new version is live).
        let v2_blob = {
            let m = manifest::read_manifest(&manifest::manifest_path(&bk.join("current"), "k")).unwrap();
            m.parts[0].blob_id.clone()
        };
        assert!(
            blob::blob_path(&bk, &v2_blob).exists(),
            "E-1: the NEW (now-live) blob must NOT be reclaimed on a post-commit fsync error"
        );
        assert_eq!(count_blobs(&bk), 2, "E-1: both OLD and NEW blobs present (neither reclaimed)");
        // (2) The OLD blob was NOT reclaimed (reclaim is withheld until the fsync lands).
        assert!(
            blob::blob_path(&bk, &v1_blob).exists(),
            "E-1: the OLD blob must NOT be reclaimed when the commit-dir fsync failed"
        );
        // (3) The journal was NOT deleted -> recover() can settle the commit.
        assert_eq!(
            list_dir(&bk.join("deleted")).len(),
            1,
            "E-1: the publish journal must be kept for recover() when the commit-dir fsync failed"
        );

        // recover() settles to a CONSISTENT state. The rename landed in this in-process
        // test (only the fsync was faked), so recover() sees the NEW manifest, whose nonce
        // matches the journal -> it reclaims the OLD blob and removes the journal. Either
        // way (OLD or NEW live), the live object must reference NO missing blob.
        fs.recover().unwrap();
        assert_object_consistent(&fs, "bkt", "k")
            .expect("E-1: after recover() the live object must reference no missing blob");
        assert!(
            list_dir(&bk.join("deleted")).is_empty(),
            "E-1: recover() settles and removes the journal"
        );
        // The live object is the NEW version (rename had landed) with exactly one blob.
        assert_eq!(
            read_all(fs.get_object("bkt", "k", None).unwrap().body),
            b"v2-new-and-longer-bytes"
        );
        assert_eq!(count_blobs(&bk), 1, "E-1: OLD blob reclaimed by recover(); only NEW remains");
    }

    #[test]
    fn f2_publish_nested_key_chain_fsync_fail_is_commit_not_durable_and_withholds_reclaim() {
        // Codex pass F-2 [HIGH — durability], LOAD-BEARING. publish() must fsync the
        // WHOLE newly-created manifest ancestor CHAIN (from `k.parent()` up to and
        // including `current/`) — not just `k.parent()` — before acking the commit. A
        // crash that lost an intermediate dirent (`current/a/`) would make a committed
        // nested-key manifest (`current/a/b/c.s3gw-live.meta`) unreachable.
        //
        // We verify the PROPAGATION + withheld-reclaim contract on a NESTED key (so the
        // chain has real intermediate dirs `current/a/`, `current/a/b/`): the
        // FORCE_COMMIT_DIR_FSYNC_FAIL hook now wraps the `fsync_dir_chain` call, so a
        // forced chain-fsync failure on an OVERWRITE must (1) return the dedicated
        // CommitNotDurable (post-commit, NOT a pre-commit Io rollback), (2) NOT reclaim
        // the OLD blob, (3) keep the journal for recover(). Fail-without-fix: revert
        // publish's chain fsync to `let _ = fsync_dir(parent)` (swallowed) and publish
        // returns Ok despite a non-durable commit -> assertions (1)/(2)/(3) FAIL.
        let dir = tempfile::tempdir().unwrap();
        let fs = CasStore::with_fsync(dir.path(), true); // --fsync ON (the F-2 path)
        fs.create_bucket("bkt").unwrap();
        let bk = dir.path().join("bkt");
        let key = "a/b/c.bin"; // nested -> current/a/b/ chain

        // v1: the OLD version. Remember its blob id.
        fs.put_object("bkt", key, &b"v1-old"[..], "", BTreeMap::new()).unwrap();
        let v1_blob = {
            let m = manifest::read_manifest(&manifest::manifest_path(&bk.join("current"), key)).unwrap();
            m.parts[0].blob_id.clone()
        };
        assert_eq!(count_blobs(&bk), 1, "only v1 before the overwrite");

        // Overwrite (v2) with the commit-dir CHAIN fsync forced to fail.
        set_force_commit_dir_fsync_fail(true);
        let res = fs.put_object("bkt", key, &b"v2-new-longer-bytes"[..], "", BTreeMap::new());
        set_force_commit_dir_fsync_fail(false);

        // (1) Dedicated post-commit error -> caller does NOT roll back the now-live blob.
        assert!(
            matches!(res, Err(StorageError::CommitNotDurable(_))),
            "F-2: a nested-key overwrite that cannot durably fsync its manifest ancestor \
             chain must fail with CommitNotDurable, got {res:?}"
        );
        // (1b) The NEW (now-live) blob is NOT reclaimed.
        let v2_blob = {
            let m = manifest::read_manifest(&manifest::manifest_path(&bk.join("current"), key)).unwrap();
            m.parts[0].blob_id.clone()
        };
        assert!(blob::blob_path(&bk, &v2_blob).exists(), "F-2: NEW blob must survive");
        assert_eq!(count_blobs(&bk), 2, "F-2: both OLD and NEW blobs present (neither reclaimed)");
        // (2) The OLD blob is NOT reclaimed (reclaim withheld until the chain fsync lands).
        assert!(
            blob::blob_path(&bk, &v1_blob).exists(),
            "F-2: the OLD blob must NOT be reclaimed when the manifest-chain fsync failed"
        );
        // (3) The journal is kept for recover().
        assert_eq!(
            list_dir(&bk.join("deleted")).len(),
            1,
            "F-2: the publish journal must be kept for recover() when the chain fsync failed"
        );

        // recover() settles to a CONSISTENT state (rename had landed; NEW manifest's
        // nonce matches the journal -> OLD blob reclaimed, journal removed).
        fs.recover().unwrap();
        assert_object_consistent(&fs, "bkt", key)
            .expect("F-2: after recover() the live nested-key object must reference no missing blob");
        assert_eq!(read_all(fs.get_object("bkt", key, None).unwrap().body), b"v2-new-longer-bytes");
        assert_eq!(count_blobs(&bk), 1, "F-2: OLD blob reclaimed by recover(); only NEW remains");
    }

    #[test]
    fn f1_site4_fresh_bucket_put_fsyncs_full_ancestor_chain_and_round_trips() {
        // Codex pass F-1 + site-4 [HIGH — durability], LOAD-BEARING under --fsync.
        // On the FIRST PUT into a freshly-created bucket, the durability class requires
        // that EVERY newly-created ancestor dirent be fsynced before the commit is acked:
        //   * site-4: the `bucket/` dirent (data-root fsync in create_bucket) and the
        //     four infra dirents `current/`,`arriving/`,`blobs/`,`deleted/` (bucket-root
        //     fsync in ensure_infra);
        //   * F-1: the blob fanout CHAIN `blobs/{ab}/{cd}/` -> `blobs/{ab}/` -> `blobs/`
        //     (fsync_blob_dir now walks the chain, not just the leaf);
        //   * F-2: the manifest key-path chain up to `current/` (publish, exercised here
        //     trivially via a top-level key whose parent IS `current/`).
        // Crash-durability itself is not observable in a unit test, so we assert the
        // fsync CHAIN is INVOKED (fanout-dir counter incremented) and that correctness
        // is preserved (the object round-trips), per the deliverable's guidance.
        //
        // Fail-without-fix: drop the create_bucket/ensure_infra fsyncs (site-4) — the
        // round-trip still passes in-process but a fresh-bucket crash loses the bucket;
        // drop the F-1 chain walk and a first-in-fanout blob's intermediate dirent is
        // lost. The counter assertion below proves fsync_blob_dir (the chain entry
        // point) ran on this first-in-fresh-bucket PUT.
        let dir = tempfile::tempdir().unwrap();
        let fs = CasStore::with_fsync(dir.path(), true); // --fsync ON
        // create_bucket under --fsync now fsyncs the data-root (bucket/ dirent) and the
        // bucket-root (infra dirents). It must succeed without error.
        fs.create_bucket("fresh").unwrap();
        let bk = dir.path().join("fresh");
        assert!(bk.join("blobs").is_dir() && bk.join("current").is_dir());

        let _ = blob::take_fsync_dir_calls(); // reset on this thread
        let body = vec![3u8; 200_000];
        // A top-level key: parent == current/, exercising the F-2 chain trivially; the
        // blob is the FIRST in its fanout, exercising the F-1 intermediate-dir chain.
        fs.put_object("fresh", "first-object.bin", &body[..], "application/octet-stream", BTreeMap::new())
            .unwrap();
        // F-1: the blob fanout-dir CHAIN fsync ran (fsync_blob_dir == chain entry point).
        assert!(
            blob::take_fsync_dir_calls() >= 1,
            "F-1: the first-in-fresh-bucket PUT must fsync the blob fanout ancestor chain"
        );
        // Correctness preserved: the object round-trips bit-for-bit and is consistent.
        let got = read_all(fs.get_object("fresh", "first-object.bin", None).unwrap().body);
        assert_eq!(got, body, "F-1/site-4 first-bucket PUT must round-trip");
        assert_object_consistent(&fs, "fresh", "first-object.bin").unwrap();
    }

    #[test]
    fn f3_upload_part_racing_delete_bucket_returns_no_such_bucket_no_phantom() {
        // Codex pass F-3 [MED — phantom bucket], LOAD-BEARING. upload_part validates the
        // upload PRE-lock, takes the bucket READ lock, then write_blob's
        // `create_dir_all(bucket/blobs/...)`. Without a head_bucket re-check UNDER the
        // read lock, a concurrent abort + DeleteBucket straggler lets upload_part
        // RECREATE the torn-down bucket (a phantom bucket).
        //
        // Deterministic interleaving (no sleeps): an upload_part thread parks at the
        // F-3 pre-lock hook (after pre-lock validation, before the read lock). The main
        // thread then ABORTS the upload (removes the upload dir) and DELETEs the bucket
        // (now empty + no in-flight upload -> succeeds, removing the whole bucket).
        // Releasing upload_part: with the fix it takes the read lock, re-checks
        // head_bucket -> NoSuchBucket, and does NOT recreate the bucket. list_buckets is
        // then empty (no phantom).
        //
        // Fail-without-fix: remove the `self.head_bucket(bucket)?` re-check in
        // upload_part and the resumed write_blob recreates `bucket/blobs/...`; the
        // result is Ok (a part written into a phantom bucket) and list_buckets reports
        // "bkt" -> both asserts FAIL.
        use std::sync::Arc;
        let _serial = upload_part_pause::serialize_test(); // single global hook slot.
        let dir = tempfile::tempdir().unwrap();
        let fs = Arc::new(CasStore::with_fsync(dir.path(), false));
        fs.create_bucket("bkt").unwrap();
        let bk = dir.path().join("bkt");
        let key = "mp/object";
        let upload_id = fs
            .create_multipart_upload("bkt", key, "application/octet-stream", BTreeMap::new())
            .unwrap();

        let hook = upload_part_pause::Hook::arm("bkt");

        // Thread U: upload_part. Parks at the pre-lock hook (validation already passed).
        let fu = Arc::clone(&fs);
        let uid = upload_id.clone();
        let u = std::thread::spawn(move || fu.upload_part("bkt", "mp/object", &uid, 1, &vec![5u8; 4096][..]));
        hook.wait_arrived();

        // While U is parked: abort the upload (remove the upload dir) then delete the
        // bucket. With no in-flight upload + no objects, DeleteBucket SUCCEEDS.
        fs.abort_multipart_upload("bkt", key, &upload_id).unwrap();
        fs.delete_bucket("bkt").unwrap();
        assert!(!bk.exists(), "the bucket dir must be gone after a successful DeleteBucket");

        // Release U: it takes the read lock and re-checks head_bucket.
        hook.release();
        let res = u.join().unwrap();
        upload_part_pause::Hook::disarm();

        // LOAD-BEARING #1: upload_part must fail NoSuchBucket (the F-3 re-check fired).
        assert!(
            matches!(res, Err(StorageError::BucketNotFound)),
            "F-3: upload_part racing a successful DeleteBucket must return NoSuchBucket, got {res:?}"
        );
        // LOAD-BEARING #2: NO phantom bucket — the bucket dir was NOT recreated, and
        // list_buckets reports none.
        assert!(
            !bk.exists(),
            "F-3: upload_part must NOT recreate the torn-down bucket (no phantom bucket dir)"
        );
        assert!(
            fs.list_buckets().unwrap().is_empty(),
            "F-3: a phantom bucket must not appear in list_buckets"
        );
    }

    #[test]
    fn e2_delete_propagates_commit_dir_fsync_and_withholds_reclaim() {
        // E-2 [HIGH — data loss], LOAD-BEARING. delete_object does:
        //   journal blobs -> remove_file(current/K) -> manifest-parent dir fsync ->
        //   reclaim blobs -> delete journal.
        // If the post-remove dir fsync is IGNORED (`let _ = ...`) and reclaim follows, a
        // crash can RESURRECT the OLD manifest (unlink not durable) with its blobs
        // permanently gone.
        //
        // The FORCE_COMMIT_DIR_FSYNC_FAIL hook forces ONLY that fsync to fail. The fix
        // PROPAGATES the error BEFORE reclaim / journal-delete, so: (1) delete returns Err,
        // (2) the blobs are NOT reclaimed, (3) the journal is kept -> recover() settles
        // via the §4 "K absent" rule to a consistent state.
        //
        // Fail-without-fix: revert to `let _ = fsync_dir(...)` and delete returns Ok
        // despite a non-durable unlink; the blob is reclaimed and the journal deleted ->
        // assertions (2)/(3) FAIL. (And in a real crash a resurrected OLD manifest would
        // dangle on a reclaimed blob.)
        let dir = tempfile::tempdir().unwrap();
        let fs = CasStore::with_fsync(dir.path(), true); // --fsync ON (the E-2 path)
        fs.create_bucket("bkt").unwrap();
        let bk = dir.path().join("bkt");

        fs.put_object("bkt", "k", &b"to-be-deleted"[..], "", BTreeMap::new())
            .unwrap();
        let blob_id = {
            let m = manifest::read_manifest(&manifest::manifest_path(&bk.join("current"), "k")).unwrap();
            m.parts[0].blob_id.clone()
        };
        assert_eq!(count_blobs(&bk), 1);

        set_force_commit_dir_fsync_fail(true);
        let res = fs.delete_object("bkt", "k");
        set_force_commit_dir_fsync_fail(false);

        // (1) The error PROPAGATES out of delete_object.
        assert!(
            matches!(res, Err(StorageError::Io(_))),
            "E-2: a delete that cannot durably fsync the manifest-parent dir must fail, got {res:?}"
        );
        // (2) The blob was NOT reclaimed (withheld until the fsync lands).
        assert!(
            blob::blob_path(&bk, &blob_id).exists(),
            "E-2: the blob must NOT be reclaimed when the commit-dir fsync failed"
        );
        // (3) The delete journal was kept for recover().
        assert_eq!(
            list_dir(&bk.join("deleted")).len(),
            1,
            "E-2: the delete journal must be kept for recover() when the commit-dir fsync failed"
        );

        // The unlink landed in-process (only the fsync was faked), so K is absent ->
        // recover()'s §4 rule reclaims the blob and removes the journal. State stays
        // consistent: no live manifest dangles on a missing blob, no blob leaks.
        fs.recover().unwrap();
        assert!(
            matches!(fs.get_object("bkt", "k", None), Err(StorageError::ObjectNotFound)),
            "E-2: the object is gone after the (settled) delete"
        );
        assert!(
            !blob::blob_path(&bk, &blob_id).exists(),
            "E-2: recover() reclaims the deleted object's blob (K absent)"
        );
        assert_eq!(count_blobs(&bk), 0, "E-2: no blob leaked after recover()");
        assert!(
            list_dir(&bk.join("deleted")).is_empty(),
            "E-2: recover() settles and removes the journal"
        );
    }

    #[test]
    fn e3_create_bucket_takes_bucket_write_lock_serializing_against_delete() {
        // E-3 [MED — concurrency], LOAD-BEARING. create_bucket and delete_bucket are the
        // two bucket-existence mutators; both must take the per-bucket WRITE lock so a
        // concurrent Create+Delete of the same name SERIALIZES (cannot both return Ok with
        // the bucket gone — a lost update).
        //
        // Interleaving (deterministic, no sleeps): a delete_bucket thread parks HOLDING
        // the bucket WRITE lock (existing delete_bucket_pause hook). A concurrent
        // create_bucket of the SAME name must BLOCK on lock_bucket (the new WRITE-lock
        // contention probe fires). Release the delete: it removes the bucket; the create
        // then resumes and recreates it. Final state is CONSISTENT — the bucket EXISTS
        // (the create that ran second wins) and both ops are well-defined, not both-Ok-
        // with-bucket-gone.
        //
        // Fail-without-fix: remove the bucket WRITE lock from create_bucket and the create
        // no longer blocks — the contention wait TIMES OUT (None), asserted as a clean
        // failure; and the create races the delete's remove_dir_all (lost update).
        use std::sync::Arc;
        let _serial = bucket_pause::serialize_test(); // single global hook slot.
        let dir = tempfile::tempdir().unwrap();
        let fs = Arc::new(CasStore::with_fsync(dir.path(), false));
        fs.create_bucket("bkt").unwrap(); // pre-exists so delete_bucket has something to remove.
        let bk = dir.path().join("bkt");

        let hook = bucket_pause::Hook::arm("bkt");

        // Thread A: delete_bucket. Parks holding the bucket WRITE lock (bucket empty).
        let fa = Arc::clone(&fs);
        let a = std::thread::spawn(move || fa.delete_bucket("bkt"));
        hook.wait_delete_parked();

        // Thread B: create_bucket of the SAME name. With the WRITE lock it BLOCKS on
        // lock_bucket; without it, it proceeds and races the delete's remove_dir_all.
        let fb = Arc::clone(&fs);
        let b = std::thread::spawn(move || fb.create_bucket("bkt"));

        // A blocked create fires note_contention (via lock_bucket's probe); a lock-free
        // create never does, so a missing lock TIMES OUT (None) -> clean failure not hang.
        let contended = hook.wait_writer_contention_timeout(std::time::Duration::from_secs(5));

        let (ra, rb) = match contended {
            Some(()) => {
                hook.release();
                (a.join().unwrap(), b.join().unwrap())
            }
            None => {
                let rb = b.join().unwrap();
                hook.release();
                (a.join().unwrap(), rb)
            }
        };
        bucket_pause::Hook::disarm();

        // LOAD-BEARING #1: the create must have BLOCKED on the bucket WRITE lock. Without
        // the lock this is None (timeout) and fails here.
        assert!(
            contended.is_some(),
            "create_bucket did NOT block on the per-bucket WRITE lock — create_bucket and \
             delete_bucket are not serialized; a concurrent create can race a bucket teardown"
        );

        // LOAD-BEARING #2: final state is consistent. The delete removed the bucket; the
        // create (which ran second, after the delete released the lock) recreated it ->
        // the bucket EXISTS, with fresh infra. Not both-Ok-with-bucket-gone.
        assert!(ra.is_ok(), "delete_bucket failed: {ra:?}");
        assert!(rb.is_ok(), "create_bucket (second) must recreate the removed bucket: {rb:?}");
        assert!(bk.is_dir(), "the bucket must exist (recreated by the serialized create)");
        assert!(bk.join("current").is_dir(), "the recreated bucket has its infra dirs");
        // And it is usable (a put round-trips), proving a consistent, non-half-created state.
        fs.put_object("bkt", "after", &b"ok"[..], "", BTreeMap::new()).unwrap();
        assert_eq!(read_all(fs.get_object("bkt", "after", None).unwrap().body), b"ok");
    }

    // ---- Codex pass I: honest durability ACK on idempotent/already-done success paths ----

    #[test]
    fn pass_i1_delete_absent_key_fsyncs_manifest_parent_under_fsync() {
        // I-1 [MED — durability]. delete_object's IDEMPOTENT absent-key path (manifest
        // already gone -> 204) must, under --fsync, fsync the manifest-parent dir before
        // returning Ok. Rationale: a RETRY of a delete whose first attempt's unlink
        // SUCCEEDED but post-unlink dir fsync FAILED would otherwise ack 204 here without
        // ever making that earlier unlink durable -> a crash could resurrect the acked-
        // deleted object. A crash is not unit-testable, so we assert the durability fsync
        // RAN on this path (pass-I counter +1) and the op still returns Ok.
        let dir = tempfile::tempdir().unwrap();
        let fs = CasStore::with_fsync(dir.path(), true); // --fsync ON
        fs.create_bucket("bkt").unwrap();

        // Put then delete a key so its manifest-parent dir (current/) EXISTS; a second
        // delete of the SAME (now-absent) key exercises the idempotent absent-key path on
        // a parent that exists — exactly the retry-of-a-real-delete scenario.
        fs.put_object("bkt", "k", &b"v"[..], "", BTreeMap::new()).unwrap();
        fs.delete_object("bkt", "k").unwrap();

        let before = pass_i_fsync_count();
        let res = fs.delete_object("bkt", "k"); // absent now -> idempotent success
        let after = pass_i_fsync_count();

        assert!(res.is_ok(), "I-1: idempotent delete of an absent key must return Ok, got {res:?}");
        assert!(
            after > before,
            "I-1: the absent-key delete path under --fsync must fsync the manifest parent dir \
             (pass-I counter must increase): before={before} after={after}"
        );
    }

    #[test]
    fn pass_i1_delete_absent_key_propagates_manifest_parent_fsync_error() {
        // I-1 [MED — durability], LOAD-BEARING. The absent-key fsync must PROPAGATE a real
        // fsync error (not swallow it): an idempotent retry whose durability fsync FAILS
        // must NOT ack 204. The FORCE_COMMIT_DIR_FSYNC_FAIL hook forces ONLY that fsync to
        // fail (it now also wraps the absent-key path), so delete returns Err.
        //
        // Fail-without-fix: remove the absent-path fsync (revert I-1) and the retry returns
        // Ok despite a non-durable prior unlink -> this assertion FAILS (the err vanishes).
        let dir = tempfile::tempdir().unwrap();
        let fs = CasStore::with_fsync(dir.path(), true);
        fs.create_bucket("bkt").unwrap();
        fs.put_object("bkt", "k", &b"v"[..], "", BTreeMap::new()).unwrap();
        fs.delete_object("bkt", "k").unwrap(); // now absent; current/ parent exists

        set_force_commit_dir_fsync_fail(true);
        let res = fs.delete_object("bkt", "k"); // absent-key path; forced fsync failure
        set_force_commit_dir_fsync_fail(false);

        assert!(
            matches!(res, Err(StorageError::Io(_))),
            "I-1: an idempotent absent-key delete whose manifest-parent fsync FAILS must \
             return Err (honest durability ACK), got {res:?}"
        );
    }

    #[test]
    fn pass_i1_delete_never_existed_key_is_ok_without_fsync_error() {
        // I-1 corollary. For a key that NEVER existed (manifest-parent dir absent) the
        // fsync targets a non-existent dir; a NotFound on the dir itself is a no-op and the
        // idempotent delete still succeeds (Ok) — it must NOT surface NotFound as an error.
        let dir = tempfile::tempdir().unwrap();
        let fs = CasStore::with_fsync(dir.path(), true);
        fs.create_bucket("bkt").unwrap();
        // Deeply-nested key whose parent dir under current/ has never been created.
        let res = fs.delete_object("bkt", "never/created/here/k");
        assert!(
            res.is_ok(),
            "I-1: delete of a never-existed key must be idempotent Ok even when its \
             manifest-parent dir does not exist, got {res:?}"
        );
    }

    #[test]
    fn pass_i2_create_bucket_existing_fsyncs_data_root_under_fsync() {
        // I-2 [MED — durability]. create_bucket on an ALREADY-EXISTING bucket is the
        // idempotent create path (handler maps BucketExists -> 200). Under --fsync it must
        // re-run ensure_infra + fsync the data-root so a RETRY of a create whose first
        // attempt's data-root fsync FAILED makes the bucket dirent durable before acking.
        // Assert the durability fsync RAN (counter +1) and the result is still the
        // idempotent BucketExists.
        let dir = tempfile::tempdir().unwrap();
        let fs = CasStore::with_fsync(dir.path(), true); // --fsync ON
        fs.create_bucket("bkt").unwrap(); // first create

        let before = pass_i_fsync_count();
        let res = fs.create_bucket("bkt"); // already exists -> idempotent path
        let after = pass_i_fsync_count();

        assert!(
            matches!(res, Err(StorageError::BucketExists)),
            "I-2: create_bucket on an existing bucket must return the idempotent \
             BucketExists (handler maps to 200), got {res:?}"
        );
        assert!(
            after > before,
            "I-2: the create-exists path under --fsync must fsync the data-root \
             (pass-I counter must increase): before={before} after={after}"
        );
        // And the bucket is still consistent/usable after the idempotent retry.
        assert!(dir.path().join("bkt").join("current").is_dir());
    }

    #[test]
    fn pass_i_delete_bucket_fsyncs_data_root_before_ok() {
        // delete_bucket data-root fold-in [MED — durability]. A successful delete_bucket
        // under --fsync must fsync the DATA-ROOT (so the bucket-removal dirent is durable)
        // BEFORE acking the 204 — symmetric to create_bucket's site-4. Assert the
        // durability fsync RAN (counter +1) and the bucket is gone.
        let dir = tempfile::tempdir().unwrap();
        let fs = CasStore::with_fsync(dir.path(), true); // --fsync ON
        fs.create_bucket("bkt").unwrap();

        let before = pass_i_fsync_count();
        let res = fs.delete_bucket("bkt"); // empty -> removed
        let after = pass_i_fsync_count();

        assert!(res.is_ok(), "delete_bucket of an empty bucket must succeed, got {res:?}");
        assert!(
            after > before,
            "delete_bucket under --fsync must fsync the data-root before Ok \
             (pass-I counter must increase): before={before} after={after}"
        );
        assert!(
            !dir.path().join("bkt").exists(),
            "delete_bucket must remove the bucket dir"
        );
    }

    #[test]
    fn pass_j_complete_fsyncs_completed_marker_dir_under_fsync() {
        // J [LOW — dirent durability], LOAD-BEARING. CompleteMultipartUpload writes a
        // `completed` marker file (its BYTES fsynced under --fsync) but, pre-J, did NOT
        // fsync the marker's PARENT dir — so a crash before the best-effort rmdir could
        // lose the dirent and re-expose the completed uploadId as in-flight. The J fix adds
        // an fsync_dir(&upload_dir) (mirroring create_multipart_upload's upload.json site)
        // gated on --fsync, wired to the pass-I fsync counter. A crash is not unit-testable,
        // so we assert the marker-dir fsync RAN: the pass-I counter must increase across
        // Complete by MORE than it would without the J block.
        //
        // Fail-without-fix: remove the new `bump_pass_i_fsync()` + fsync_dir(&upload_dir)
        // block and the post-Complete counter drops by 1, so `after >= before + EXPECTED`
        // FAILS.
        let dir = tempfile::tempdir().unwrap();
        let fs = CasStore::with_fsync(dir.path(), true); // --fsync ON (fsync store)
        fs.create_bucket("bkt").unwrap();
        let key = "j/mp/object.bin";
        let (upload_id, parts, etags) = upload_3_parts(&fs, "bkt", key);

        let complete: Vec<CompletePart> = (0..3)
            .map(|i| CompletePart { part_number: (i + 1) as i32, etag: etags[i].clone() })
            .collect();

        let before = pass_i_fsync_count();
        fs.complete_multipart_upload("bkt", key, &upload_id, &complete).unwrap();
        let after = pass_i_fsync_count();

        // The new marker-dir fsync contributes EXACTLY +1 to the pass-I counter beyond any
        // pre-existing blob/commit fsyncs that also bump it. Assert STRICTLY GREATER so the
        // J block is load-bearing regardless of how many other sites bumped during Complete.
        assert!(
            after > before,
            "J: Complete under --fsync must fsync the completed-marker dir \
             (pass-I counter must increase): before={before} after={after}"
        );

        // The object is still durably published and round-trips bit-for-bit.
        let mut want = Vec::new();
        for p in &parts {
            want.extend_from_slice(p);
        }
        let got = read_all(fs.get_object("bkt", key, None).unwrap().body);
        assert_eq!(got, want, "J: Complete must still round-trip the assembled object");
        assert_object_consistent(&fs, "bkt", key).unwrap();
    }

    #[test]
    fn d1_recover_skips_corrupt_journal_and_applies_valid_one() {
        // D-1 [MED — resilience], LOAD-BEARING. A corrupt/garbage `deleted/*.journal`
        // (e.g. a truncated journal from a pre-D-1 crash mid-write, or planted bytes)
        // must NOT make recover() FAIL: recover() must SKIP the unreadable journal
        // (logging a warning, leaving it on disk) and still apply a VALID journal in the
        // same bucket. Aborting recover() on a parse error would wedge startup until a
        // human cleaned the file by hand.
        //
        // Fail-without-fix: revert apply_journal to `Err(e) => return Err(e.into())` on
        // the read/parse error and recover() returns Err -> this test FAILS at the
        // `recover().unwrap()`.
        let (dir, fs) = store();
        let bk = dir.path().join("bkt");

        // (a) A CORRUPT journal: not valid JSON. recover() must skip it.
        let corrupt = bk
            .join("deleted")
            .join(format!("{}.journal", Uuid::new_v4()));
        std::fs::write(&corrupt, b"{ this is not valid journal json !!").unwrap();

        // (b) A VALID delete journal for an absent key listing a real orphan blob, so we
        // can prove the valid journal STILL applies (its blob is reclaimed) even though a
        // corrupt journal sits beside it.
        let orphan = blob::write_blob(&bk, &b"reclaim me via a valid journal"[..]).unwrap();
        let valid = bk
            .join("deleted")
            .join(format!("{}.journal", Uuid::new_v4()));
        let j = Journal {
            mode: JournalMode::Delete,
            supersedes_key: "gone".into(), // absent key -> delete journal EXECUTES
            commit_nonce: String::new(),
            expected_new_etag: String::new(),
            blobs: vec![orphan.blob_id.clone()],
        };
        fs.write_journal(&valid, &j).unwrap();

        // recover() must NOT fail despite the corrupt journal.
        let stats = fs.recover().expect("recover() must tolerate a corrupt journal, not fail");

        // The valid journal applied: its orphan blob is gone, the journal is removed.
        assert!(
            !blob::blob_path(&bk, &orphan.blob_id).exists(),
            "the VALID journal must still apply (orphan blob reclaimed) despite the corrupt one"
        );
        assert!(!valid.exists(), "the valid journal is removed after it applies");
        assert!(stats.journal_blobs_reclaimed >= 1, "valid journal reclaimed its blob");

        // The corrupt journal is SKIPPED and left in place (not deleted, not fatal).
        assert!(
            corrupt.exists(),
            "the corrupt journal is left on disk (skipped, not consumed)"
        );
    }

    #[test]
    fn d1_write_journal_is_atomic_no_torn_journal_on_disk() {
        // D-1 [MED — atomicity]. write_journal must publish the journal via temp+rename,
        // so the only `*.journal` file that ever lands in `deleted/` is fully serialized
        // (a valid Journal), and no `*.journal.tmp.*` temp is left behind on success.
        let (dir, fs) = store();
        let bk = dir.path().join("bkt");
        let jpath = bk
            .join("deleted")
            .join(format!("{}.journal", Uuid::new_v4()));
        let j = Journal {
            mode: JournalMode::Delete,
            supersedes_key: "k".into(),
            commit_nonce: String::new(),
            expected_new_etag: String::new(),
            blobs: vec![],
        };
        fs.write_journal(&jpath, &j).unwrap();

        // No temp sibling survives, and the published file re-reads as a valid Journal.
        let entries = list_dir(&bk.join("deleted"));
        assert!(
            entries.iter().all(|n| !n.contains(".tmp.")),
            "no `.journal.tmp.*` temp may survive a successful write_journal, saw {entries:?}"
        );
        let round = CasStore::read_journal(&jpath).expect("published journal must parse");
        assert_eq!(round.supersedes_key, "k");
    }

    #[test]
    fn multipart_under_fsync_dir_fsync_path_round_trips() {
        // A6 [MED]. Under --fsync, CreateMultipartUpload and UploadPart fsync the
        // CONTAINING directories (arriving/, the upload dir, parts/) so the upload.json
        // and `.ref` directory ENTRIES are crash-durable, not just their file bytes.
        // This exercises that dir-fsync path (which was previously skipped) on a NESTED
        // key and asserts it runs WITHOUT error and the object still round-trips bit-
        // for-bit. (A pure-durability change: the assertion is "the fsync_dir calls do
        // not error and correctness is unchanged"; the crash-window itself is not
        // observable in a unit test.)
        let dir = tempfile::tempdir().unwrap();
        let fs = CasStore::with_fsync(dir.path(), true); // --fsync ON
        fs.create_bucket("bkt").unwrap();
        let bk = dir.path().join("bkt");
        let key = "deep/nested/key/object.bin";

        let (upload_id, parts, etags) = upload_3_parts(&fs, "bkt", key);
        // upload.json + 3 part refs all written via the fsync'd dir path.
        assert!(bk.join("arriving").join(&upload_id).join("upload.json").exists());
        assert_eq!(fs.list_parts("bkt", key, &upload_id).unwrap().len(), 3);

        let complete: Vec<CompletePart> = (0..3)
            .map(|i| CompletePart { part_number: (i + 1) as i32, etag: etags[i].clone() })
            .collect();
        fs.complete_multipart_upload("bkt", key, &upload_id, &complete).unwrap();

        // Round-trips bit-for-bit.
        let mut want = Vec::new();
        for p in &parts {
            want.extend_from_slice(p);
        }
        let got = read_all(fs.get_object("bkt", key, None).unwrap().body);
        assert_eq!(got, want, "fsync-path multipart object must round-trip exactly");
        assert_object_consistent(&fs, "bkt", key).unwrap();
    }

    #[test]
    fn upload_part_propagates_parts_dir_fsync_error_and_rolls_back() {
        // B4 [MED]. Under --fsync, UploadPart fsyncs the `parts/` dir so the renamed
        // `.ref` ENTRY is durable. The fsync error must be PROPAGATED (not swallowed) —
        // a part ACKed with a non-durable dir entry is a false durability promise — and
        // the just-written part (ref + blob) must be rolled back so the part number is
        // left in its prior state and the client can retry.
        //
        // Fail-without-fix: revert the `?`-propagation (`let _ = fsync_dir(...)`) and the
        // upload_part below returns Ok(_) instead of Err -> the asserts FAIL.
        let dir = tempfile::tempdir().unwrap();
        let fs = CasStore::with_fsync(dir.path(), true); // --fsync ON
        fs.create_bucket("bkt").unwrap();
        let bk = dir.path().join("bkt");
        let key = "fsync/part";
        let upload_id = fs
            .create_multipart_upload("bkt", key, "application/octet-stream", BTreeMap::new())
            .unwrap();

        // Arm the parts/-dir fsync failure for the next upload_part on this thread.
        set_force_parts_fsync_fail(true);
        let res = fs.upload_part("bkt", key, &upload_id, 1, &vec![9u8; 4096][..]);
        set_force_parts_fsync_fail(false);

        // The error PROPAGATED.
        assert!(
            matches!(res, Err(StorageError::Io(_))),
            "parts/ dir-fsync error must propagate from upload_part, got {res:?}"
        );
        // Rolled back: no `.ref` installed, and the part blob was reclaimed (0 blobs).
        let upload_dir = bk.join("arriving").join(&upload_id);
        assert!(
            !upload_dir.join("parts").join("00001.ref").exists(),
            "the part ref must be rolled back on a propagated fsync error"
        );
        assert_eq!(
            count_blobs(&bk),
            0,
            "the part blob must be reclaimed on a propagated fsync error"
        );
        assert!(
            fs.list_parts("bkt", key, &upload_id).unwrap().is_empty(),
            "no part should be recorded after the rolled-back upload_part"
        );

        // A subsequent (un-armed) retry of the same part succeeds and is durable.
        let etag = fs.upload_part("bkt", key, &upload_id, 1, &vec![9u8; 4096][..]).unwrap();
        assert_eq!(etag, format!("\"{}\"", md5_hex(&vec![9u8; 4096])));
        assert_eq!(count_blobs(&bk), 1);
        assert_eq!(fs.list_parts("bkt", key, &upload_id).unwrap().len(), 1);
    }

    #[test]
    fn complete_rejects_missing_or_short_part_blob_invalid_part() {
        // A7 [MED]. Complete builds the manifest from each `.ref`'s recorded size/md5
        // but must also STAT the referenced blob: a missing OR short blob (a stale ref,
        // a crash, or the A1 race) must yield InvalidPart and publish NOTHING. Two
        // sub-cases below: blob deleted, and blob truncated to the wrong size.
        for case in ["missing", "short"] {
            let (dir, fs) = store();
            let bk = dir.path().join("bkt");
            let key = "mp/object";
            let (upload_id, _parts, etags) = upload_3_parts(&fs, "bkt", key);

            // Find part 2's blob id from its ref, then corrupt that blob on disk.
            let refs =
                CasStore::read_part_refs(&bk.join("arriving").join(&upload_id)).unwrap();
            let blob2 = blob::blob_path(&bk, &refs[&2].blob_id);
            match case {
                "missing" => std::fs::remove_file(&blob2).unwrap(),
                "short" => {
                    // Rewrite the blob shorter than its recorded size (size mismatch).
                    std::fs::write(&blob2, b"short").unwrap();
                }
                _ => unreachable!(),
            }

            let complete: Vec<CompletePart> = (0..3)
                .map(|i| CompletePart { part_number: (i + 1) as i32, etag: etags[i].clone() })
                .collect();
            let r = fs.complete_multipart_upload("bkt", key, &upload_id, &complete);
            assert!(
                matches!(r, Err(StorageError::InvalidPart)),
                "[{case}] Complete must fail InvalidPart when a part blob is {case}, got {r:?}"
            );
            // NOTHING was published: no live manifest for the key.
            assert!(
                matches!(fs.head_object("bkt", key), Err(StorageError::ObjectNotFound)),
                "[{case}] no manifest must be published when a part blob is {case}"
            );
            // The upload is left intact (retryable) — its dir still exists.
            assert!(bk.join("arriving").join(&upload_id).exists());
        }
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

    // ----- Codex pass G: multipart ops check head_bucket first (NoSuchBucket precedence)
    //
    // Each test proves the FIRST error for a request against a MISSING bucket is
    // NoSuchBucket (BucketNotFound), NOT NoSuchUpload — matching S3 and the other
    // handlers — while the normal path (existing bucket, missing/wrong upload) still
    // yields NoSuchUpload. The upload id used for the "missing bucket" case is a VALID
    // uuid (so upload_dir's parse succeeds): without the up-front head_bucket the op
    // would resolve the (absent) upload dir and return NoSuchUpload.

    #[test]
    fn g_upload_part_missing_bucket_is_no_such_bucket() {
        let (_dir, fs) = store();
        // A live upload in the real bucket gives us a valid uuid to reuse.
        let upload_id = fs
            .create_multipart_upload("bkt", "k", "", BTreeMap::new())
            .unwrap();

        // Missing bucket -> NoSuchBucket (precedence), NOT NoSuchUpload.
        assert!(
            matches!(
                fs.upload_part("nope", "k", &upload_id, 1, &b"x"[..]).unwrap_err(),
                StorageError::BucketNotFound
            ),
            "upload_part against a missing bucket must be NoSuchBucket, not NoSuchUpload"
        );
        // Existing bucket, missing upload -> still NoSuchUpload.
        let bogus = Uuid::new_v4().to_string();
        assert!(matches!(
            fs.upload_part("bkt", "k", &bogus, 1, &b"x"[..]).unwrap_err(),
            StorageError::NoSuchUpload
        ));
    }

    #[test]
    fn g_complete_missing_bucket_is_no_such_bucket() {
        let (_dir, fs) = store();
        let upload_id = fs
            .create_multipart_upload("bkt", "k", "", BTreeMap::new())
            .unwrap();
        let etag = fs.upload_part("bkt", "k", &upload_id, 1, &b"x"[..]).unwrap();
        let complete = vec![CompletePart { part_number: 1, etag: etag.clone() }];

        // Missing bucket -> NoSuchBucket (precedence), NOT NoSuchUpload.
        assert!(
            matches!(
                fs.complete_multipart_upload("nope", "k", &upload_id, &complete).unwrap_err(),
                StorageError::BucketNotFound
            ),
            "complete against a missing bucket must be NoSuchBucket, not NoSuchUpload"
        );
        // Existing bucket, missing upload -> still NoSuchUpload.
        let bogus = Uuid::new_v4().to_string();
        assert!(matches!(
            fs.complete_multipart_upload("bkt", "k", &bogus, &complete).unwrap_err(),
            StorageError::NoSuchUpload
        ));
    }

    #[test]
    fn h_complete_racing_abort_returns_no_such_upload_not_invalid_part() {
        // Codex pass H [LOW — S3 error code on a concurrent race], LOAD-BEARING.
        // `complete_multipart_upload` validates the upload (assert_upload_matches) PRE-lock,
        // then takes the per-key lock and calls read_part_refs. A concurrent Abort that
        // removes the upload dir in that window makes read_part_refs return an EMPTY map,
        // so the per-part lookup reports InvalidPart — the WRONG error for a vanished
        // upload (should be NoSuchUpload).
        //
        // Deterministic interleaving (no sleeps): a Complete thread parks at the H pre-lock
        // hook (after pre-lock validation, before the bucket/per-key locks). The main thread
        // then ABORTS the upload (which takes the per-key lock — free, since Complete has
        // not taken it yet — and removes the upload dir). Releasing Complete: with the fix it
        // takes the per-key lock, re-checks the upload, finds the dir gone, and returns
        // NoSuchUpload.
        //
        // Fail-without-fix: remove the post-lock `assert_upload_matches` re-check in
        // complete_multipart_upload and the resumed Complete's read_part_refs returns an
        // empty map -> the per-part lookup yields InvalidPart -> this assertion FAILS.
        use std::sync::Arc;
        let _serial = complete_pause::serialize_test(); // single global hook slot.
        let dir = tempfile::tempdir().unwrap();
        let fs = Arc::new(CasStore::with_fsync(dir.path(), false));
        fs.create_bucket("bkt").unwrap();
        let bk = dir.path().join("bkt");
        let key = "h/object";
        let upload_id = fs
            .create_multipart_upload("bkt", key, "application/octet-stream", BTreeMap::new())
            .unwrap();
        let etag = fs.upload_part("bkt", key, &upload_id, 1, &vec![7u8; 4096][..]).unwrap();

        let hook = complete_pause::Hook::arm("bkt", key);

        // Thread C: Complete. Parks at the pre-lock hook (validation already passed).
        let fc = Arc::clone(&fs);
        let uid = upload_id.clone();
        let et = etag.clone();
        let c = std::thread::spawn(move || {
            fc.complete_multipart_upload(
                "bkt",
                "h/object",
                &uid,
                &[CompletePart { part_number: 1, etag: et }],
            )
        });
        hook.wait_arrived();

        // While C is parked: abort the upload (removes the whole upload dir under the
        // per-key lock — uncontended, C has not taken it yet).
        fs.abort_multipart_upload("bkt", key, &upload_id).unwrap();
        assert!(
            !bk.join("arriving").join(&upload_id).exists(),
            "the upload dir must be gone after a successful Abort"
        );

        // Release C: with the H fix it takes the per-key lock, re-checks the upload, and
        // returns NoSuchUpload.
        hook.release();
        let res = c.join().unwrap();
        complete_pause::Hook::disarm();

        assert!(
            matches!(res, Err(StorageError::NoSuchUpload)),
            "H: Complete racing a concurrent Abort (upload removed before read_part_refs) \
             must return NoSuchUpload, not InvalidPart, got {res:?}"
        );
        // The Abort reclaimed the only part blob; Complete published nothing.
        assert_eq!(count_blobs(&bk), 0, "H: no blob may leak / be published on the lost race");
        assert!(
            matches!(fs.get_object("bkt", key, None), Err(StorageError::ObjectNotFound)),
            "H: nothing must be published for the raced-away upload"
        );
    }

    #[test]
    fn h_complete_empty_and_bad_parts_still_invalid_part() {
        // H boundary: the re-check must NOT turn the genuinely-empty-parts case (a real,
        // present upload with NO parts uploaded) OR the bad-part case into NoSuchUpload —
        // both stay InvalidPart. This proves the fix distinguishes "upload dir gone ->
        // NoSuchUpload" from "upload exists but no/unknown parts -> InvalidPart".
        let (_dir, fs) = store();
        let key = "h/empty";
        let upload_id = fs
            .create_multipart_upload("bkt", key, "", BTreeMap::new())
            .unwrap();

        // Upload exists, but the client claims a part that was never uploaded -> InvalidPart
        // (read_part_refs returns an empty map for the present-but-partless upload, and the
        // per-part lookup misses).
        let claim = vec![CompletePart { part_number: 1, etag: "\"deadbeef\"".to_string() }];
        assert!(
            matches!(
                fs.complete_multipart_upload("bkt", key, &upload_id, &claim).unwrap_err(),
                StorageError::InvalidPart
            ),
            "a present upload with no uploaded parts must be InvalidPart, not NoSuchUpload"
        );

        // Upload part 1, then claim a WRONG etag -> InvalidPart (upload present).
        let etag = fs.upload_part("bkt", key, &upload_id, 1, &b"abc"[..]).unwrap();
        let _ = etag;
        let bad = vec![CompletePart { part_number: 1, etag: "\"00000000\"".to_string() }];
        assert!(
            matches!(
                fs.complete_multipart_upload("bkt", key, &upload_id, &bad).unwrap_err(),
                StorageError::InvalidPart
            ),
            "a present upload with a mismatched part etag must be InvalidPart, not NoSuchUpload"
        );

        // An empty parts list is still InvalidPart (pre-lock guard, upload present).
        assert!(
            matches!(
                fs.complete_multipart_upload("bkt", key, &upload_id, &[]).unwrap_err(),
                StorageError::InvalidPart
            ),
            "an empty parts list must be InvalidPart, not NoSuchUpload"
        );
    }

    #[test]
    fn g_abort_missing_bucket_is_no_such_bucket() {
        let (_dir, fs) = store();
        let upload_id = fs
            .create_multipart_upload("bkt", "k", "", BTreeMap::new())
            .unwrap();

        // Missing bucket -> NoSuchBucket (precedence). Abort previously never called
        // head_bucket at all, so without the fix this returned NoSuchUpload.
        assert!(
            matches!(
                fs.abort_multipart_upload("nope", "k", &upload_id).unwrap_err(),
                StorageError::BucketNotFound
            ),
            "abort against a missing bucket must be NoSuchBucket, not NoSuchUpload"
        );
        // Existing bucket, missing upload -> still NoSuchUpload.
        let bogus = Uuid::new_v4().to_string();
        assert!(matches!(
            fs.abort_multipart_upload("bkt", "k", &bogus).unwrap_err(),
            StorageError::NoSuchUpload
        ));
    }

    #[test]
    fn g_list_parts_missing_bucket_is_no_such_bucket() {
        let (_dir, fs) = store();
        let upload_id = fs
            .create_multipart_upload("bkt", "k", "", BTreeMap::new())
            .unwrap();

        // Missing bucket -> NoSuchBucket (precedence). ListParts previously never called
        // head_bucket at all, so without the fix this returned NoSuchUpload.
        assert!(
            matches!(
                fs.list_parts("nope", "k", &upload_id).unwrap_err(),
                StorageError::BucketNotFound
            ),
            "list_parts against a missing bucket must be NoSuchBucket, not NoSuchUpload"
        );
        // Existing bucket, missing upload -> still NoSuchUpload.
        let bogus = Uuid::new_v4().to_string();
        assert!(matches!(
            fs.list_parts("bkt", "k", &bogus).unwrap_err(),
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
    fn list_prefix_with_dotdot_does_not_escape_walk_root() {
        // B3 [MED — API-reachable traversal/DoS], LOAD-BEARING. A client ListObjectsV2
        // `prefix` is a FILTER, never a path. Before the fix, `prefix_walk_root` pushed
        // the prefix's dir-portion segments onto `current_root` with NO sanitization, so
        // a prefix like `../<sentinel>/...` rooted the recursive walk OUTSIDE `current/`
        // — an unbounded-readdir DoS over arbitrary host dirs. The fix sanitizes the
        // dir-portion: any `..`/`.`/empty segment (or an absolute dir-portion) DROPS the
        // prune and roots the walk at `current_root`; the per-key `starts_with(prefix)`
        // filter then matches nothing (no 400 — the escaping prefix is simply unmatched).
        //
        // Fail-without-fix: revert the sanitization and `walk_root` resolves to the
        // sentinel dir OUTSIDE current/, so the assert `walk_root == current_root` FAILS.
        let (dir, fs) = store();
        let bk = dir.path().join("bkt");
        let current_root = bk.join("current");

        // Plant a SENTINEL directory OUTSIDE current/ (a sibling under the bucket root),
        // containing a manifest-looking file. If the walk ever escaped to it, the walk
        // would readdir here. It must NEVER be read.
        let sentinel = bk.join("escape-sentinel");
        std::fs::create_dir_all(&sentinel).unwrap();
        std::fs::write(
            sentinel.join("leaked.s3gw-live.meta"),
            b"{\"should\":\"never be listed\"}",
        )
        .unwrap();

        // A legitimate object so the bucket is non-empty.
        put(&fs, "real/key");

        // The escaping prefix's dir-portion is `../escape-sentinel` -> walk_root MUST
        // fall back to current_root (no escape).
        let escaping_prefix = "../escape-sentinel/leaked";
        let (walk_root, strip) = fs.prefix_walk_root(&current_root, escaping_prefix);
        assert_eq!(
            walk_root, current_root,
            "escaping prefix must NOT root the walk outside current/"
        );
        assert_eq!(strip, current_root);

        // End-to-end: the listing with the escaping prefix returns NOTHING (the sentinel
        // is never surfaced) and does not error.
        let mut input = li("bkt");
        input.prefix = escaping_prefix.to_string();
        let out = fs.list_objects(&input).unwrap();
        assert!(
            out.objects.is_empty() && out.common_prefixes.is_empty(),
            "escaping prefix must match nothing, got {out:?}"
        );

        // A normal directory-boundary prefix still prunes to its subtree.
        let (clean_root, _) = fs.prefix_walk_root(&current_root, "real/");
        assert_eq!(
            clean_root,
            current_root.join("real"),
            "a clean prefix must still prune to current/real/"
        );
        let mut input2 = li("bkt");
        input2.prefix = "real/".into();
        let out2 = fs.list_objects(&input2).unwrap();
        assert_eq!(keys_of(&out2), vec!["real/key"]);

        // Absolute and `.`-laden dir-portions also fall back to current_root.
        let (abs_root, _) = fs.prefix_walk_root(&current_root, "/etc/passwd");
        assert_eq!(abs_root, current_root);
        let (dot_root, _) = fs.prefix_walk_root(&current_root, "./x/y");
        assert_eq!(dot_root, current_root);
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

//! Immutable, uuid-named blob store (content-addressed storage rewrite, Phase A).
//!
//! A **blob** is an immutable file holding object data. For a single-part PUT the
//! whole body is one blob; for multipart, each part is one blob (Phase A only
//! writes single-part blobs, but the model is multipart-compatible). A blob id is
//! a fresh v4 UUID; its on-disk name is the full uuid string and its directory is
//! derived by a 2×2-hex fanout of the id (`blobs/{ab}/{cd}/{uuid}`).
//!
//! Blobs are written ONCE via Direct-IO with a ONE-PASS MD5 (read→md5.update→
//! pwrite over a reused aligned buffer — the payload is never held in memory),
//! fsynced (data fsync is always on, like today's `--fsync`-independent data
//! fsync), and never opened for write again. Reads use the existing
//! `DioFile::open_read` (O_DIRECT + buffered fallback, O_NOFOLLOW).
//!
//! See `REDESIGN.md` §1.1 / §1.2.

use std::io::{self, Read};
use std::path::{Path, PathBuf};

use md5::{Digest, Md5};
use uuid::Uuid;

use super::aligned::{AlignedBuf, DEFAULT_BUF_SIZE};
use super::directio::DioFile;

/// The per-bucket blobs subdirectory name.
pub const BLOBS_DIR: &str = "blobs";

/// Outcome of writing a blob: its id, byte size, and hex MD5 of its bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobInfo {
    /// v4 uuid; the blob's on-disk file name.
    pub blob_id: String,
    pub size: u64,
    /// Lowercase hex MD5 of the blob bytes (no quotes).
    pub md5_hex: String,
}

/// Resolve a blob id to its on-disk path under `bucket_root` using the 2×2-hex
/// fanout: `blobs/{id[0..2]}/{id[2..4]}/{id}`. The two parent dirs are created
/// lazily by [`write_blob`]; this is the pure path computation.
///
/// A blob id is a syntactic uuid (see [`is_valid_blob_id`]); it is never an
/// absolute or relative path, so a crafted manifest cannot point a part at an
/// arbitrary filesystem location — there is no path to validate, only a uuid.
pub fn blob_path(bucket_root: &Path, blob_id: &str) -> PathBuf {
    // Caller is expected to have validated the id; fanout on the first 4 hex
    // chars. We index by char boundaries which are ASCII for a uuid.
    let (l1, l2) = fanout(blob_id);
    bucket_root.join(BLOBS_DIR).join(l1).join(l2).join(blob_id)
}

/// First two fanout components (`ab`, `cd`) of a blob id. Falls back to `00`
/// for malformed-but-short ids (never produced internally; validated upstream).
fn fanout(blob_id: &str) -> (&str, &str) {
    let l1 = blob_id.get(0..2).unwrap_or("00");
    let l2 = blob_id.get(2..4).unwrap_or("00");
    (l1, l2)
}

/// True iff `id` is a syntactically valid v4-style uuid (8-4-4-4-12 lowercase
/// hex with hyphens). Used to syntactically check a manifest's `blob_id` — the
/// only validation a part reference needs, since the id is resolved through
/// [`blob_path`] and never opened as a client-supplied path.
pub fn is_valid_blob_id(id: &str) -> bool {
    Uuid::parse_str(id).is_ok()
}

// Test-only injection: force `write_blob` to take the buffered (non-O_DIRECT)
// path even where O_DIRECT would be accepted, so the buffered-fallback branch is
// covered on filesystems that DO support O_DIRECT. Thread-local so it never leaks
// across parallel tests. (The Direct-IO path is the default and is what most
// tmpfs/CI filesystems already exercise via the EINVAL fallback in `DioFile`.)
#[cfg(test)]
thread_local! {
    static FORCE_BUFFERED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
pub(crate) fn set_force_buffered(v: bool) {
    FORCE_BUFFERED.with(|c| c.set(v));
}

/// Stream `body` into a fresh blob under `bucket_root/blobs/`, computing the MD5
/// in one pass while writing, then fsync the blob (data durability is ALWAYS on).
///
/// Returns the [`BlobInfo`] (id, size, hex md5). On any error the partially
/// written blob is removed so no orphan with a known-but-uncommitted id is left
/// — the caller has not yet recorded the id in a manifest, so this cleanup is
/// exact (see REDESIGN §1.1: a single-PUT pre-commit failure deletes its one
/// blob directly).
pub fn write_blob<R: Read>(bucket_root: &Path, mut body: R) -> io::Result<BlobInfo> {
    let blob_id = Uuid::new_v4().to_string();
    let path = blob_path(bucket_root, &blob_id);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // RAII cleanup of the partial blob on any early return.
    struct PartialBlob<'a>(&'a Path, bool);
    impl Drop for PartialBlob<'_> {
        fn drop(&mut self) {
            if self.1 {
                let _ = std::fs::remove_file(self.0);
            }
        }
    }
    let mut cleanup = PartialBlob(&path, true);

    let file = DioFile::create_write(&path)?;
    #[cfg(test)]
    if FORCE_BUFFERED.with(|c| c.get()) {
        file.force_buffered_for_test()?;
    }

    let mut buf = AlignedBuf::new(DEFAULT_BUF_SIZE);
    let mut hasher = Md5::new();
    let mut written: u64 = 0;
    let cap = buf.capacity();
    loop {
        // ONE-PASS: read a block, fold into MD5, write the same block. The
        // payload is never fully materialized in memory.
        let n = read_full(&mut body, &mut buf[..cap])?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        write_all_at(&file, &buf[..n], written)?;
        written += n as u64;
    }
    // Data fsync is ALWAYS on (independent of the --fsync metadata flag): a blob
    // that a manifest will reference must be durable before the manifest commits.
    file.fsync()?;
    drop(file);

    cleanup.1 = false; // committed-as-a-file; the manifest commit owns it now.
    Ok(BlobInfo {
        blob_id,
        size: written,
        md5_hex: hex::encode(hasher.finalize()),
    })
}

/// Move an existing blob to a FRESH uuid id via a same-filesystem `rename` (O(1),
/// NO data copy), returning the new id. Used by CompleteMultipartUpload to give the
/// committed manifest sole ownership of the part blobs: after the move the upload's
/// surviving `.ref`s point at the now-ENOENT OLD id, so any later abort/gc/retry
/// reclaim through those refs is a harmless no-op that can never touch the live
/// object's blobs (REDESIGN §6 / Codex pass B1).
///
/// `rename(2)` within one filesystem is atomic and does not copy the bytes — the
/// blob's inode is untouched, preserving the one-pass-MD5 / no-data-copy payload
/// invariant. The destination's two fanout parent dirs are created first. The `from`
/// id is assumed already validated (it came from a stored ref Complete vetted); the
/// `to` id is a freshly minted uuid.
pub fn move_blob_to_new_id(bucket_root: &Path, from_id: &str) -> io::Result<String> {
    let new_id = Uuid::new_v4().to_string();
    let from = blob_path(bucket_root, from_id);
    let to = blob_path(bucket_root, &new_id);
    if let Some(parent) = to.parent() {
        std::fs::create_dir_all(parent)?;
    }
    super::directio::rename(&from, &to)?;
    Ok(new_id)
}

/// Move a blob BACK from its manifest-owned id to its original ref id — the rollback
/// of [`move_blob_to_new_id`] when a later step of Complete fails. Same-filesystem
/// `rename`, no copy. Restores the upload to its pre-Complete state so it stays
/// retryable (E2). Idempotent-ish: if the source is already gone (e.g. a partial
/// rollback) the caller treats the error as best-effort during unwind.
pub fn move_blob_back(bucket_root: &Path, from_id: &str, to_id: &str) -> io::Result<()> {
    let from = blob_path(bucket_root, from_id);
    let to = blob_path(bucket_root, to_id);
    if let Some(parent) = to.parent() {
        std::fs::create_dir_all(parent)?;
    }
    super::directio::rename(&from, &to)
}

// Test-only counter of `fsync_blob_dir` calls, so a load-bearing test can assert
// the C1 fanout-dir fsync actually runs on the durable path (and is ORDERED before
// the manifest commit). Compiles out entirely in non-test builds.
#[cfg(test)]
thread_local! {
    static FSYNC_DIR_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Test-only: read-and-reset the `fsync_blob_dir` call counter.
#[cfg(test)]
pub(crate) fn take_fsync_dir_calls() -> usize {
    FSYNC_DIR_CALLS.with(|c| {
        let n = c.get();
        c.set(0);
        n
    })
}

/// C1 [HIGH — durability]: fsync a blob's fanout PARENT dir (`blobs/{ab}/{cd}/`) so
/// the blob's DIRENT — not just its file bytes — is durable. `write_blob` /
/// `move_blob_to_new_id` fsync the blob FILE (and create its two fanout dirs), but a
/// crash can still lose the just-created DIRENT in the fanout parent. The caller MUST
/// invoke this (under `--fsync`) AFTER writing/moving the blob and BEFORE committing
/// the manifest that references it (`publish`), so the blob is reachable on disk
/// before the manifest points at it — otherwise a durable manifest can reference a
/// blob whose dirent was lost (a dangling live object).
///
/// Best-effort on the missing-parent case (the parent always exists post-write); a
/// genuine fsync error is propagated so the caller fails BEFORE the commit rather
/// than acking a non-durable blob.
pub fn fsync_blob_dir(bucket_root: &Path, blob_id: &str) -> io::Result<()> {
    #[cfg(test)]
    FSYNC_DIR_CALLS.with(|c| c.set(c.get() + 1));
    let path = blob_path(bucket_root, blob_id);
    if let Some(parent) = path.parent() {
        super::directio::fsync_dir(parent)?;
    }
    Ok(())
}

/// Open a blob for streaming reads by id (Direct-IO, O_NOFOLLOW). A missing blob
/// surfaces as an `io::Error` (`NotFound`) — the reader treats this as fail-fast
/// truncation (REDESIGN §5).
pub fn open_blob(bucket_root: &Path, blob_id: &str) -> io::Result<DioFile> {
    let path = blob_path(bucket_root, blob_id);
    DioFile::open_read(&path)
}

/// Delete a blob by id (idempotent: a missing blob is a no-op). Used by the
/// reclaim step of the commit/delete journal, and by recover()/GC.
///
/// A4 [HIGH — validate blob_id before unlink]: the id is validated with
/// [`is_valid_blob_id`] BEFORE it is resolved to a path. Reclaim ids can originate
/// from an ON-DISK journal/manifest/ref (replayed by `recover()`/`apply_journal`),
/// which a corrupt or PLANTED file could populate with a `..`-laden or absolute
/// "blob_id". `blob_path` does a fixed 2×2 fanout of the FIRST FOUR chars and then
/// `join`s the WHOLE id, so an id like `../../../etc/cron.d/x` would resolve OUTSIDE
/// the bucket and unlink an arbitrary host file during recovery. A non-uuid id is
/// therefore SKIPPED (treated as a no-op) — it can never name a blob this store
/// wrote (every blob id is a fresh v4 uuid), so skipping it loses nothing while
/// closing the planted-journal arbitrary-unlink hole. This single chokepoint guards
/// EVERY reclaim-by-id site (publish, delete, apply_journal, gc_abandoned, abort).
pub fn reclaim_blob(bucket_root: &Path, blob_id: &str) -> io::Result<()> {
    if !is_valid_blob_id(blob_id) {
        return Ok(());
    }
    let path = blob_path(bucket_root, blob_id);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Read up to `buf.len()` bytes, looping until the buffer is full or EOF.
/// (Local copy of `filesystem::read_full` so the new modules are self-contained.)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn md5_hex(data: &[u8]) -> String {
        let mut h = Md5::new();
        h.update(data);
        hex::encode(h.finalize())
    }

    #[test]
    fn fanout_path_is_two_by_two_hex() {
        let root = Path::new("/data/bk");
        let id = "b3f1c2a4-1111-2222-3333-444455556666";
        let p = blob_path(root, id);
        assert_eq!(p, Path::new("/data/bk/blobs/b3/f1").join(id));
    }

    #[test]
    fn blob_id_validation() {
        assert!(is_valid_blob_id(&Uuid::new_v4().to_string()));
        assert!(!is_valid_blob_id("not-a-uuid"));
        assert!(!is_valid_blob_id("../../etc/passwd"));
        assert!(!is_valid_blob_id(""));
    }

    #[test]
    fn write_read_round_trip_small() {
        let dir = tempfile::tempdir().unwrap();
        let data = b"the quick brown fox jumps over the lazy dog";
        let info = write_blob(dir.path(), &data[..]).unwrap();
        assert_eq!(info.size, data.len() as u64);
        assert_eq!(info.md5_hex, md5_hex(data));
        assert!(is_valid_blob_id(&info.blob_id));

        // The file lives at the fanout path.
        let p = blob_path(dir.path(), &info.blob_id);
        assert!(p.exists());

        // Read it back through open_blob.
        let f = open_blob(dir.path(), &info.blob_id).unwrap();
        assert_eq!(f.size().unwrap(), data.len() as u64);
        let mut buf = vec![0u8; data.len()];
        let n = f.pread_at(&mut buf, 0).unwrap();
        assert_eq!(n, data.len());
        assert_eq!(&buf, data);
    }

    #[test]
    fn write_read_round_trip_streaming_50mb() {
        let dir = tempfile::tempdir().unwrap();
        // 50 MiB of pseudo-random-ish bytes (deterministic).
        let size = 50 * 1024 * 1024usize;
        let mut data = vec![0u8; size];
        for (i, b) in data.iter_mut().enumerate() {
            *b = (i.wrapping_mul(2654435761) >> 13) as u8;
        }
        let info = write_blob(dir.path(), &data[..]).unwrap();
        assert_eq!(info.size, size as u64);
        assert_eq!(info.md5_hex, md5_hex(&data));

        // Stream it back and verify byte-exact.
        let mut reader = super::super::reader::PlainFileReader::open(
            &blob_path(dir.path(), &info.blob_id),
            None,
        )
        .unwrap();
        let mut out = Vec::with_capacity(size);
        reader.read_to_end(&mut out).unwrap();
        assert_eq!(out.len(), size);
        assert_eq!(out, data);
    }

    #[test]
    fn buffered_fallback_path_produces_same_md5() {
        let dir = tempfile::tempdir().unwrap();
        let data: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        set_force_buffered(true);
        let info = write_blob(dir.path(), &data[..]);
        set_force_buffered(false);
        let info = info.unwrap();
        assert_eq!(info.size, data.len() as u64);
        assert_eq!(info.md5_hex, md5_hex(&data));
        // Confirm round-trip read.
        let f = open_blob(dir.path(), &info.blob_id).unwrap();
        let mut buf = vec![0u8; data.len()];
        f.pread_at(&mut buf, 0).unwrap();
        assert_eq!(buf, data);
    }

    #[test]
    fn reclaim_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let info = write_blob(dir.path(), &b"hi"[..]).unwrap();
        assert!(blob_path(dir.path(), &info.blob_id).exists());
        reclaim_blob(dir.path(), &info.blob_id).unwrap();
        assert!(!blob_path(dir.path(), &info.blob_id).exists());
        // Second reclaim of a missing blob is a no-op.
        reclaim_blob(dir.path(), &info.blob_id).unwrap();
    }

    #[test]
    fn open_missing_blob_errors() {
        let dir = tempfile::tempdir().unwrap();
        match open_blob(dir.path(), &Uuid::new_v4().to_string()) {
            Err(e) => assert_eq!(e.kind(), io::ErrorKind::NotFound),
            Ok(_) => panic!("expected open of a missing blob to fail"),
        }
    }

    #[test]
    fn zero_byte_blob() {
        let dir = tempfile::tempdir().unwrap();
        let info = write_blob(dir.path(), &b""[..]).unwrap();
        assert_eq!(info.size, 0);
        assert_eq!(info.md5_hex, md5_hex(b""));
        assert!(blob_path(dir.path(), &info.blob_id).exists());
    }
}

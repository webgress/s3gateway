//! Direct-IO file primitives with graceful fallback to buffered IO.
//!
//! These are BLOCKING helpers (raw `pread`/`pwrite`/`fsync` via rustix). They
//! are intended to be invoked from `tokio::task::spawn_blocking` on the storage
//! thread pool — they are deliberately NOT async.
//!
//! O_DIRECT semantics: we attempt to open with `O_DIRECT`. On filesystems that
//! reject it (tmpfs, overlayfs, some test fs) the open fails with `EINVAL`; we
//! transparently retry without `O_DIRECT` and fall back to buffered IO. The
//! caller's read/write code path is identical either way; the only difference is
//! whether the kernel page cache is bypassed.

use std::cell::Cell;
use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::path::{Path, PathBuf};

use rustix::fs::{Mode, OFlags};

/// A file opened for reading or writing, recording whether O_DIRECT is active.
///
/// Fallback is two-stage: (1) if the O_DIRECT *open* fails with EINVAL/ENOTSUP
/// (tmpfs etc.) we open buffered immediately; (2) some filesystems accept the
/// O_DIRECT open but reject *unaligned* IO with EINVAL — in that case we detect
/// the EINVAL on the first pread/pwrite and transparently reopen the same file
/// buffered, then retry. After fallback, `direct` reports false.
pub struct DioFile {
    fd: Cell<OwnedFd>,
    path: PathBuf,
    flags: OFlags,
    mode: Mode,
    /// True while O_DIRECT is in effect (IO should be page-aligned).
    direct: Cell<bool>,
}

// Cell<OwnedFd>/Cell<bool> are Send (contents are Send); single-op usage in
// spawn_blocking means no cross-thread sharing of a single DioFile.
unsafe impl Send for DioFile {}

impl DioFile {
    /// Open an existing file for reading. Tries O_DIRECT, falls back to buffered.
    ///
    /// `O_NOFOLLOW` is set so a SYMLINK at the final path component is rejected
    /// (ELOOP) rather than followed — defense-in-depth against a symlink planted
    /// inside a bucket that points outside the data root (the lexical containment
    /// check in `validate_object_path` cannot see symlinks). Intermediate
    /// directory components are not covered by O_NOFOLLOW; the parent-dir
    /// canonicalization in `validate_object_path` backstops those.
    pub fn open_read(path: &Path) -> io::Result<Self> {
        Self::open_internal(path, OFlags::RDONLY | OFlags::NOFOLLOW, Mode::empty())
    }

    /// Create/truncate a file for writing. Tries O_DIRECT, falls back.
    ///
    /// `O_NOFOLLOW` rejects a symlinked leaf (see [`Self::open_read`]). On
    /// create, this means an existing symlink at `path` causes ELOOP instead of
    /// writing through it to an arbitrary target.
    pub fn create_write(path: &Path) -> io::Result<Self> {
        Self::open_internal(
            path,
            OFlags::WRONLY | OFlags::CREATE | OFlags::TRUNC | OFlags::NOFOLLOW,
            Mode::from_bits_truncate(0o644),
        )
    }

    fn open_internal(path: &Path, flags: OFlags, mode: Mode) -> io::Result<Self> {
        // First attempt: with O_DIRECT.
        match rustix::fs::open(path, flags | OFlags::DIRECT, mode) {
            Ok(fd) => Ok(DioFile {
                fd: Cell::new(fd),
                path: path.to_path_buf(),
                flags,
                mode,
                direct: Cell::new(true),
            }),
            Err(e) if e == rustix::io::Errno::INVAL || e == rustix::io::Errno::OPNOTSUPP => {
                // Filesystem does not support O_DIRECT (e.g. tmpfs). Fall back.
                let fd = rustix::fs::open(path, flags, mode).map_err(io::Error::from)?;
                Ok(DioFile {
                    fd: Cell::new(fd),
                    path: path.to_path_buf(),
                    flags,
                    mode,
                    direct: Cell::new(false),
                })
            }
            Err(e) => Err(io::Error::from(e)),
        }
    }

    /// Whether O_DIRECT is currently in effect.
    pub fn is_direct(&self) -> bool {
        self.direct.get()
    }

    /// Test-only: force this file onto the buffered (non-O_DIRECT) IO path even on
    /// a filesystem that accepted O_DIRECT, so the buffered branch of the blob
    /// write loop can be exercised deterministically. No-op if already buffered.
    #[cfg(test)]
    pub fn force_buffered_for_test(&self) -> io::Result<()> {
        if self.direct.get() {
            self.fallback_buffered()?;
        }
        Ok(())
    }

    /// Reopen the same file buffered (without O_DIRECT) after an alignment EINVAL.
    /// For a write fd this preserves already-written data (no O_TRUNC on reopen).
    fn fallback_buffered(&self) -> io::Result<()> {
        let reopen_flags = self.flags & !OFlags::TRUNC & !OFlags::CREATE;
        let fd = rustix::fs::open(&self.path, reopen_flags, self.mode).map_err(io::Error::from)?;
        self.fd.set(fd);
        self.direct.set(false);
        Ok(())
    }

    /// Borrow the current fd. SAFETY: caller holds `&self`; the `Cell<OwnedFd>`
    /// is only swapped via `&self` methods on this thread, so the borrow is valid
    /// for the call.
    fn with_fd<T>(&self, f: impl FnOnce(rustix::fd::BorrowedFd<'_>) -> T) -> T {
        let fd_ref = unsafe { &*self.fd.as_ptr() };
        f(fd_ref.as_fd())
    }

    /// Positional read at `offset`. Returns bytes read (0 = EOF).
    /// With O_DIRECT the caller must pass a page-aligned buffer and offset; on an
    /// alignment EINVAL we fall back to buffered and retry once.
    pub fn pread_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        match self.with_fd(|fd| rustix::io::pread(fd, buf, offset)) {
            Ok(n) => Ok(n),
            Err(e) if e == rustix::io::Errno::INVAL && self.direct.get() => {
                self.fallback_buffered()?;
                self.with_fd(|fd| rustix::io::pread(fd, buf, offset))
                    .map_err(io::Error::from)
            }
            Err(e) => Err(io::Error::from(e)),
        }
    }

    /// Positional write at `offset`. Returns bytes written. Falls back to
    /// buffered IO and retries once on an alignment EINVAL.
    pub fn pwrite_at(&self, buf: &[u8], offset: u64) -> io::Result<usize> {
        match self.with_fd(|fd| rustix::io::pwrite(fd, buf, offset)) {
            Ok(n) => Ok(n),
            Err(e) if e == rustix::io::Errno::INVAL && self.direct.get() => {
                self.fallback_buffered()?;
                self.with_fd(|fd| rustix::io::pwrite(fd, buf, offset))
                    .map_err(io::Error::from)
            }
            Err(e) => Err(io::Error::from(e)),
        }
    }

    /// Flush data + metadata to stable storage.
    pub fn fsync(&self) -> io::Result<()> {
        self.with_fd(|fd| rustix::fs::fsync(fd))
            .map_err(io::Error::from)
    }

    /// Current file size in bytes.
    pub fn size(&self) -> io::Result<u64> {
        let st = self
            .with_fd(|fd| rustix::fs::fstat(fd))
            .map_err(io::Error::from)?;
        Ok(st.st_size as u64)
    }
}

/// Atomic rename (Go `os.Rename` semantics).
pub fn rename(from: &Path, to: &Path) -> io::Result<()> {
    rustix::fs::rename(from, to).map_err(io::Error::from)
}

/// fsync a directory so a rename/creation within it is durable.
pub fn fsync_dir(dir: &Path) -> io::Result<()> {
    let fd = rustix::fs::open(dir, OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty())
        .map_err(io::Error::from)?;
    rustix::fs::fsync(fd.as_fd()).map_err(io::Error::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_then_read_with_fallback() {
        // On tmpfs/most CI fs, O_DIRECT will fall back; either way IO must work.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f.bin");

        let data = b"the quick brown fox";
        {
            let f = DioFile::create_write(&path).unwrap();
            let n = f.pwrite_at(data, 0).unwrap();
            assert_eq!(n, data.len());
            f.fsync().unwrap();
        }
        {
            let f = DioFile::open_read(&path).unwrap();
            assert_eq!(f.size().unwrap(), data.len() as u64);
            let mut buf = vec![0u8; data.len()];
            let n = f.pread_at(&mut buf, 0).unwrap();
            assert_eq!(n, data.len());
            assert_eq!(&buf, data);
        }
    }

    #[test]
    fn rename_is_atomic_move() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a");
        let b = dir.path().join("b");
        {
            let f = DioFile::create_write(&a).unwrap();
            f.pwrite_at(b"x", 0).unwrap();
        }
        rename(&a, &b).unwrap();
        assert!(!a.exists());
        assert!(b.exists());
    }

    #[test]
    fn positional_offsets() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.bin");
        let f = DioFile::create_write(&path).unwrap();
        f.pwrite_at(b"AAAA", 0).unwrap();
        f.pwrite_at(b"BBBB", 4).unwrap();
        f.fsync().unwrap();
        let r = DioFile::open_read(&path).unwrap();
        let mut buf = [0u8; 4];
        r.pread_at(&mut buf, 4).unwrap();
        assert_eq!(&buf, b"BBBB");
    }
}

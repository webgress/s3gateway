//! `.s3meta` JSON sidecar files.
//!
//! Ported from the Go `internal/storage/metadata.go`, extended to record
//! multipart manifests so multipart objects can be reassembled on read without
//! ever concatenating parts on disk.

use std::collections::BTreeMap;
use std::io;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// One stored part of a multipart object (kept on disk under `.multipart`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PartRef {
    pub part_number: i32,
    /// Absolute or root-relative path to the part data file.
    pub path: String,
    pub size: u64,
    /// Hex MD5 of this part's bytes (no quotes).
    pub md5_hex: String,
}

/// Object metadata sidecar. `multipart` is `Some` for objects stored as parts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObjectMetadata {
    pub content_type: String,
    pub content_length: i64,
    /// ETag including surrounding quotes (S3 wire format).
    pub etag: String,
    /// Last-modified as Unix seconds (UTC).
    pub last_modified: i64,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub user_metadata: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub content_disposition: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub content_encoding: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cache_control: String,
    /// Present for multipart objects: ordered parts to stream on read.
    /// NOTE: this is the key design point — multipart objects are NOT
    /// concatenated into a single file; they are reassembled on read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub multipart: Option<Vec<PartRef>>,
}

impl ObjectMetadata {
    pub fn is_multipart(&self) -> bool {
        self.multipart.is_some()
    }
}

/// Write metadata atomically (temp file + rename), matching the Go impl.
///
/// This is the non-durable variant (no fsync). For crash-safe publication use
/// [`write_metadata_durable`], which fsyncs the sidecar before rename. The
/// `.tmp` suffix here would collide with the list-scan's `.tmp.` skip filter, so
/// it is deliberately a plain `.tmp` (no trailing dot) and the sidecar itself is
/// never returned by listings (it ends in `.s3meta`).
pub fn write_metadata(path: &Path, meta: &ObjectMetadata) -> io::Result<()> {
    let data = serde_json::to_vec_pretty(meta).map_err(io::Error::other)?;
    let tmp = with_suffix(path, ".tmp");
    std::fs::write(&tmp, &data)?;
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// Write metadata atomically AND durably: write the temp sidecar, fsync its
/// bytes to stable storage, rename it into place, then fsync the parent
/// directory so the rename (the new directory entry) survives a crash. Use this
/// on the object-publication path when `--fsync` is enabled.
pub fn write_metadata_durable(path: &Path, meta: &ObjectMetadata) -> io::Result<()> {
    use super::directio::{fsync_dir, DioFile};
    let data = serde_json::to_vec_pretty(meta).map_err(io::Error::other)?;
    let tmp = with_suffix(path, ".tmp");
    {
        let f = DioFile::create_write(&tmp)?;
        let mut off = 0u64;
        let mut buf: &[u8] = &data;
        while !buf.is_empty() {
            let n = f.pwrite_at(buf, off)?;
            if n == 0 {
                let _ = std::fs::remove_file(&tmp);
                return Err(io::Error::new(io::ErrorKind::WriteZero, "pwrite wrote 0"));
            }
            off += n as u64;
            buf = &buf[n..];
        }
        f.fsync()?;
    }
    match std::fs::rename(&tmp, path) {
        Ok(()) => {}
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
    }
    if let Some(parent) = path.parent() {
        fsync_dir(parent)?;
    }
    Ok(())
}

/// Write a metadata sidecar to an explicit temp path and fsync its bytes to
/// stable storage, WITHOUT renaming it into place. Used by the multipart-complete
/// commit sequence (C1), where the sidecar rename is deferred to be the LAST
/// durable step so nothing the prior object's live sidecar references changes
/// until the new sidecar is committed. Pair with [`commit_metadata_temp`].
pub fn write_metadata_temp_durable(tmp: &Path, meta: &ObjectMetadata) -> io::Result<()> {
    use super::directio::DioFile;
    let data = serde_json::to_vec_pretty(meta).map_err(io::Error::other)?;
    let f = DioFile::create_write(tmp)?;
    let mut off = 0u64;
    let mut buf: &[u8] = &data;
    while !buf.is_empty() {
        let n = f.pwrite_at(buf, off)?;
        if n == 0 {
            let _ = std::fs::remove_file(tmp);
            return Err(io::Error::new(io::ErrorKind::WriteZero, "pwrite wrote 0"));
        }
        off += n as u64;
        buf = &buf[n..];
    }
    f.fsync()?;
    Ok(())
}

/// Write a metadata sidecar to an explicit temp path (non-durable: no fsync),
/// WITHOUT renaming it into place. Non-durable companion to
/// [`write_metadata_temp_durable`] for the `--fsync false` path.
pub fn write_metadata_temp(tmp: &Path, meta: &ObjectMetadata) -> io::Result<()> {
    let data = serde_json::to_vec_pretty(meta).map_err(io::Error::other)?;
    std::fs::write(tmp, &data)
}

/// Commit a previously-staged temp sidecar (from [`write_metadata_temp_durable`]
/// or [`write_metadata_temp`]) by renaming it into place at `path`. When
/// `durable`, the parent directory is fsynced afterward so the rename survives a
/// crash. This is the LAST durable step of the multipart-complete commit (C1).
pub fn commit_metadata_temp(tmp: &Path, path: &Path, durable: bool) -> io::Result<()> {
    use super::directio::fsync_dir;
    match std::fs::rename(tmp, path) {
        Ok(()) => {}
        Err(e) => {
            let _ = std::fs::remove_file(tmp);
            return Err(e);
        }
    }
    if durable {
        if let Some(parent) = path.parent() {
            fsync_dir(parent)?;
        }
    }
    Ok(())
}

/// Read+parse a metadata sidecar.
///
/// B1: open the sidecar with `O_NOFOLLOW` so a SYMLINK planted at the `.s3meta`
/// path (pointing at an outside-root file) is rejected (ELOOP) rather than
/// followed — `std::fs::read` follows symlinks. The sidecar is small JSON, so we
/// read it through a plain buffered fd (NOT DioFile/O_DIRECT, which would impose
/// alignment on a tiny metadata read).
pub fn read_metadata(path: &Path) -> io::Result<ObjectMetadata> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let mut data = Vec::new();
    f.read_to_end(&mut data)?;
    serde_json::from_slice(&data).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

fn with_suffix(path: &Path, suffix: &str) -> std::path::PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(suffix);
    std::path::PathBuf::from(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ObjectMetadata {
        let mut um = BTreeMap::new();
        um.insert("x-amz-meta-foo".to_string(), "bar".to_string());
        ObjectMetadata {
            content_type: "text/plain".into(),
            content_length: 11,
            etag: "\"abc\"".into(),
            last_modified: 1_700_000_000,
            user_metadata: um,
            content_disposition: String::new(),
            content_encoding: String::new(),
            cache_control: String::new(),
            multipart: None,
        }
    }

    #[test]
    fn round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("o.s3meta");
        let m = sample();
        write_metadata(&p, &m).unwrap();
        let read = read_metadata(&p).unwrap();
        assert_eq!(read, m);
    }

    #[test]
    fn empty_optionals_omitted_in_json() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("o.s3meta");
        let mut m = sample();
        m.user_metadata.clear();
        write_metadata(&p, &m).unwrap();
        let raw = std::fs::read_to_string(&p).unwrap();
        assert!(!raw.contains("user_metadata"));
        assert!(!raw.contains("multipart"));
    }

    #[test]
    fn multipart_manifest_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("o.s3meta");
        let mut m = sample();
        m.multipart = Some(vec![
            PartRef {
                part_number: 1,
                path: "/data/.multipart/u/parts/00001".into(),
                size: 5,
                md5_hex: "aaaa".into(),
            },
            PartRef {
                part_number: 2,
                path: "/data/.multipart/u/parts/00002".into(),
                size: 6,
                md5_hex: "bbbb".into(),
            },
        ]);
        write_metadata(&p, &m).unwrap();
        let read = read_metadata(&p).unwrap();
        assert!(read.is_multipart());
        assert_eq!(read.multipart.as_ref().unwrap().len(), 2);
        assert_eq!(read, m);
    }

    #[test]
    fn corrupt_json_errors() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("bad.s3meta");
        std::fs::write(&p, b"{not json").unwrap();
        assert!(read_metadata(&p).is_err());
    }

    #[test]
    fn missing_file_errors() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("nope.s3meta");
        assert!(read_metadata(&p).is_err());
    }
}

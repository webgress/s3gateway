//! Per-key JSON manifest (`.meta`) — the atomic commit unit of the
//! content-addressed store (REDESIGN §2).
//!
//! One manifest file per live object key, stored as a KEY-PATH TREE under
//! `{bucket}/current/{escaped-key}.meta`. It is small JSON describing the object's
//! headers, total size, ETag, ordered blob parts, and a per-version `commit_nonce`
//! used by the journal/sweep "did my commit land?" check (REDESIGN §3.2).
//!
//! The manifest is published by an atomic temp+rename (ported from the old
//! `write_metadata_temp_durable`/`commit_metadata_temp` discipline), so a reader's
//! `open`+`read` of `current/K.meta` always observes a consistent snapshot — the
//! pre-rename inode or the post-rename inode, never a torn file.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::metadata::{ObjectMetadata, PartRef};

/// Live-manifest tree root within a bucket.
pub const CURRENT_DIR: &str = "current";
/// In-flight uploads / staged manifests within a bucket.
pub const ARRIVING_DIR: &str = "arriving";
/// Reclaim-journal markers within a bucket.
pub const DELETED_DIR: &str = "deleted";
/// Manifest filename suffix. The manifest for key `K` is `{K}.meta`. Because the
/// ONLY files under `current/` are manifests (blobs live in `blobs/`, staged temps
/// in `arriving/`), the mapping `key K -> file {K}.meta` is an unambiguous
/// bijection: decode strips exactly one trailing `.meta`. A literal object key
/// ending in `.meta` (e.g. `report.meta`) therefore round-trips for free — its
/// manifest is `report.meta.meta` and stripping one `.meta` recovers `report.meta`
/// — with no special escape needed.
///
/// NOTE (REDESIGN §7.3 deviation): the doc proposed a `\x00m` escape marker for
/// `.meta`-suffixed keys, but a literal NUL byte is REJECTED by the OS in an
/// on-disk filename (EINVAL), so it is unusable as a real filename byte. The
/// double-suffix + strip-one-`.meta` scheme above is collision-free (every
/// `current/` file is exactly `{key}.meta`) and valid on disk, so it supersedes
/// the doc's escape. See `escape_key_to_relpath` / `decode_relpath_to_key`.
pub const META_SUFFIX: &str = ".meta";

/// One stored part of an object, referenced by immutable blob id (REDESIGN §2).
/// This is the CAS analog of the old [`PartRef`] (which carried a `path`); here a
/// part is a uuid resolved via `blob::blob_path`, never a client/manifest path.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestPartRef {
    pub part_number: u32,
    /// v4 uuid -> `blobs/xx/yy/{blob_id}`.
    pub blob_id: String,
    pub size: u64,
    /// Hex MD5 of THIS blob's bytes (no quotes). Reused for the composite ETag
    /// and for multipart ListParts/Complete validation.
    pub md5_hex: String,
}

/// The atomic commit unit: a single object version.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Manifest {
    /// The full object key (authoritative; survives filename escaping).
    pub key: String,
    pub content_type: String,
    /// Total logical size = sum(parts[].size).
    pub content_length: u64,
    /// Quoted. Single-part: `"md5"`. Multipart: `"md5-N"`.
    pub etag: String,
    /// Unix seconds.
    pub last_modified: i64,
    /// Unix seconds (first write of this version).
    pub created: i64,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub user_metadata: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub content_disposition: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub content_encoding: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cache_control: String,
    /// ALWAYS present; `len == 1` for single-part. Ordered by part_number.
    pub parts: Vec<ManifestPartRef>,
    /// Random per-version nonce. The journal records the NEW version's nonce; the
    /// sweep deletes old blobs IFF the live manifest carries exactly this nonce
    /// (REDESIGN §3.2 — the authoritative "did my commit land" check).
    pub commit_nonce: String,
}

impl Manifest {
    /// Generate a fresh random commit nonce (a v4 uuid is sufficiently unique).
    pub fn new_nonce() -> String {
        Uuid::new_v4().to_string()
    }

    /// The ordered blob ids this version owns/references.
    pub fn blob_ids(&self) -> Vec<String> {
        self.parts.iter().map(|p| p.blob_id.clone()).collect()
    }

    /// Derive the handler-facing [`ObjectMetadata`] header bundle from this
    /// manifest. For a multipart object (`parts.len() > 1`) the `multipart` field
    /// is populated (with synthetic per-part `PartRef`s carrying the blob id in
    /// the `path` slot purely for header-derivation parity — handlers do not open
    /// these); single-part leaves it `None`. This keeps the public
    /// `ObjectMetadata` shape unchanged so `apply_object_headers` is untouched.
    pub fn to_object_metadata(&self) -> ObjectMetadata {
        let multipart = if self.parts.len() > 1 {
            Some(
                self.parts
                    .iter()
                    .map(|p| PartRef {
                        part_number: p.part_number as i32,
                        path: p.blob_id.clone(),
                        size: p.size,
                        md5_hex: p.md5_hex.clone(),
                    })
                    .collect(),
            )
        } else {
            None
        };
        ObjectMetadata {
            content_type: self.content_type.clone(),
            content_length: self.content_length as i64,
            etag: self.etag.clone(),
            last_modified: self.last_modified,
            user_metadata: self.user_metadata.clone(),
            content_disposition: self.content_disposition.clone(),
            content_encoding: self.content_encoding.clone(),
            cache_control: self.cache_control.clone(),
            multipart,
        }
    }
}

/// Map an object key to its RELATIVE filesystem path under `current/` (one path
/// component per `/`-segment). The `.meta` suffix is NOT part of this relpath; it
/// is appended to the final segment by [`manifest_path`]. No segment escaping is
/// performed — see [`META_SUFFIX`] for why the double-suffix scheme is
/// collision-free.
///
/// A key like `a.meta/b` makes `current/a.meta/` a DIRECTORY and the manifest is
/// `current/a.meta/b.meta`, which never collides with the `current/a.meta.meta`
/// MANIFEST of key `a.meta` — coexistence is intentional (REDESIGN §7.2).
pub fn escape_key_to_relpath(key: &str) -> PathBuf {
    let mut path = PathBuf::new();
    for seg in key.split('/') {
        path.push(seg);
    }
    path
}

/// Absolute manifest path for `key` under a bucket's `current/` tree:
/// `{current_root}/{escaped-key}.meta`. The `.meta` suffix is appended to the
/// FINAL (escaped) segment only.
pub fn manifest_path(current_root: &Path, key: &str) -> PathBuf {
    let rel = escape_key_to_relpath(key);
    let comps: Vec<&OsStr> = rel.iter().collect();
    let mut full = current_root.to_path_buf();
    if comps.is_empty() {
        // Empty key: degenerate; place a `.meta` file at the root (rejected by
        // key validation upstream, but keep total-function behavior).
        full.push(META_SUFFIX);
        return full;
    }
    for (i, c) in comps.iter().enumerate() {
        if i + 1 == comps.len() {
            let mut leaf = c.to_os_string();
            leaf.push(META_SUFFIX);
            full.push(leaf);
        } else {
            full.push(c);
        }
    }
    full
}

/// Recover the object key from a manifest path RELATIVE to `current/` (with the
/// trailing `.meta`). Strips exactly one trailing `.meta` from the final segment
/// and rejoins segments with `/`. Returns `None` if the final segment does not end
/// in `.meta` (i.e. it is not a manifest, e.g. a staged temp).
pub fn decode_relpath_to_key(rel: &Path) -> Option<String> {
    let comps: Vec<String> = rel
        .iter()
        .map(|c| c.to_string_lossy().into_owned())
        .collect();
    if comps.is_empty() {
        return None;
    }
    let mut out_segs: Vec<String> = Vec::with_capacity(comps.len());
    let last = comps.len() - 1;
    for (i, c) in comps.iter().enumerate() {
        if i == last {
            // Strip exactly one manifest `.meta` suffix to recover the key's final
            // segment (the bijection of META_SUFFIX).
            let stem = c.strip_suffix(META_SUFFIX)?;
            out_segs.push(stem.to_string());
        } else {
            out_segs.push(c.clone());
        }
    }
    Some(out_segs.join("/"))
}

/// Write a manifest to an explicit temp path and (when `durable`) fsync its bytes
/// to stable storage, WITHOUT renaming it into place. Ported from
/// `write_metadata_temp_durable` / `write_metadata_temp`. The blob containing the
/// JSON is tiny, so we use a plain buffered fd (not O_DIRECT) but with O_NOFOLLOW.
pub fn write_manifest_temp(tmp: &Path, m: &Manifest, durable: bool) -> io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let data = serde_json::to_vec_pretty(m).map_err(io::Error::other)?;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(tmp)?;
    f.write_all(&data)?;
    if durable {
        f.sync_all()?;
    }
    Ok(())
}

/// Read+parse a manifest at `path`, with O_NOFOLLOW so a planted symlink at the
/// `.meta` path is rejected (ELOOP) rather than followed (`std::fs::read` would
/// follow it). Ported from `read_metadata`.
pub fn read_manifest(path: &Path) -> io::Result<Manifest> {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(key: &str) -> Manifest {
        let mut um = BTreeMap::new();
        um.insert("x-amz-meta-foo".to_string(), "bar".to_string());
        Manifest {
            key: key.to_string(),
            content_type: "text/plain".into(),
            content_length: 11,
            etag: "\"abc\"".into(),
            last_modified: 1_700_000_000,
            created: 1_699_999_000,
            user_metadata: um,
            content_disposition: String::new(),
            content_encoding: String::new(),
            cache_control: String::new(),
            parts: vec![ManifestPartRef {
                part_number: 1,
                blob_id: Uuid::new_v4().to_string(),
                size: 11,
                md5_hex: "5eb63bbbe01eeed093cb22bb8f5acdc3".into(),
            }],
            commit_nonce: Manifest::new_nonce(),
        }
    }

    #[test]
    fn manifest_round_trip_all_fields() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("o.meta");
        let mut m = sample("a/b/c");
        m.content_disposition = "inline".into();
        m.content_encoding = "gzip".into();
        m.cache_control = "no-cache".into();
        m.parts.push(ManifestPartRef {
            part_number: 2,
            blob_id: Uuid::new_v4().to_string(),
            size: 7,
            md5_hex: "deadbeef".into(),
        });
        m.content_length = 18;
        write_manifest_temp(&p, &m, true).unwrap();
        let read = read_manifest(&p).unwrap();
        assert_eq!(read, m);
    }

    #[test]
    fn empty_optionals_omitted() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("o.meta");
        let mut m = sample("k");
        m.user_metadata.clear();
        write_manifest_temp(&p, &m, false).unwrap();
        let raw = std::fs::read_to_string(&p).unwrap();
        assert!(!raw.contains("user_metadata"));
        assert!(!raw.contains("content_disposition"));
        // parts and commit_nonce are always present.
        assert!(raw.contains("\"parts\""));
        assert!(raw.contains("commit_nonce"));
    }

    #[test]
    fn corrupt_and_missing_manifest_error() {
        let dir = tempfile::tempdir().unwrap();
        let bad = dir.path().join("bad.meta");
        std::fs::write(&bad, b"{not json").unwrap();
        assert!(read_manifest(&bad).is_err());
        assert!(read_manifest(&dir.path().join("nope.meta")).is_err());
    }

    #[test]
    fn key_to_path_simple_and_nested() {
        let cur = Path::new("/data/bk/current");
        assert_eq!(
            manifest_path(cur, "photo.jpg"),
            Path::new("/data/bk/current/photo.jpg.meta")
        );
        assert_eq!(
            manifest_path(cur, "a/b/c"),
            Path::new("/data/bk/current/a/b/c.meta")
        );
    }

    #[test]
    fn key_ending_in_meta_round_trips_via_double_suffix() {
        let cur = Path::new("/data/bk/current");
        // report.meta -> report.meta.meta (double suffix; valid on disk, no NUL).
        let p = manifest_path(cur, "report.meta");
        let fname = p.file_name().unwrap().to_string_lossy();
        assert_eq!(fname, "report.meta.meta");
        // Decode strips exactly one .meta.
        let rel = p.strip_prefix(cur).unwrap();
        assert_eq!(decode_relpath_to_key(rel).unwrap(), "report.meta");
    }

    #[test]
    fn nested_key_ending_in_meta_round_trips() {
        let cur = Path::new("/data/bk/current");
        // a/b.meta -> a/b.meta.meta ; intermediate "a" untouched.
        let p = manifest_path(cur, "a/b.meta");
        assert_eq!(p, Path::new("/data/bk/current/a/b.meta.meta"));
        let rel = p.strip_prefix(cur).unwrap();
        assert_eq!(decode_relpath_to_key(rel).unwrap(), "a/b.meta");
        // a.meta/b -> a.meta/b.meta ; intermediate a.meta is a plain dir segment.
        let p2 = manifest_path(cur, "a.meta/b");
        assert_eq!(p2, Path::new("/data/bk/current/a.meta/b.meta"));
        let rel2 = p2.strip_prefix(cur).unwrap();
        assert_eq!(decode_relpath_to_key(rel2).unwrap(), "a.meta/b");
    }

    #[test]
    fn coexist_a_and_a_slash_b_paths_differ() {
        let cur = Path::new("/data/bk/current");
        let pa = manifest_path(cur, "a");
        let pab = manifest_path(cur, "a/b");
        // "a" -> current/a.meta (a FILE); "a/b" -> current/a/b.meta (under dir a/).
        assert_eq!(pa, Path::new("/data/bk/current/a.meta"));
        assert_eq!(pab, Path::new("/data/bk/current/a/b.meta"));
        assert_ne!(pa.parent(), Some(pab.parent().unwrap()));
    }

    #[test]
    fn decode_rejects_non_manifest() {
        assert!(decode_relpath_to_key(Path::new("foo.tmp.123")).is_none());
        assert!(decode_relpath_to_key(Path::new("staged")).is_none());
    }

    #[test]
    fn to_object_metadata_single_and_multi() {
        let m1 = sample("k");
        let om1 = m1.to_object_metadata();
        assert!(om1.multipart.is_none());
        assert_eq!(om1.etag, "\"abc\"");

        let mut m2 = sample("k");
        m2.parts.push(ManifestPartRef {
            part_number: 2,
            blob_id: Uuid::new_v4().to_string(),
            size: 7,
            md5_hex: "deadbeef".into(),
        });
        let om2 = m2.to_object_metadata();
        assert_eq!(om2.multipart.as_ref().unwrap().len(), 2);
    }
}

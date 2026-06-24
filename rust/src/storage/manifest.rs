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
/// Manifest filename suffix (CAS encode v2 — RESERVED-SUFFIX scheme). The live
/// manifest for key `K` is the file `{leaf}{MANIFEST_SUFFIX}` under `current/`,
/// where `{leaf}` is `K`'s final `/`-segment and the earlier segments are RAW
/// directory names (no transform). Because the ONLY files under `current/` are
/// manifests (blobs live in `blobs/`, staged temps in `arriving/`), and because
/// any key whose `/`-split contains a segment ending in `MANIFEST_SUFFIX` is
/// REJECTED up front (`CasStore::validate_object_path`), the mapping
/// `key K -> file {leaf}{MANIFEST_SUFFIX}` is a collision-free bijection: decode
/// strips exactly one trailing `MANIFEST_SUFFIX` from the file's name and joins it
/// with the raw ancestor dir names.
///
/// This SUPERSEDES the old `.meta`-double-suffix scheme (`report.meta` ->
/// `report.meta.meta`) and its companion `KeyPrefixConflict`/409 runtime check.
/// The longer, distinctive suffix means an ordinary key ending in `.meta` (e.g.
/// `report.meta` -> `report.meta.s3gw-live.meta`) needs no special casing, and the
/// only structural collision — a key `a` (FILE `current/a.s3gw-live.meta`) vs a key
/// `a.s3gw-live.meta/b` (which would need DIRECTORY `current/a.s3gw-live.meta/`) —
/// is impossible because the latter has a segment ending in `MANIFEST_SUFFIX` and
/// is rejected. Thus `a` and `a.meta/b` (and `a` and `a/b`) freely COEXIST, which
/// is also more S3-faithful.
///
/// KNOWN LIMITATION (reserved suffix): an object key may NOT contain any
/// `/`-segment ending in `MANIFEST_SUFFIX`. This is the single, easily-changed
/// reservation the on-disk manifest tree requires; such keys are rejected with 400
/// InvalidArgument. See `escape_key_to_relpath` / `decode_relpath_to_key` and
/// `CasStore::validate_object_path`.
pub const MANIFEST_SUFFIX: &str = ".s3gw-live.meta";

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
/// component per `/`-segment). The `MANIFEST_SUFFIX` is NOT part of this relpath; it
/// is appended to the final segment by [`manifest_path`]. Every segment EXCEPT the
/// last is a RAW directory name (no transform). No escaping is performed — the
/// reserved-suffix rejection in `CasStore::validate_object_path` guarantees no key
/// segment can end in `MANIFEST_SUFFIX`, so no escape is needed (see
/// [`MANIFEST_SUFFIX`]).
///
/// A key like `a.meta/b` makes `current/a.meta/` a raw DIRECTORY and the manifest
/// is `current/a.meta/b.s3gw-live.meta`, which never collides with the FILE
/// `current/a.s3gw-live.meta` (the manifest of key `a`) — coexistence is intentional.
pub fn escape_key_to_relpath(key: &str) -> PathBuf {
    let mut path = PathBuf::new();
    for seg in key.split('/') {
        path.push(seg);
    }
    path
}

/// Absolute manifest path for `key` under a bucket's `current/` tree:
/// `{current_root}/{raw-ancestor-dirs}/{leaf}{MANIFEST_SUFFIX}`. The
/// `MANIFEST_SUFFIX` is appended to the FINAL segment only; ancestor segments are
/// raw directory names.
pub fn manifest_path(current_root: &Path, key: &str) -> PathBuf {
    let rel = escape_key_to_relpath(key);
    let comps: Vec<&OsStr> = rel.iter().collect();
    let mut full = current_root.to_path_buf();
    if comps.is_empty() {
        // Empty key: degenerate; place a bare `MANIFEST_SUFFIX` file at the root
        // (rejected by key validation upstream, but keep total-function behavior).
        full.push(MANIFEST_SUFFIX);
        return full;
    }
    for (i, c) in comps.iter().enumerate() {
        if i + 1 == comps.len() {
            let mut leaf = c.to_os_string();
            leaf.push(MANIFEST_SUFFIX);
            full.push(leaf);
        } else {
            full.push(c);
        }
    }
    full
}

/// Recover the object key from a manifest path RELATIVE to `current/` (with the
/// trailing `MANIFEST_SUFFIX`). Strips exactly one trailing `MANIFEST_SUFFIX` from
/// the final segment and rejoins the raw ancestor segments with `/`. This is the
/// exact inverse of [`manifest_path`]. Returns `None` if the final segment does not
/// end in `MANIFEST_SUFFIX` (i.e. it is not a live manifest filename — e.g. a staged
/// temp). NOTE: callers (listing) only invoke this on FILE entries; a DIRECTORY
/// under `current/` is a raw key-prefix ancestor and is never decoded here.
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
            // Strip exactly one manifest suffix to recover the key's final segment
            // (the bijection of MANIFEST_SUFFIX).
            let stem = c.strip_suffix(MANIFEST_SUFFIX)?;
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
            Path::new("/data/bk/current/photo.jpg.s3gw-live.meta")
        );
        assert_eq!(
            manifest_path(cur, "a/b/c"),
            Path::new("/data/bk/current/a/b/c.s3gw-live.meta")
        );
    }

    #[test]
    fn key_ending_in_meta_round_trips() {
        let cur = Path::new("/data/bk/current");
        // report.meta -> report.meta.s3gw-live.meta (ordinary .meta keys are now
        // fine — no double-suffix special-casing).
        let p = manifest_path(cur, "report.meta");
        let fname = p.file_name().unwrap().to_string_lossy();
        assert_eq!(fname, "report.meta.s3gw-live.meta");
        // Decode strips exactly one MANIFEST_SUFFIX.
        let rel = p.strip_prefix(cur).unwrap();
        assert_eq!(decode_relpath_to_key(rel).unwrap(), "report.meta");
    }

    #[test]
    fn nested_key_ending_in_meta_round_trips() {
        let cur = Path::new("/data/bk/current");
        // a/b.meta -> a/b.meta.s3gw-live.meta ; intermediate "a" untouched.
        let p = manifest_path(cur, "a/b.meta");
        assert_eq!(p, Path::new("/data/bk/current/a/b.meta.s3gw-live.meta"));
        let rel = p.strip_prefix(cur).unwrap();
        assert_eq!(decode_relpath_to_key(rel).unwrap(), "a/b.meta");
        // a.meta/b -> a.meta/b.s3gw-live.meta ; intermediate a.meta is a raw dir.
        let p2 = manifest_path(cur, "a.meta/b");
        assert_eq!(p2, Path::new("/data/bk/current/a.meta/b.s3gw-live.meta"));
        let rel2 = p2.strip_prefix(cur).unwrap();
        assert_eq!(decode_relpath_to_key(rel2).unwrap(), "a.meta/b");
    }

    #[test]
    fn coexist_a_and_a_slash_b_paths_differ() {
        let cur = Path::new("/data/bk/current");
        let pa = manifest_path(cur, "a");
        let pab = manifest_path(cur, "a/b");
        // "a" -> current/a.s3gw-live.meta (FILE); "a/b" -> current/a/b.s3gw-live.meta.
        assert_eq!(pa, Path::new("/data/bk/current/a.s3gw-live.meta"));
        assert_eq!(pab, Path::new("/data/bk/current/a/b.s3gw-live.meta"));
        assert_ne!(pa.parent(), Some(pab.parent().unwrap()));
    }

    #[test]
    fn coexist_a_and_a_meta_slash_b_paths_differ() {
        // The collision the OLD `.meta` suffix + KeyPrefixConflict guarded against is
        // gone: key `a` (FILE current/a.s3gw-live.meta) and key `a.meta/b` (raw dir
        // current/a.meta/, file b.s3gw-live.meta) map to DIFFERENT, non-nested paths.
        let cur = Path::new("/data/bk/current");
        let pa = manifest_path(cur, "a");
        let pab = manifest_path(cur, "a.meta/b");
        assert_eq!(pa, Path::new("/data/bk/current/a.s3gw-live.meta"));
        assert_eq!(pab, Path::new("/data/bk/current/a.meta/b.s3gw-live.meta"));
        // `a`'s manifest FILE is not an ancestor dir of `a.meta/b`'s manifest.
        assert!(!pab.starts_with(&pa));
    }

    #[test]
    fn decode_rejects_non_manifest() {
        assert!(decode_relpath_to_key(Path::new("foo.tmp.123")).is_none());
        assert!(decode_relpath_to_key(Path::new("staged")).is_none());
        // A plain `.meta`-suffixed name is NOT a manifest under the new scheme.
        assert!(decode_relpath_to_key(Path::new("report.meta")).is_none());
    }

    #[test]
    fn key_to_path_decode_round_trip_tricky() {
        // encode∘decode == identity over tricky keys (the reserved-suffix key
        // `report.s3gw-live.meta` is rejected upstream, so it is not round-tripped
        // here — see `CasStore::validate_object_path` tests).
        let cur = Path::new("/data/bk/current");
        for key in [
            "a",
            "a/b",
            "a.meta",
            "a.meta/b",
            "deeply/nested/path/to/object.bin",
            "café/résumé.txt",
            "emoji/😀/file",
            "trailing.dot.",
            "x.s3gw-live.metameta",
        ] {
            let p = manifest_path(cur, key);
            let rel = p.strip_prefix(cur).unwrap();
            let decoded = decode_relpath_to_key(rel)
                .unwrap_or_else(|| panic!("decode failed for key {key:?}"));
            assert_eq!(decoded, key, "round-trip mismatch for key {key:?}");
        }
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

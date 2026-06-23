//! Streaming object-body readers (blocking `io::Read`), with byte-range support.
//!
//! Two implementations:
//!   - [`PlainFileReader`]: a single on-disk file (single-part objects).
//!   - [`MultipartReader`]: REASSEMBLE-ON-READ. Given a multipart manifest, it
//!     streams the part files back-to-back as one logical object body, with at
//!     most one fd open at a time and a single reused aligned buffer. It supports
//!     byte ranges spanning the concatenated logical object. This is the key
//!     design point: parts are never concatenated on disk.
//!
//! Both are blocking and meant to be driven from `spawn_blocking`.

use std::io::{self, Read};
use std::path::PathBuf;

use super::aligned::AlignedBuf;
use super::directio::DioFile;
use super::metadata::PartRef;

/// A resolved byte range `[start, end_inclusive]` over a logical object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteRange {
    pub start: u64,
    /// Inclusive end offset.
    pub end: u64,
}

impl ByteRange {
    pub fn len(&self) -> u64 {
        self.end - self.start + 1
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Parse an HTTP `Range: bytes=...` header value against a known object size.
/// Returns `Ok(None)` if the header is absent/unparseable (caller serves the
/// full body) or `Err(())` if the range is unsatisfiable (caller returns 416).
/// The unit error is an intentional single-bit signal ("416"); no richer error
/// type is warranted.
#[allow(clippy::result_unit_err)]
pub fn parse_range(header: &str, size: u64) -> Result<Option<ByteRange>, ()> {
    let spec = match header.strip_prefix("bytes=") {
        Some(s) => s.trim(),
        None => return Ok(None),
    };
    // Only single ranges are supported.
    let (a, b) = spec.split_once('-').ok_or(())?;
    let (a, b) = (a.trim(), b.trim());
    if size == 0 {
        return Err(());
    }
    let range = if a.is_empty() {
        // suffix range: last N bytes
        let n: u64 = b.parse().map_err(|_| ())?;
        if n == 0 {
            return Err(());
        }
        let n = n.min(size);
        ByteRange {
            start: size - n,
            end: size - 1,
        }
    } else {
        let start: u64 = a.parse().map_err(|_| ())?;
        if start >= size {
            return Err(());
        }
        let end = if b.is_empty() {
            size - 1
        } else {
            let e: u64 = b.parse().map_err(|_| ())?;
            e.min(size - 1)
        };
        if end < start {
            return Err(());
        }
        ByteRange { start, end }
    };
    Ok(Some(range))
}

/// Reader over a single on-disk file, optionally limited to a byte range.
pub struct PlainFileReader {
    file: DioFile,
    buf: AlignedBuf,
    /// Next absolute file offset to read from.
    pos: u64,
    /// Absolute offset (exclusive) at which to stop.
    end: u64,
    /// Leftover decoded bytes from the last aligned read not yet handed out.
    pending: Vec<u8>,
    pending_off: usize,
}

impl PlainFileReader {
    /// Open `path` for streaming. If `range` is `None`, streams the whole file.
    pub fn open(path: &std::path::Path, range: Option<ByteRange>) -> io::Result<Self> {
        let file = DioFile::open_read(path)?;
        let size = file.size()?;
        let (start, end) = match range {
            Some(r) => (r.start, r.end + 1),
            None => (0, size),
        };
        Ok(PlainFileReader {
            file,
            buf: AlignedBuf::new(super::aligned::DEFAULT_BUF_SIZE),
            pos: start,
            end: end.min(size),
            pending: Vec::new(),
            pending_off: 0,
        })
    }

    /// Total bytes this reader will yield.
    pub fn remaining(&self) -> u64 {
        self.end.saturating_sub(self.pos) + (self.pending.len() - self.pending_off) as u64
    }
}

impl Read for PlainFileReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        // Serve any pending leftover first.
        if self.pending_off < self.pending.len() {
            let n = (self.pending.len() - self.pending_off).min(out.len());
            out[..n].copy_from_slice(&self.pending[self.pending_off..self.pending_off + n]);
            self.pending_off += n;
            return Ok(n);
        }
        if self.pos >= self.end {
            return Ok(0);
        }

        // With O_DIRECT, reads must be page-aligned. Read an aligned window that
        // covers [pos, ...) and slice out the requested portion. With buffered
        // IO this still works (alignment is just harmless).
        let aligned_start = self.pos & !(super::aligned::ALIGN as u64 - 1);
        let skip = (self.pos - aligned_start) as usize;
        let cap = self.buf.capacity();
        let n = self.file.pread_at(&mut self.buf[..cap], aligned_start)?;
        if n == 0 {
            return Ok(0);
        }
        // Bytes available in this window from `skip` up to logical end.
        let window_end = (aligned_start + n as u64).min(self.end);
        if window_end <= self.pos {
            return Ok(0);
        }
        let avail = (window_end - self.pos) as usize;
        let data = &self.buf[skip..skip + avail];
        let take = avail.min(out.len());
        out[..take].copy_from_slice(&data[..take]);
        if take < avail {
            // Stash the rest for the next read().
            self.pending = data[take..].to_vec();
            self.pending_off = 0;
        }
        self.pos = window_end;
        Ok(take)
    }
}

/// Reassemble-on-read reader for multipart objects.
///
/// Streams `parts` in order as one logical body. Maintains one open fd at a
/// time and a single reused aligned buffer. Supports a byte range over the
/// concatenated logical object.
pub struct MultipartReader {
    parts: Vec<PartRef>,
    buf: AlignedBuf,
    /// Index of the part we are currently reading.
    cur_part: usize,
    /// Open fd for the current part (lazily opened).
    cur_file: Option<DioFile>,
    /// Read offset within the current part.
    cur_off: u64,
    /// Logical bytes still to yield (after range trimming).
    remaining: u64,
    /// Bytes to skip at the start of the current part (for range start).
    skip_in_part: u64,
    pending: Vec<u8>,
    pending_off: usize,
}

impl MultipartReader {
    /// Build a reader over `parts`. If `range` is `None`, streams everything.
    pub fn new(parts: Vec<PartRef>, range: Option<ByteRange>) -> Self {
        let total: u64 = parts.iter().map(|p| p.size).sum();
        let (start, len) = match range {
            Some(r) => (r.start, r.len().min(total.saturating_sub(r.start))),
            None => (0, total),
        };

        // Locate the starting part and intra-part skip from the logical start.
        let mut acc = 0u64;
        let mut cur_part = parts.len();
        let mut skip_in_part = 0u64;
        for (i, p) in parts.iter().enumerate() {
            if start < acc + p.size {
                cur_part = i;
                skip_in_part = start - acc;
                break;
            }
            acc += p.size;
        }

        MultipartReader {
            parts,
            buf: AlignedBuf::new(super::aligned::DEFAULT_BUF_SIZE),
            cur_part,
            cur_file: None,
            cur_off: 0,
            remaining: len,
            skip_in_part,
            pending: Vec::new(),
            pending_off: 0,
        }
    }

    /// Total logical bytes this reader will yield.
    pub fn remaining(&self) -> u64 {
        self.remaining + (self.pending.len() - self.pending_off) as u64
    }

    /// Ensure the current part file is open, applying any pending skip.
    fn ensure_open(&mut self) -> io::Result<bool> {
        while self.cur_part < self.parts.len() {
            if self.cur_file.is_none() {
                let path = PathBuf::from(&self.parts[self.cur_part].path);
                let f = DioFile::open_read(&path)?;
                self.cur_file = Some(f);
                self.cur_off = self.skip_in_part;
                self.skip_in_part = 0;
            }
            // If we've consumed this whole part, advance.
            if self.cur_off >= self.parts[self.cur_part].size {
                self.cur_file = None;
                self.cur_part += 1;
                continue;
            }
            return Ok(true);
        }
        Ok(false)
    }
}

impl Read for MultipartReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.pending_off < self.pending.len() {
            let n = (self.pending.len() - self.pending_off).min(out.len());
            out[..n].copy_from_slice(&self.pending[self.pending_off..self.pending_off + n]);
            self.pending_off += n;
            return Ok(n);
        }
        if self.remaining == 0 {
            return Ok(0);
        }
        if !self.ensure_open()? {
            return Ok(0);
        }

        let part_size = self.parts[self.cur_part].size;
        let file = self.cur_file.as_ref().unwrap();

        // Aligned read window covering cur_off within the current part.
        let aligned_start = self.cur_off & !(super::aligned::ALIGN as u64 - 1);
        let skip = (self.cur_off - aligned_start) as usize;
        let cap = self.buf.capacity();
        let n = file.pread_at(&mut self.buf[..cap], aligned_start)?;
        if n == 0 {
            // Part shorter than expected; advance to next part.
            self.cur_file = None;
            self.cur_part += 1;
            return self.read(out);
        }
        let window_end = (aligned_start + n as u64).min(part_size);
        if window_end <= self.cur_off {
            self.cur_file = None;
            self.cur_part += 1;
            return self.read(out);
        }
        let avail_in_part = (window_end - self.cur_off) as usize;
        // Don't exceed the logical remaining count.
        let avail = (avail_in_part as u64).min(self.remaining) as usize;
        let data = &self.buf[skip..skip + avail];
        let take = avail.min(out.len());
        out[..take].copy_from_slice(&data[..take]);
        if take < avail {
            self.pending = data[take..].to_vec();
            self.pending_off = 0;
        }
        self.cur_off += avail as u64;
        self.remaining -= avail as u64;
        if self.cur_off >= part_size {
            self.cur_file = None;
            self.cur_part += 1;
        }
        Ok(take)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_file(dir: &std::path::Path, name: &str, data: &[u8]) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, data).unwrap();
        p
    }

    #[test]
    fn plain_full_read() {
        let dir = tempfile::tempdir().unwrap();
        let data: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();
        let p = write_file(dir.path(), "f", &data);
        let mut r = PlainFileReader::open(&p, None).unwrap();
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        assert_eq!(out, data);
    }

    #[test]
    fn plain_range_read() {
        let dir = tempfile::tempdir().unwrap();
        let data: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();
        let p = write_file(dir.path(), "f", &data);
        // range bytes=100-199 (inclusive)
        let r = ByteRange {
            start: 100,
            end: 199,
        };
        let mut rd = PlainFileReader::open(&p, Some(r)).unwrap();
        let mut out = Vec::new();
        rd.read_to_end(&mut out).unwrap();
        assert_eq!(out, data[100..=199]);
    }

    #[test]
    fn parse_range_cases() {
        assert_eq!(parse_range("bytes=0-99", 1000).unwrap().unwrap(),
            ByteRange { start: 0, end: 99 });
        assert_eq!(parse_range("bytes=500-", 1000).unwrap().unwrap(),
            ByteRange { start: 500, end: 999 });
        assert_eq!(parse_range("bytes=-100", 1000).unwrap().unwrap(),
            ByteRange { start: 900, end: 999 });
        // end clamps to size-1
        assert_eq!(parse_range("bytes=0-100000", 1000).unwrap().unwrap(),
            ByteRange { start: 0, end: 999 });
        // no header
        assert!(parse_range("something", 1000).unwrap().is_none());
        // unsatisfiable: start past end
        assert!(parse_range("bytes=2000-", 1000).is_err());
    }

    fn md5_hex(data: &[u8]) -> String {
        use md5::{Digest, Md5};
        let mut h = Md5::new();
        h.update(data);
        hex::encode(h.finalize())
    }

    #[test]
    fn multipart_full_concat() {
        let dir = tempfile::tempdir().unwrap();
        let p1 = b"AAAAAAAAAA".to_vec(); // 10
        let p2 = b"BBBBBBBBBBBBBBB".to_vec(); // 15
        let p3 = b"CC".to_vec(); // 2
        let f1 = write_file(dir.path(), "00001", &p1);
        let f2 = write_file(dir.path(), "00002", &p2);
        let f3 = write_file(dir.path(), "00003", &p3);
        let parts = vec![
            PartRef { part_number: 1, path: f1.to_string_lossy().into(), size: p1.len() as u64, md5_hex: md5_hex(&p1) },
            PartRef { part_number: 2, path: f2.to_string_lossy().into(), size: p2.len() as u64, md5_hex: md5_hex(&p2) },
            PartRef { part_number: 3, path: f3.to_string_lossy().into(), size: p3.len() as u64, md5_hex: md5_hex(&p3) },
        ];
        let mut r = MultipartReader::new(parts, None);
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        let mut expected = p1.clone();
        expected.extend_from_slice(&p2);
        expected.extend_from_slice(&p3);
        assert_eq!(out, expected);
    }

    #[test]
    fn multipart_range_spanning_parts() {
        let dir = tempfile::tempdir().unwrap();
        // Three 1000-byte parts of distinct bytes.
        let p1 = vec![1u8; 1000];
        let p2 = vec![2u8; 1000];
        let p3 = vec![3u8; 1000];
        let f1 = write_file(dir.path(), "00001", &p1);
        let f2 = write_file(dir.path(), "00002", &p2);
        let f3 = write_file(dir.path(), "00003", &p3);
        let parts = vec![
            PartRef { part_number: 1, path: f1.to_string_lossy().into(), size: 1000, md5_hex: md5_hex(&p1) },
            PartRef { part_number: 2, path: f2.to_string_lossy().into(), size: 1000, md5_hex: md5_hex(&p2) },
            PartRef { part_number: 3, path: f3.to_string_lossy().into(), size: 1000, md5_hex: md5_hex(&p3) },
        ];
        // Logical range [500, 2499]: last 500 of p1, all of p2, first 500 of p3.
        let r = ByteRange { start: 500, end: 2499 };
        let mut rd = MultipartReader::new(parts, Some(r));
        let mut out = Vec::new();
        rd.read_to_end(&mut out).unwrap();
        let mut expected = Vec::new();
        expected.extend_from_slice(&p1[500..]);
        expected.extend_from_slice(&p2);
        expected.extend_from_slice(&p3[..500]);
        assert_eq!(out.len(), 2000);
        assert_eq!(out, expected);
    }

    #[test]
    fn multipart_large_one_pass() {
        // ~3MB across parts, read with a small odd buffer to exercise boundaries.
        let dir = tempfile::tempdir().unwrap();
        let mk = |seed: u8, n: usize| -> Vec<u8> {
            (0..n).map(|i| (i as u8).wrapping_add(seed)).collect()
        };
        let p1 = mk(0, 1_500_000);
        let p2 = mk(99, 1_500_007);
        let f1 = write_file(dir.path(), "00001", &p1);
        let f2 = write_file(dir.path(), "00002", &p2);
        let parts = vec![
            PartRef { part_number: 1, path: f1.to_string_lossy().into(), size: p1.len() as u64, md5_hex: md5_hex(&p1) },
            PartRef { part_number: 2, path: f2.to_string_lossy().into(), size: p2.len() as u64, md5_hex: md5_hex(&p2) },
        ];
        let mut rd = MultipartReader::new(parts, None);
        let mut out = Vec::new();
        let mut tmp = [0u8; 4099];
        loop {
            let n = rd.read(&mut tmp).unwrap();
            if n == 0 { break; }
            out.extend_from_slice(&tmp[..n]);
        }
        let mut expected = p1.clone();
        expected.extend_from_slice(&p2);
        assert_eq!(out, expected);
    }
}

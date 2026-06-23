//! Synchronous de-framing reader for `STREAMING-AWS4-HMAC-SHA256-PAYLOAD`.
//!
//! Ported from the Go `internal/auth/chunked_reader.go`. The aws-cli sends
//! `s3 cp` bodies in chunked SigV4 format:
//!
//! ```text
//! {hex-size};chunk-signature={sig}\r\n{data}\r\n
//! ...
//! 0;chunk-signature={sig}\r\n\r\n
//! ```
//!
//! OPTIMIZATION / SECURITY NOTE: we verify only the SEED signature (done in
//! sigv4 verification before this reader runs) and SKIP per-chunk signature
//! verification. This matches the Go impl and avoids a per-byte HMAC cost on the
//! hot path; payload integrity is covered by TLS. This reader is a pure
//! `io::Read` adapter so it can wrap any blocking body source and be driven from
//! `spawn_blocking`.

use std::io::{self, BufRead, BufReader, Read};

const MAX_LINE_LEN: usize = 4096;

/// De-framing reader: strips the chunk headers/trailers and yields only the
/// payload bytes. Returns EOF after the terminating `0`-size chunk.
pub struct ChunkedReader<R: Read> {
    inner: BufReader<R>,
    /// Bytes remaining in the current chunk's data section.
    remaining: u64,
    done: bool,
}

impl<R: Read> ChunkedReader<R> {
    pub fn new(inner: R) -> Self {
        ChunkedReader {
            inner: BufReader::with_capacity(64 * 1024, inner),
            remaining: 0,
            done: false,
        }
    }

    /// Read the next chunk header line (terminated by `\n`), trimmed of trailing
    /// whitespace. Errors if the line exceeds [`MAX_LINE_LEN`] or stream ends.
    fn read_header_line(&mut self) -> io::Result<Vec<u8>> {
        let mut line = Vec::with_capacity(64);
        loop {
            let buf = self.inner.fill_buf()?;
            if buf.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "unexpected EOF reading chunk header",
                ));
            }
            if let Some(pos) = buf.iter().position(|&b| b == b'\n') {
                line.extend_from_slice(&buf[..=pos]);
                let consumed = pos + 1;
                self.inner.consume(consumed);
                break;
            } else {
                line.extend_from_slice(buf);
                let n = buf.len();
                self.inner.consume(n);
            }
            if line.len() > MAX_LINE_LEN {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "chunk header line too long",
                ));
            }
        }
        // Trim trailing ASCII whitespace (\r\n etc).
        while matches!(line.last(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            line.pop();
        }
        Ok(line)
    }

    /// Consume the literal `\r\n` that follows a chunk's data.
    fn read_crlf(&mut self) -> io::Result<()> {
        let mut crlf = [0u8; 2];
        self.inner.read_exact(&mut crlf)?;
        if &crlf != b"\r\n" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "malformed chunked encoding: expected CRLF",
            ));
        }
        Ok(())
    }
}

impl<R: Read> Read for ChunkedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.done {
            return Ok(0);
        }
        loop {
            // Drain current chunk's data first.
            if self.remaining > 0 {
                if buf.is_empty() {
                    return Ok(0);
                }
                let want = std::cmp::min(buf.len() as u64, self.remaining) as usize;
                let n = self.inner.read(&mut buf[..want])?;
                if n == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "unexpected EOF in chunk data",
                    ));
                }
                self.remaining -= n as u64;
                if self.remaining == 0 {
                    // Consume trailing CRLF after the data segment.
                    self.read_crlf()?;
                }
                return Ok(n);
            }

            // Read next chunk header.
            let line = self.read_header_line()?;
            let (hex_size, _sig) = parse_chunk_extension(&line);
            let size = parse_hex_uint(hex_size)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

            if size == 0 {
                // Final chunk; signal EOF. The terminating `0`-chunk may be
                // followed by EITHER a bare `\r\n` OR one-or-more trailer header
                // lines (the STREAMING-*-TRAILER variants this reader is fed, see
                // `handler::is_chunked_upload`). We therefore DELIBERATELY do not
                // require a specific terminator here: we've already de-framed every
                // payload byte, and the seed signature was verified upstream.
                // Consuming the trailer is best-effort and any error is benign
                // (the connection/body is about to be dropped), so it is ignored
                // on purpose rather than propagated — propagating it would reject
                // legitimate trailer-bearing uploads.
                self.done = true;
                let _ = self.read_crlf();
                return Ok(0);
            }
            self.remaining = size;
        }
    }
}

const CHUNK_SIG_STR: &[u8] = b";chunk-signature=";

/// Split a header line into `(hex-size, signature)`. Signature may be empty.
fn parse_chunk_extension(buf: &[u8]) -> (&[u8], &[u8]) {
    if let Some(idx) = find_subslice(buf, CHUNK_SIG_STR) {
        (&buf[..idx], &buf[idx + CHUNK_SIG_STR.len()..])
    } else {
        (buf, &[])
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Parse a hex chunk size (Go `parseHexUint`). Rejects >16 hex digits.
fn parse_hex_uint(v: &[u8]) -> Result<u64, &'static str> {
    if v.is_empty() {
        return Err("empty chunk size");
    }
    let mut n: u64 = 0;
    for (i, &b) in v.iter().enumerate() {
        let d = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => return Err("invalid byte in chunk length"),
        };
        if i >= 16 {
            return Err("chunk length too large");
        }
        n = (n << 4) | d as u64;
    }
    Ok(n)
}

/// Compute the signature for a single chunk (Go `GetChunkSignature`). Provided
/// for completeness / future per-chunk verification; not used on the hot path.
pub fn get_chunk_signature(
    seed_signature: &str,
    seed_date_iso: &str,
    region: &str,
    service: &str,
    secret_key: &str,
    hashed_chunk: &str,
) -> String {
    use super::sigv4::{
        get_scope, get_signature, get_signing_key, EMPTY_SHA256, SIGN_V4_ALGORITHM,
    };
    let yyyymmdd = &seed_date_iso[..8.min(seed_date_iso.len())];
    let scope = get_scope(yyyymmdd, region, service);
    let string_to_sign = format!(
        "{}-PAYLOAD\n{}\n{}\n{}\n{}\n{}",
        SIGN_V4_ALGORITHM, seed_date_iso, scope, seed_signature, EMPTY_SHA256, hashed_chunk
    );
    let signing_key = get_signing_key(secret_key, yyyymmdd, region, service);
    get_signature(&signing_key, &string_to_sign)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(data: &[u8]) -> Vec<u8> {
        // Build a single-chunk + terminator stream with dummy chunk signatures.
        let mut out = Vec::new();
        let header = format!("{:x};chunk-signature=deadbeef\r\n", data.len());
        out.extend_from_slice(header.as_bytes());
        out.extend_from_slice(data);
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(b"0;chunk-signature=deadbeef\r\n\r\n");
        out
    }

    fn frame_multi(chunks: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        for c in chunks {
            let header = format!("{:x};chunk-signature=abc\r\n", c.len());
            out.extend_from_slice(header.as_bytes());
            out.extend_from_slice(c);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"0;chunk-signature=abc\r\n\r\n");
        out
    }

    #[test]
    fn single_chunk() {
        let payload = b"hello world";
        let framed = frame(payload);
        let mut r = ChunkedReader::new(&framed[..]);
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        assert_eq!(out, payload);
    }

    #[test]
    fn multiple_chunks() {
        let framed = frame_multi(&[b"abc", b"defgh", b"ij"]);
        let mut r = ChunkedReader::new(&framed[..]);
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        assert_eq!(out, b"abcdefghij");
    }

    #[test]
    fn empty_payload() {
        let framed = frame(b"");
        let mut r = ChunkedReader::new(&framed[..]);
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn large_payload_small_buffer_reads() {
        // 100KB across small reads to exercise chunk-boundary logic.
        let payload: Vec<u8> = (0..100_000).map(|i| (i % 251) as u8).collect();
        let framed = frame_multi(&[&payload[..40000], &payload[40000..]]);
        let mut r = ChunkedReader::new(&framed[..]);
        let mut out = Vec::new();
        let mut tmp = [0u8; 37]; // odd buffer size
        loop {
            let n = r.read(&mut tmp).unwrap();
            if n == 0 {
                break;
            }
            out.extend_from_slice(&tmp[..n]);
        }
        assert_eq!(out, payload);
    }

    #[test]
    fn parse_hex() {
        assert_eq!(parse_hex_uint(b"a").unwrap(), 10);
        assert_eq!(parse_hex_uint(b"10").unwrap(), 16);
        assert_eq!(parse_hex_uint(b" FF".trim_ascii()).unwrap(), 255);
        assert!(parse_hex_uint(b"xyz").is_err());
        assert!(parse_hex_uint(b"").is_err());
    }

    #[test]
    fn parse_extension() {
        let (size, sig) = parse_chunk_extension(b"1a;chunk-signature=abcd");
        assert_eq!(size, b"1a");
        assert_eq!(sig, b"abcd");
        let (size2, sig2) = parse_chunk_extension(b"1a");
        assert_eq!(size2, b"1a");
        assert!(sig2.is_empty());
    }

    #[test]
    fn truncated_stream_errors() {
        // Declare 10 bytes but provide only 3.
        let mut framed = Vec::new();
        framed.extend_from_slice(b"a;chunk-signature=x\r\n");
        framed.extend_from_slice(b"abc");
        let mut r = ChunkedReader::new(&framed[..]);
        let mut out = Vec::new();
        assert!(r.read_to_end(&mut out).is_err());
    }
}

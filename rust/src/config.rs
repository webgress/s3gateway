//! CLI flags + runtime configuration. Mirrors the Go binary's flags and adds
//! `--workers` (thread-per-core runtime count) and `--ktls` (kTLS offload).

use clap::Parser;

/// Lightweight, max-throughput S3-compatible object storage gateway.
#[derive(Debug, Clone, Parser)]
#[command(name = "s3gateway-rs", version, about)]
pub struct Config {
    /// HTTP listen port.
    #[arg(long, default_value_t = 8333)]
    pub port: u16,

    /// Root directory for object storage (required).
    #[arg(long)]
    pub data_dir: String,

    /// Path to credentials JSON.
    #[arg(long, default_value = "credentials.json")]
    pub credentials: String,

    /// TLS certificate file (enables HTTPS).
    #[arg(long)]
    pub tls_cert: Option<String>,

    /// TLS private key file.
    #[arg(long)]
    pub tls_key: Option<String>,

    /// AWS region for SigV4.
    #[arg(long, default_value = "us-east-1")]
    pub region: String,

    /// Log level: debug, info, warn, error.
    #[arg(long, default_value = "info")]
    pub log_level: String,

    /// Number of thread-per-core tokio runtimes (default = num CPUs).
    #[arg(long, default_value_t = default_workers())]
    pub workers: usize,

    /// Use kTLS offload (when false, stay in userspace rustls).
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub ktls: bool,

    /// Durable object publication: fsync the data file, sidecar, and parent
    /// directory before reporting success. Default true (crash-safe). Set to
    /// false to skip the sidecar/dir fsyncs for maximum throughput, at the cost
    /// of durability — a power loss may leave a just-PUT object's metadata or
    /// directory entry unflushed (the data file is still fsync'd either way).
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub fsync: bool,

    /// Abandoned-multipart-upload reaper threshold (S3's
    /// AbortIncompleteMultipartUpload). When set, at STARTUP (after crash-recovery,
    /// before the listener binds) any in-flight multipart upload older than this age
    /// is aborted and its part blobs reclaimed. Default OFF (in-flight uploads are
    /// kept indefinitely). Accepts a duration like `30m`, `24h`, `7d` (units:
    /// `s`/`m`/`h`/`d`; a bare number is seconds).
    #[arg(long, value_parser = parse_duration)]
    pub abort_incomplete_uploads_after: Option<std::time::Duration>,
}

fn default_workers() -> usize {
    num_cpus::get()
}

/// Parse a human duration with a `s`/`m`/`h`/`d` suffix (e.g. `30m`, `24h`, `7d`).
/// A bare integer is interpreted as seconds. Dependency-free (no humantime crate).
fn parse_duration(s: &str) -> Result<std::time::Duration, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty duration".to_string());
    }
    let (num, unit_secs): (&str, u64) = match s.as_bytes().last() {
        Some(b's') => (&s[..s.len() - 1], 1),
        Some(b'm') => (&s[..s.len() - 1], 60),
        Some(b'h') => (&s[..s.len() - 1], 3600),
        Some(b'd') => (&s[..s.len() - 1], 86_400),
        Some(c) if c.is_ascii_digit() => (s, 1), // bare number == seconds
        _ => return Err(format!("invalid duration unit in {s:?} (use s/m/h/d)")),
    };
    let n: u64 = num
        .trim()
        .parse()
        .map_err(|_| format!("invalid duration number in {s:?}"))?;
    Ok(std::time::Duration::from_secs(n.saturating_mul(unit_secs)))
}

impl Config {
    /// Whether TLS is configured (both cert and key present).
    pub fn tls_enabled(&self) -> bool {
        self.tls_cert.is_some() && self.tls_key.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn parses_required_and_defaults() {
        let cfg = Config::parse_from(["s3gateway-rs", "--data-dir", "/tmp/data"]);
        assert_eq!(cfg.port, 8333);
        assert_eq!(cfg.data_dir, "/tmp/data");
        assert_eq!(cfg.credentials, "credentials.json");
        assert_eq!(cfg.region, "us-east-1");
        assert_eq!(cfg.log_level, "info");
        assert!(cfg.workers >= 1);
        assert!(cfg.ktls);
        assert!(cfg.fsync);
        assert!(!cfg.tls_enabled());
    }

    #[test]
    fn parses_overrides() {
        let cfg = Config::parse_from([
            "s3gateway-rs",
            "--data-dir",
            "/d",
            "--port",
            "9000",
            "--workers",
            "4",
            "--ktls",
            "false",
            "--fsync",
            "false",
            "--tls-cert",
            "/c.pem",
            "--tls-key",
            "/k.pem",
        ]);
        assert_eq!(cfg.port, 9000);
        assert_eq!(cfg.workers, 4);
        assert!(!cfg.ktls);
        assert!(!cfg.fsync);
        assert!(cfg.tls_enabled());
    }

    #[test]
    fn abort_incomplete_uploads_after_defaults_off_and_parses() {
        use std::time::Duration;
        // Default: absent -> reaper OFF.
        let cfg = Config::parse_from(["s3gateway-rs", "--data-dir", "/d"]);
        assert!(cfg.abort_incomplete_uploads_after.is_none());
        // Units.
        for (arg, secs) in [("45s", 45), ("30m", 1800), ("24h", 86_400), ("7d", 604_800), ("90", 90)] {
            let cfg = Config::parse_from([
                "s3gateway-rs",
                "--data-dir",
                "/d",
                "--abort-incomplete-uploads-after",
                arg,
            ]);
            assert_eq!(cfg.abort_incomplete_uploads_after, Some(Duration::from_secs(secs)), "arg {arg}");
        }
    }

    #[test]
    fn parse_duration_rejects_garbage() {
        assert!(parse_duration("").is_err());
        assert!(parse_duration("abc").is_err());
        assert!(parse_duration("12x").is_err());
        assert!(parse_duration("h").is_err());
    }
}

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
}

fn default_workers() -> usize {
    num_cpus::get()
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
            "--tls-cert",
            "/c.pem",
            "--tls-key",
            "/k.pem",
        ]);
        assert_eq!(cfg.port, 9000);
        assert_eq!(cfg.workers, 4);
        assert!(!cfg.ktls);
        assert!(cfg.tls_enabled());
    }
}

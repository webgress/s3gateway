//! s3gateway-rs entry point.
//!
//! Parses CLI flags, loads credentials, initializes JSON logging, installs the
//! rustls crypto provider, then launches the thread-per-core hyper server.

use std::sync::Arc;

use clap::Parser;

use s3gateway_rs::auth::CredentialStore;
use s3gateway_rs::config::Config;
use s3gateway_rs::handler::Ctx;
use s3gateway_rs::server;
use s3gateway_rs::storage::Filesystem;

fn main() {
    let cfg = Config::parse();

    init_logging(&cfg.log_level);

    // Install the process-wide default rustls crypto provider (ring). Safe to
    // call even when serving plaintext.
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Load credentials up front so misconfiguration fails fast.
    let store = match CredentialStore::load(&cfg.credentials) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("failed to load credentials from {}: {e}", cfg.credentials);
            std::process::exit(1);
        }
    };

    let fs = Filesystem::with_fsync(&cfg.data_dir, cfg.fsync);
    if let Err(e) = std::fs::create_dir_all(fs.root()) {
        eprintln!("failed to create data dir {}: {e}", cfg.data_dir);
        std::process::exit(1);
    }

    tracing::info!(
        port = cfg.port,
        data_dir = %cfg.data_dir,
        region = %cfg.region,
        workers = cfg.workers,
        ktls = cfg.ktls,
        fsync = cfg.fsync,
        tls = cfg.tls_enabled(),
        credentials = store.len(),
        "s3gateway-rs starting"
    );

    let ctx = Ctx {
        fs,
        creds: Arc::new(store),
        region: cfg.region.clone(),
    };

    if let Err(e) = server::run(cfg, ctx) {
        eprintln!("server error: {e}");
        std::process::exit(1);
    }
}

/// Initialize JSON structured logging at the requested level.
fn init_logging(level: &str) {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_new(level).unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .json()
        .with_env_filter(filter)
        .try_init();
}

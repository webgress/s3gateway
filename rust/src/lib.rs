//! s3gateway-rs library layer.
//!
//! Synchronous, fully unit-testable building blocks for a max-throughput
//! S3-compatible gateway:
//!   - [`auth`]: credentials, SigV4 verification, chunked payload de-framing.
//!   - [`storage`]: Direct-IO storage pool, metadata, multipart store-parts /
//!     reassemble-on-read, listing.
//!   - [`s3response`]: S3 XML responses + error-code mapping.
//!   - [`config`]: CLI flags / runtime config.
//!
//! The [`server`] module provides the thread-per-core tokio + hyper +
//! rustls/ktls server, and [`handler`] provides the HTTP handlers built on top
//! of these. The storage read/write helpers are BLOCKING and are invoked from
//! `tokio::task::spawn_blocking`.

pub mod auth;
pub mod config;
pub mod handler;
pub mod s3response;
pub mod server;
pub mod storage;

pub use config::Config;

//! Thread-per-core, shared-nothing HTTP/HTTPS server.
//!
//! Each worker is an OS thread pinned to a core, running its OWN tokio
//! current-thread runtime and owning its OWN `SO_REUSEPORT` listener bound to the
//! same port. The kernel load-balances accepts across the per-core listeners, so
//! a connection is handled end-to-end on the accepting core (no cross-core
//! handoff, minimal cache churn).
//!
//! TLS: when a cert/key is configured we complete a rustls handshake
//! (tokio-rustls). If `--ktls` is set AND the kernel `tls` ULP is available, we
//! upgrade to kernel TLS via `ktls::config_ktls_server` (which on an
//! offload-capable NIC becomes inline NIC offload, and otherwise is in-kernel
//! software kTLS). Availability is probed ONCE at startup with a throwaway
//! loopback socket: if the kernel cannot load the `tls` ULP, we never consume
//! the connection into the kTLS path and instead serve it over the userspace
//! rustls `TlsStream` — a genuine, working fallback (no dropped connections).
//! With no cert we serve plaintext HTTP.

pub mod router;

use std::io;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rustls::ServerConfig;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

use crate::config::Config;
use crate::handler::Ctx;

/// The serving mode actually in effect (for the startup log line).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServeMode {
    Plaintext,
    RustlsUserspace,
    RustlsKtls,
}

impl ServeMode {
    fn label(self) -> &'static str {
        match self {
            ServeMode::Plaintext => "plaintext",
            ServeMode::RustlsUserspace => "rustls(userspace)",
            ServeMode::RustlsKtls => "rustls+kTLS(offload)",
        }
    }
}

/// TLS state shared across workers (None = plaintext).
#[derive(Clone)]
struct TlsState {
    acceptor: TlsAcceptor,
    /// True only if `--ktls` is set AND the kernel `tls` ULP is actually
    /// loadable (probed once at startup). When false we serve userspace rustls.
    use_ktls: bool,
}

/// Logged-once guard so the userspace-fallback WARN is emitted a single time.
static KTLS_FALLBACK_WARNED: AtomicBool = AtomicBool::new(false);

/// Probe (once) whether the kernel `tls` ULP can be enabled on a TCP socket.
///
/// We open a throwaway loopback TCP connection and attempt
/// `setsockopt(TCP_ULP, "tls")` on the connected fd. Success means kTLS
/// (software at minimum, NIC-offloaded if the hardware supports it) is usable;
/// failure (ENOENT / EOPNOTSUPP — kernel module not loaded) means we must stay
/// in userspace rustls. The probe leaves the real listener untouched.
fn ktls_ulp_available() -> bool {
    // Env-gated injection for verification: forces the "unavailable" branch so
    // the userspace fallback can be exercised on offload-capable hardware.
    if std::env::var_os("S3GW_FORCE_KTLS_FAIL").is_some() {
        return false;
    }
    probe_tls_ulp().unwrap_or(false)
}

/// Establish a connected loopback TCP pair and try to set the `tls` ULP.
fn probe_tls_ulp() -> io::Result<bool> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let client = std::net::TcpStream::connect(addr)?;
    let (server, _peer) = listener.accept()?;
    // setsockopt(SOL_TCP=6, TCP_ULP=31, "tls"). The ULP can only be set on an
    // ESTABLISHED socket, which both ends of this loopback pair now are.
    const SOL_TCP: libc::c_int = 6;
    const TCP_ULP: libc::c_int = 31;
    let rc = unsafe {
        libc::setsockopt(
            server.as_raw_fd(),
            SOL_TCP,
            TCP_ULP,
            c"tls".as_ptr() as *const libc::c_void,
            3,
        )
    };
    drop(client);
    drop(server);
    Ok(rc == 0)
}

/// Run the server: spawn one pinned worker thread per `--workers`, each with its
/// own runtime + SO_REUSEPORT listener. Blocks until all workers exit (they run
/// forever in practice; Ctrl-C terminates the process).
pub fn run(cfg: Config, ctx: Ctx) -> io::Result<()> {
    let addr: SocketAddr = format!("0.0.0.0:{}", cfg.port)
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("bad addr: {e}")))?;

    // Build TLS state once (shared, cheaply cloneable) if configured.
    let (tls_state, mode) = if cfg.tls_enabled() {
        let server_config = build_tls_config(&cfg)?;
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        // Decide kTLS vs userspace ONCE, up front: only use kTLS if requested
        // AND the kernel `tls` ULP is actually loadable on this host.
        let use_ktls = cfg.ktls && ktls_ulp_available();
        if cfg.ktls && !use_ktls {
            tracing::warn!(
                "kTLS requested (--ktls) but kernel `tls` ULP is unavailable; \
                 serving TLS over userspace rustls"
            );
        }
        let mode = if use_ktls {
            ServeMode::RustlsKtls
        } else {
            ServeMode::RustlsUserspace
        };
        (Some(TlsState { acceptor, use_ktls }), mode)
    } else {
        (None, ServeMode::Plaintext)
    };

    let core_ids = core_affinity::get_core_ids().unwrap_or_default();
    let workers = cfg.workers.max(1);

    tracing::info!(
        mode = mode.label(),
        workers = workers,
        cores_detected = core_ids.len(),
        port = cfg.port,
        "serving"
    );
    // Always print a clear human-readable startup line too.
    eprintln!(
        "s3gateway-rs: mode={} workers={} port={} cores_detected={}",
        mode.label(),
        workers,
        cfg.port,
        core_ids.len()
    );

    let mut handles = Vec::with_capacity(workers);
    for i in 0..workers {
        let ctx = ctx.clone();
        let tls_state = tls_state.clone();
        let core_id = core_ids.get(i % core_ids.len().max(1)).copied();
        let handle = std::thread::Builder::new()
            .name(format!("s3gw-worker-{i}"))
            .spawn(move || {
                if let Some(cid) = core_id {
                    // Pin this worker to a specific core.
                    core_affinity::set_for_current(cid);
                }
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("build current-thread runtime");
                // A LocalSet lets us spawn !Send per-connection tasks (the TLS /
                // kTLS stream types are not necessarily Send) onto this core's
                // own runtime — keeping the connection on the accepting core.
                let local = tokio::task::LocalSet::new();
                local.block_on(&rt, async move {
                    if let Err(e) = worker_loop(addr, ctx, tls_state, i).await {
                        tracing::error!(worker = i, error = %e, "worker loop exited");
                    }
                });
            })?;
        handles.push(handle);
    }

    for h in handles {
        let _ = h.join();
    }
    Ok(())
}

/// Per-worker accept loop on a dedicated SO_REUSEPORT listener.
async fn worker_loop(
    addr: SocketAddr,
    ctx: Ctx,
    tls_state: Option<TlsState>,
    worker: usize,
) -> io::Result<()> {
    let listener = make_reuseport_listener(addr)?;
    tracing::debug!(worker = worker, "listening");

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                tracing::warn!(worker = worker, error = %e, "accept failed");
                continue;
            }
        };
        // Nagle off for latency.
        let _ = stream.set_nodelay(true);

        let ctx = ctx.clone();
        let tls_state = tls_state.clone();
        // Handle the connection on this same core's runtime.
        tokio::task::spawn_local(async move {
            if let Err(e) = serve_conn(stream, peer, ctx, tls_state).await {
                tracing::debug!(error = %e, "connection ended");
            }
        });
    }
}

/// Complete TLS (if configured) and serve HTTP/1.1 over the resulting stream.
async fn serve_conn(
    tcp: TcpStream,
    peer: SocketAddr,
    ctx: Ctx,
    tls_state: Option<TlsState>,
) -> io::Result<()> {
    let stream: UnifiedStream = match tls_state {
        None => UnifiedStream::Plain(tcp),
        Some(ts) => establish_tls(tcp, ts).await?,
    };

    let io = TokioIo::new(stream);
    let remote = peer.to_string();

    let service = service_fn(move |req| {
        let ctx = ctx.clone();
        let remote = remote.clone();
        async move { router::dispatch(ctx, remote, req).await }
    });

    if let Err(e) = http1::Builder::new().serve_connection(io, service).await {
        return Err(io::Error::other(format!("http1 serve: {e}")));
    }
    Ok(())
}

/// Complete the rustls handshake and produce the serving stream.
///
/// kTLS-vs-userspace is decided UP FRONT (in `run`, via the one-time `tls` ULP
/// probe), so we never consume a connection into the kTLS path on a host that
/// can't support it. When `use_ktls` is true we know the ULP is loadable, so the
/// corked handshake + `config_ktls_server` upgrade is expected to succeed; on the
/// off chance it still errors (e.g. unexpected cipher), we cannot reuse the
/// drained CorkStream, so that single connection is dropped while subsequent
/// connections keep working. When `use_ktls` is false we serve the plain
/// userspace rustls `TlsStream` — a fully-correct TLS path.
async fn establish_tls(tcp: TcpStream, ts: TlsState) -> io::Result<UnifiedStream> {
    if ts.use_ktls {
        // kTLS requires the inner IO be wrapped in a CorkStream so rustls can be
        // drained cleanly before handing the fd to the kernel.
        let corked = ktls::CorkStream::new(tcp);
        let tls = ts
            .acceptor
            .accept(corked)
            .await
            .map_err(|e| io::Error::other(format!("tls handshake: {e}")))?;
        match ktls::config_ktls_server(tls).await {
            Ok(kstream) => Ok(UnifiedStream::Ktls(Box::new(kstream))),
            Err(e) => {
                // ULP was available but the upgrade still failed; the CorkStream
                // is already drained so we can't serve this one connection.
                Err(io::Error::other(format!(
                    "ktls upgrade failed unexpectedly after ULP probe: {e}"
                )))
            }
        }
    } else {
        // Userspace rustls fallback (and the path taken whenever kTLS is
        // unavailable or disabled). Warn ONCE so operators know offload is off.
        if !KTLS_FALLBACK_WARNED.swap(true, Ordering::Relaxed) {
            tracing::warn!("serving TLS over userspace rustls (kTLS offload not in use)");
        }
        let tls = ts
            .acceptor
            .accept(tcp)
            .await
            .map_err(|e| io::Error::other(format!("tls handshake: {e}")))?;
        Ok(UnifiedStream::Tls(Box::new(tls)))
    }
}

/// Build a SO_REUSEADDR + SO_REUSEPORT listener bound to `addr`.
fn make_reuseport_listener(addr: SocketAddr) -> io::Result<TcpListener> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let sock = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    sock.set_reuse_address(true)?;
    sock.set_reuse_port(true)?;
    sock.set_nonblocking(true)?;
    sock.bind(&addr.into())?;
    sock.listen(1024)?;
    let std_listener: std::net::TcpListener = sock.into();
    TcpListener::from_std(std_listener)
}

/// Build a rustls ServerConfig with secret extraction enabled (required by
/// ktls) and AES-GCM cipher suites preferred (those are the NIC-offloadable
/// ones).
fn build_tls_config(cfg: &Config) -> io::Result<ServerConfig> {
    let cert_path = cfg.tls_cert.as_ref().unwrap();
    let key_path = cfg.tls_key.as_ref().unwrap();

    let certs = load_certs(cert_path)?;
    let key = load_private_key(key_path)?;

    // Use the ring provider but restrict to AES-GCM suites (offloadable) and
    // request secret extraction so ktls can pull the traffic keys.
    let provider = aes_gcm_ring_provider();

    let mut config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .map_err(|e| io::Error::other(format!("tls protocol versions: {e}")))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| io::Error::other(format!("tls cert/key: {e}")))?;

    // Required for kTLS: lets us extract the negotiated traffic secrets.
    config.enable_secret_extraction = true;
    Ok(config)
}

/// A ring-based CryptoProvider limited to AES-GCM cipher suites (the
/// NIC-offloadable ones for kTLS).
fn aes_gcm_ring_provider() -> rustls::crypto::CryptoProvider {
    use rustls::crypto::ring;
    let mut provider = ring::default_provider();
    provider.cipher_suites.retain(|cs| {
        matches!(
            cs.suite(),
            rustls::CipherSuite::TLS13_AES_256_GCM_SHA384
                | rustls::CipherSuite::TLS13_AES_128_GCM_SHA256
                | rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                | rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
                | rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
                | rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        )
    });
    provider
}

fn load_certs(path: &str) -> io::Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let data = std::fs::read(path)?;
    let mut reader = std::io::BufReader::new(&data[..]);
    let certs: Vec<_> = rustls_pemfile::certs(&mut reader).collect::<Result<_, _>>()?;
    if certs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "no certificates found in cert file",
        ));
    }
    Ok(certs)
}

fn load_private_key(path: &str) -> io::Result<rustls::pki_types::PrivateKeyDer<'static>> {
    let data = std::fs::read(path)?;
    let mut reader = std::io::BufReader::new(&data[..]);
    rustls_pemfile::private_key(&mut reader)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "no private key found in key file",
        )
    })
}

/// Unified stream type so hyper can serve over plaintext, userspace rustls, or
/// kTLS streams with one code path. All three impl AsyncRead + AsyncWrite.
pub enum UnifiedStream {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::server::TlsStream<TcpStream>>),
    Ktls(Box<ktls::KtlsStream<TcpStream>>),
}

impl AsyncRead for UnifiedStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            UnifiedStream::Plain(s) => Pin::new(s).poll_read(cx, buf),
            UnifiedStream::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
            UnifiedStream::Ktls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for UnifiedStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            UnifiedStream::Plain(s) => Pin::new(s).poll_write(cx, buf),
            UnifiedStream::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
            UnifiedStream::Ktls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            UnifiedStream::Plain(s) => Pin::new(s).poll_flush(cx),
            UnifiedStream::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
            UnifiedStream::Ktls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            UnifiedStream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            UnifiedStream::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
            UnifiedStream::Ktls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

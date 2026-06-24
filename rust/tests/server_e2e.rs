//! End-to-end server test: start the real thread-per-core server on an ephemeral
//! port and drive it with hand-built, SigV4-signed HTTP/1.1 requests over a raw
//! TCP socket. Exercises the full stack: routing, auth, the streaming PUT bridge,
//! and the streaming GET body — without any external S3 client.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use s3gateway_rs::auth::{
    encode_path, get_canonical_request, get_scope, get_signature, get_signing_key,
    get_string_to_sign, hash_sha256, time as atime, CredentialStore, EMPTY_SHA256,
    SIGN_V4_ALGORITHM,
};
use s3gateway_rs::config::Config;
use s3gateway_rs::handler::Ctx;
use s3gateway_rs::storage::CasStore;

const ACCESS: &str = "test-access-key";
const SECRET: &str = "test-secret-key";
const REGION: &str = "us-east-1";

/// Pick a free port by binding to :0 and reading it back.
fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

/// Start the server in a background thread; return its port.
fn start_server() -> u16 {
    let port = free_port();
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().to_string_lossy().into_owned();
    // Leak the tempdir so it survives the test process (cleaned by /tmp later).
    std::mem::forget(dir);

    let creds = CredentialStore::from_json(
        format!(r#"{{"credentials":[{{"accessKeyId":"{ACCESS}","secretAccessKey":"{SECRET}"}}]}}"#)
            .as_bytes(),
    )
    .unwrap();

    let cfg = Config {
        port,
        data_dir: data_dir.clone(),
        credentials: "unused".into(),
        tls_cert: None,
        tls_key: None,
        region: REGION.into(),
        log_level: "error".into(),
        workers: 1,
        ktls: false,
        fsync: true,
    };
    let fs = CasStore::new(&data_dir);
    std::fs::create_dir_all(fs.root()).unwrap();
    fs.recover().unwrap();
    let ctx = Ctx {
        fs,
        creds: Arc::new(creds),
        region: REGION.into(),
    };

    std::thread::spawn(move || {
        let _ = s3gateway_rs::server::run(cfg, ctx);
    });

    // Wait until the port is accepting connections.
    for _ in 0..100 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    port
}

/// Build a SigV4 `Authorization` header for a request with an empty/known body.
fn sign(
    method: &str,
    path: &str,
    query: &str,
    host: &str,
    payload_hash: &str,
    amz_date: &str,
) -> (String, Vec<(String, String)>) {
    let yyyymmdd = &amz_date[..8];
    // Signed headers: host, x-amz-content-sha256, x-amz-date.
    let mut signed: BTreeMap<String, Vec<String>> = BTreeMap::new();
    signed.insert("host".into(), vec![host.into()]);
    signed.insert(
        "x-amz-content-sha256".into(),
        vec![payload_hash.to_string()],
    );
    signed.insert("x-amz-date".into(), vec![amz_date.into()]);

    let canonical = get_canonical_request(method, &encode_path(path), query, &signed, payload_hash);
    let scope = get_scope(yyyymmdd, REGION, "s3");
    let sts = get_string_to_sign(&canonical, amz_date, &scope);
    let key = get_signing_key(SECRET, yyyymmdd, REGION, "s3");
    let sig = get_signature(&key, &sts);
    let auth = format!(
        "{} Credential={}/{}/{}/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature={}",
        SIGN_V4_ALGORITHM, ACCESS, yyyymmdd, REGION, sig
    );
    let extra = vec![
        ("x-amz-content-sha256".to_string(), payload_hash.to_string()),
        ("x-amz-date".to_string(), amz_date.to_string()),
    ];
    (auth, extra)
}

/// Send a raw HTTP/1.1 request and return (status_line, headers_blob, body).
fn http_request(
    port: u16,
    method: &str,
    path_and_query: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> (String, String, Vec<u8>) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();

    let mut req = format!("{method} {path_and_query} HTTP/1.1\r\n");
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str(&format!("Content-Length: {}\r\n", body.len()));
    req.push_str("Connection: close\r\n\r\n");

    stream.write_all(req.as_bytes()).unwrap();
    stream.write_all(body).unwrap();
    stream.flush().unwrap();

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).unwrap();

    // Split headers/body on the first CRLFCRLF.
    let sep = find_subslice(&raw, b"\r\n\r\n").expect("no header/body separator");
    let head = String::from_utf8_lossy(&raw[..sep]).into_owned();
    let body = raw[sep + 4..].to_vec();
    let mut lines = head.splitn(2, "\r\n");
    let status_line = lines.next().unwrap_or("").to_string();
    let headers_blob = lines.next().unwrap_or("").to_string();
    (status_line, headers_blob, body)
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[test]
fn e2e_put_get_list_delete() {
    let port = start_server();
    let host = format!("127.0.0.1:{port}");
    let amz_date = atime::iso8601_from_unix(atime::now_unix());

    // --- CreateBucket: PUT /testbucket ---
    let (auth, extra) = sign("PUT", "/testbucket", "", &host, EMPTY_SHA256, &amz_date);
    let mut headers = vec![
        ("Host".into(), host.clone()),
        ("Authorization".into(), auth),
    ];
    headers.extend(extra);
    let (status, _h, _b) = http_request(port, "PUT", "/testbucket", &headers, b"");
    assert!(status.contains("200"), "create-bucket status: {status}");

    // --- PutObject: PUT /testbucket/hello.txt ---
    let payload = b"hello from e2e test";
    let payload_hash = hash_sha256(payload);
    let (auth, extra) = sign(
        "PUT",
        "/testbucket/hello.txt",
        "",
        &host,
        &payload_hash,
        &amz_date,
    );
    let mut headers = vec![
        ("Host".into(), host.clone()),
        ("Authorization".into(), auth),
    ];
    headers.extend(extra);
    headers.push(("Content-Type".into(), "text/plain".into()));
    let (status, hblob, _b) = http_request(port, "PUT", "/testbucket/hello.txt", &headers, payload);
    assert!(status.contains("200"), "put-object status: {status}");
    assert!(
        hblob.to_lowercase().contains("etag"),
        "put response missing ETag: {hblob}"
    );

    // --- GetObject: GET /testbucket/hello.txt ---
    let (auth, extra) = sign(
        "GET",
        "/testbucket/hello.txt",
        "",
        &host,
        EMPTY_SHA256,
        &amz_date,
    );
    let mut headers = vec![
        ("Host".into(), host.clone()),
        ("Authorization".into(), auth),
    ];
    headers.extend(extra);
    let (status, hblob, body) = http_request(port, "GET", "/testbucket/hello.txt", &headers, b"");
    assert!(status.contains("200"), "get-object status: {status}");
    assert_eq!(body, payload, "get-object body mismatch");
    assert!(
        hblob.to_lowercase().contains("content-type: text/plain"),
        "content-type not preserved: {hblob}"
    );

    // --- Range GET: bytes=0-4 -> 206 + "hello" ---
    let (auth, extra) = sign(
        "GET",
        "/testbucket/hello.txt",
        "",
        &host,
        EMPTY_SHA256,
        &amz_date,
    );
    let mut headers = vec![
        ("Host".into(), host.clone()),
        ("Authorization".into(), auth),
    ];
    headers.extend(extra);
    headers.push(("Range".into(), "bytes=0-4".into()));
    let (status, hblob, body) = http_request(port, "GET", "/testbucket/hello.txt", &headers, b"");
    assert!(status.contains("206"), "range get status: {status}");
    assert_eq!(body, b"hello");
    assert!(
        hblob.to_lowercase().contains("content-range: bytes 0-4/19"),
        "missing content-range: {hblob}"
    );

    // --- ListObjectsV2: GET /testbucket?list-type=2 ---
    let (auth, extra) = sign(
        "GET",
        "/testbucket",
        "list-type=2",
        &host,
        EMPTY_SHA256,
        &amz_date,
    );
    let mut headers = vec![
        ("Host".into(), host.clone()),
        ("Authorization".into(), auth),
    ];
    headers.extend(extra);
    let (status, _h, body) = http_request(port, "GET", "/testbucket?list-type=2", &headers, b"");
    assert!(status.contains("200"), "list status: {status}");
    let body_str = String::from_utf8_lossy(&body);
    assert!(
        body_str.contains("<Key>hello.txt</Key>"),
        "list body: {body_str}"
    );
    assert!(body_str.contains("<KeyCount>1</KeyCount>"));

    // --- Unauthenticated request -> AccessDenied ---
    let (status, _h, body) = http_request(
        port,
        "GET",
        "/testbucket?list-type=2",
        &[("Host".into(), host.clone())],
        b"",
    );
    assert!(status.contains("403"), "unauth status: {status}");
    assert!(String::from_utf8_lossy(&body).contains("AccessDenied"));

    // --- NoSuchKey -> 404 ---
    let (auth, extra) = sign(
        "GET",
        "/testbucket/missing",
        "",
        &host,
        EMPTY_SHA256,
        &amz_date,
    );
    let mut headers = vec![
        ("Host".into(), host.clone()),
        ("Authorization".into(), auth),
    ];
    headers.extend(extra);
    let (status, _h, body) = http_request(port, "GET", "/testbucket/missing", &headers, b"");
    assert!(status.contains("404"), "nosuchkey status: {status}");
    assert!(String::from_utf8_lossy(&body).contains("NoSuchKey"));

    // --- DeleteObject -> 204 ---
    let (auth, extra) = sign(
        "DELETE",
        "/testbucket/hello.txt",
        "",
        &host,
        EMPTY_SHA256,
        &amz_date,
    );
    let mut headers = vec![
        ("Host".into(), host.clone()),
        ("Authorization".into(), auth),
    ];
    headers.extend(extra);
    let (status, _h, _b) = http_request(port, "DELETE", "/testbucket/hello.txt", &headers, b"");
    assert!(status.contains("204"), "delete status: {status}");

    // --- Healthz (unauthenticated) ---
    let (status, _h, body) = http_request(port, "GET", "/healthz", &[("Host".into(), host)], b"");
    assert!(status.contains("200"));
    assert_eq!(String::from_utf8_lossy(&body), "{\"status\":\"ok\"}");
}

#[test]
fn e2e_complete_multipart_oversized_body_rejected() {
    // F9 regression: an over-cap CompleteMultipartUpload body must be rejected
    // (EntityTooLarge, 400) rather than buffered into memory (OOM). We POST a
    // >8 MiB body to the Complete route; the server bounds the read and errors.
    let port = start_server();
    let host = format!("127.0.0.1:{port}");
    let amz_date = atime::iso8601_from_unix(atime::now_unix());

    // Bucket so routing reaches the multipart handler.
    let (auth, extra) = sign("PUT", "/mpbucket", "", &host, EMPTY_SHA256, &amz_date);
    let mut headers = vec![
        ("Host".into(), host.clone()),
        ("Authorization".into(), auth),
    ];
    headers.extend(extra);
    let (status, _h, _b) = http_request(port, "PUT", "/mpbucket", &headers, b"");
    assert!(status.contains("200"), "create-bucket status: {status}");

    // A 9 MiB body (over the 8 MiB cap). Use UNSIGNED-PAYLOAD so we don't have to
    // hash the whole thing for the signature; the body is rejected by size before
    // the manifest is ever parsed.
    let big = vec![b'a'; 9 * 1024 * 1024];
    let uuid = "11111111-1111-1111-1111-111111111111";
    let path = format!("/mpbucket/k?uploadId={uuid}");
    let (auth, _extra) = sign(
        "POST",
        "/mpbucket/k",
        &format!("uploadId={uuid}"),
        &host,
        "UNSIGNED-PAYLOAD",
        &amz_date,
    );
    let headers = vec![
        ("Host".into(), host.clone()),
        ("Authorization".into(), auth),
        ("x-amz-content-sha256".into(), "UNSIGNED-PAYLOAD".into()),
        ("x-amz-date".into(), amz_date.clone()),
    ];
    let (status, _h, body) = http_request(port, "POST", &path, &headers, &big);
    // Must NOT be a 200 success and must NOT crash the server; expect 400.
    assert!(
        status.contains("400"),
        "oversized complete body should be rejected (got status: {status}, body: {})",
        String::from_utf8_lossy(&body)
    );
}

//! AWS Signature Version 4 verification (header + presigned).
//!
//! Ported faithfully from the Go `internal/auth/sigv4.go`. Implements:
//!   - `parse_sign_v4` (Authorization header parsing)
//!   - canonical request, string-to-sign, signing-key HMAC chain, hex signature
//!   - constant-time signature comparison
//!   - clock-skew rejection (>15 min)
//!   - presigned query-param verification
//!   - `encode_path` for unicode/special chars
//!
//! The request is represented abstractly via [`SignableRequest`] so this code is
//! transport-agnostic and fully unit-testable without a live HTTP server.
//! coder-2 will adapt hyper requests into a `SignableRequest`.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

use super::credentials::{Credential, CredentialStore};
use super::time as t;

type HmacSha256 = Hmac<Sha256>;

pub const SIGN_V4_ALGORITHM: &str = "AWS4-HMAC-SHA256";
pub const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
pub const UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";
pub const STREAMING_PAYLOAD: &str = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD";
/// Max permitted clock skew, in seconds (15 minutes).
pub const MAX_CLOCK_SKEW_SECS: i64 = 15 * 60;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SigV4Error {
    #[error("missing Authorization header")]
    MissingAuthHeader,
    #[error("unsupported signature version")]
    UnsupportedVersion,
    #[error("malformed auth header: {0}")]
    MalformedAuth(String),
    #[error("missing date header")]
    MissingDate,
    #[error("malformed date")]
    MalformedDate,
    #[error("request time too skewed")]
    Skewed,
    #[error("invalid access key")]
    InvalidAccessKey,
    #[error("signature does not match")]
    SignatureMismatch,
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),
    #[error("missing query param: {0}")]
    MissingQueryParam(&'static str),
    #[error("invalid expires value")]
    InvalidExpires,
    #[error("presigned request expired")]
    Expired,
}

/// Parsed credential scope: `AccessKey/yyyymmdd/region/service/aws4_request`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialHeader {
    pub access_key: String,
    /// `yyyymmdd` date string from the credential scope.
    pub date: String,
    pub region: String,
    pub service: String,
    pub request: String,
}

impl CredentialHeader {
    pub fn scope(&self) -> String {
        format!(
            "{}/{}/{}/{}",
            self.date, self.region, self.service, self.request
        )
    }
}

/// Parsed `Authorization: AWS4-HMAC-SHA256 ...` header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignV4Values {
    pub credential: CredentialHeader,
    pub signed_headers: Vec<String>,
    pub signature: String,
}

/// Outcome of a successful verification.
#[derive(Debug, Clone)]
pub struct AuthResult {
    pub access_key_id: String,
    pub credential: Credential,
    /// The signature we computed (== the seed signature for chunked uploads).
    pub computed_signature: String,
    /// The `yyyymmdd` date used (for chunk-signature chaining if ever needed).
    pub date_yyyymmdd: String,
    pub region: String,
    pub service: String,
}

/// Transport-agnostic view of a request needed for SigV4 verification.
///
/// `headers` keys are case-insensitive on lookup. `query` holds the *decoded*
/// query parameters. `path` is the URI-escaped path (already percent-encoded by
/// the client), matching Go's `r.URL.EscapedPath()`.
pub struct SignableRequest<'a> {
    pub method: &'a str,
    /// Already percent-encoded path (e.g. `/bucket/my%20key`). Use `/` if empty.
    pub escaped_path: &'a str,
    /// Decoded query parameters (name -> values). Multiple values allowed.
    pub query: &'a BTreeMap<String, Vec<String>>,
    /// Lowercased header name -> values.
    pub headers: &'a BTreeMap<String, Vec<String>>,
    /// Host (authority), used for the `host` signed header.
    pub host: &'a str,
}

impl<'a> SignableRequest<'a> {
    fn header(&self, name: &str) -> Option<&str> {
        let lname = name.to_ascii_lowercase();
        self.headers
            .get(&lname)
            .and_then(|v| v.first())
            .map(|s| s.as_str())
    }

    fn query1(&self, name: &str) -> Option<&str> {
        self.query
            .get(name)
            .and_then(|v| v.first())
            .map(|s| s.as_str())
    }

    fn is_presigned(&self) -> bool {
        self.query.contains_key("X-Amz-Algorithm")
    }
}

/// Verify a request's SigV4 signature (dispatches header vs presigned).
///
/// `_region` is intentionally unused: like the Go implementation, we sign with
/// the region taken from the client's own `Credential=` scope rather than
/// enforcing the configured region. Clients commonly hard-sign `us-east-1`
/// regardless of endpoint, so a strict region check would reject legitimate
/// requests. The signature still binds the region (it is part of the signing
/// key), so this is safe — it just doesn't add an extra equality assertion.
pub fn verify_request(
    req: &SignableRequest,
    store: &CredentialStore,
    _region: &str,
    now_unix: i64,
) -> Result<AuthResult, SigV4Error> {
    if req.is_presigned() {
        verify_presigned(req, store, now_unix)
    } else {
        verify_header(req, store, now_unix)
    }
}

fn verify_header(
    req: &SignableRequest,
    store: &CredentialStore,
    now_unix: i64,
) -> Result<AuthResult, SigV4Error> {
    let auth_header = req
        .header("authorization")
        .filter(|s| !s.is_empty())
        .ok_or(SigV4Error::MissingAuthHeader)?;

    let sv = parse_sign_v4(auth_header)?;
    let req_time = parse_request_date(req)?;

    // Clock skew check.
    if (now_unix - req_time).abs() > MAX_CLOCK_SKEW_SECS {
        return Err(SigV4Error::Skewed);
    }

    // B2: AWS requires EVERY `x-amz-*` request header to be signed. If any such
    // header is present but absent from SignedHeaders, an attacker could inject
    // unsigned `x-amz-meta-*` (etc.) that the server would honor. Reject.
    assert_all_amz_headers_signed(req, &sv.signed_headers)?;

    let cred = store
        .lookup(&sv.credential.access_key)
        .ok_or(SigV4Error::InvalidAccessKey)?;

    let hashed_payload = content_sha256(req);
    let canonical = canonical_request_for(req, &sv.signed_headers, &hashed_payload, false);
    let scope = sv.credential.scope();
    let amz_date = req
        .header("x-amz-date")
        .map(|s| s.to_string())
        .unwrap_or_else(|| t::iso8601_from_unix(req_time));
    let string_to_sign = get_string_to_sign(&canonical, &amz_date, &scope);
    let signing_key = get_signing_key(
        &cred.secret_access_key,
        &sv.credential.date,
        &sv.credential.region,
        &sv.credential.service,
    );
    let calculated = get_signature(&signing_key, &string_to_sign);

    if !compare_signatures(&calculated, &sv.signature) {
        return Err(SigV4Error::SignatureMismatch);
    }

    Ok(AuthResult {
        access_key_id: sv.credential.access_key.clone(),
        credential: cred.clone(),
        computed_signature: calculated,
        date_yyyymmdd: sv.credential.date.clone(),
        region: sv.credential.region.clone(),
        service: sv.credential.service.clone(),
    })
}

fn verify_presigned(
    req: &SignableRequest,
    store: &CredentialStore,
    now_unix: i64,
) -> Result<AuthResult, SigV4Error> {
    let algo = req.query1("X-Amz-Algorithm").unwrap_or("");
    if algo != SIGN_V4_ALGORITHM {
        return Err(SigV4Error::UnsupportedAlgorithm(algo.to_string()));
    }

    let date_str = req
        .query1("X-Amz-Date")
        .filter(|s| !s.is_empty())
        .ok_or(SigV4Error::MissingQueryParam("X-Amz-Date"))?;
    let req_time = t::parse_iso8601(date_str).ok_or(SigV4Error::MalformedDate)?;

    // F8: reject a URL dated too far in the FUTURE. The 7-day cap below bounds the
    // window LENGTH but not its START, so without this a far-future `X-Amz-Date`
    // (with any Expires) would be accepted once wall-clock reached it / would pass
    // the `now > req_time + expires` test trivially. Apply the same 15-minute
    // not-before skew the header-auth path uses.
    if req_time - now_unix > MAX_CLOCK_SKEW_SECS {
        return Err(SigV4Error::Skewed);
    }

    let expires_str = req
        .query1("X-Amz-Expires")
        .filter(|s| !s.is_empty())
        .ok_or(SigV4Error::MissingQueryParam("X-Amz-Expires"))?;
    let expires: i64 = expires_str
        .parse()
        .map_err(|_| SigV4Error::InvalidExpires)?;
    if !(0..=604_800).contains(&expires) {
        return Err(SigV4Error::InvalidExpires);
    }
    if now_unix > req_time + expires {
        return Err(SigV4Error::Expired);
    }

    let cred_str = req
        .query1("X-Amz-Credential")
        .ok_or(SigV4Error::MissingQueryParam("X-Amz-Credential"))?;
    let cred_header = parse_credential_value(cred_str)?;

    let cred = store
        .lookup(&cred_header.access_key)
        .ok_or(SigV4Error::InvalidAccessKey)?;

    let signed_headers: Vec<String> = req
        .query1("X-Amz-SignedHeaders")
        .unwrap_or("")
        .split(';')
        .map(|s| s.to_string())
        .collect();

    // B2: presigned requests must also sign every `x-amz-*` request header.
    assert_all_amz_headers_signed(req, &signed_headers)?;

    let provided_sig = req.query1("X-Amz-Signature").unwrap_or("");

    let hashed_payload = req
        .query1("X-Amz-Content-Sha256")
        .filter(|s| !s.is_empty())
        .unwrap_or(UNSIGNED_PAYLOAD)
        .to_string();

    let canonical = canonical_request_for(req, &signed_headers, &hashed_payload, true);
    let scope = cred_header.scope();
    let string_to_sign = get_string_to_sign(&canonical, date_str, &scope);
    let signing_key = get_signing_key(
        &cred.secret_access_key,
        &cred_header.date,
        &cred_header.region,
        &cred_header.service,
    );
    let calculated = get_signature(&signing_key, &string_to_sign);

    if !compare_signatures(&calculated, provided_sig) {
        return Err(SigV4Error::SignatureMismatch);
    }

    Ok(AuthResult {
        access_key_id: cred_header.access_key.clone(),
        credential: cred.clone(),
        computed_signature: calculated,
        date_yyyymmdd: cred_header.date.clone(),
        region: cred_header.region.clone(),
        service: cred_header.service.clone(),
    })
}

/// Parse the `Authorization` header value into its three components.
pub fn parse_sign_v4(v4_auth: &str) -> Result<SignV4Values, SigV4Error> {
    // Match Go: strip ALL spaces, then split on the algorithm prefix.
    let stripped: String = v4_auth.chars().filter(|c| *c != ' ').collect();
    if stripped.is_empty() {
        return Err(SigV4Error::MalformedAuth("empty auth header".into()));
    }
    if !stripped.starts_with(SIGN_V4_ALGORITHM) {
        return Err(SigV4Error::UnsupportedVersion);
    }
    let rest = &stripped[SIGN_V4_ALGORITHM.len()..];
    let fields: Vec<&str> = rest.split(',').collect();
    if fields.len() != 3 {
        return Err(SigV4Error::MalformedAuth(format!(
            "expected 3 fields, got {}",
            fields.len()
        )));
    }

    let credential = parse_credential_field(fields[0])?;
    let signed_headers = parse_signed_headers_field(fields[1])?;
    let signature = parse_signature_field(fields[2])?;

    Ok(SignV4Values {
        credential,
        signed_headers,
        signature,
    })
}

fn parse_credential_field(s: &str) -> Result<CredentialHeader, SigV4Error> {
    let (k, v) = s
        .trim()
        .split_once('=')
        .ok_or_else(|| SigV4Error::MalformedAuth("missing Credential tag".into()))?;
    if k != "Credential" {
        return Err(SigV4Error::MalformedAuth("missing Credential tag".into()));
    }
    parse_credential_value(v)
}

/// Parse `AccessKey/yyyymmdd/region/service/aws4_request`.
pub fn parse_credential_value(s: &str) -> Result<CredentialHeader, SigV4Error> {
    let elems: Vec<&str> = s.trim().split('/').collect();
    if elems.len() != 5 {
        return Err(SigV4Error::MalformedAuth(format!(
            "malformed credential: expected 5 elements, got {}",
            elems.len()
        )));
    }
    // Validate the date is a real yyyymmdd.
    if t::parse_yyyymmdd(elems[1]).is_none() {
        return Err(SigV4Error::MalformedDate);
    }
    Ok(CredentialHeader {
        access_key: elems[0].to_string(),
        date: elems[1].to_string(),
        region: elems[2].to_string(),
        service: elems[3].to_string(),
        request: elems[4].to_string(),
    })
}

fn parse_signed_headers_field(s: &str) -> Result<Vec<String>, SigV4Error> {
    let (k, v) = s
        .trim()
        .split_once('=')
        .ok_or_else(|| SigV4Error::MalformedAuth("missing SignedHeaders tag".into()))?;
    if k != "SignedHeaders" {
        return Err(SigV4Error::MalformedAuth(
            "missing SignedHeaders tag".into(),
        ));
    }
    if v.is_empty() {
        return Err(SigV4Error::MalformedAuth("empty signed headers".into()));
    }
    Ok(v.split(';').map(|s| s.to_string()).collect())
}

fn parse_signature_field(s: &str) -> Result<String, SigV4Error> {
    let (k, v) = s
        .trim()
        .split_once('=')
        .ok_or_else(|| SigV4Error::MalformedAuth("missing Signature tag".into()))?;
    if k != "Signature" {
        return Err(SigV4Error::MalformedAuth("missing Signature tag".into()));
    }
    if v.is_empty() {
        return Err(SigV4Error::MalformedAuth("empty signature".into()));
    }
    Ok(v.to_string())
}

fn parse_request_date(req: &SignableRequest) -> Result<i64, SigV4Error> {
    if let Some(x) = req.header("x-amz-date").filter(|s| !s.is_empty()) {
        return t::parse_iso8601(x).ok_or(SigV4Error::MalformedDate);
    }
    if let Some(d) = req.header("date").filter(|s| !s.is_empty()) {
        return t::parse_http_date(d).ok_or(SigV4Error::MalformedDate);
    }
    Err(SigV4Error::MissingDate)
}

fn content_sha256(req: &SignableRequest) -> String {
    req.header("x-amz-content-sha256")
        .filter(|s| !s.is_empty())
        .unwrap_or(EMPTY_SHA256)
        .to_string()
}

/// Build the canonical request from a [`SignableRequest`] and the signed-header
/// list. For presigned URLs we drop `X-Amz-Signature` from the query string.
fn canonical_request_for(
    req: &SignableRequest,
    signed_headers: &[String],
    hashed_payload: &str,
    presigned: bool,
) -> String {
    let extracted = extract_signed_headers(signed_headers, req);
    let query_str = encode_query(req.query, presigned);
    let url_path = if req.escaped_path.is_empty() {
        "/"
    } else {
        req.escaped_path
    };
    get_canonical_request(req.method, url_path, &query_str, &extracted, hashed_payload)
}

/// B2: assert that every `x-amz-*` header present on the request is included in
/// the client's SignedHeaders set. AWS mandates that all `x-amz-*` headers be
/// signed; an unsigned one (e.g. an injected `x-amz-meta-*`) must be rejected as
/// SignatureDoesNotMatch. Comparison is case-insensitive (header names are
/// already lowercased in the request map; we lowercase the signed list too).
fn assert_all_amz_headers_signed(
    req: &SignableRequest,
    signed_headers: &[String],
) -> Result<(), SigV4Error> {
    let signed_set: std::collections::BTreeSet<String> = signed_headers
        .iter()
        .map(|h| h.to_ascii_lowercase())
        .collect();
    for name in req.headers.keys() {
        // req.headers keys are already lowercased (see router::collect_headers).
        if name.starts_with("x-amz-") && !signed_set.contains(name) {
            return Err(SigV4Error::SignatureMismatch);
        }
    }
    Ok(())
}

/// Extract the values of the signed headers (lowercased name -> values),
/// resolving `host` to the request authority. Matches Go's `extractSignedHeaders`.
fn extract_signed_headers(
    signed_headers: &[String],
    req: &SignableRequest,
) -> BTreeMap<String, Vec<String>> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for h in signed_headers {
        let lh = h.to_ascii_lowercase();
        if lh == "host" {
            out.insert(lh, vec![req.host.to_string()]);
            continue;
        }
        if let Some(vals) = req.headers.get(&lh) {
            out.insert(lh, vals.clone());
        }
    }
    out
}

/// AWS canonical query string: percent-encoded names+values, sorted by key.
/// Our `query` map holds DECODED params; AWS canonicalization requires the
/// values be re-encoded with RFC3986 rules then `+` -> `%20`. We build a sorted
/// `key=value` list using the same escaping AWS expects.
fn encode_query(query: &BTreeMap<String, Vec<String>>, presigned: bool) -> String {
    // BTreeMap already sorts by key. For each key, sort its values (AWS sorts by
    // key then value).
    let mut pairs: Vec<(String, String)> = Vec::new();
    for (k, vals) in query {
        if presigned && k == "X-Amz-Signature" {
            continue;
        }
        let ek = uri_encode(k, true);
        let mut encoded_vals: Vec<String> = vals.iter().map(|v| uri_encode(v, true)).collect();
        encoded_vals.sort();
        for ev in encoded_vals {
            pairs.push((ek.clone(), ev));
        }
    }
    pairs.sort();
    pairs
        .into_iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join("&")
}

/// RFC3986 URI-encode. When `encode_slash` is false, `/` is left intact (used
/// for object paths in some contexts). For query params, `/` IS encoded.
pub fn uri_encode(s: &str, encode_slash: bool) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b'/' if !encode_slash => out.push('/'),
            _ => {
                out.push('%');
                out.push(hex_upper(b >> 4));
                out.push(hex_upper(b & 0xf));
            }
        }
    }
    out
}

fn hex_upper(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        _ => (b'A' + nibble - 10) as char,
    }
}

/// Build the canonical request string (Go `GetCanonicalRequest`). S3 uses
/// `disableDoubleEncoding`, so the path is used as-is. `+` in the query is
/// normalized to `%20`.
pub fn get_canonical_request(
    method: &str,
    url_path: &str,
    query_string: &str,
    signed_headers: &BTreeMap<String, Vec<String>>,
    hashed_payload: &str,
) -> String {
    let raw_query = query_string.replace('+', "%20");
    format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method,
        url_path,
        raw_query,
        canonical_headers(signed_headers),
        signed_headers_list(signed_headers),
        hashed_payload
    )
}

fn canonical_headers(headers: &BTreeMap<String, Vec<String>>) -> String {
    // BTreeMap is already sorted by (lowercased) key.
    let mut buf = String::new();
    for (k, vals) in headers {
        buf.push_str(k);
        buf.push(':');
        let joined = vals
            .iter()
            .map(|v| trim_all(v))
            .collect::<Vec<_>>()
            .join(",");
        buf.push_str(&joined);
        buf.push('\n');
    }
    buf
}

fn signed_headers_list(headers: &BTreeMap<String, Vec<String>>) -> String {
    headers.keys().cloned().collect::<Vec<_>>().join(";")
}

/// Collapse internal whitespace runs to a single space and trim ends
/// (Go's `strings.Join(strings.Fields(s), " ")`).
fn trim_all(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// String-to-sign (Go `GetStringToSign`). `amz_date` is the ISO8601 timestamp.
pub fn get_string_to_sign(canonical_request: &str, amz_date: &str, scope: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(canonical_request.as_bytes());
    let hash = hasher.finalize();
    format!(
        "{}\n{}\n{}\n{}",
        SIGN_V4_ALGORITHM,
        amz_date,
        scope,
        hex::encode(hash)
    )
}

/// Compute the SigV4 signing-key HMAC chain (Go `GetSigningKey`).
pub fn get_signing_key(secret_key: &str, date: &str, region: &str, service: &str) -> Vec<u8> {
    let k_date = hmac_sha256(format!("AWS4{}", secret_key).as_bytes(), date.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    hmac_sha256(&k_service, b"aws4_request")
}

/// Hex-encoded HMAC-SHA256 signature (Go `GetSignature`).
pub fn get_signature(signing_key: &[u8], string_to_sign: &str) -> String {
    hex::encode(hmac_sha256(signing_key, string_to_sign.as_bytes()))
}

/// Constant-time signature comparison (Go `CompareSignatures`).
pub fn compare_signatures(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Build the credential scope string (Go `GetScope`).
pub fn get_scope(date_yyyymmdd: &str, region: &str, service: &str) -> String {
    format!("{}/{}/{}/aws4_request", date_yyyymmdd, region, service)
}

pub(crate) fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// SigV4 path encoding (Go `EncodePath`). Reserved set `[A-Za-z0-9-_.~/]` passes
/// through; everything else is UTF-8 percent-encoded with uppercase hex.
pub fn encode_path(path_name: &str) -> String {
    if path_name.bytes().all(
        |b| matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/'),
    ) && !path_name.is_empty()
    {
        return path_name.to_string();
    }
    let mut out = String::with_capacity(path_name.len() * 3);
    for ch in path_name.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '~' | '/') {
            out.push(ch);
        } else {
            let mut buf = [0u8; 4];
            for b in ch.encode_utf8(&mut buf).bytes() {
                out.push('%');
                out.push(hex_upper(b >> 4));
                out.push(hex_upper(b & 0xf));
            }
        }
    }
    out
}

/// Hex-encoded SHA256 of `data`.
pub fn hash_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> BTreeMap<String, Vec<String>> {
        let mut m = BTreeMap::new();
        for (k, v) in pairs {
            m.entry(k.to_ascii_lowercase())
                .or_insert_with(Vec::new)
                .push(v.to_string());
        }
        m
    }

    #[test]
    fn signing_key_length() {
        let key = get_signing_key(
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "20130524",
            "us-east-1",
            "s3",
        );
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn signature_hex_length() {
        let key = get_signing_key(
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "20130524",
            "us-east-1",
            "s3",
        );
        let sig = get_signature(&key, "test string to sign");
        assert_eq!(sig.len(), 64);
    }

    /// Known signing-key HMAC-chain vector. Inputs are the canonical AWS example
    /// (secret `wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY`, `20120215`,
    /// `us-east-1`, `iam`). The expected `kSigning` hex was cross-verified
    /// against an independent reference HMAC implementation, authoritatively
    /// pinning `get_signing_key`.
    #[test]
    fn known_signing_key_vector() {
        let key = get_signing_key(
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "20120215",
            "us-east-1",
            "iam",
        );
        let expected =
            hex::decode("f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d")
                .unwrap();
        assert_eq!(key, expected);
    }

    /// End-to-end determinism vector: a fixed request must yield a fixed
    /// signature. This pins canonical-request -> string-to-sign -> signing key
    /// -> signature so any regression in the chain is caught. The value was
    /// computed by this implementation and cross-checked structurally below.
    #[test]
    fn deterministic_signature_vector() {
        let secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
        let (date, region, service, amz_date) = ("20130524", "us-east-1", "s3", "20130524T000000Z");

        let mut h = BTreeMap::new();
        h.insert(
            "host".to_string(),
            vec!["examplebucket.s3.amazonaws.com".to_string()],
        );
        h.insert(
            "x-amz-content-sha256".to_string(),
            vec![EMPTY_SHA256.into()],
        );
        h.insert("x-amz-date".to_string(), vec![amz_date.to_string()]);

        let canonical = get_canonical_request("GET", "/test.txt", "", &h, EMPTY_SHA256);
        let cr_hash = hash_sha256(canonical.as_bytes());
        let scope = get_scope(date, region, service);
        let sts = get_string_to_sign(&canonical, amz_date, &scope);
        // string-to-sign embeds the canonical-request hash.
        assert!(sts.contains(&cr_hash));

        let key = get_signing_key(secret, date, region, service);
        let sig = get_signature(&key, &sts);
        assert_eq!(
            sig,
            "14f6a0997b2b70a86f4726658a6575b5109092ccb5fd328f51b369c44b4ac958"
        );
    }

    #[test]
    fn compare_constant_time() {
        assert!(compare_signatures("abc123", "abc123"));
        assert!(!compare_signatures("abc123", "abc124"));
        assert!(!compare_signatures("abc123", "abc12"));
    }

    #[test]
    fn parse_valid_auth_header() {
        let header = "AWS4-HMAC-SHA256 Credential=AKID/20240101/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let sv = parse_sign_v4(header).unwrap();
        assert_eq!(sv.credential.access_key, "AKID");
        assert_eq!(sv.credential.region, "us-east-1");
        assert_eq!(sv.credential.service, "s3");
        assert_eq!(sv.signed_headers.len(), 2);
        assert_eq!(
            sv.signature,
            "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        );
    }

    #[test]
    fn parse_malformed_auth() {
        for h in [
            "",
            "Basic abc",
            "AWS4-HMAC-SHA256",
            "AWS4-HMAC-SHA256 Credential=bad",
            "AWS4-HMAC-SHA256 Credential=a/b/c, SignedHeaders=host, Signature=abc",
        ] {
            assert!(parse_sign_v4(h).is_err(), "should reject: {h:?}");
        }
    }

    #[test]
    fn parse_credential_value_ok() {
        let c = parse_credential_value("AKID/20240315/eu-west-1/s3/aws4_request").unwrap();
        assert_eq!(c.access_key, "AKID");
        assert_eq!(c.region, "eu-west-1");
    }

    #[test]
    fn encode_path_simple() {
        assert_eq!(encode_path("/bucket/key"), "/bucket/key");
    }

    #[test]
    fn encode_path_space() {
        assert!(encode_path("/bucket/hello world").contains("%20"));
    }

    #[test]
    fn encode_path_unicode() {
        let got = encode_path("/bucket/日本語");
        assert_ne!(got, "/bucket/日本語");
        assert!(got.contains('%'));
    }

    #[test]
    fn canonical_request_shape() {
        let h = headers(&[
            ("host", "examplebucket.s3.amazonaws.com"),
            ("x-amz-date", "20130524T000000Z"),
        ]);
        let cr = get_canonical_request("GET", "/test.txt", "", &h, EMPTY_SHA256);
        assert!(cr.starts_with("GET\n/test.txt\n"));
        assert!(cr.ends_with(EMPTY_SHA256));
        assert!(cr.contains("host:"));
    }

    #[test]
    fn string_to_sign_shape() {
        let sts = get_string_to_sign(
            "canonical-request",
            "20130524T000000Z",
            "20130524/us-east-1/s3/aws4_request",
        );
        assert!(sts.starts_with(SIGN_V4_ALGORITHM));
        assert_eq!(sts.split('\n').count(), 4);
    }

    #[test]
    fn get_scope_format() {
        assert_eq!(
            get_scope("20240101", "us-east-1", "s3"),
            "20240101/us-east-1/s3/aws4_request"
        );
    }

    fn build_signed_request(
        store: &CredentialStore,
        access: &str,
        secret: &str,
        region: &str,
        now_unix: i64,
    ) -> (BTreeMap<String, Vec<String>>, BTreeMap<String, Vec<String>>) {
        let service = "s3";
        let amz_date = t::iso8601_from_unix(now_unix);
        let yyyymmdd = &amz_date[..8];

        let mut h = BTreeMap::new();
        h.insert("host".into(), vec!["localhost:8333".into()]);
        h.insert("x-amz-date".into(), vec![amz_date.clone()]);
        h.insert("x-amz-content-sha256".into(), vec![EMPTY_SHA256.into()]);

        let signed_headers = vec![
            "host".to_string(),
            "x-amz-content-sha256".to_string(),
            "x-amz-date".to_string(),
        ];
        let extracted = {
            let req = SignableRequest {
                method: "GET",
                escaped_path: "/test-bucket",
                query: &BTreeMap::new(),
                headers: &h,
                host: "localhost:8333",
            };
            extract_signed_headers(&signed_headers, &req)
        };
        let canonical = get_canonical_request("GET", "/test-bucket", "", &extracted, EMPTY_SHA256);
        let scope = get_scope(yyyymmdd, region, service);
        let sts = get_string_to_sign(&canonical, &amz_date, &scope);
        let key = get_signing_key(secret, yyyymmdd, region, service);
        let sig = get_signature(&key, &sts);

        let cred_str = format!(
            "{}/{}/{}/{}/aws4_request",
            access, yyyymmdd, region, service
        );
        let auth = format!(
            "{} Credential={}, SignedHeaders={}, Signature={}",
            SIGN_V4_ALGORITHM,
            cred_str,
            signed_headers.join(";"),
            sig
        );
        h.insert("authorization".into(), vec![auth]);
        let _ = store;
        (h, BTreeMap::new())
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let store = CredentialStore::from_json(
            br#"{"credentials":[{"accessKeyId":"test-access-key","secretAccessKey":"test-secret-key"}]}"#,
        )
        .unwrap();
        let now = 1_700_000_000;
        let (h, q) = build_signed_request(
            &store,
            "test-access-key",
            "test-secret-key",
            "us-east-1",
            now,
        );
        let req = SignableRequest {
            method: "GET",
            escaped_path: "/test-bucket",
            query: &q,
            headers: &h,
            host: "localhost:8333",
        };
        let res = verify_request(&req, &store, "us-east-1", now).unwrap();
        assert_eq!(res.access_key_id, "test-access-key");
    }

    #[test]
    fn clock_skew_rejected() {
        let store = CredentialStore::from_json(
            br#"{"credentials":[{"accessKeyId":"AKID","secretAccessKey":"SECRET"}]}"#,
        )
        .unwrap();
        let sign_time = 1_700_000_000;
        let (h, q) = build_signed_request(&store, "AKID", "SECRET", "us-east-1", sign_time);
        let req = SignableRequest {
            method: "GET",
            escaped_path: "/test-bucket",
            query: &q,
            headers: &h,
            host: "localhost:8333",
        };
        // verify "now" 20 minutes later than the request time.
        let now = sign_time + 20 * 60;
        let err = verify_request(&req, &store, "us-east-1", now).unwrap_err();
        assert_eq!(err, SigV4Error::Skewed);
    }

    #[test]
    fn invalid_access_key_rejected() {
        let store = CredentialStore::from_json(
            br#"{"credentials":[{"accessKeyId":"AKID","secretAccessKey":"SECRET"}]}"#,
        )
        .unwrap();
        let now = 1_700_000_000;
        let amz_date = t::iso8601_from_unix(now);
        let mut h = BTreeMap::new();
        h.insert("host".into(), vec!["localhost:8333".into()]);
        h.insert("x-amz-date".into(), vec![amz_date.clone()]);
        h.insert("x-amz-content-sha256".into(), vec![EMPTY_SHA256.into()]);
        let cred_str = format!("WRONG-KEY/{}/us-east-1/s3/aws4_request", &amz_date[..8]);
        h.insert(
            "authorization".into(),
            vec![format!(
                "{} Credential={}, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=0000000000000000000000000000000000000000000000000000000000000000",
                SIGN_V4_ALGORITHM, cred_str
            )],
        );
        let q = BTreeMap::new();
        let req = SignableRequest {
            method: "GET",
            escaped_path: "/bucket",
            query: &q,
            headers: &h,
            host: "localhost:8333",
        };
        let err = verify_request(&req, &store, "us-east-1", now).unwrap_err();
        assert_eq!(err, SigV4Error::InvalidAccessKey);
    }

    #[test]
    fn invalid_signature_rejected() {
        let store = CredentialStore::from_json(
            br#"{"credentials":[{"accessKeyId":"AKID","secretAccessKey":"SECRET"}]}"#,
        )
        .unwrap();
        let now = 1_700_000_000;
        let amz_date = t::iso8601_from_unix(now);
        let mut h = BTreeMap::new();
        h.insert("host".into(), vec!["localhost:8333".into()]);
        h.insert("x-amz-date".into(), vec![amz_date.clone()]);
        h.insert("x-amz-content-sha256".into(), vec![EMPTY_SHA256.into()]);
        let cred_str = format!("AKID/{}/us-east-1/s3/aws4_request", &amz_date[..8]);
        h.insert(
            "authorization".into(),
            vec![format!(
                "{} Credential={}, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=badbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadb",
                SIGN_V4_ALGORITHM, cred_str
            )],
        );
        let q = BTreeMap::new();
        let req = SignableRequest {
            method: "GET",
            escaped_path: "/bucket",
            query: &q,
            headers: &h,
            host: "localhost:8333",
        };
        let err = verify_request(&req, &store, "us-east-1", now).unwrap_err();
        assert_eq!(err, SigV4Error::SignatureMismatch);
    }

    #[test]
    fn presigned_round_trip() {
        let store = CredentialStore::from_json(
            br#"{"credentials":[{"accessKeyId":"AKID","secretAccessKey":"SECRET"}]}"#,
        )
        .unwrap();
        let now = 1_700_000_000;
        let amz_date = t::iso8601_from_unix(now);
        let yyyymmdd = &amz_date[..8];
        let region = "us-east-1";
        let service = "s3";

        // Build query params for a presigned GET.
        let mut q: BTreeMap<String, Vec<String>> = BTreeMap::new();
        q.insert("X-Amz-Algorithm".into(), vec![SIGN_V4_ALGORITHM.into()]);
        q.insert(
            "X-Amz-Credential".into(),
            vec![format!(
                "AKID/{}/{}/{}/aws4_request",
                yyyymmdd, region, service
            )],
        );
        q.insert("X-Amz-Date".into(), vec![amz_date.clone()]);
        q.insert("X-Amz-Expires".into(), vec!["3600".into()]);
        q.insert("X-Amz-SignedHeaders".into(), vec!["host".into()]);

        let mut h = BTreeMap::new();
        h.insert("host".into(), vec!["localhost:8333".into()]);

        let req_for_sign = SignableRequest {
            method: "GET",
            escaped_path: "/bucket/key",
            query: &q,
            headers: &h,
            host: "localhost:8333",
        };
        let extracted = extract_signed_headers(&["host".to_string()], &req_for_sign);
        let canonical = get_canonical_request(
            "GET",
            "/bucket/key",
            &encode_query(&q, true),
            &extracted,
            UNSIGNED_PAYLOAD,
        );
        let scope = get_scope(yyyymmdd, region, service);
        let sts = get_string_to_sign(&canonical, &amz_date, &scope);
        let key = get_signing_key("SECRET", yyyymmdd, region, service);
        let sig = get_signature(&key, &sts);
        q.insert("X-Amz-Signature".into(), vec![sig]);

        let req = SignableRequest {
            method: "GET",
            escaped_path: "/bucket/key",
            query: &q,
            headers: &h,
            host: "localhost:8333",
        };
        let res = verify_request(&req, &store, region, now).unwrap();
        assert_eq!(res.access_key_id, "AKID");
    }

    #[test]
    fn presigned_expired_rejected() {
        let store = CredentialStore::from_json(
            br#"{"credentials":[{"accessKeyId":"AKID","secretAccessKey":"SECRET"}]}"#,
        )
        .unwrap();
        let sign_time = 1_700_000_000;
        let amz_date = t::iso8601_from_unix(sign_time);
        let yyyymmdd = &amz_date[..8];
        let mut q: BTreeMap<String, Vec<String>> = BTreeMap::new();
        q.insert("X-Amz-Algorithm".into(), vec![SIGN_V4_ALGORITHM.into()]);
        q.insert(
            "X-Amz-Credential".into(),
            vec![format!("AKID/{}/us-east-1/s3/aws4_request", yyyymmdd)],
        );
        q.insert("X-Amz-Date".into(), vec![amz_date]);
        q.insert("X-Amz-Expires".into(), vec!["60".into()]);
        q.insert("X-Amz-SignedHeaders".into(), vec!["host".into()]);
        q.insert("X-Amz-Signature".into(), vec!["deadbeef".into()]);
        let mut h = BTreeMap::new();
        h.insert("host".into(), vec!["localhost:8333".into()]);
        let req = SignableRequest {
            method: "GET",
            escaped_path: "/bucket/key",
            query: &q,
            headers: &h,
            host: "localhost:8333",
        };
        // now is well past expiry.
        let err = verify_request(&req, &store, "us-east-1", sign_time + 3600).unwrap_err();
        assert_eq!(err, SigV4Error::Expired);
    }

    #[test]
    fn presigned_future_dated_rejected() {
        // F8 regression: a presigned URL dated far in the FUTURE must be rejected
        // (not-before / future-skew check), even though the 7-day Expires cap is
        // satisfied. We sign at a far-future time but verify with `now` ~today.
        let store = CredentialStore::from_json(
            br#"{"credentials":[{"accessKeyId":"AKID","secretAccessKey":"SECRET"}]}"#,
        )
        .unwrap();
        let now = 1_700_000_000;
        // Sign for a time 10 days in the future (well beyond the 15-min skew).
        let future = now + 10 * 86_400;
        let amz_date = t::iso8601_from_unix(future);
        let yyyymmdd = &amz_date[..8];
        let region = "us-east-1";
        let service = "s3";

        let mut q: BTreeMap<String, Vec<String>> = BTreeMap::new();
        q.insert("X-Amz-Algorithm".into(), vec![SIGN_V4_ALGORITHM.into()]);
        q.insert(
            "X-Amz-Credential".into(),
            vec![format!(
                "AKID/{}/{}/{}/aws4_request",
                yyyymmdd, region, service
            )],
        );
        q.insert("X-Amz-Date".into(), vec![amz_date.clone()]);
        q.insert("X-Amz-Expires".into(), vec!["3600".into()]);
        q.insert("X-Amz-SignedHeaders".into(), vec!["host".into()]);

        let mut h = BTreeMap::new();
        h.insert("host".into(), vec!["localhost:8333".into()]);

        // Compute a VALID signature so the rejection is due to the date, not a
        // signature mismatch (proves the future-date guard runs first).
        let req_for_sign = SignableRequest {
            method: "GET",
            escaped_path: "/bucket/key",
            query: &q,
            headers: &h,
            host: "localhost:8333",
        };
        let extracted = extract_signed_headers(&["host".to_string()], &req_for_sign);
        let canonical = get_canonical_request(
            "GET",
            "/bucket/key",
            &encode_query(&q, true),
            &extracted,
            UNSIGNED_PAYLOAD,
        );
        let scope = get_scope(yyyymmdd, region, service);
        let sts = get_string_to_sign(&canonical, &amz_date, &scope);
        let key = get_signing_key("SECRET", yyyymmdd, region, service);
        let sig = get_signature(&key, &sts);
        q.insert("X-Amz-Signature".into(), vec![sig]);

        let req = SignableRequest {
            method: "GET",
            escaped_path: "/bucket/key",
            query: &q,
            headers: &h,
            host: "localhost:8333",
        };
        let err = verify_request(&req, &store, region, now).unwrap_err();
        assert_eq!(err, SigV4Error::Skewed);
    }

    /// B2 helper: build a header-auth PUT that signs exactly `signed_header_names`
    /// over the header map `h`. Inserts the computed `authorization` into `h`.
    fn sign_header_request_with(
        secret: &str,
        access: &str,
        region: &str,
        now_unix: i64,
        h: &mut BTreeMap<String, Vec<String>>,
        signed_header_names: &[&str],
    ) {
        let service = "s3";
        let yyyymmdd = {
            let d = t::iso8601_from_unix(now_unix);
            d[..8].to_string()
        };
        let amz_date = h.get("x-amz-date").unwrap()[0].clone();
        let signed: Vec<String> = signed_header_names.iter().map(|s| s.to_string()).collect();
        let req = SignableRequest {
            method: "PUT",
            escaped_path: "/bucket/key",
            query: &BTreeMap::new(),
            headers: h,
            host: "localhost:8333",
        };
        let extracted = extract_signed_headers(&signed, &req);
        let canonical =
            get_canonical_request("PUT", "/bucket/key", "", &extracted, UNSIGNED_PAYLOAD);
        let scope = get_scope(&yyyymmdd, region, service);
        let sts = get_string_to_sign(&canonical, &amz_date, &scope);
        let key = get_signing_key(secret, &yyyymmdd, region, service);
        let sig = get_signature(&key, &sts);
        let cred_str = format!(
            "{}/{}/{}/{}/aws4_request",
            access, yyyymmdd, region, service
        );
        let auth = format!(
            "{} Credential={}, SignedHeaders={}, Signature={}",
            SIGN_V4_ALGORITHM,
            cred_str,
            signed.join(";"),
            sig
        );
        h.insert("authorization".into(), vec![auth]);
    }

    #[test]
    fn unsigned_amz_header_rejected() {
        // B2: a request with a VALID signature but an extra UNSIGNED `x-amz-meta-*`
        // header must be rejected (SignatureDoesNotMatch). Mutation evidence:
        // remove the `assert_all_amz_headers_signed` call in `verify_header` and
        // this test fails (the unsigned header would be honored).
        let store = CredentialStore::from_json(
            br#"{"credentials":[{"accessKeyId":"AKID","secretAccessKey":"SECRET"}]}"#,
        )
        .unwrap();
        let now = 1_700_000_000;
        let amz_date = t::iso8601_from_unix(now);
        let mut h = BTreeMap::new();
        h.insert("host".into(), vec!["localhost:8333".into()]);
        h.insert("x-amz-date".into(), vec![amz_date]);
        h.insert("x-amz-content-sha256".into(), vec![UNSIGNED_PAYLOAD.into()]);
        // Sign WITHOUT x-amz-meta-foo.
        sign_header_request_with(
            "SECRET",
            "AKID",
            "us-east-1",
            now,
            &mut h,
            &["host", "x-amz-content-sha256", "x-amz-date"],
        );
        // Inject an UNSIGNED x-amz-meta-* header AFTER signing.
        h.insert("x-amz-meta-foo".into(), vec!["evil".into()]);

        let q = BTreeMap::new();
        let req = SignableRequest {
            method: "PUT",
            escaped_path: "/bucket/key",
            query: &q,
            headers: &h,
            host: "localhost:8333",
        };
        let err = verify_request(&req, &store, "us-east-1", now).unwrap_err();
        assert_eq!(err, SigV4Error::SignatureMismatch);
    }

    #[test]
    fn correctly_signed_amz_header_accepted() {
        // B2 (positive): when the same `x-amz-meta-foo` header IS in SignedHeaders
        // (and signed), the request succeeds.
        let store = CredentialStore::from_json(
            br#"{"credentials":[{"accessKeyId":"AKID","secretAccessKey":"SECRET"}]}"#,
        )
        .unwrap();
        let now = 1_700_000_000;
        let amz_date = t::iso8601_from_unix(now);
        let mut h = BTreeMap::new();
        h.insert("host".into(), vec!["localhost:8333".into()]);
        h.insert("x-amz-date".into(), vec![amz_date]);
        h.insert("x-amz-content-sha256".into(), vec![UNSIGNED_PAYLOAD.into()]);
        h.insert("x-amz-meta-foo".into(), vec!["good".into()]);
        // Sign INCLUDING x-amz-meta-foo.
        sign_header_request_with(
            "SECRET",
            "AKID",
            "us-east-1",
            now,
            &mut h,
            &[
                "host",
                "x-amz-content-sha256",
                "x-amz-date",
                "x-amz-meta-foo",
            ],
        );
        let q = BTreeMap::new();
        let req = SignableRequest {
            method: "PUT",
            escaped_path: "/bucket/key",
            query: &q,
            headers: &h,
            host: "localhost:8333",
        };
        let res = verify_request(&req, &store, "us-east-1", now).unwrap();
        assert_eq!(res.access_key_id, "AKID");
    }

    /// B2 helper: build a presigned GET that signs exactly `signed_header_names`
    /// over the header map `h`, computing a VALID `X-Amz-Signature`. Returns the
    /// query map ready to verify; `h` is left holding only the request headers.
    fn presign_request_with(
        secret: &str,
        access: &str,
        region: &str,
        now_unix: i64,
        h: &BTreeMap<String, Vec<String>>,
        signed_header_names: &[&str],
    ) -> BTreeMap<String, Vec<String>> {
        let service = "s3";
        let amz_date = t::iso8601_from_unix(now_unix);
        let yyyymmdd = amz_date[..8].to_string();
        let mut q: BTreeMap<String, Vec<String>> = BTreeMap::new();
        q.insert("X-Amz-Algorithm".into(), vec![SIGN_V4_ALGORITHM.into()]);
        q.insert(
            "X-Amz-Credential".into(),
            vec![format!(
                "{}/{}/{}/{}/aws4_request",
                access, yyyymmdd, region, service
            )],
        );
        q.insert("X-Amz-Date".into(), vec![amz_date.clone()]);
        q.insert("X-Amz-Expires".into(), vec!["3600".into()]);
        let signed: Vec<String> = signed_header_names.iter().map(|s| s.to_string()).collect();
        q.insert("X-Amz-SignedHeaders".into(), vec![signed.join(";")]);

        // Build the canonical request over ONLY the signed headers, mirroring
        // verify_presigned (which uses the presigned=true query-canonicalization).
        let req = SignableRequest {
            method: "GET",
            escaped_path: "/bucket/key",
            query: &q,
            headers: h,
            host: "localhost:8333",
        };
        let extracted = extract_signed_headers(&signed, &req);
        let canonical = get_canonical_request(
            "GET",
            "/bucket/key",
            &encode_query(&q, true),
            &extracted,
            UNSIGNED_PAYLOAD,
        );
        let scope = get_scope(&yyyymmdd, region, service);
        let sts = get_string_to_sign(&canonical, &amz_date, &scope);
        let key = get_signing_key(secret, &yyyymmdd, region, service);
        let sig = get_signature(&key, &sts);
        q.insert("X-Amz-Signature".into(), vec![sig]);
        q
    }

    #[test]
    fn presigned_unsigned_amz_header_rejected() {
        // B2 (discriminating): a presigned URL with a VALID signature whose
        // SignedHeaders OMITS a present `x-amz-meta-*` header must be rejected
        // (SignatureDoesNotMatch). The signature is genuinely valid for the
        // canonical request WITHOUT the meta header, so the rejection can only
        // come from `assert_all_amz_headers_signed` — not a signature mismatch.
        // Mutation evidence: neuter that call in `verify_presigned` and this test
        // FAILS (the request would verify successfully).
        let store = CredentialStore::from_json(
            br#"{"credentials":[{"accessKeyId":"AKID","secretAccessKey":"SECRET"}]}"#,
        )
        .unwrap();
        let now = 1_700_000_000;
        let region = "us-east-1";
        let mut h = BTreeMap::new();
        h.insert("host".into(), vec!["localhost:8333".into()]);
        // Sign over host ONLY (the meta header is deliberately not signed).
        let q = presign_request_with("SECRET", "AKID", region, now, &h, &["host"]);
        // Inject an UNSIGNED x-amz-meta-* header AFTER signing.
        h.insert("x-amz-meta-foo".into(), vec!["evil".into()]);

        let req = SignableRequest {
            method: "GET",
            escaped_path: "/bucket/key",
            query: &q,
            headers: &h,
            host: "localhost:8333",
        };
        let err = verify_request(&req, &store, region, now).unwrap_err();
        assert_eq!(err, SigV4Error::SignatureMismatch);
    }

    #[test]
    fn presigned_signed_amz_header_accepted() {
        // B2 (positive, presigned): when the same `x-amz-meta-foo` header IS in
        // SignedHeaders (and signed), the presigned request succeeds. Paired with
        // `presigned_unsigned_amz_header_rejected` this proves the check
        // discriminates on whether the header is covered, not on signature alone.
        let store = CredentialStore::from_json(
            br#"{"credentials":[{"accessKeyId":"AKID","secretAccessKey":"SECRET"}]}"#,
        )
        .unwrap();
        let now = 1_700_000_000;
        let region = "us-east-1";
        let mut h = BTreeMap::new();
        h.insert("host".into(), vec!["localhost:8333".into()]);
        h.insert("x-amz-meta-foo".into(), vec!["good".into()]);
        // Sign INCLUDING x-amz-meta-foo.
        let q = presign_request_with(
            "SECRET",
            "AKID",
            region,
            now,
            &h,
            &["host", "x-amz-meta-foo"],
        );

        let req = SignableRequest {
            method: "GET",
            escaped_path: "/bucket/key",
            query: &q,
            headers: &h,
            host: "localhost:8333",
        };
        let res = verify_request(&req, &store, region, now).unwrap();
        assert_eq!(res.access_key_id, "AKID");
    }
}

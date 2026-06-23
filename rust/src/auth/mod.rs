//! Authentication: credentials, SigV4 verification, chunked payload de-framing.

pub mod chunked_reader;
pub mod credentials;
pub mod sigv4;
pub mod time;

pub use chunked_reader::{get_chunk_signature, ChunkedReader};
pub use credentials::{Credential, CredentialError, CredentialStore};
pub use sigv4::{
    compare_signatures, encode_path, get_canonical_request, get_scope, get_signature,
    get_signing_key, get_string_to_sign, hash_sha256, parse_credential_value, parse_sign_v4,
    verify_request, AuthResult, CredentialHeader, SigV4Error, SignV4Values, SignableRequest,
    EMPTY_SHA256, MAX_CLOCK_SKEW_SECS, SIGN_V4_ALGORITHM, STREAMING_PAYLOAD, UNSIGNED_PAYLOAD,
};

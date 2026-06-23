//! Static credential loading from JSON.
//!
//! Ported from the Go `internal/auth/credentials.go`. Format:
//! `{"credentials":[{"accessKeyId":"...","secretAccessKey":"..."}]}`.

use std::collections::HashMap;
use std::path::Path;

use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CredentialError {
    #[error("read credentials file: {0}")]
    Read(#[from] std::io::Error),
    #[error("parse credentials: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("no credentials configured")]
    Empty,
    #[error("credential missing accessKeyId or secretAccessKey")]
    MissingFields,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Credential {
    #[serde(rename = "accessKeyId")]
    pub access_key_id: String,
    #[serde(rename = "secretAccessKey")]
    pub secret_access_key: String,
}

#[derive(Debug, Deserialize)]
struct CredentialsConfig {
    #[serde(default)]
    credentials: Vec<Credential>,
}

/// Immutable, lookup-by-access-key credential store.
#[derive(Debug, Clone, Default)]
pub struct CredentialStore {
    creds: HashMap<String, Credential>,
}

impl CredentialStore {
    /// Build a store directly from parsed JSON bytes (used by tests + file load).
    pub fn from_json(data: &[u8]) -> Result<Self, CredentialError> {
        let cfg: CredentialsConfig = serde_json::from_slice(data)?;
        if cfg.credentials.is_empty() {
            return Err(CredentialError::Empty);
        }
        let mut creds = HashMap::with_capacity(cfg.credentials.len());
        for c in cfg.credentials {
            if c.access_key_id.is_empty() || c.secret_access_key.is_empty() {
                return Err(CredentialError::MissingFields);
            }
            creds.insert(c.access_key_id.clone(), c);
        }
        Ok(CredentialStore { creds })
    }

    /// Load credentials from a JSON file on disk.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, CredentialError> {
        let data = std::fs::read(path)?;
        Self::from_json(&data)
    }

    /// Look up a credential by access key id.
    pub fn lookup(&self, access_key_id: &str) -> Option<&Credential> {
        self.creds.get(access_key_id)
    }

    pub fn len(&self) -> usize {
        self.creds.len()
    }

    pub fn is_empty(&self) -> bool {
        self.creds.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_valid() {
        let json = br#"{"credentials":[{"accessKeyId":"AK","secretAccessKey":"SK"}]}"#;
        let store = CredentialStore::from_json(json).unwrap();
        assert_eq!(store.len(), 1);
        let c = store.lookup("AK").unwrap();
        assert_eq!(c.secret_access_key, "SK");
    }

    #[test]
    fn load_multiple() {
        let json = br#"{"credentials":[
            {"accessKeyId":"A1","secretAccessKey":"S1"},
            {"accessKeyId":"A2","secretAccessKey":"S2"}
        ]}"#;
        let store = CredentialStore::from_json(json).unwrap();
        assert_eq!(store.len(), 2);
        assert_eq!(store.lookup("A2").unwrap().secret_access_key, "S2");
    }

    #[test]
    fn empty_config_errors() {
        let json = br#"{"credentials":[]}"#;
        assert!(matches!(
            CredentialStore::from_json(json),
            Err(CredentialError::Empty)
        ));
    }

    #[test]
    fn missing_fields_errors() {
        let json = br#"{"credentials":[{"accessKeyId":"AK","secretAccessKey":""}]}"#;
        assert!(matches!(
            CredentialStore::from_json(json),
            Err(CredentialError::MissingFields)
        ));
    }

    #[test]
    fn lookup_not_found() {
        let json = br#"{"credentials":[{"accessKeyId":"AK","secretAccessKey":"SK"}]}"#;
        let store = CredentialStore::from_json(json).unwrap();
        assert!(store.lookup("nope").is_none());
    }

    #[test]
    fn load_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("creds.json");
        std::fs::write(
            &path,
            br#"{"credentials":[{"accessKeyId":"FK","secretAccessKey":"FS"}]}"#,
        )
        .unwrap();
        let store = CredentialStore::load(&path).unwrap();
        assert_eq!(store.lookup("FK").unwrap().secret_access_key, "FS");
    }

    #[test]
    fn malformed_json_errors() {
        let json = br#"{not json"#;
        assert!(matches!(
            CredentialStore::from_json(json),
            Err(CredentialError::Parse(_))
        ));
    }
}

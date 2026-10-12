// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! Bounded server transaction records; no backend, identity, grant or code issuance.

use super::authorization::{
    MAX_AUTHORIZATION_QUERY_BYTES, ValidatedAuthorizationRequest, validate_authorization_request,
};
use crate::config::OAuthConfig;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

pub const MAX_TRANSACTION_BYTES: usize = 16 * 1024;

/// Store-provided source witness. No public constructor, Clone, Debug or deserialization.
pub struct BoundAuthorizationTransaction {
    transaction: AuthorizationTransaction,
    transaction_id_hash: [u8; 32],
}
impl BoundAuthorizationTransaction {
    pub(super) fn from_store(
        transaction: AuthorizationTransaction,
        transaction_id_hash: [u8; 32],
    ) -> Self {
        Self {
            transaction,
            transaction_id_hash,
        }
    }
    pub fn transaction(&self) -> &AuthorizationTransaction {
        &self.transaction
    }
    pub(super) fn into_parts(self) -> (AuthorizationTransaction, [u8; 32]) {
        (self.transaction, self.transaction_id_hash)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordError {
    TooLarge,
    InvalidRecord,
    UnsupportedVersion,
    InvalidTime,
    Expired,
}

/// Owned validated input, not authentication/consent proof. No Debug or public Deserialize.
pub struct AuthorizationTransaction {
    request: ValidatedAuthorizationRequest,
    browser_binding: [u8; 32],
    expires_at_ms: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransactionDto {
    version: u8,
    client_id: String,
    redirect_uri: String,
    resource: String,
    scopes: Vec<String>,
    state: Option<String>,
    pkce_challenge: [u8; 32],
    browser_binding: [u8; 32],
    expires_at_ms: u64,
}

impl TransactionDto {
    /// Validated cache fields are reconstructed as known parameters, never parser extensions.
    fn query(&self) -> String {
        let scope = self.scopes.join(" ");
        let challenge = URL_SAFE_NO_PAD.encode(self.pkce_challenge);
        let mut form = url::form_urlencoded::Serializer::new(String::new());
        form.extend_pairs([
            ("client_id", self.client_id.as_str()),
            ("redirect_uri", self.redirect_uri.as_str()),
            ("response_type", "code"),
            ("resource", self.resource.as_str()),
            ("scope", &scope),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
        ]);
        if let Some(state) = &self.state {
            form.append_pair("state", state);
        }
        form.finish()
    }
}

pub(super) fn valid_time(ms: u64) -> bool {
    ms <= 253402300799999
        && i64::try_from(ms)
            .ok()
            .and_then(DateTime::<Utc>::from_timestamp_millis)
            .is_some()
}

impl AuthorizationTransaction {
    /// Binding is a hash, not a raw browser cookie. Expiry is computed by the trusted server.
    pub fn new(
        request: ValidatedAuthorizationRequest,
        browser_binding: [u8; 32],
        expires_at_ms: u64,
    ) -> Result<Self, RecordError> {
        if expires_at_ms == 0 || !valid_time(expires_at_ms) {
            return Err(RecordError::InvalidTime);
        }
        let record = Self {
            request,
            browser_binding,
            expires_at_ms,
        };
        // Only records that fit the codec and canonical request gate may be persisted.
        record.encode()?;
        Ok(record)
    }
    pub fn request(&self) -> &ValidatedAuthorizationRequest {
        &self.request
    }
    pub fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }
    pub fn is_expired(&self, server_now_ms: u64) -> bool {
        server_now_ms >= self.expires_at_ms
    }
    pub fn matches_browser_binding(&self, binding: &[u8; 32]) -> bool {
        bool::from(self.browser_binding.ct_eq(binding))
    }
    fn dto(&self) -> TransactionDto {
        TransactionDto {
            version: 1,
            client_id: self.request.client_id().into(),
            redirect_uri: self.request.redirect_uri().into(),
            resource: self.request.resource().into(),
            scopes: self.request.scopes().to_vec(),
            state: self.request.state().map(String::from),
            pkce_challenge: *self.request.challenge().digest(),
            browser_binding: self.browser_binding,
            expires_at_ms: self.expires_at_ms,
        }
    }
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        let dto = self.dto();
        if dto.query().len() > MAX_AUTHORIZATION_QUERY_BYTES {
            return Err(RecordError::TooLarge);
        }
        let bytes = serde_json::to_vec(&dto).map_err(|_| RecordError::InvalidRecord)?;
        if bytes.len() > MAX_TRANSACTION_BYTES {
            return Err(RecordError::TooLarge);
        }
        Ok(bytes)
    }
    /// Caller supplies trusted backend/server time, never an HTTP timestamp. Cache content is
    /// structurally revalidated against current config; this is not a MAC or storage authenticator.
    pub fn decode(
        bytes: &[u8],
        config: &OAuthConfig,
        server_now_ms: u64,
    ) -> Result<Self, RecordError> {
        if bytes.len() > MAX_TRANSACTION_BYTES {
            return Err(RecordError::TooLarge);
        }
        let dto: TransactionDto =
            serde_json::from_slice(bytes).map_err(|_| RecordError::InvalidRecord)?;
        if dto.version != 1 {
            return Err(RecordError::UnsupportedVersion);
        }
        if !valid_time(server_now_ms) || !valid_time(dto.expires_at_ms) || dto.expires_at_ms == 0 {
            return Err(RecordError::InvalidTime);
        }
        if server_now_ms >= dto.expires_at_ms {
            return Err(RecordError::Expired);
        }
        let query = dto.query();
        let request = validate_authorization_request(config, query.as_bytes())
            .map_err(|_| RecordError::InvalidRecord)?;
        if request.scopes() != dto.scopes {
            return Err(RecordError::InvalidRecord);
        }
        Ok(Self {
            request,
            browser_binding: dto.browser_binding,
            expires_at_ms: dto.expires_at_ms,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};
    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const RESOURCE: &str = "https://mcp.example.org/mcp";
    const CALLBACK: &str = "https://app.example.org/cb?fixed=a%20b";

    fn fixture() -> (OAuthConfig, AuthorizationTransaction) {
        let config: OAuthConfig = serde_json::from_value(json!({"issuer": "https://login.example.org", "clients": [
            {"client_id": "desktop", "display_name": "Desktop", "redirect_uris": [CALLBACK], "resources": [{"resource": RESOURCE, "scopes": ["read", "open"]}]}],
            "resources": [{"resource": RESOURCE, "allowed_realms": ["local"], "scopes": [{"name": "read", "required_roles": ["reader"]}, {"name": "open", "required_roles": []}]}]})).unwrap();
        let query = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs([
                ("client_id", "desktop"),
                ("redirect_uri", CALLBACK),
                ("response_type", "code"),
                ("resource", RESOURCE),
                ("scope", "open read"),
                ("state", "opaque + café<&>"),
                (
                    "code_challenge",
                    "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                ),
                ("code_challenge_method", "S256"),
                ("password", "not-retained"),
                ("username", "ignored"),
                ("unknown", "ignored"),
            ])
            .finish();
        let request = validate_authorization_request(&config, query.as_bytes()).unwrap();
        (
            config,
            AuthorizationTransaction::new(request, [7; 32], 2000).unwrap(),
        )
    }
    #[test]
    fn decode_revalidates_any_port_loopback_callback_and_keeps_exact_spelling() {
        let (mut config, record) = fixture();
        config.clients[0].application_type = crate::config::oauth::ApplicationType::Native;
        config.clients[0].redirect_uris = vec!["http://localhost/cb".into()];
        let mut dto: Value = serde_json::from_slice(&record.encode().unwrap()).unwrap();
        for (callback, accepted) in [
            ("http://localhost:1/cb", true),
            ("http://localhost:65535/cb", true),
            ("http://localhost/cb", false),
            ("http://localhost:0/cb", false),
            ("http://127.0.0.1:8080/cb", false),
        ] {
            dto["redirect_uri"] = json!(callback);
            let bytes = serde_json::to_vec(&dto).unwrap();
            let restored = AuthorizationTransaction::decode(&bytes, &config, 1);
            assert_eq!(restored.is_ok(), accepted, "{callback}");
            if let Ok(restored) = restored {
                assert_eq!(restored.request().redirect_uri(), callback);
            }
        }
    }
    #[test]
    fn round_trip_known_fields_binding_and_exact_expiry_boundary() {
        let (config, record) = fixture();
        let bytes = record.encode().unwrap();
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        let mut fields = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>();
        fields.sort_unstable();
        assert_eq!(
            fields.join(" "),
            "browser_binding client_id expires_at_ms pkce_challenge redirect_uri resource scopes state version"
        );
        assert!(
            !std::str::from_utf8(&bytes)
                .unwrap()
                .contains("not-retained")
        );
        let restored = AuthorizationTransaction::decode(&bytes, &config, 1999).unwrap();
        assert_eq!(restored.request().redirect_uri(), CALLBACK);
        assert_eq!(restored.request().client_id(), "desktop");
        assert_eq!(restored.request().resource(), RESOURCE);
        assert_eq!(restored.request().scopes(), &["open", "read"]);
        assert_eq!(restored.request().state(), Some("opaque + café<&>"));
        assert!(restored.request().challenge().verify(VERIFIER));
        assert!(restored.matches_browser_binding(&[7; 32]));
        assert!(!restored.matches_browser_binding(&[8; 32]));
        assert_eq!(restored.expires_at_ms(), 2000);
        assert!(!restored.is_expired(1999));
        assert!(restored.is_expired(2000));
        assert_eq!(
            AuthorizationTransaction::decode(&bytes, &config, 2000).err(),
            Some(RecordError::Expired)
        );
        let mut no_state = value;
        no_state["state"] = Value::Null;
        assert!(
            AuthorizationTransaction::decode(&serde_json::to_vec(&no_state).unwrap(), &config, 1)
                .unwrap()
                .request()
                .state()
                .is_none()
        );
    }
    #[test]
    fn valid_raw_query_rejects_oversized_canonical_transaction() {
        let (mut config, _) = fixture();
        let callback = format!("https://app.example.org/{}", "!".repeat(2000));
        let resource = format!("https://mcp.example.org/{}", "!".repeat(2000));
        config.clients[0].redirect_uris = vec![callback.clone()];
        config.clients[0].resources[0].resource = resource.clone();
        config.resources[0].resource = resource.clone();
        assert!(callback.len() <= 2048 && resource.len() <= 2048);
        let raw = format!(
            "client_id=desktop&redirect_uri={callback}&response_type=code&resource={resource}&scope=read&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256"
        );
        assert_eq!(MAX_AUTHORIZATION_QUERY_BYTES, 8 * 1024);
        assert!(raw.len() < MAX_AUTHORIZATION_QUERY_BYTES);
        let request = validate_authorization_request(&config, raw.as_bytes()).unwrap();
        let dto = TransactionDto {
            version: 1,
            client_id: request.client_id().into(),
            redirect_uri: request.redirect_uri().into(),
            resource: request.resource().into(),
            scopes: request.scopes().to_vec(),
            state: None,
            pkce_challenge: *request.challenge().digest(),
            browser_binding: [7; 32],
            expires_at_ms: 60000,
        };
        assert!(dto.query().len() > MAX_AUTHORIZATION_QUERY_BYTES);
        assert_eq!(
            AuthorizationTransaction::new(request, [7; 32], 60000).err(),
            Some(RecordError::TooLarge)
        );
    }
    #[test]
    fn valid_json_at_wire_limit_round_trips_but_one_extra_byte_fails() {
        let (config, record) = fixture();
        let original = record.encode().unwrap();
        let mut padded = original.clone();
        padded.resize(MAX_TRANSACTION_BYTES, b' ');
        let restored = AuthorizationTransaction::decode(&padded, &config, 1999).unwrap();
        assert_eq!(restored.encode().unwrap(), original);
        assert!(restored.matches_browser_binding(&[7; 32]));
        assert!(restored.request().challenge().verify(VERIFIER));
        padded.push(b' ');
        assert_eq!(
            AuthorizationTransaction::decode(&padded, &config, 1999).err(),
            Some(RecordError::TooLarge)
        );
    }
    #[test]
    fn malformed_versions_times_and_tampered_request_fields_fail_closed() {
        use RecordError::*;
        let (config, record) = fixture();
        let original: Value = serde_json::from_slice(&record.encode().unwrap()).unwrap();
        for (field, replacement, error) in [
            ("version", json!(2), UnsupportedVersion),
            ("client_id", json!("unknown"), InvalidRecord),
            (
                "redirect_uri",
                json!("https://evil.example.org/cb"),
                InvalidRecord,
            ),
            (
                "resource",
                json!("https://mcp.example.org/mcp/"),
                InvalidRecord,
            ),
            ("scopes", json!(["unknown"]), InvalidRecord),
            ("scopes", json!(["open read"]), InvalidRecord),
            ("state", json!("line\n"), InvalidRecord),
            ("pkce_challenge", json!([1, 2]), InvalidRecord),
            ("browser_binding", json!([0]), InvalidRecord),
            ("expires_at_ms", json!(0), InvalidTime),
            ("expires_at_ms", json!(u64::MAX), InvalidTime),
            ("password", json!("ignored"), InvalidRecord),
        ] {
            let mut value = original.clone();
            value[field] = replacement;
            assert_eq!(
                AuthorizationTransaction::decode(&serde_json::to_vec(&value).unwrap(), &config, 1)
                    .err(),
                Some(error),
                "{field}"
            );
        }
        for bytes in [b"not JSON".as_slice(), b"\xff"] {
            assert!(AuthorizationTransaction::decode(bytes, &config, 1).is_err());
        }
        let oversized = vec![b'x'; MAX_TRANSACTION_BYTES + 1];
        assert_eq!(
            AuthorizationTransaction::decode(&oversized, &config, 1).err(),
            Some(TooLarge)
        );
        let boundary = vec![b'x'; MAX_TRANSACTION_BYTES];
        assert_eq!(
            AuthorizationTransaction::decode(&boundary, &config, 1).err(),
            Some(InvalidRecord)
        );
        let bytes = record.encode().unwrap();
        assert_eq!(
            AuthorizationTransaction::decode(&bytes, &config, u64::MAX).err(),
            Some(InvalidTime)
        );
        let mut revoked = config;
        revoked.clients[0].resources.clear();
        assert_eq!(
            AuthorizationTransaction::decode(&bytes, &revoked, 1).err(),
            Some(InvalidRecord)
        );
        for expiry in [0, 253402300800000, u64::MAX] {
            let (_, record) = fixture();
            assert_eq!(
                AuthorizationTransaction::new(record.request, [0; 32], expiry).err(),
                Some(InvalidTime)
            );
        }
        assert!(valid_time(253402300799999));
    }
}

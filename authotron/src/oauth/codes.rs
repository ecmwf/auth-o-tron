// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! Secret authorization-code handles and trusted stored envelopes.

use super::{
    code_grant::{CodeGrant, CodeGrantError, MAX_CODE_GRANT_BYTES},
    records::valid_time,
    store::TransactionId,
};
use crate::config::OAuthConfig;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use subtle::ConstantTimeEq;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeStoreError {
    Missing,
    Limited,
    InvalidToken,
    InvalidDecision,
    Unavailable,
}

/// Secret 32-byte random handle; no Debug, Clone, serde or public generation.
pub struct AuthorizationCode(TransactionId);
impl AuthorizationCode {
    pub(super) fn generate() -> Result<Self, CodeStoreError> {
        TransactionId::generate()
            .map(Self)
            .map_err(|_| CodeStoreError::Unavailable)
    }
    /// Valid: 43 `A` characters; invalid: that value followed by `=` or ending in `B`.
    pub fn parse(value: &str) -> Result<Self, CodeStoreError> {
        TransactionId::parse(value)
            .map(Self)
            .map_err(|_| CodeStoreError::Missing)
    }
    pub fn as_secret_str(&self) -> &str {
        self.0.as_secret_str()
    }
    pub(super) fn hash(&self) -> [u8; 32] {
        self.0.hash()
    }
}

pub enum CodeIssueOutcome {
    Issued(IssuedCode),
    Denied,
}

/// Persisted code delivery data, with no Debug, Clone or serde.
pub struct IssuedCode {
    code: AuthorizationCode,
    expires_at_ms: u64,
    redirect_uri: String,
    state: Option<String>,
}
impl IssuedCode {
    pub(super) fn new(code: AuthorizationCode, grant: &CodeGrant) -> Self {
        Self {
            code,
            expires_at_ms: grant.expires_at_ms(),
            redirect_uri: grant.redirect_uri().into(),
            state: grant.state().map(str::to_owned),
        }
    }
    pub fn code(&self) -> &AuthorizationCode {
        &self.code
    }
    pub fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }
    pub fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }
    /// Untrusted client text, never identity or a logging field.
    pub fn state(&self) -> Option<&str> {
        self.state.as_deref()
    }
}

pub(super) struct StoredCode {
    code_hash: [u8; 32],
    issuer: String,
    bytes: Vec<u8>,
    expires_at_ms: u64,
}
impl StoredCode {
    pub(super) fn issuer(&self) -> &str {
        &self.issuer
    }
    // Read-only metadata for explicit shared-backend persistence in the next slice.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn code_hash(&self) -> &[u8; 32] {
        &self.code_hash
    }
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn payload(&self) -> &[u8] {
        &self.bytes
    }
    pub(super) fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }
    pub(super) fn new(
        code: &AuthorizationCode,
        grant: CodeGrant,
        issuer: &str,
    ) -> Result<Self, CodeStoreError> {
        let bytes = grant.encode().map_err(|_| CodeStoreError::Unavailable)?;
        Self::from_backend(
            &URL_SAFE_NO_PAD.encode(code.hash()),
            issuer,
            grant.expires_at_ms(),
            &bytes,
        )
    }
    /// Trusted backend metadata only, not request JSON or proof restoration.
    /// Hash example: 43 `A` characters are canonical; a final `B` is an invalid alias.
    pub(super) fn from_backend(
        code_hash: &str,
        issuer: &str,
        expires_at_ms: u64,
        payload: &[u8],
    ) -> Result<Self, CodeStoreError> {
        use CodeStoreError::Unavailable;
        if code_hash.len() != 43
            || issuer.len() > 2048
            || payload.is_empty()
            || payload.len() > MAX_CODE_GRANT_BYTES
            || expires_at_ms == 0
            || !valid_time(expires_at_ms)
        {
            return Err(Unavailable);
        }
        let hash = URL_SAFE_NO_PAD.decode(code_hash).map_err(|_| Unavailable)?;
        if URL_SAFE_NO_PAD.encode(&hash) != code_hash {
            return Err(Unavailable);
        }
        // Reuse origin validation without replacing the cached literal spelling.
        OAuthConfig {
            issuer: Some(issuer.into()),
            ..Default::default()
        }
        .validate()
        .map_err(|_| Unavailable)?;
        Ok(Self {
            code_hash: hash.try_into().map_err(|_| Unavailable)?,
            issuer: issuer.into(),
            bytes: payload.into(),
            expires_at_ms,
        })
    }
    // Record validation only; the store must atomically consume before returning proof.
    pub(super) fn grant(
        &self,
        code: &AuthorizationCode,
        cfg: &OAuthConfig,
        now: u64,
    ) -> Result<CodeGrant, CodeStoreError> {
        if !bool::from(self.code_hash.ct_eq(&code.hash()))
            || Some(self.issuer()) != cfg.issuer.as_deref()
        {
            return Err(CodeStoreError::Unavailable);
        }
        if now >= self.expires_at_ms {
            return Err(CodeStoreError::Missing);
        }
        let grant = CodeGrant::decode(&self.bytes, cfg, now).map_err(|error| match error {
            CodeGrantError::Expired => CodeStoreError::Missing,
            _ => CodeStoreError::Unavailable,
        })?;
        if grant.expires_at_ms() > self.expires_at_ms {
            return Err(CodeStoreError::Unavailable);
        }
        Ok(grant)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_handles_are_canonical_bounded_and_secret() {
        let code = AuthorizationCode::generate().unwrap();
        assert_eq!(code.as_secret_str().len(), 43);
        assert_eq!(
            AuthorizationCode::parse(code.as_secret_str())
                .unwrap()
                .hash(),
            code.hash()
        );
        assert_ne!(AuthorizationCode::generate().unwrap().hash(), code.hash());
        assert!(AuthorizationCode::parse(&"A".repeat(43)).is_ok());
        for invalid in [
            "".into(),
            "A".repeat(42),
            "A".repeat(44),
            "A".repeat(43) + "=",
            "A".repeat(42) + "B",
            "!".repeat(43),
        ] {
            assert_eq!(
                AuthorizationCode::parse(&invalid).err(),
                Some(CodeStoreError::Missing)
            );
        }
    }

    #[tokio::test]
    async fn portable_envelope_pins_literal_issuer_and_bounds_backend_fields() {
        let (mut cfg, id, approval, now) =
            super::super::code_grant::tests::approved(300, 300).await;
        cfg.issuer = Some("https://login.example.org/".into());
        let grant = CodeGrant::from_consent(approval, &cfg, &id, &[7; 32], now).unwrap();
        let code = AuthorizationCode::generate().unwrap();
        let record = StoredCode::new(&code, grant, cfg.issuer.as_deref().unwrap()).unwrap();
        let hash = URL_SAFE_NO_PAD.encode(record.code_hash());
        let restored = StoredCode::from_backend(
            &hash,
            record.issuer(),
            record.expires_at_ms(),
            record.payload(),
        )
        .unwrap();
        assert_eq!(restored.code_hash(), &code.hash());
        assert_eq!(restored.issuer(), "https://login.example.org/");
        assert_eq!(restored.payload(), record.payload());
        assert!(restored.grant(&code, &cfg, now).is_ok());
        for issuer in ["https://login.example.org", "https://other.example.org/"] {
            cfg.issuer = Some(issuer.into());
            assert_eq!(
                restored.grant(&code, &cfg, now).err(),
                Some(CodeStoreError::Unavailable)
            );
            assert_eq!(restored.issuer(), "https://login.example.org/");
        }
        cfg.issuer = Some(record.issuer().into());
        let mut boundary = record.payload().to_vec();
        boundary.resize(MAX_CODE_GRANT_BYTES, b' ');
        assert!(
            StoredCode::from_backend(&hash, record.issuer(), record.expires_at_ms(), &boundary)
                .unwrap()
                .grant(&code, &cfg, now)
                .is_ok()
        );
        boundary.push(b' ');
        for (hash, issuer, expiry, payload) in [
            (
                "short",
                record.issuer(),
                record.expires_at_ms(),
                record.payload(),
            ),
            (
                &("A".repeat(42) + "B"),
                record.issuer(),
                record.expires_at_ms(),
                record.payload(),
            ),
            (
                &hash,
                "http://login.example.org",
                record.expires_at_ms(),
                record.payload(),
            ),
            (
                &hash,
                &"x".repeat(2049),
                record.expires_at_ms(),
                record.payload(),
            ),
            (&hash, record.issuer(), 0, record.payload()),
            (&hash, record.issuer(), 253402300800000, record.payload()),
            (&hash, record.issuer(), record.expires_at_ms(), &[]),
            (
                &hash,
                record.issuer(),
                record.expires_at_ms(),
                boundary.as_slice(),
            ),
        ] {
            assert_eq!(
                StoredCode::from_backend(hash, issuer, expiry, payload).err(),
                Some(CodeStoreError::Unavailable)
            );
        }
    }
    #[tokio::test]
    async fn stored_envelopes_bind_actual_code_hash_and_preserve_grant_constraints() {
        let (mut cfg, id, approval, now) =
            super::super::code_grant::tests::approved(300, 300).await;
        let grant = CodeGrant::from_consent(approval, &cfg, &id, &[7; 32], now).unwrap();
        let code = AuthorizationCode::generate().unwrap();
        let mut record = StoredCode::new(&code, grant, cfg.issuer.as_deref().unwrap()).unwrap();
        assert!(record.expires_at_ms() > now);
        assert_eq!(record.code_hash, code.hash());
        assert!(
            !std::str::from_utf8(&record.bytes)
                .unwrap()
                .contains(code.as_secret_str())
        );
        let restored = record.grant(&code, &cfg, now).unwrap();
        assert_eq!(restored.state(), Some("opaque+client"));
        assert_eq!(restored.expires_at_ms(), record.expires_at_ms);
        assert_eq!(
            restored.validate_redemption(
                "desktop",
                "http://127.0.0.1:49152/cb",
                "https://mcp.example.org/mcp",
                "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
                &cfg,
                now
            ),
            Ok(())
        );
        let other = AuthorizationCode::generate().unwrap();
        assert_eq!(
            record.grant(&other, &cfg, now).err(),
            Some(CodeStoreError::Unavailable)
        );
        cfg.authorization_code_ttl_seconds = 30;
        assert_eq!(
            record.grant(&code, &cfg, now).unwrap().expires_at_ms(),
            now + 30_000
        );
        assert_eq!(
            record.grant(&code, &cfg, record.expires_at_ms).err(),
            Some(CodeStoreError::Missing)
        );
        record.expires_at_ms = now + 1;
        assert_eq!(
            record.grant(&code, &cfg, now).err(),
            Some(CodeStoreError::Unavailable)
        );
        record.bytes = b"{}".to_vec();
        assert_eq!(
            record.grant(&code, &cfg, now).err(),
            Some(CodeStoreError::Unavailable)
        );
    }
}

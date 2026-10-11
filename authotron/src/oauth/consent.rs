// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! Explicit in-process consent decisions; no persistence, authorization code or token issuance.

use super::{
    context::{AuthenticatedAuthorization, MAX_AUTHENTICATED_CONTEXT_BYTES},
    records::valid_time,
    store::TransactionId,
};
use crate::{config::OAuthConfig, models::user::User};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

pub(super) const MAX_CONSENT_SESSION_BYTES: usize = 96 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentError {
    InvalidToken,
    InvalidDecision,
    InvalidContext,
    Unavailable,
    TooLarge,
    InvalidRecord,
    UnsupportedVersion,
}

/// Secret render token only: no Debug, Clone, Serialize or public construction.
pub struct ConsentToken(TransactionId);
impl ConsentToken {
    pub fn as_secret_str(&self) -> &str {
        self.0.as_secret_str()
    }
}

pub struct ConsentSession {
    context: AuthenticatedAuthorization,
    csrf_hash: [u8; 32],
    expires_at_ms: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConsentDto {
    version: u8,
    context: String,
    csrf_hash: [u8; 32],
    expires_at_ms: u64,
}
pub struct ConsentedAuthorization {
    context: AuthenticatedAuthorization,
    expires_at_ms: u64,
}
impl ConsentedAuthorization {
    pub(super) fn into_parts(self) -> (AuthenticatedAuthorization, u64) {
        (self.context, self.expires_at_ms)
    }
    pub fn as_user(&self) -> &User {
        self.context.as_user()
    }
    pub fn scopes(&self) -> &[String] {
        self.context.authorized_scopes()
    }
    pub fn client_id(&self) -> &str {
        self.context.transaction().request().client_id()
    }
    pub fn resource(&self) -> &str {
        self.context.transaction().request().resource()
    }
    pub fn redirect_uri(&self) -> &str {
        self.context.transaction().request().redirect_uri()
    }
    pub fn verified_at_ms(&self) -> u64 {
        self.context.verified_at_ms()
    }
    pub fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }
}
pub enum ConsentOutcome {
    Approved(Box<ConsentedAuthorization>),
    Denied,
}

fn checked(
    context: &AuthenticatedAuthorization,
    source_id: &TransactionId,
    config: &OAuthConfig,
    browser_hash: &[u8; 32],
    server_now_ms: u64,
) -> Result<AuthenticatedAuthorization, ConsentError> {
    if !context.matches_source(&source_id.hash()) {
        return Err(ConsentError::InvalidContext);
    }
    let bytes = context.encode().map_err(|_| ConsentError::InvalidContext)?;
    AuthenticatedAuthorization::decode(&bytes, config, browser_hash, server_now_ms)
        .map_err(|_| ConsentError::InvalidContext)
}
impl ConsentSession {
    pub(super) fn into_context(self) -> AuthenticatedAuthorization {
        self.context
    }
    pub(super) fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }
    /// A store may shorten but never extend the source record's expiry ceiling.
    pub(super) fn from_stored_context(
        context: AuthenticatedAuthorization,
        source_id: &TransactionId,
        config: &OAuthConfig,
        browser_hash: &[u8; 32],
        now: u64,
        ceiling: u64,
    ) -> Result<(Self, ConsentToken), ConsentError> {
        if !valid_time(ceiling) || now >= ceiling {
            return Err(ConsentError::InvalidContext);
        }
        let (mut session, token) = Self::new(context, source_id, config, browser_hash, now)?;
        session.expires_at_ms = session.expires_at_ms.min(ceiling);
        Ok((session, token))
    }
    /// Rotate the challenge after validation, preserving the existing session ceiling.
    pub(super) fn renew(
        self,
        source_id: &TransactionId,
        config: &OAuthConfig,
        browser_hash: &[u8; 32],
        now: u64,
    ) -> Result<(Self, ConsentToken), ConsentError> {
        Self::from_stored_context(
            self.context,
            source_id,
            config,
            browser_hash,
            now,
            self.expires_at_ms,
        )
    }
    pub(super) fn encode(&self) -> Result<Vec<u8>, ConsentError> {
        let context = self
            .context
            .encode()
            .map_err(|_| ConsentError::InvalidContext)?;
        let dto = ConsentDto {
            version: 1,
            context: URL_SAFE_NO_PAD.encode(context),
            csrf_hash: self.csrf_hash,
            expires_at_ms: self.expires_at_ms,
        };
        let bytes = serde_json::to_vec(&dto).map_err(|_| ConsentError::InvalidRecord)?;
        if bytes.len() > MAX_CONSENT_SESSION_BYTES {
            return Err(ConsentError::TooLarge);
        }
        Ok(bytes)
    }
    /// Trusted authenticated storage only, not request JSON or a MAC. No approval is restored.
    pub(super) fn decode(
        bytes: &[u8],
        source_id: &TransactionId,
        config: &OAuthConfig,
        browser_hash: &[u8; 32],
        server_now_ms: u64,
    ) -> Result<Self, ConsentError> {
        use ConsentError::*;
        if bytes.len() > MAX_CONSENT_SESSION_BYTES {
            return Err(TooLarge);
        }
        let dto: ConsentDto = serde_json::from_slice(bytes).map_err(|_| InvalidRecord)?;
        if dto.version != 1 {
            return Err(UnsupportedVersion);
        }
        if dto.expires_at_ms == 0 || !valid_time(dto.expires_at_ms) {
            return Err(InvalidRecord);
        }
        if !valid_time(server_now_ms) || server_now_ms >= dto.expires_at_ms {
            return Err(InvalidContext);
        }
        if dto.context.len() > (MAX_AUTHENTICATED_CONTEXT_BYTES * 4).div_ceil(3) {
            return Err(TooLarge);
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(&dto.context)
            .map_err(|_| InvalidRecord)?;
        if bytes.len() > MAX_AUTHENTICATED_CONTEXT_BYTES {
            return Err(TooLarge);
        }
        if URL_SAFE_NO_PAD.encode(&bytes) != dto.context {
            return Err(InvalidRecord);
        }
        let context =
            AuthenticatedAuthorization::decode(&bytes, config, browser_hash, server_now_ms)
                .map_err(|_| InvalidContext)?;
        if !context.matches_source(&source_id.hash()) {
            return Err(InvalidContext);
        }
        if dto.expires_at_ms > context.transaction().expires_at_ms() {
            return Err(InvalidRecord);
        }
        let expires_at_ms = dto.expires_at_ms.min(context.expires_at_ms());
        Ok(Self {
            context,
            csrf_hash: dto.csrf_hash,
            expires_at_ms,
        })
    }
    /// Trusted server time and source ID only. Caller enforces Origin/CSRF request context.
    pub fn new(
        context: AuthenticatedAuthorization,
        source_id: &TransactionId,
        config: &OAuthConfig,
        browser_hash: &[u8; 32],
        server_now_ms: u64,
    ) -> Result<(Self, ConsentToken), ConsentError> {
        let original_expiry = context.expires_at_ms();
        if server_now_ms >= original_expiry {
            return Err(ConsentError::InvalidContext);
        }
        let context = checked(&context, source_id, config, browser_hash, server_now_ms)?;
        let expires_at_ms = original_expiry.min(context.expires_at_ms());
        let token = TransactionId::generate().map_err(|_| ConsentError::Unavailable)?;
        let csrf_hash = token.hash();
        Ok((
            Self {
                context,
                csrf_hash,
                expires_at_ms,
            },
            ConsentToken(token),
        ))
    }
    /// Consumes this session even on failure. Only exact "approve"/"deny" are decisions;
    /// future HTTP parsing must reject duplicate fields and check Origin independently.
    pub fn decide(
        self,
        submitted_token: &str,
        decision: &str,
        source_id: &TransactionId,
        browser_hash: &[u8; 32],
        config: &OAuthConfig,
        server_now_ms: u64,
    ) -> Result<ConsentOutcome, ConsentError> {
        let token =
            TransactionId::parse(submitted_token).map_err(|_| ConsentError::InvalidToken)?;
        if !bool::from(self.csrf_hash.ct_eq(&token.hash())) {
            return Err(ConsentError::InvalidToken);
        }
        if server_now_ms >= self.expires_at_ms {
            return Err(ConsentError::InvalidContext);
        }
        let context = checked(
            &self.context,
            source_id,
            config,
            browser_hash,
            server_now_ms,
        )?;
        let expires_at_ms = self.expires_at_ms.min(context.expires_at_ms());
        match decision {
            "approve" => Ok(ConsentOutcome::Approved(Box::new(ConsentedAuthorization {
                context,
                expires_at_ms,
            }))),
            "deny" => Ok(ConsentOutcome::Denied),
            _ => Err(ConsentError::InvalidDecision),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{
        context::tests::fixture as verified_fixture,
        store::{MemoryTransactionStore, tests::request},
    };
    use super::*;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use std::sync::Arc;

    async fn fixture() -> (OAuthConfig, TransactionId, AuthenticatedAuthorization, u64) {
        let (mut config, _, identity) = verified_fixture().await;
        config.max_authentication_age_seconds = 1;
        let now = identity.verified_at_ms();
        let store = MemoryTransactionStore::new(Arc::new(config.clone())).unwrap();
        let created = store.create(request(&config), [7; 32]).await.unwrap();
        let source = store.lookup_bound(&created.id, &[7; 32]).await.unwrap();
        let context =
            AuthenticatedAuthorization::new_bound(source, identity, &[7; 32], &config, now)
                .unwrap();
        (config, created.id, context, now)
    }
    #[tokio::test]
    async fn internal_renewal_preserves_ceiling_under_relaxed_policy() {
        let (mut config, id, context, now) = fixture().await;
        let (session, first) = ConsentSession::new(context, &id, &config, &[7; 32], now).unwrap();
        let expiry = session.expires_at_ms();
        config.max_authentication_age_seconds = 300;
        let (session, second) = session.renew(&id, &config, &[7; 32], now + 500).unwrap();
        assert_eq!(session.expires_at_ms(), expiry);
        assert!(first.as_secret_str() != second.as_secret_str());
        assert_eq!(
            session
                .decide(
                    second.as_secret_str(),
                    "approve",
                    &id,
                    &[7; 32],
                    &config,
                    expiry
                )
                .err(),
            Some(ConsentError::InvalidContext)
        );
    }
    #[tokio::test]
    async fn private_codec_round_trip_keeps_hash_only_and_original_deadline() {
        let (mut config, id, context, now) = fixture().await;
        let (session, token) = ConsentSession::new(context, &id, &config, &[7; 32], now).unwrap();
        let expiry = session.expires_at_ms;
        let bytes = session.encode().unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let mut names = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>();
        names.sort_unstable();
        assert_eq!(names.join(" "), "context csrf_hash expires_at_ms version");
        assert!(
            !std::str::from_utf8(&bytes)
                .unwrap()
                .contains(token.as_secret_str())
        );
        let restored = ConsentSession::decode(&bytes, &id, &config, &[7; 32], now).unwrap();
        assert!(restored.encode().unwrap() == bytes);
        let ConsentOutcome::Approved(approved) = restored
            .decide(
                token.as_secret_str(),
                "approve",
                &id,
                &[7; 32],
                &config,
                now,
            )
            .unwrap()
        else {
            panic!("approval was not returned")
        };
        assert_eq!(approved.client_id(), "desktop");
        assert_eq!(approved.scopes(), &["read"]);
        config.max_authentication_age_seconds = 300;
        let restored = ConsentSession::decode(&bytes, &id, &config, &[7; 32], now + 999).unwrap();
        assert_eq!(restored.expires_at_ms, expiry);
        assert_eq!(
            ConsentSession::decode(&bytes, &id, &config, &[7; 32], expiry).err(),
            Some(ConsentError::InvalidContext)
        );
        // A persisted longer-age session is tightened by current policy, without renewing its ceiling.
        let mut value = value;
        value["expires_at_ms"] = serde_json::json!(now + 10000);
        let longer = serde_json::to_vec(&value).unwrap();
        config.max_authentication_age_seconds = 1;
        assert_eq!(
            ConsentSession::decode(&longer, &id, &config, &[7; 32], now)
                .unwrap()
                .expires_at_ms,
            now + 1000
        );
    }
    #[tokio::test]
    async fn private_codec_enforces_wire_bounds_shape_and_current_context() {
        use ConsentError::*;
        use serde_json::json;
        let (config, id, context, now) = fixture().await;
        let transaction_expiry = context.transaction().expires_at_ms();
        let (session, _) = ConsentSession::new(context, &id, &config, &[7; 32], now).unwrap();
        let bytes = session.encode().unwrap();
        let original: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        for (field, replacement, error) in [
            ("version", json!(2), UnsupportedVersion),
            ("csrf_hash", json!([1, 2]), InvalidRecord),
            ("expires_at_ms", json!(0), InvalidRecord),
            ("expires_at_ms", json!(u64::MAX), InvalidRecord),
            (
                "expires_at_ms",
                json!(transaction_expiry + 1),
                InvalidRecord,
            ),
            ("context", json!("%%%"), InvalidRecord),
            (
                "context",
                json!(format!("{}=", original["context"].as_str().unwrap())),
                InvalidRecord,
            ),
            (
                "context",
                json!(URL_SAFE_NO_PAD.encode(b"bad JSON")),
                InvalidContext,
            ),
            (
                "context",
                json!(URL_SAFE_NO_PAD.encode(vec![b'x'; MAX_AUTHENTICATED_CONTEXT_BYTES + 1])),
                TooLarge,
            ),
            ("token", json!("forbidden"), InvalidRecord),
            ("approved", json!(true), InvalidRecord),
        ] {
            let mut value = original.clone();
            value[field] = replacement;
            assert_eq!(
                ConsentSession::decode(
                    &serde_json::to_vec(&value).unwrap(),
                    &id,
                    &config,
                    &[7; 32],
                    now
                )
                .err(),
                Some(error),
                "{field}"
            );
        }
        let mut padded = bytes.clone();
        padded.resize(MAX_CONSENT_SESSION_BYTES, b' ');
        assert!(ConsentSession::decode(&padded, &id, &config, &[7; 32], now).is_ok());
        padded.push(b' ');
        assert_eq!(
            ConsentSession::decode(&padded, &id, &config, &[7; 32], now).err(),
            Some(TooLarge)
        );
        assert_eq!(
            ConsentSession::decode(b"\xff", &id, &config, &[7; 32], now).err(),
            Some(InvalidRecord)
        );
        assert_eq!(
            ConsentSession::decode(&bytes, &id, &config, &[8; 32], now).err(),
            Some(InvalidContext)
        );
        assert_eq!(
            ConsentSession::decode(
                &bytes,
                &TransactionId::generate().unwrap(),
                &config,
                &[7; 32],
                now
            )
            .err(),
            Some(InvalidContext)
        );
        assert_eq!(
            ConsentSession::decode(&bytes, &id, &config, &[7; 32], now + 1000).err(),
            Some(InvalidContext)
        );
        assert_eq!(
            ConsentSession::decode(&bytes, &id, &config, &[7; 32], u64::MAX).err(),
            Some(InvalidContext)
        );
        let mut revoked = config.clone();
        revoked.clients[0].resources.clear();
        assert_eq!(
            ConsentSession::decode(&bytes, &id, &revoked, &[7; 32], now).err(),
            Some(InvalidContext)
        );
        let mut denied = config;
        denied.resources[0].scopes[0]
            .required_roles
            .push("absent".into());
        assert_eq!(
            ConsentSession::decode(&bytes, &id, &denied, &[7; 32], now).err(),
            Some(InvalidContext)
        );
    }
    #[tokio::test]
    async fn only_explicit_checked_approval_returns_opaque_consent() {
        for decision in ["approve", "deny", "", "Approve", " approve", "other"] {
            let (config, id, context, now) = fixture().await;
            let expires = context.expires_at_ms();
            let (session, token) =
                ConsentSession::new(context, &id, &config, &[7; 32], now).unwrap();
            assert_eq!(token.as_secret_str().len(), 43);
            let outcome =
                session.decide(token.as_secret_str(), decision, &id, &[7; 32], &config, now);
            match decision {
                "approve" => {
                    let ConsentOutcome::Approved(approved) = outcome.unwrap() else {
                        panic!("approval was not returned")
                    };
                    assert_eq!(approved.as_user().username, "alice");
                    assert_eq!(approved.scopes(), &["read"]);
                    assert_eq!(approved.client_id(), "desktop");
                    assert_eq!(approved.resource(), "https://mcp.example.org/mcp");
                    assert_eq!(approved.redirect_uri(), "https://app.example.org/cb");
                    assert_eq!(approved.verified_at_ms(), now);
                    assert_eq!(approved.expires_at_ms(), expires);
                    assert!(
                        approved.as_user().attributes.is_empty()
                            && approved.as_user().scopes.is_empty()
                    );
                }
                "deny" => assert!(matches!(outcome, Ok(ConsentOutcome::Denied))),
                _ => assert_eq!(outcome.err(), Some(ConsentError::InvalidDecision)),
            }
        }
    }
    #[tokio::test]
    async fn csrf_is_session_specific_and_policy_relaxation_cannot_extend_session() {
        let (mut config, id, context, now) = fixture().await;
        let expires = context.expires_at_ms();
        let (session, token) = ConsentSession::new(context, &id, &config, &[7; 32], now).unwrap();
        config.max_authentication_age_seconds = 300;
        let ConsentOutcome::Approved(approved) = session
            .decide(
                token.as_secret_str(),
                "approve",
                &id,
                &[7; 32],
                &config,
                now,
            )
            .unwrap()
        else {
            panic!("approval was not returned")
        };
        assert_eq!(approved.expires_at_ms(), expires);
        let (mut config, id, context, now) = fixture().await;
        let (session, token) = ConsentSession::new(context, &id, &config, &[7; 32], now).unwrap();
        config.max_authentication_age_seconds = 300;
        assert_eq!(
            session
                .decide(
                    token.as_secret_str(),
                    "approve",
                    &id,
                    &[7; 32],
                    &config,
                    now + 1000
                )
                .err(),
            Some(ConsentError::InvalidContext)
        );
        let (config, id, context, now) = fixture().await;
        let (session, _) = ConsentSession::new(context, &id, &config, &[7; 32], now).unwrap();
        let (other_config, other_id, other_context, other_now) = fixture().await;
        let (_, other_token) =
            ConsentSession::new(other_context, &other_id, &other_config, &[7; 32], other_now)
                .unwrap();
        assert_eq!(
            session
                .decide(
                    other_token.as_secret_str(),
                    "approve",
                    &id,
                    &[7; 32],
                    &config,
                    now
                )
                .err(),
            Some(ConsentError::InvalidToken)
        );
    }
    #[tokio::test]
    async fn invalid_tokens_never_approve_or_deny() {
        for decision in ["approve", "deny"] {
            for case in ["empty", "wrong", "padding", "noncanonical", "oversized"] {
                let (config, id, context, now) = fixture().await;
                let (session, token) =
                    ConsentSession::new(context, &id, &config, &[7; 32], now).unwrap();
                let submitted = match case {
                    "empty" => String::new(),
                    "wrong" => URL_SAFE_NO_PAD.encode([0; 32]),
                    "padding" => format!("{}=", token.as_secret_str()),
                    "noncanonical" => format!("{}B", "A".repeat(42)),
                    _ => "A".repeat(44),
                };
                assert_eq!(
                    session
                        .decide(&submitted, decision, &id, &[7; 32], &config, now)
                        .err(),
                    Some(ConsentError::InvalidToken)
                );
            }
        }
    }
    #[tokio::test]
    async fn both_decisions_recheck_browser_source_freshness_and_current_policy() {
        for decision in ["approve", "deny"] {
            for case in [
                "browser", "source", "stale", "expired", "policy", "callback", "time",
            ] {
                let (mut config, id, context, now) = fixture().await;
                let expiry = context.transaction().expires_at_ms();
                let (session, token) =
                    ConsentSession::new(context, &id, &config, &[7; 32], now).unwrap();
                let mut hash = [7; 32];
                let mut time = now;
                let mut source = TransactionId::parse(id.as_secret_str()).unwrap();
                match case {
                    "browser" => hash = [8; 32],
                    "source" => source = TransactionId::generate().unwrap(),
                    "stale" => time += 1000,
                    "expired" => time = expiry,
                    "policy" => config.resources[0].scopes[0]
                        .required_roles
                        .push("absent".into()),
                    "callback" => {
                        config.clients[0].redirect_uris[0] = "https://other.example.org/cb".into()
                    }
                    _ => time = u64::MAX,
                }
                assert_eq!(
                    session
                        .decide(
                            token.as_secret_str(),
                            decision,
                            &source,
                            &hash,
                            &config,
                            time
                        )
                        .err(),
                    Some(ConsentError::InvalidContext),
                    "{case}"
                );
            }
        }
        let (config, _, context, now) = fixture().await;
        assert_eq!(
            ConsentSession::new(
                context,
                &TransactionId::generate().unwrap(),
                &config,
                &[7; 32],
                now
            )
            .err(),
            Some(ConsentError::InvalidContext)
        );
    }
}

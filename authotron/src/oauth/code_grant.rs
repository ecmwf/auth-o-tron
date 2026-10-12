// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! Consent-derived code-grant eligibility, without code IDs, storage or token issuance.

use super::{
    authorization::{PkceChallenge, ValidatedAuthorizationRequest},
    consent::ConsentedAuthorization,
    context::{AuthenticatedAuthorization, MAX_AUTHENTICATED_CONTEXT_BYTES},
    records::valid_time,
    store::TransactionId,
};
use crate::{config::OAuthConfig, models::user::User};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};

pub(super) const MAX_CODE_GRANT_BYTES: usize = 96 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeGrantError {
    Configuration,
    InvalidTime,
    InvalidContext,
    Expired,
    InvalidRedemption,
    TooLarge,
    InvalidRecord,
    UnsupportedVersion,
}

/// Owned approval snapshot: no Debug, Clone, serde or raw-identity constructor.
pub struct CodeGrant {
    context: AuthenticatedAuthorization,
    source_hash: [u8; 32],
    browser_hash: [u8; 32],
    issued_at_ms: u64,
    expires_at_ms: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CodeGrantDto {
    version: u8,
    context: String,
    source_hash: [u8; 32],
    browser_hash: [u8; 32],
    issued_at_ms: u64,
    expires_at_ms: u64,
}

fn configuration(config: &OAuthConfig) -> Result<(), CodeGrantError> {
    config
        .validate()
        .map_err(|_| CodeGrantError::Configuration)?;
    if config
        .issuer
        .as_ref()
        .is_none_or(|issuer| issuer.len() > 2048)
    {
        return Err(CodeGrantError::Configuration);
    }
    Ok(())
}

fn checked_context(
    context: &AuthenticatedAuthorization,
    source_hash: &[u8; 32],
    browser_hash: &[u8; 32],
    config: &OAuthConfig,
    now: u64,
) -> Result<AuthenticatedAuthorization, CodeGrantError> {
    if !context.matches_source(source_hash) {
        return Err(CodeGrantError::InvalidContext);
    }
    let bytes = context
        .encode()
        .map_err(|_| CodeGrantError::InvalidContext)?;
    AuthenticatedAuthorization::decode(&bytes, config, browser_hash, now)
        .map_err(|_| CodeGrantError::InvalidContext)
}

impl CodeGrant {
    pub(super) fn encode(&self) -> Result<Vec<u8>, CodeGrantError> {
        let context = self
            .context
            .encode()
            .map_err(|_| CodeGrantError::InvalidContext)?;
        let dto = CodeGrantDto {
            version: 1,
            context: URL_SAFE_NO_PAD.encode(context),
            source_hash: self.source_hash,
            browser_hash: self.browser_hash,
            issued_at_ms: self.issued_at_ms,
            expires_at_ms: self.expires_at_ms,
        };
        let bytes = serde_json::to_vec(&dto).map_err(|_| CodeGrantError::InvalidRecord)?;
        if bytes.len() > MAX_CODE_GRANT_BYTES {
            return Err(CodeGrantError::TooLarge);
        }
        Ok(bytes)
    }
    /// Trusted backend asserts prior approval; not request JSON, a MAC or issuance proof.
    /// Base64url example: `e30` canonically encodes `{}`; `e30=` has invalid padding.
    /// Decoded bytes must separately satisfy the authenticated-context codec.
    pub(super) fn decode(
        bytes: &[u8],
        config: &OAuthConfig,
        server_now_ms: u64,
    ) -> Result<Self, CodeGrantError> {
        use CodeGrantError::*;
        if bytes.len() > MAX_CODE_GRANT_BYTES {
            return Err(TooLarge);
        }
        let dto: CodeGrantDto = serde_json::from_slice(bytes).map_err(|_| InvalidRecord)?;
        if dto.version != 1 {
            return Err(UnsupportedVersion);
        }
        configuration(config)?;
        if dto.issued_at_ms == 0
            || !valid_time(dto.issued_at_ms)
            || !valid_time(dto.expires_at_ms)
            || dto.expires_at_ms <= dto.issued_at_ms
            || dto.expires_at_ms - dto.issued_at_ms > 300_000
        {
            return Err(InvalidRecord);
        }
        if !valid_time(server_now_ms) || dto.issued_at_ms > server_now_ms {
            return Err(InvalidTime);
        }
        if server_now_ms >= dto.expires_at_ms {
            return Err(Expired);
        }
        let deadline = dto
            .issued_at_ms
            .checked_add(config.authorization_code_ttl_seconds * 1000)
            .filter(|time| valid_time(*time))
            .ok_or(InvalidTime)?;
        if dto.context.len() > (MAX_AUTHENTICATED_CONTEXT_BYTES * 4).div_ceil(3) {
            return Err(TooLarge);
        }
        let context_bytes = URL_SAFE_NO_PAD
            .decode(&dto.context)
            .map_err(|_| InvalidRecord)?;
        if context_bytes.len() > MAX_AUTHENTICATED_CONTEXT_BYTES {
            return Err(TooLarge);
        }
        if URL_SAFE_NO_PAD.encode(&context_bytes) != dto.context {
            return Err(InvalidRecord);
        }
        let context = AuthenticatedAuthorization::decode(
            &context_bytes,
            config,
            &dto.browser_hash,
            server_now_ms,
        )
        .map_err(|_| InvalidContext)?;
        let context = checked_context(
            &context,
            &dto.source_hash,
            &dto.browser_hash,
            config,
            server_now_ms,
        )?;
        if dto.expires_at_ms > context.transaction().expires_at_ms() {
            return Err(InvalidRecord);
        }
        let expires_at_ms = dto.expires_at_ms.min(deadline).min(context.expires_at_ms());
        if server_now_ms >= expires_at_ms {
            return Err(Expired);
        }
        Ok(Self {
            context,
            source_hash: dto.source_hash,
            browser_hash: dto.browser_hash,
            issued_at_ms: dto.issued_at_ms,
            expires_at_ms,
        })
    }
    /// Consumes checked explicit approval. Source ID, binding and time are server-owned.
    pub fn from_consent(
        approval: ConsentedAuthorization,
        config: &OAuthConfig,
        source_id: &TransactionId,
        browser_hash: &[u8; 32],
        server_now_ms: u64,
    ) -> Result<Self, CodeGrantError> {
        configuration(config)?;
        if !valid_time(server_now_ms) {
            return Err(CodeGrantError::InvalidTime);
        }
        let code_deadline = config
            .authorization_code_ttl_seconds
            .checked_mul(1000)
            .and_then(|ttl| server_now_ms.checked_add(ttl))
            .filter(|deadline| valid_time(*deadline))
            .ok_or(CodeGrantError::InvalidTime)?;
        let (context, ceiling) = approval.into_parts();
        if server_now_ms >= ceiling {
            return Err(CodeGrantError::Expired);
        }
        let source_hash = source_id.hash();
        let context = checked_context(&context, &source_hash, browser_hash, config, server_now_ms)?;
        let expires_at_ms = code_deadline.min(ceiling).min(context.expires_at_ms());
        Ok(Self {
            context,
            source_hash,
            browser_hash: *browser_hash,
            issued_at_ms: server_now_ms,
            expires_at_ms,
        })
    }
    fn request(&self) -> &ValidatedAuthorizationRequest {
        self.context.transaction().request()
    }
    pub fn as_user(&self) -> &User {
        self.context.as_user()
    }
    pub fn scopes(&self) -> &[String] {
        self.context.authorized_scopes()
    }
    pub fn client_id(&self) -> &str {
        self.request().client_id()
    }
    pub fn redirect_uri(&self) -> &str {
        self.request().redirect_uri()
    }
    pub fn resource(&self) -> &str {
        self.request().resource()
    }
    /// Untrusted client text, never identity or a logging field.
    pub fn state(&self) -> Option<&str> {
        self.request().state()
    }
    pub fn challenge(&self) -> &PkceChallenge {
        self.request().challenge()
    }
    pub fn verified_at_ms(&self) -> u64 {
        self.context.verified_at_ms()
    }
    pub fn issued_at_ms(&self) -> u64 {
        self.issued_at_ms
    }
    pub fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }
    /// Pure eligibility check, not consumption or token-issuance proof. Public clients
    /// require exact client/callback/resource and S256 PKCE; no verifier is retained.
    pub fn validate_redemption(
        &self,
        client_id: &str,
        redirect_uri: &str,
        resource: &str,
        verifier: &str,
        config: &OAuthConfig,
        server_now_ms: u64,
    ) -> Result<(), CodeGrantError> {
        configuration(config)?;
        if !valid_time(server_now_ms) || server_now_ms < self.issued_at_ms {
            return Err(CodeGrantError::InvalidTime);
        }
        if server_now_ms >= self.expires_at_ms {
            return Err(CodeGrantError::Expired);
        }
        if client_id != self.client_id()
            || redirect_uri != self.redirect_uri()
            || resource != self.resource()
            || !self.challenge().verify(verifier)
        {
            return Err(CodeGrantError::InvalidRedemption);
        }
        checked_context(
            &self.context,
            &self.source_hash,
            &self.browser_hash,
            config,
            server_now_ms,
        )?;
        Ok(())
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::oauth::{
        authorization::validate_authorization_request, consent::ConsentOutcome,
        context::tests::fixture as verified_fixture, store::MemoryTransactionStore,
    };
    use std::{
        sync::Arc,
        time::{SystemTime, UNIX_EPOCH},
    };

    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const CLIENT: &str = "desktop";
    const CALLBACK: &str = "http://127.0.0.1:49152/cb";
    const RESOURCE: &str = "https://mcp.example.org/mcp";

    pub(in crate::oauth) async fn approved(
        tx_ttl: u64,
        age: u64,
    ) -> (OAuthConfig, TransactionId, ConsentedAuthorization, u64) {
        let (mut cfg, _, identity) = verified_fixture().await;
        cfg.authorization_transaction_ttl_seconds = tx_ttl;
        cfg.max_authentication_age_seconds = age;
        cfg.clients[0].application_type = crate::config::oauth::ApplicationType::Native;
        cfg.clients[0].redirect_uris = vec![CALLBACK.into()];
        let store = MemoryTransactionStore::new(Arc::new(cfg.clone())).unwrap();
        let request = validate_authorization_request(&cfg, b"client_id=desktop&redirect_uri=http://127.0.0.1:49152/cb&response_type=code&resource=https://mcp.example.org/mcp&scope=read&state=opaque%2Bclient&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256").unwrap();
        let created = store.create(request, [7; 32]).await.unwrap();
        let witness = store.lookup_bound(&created.id, &[7; 32]).await.unwrap();
        let now = identity.verified_at_ms();
        let context =
            AuthenticatedAuthorization::new_bound(witness, identity, &[7; 32], &cfg, now).unwrap();
        store
            .promote_authenticated(&created.id, &[7; 32], context)
            .await
            .unwrap();
        let token = store.prepare_consent(&created.id, &[7; 32]).await.unwrap();
        let ConsentOutcome::Approved(approval) = store
            .decide_consent(&created.id, &[7; 32], token.as_secret_str(), "approve")
            .await
            .unwrap()
        else {
            panic!("explicit approval required");
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        (cfg, created.id, *approval, now)
    }

    #[tokio::test]
    async fn private_codec_round_trip_bounds_and_expiry_tightening() {
        let (mut cfg, id, approval, now) = approved(300, 300).await;
        let grant = CodeGrant::from_consent(approval, &cfg, &id, &[7; 32], now).unwrap();
        let bytes = grant.encode().unwrap();
        let dto: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let mut fields: Vec<_> = dto
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        fields.sort_unstable();
        assert_eq!(
            fields,
            [
                "browser_hash",
                "context",
                "expires_at_ms",
                "issued_at_ms",
                "source_hash",
                "version"
            ]
        );
        let restored = CodeGrant::decode(&bytes, &cfg, now).unwrap();
        assert_eq!(restored.encode().unwrap(), bytes);
        assert_eq!(restored.state(), Some("opaque+client"));
        assert_eq!(restored.as_user().roles, ["reader", "member"]);
        assert_eq!(restored.scopes(), ["read"]);
        assert_eq!(
            restored.validate_redemption(CLIENT, CALLBACK, RESOURCE, VERIFIER, &cfg, now),
            Ok(())
        );
        let context: serde_json::Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(dto["context"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
        assert!(context.get("attributes").is_none() && context.get("scopes").is_none());
        assert!(!String::from_utf8(bytes.clone()).unwrap().contains(VERIFIER));
        let mut context_bytes = serde_json::to_vec(&context).unwrap();
        context_bytes.resize(MAX_AUTHENTICATED_CONTEXT_BYTES, b' ');
        let mut boundary = dto;
        boundary["context"] = serde_json::json!(URL_SAFE_NO_PAD.encode(&context_bytes));
        let boundary = serde_json::to_vec(&boundary).unwrap();
        assert!(CodeGrant::decode(&boundary, &cfg, now).is_ok());
        let mut padded = bytes.clone();
        padded.resize(MAX_CODE_GRANT_BYTES, b' ');
        assert!(CodeGrant::decode(&padded, &cfg, now).is_ok());
        padded.push(b' ');
        assert_eq!(
            CodeGrant::decode(&padded, &cfg, now).err(),
            Some(CodeGrantError::TooLarge)
        );
        cfg.authorization_code_ttl_seconds = 30;
        let tightened = CodeGrant::decode(&bytes, &cfg, now).unwrap();
        assert_eq!(tightened.expires_at_ms(), now + 30_000);
        assert_eq!(
            CodeGrant::decode(&bytes, &cfg, now + 30_000).err(),
            Some(CodeGrantError::Expired)
        );
        cfg.authorization_code_ttl_seconds = 300;
        assert_eq!(
            CodeGrant::decode(&bytes, &cfg, now)
                .unwrap()
                .expires_at_ms(),
            grant.expires_at_ms()
        );
        assert_eq!(
            CodeGrant::decode(&tightened.encode().unwrap(), &cfg, now)
                .unwrap()
                .expires_at_ms(),
            tightened.expires_at_ms()
        );
        cfg.max_authentication_age_seconds = 1;
        assert_eq!(
            CodeGrant::decode(&bytes, &cfg, now)
                .unwrap()
                .expires_at_ms(),
            grant.verified_at_ms() + 1000
        );
    }

    #[tokio::test]
    async fn private_codec_rejects_shape_context_binding_and_time_metadata() {
        use CodeGrantError::*;
        let (cfg, id, approval, now) = approved(300, 300).await;
        let grant = CodeGrant::from_consent(approval, &cfg, &id, &[7; 32], now).unwrap();
        let original: serde_json::Value = serde_json::from_slice(&grant.encode().unwrap()).unwrap();
        for (field, value, expected) in [
            ("version", serde_json::json!(2), UnsupportedVersion),
            ("approved", serde_json::json!(true), InvalidRecord),
            (
                "source_hash",
                serde_json::json!([8; 32].to_vec()),
                InvalidContext,
            ),
            (
                "browser_hash",
                serde_json::json!([8; 32].to_vec()),
                InvalidContext,
            ),
            ("issued_at_ms", serde_json::json!(0), InvalidRecord),
            ("issued_at_ms", serde_json::json!(now + 1), InvalidTime),
            ("expires_at_ms", serde_json::json!(now), InvalidRecord),
            (
                "expires_at_ms",
                serde_json::json!(now + 300_001),
                InvalidRecord,
            ),
            (
                "expires_at_ms",
                serde_json::json!(253402300800000_u64),
                InvalidRecord,
            ),
            ("context", serde_json::json!("e30="), InvalidRecord),
            ("context", serde_json::json!("e31"), InvalidRecord),
            (
                "context",
                serde_json::json!(
                    "A".repeat((MAX_AUTHENTICATED_CONTEXT_BYTES * 4).div_ceil(3) + 1)
                ),
                TooLarge,
            ),
        ] {
            let mut dto = original.clone();
            dto[field] = value;
            assert_eq!(
                CodeGrant::decode(&serde_json::to_vec(&dto).unwrap(), &cfg, now).err(),
                Some(expected)
            );
        }
        let mut dto = original.clone();
        dto.as_object_mut().unwrap().remove("source_hash");
        assert_eq!(
            CodeGrant::decode(&serde_json::to_vec(&dto).unwrap(), &cfg, now).err(),
            Some(InvalidRecord)
        );
        let mut context: serde_json::Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(original["context"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
        context["attributes"] = serde_json::json!({"approved": true});
        dto = original;
        dto["context"] =
            serde_json::json!(URL_SAFE_NO_PAD.encode(serde_json::to_vec(&context).unwrap()));
        assert_eq!(
            CodeGrant::decode(&serde_json::to_vec(&dto).unwrap(), &cfg, now).err(),
            Some(InvalidContext)
        );
        let bytes = grant.encode().unwrap();
        assert_eq!(
            CodeGrant::decode(&bytes, &cfg, now - 1).err(),
            Some(InvalidTime)
        );
        assert_eq!(
            CodeGrant::decode(&bytes, &cfg, u64::MAX).err(),
            Some(InvalidTime)
        );
        assert_eq!(
            CodeGrant::decode(&bytes, &cfg, grant.expires_at_ms()).err(),
            Some(Expired)
        );
    }

    #[tokio::test]
    async fn loopback_any_port_registration_still_requires_exact_redemption_callback() {
        let (mut cfg, id, approval, now) = approved(300, 300).await;
        let grant = CodeGrant::from_consent(approval, &cfg, &id, &[7; 32], now).unwrap();
        cfg.clients[0].redirect_uris = vec!["http://127.0.0.1/cb".into()];
        let restored = CodeGrant::decode(&grant.encode().unwrap(), &cfg, now).unwrap();
        assert_eq!(restored.redirect_uri(), CALLBACK);
        assert!(
            restored
                .validate_redemption(CLIENT, CALLBACK, RESOURCE, VERIFIER, &cfg, now)
                .is_ok()
        );
        for other in [
            "http://127.0.0.1:49153/cb",
            "http://127.0.0.1/cb",
            "http://localhost:49152/cb",
        ] {
            assert_eq!(
                restored
                    .validate_redemption(CLIENT, other, RESOURCE, VERIFIER, &cfg, now)
                    .err(),
                Some(CodeGrantError::InvalidRedemption),
                "{other}"
            );
        }
    }

    #[tokio::test]
    async fn private_codec_rechecks_registry_policy_and_original_transaction_ceiling() {
        let (cfg, id, approval, now) = approved(30, 300).await;
        let grant = CodeGrant::from_consent(approval, &cfg, &id, &[7; 32], now).unwrap();
        let bytes = grant.encode().unwrap();
        for case in 0..3 {
            let mut changed = cfg.clone();
            match case {
                0 => changed.clients[0].client_id = "other".into(),
                1 => {
                    changed.clients[0].redirect_uris =
                        vec!["https://app.example.org/removed".into()]
                }
                _ => changed.resources[0].scopes[0]
                    .required_roles
                    .push("revoked".into()),
            }
            assert_eq!(
                CodeGrant::decode(&bytes, &changed, now).err(),
                Some(CodeGrantError::InvalidContext)
            );
        }
        let mut dto: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        dto["expires_at_ms"] = serde_json::json!(now + 60_000);
        assert_eq!(
            CodeGrant::decode(&serde_json::to_vec(&dto).unwrap(), &cfg, now).err(),
            Some(CodeGrantError::InvalidRecord)
        );
    }

    #[tokio::test]
    async fn approval_metadata_and_deadline_minima_survive_policy_relaxation() {
        for (tx_ttl, age, code_ttl, current_age) in [
            (30, 300, 60, 3600),
            (300, 300, 30, 3600),
            (300, 1, 60, 3600),
            (300, 300, 60, 1),
        ] {
            let (mut cfg, id, approval, now) = approved(tx_ttl, age).await;
            let ceiling = approval.expires_at_ms();
            let verified = approval.verified_at_ms();
            cfg.max_authentication_age_seconds = current_age;
            cfg.authorization_code_ttl_seconds = code_ttl;
            let grant = CodeGrant::from_consent(approval, &cfg, &id, &[7; 32], now).unwrap();
            assert_eq!(
                grant.expires_at_ms(),
                ceiling
                    .min(now + code_ttl * 1000)
                    .min(verified + current_age * 1000)
            );
            assert_eq!(grant.issued_at_ms(), now);
            assert_eq!(grant.verified_at_ms(), verified);
            assert_eq!(grant.as_user().username, "alice");
            assert_eq!(grant.as_user().roles, ["reader", "member"]);
            assert_eq!(grant.scopes(), ["read"]);
            assert_eq!(grant.client_id(), CLIENT);
            assert_eq!(grant.redirect_uri(), CALLBACK);
            assert_eq!(grant.resource(), RESOURCE);
            assert_eq!(grant.state(), Some("opaque+client"));
            assert!(grant.context.matches_source(&id.hash()));
            assert!(
                grant
                    .validate_redemption(CLIENT, CALLBACK, RESOURCE, VERIFIER, &cfg, now)
                    .is_ok()
            );
        }
    }

    #[tokio::test]
    async fn construction_rejects_source_binding_policy_time_and_expired_approval() {
        for case in 0..7 {
            let (mut cfg, id, approval, mut now) = approved(300, 300).await;
            let other = TransactionId::generate().unwrap();
            let mut binding = [7; 32];
            let expected = match case {
                0 => CodeGrantError::InvalidContext,
                1 => {
                    binding = [8; 32];
                    CodeGrantError::InvalidContext
                }
                2 => {
                    cfg.resources[0].scopes[0]
                        .required_roles
                        .push("revoked".into());
                    CodeGrantError::InvalidContext
                }
                3 => {
                    now = approval.expires_at_ms();
                    CodeGrantError::Expired
                }
                4 => {
                    now = u64::MAX;
                    CodeGrantError::InvalidTime
                }
                5 => {
                    now = 253402300799999;
                    CodeGrantError::InvalidTime
                }
                _ => {
                    cfg.authorization_code_ttl_seconds = 301;
                    CodeGrantError::Configuration
                }
            };
            assert_eq!(
                CodeGrant::from_consent(
                    approval,
                    &cfg,
                    if case == 0 { &other } else { &id },
                    &binding,
                    now
                )
                .err(),
                Some(expected)
            );
        }
    }

    #[tokio::test]
    async fn redemption_requires_exact_inputs_current_policy_and_strict_time_without_consumption() {
        let (cfg, id, approval, now) = approved(300, 300).await;
        let grant = CodeGrant::from_consent(approval, &cfg, &id, &[7; 32], now).unwrap();
        for (client, callback, resource, verifier) in [
            ("other", CALLBACK, RESOURCE, VERIFIER),
            (CLIENT, "http://127.0.0.1:49152/CB", RESOURCE, VERIFIER),
            (CLIENT, "http://127.0.0.1:49153/cb", RESOURCE, VERIFIER),
            (CLIENT, CALLBACK, "", VERIFIER),
            (CLIENT, CALLBACK, RESOURCE, "short"),
            (CLIENT, CALLBACK, RESOURCE, &"x".repeat(129)),
            (CLIENT, CALLBACK, RESOURCE, &"!".repeat(43)),
            (CLIENT, CALLBACK, RESOURCE, &"x".repeat(43)),
        ] {
            assert_eq!(
                grant.validate_redemption(client, callback, resource, verifier, &cfg, now),
                Err(CodeGrantError::InvalidRedemption)
            );
        }
        let check = |cfg: &OAuthConfig, at| {
            grant.validate_redemption(CLIENT, CALLBACK, RESOURCE, VERIFIER, cfg, at)
        };
        assert_eq!(check(&cfg, now - 1), Err(CodeGrantError::InvalidTime));
        assert_eq!(check(&cfg, u64::MAX), Err(CodeGrantError::InvalidTime));
        assert_eq!(
            check(&cfg, grant.expires_at_ms()),
            Err(CodeGrantError::Expired)
        );
        for case in 0..4 {
            let mut changed = cfg.clone();
            match case {
                0 => {
                    changed.clients[0].redirect_uris = vec!["https://app.example.org/other".into()]
                }
                1 => changed.clients[0].resources.clear(),
                2 => changed.resources[0].scopes[0]
                    .required_roles
                    .push("revoked".into()),
                _ => changed.max_authentication_age_seconds = 1,
            }
            let at = if case == 3 {
                grant.verified_at_ms() + 1000
            } else {
                now
            };
            assert_eq!(check(&changed, at), Err(CodeGrantError::InvalidContext));
        }
        assert_eq!(check(&cfg, now), Ok(()));
        assert_eq!(check(&cfg, now), Ok(()));
    }
}

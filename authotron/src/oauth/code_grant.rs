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
    context::AuthenticatedAuthorization,
    records::valid_time,
    store::TransactionId,
};
use crate::{config::OAuthConfig, models::user::User};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeGrantError {
    Configuration,
    InvalidTime,
    InvalidContext,
    Expired,
    InvalidRedemption,
}

/// Owned approval snapshot: no Debug, Clone, serde or raw-identity constructor.
pub struct CodeGrant {
    context: AuthenticatedAuthorization,
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
mod tests {
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

    async fn approved(
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

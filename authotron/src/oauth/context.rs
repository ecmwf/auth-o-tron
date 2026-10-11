// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! Fresh, browser-bound policy eligibility for later consent; no grant or code issuance.

use super::{
    authentication::VerifiedOAuthIdentity,
    records::{AuthorizationTransaction, valid_time},
};
use crate::{config::OAuthConfig, models::user::User};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextError {
    Configuration,
    InvalidTime,
    InvalidTransaction,
    Binding,
    StaleIdentity,
    AccessDenied,
}

/// Owns opaque verification proof and validated input. No Debug, Clone or serialization.
pub struct AuthenticatedAuthorization {
    transaction: AuthorizationTransaction,
    identity: VerifiedOAuthIdentity,
    scopes: Vec<String>,
    expires_at_ms: u64,
}
impl AuthenticatedAuthorization {
    /// Server supplies trusted time and binding; callers still enforce Origin/CSRF.
    /// Check the bound transaction before credential verification and use coherent
    /// verification-state/config snapshots; this constructor cannot establish that linkage.
    /// This checks policy eligibility now, not consent or future issuance eligibility.
    pub fn new(
        transaction: AuthorizationTransaction,
        identity: VerifiedOAuthIdentity,
        browser_hash: &[u8; 32],
        config: &OAuthConfig,
        server_now_ms: u64,
    ) -> Result<Self, ContextError> {
        use ContextError::*;
        config.validate().map_err(|_| Configuration)?;
        let verified_at = identity.verified_at_ms();
        if !valid_time(server_now_ms) || !valid_time(verified_at) {
            return Err(InvalidTime);
        }
        let transaction = AuthorizationTransaction::decode(
            &transaction.encode().map_err(|_| InvalidTransaction)?,
            config,
            server_now_ms,
        )
        .map_err(|_| InvalidTransaction)?;
        if !transaction.matches_browser_binding(browser_hash) {
            return Err(Binding);
        }
        let skew = config
            .authentication_clock_skew_seconds
            .checked_mul(1000)
            .ok_or(InvalidTime)?;
        if verified_at.saturating_sub(server_now_ms) > skew {
            return Err(StaleIdentity);
        }
        let fresh_until = config
            .max_authentication_age_seconds
            .checked_mul(1000)
            .and_then(|age| verified_at.checked_add(age))
            .filter(|time| valid_time(*time))
            .ok_or(InvalidTime)?;
        if server_now_ms >= fresh_until {
            return Err(StaleIdentity);
        }
        let request = transaction.request();
        let scopes = config
            .authorize_scopes(
                request.client_id(),
                request.resource(),
                request.scopes(),
                identity.as_user(),
            )
            .map_err(|_| AccessDenied)?
            .0;
        let expires_at_ms = transaction.expires_at_ms().min(fresh_until);
        Ok(Self {
            transaction,
            identity,
            scopes,
            expires_at_ms,
        })
    }
    pub fn transaction(&self) -> &AuthorizationTransaction {
        &self.transaction
    }
    pub fn as_user(&self) -> &User {
        self.identity.as_user()
    }
    pub fn verified_at_ms(&self) -> u64 {
        self.identity.verified_at_ms()
    }
    /// Eligible scopes only; this accessor conveys no consent decision.
    pub fn authorized_scopes(&self) -> &[String] {
        &self.scopes
    }
    pub fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        auth::Auth,
        browser::{BrowserCredentials, BrowserLoginState},
        config::ConfigV2,
        metrics::Metrics,
        oauth::{authentication::verify_identity, authorization::validate_authorization_request},
        store::no_store::NoStore,
    };
    use serde_json::json;
    use std::sync::Arc;

    async fn fixture() -> (OAuthConfig, AuthorizationTransaction, VerifiedOAuthIdentity) {
        let config: ConfigV2 = serde_json::from_value(json!({"store": {"enabled": false}, "services": [], "augmenters": [],
            "providers": [{"type": "plain", "name": "basic", "realm": "local", "users": [{"username": "alice", "password": "päss:秘密", "roles": ["reader", "member"]}]}],
            "server": {"port": 0}, "jwt": {"iss": "fixture", "exp": 300, "secret": "fixture-only"}, "logging": {"level": "warn", "format": "console"},
            "ui": {"basic": {"provider_name": "basic"}, "browser_session": {"public_origin": "https://login.example.org", "backend": {"type": "memory"}}},
            "oauth": {"issuer": "https://login.example.org", "clients": [{"client_id": "desktop", "display_name": "Desktop", "redirect_uris": ["https://app.example.org/cb"], "resources": [{"resource": "https://mcp.example.org/mcp", "scopes": ["read"]}]}],
            "resources": [{"resource": "https://mcp.example.org/mcp", "allowed_realms": ["local"], "scopes": [{"name": "read", "required_roles": ["reader", "member"]}]}]}
        })).unwrap();
        let browser = BrowserLoginState::new(&config).unwrap();
        let auth = Auth::new(&config.providers, &[], Arc::new(NoStore), config.auth);
        let identity = verify_identity(
            BrowserCredentials::Basic {
                username: "alice",
                password: "päss:秘密",
            },
            &browser,
            &auth,
            &Metrics::new(),
        )
        .await
        .unwrap();
        let request = validate_authorization_request(&config.oauth, b"client_id=desktop&redirect_uri=https://app.example.org/cb&response_type=code&resource=https://mcp.example.org/mcp&scope=read&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256").unwrap();
        let transaction =
            AuthorizationTransaction::new(request, [7; 32], identity.verified_at_ms() + 300000)
                .unwrap();
        (*config.oauth, transaction, identity)
    }
    #[tokio::test]
    async fn context_owns_real_proof_and_bounds_eligibility_to_freshness_and_transaction() {
        let (mut config, transaction, identity) = fixture().await;
        config.max_authentication_age_seconds = 1;
        let verified = identity.verified_at_ms();
        let context = AuthenticatedAuthorization::new(
            transaction,
            identity,
            &[7; 32],
            &config,
            verified + 999,
        )
        .unwrap();
        assert_eq!(context.as_user().username, "alice");
        assert_eq!(context.as_user().realm, "local");
        assert_eq!(context.as_user().roles, ["reader", "member"]);
        assert!(context.as_user().attributes.is_empty() && context.as_user().scopes.is_empty());
        assert_eq!(context.authorized_scopes(), &["read"]);
        assert_eq!(context.verified_at_ms(), verified);
        assert_eq!(context.expires_at_ms(), verified + 1000);
        assert_eq!(context.transaction().request().client_id(), "desktop");
        let (mut config, transaction, identity) = fixture().await;
        config.max_authentication_age_seconds = 3600;
        let expiry = transaction.expires_at_ms();
        let now = identity.verified_at_ms();
        assert_eq!(
            AuthenticatedAuthorization::new(transaction, identity, &[7; 32], &config, now)
                .unwrap()
                .expires_at_ms(),
            expiry
        );
    }
    #[tokio::test]
    async fn age_boundary_and_future_skew_are_exact_without_grace_on_age() {
        for (age, skew, offset, accepted) in [
            (1, 30, 1000i64, false),
            (300, 30, -30000, true),
            (300, 30, -30001, false),
            (300, 0, -1, false),
        ] {
            let (mut config, transaction, identity) = fixture().await;
            config.max_authentication_age_seconds = age;
            config.authentication_clock_skew_seconds = skew;
            let now = identity
                .verified_at_ms()
                .checked_add_signed(offset)
                .unwrap();
            let result =
                AuthenticatedAuthorization::new(transaction, identity, &[7; 32], &config, now);
            if accepted {
                assert!(result.is_ok());
            } else {
                assert_eq!(result.err(), Some(ContextError::StaleIdentity));
            }
        }
    }
    #[tokio::test]
    async fn changed_requests_binding_time_and_role_policy_fail_closed() {
        use ContextError::*;
        for (case, expected) in [
            ("binding", Binding),
            ("callback", InvalidTransaction),
            ("unbound", InvalidTransaction),
            ("role", AccessDenied),
            ("realm", AccessDenied),
            ("expired", InvalidTransaction),
            ("time", InvalidTime),
            ("config", Configuration),
        ] {
            let (mut config, transaction, identity) = fixture().await;
            let mut hash = [7; 32];
            let mut now = identity.verified_at_ms();
            match case {
                "binding" => hash = [8; 32],
                "callback" => {
                    config.clients[0].redirect_uris[0] = "https://other.example.org/cb".into()
                }
                "unbound" => config.clients[0].resources.clear(),
                "role" => config.resources[0].scopes[0]
                    .required_roles
                    .push("absent".into()),
                "realm" => config.resources[0].allowed_realms = vec!["other".into()],
                "expired" => now = transaction.expires_at_ms(),
                "time" => now = u64::MAX,
                _ => config.max_authentication_age_seconds = 0,
            }
            assert_eq!(
                AuthenticatedAuthorization::new(transaction, identity, &hash, &config, now).err(),
                Some(expected),
                "{case}"
            );
        }
    }
}

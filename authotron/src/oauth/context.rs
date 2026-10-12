// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! Fresh, browser-bound policy eligibility for later consent; no grant or code issuance.

use super::{
    authentication::{AuthenticationError, VerifiedOAuthIdentity, restore_from_trusted_storage},
    records::{
        AuthorizationTransaction, BoundAuthorizationTransaction, MAX_TRANSACTION_BYTES, valid_time,
    },
};
use crate::{
    config::{OAuthConfig, OAuthPolicyError},
    models::user::User,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

pub(super) const MAX_AUTHENTICATED_CONTEXT_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextError {
    Configuration,
    InvalidTime,
    InvalidTransaction,
    Binding,
    StaleIdentity,
    AccessDenied,
    TooLarge,
    InvalidRecord,
    UnsupportedVersion,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContextDto {
    version: u8,
    username: String,
    realm: String,
    roles: Vec<String>,
    provider_roles: Vec<String>,
    method: String,
    verified_at_ms: u64,
    transaction: String,
    source_transaction_id_hash: Option<[u8; 32]>,
}

/// Owns verification proof/snapshot and validated input. No Debug, Clone or public serialization.
pub struct AuthenticatedAuthorization {
    transaction: AuthorizationTransaction,
    identity: VerifiedOAuthIdentity,
    scopes: Vec<String>,
    expires_at_ms: u64,
    source_transaction_id_hash: Option<[u8; 32]>,
}
impl AuthenticatedAuthorization {
    /// Bind only from a successful store lookup, not a caller-selected identifier tag.
    pub fn new_bound(
        source: BoundAuthorizationTransaction,
        identity: VerifiedOAuthIdentity,
        browser_hash: &[u8; 32],
        config: &OAuthConfig,
        server_now_ms: u64,
    ) -> Result<Self, ContextError> {
        let (transaction, hash) = source.into_parts();
        let mut context = Self::new(transaction, identity, browser_hash, config, server_now_ms)?;
        context.source_transaction_id_hash = Some(hash);
        Ok(context)
    }
    pub(super) fn matches_source(&self, transaction_id_hash: &[u8; 32]) -> bool {
        self.source_transaction_id_hash
            .as_ref()
            .is_some_and(|hash| bool::from(hash.ct_eq(transaction_id_hash)))
    }
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
        Self::preflight(&identity, config, server_now_ms)?;
        let transaction = AuthorizationTransaction::decode(
            &transaction
                .encode()
                .map_err(|_| ContextError::InvalidTransaction)?,
            config,
            server_now_ms,
        )
        .map_err(|_| ContextError::InvalidTransaction)?;
        let (scopes, expires_at_ms) =
            Self::evaluate(&transaction, &identity, browser_hash, config, server_now_ms)?;
        Ok(Self {
            transaction,
            identity,
            scopes,
            expires_at_ms,
            source_transaction_id_hash: None,
        })
    }
    fn preflight(
        identity: &VerifiedOAuthIdentity,
        config: &OAuthConfig,
        server_now_ms: u64,
    ) -> Result<(), ContextError> {
        config.validate().map_err(|_| ContextError::Configuration)?;
        if !valid_time(server_now_ms) || !valid_time(identity.verified_at_ms()) {
            return Err(ContextError::InvalidTime);
        }
        Ok(())
    }
    /// Checks binding, freshness and current scope policy for a transaction already
    /// validated against `config` at `server_now_ms`; returns eligible scopes and expiry.
    fn evaluate(
        transaction: &AuthorizationTransaction,
        identity: &VerifiedOAuthIdentity,
        browser_hash: &[u8; 32],
        config: &OAuthConfig,
        server_now_ms: u64,
    ) -> Result<(Vec<String>, u64), ContextError> {
        use ContextError::*;
        Self::preflight(identity, config, server_now_ms)?;
        let verified_at = identity.verified_at_ms();
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
        let fresh_until = fresh_until(verified_at, config)?;
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
            .map_err(policy_error)?
            .0;
        Ok((scopes, transaction.expires_at_ms().min(fresh_until)))
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
    pub fn provider_roles(&self) -> &[String] {
        self.identity.provider_roles()
    }
    pub fn method(&self) -> &str {
        self.identity.method()
    }
    /// Eligible scopes only; this accessor conveys no consent decision.
    pub fn authorized_scopes(&self) -> &[String] {
        &self.scopes
    }
    pub fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }
    pub(super) fn encode(&self) -> Result<Vec<u8>, ContextError> {
        let user = self.as_user();
        let transaction = self
            .transaction
            .encode()
            .map_err(|_| ContextError::InvalidTransaction)?;
        let dto = ContextDto {
            version: 4,
            username: user.username.clone(),
            realm: user.realm.clone(),
            roles: user.roles.clone(),
            provider_roles: self.provider_roles().to_vec(),
            method: self.method().into(),
            verified_at_ms: self.verified_at_ms(),
            transaction: URL_SAFE_NO_PAD.encode(transaction),
            source_transaction_id_hash: self.source_transaction_id_hash,
        };
        let bytes = serde_json::to_vec(&dto).map_err(|_| ContextError::InvalidRecord)?;
        if bytes.len() > MAX_AUTHENTICATED_CONTEXT_BYTES {
            return Err(ContextError::TooLarge);
        }
        Ok(bytes)
    }
    /// Trusted storage only, not request JSON or a MAC. Restores verification-time roles;
    /// current eligibility is rechecked, but live upstream revocation is not queried.
    pub(super) fn decode(
        bytes: &[u8],
        config: &OAuthConfig,
        browser_hash: &[u8; 32],
        server_now_ms: u64,
    ) -> Result<Self, ContextError> {
        let (transaction, identity, source) = decode_parts(bytes, config, server_now_ms)?;
        let mut context = Self::new(transaction, identity, browser_hash, config, server_now_ms)?;
        // This field is authoritative only across the explicitly trusted-storage boundary.
        context.source_transaction_id_hash = source;
        Ok(context)
    }
    /// Distinguishes a well-formed, browser-bound record whose verified identity no longer
    /// satisfies the current scope policy from storage corruption. Returns the stored
    /// transaction and the expiry an eligible context would have had, only for
    /// `AccessDenied`; any other failure is reported unchanged, and an eligible record
    /// yields `Ok(None)`. The source hash must match `transaction_id_hash`.
    pub(super) fn policy_denied_transaction(
        bytes: &[u8],
        config: &OAuthConfig,
        browser_hash: &[u8; 32],
        transaction_id_hash: &[u8; 32],
        server_now_ms: u64,
    ) -> Result<Option<(AuthorizationTransaction, u64)>, ContextError> {
        let (transaction, identity, source) = decode_parts(bytes, config, server_now_ms)?;
        if !source.is_some_and(|hash| bool::from(hash.ct_eq(transaction_id_hash))) {
            return Err(ContextError::InvalidRecord);
        }
        // `decode_parts` already validated the transaction against `config` and `now`.
        match Self::evaluate(&transaction, &identity, browser_hash, config, server_now_ms) {
            Ok(_) => Ok(None),
            Err(ContextError::AccessDenied) => {
                let bound = fresh_until(identity.verified_at_ms(), config)?
                    .min(transaction.expires_at_ms());
                Ok(Some((transaction, bound)))
            }
            Err(error) => Err(error),
        }
    }
}

fn fresh_until(verified_at_ms: u64, config: &OAuthConfig) -> Result<u64, ContextError> {
    config
        .max_authentication_age_seconds
        .checked_mul(1000)
        .and_then(|age| verified_at_ms.checked_add(age))
        .filter(|time| valid_time(*time))
        .ok_or(ContextError::InvalidTime)
}

/// Only a scope-policy denial becomes `AccessDenied` (an `access_denied` redirect);
/// configuration or request drift stays a local 503/400-class error.
fn policy_error(error: OAuthPolicyError) -> ContextError {
    match error {
        OAuthPolicyError::AccessDenied => ContextError::AccessDenied,
        OAuthPolicyError::InvalidConfiguration => ContextError::Configuration,
        OAuthPolicyError::InvalidClient
        | OAuthPolicyError::InvalidResource
        | OAuthPolicyError::InvalidScope => ContextError::InvalidTransaction,
    }
}

type ContextParts = (
    AuthorizationTransaction,
    VerifiedOAuthIdentity,
    Option<[u8; 32]>,
);

/// Structural decode shared by full restoration and policy classification.
fn decode_parts(
    bytes: &[u8],
    config: &OAuthConfig,
    server_now_ms: u64,
) -> Result<ContextParts, ContextError> {
    use ContextError::*;
    if bytes.len() > MAX_AUTHENTICATED_CONTEXT_BYTES {
        return Err(TooLarge);
    }
    let dto: ContextDto = serde_json::from_slice(bytes).map_err(|_| InvalidRecord)?;
    if dto.version != 4 {
        return Err(UnsupportedVersion);
    }
    if dto.transaction.len() > (MAX_TRANSACTION_BYTES * 4).div_ceil(3) {
        return Err(TooLarge);
    }
    let transaction = URL_SAFE_NO_PAD
        .decode(&dto.transaction)
        .map_err(|_| InvalidRecord)?;
    if transaction.len() > MAX_TRANSACTION_BYTES {
        return Err(TooLarge);
    }
    if URL_SAFE_NO_PAD.encode(&transaction) != dto.transaction {
        return Err(InvalidRecord);
    }
    let transaction = AuthorizationTransaction::decode(&transaction, config, server_now_ms)
        .map_err(|_| InvalidTransaction)?;
    let identity = restore_from_trusted_storage(
        dto.username,
        dto.realm,
        dto.roles,
        dto.provider_roles,
        dto.method,
        dto.verified_at_ms,
    )
    .map_err(|error| match error {
        AuthenticationError::Unavailable => InvalidTime,
        _ => InvalidRecord,
    })?;
    Ok((transaction, identity, dto.source_transaction_id_hash))
}

#[cfg(test)]
pub(super) mod tests {
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

    pub(in crate::oauth) async fn fixture()
    -> (OAuthConfig, AuthorizationTransaction, VerifiedOAuthIdentity) {
        let config: ConfigV2 = serde_json::from_value(json!({"store": {"enabled": false}, "services": [], "augmenters": [],
            "providers": [{"type": "plain", "name": "basic", "realm": "local", "users": [{"username": "alice", "password": "päss:秘密", "roles": ["reader", "member"]}], "browser": {"id": "password", "label": "Password"}}],
            "server": {"port": 0}, "jwt": {"iss": "fixture", "exp": 300, "secret": "fixture-only"}, "logging": {"level": "warn", "format": "console"},
            "ui": {"browser_session": {"public_origin": "https://login.example.org", "backend": {"type": "memory"}}},
            "oauth": {"issuer": "https://login.example.org", "clients": [{"client_id": "desktop", "display_name": "Desktop", "redirect_uris": ["https://app.example.org/cb"], "resources": [{"resource": "https://mcp.example.org/mcp", "scopes": ["read"]}]}],
            "resources": [{"resource": "https://mcp.example.org/mcp", "allowed_realms": ["local"], "scopes": [{"name": "read", "required_roles": ["reader", "member"]}]}]}
        })).unwrap();
        let browser = BrowserLoginState::new(&config).unwrap();
        let auth = Auth::new(&config.providers, &[], Arc::new(NoStore), config.auth);
        let identity = verify_identity(
            "password",
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
    async fn private_codec_round_trips_and_recomputes_policy_and_expiry() {
        let (mut config, transaction, identity) = fixture().await;
        let now = identity.verified_at_ms();
        let context =
            AuthenticatedAuthorization::new(transaction, identity, &[7; 32], &config, now).unwrap();
        let bytes = context.encode().unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let mut names = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>();
        names.sort_unstable();
        assert_eq!(
            names.join(" "),
            "method provider_roles realm roles source_transaction_id_hash transaction username verified_at_ms version"
        );
        let restored = AuthenticatedAuthorization::decode(&bytes, &config, &[7; 32], now).unwrap();
        assert_eq!(restored.encode().unwrap(), bytes);
        assert!(restored.as_user().attributes.is_empty() && restored.as_user().scopes.is_empty());
        config.max_authentication_age_seconds = 1;
        let restored =
            AuthenticatedAuthorization::decode(&bytes, &config, &[7; 32], now + 999).unwrap();
        assert_eq!(restored.expires_at_ms(), now + 1000);
        assert_eq!(
            AuthenticatedAuthorization::decode(&bytes, &config, &[7; 32], now + 1000).err(),
            Some(ContextError::StaleIdentity)
        );
        config.resources[0].scopes[0]
            .required_roles
            .push("absent".into());
        assert_eq!(
            AuthenticatedAuthorization::decode(&bytes, &config, &[7; 32], now).err(),
            Some(ContextError::AccessDenied)
        );
    }
    #[tokio::test]
    async fn private_codec_rejects_malformed_snapshots_extensions_and_transactions() {
        use ContextError::*;
        let (config, transaction, identity) = fixture().await;
        let now = identity.verified_at_ms();
        let context =
            AuthenticatedAuthorization::new(transaction, identity, &[7; 32], &config, now).unwrap();
        let bytes = context.encode().unwrap();
        let original: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        for (field, replacement, error) in [
            ("version", json!(5), UnsupportedVersion),
            ("version", json!(3), UnsupportedVersion),
            ("method", json!("Password"), InvalidRecord),
            ("method", json!(""), InvalidRecord),
            ("provider_roles", json!(vec!["reader"; 65]), InvalidRecord),
            ("provider_roles", json!([""]), InvalidRecord),
            ("source_transaction_id_hash", json!([1, 2]), InvalidRecord),
            ("username", json!(" "), InvalidRecord),
            ("realm", json!("local\n"), InvalidRecord),
            ("roles", json!(["x".repeat(129)]), InvalidRecord),
            ("roles", json!(vec!["reader"; 65]), InvalidRecord),
            ("roles", json!([""]), InvalidRecord),
            ("verified_at_ms", json!(u64::MAX), InvalidTime),
            ("verified_at_ms", json!(now + 30001), StaleIdentity),
            ("transaction", json!("%%%"), InvalidRecord),
            (
                "transaction",
                json!(format!("{}=", original["transaction"].as_str().unwrap())),
                InvalidRecord,
            ),
            (
                "transaction",
                json!(URL_SAFE_NO_PAD.encode(b"bad JSON")),
                InvalidTransaction,
            ),
            (
                "transaction",
                json!(URL_SAFE_NO_PAD.encode(vec![b'x'; MAX_TRANSACTION_BYTES + 1])),
                TooLarge,
            ),
            ("attributes", json!({"email": "hidden"}), InvalidRecord),
            ("consent", json!(true), InvalidRecord),
            ("scopes", json!(["read"]), InvalidRecord),
            ("authorized_scopes", json!(["read"]), InvalidRecord),
            ("expires_at_ms", json!(now + 999999), InvalidRecord),
        ] {
            let mut value = original.clone();
            value[field] = replacement;
            assert_eq!(
                AuthenticatedAuthorization::decode(
                    &serde_json::to_vec(&value).unwrap(),
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
        padded.resize(MAX_AUTHENTICATED_CONTEXT_BYTES, b' ');
        assert!(AuthenticatedAuthorization::decode(&padded, &config, &[7; 32], now).is_ok());
        padded.push(b' ');
        assert_eq!(
            AuthenticatedAuthorization::decode(&padded, &config, &[7; 32], now).err(),
            Some(TooLarge)
        );
        assert_eq!(
            AuthenticatedAuthorization::decode(b"\xff", &config, &[7; 32], now).err(),
            Some(InvalidRecord)
        );
        assert_eq!(
            AuthenticatedAuthorization::decode(&bytes, &config, &[8; 32], now).err(),
            Some(Binding)
        );
        assert_eq!(
            AuthenticatedAuthorization::decode(&bytes, &config, &[7; 32], u64::MAX).err(),
            Some(InvalidTransaction)
        );
        let mut revoked = config.clone();
        revoked.clients.clear();
        assert_eq!(
            AuthenticatedAuthorization::decode(&bytes, &revoked, &[7; 32], now).err(),
            Some(InvalidTransaction)
        );
        let mut changed = config.clone();
        changed.clients[0].redirect_uris[0] = "https://other.example.org/cb".into();
        assert_eq!(
            AuthenticatedAuthorization::decode(&bytes, &changed, &[7; 32], now).err(),
            Some(InvalidTransaction)
        );
        assert_eq!(
            AuthenticatedAuthorization::decode(
                &bytes,
                &config,
                &[7; 32],
                context.transaction().expires_at_ms()
            )
            .err(),
            Some(InvalidTransaction)
        );
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
    #[test]
    fn only_policy_access_denied_maps_to_access_denied() {
        use OAuthPolicyError as P;
        assert_eq!(policy_error(P::AccessDenied), ContextError::AccessDenied);
        assert_eq!(
            policy_error(P::InvalidConfiguration),
            ContextError::Configuration
        );
        for error in [P::InvalidClient, P::InvalidResource, P::InvalidScope] {
            assert_eq!(policy_error(error), ContextError::InvalidTransaction);
        }
    }
    #[tokio::test]
    async fn policy_denied_transaction_returns_stored_transaction_without_round_trip() {
        let (mut config, transaction, identity) = fixture().await;
        let now = identity.verified_at_ms();
        let mut context =
            AuthenticatedAuthorization::new(transaction, identity, &[7; 32], &config, now).unwrap();
        context.source_transaction_id_hash = Some([3; 32]);
        let bytes = context.encode().unwrap();
        assert!(
            AuthenticatedAuthorization::policy_denied_transaction(
                &bytes, &config, &[7; 32], &[3; 32], now
            )
            .unwrap()
            .is_none()
        );
        config.resources[0].scopes[0]
            .required_roles
            .push("absent".into());
        let denied = AuthenticatedAuthorization::policy_denied_transaction(
            &bytes, &config, &[7; 32], &[3; 32], now,
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            denied.0.encode().unwrap(),
            context.transaction().encode().unwrap()
        );
        assert_eq!(denied.1, context.expires_at_ms());
        assert_eq!(
            AuthenticatedAuthorization::policy_denied_transaction(
                &bytes, &config, &[7; 32], &[4; 32], now
            )
            .err(),
            Some(ContextError::InvalidRecord)
        );
        assert_eq!(
            AuthenticatedAuthorization::policy_denied_transaction(
                &bytes, &config, &[8; 32], &[3; 32], now
            )
            .err(),
            Some(ContextError::Binding)
        );
    }
}

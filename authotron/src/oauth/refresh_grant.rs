// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! Refresh-token issuance at code exchange, the `refresh_token` grant and RFC 7009
//! revocation. Every refresh re-runs augmentation and current policy before rotating.

use super::{
    authentication::projection,
    refresh::{
        EndedUpstream, Presented, RefreshGrant, RefreshStoreError, RefreshToken, Revocation,
        Rotated, effective_absolute,
    },
    refresh_store::MemoryRefreshStore,
    runtime::OAuthRuntime,
    store::RedeemedAuthorization,
    tokens::{TokenError, TokenIssuer, TokenResponse},
    valkey_refresh::ValkeyRefreshStore,
};
use crate::{
    auth::Auth,
    browser::{BrowserLoginState, BrowserMethod},
    config::{OAuthPolicyError, RefreshTokenPolicy},
    metrics::{Metrics, RefreshTokenEvent},
    models::user::User,
};

pub(crate) enum RefreshBackend {
    Memory(Box<MemoryRefreshStore>),
    Valkey(Box<ValkeyRefreshStore>),
}
macro_rules! refresh_dispatch {
    ($backend:expr, $method:ident($($arg:expr),*)) => {
        match $backend {
            RefreshBackend::Memory(store) => store.$method($($arg),*).await,
            RefreshBackend::Valkey(store) => store.$method($($arg),*).await,
        }
    };
}

/// Token-endpoint outcomes; mapped to RFC 6749 §5.2 / RFC 8707 error codes by the route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RefreshGrantError {
    InvalidGrant,
    InvalidScope,
    InvalidTarget,
    Unavailable,
}
impl From<RefreshStoreError> for RefreshGrantError {
    fn from(_: RefreshStoreError) -> Self {
        Self::Unavailable
    }
}

pub(crate) struct RefreshRequest<'a> {
    pub token: &'a str,
    pub client_id: &'a str,
    pub scope: Option<&'a str>,
    pub resource: Option<&'a str>,
}

/// Space-delimited scope narrowing (RFC 6749 §6). Valid: `read`, `read write`.
/// Invalid: empty, `read  write` (empty item), ` read`, `read read` (duplicate).
fn narrowed_scopes(
    requested: Option<&str>,
    granted: &[String],
) -> Result<Vec<String>, RefreshGrantError> {
    let Some(requested) = requested else {
        return Ok(granted.to_vec());
    };
    let mut scopes: Vec<String> = Vec::new();
    for scope in requested.split(' ') {
        if scope.is_empty()
            || scopes.iter().any(|s| s == scope)
            || !granted.iter().any(|s| s == scope)
        {
            return Err(RefreshGrantError::InvalidScope);
        }
        scopes.push(scope.into());
    }
    Ok(scopes)
}

/// The client policy with its absolute lifetime capped by the login method's
/// `refresh_max_lifetime_seconds`.
fn method_policy(policy: &RefreshTokenPolicy, method: &BrowserMethod) -> RefreshTokenPolicy {
    let absolute_ttl_seconds = method
        .refresh_max_lifetime_seconds
        .map_or(policy.absolute_ttl_seconds, |cap| {
            cap.min(policy.absolute_ttl_seconds)
        });
    RefreshTokenPolicy {
        absolute_ttl_seconds,
        ..policy.clone()
    }
}

impl OAuthRuntime {
    fn refresh_policy(&self, client_id: &str) -> Option<&RefreshTokenPolicy> {
        self.config
            .clients
            .iter()
            .find(|client| client.client_id == client_id)
            .map(|client| &client.refresh_tokens)
            .filter(|policy| policy.enabled)
    }
    pub(crate) fn refresh_supported(&self) -> bool {
        self.refresh.is_some()
    }
    /// Signs the access token for consumed code proof and, for opted-in clients,
    /// starts a refresh-token family bound to the same client, resource and scopes.
    /// The code is already consumed, so a family that cannot be stored is logged and
    /// counted, and the access token is returned without a `refresh_token`.
    pub(crate) async fn exchange(
        &self,
        proof: RedeemedAuthorization,
        browser: &BrowserLoginState,
        metrics: &Metrics,
    ) -> Result<TokenResponse, RefreshGrantError> {
        let code = proof.grant();
        let grant = RefreshGrant {
            client_id: code.client_id().into(),
            resource: code.resource().into(),
            scopes: code.scopes().to_vec(),
            username: code.as_user().username.clone(),
            realm: code.as_user().realm.clone(),
            provider_roles: code.provider_roles().to_vec(),
            method: code.method().into(),
            upstream_coupled: code.upstream().is_some(),
        };
        let upstream = code.upstream().map(str::to_owned);
        let response = self
            .token(proof)
            .map_err(|_| RefreshGrantError::Unavailable)?;
        Ok(self
            .with_new_family(response, &grant, upstream.as_deref(), browser, metrics)
            .await)
    }
    /// `upstream` is the sealed upstream grant of a coupled family; it is revoked at the
    /// provider when no family holds it.
    pub(super) async fn with_new_family(
        &self,
        response: TokenResponse,
        grant: &RefreshGrant,
        upstream: Option<&str>,
        browser: &BrowserLoginState,
        metrics: &Metrics,
    ) -> TokenResponse {
        let unheld = || {
            upstream.map(|sealed| EndedUpstream {
                grant: grant.clone(),
                sealed: sealed.to_owned(),
            })
        };
        let (Some(backend), Some(policy), Some(method)) = (
            &self.refresh,
            self.refresh_policy(&grant.client_id),
            browser.method(&grant.method),
        ) else {
            self.end_upstream(unheld(), browser, metrics);
            return response;
        };
        let policy = &method_policy(policy, method);
        let issued = async {
            let token = RefreshToken::generate()?;
            let now = self
                .now()
                .await
                .map_err(|_| RefreshStoreError::Unavailable)?;
            let evicted =
                refresh_dispatch!(backend, issue(grant, token.hash(), now, policy, upstream))?;
            Ok::<_, RefreshStoreError>((token, evicted))
        };
        match issued.await {
            Ok((token, evicted)) => {
                self.end_upstream(evicted, browser, metrics);
                metrics.record_refresh_token(RefreshTokenEvent::Issued);
                response.with_refresh_token(&token)
            }
            Err(error) => {
                tracing::warn!(
                    event_name = "oauth.refresh_token.issue_failed",
                    client_id = %grant.client_id,
                    error = ?error,
                    "refresh token family not stored; returning the access token alone"
                );
                metrics.record_refresh_token(RefreshTokenEvent::IssueFailed);
                self.end_upstream(unheld(), browser, metrics);
                response
            }
        }
    }

    pub(crate) async fn refresh(
        &self,
        request: RefreshRequest<'_>,
        auth: &Auth,
        browser: &BrowserLoginState,
        metrics: &Metrics,
    ) -> Result<TokenResponse, RefreshGrantError> {
        use RefreshGrantError::*;
        let backend = self.refresh.as_ref().ok_or(InvalidGrant)?;
        let presented = RefreshToken::parse(request.token).ok_or(InvalidGrant)?;
        let hash = presented.hash();
        let now = self.now().await.map_err(|_| Unavailable)?;
        let family = match refresh_dispatch!(backend, lookup(&hash, now))? {
            Presented::Current(family) => family,
            Presented::Reused { ended, .. } => {
                metrics.record_refresh_token(RefreshTokenEvent::ReuseDetected);
                metrics.record_refresh_token(RefreshTokenEvent::FamilyRevoked);
                self.end_upstream(ended.map(|ended| *ended), browser, metrics);
                return Err(InvalidGrant);
            }
            Presented::Grace | Presented::Missing => return Err(InvalidGrant),
        };
        // A token presented by another client is rejected without touching the family.
        if family.grant.client_id != request.client_id {
            return Err(InvalidGrant);
        }
        let family_id = family.family_id.clone();
        let revoke = move |reason: RefreshGrantError| async move {
            let ended = refresh_dispatch!(backend, revoke_family(&family_id))?;
            metrics.record_refresh_token(RefreshTokenEvent::FamilyRevoked);
            self.end_upstream(ended, browser, metrics);
            Err::<TokenResponse, _>(reason)
        };
        // A removed login method or client opt-out ends the family.
        let (Some(policy), Some(method)) = (
            self.refresh_policy(request.client_id),
            browser.method(&family.grant.method),
        ) else {
            return revoke(InvalidGrant).await;
        };
        let policy = &method_policy(policy, method);
        let ceiling =
            match effective_absolute(family.created_at_ms, family.absolute_expires_at_ms, policy) {
                Some(ceiling) if now < ceiling => ceiling,
                _ => return revoke(InvalidGrant).await,
            };
        // Providers that can tell (plain password users) end families of removed accounts.
        if method.account_still_exists(&family.grant.username) == Some(false) {
            tracing::info!(
                event_name = "oauth.refresh_token.account_removed",
                method = %family.grant.method,
                "refresh token family revoked: account no longer configured"
            );
            return revoke(InvalidGrant).await;
        }
        if request
            .resource
            .is_some_and(|resource| resource != family.grant.resource)
        {
            return Err(InvalidTarget);
        }
        let scopes = narrowed_scopes(request.scope, &family.grant.scopes)?;
        let user = User::new(
            family.grant.realm.clone(),
            family.grant.username.clone(),
            Some(family.grant.provider_roles.clone()),
            None,
            None,
            None,
        );
        let user = tokio::time::timeout(
            browser.verification_timeout(),
            auth.check_augmenters_strict(user, metrics),
        )
        .await
        .map_err(|_| Unavailable)?
        .map_err(|_| Unavailable)?;
        let user = projection(&user).map_err(|_| InvalidGrant)?;
        let issuer = TokenIssuer::new(&self.config, &self.keys).map_err(|_| Unavailable)?;
        let response = issuer
            .issue_refreshed(
                request.client_id,
                &family.grant.resource,
                &scopes,
                &user,
                now,
            )
            .map_err(|error| match error {
                TokenError::Policy(OAuthPolicyError::InvalidScope) => InvalidScope,
                TokenError::Policy(_) | TokenError::Identity => InvalidGrant,
                _ => Unavailable,
            })?;
        let next = RefreshToken::generate()?;
        match refresh_dispatch!(
            backend,
            rotate(
                &family.family_id,
                &hash,
                next.hash(),
                now,
                policy.idle_ttl_seconds,
                ceiling
            )
        )? {
            Rotated::Rotated => {
                metrics.record_refresh_token(RefreshTokenEvent::Rotated);
                Ok(response.with_refresh_token(&next))
            }
            Rotated::Stale => Err(InvalidGrant),
        }
    }

    /// RFC 7009 §2.2: unknown, malformed or foreign tokens succeed without effect.
    pub(crate) async fn revoke(
        &self,
        token: &str,
        client_id: &str,
        browser: &BrowserLoginState,
        metrics: &Metrics,
    ) -> Result<(), RefreshGrantError> {
        let (Some(backend), Some(token)) = (&self.refresh, RefreshToken::parse(token)) else {
            return Ok(());
        };
        if let Revocation::Revoked(ended) =
            refresh_dispatch!(backend, revoke_token(&token.hash(), client_id))?
        {
            metrics.record_refresh_token(RefreshTokenEvent::FamilyRevoked);
            self.end_upstream(ended, browser, metrics);
        }
        Ok(())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::{
        augmenters::AugmenterConfig, config::ConfigV2, oauth::refresh::tests::grant,
        store::no_store::NoStore,
    };
    use rsa::pkcs8::{EncodePrivateKey, LineEnding};
    use std::{io::Write, sync::Arc};

    async fn runtime() -> (tempfile::NamedTempFile, ConfigV2, Arc<OAuthRuntime>) {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        let pem = super::super::keys::tests::keys()[0]
            .to_pkcs8_pem(LineEnding::LF)
            .unwrap();
        file.write_all(pem.as_bytes()).unwrap();
        let config: ConfigV2 = serde_json::from_value(serde_json::json!({
            "store": {"enabled": false}, "services": [], "augmenters": [],
            "providers": [{"type": "plain", "name": "basic", "realm": "local", "users": [{"username": "alice", "password": "fixture-only"}], "browser": {"id": "password", "label": "Password"}}],
            "server": {"port": 0}, "jwt": {"iss": "fixture", "exp": 300, "secret": "fixture-only"}, "logging": {"level": "warn", "format": "console"},
            "ui": {"enabled": true, "browser_session": {"public_origin": "https://login.example.org", "backend": {"type": "memory"}}},
            "oauth": {"enabled": true, "issuer": "https://login.example.org/", "signing": {"active_kid": "k", "keys": [{"kid": "k", "private_key_file": file.path()}]},
                "clients": [{"client_id": "desktop", "display_name": "Desktop", "redirect_uris": ["https://app.example.org/cb"],
                    "resources": [{"resource": "https://mcp.example.org/mcp", "scopes": ["read"]}],
                    "refresh_tokens": {"enabled": true, "idle_ttl_seconds": 600, "absolute_ttl_seconds": 3600}}],
                "resources": [{"resource": "https://mcp.example.org/mcp", "allowed_realms": ["local"], "scopes": [{"name": "read", "required_roles": ["reader"]}]}]}
        }))
        .unwrap();
        let runtime = OAuthRuntime::initialize(&config).await.unwrap().unwrap();
        (file, config, runtime)
    }
    async fn family(runtime: &OAuthRuntime, grant: &RefreshGrant) -> RefreshToken {
        let token = RefreshToken::generate().unwrap();
        let backend = runtime.refresh.as_ref().unwrap();
        let policy = runtime.refresh_policy("desktop").unwrap();
        let now = runtime.now().await.unwrap();
        refresh_dispatch!(backend, issue(grant, token.hash(), now, policy, None)).unwrap();
        token
    }
    fn auth(config: &ConfigV2, augmenters: serde_json::Value) -> Auth {
        let augmenters: Vec<AugmenterConfig> = serde_json::from_value(augmenters).unwrap();
        Auth::new(
            &config.providers,
            &augmenters,
            Arc::new(NoStore),
            config.auth.clone(),
        )
    }
    fn browser(config: &ConfigV2) -> BrowserLoginState {
        BrowserLoginState::new(config).unwrap()
    }
    /// `config` with the password method's provider block edited by `edit`.
    fn with_provider(config: &ConfigV2, edit: impl FnOnce(&mut serde_json::Value)) -> ConfigV2 {
        let mut value = serde_json::to_value(config).unwrap();
        edit(&mut value["providers"][0]);
        serde_json::from_value(value).unwrap()
    }
    fn request(token: &RefreshToken) -> RefreshRequest<'_> {
        RefreshRequest {
            token: token.as_secret_str(),
            client_id: "desktop",
            scope: None,
            resource: None,
        }
    }

    #[tokio::test]
    async fn refresh_reruns_augmentation_from_provider_roles_and_fails_closed() {
        let (_file, config, runtime) = runtime().await;
        let metrics = Metrics::new();
        let browser = browser(&config);
        let mut stale = grant();
        stale.provider_roles = vec![];
        // Provider roles alone lack `reader`; no augmenter grants it, so policy denies.
        let token = family(&runtime, &stale).await;
        let none = auth(&config, serde_json::json!([]));
        assert_eq!(
            runtime
                .refresh(request(&token), &none, &browser, &metrics)
                .await
                .err(),
            Some(RefreshGrantError::InvalidGrant)
        );
        // The augmenter now grants `reader`: the same family refreshes successfully.
        let granting = auth(
            &config,
            serde_json::json!([{"type": "plain", "name": "r", "realm": "local", "roles": {"reader": ["alice"]}}]),
        );
        let response = runtime
            .refresh(request(&token), &granting, &browser, &metrics)
            .await
            .unwrap();
        let next = serde_json::to_value(response).unwrap()["refresh_token"]
            .as_str()
            .map(String::from)
            .unwrap();
        // An unreachable LDAP augmenter fails strict augmentation: 503 class, token kept.
        let failing = auth(
            &config,
            serde_json::json!([{"type": "ldap", "name": "l", "realm": "local", "uri": "ldap://127.0.0.1:9", "search_base": "dc=example", "filter": "cn", "ldap_password": "y"}]),
        );
        let next = RefreshToken::parse(&next).unwrap();
        assert_eq!(
            runtime
                .refresh(request(&next), &failing, &browser, &metrics)
                .await
                .err(),
            Some(RefreshGrantError::Unavailable)
        );
        assert!(
            runtime
                .refresh(request(&next), &granting, &browser, &metrics)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn unstorable_family_still_returns_the_access_token() {
        let (_file, config, runtime) = runtime().await;
        let metrics = Metrics::new();
        let browser = browser(&config);
        let issuer = TokenIssuer::new(&runtime.config, &runtime.keys).unwrap();
        let user = User::new(
            "local".into(),
            "alice".into(),
            Some(vec!["reader".into()]),
            None,
            None,
            None,
        );
        let issued = || {
            issuer
                .issue_refreshed(
                    "desktop",
                    "https://mcp.example.org/mcp",
                    &["read".into()],
                    &user,
                    1_700_000_000_000,
                )
                .unwrap()
        };
        let response = runtime
            .with_new_family(issued(), &grant(), None, &browser, &metrics)
            .await;
        assert!(serde_json::to_value(response).unwrap()["refresh_token"].is_string());
        // A sealed upstream grant from the sign-in couples the new family.
        let coupled = RefreshGrant {
            upstream_coupled: true,
            ..grant()
        };
        let response = runtime
            .with_new_family(issued(), &coupled, Some("v1.k.AAAA"), &browser, &metrics)
            .await;
        let token = serde_json::to_value(response).unwrap()["refresh_token"]
            .as_str()
            .map(|token| RefreshToken::parse(token).unwrap())
            .unwrap();
        let RefreshBackend::Memory(store) = runtime.refresh.as_ref().unwrap() else {
            unreachable!()
        };
        let now = runtime.now().await.unwrap();
        let Presented::Current(family) = store.lookup(&token.hash(), now).await.unwrap() else {
            panic!("expected the coupled family");
        };
        assert!(family.grant.upstream_coupled);
        assert_eq!(family.upstream.unwrap().sealed, "v1.k.AAAA");
        let mut oversized = grant();
        oversized.provider_roles = vec!["r".repeat(64); 1024];
        let response = runtime
            .with_new_family(issued(), &oversized, None, &browser, &metrics)
            .await;
        let body = serde_json::to_value(response).unwrap();
        assert!(body["access_token"].is_string());
        assert!(body.get("refresh_token").is_none());
        let output = metrics.render().unwrap();
        for line in [
            "authotron_oauth_refresh_tokens_total{event=\"issued\"} 2",
            "authotron_oauth_refresh_tokens_total{event=\"issue_failed\"} 1",
        ] {
            assert!(output.contains(line), "{line}");
        }
    }

    async fn family_absolute(runtime: &OAuthRuntime, token: &RefreshToken, now: u64) -> u64 {
        let backend = runtime.refresh.as_ref().unwrap();
        let RefreshBackend::Memory(store) = backend else {
            unreachable!()
        };
        let presented = store.lookup(&token.hash(), now).await.unwrap();
        match presented {
            Presented::Current(family) => family.absolute_expires_at_ms,
            other => panic!("expected current family, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn login_method_caps_family_lifetime_at_issue_and_on_refresh() {
        let (_file, config, runtime) = runtime().await;
        let metrics = Metrics::new();
        let granting = auth(
            &config,
            serde_json::json!([{"type": "plain", "name": "r", "realm": "local", "roles": {"reader": ["alice"]}}]),
        );
        let capped = with_provider(&config, |provider| {
            provider["browser"]["refresh_max_lifetime_seconds"] = 600.into();
        });
        let capped = browser(&capped);
        let issuer = TokenIssuer::new(&runtime.config, &runtime.keys).unwrap();
        let user = User::new(
            "local".into(),
            "alice".into(),
            Some(vec!["reader".into()]),
            None,
            None,
            None,
        );
        let now = runtime.now().await.unwrap();
        let response = issuer
            .issue_refreshed(
                "desktop",
                "https://mcp.example.org/mcp",
                &["read".into()],
                &user,
                now,
            )
            .unwrap();
        let response = runtime
            .with_new_family(response, &grant(), None, &capped, &metrics)
            .await;
        let token = serde_json::to_value(response).unwrap()["refresh_token"]
            .as_str()
            .map(|token| RefreshToken::parse(token).unwrap())
            .unwrap();
        let absolute = family_absolute(&runtime, &token, now).await;
        assert!(
            (now + 600_000..now + 601_000).contains(&absolute),
            "{absolute}"
        );
        // Uncapped families follow the client's absolute lifetime (3600 s).
        let uncapped = family(&runtime, &grant()).await;
        assert!(family_absolute(&runtime, &uncapped, now).await >= now + 3_600_000);
        // A cap configured after login shortens the family at its next refresh.
        let response = runtime
            .refresh(request(&uncapped), &granting, &capped, &metrics)
            .await
            .unwrap();
        let next = serde_json::to_value(response).unwrap()["refresh_token"]
            .as_str()
            .map(|token| RefreshToken::parse(token).unwrap())
            .unwrap();
        assert!(family_absolute(&runtime, &next, now).await < now + 601_000);
    }

    #[tokio::test]
    async fn removed_password_account_or_method_revokes_the_family() {
        let (_file, config, runtime) = runtime().await;
        let metrics = Metrics::new();
        let granting = auth(
            &config,
            serde_json::json!([{"type": "plain", "name": "r", "realm": "local", "roles": {"reader": ["alice"]}}]),
        );
        let current = browser(&config);
        let removed_user = browser(&with_provider(&config, |provider| {
            provider["users"] =
                serde_json::json!([{"username": "bob", "password": "fixture-only"}]);
        }));
        let renamed_method = browser(&with_provider(&config, |provider| {
            provider["browser"]["id"] = "staff".into();
        }));
        for removed in [&removed_user, &renamed_method] {
            let token = family(&runtime, &grant()).await;
            assert_eq!(
                runtime
                    .refresh(request(&token), &granting, removed, &metrics)
                    .await
                    .err(),
                Some(RefreshGrantError::InvalidGrant)
            );
            // The family is revoked, not merely rejected.
            assert_eq!(
                runtime
                    .refresh(request(&token), &granting, &current, &metrics)
                    .await
                    .err(),
                Some(RefreshGrantError::InvalidGrant)
            );
        }
        let token = family(&runtime, &grant()).await;
        assert!(
            runtime
                .refresh(request(&token), &granting, &current, &metrics)
                .await
                .is_ok()
        );
        let output = metrics.render().unwrap();
        assert!(
            output.contains("authotron_oauth_refresh_tokens_total{event=\"family_revoked\"} 2")
        );
    }

    #[test]
    fn scope_narrowing_accepts_only_unique_granted_subsets() {
        let granted = vec!["read".to_string(), "write".to_string()];
        assert_eq!(narrowed_scopes(None, &granted), Ok(granted.clone()));
        assert_eq!(
            narrowed_scopes(Some("write"), &granted),
            Ok(vec!["write".into()])
        );
        assert_eq!(
            narrowed_scopes(Some("write read"), &granted),
            Ok(vec!["write".into(), "read".into()])
        );
        for invalid in [
            "",
            " read",
            "read ",
            "read  write",
            "read read",
            "admin",
            "read admin",
        ] {
            assert_eq!(
                narrowed_scopes(Some(invalid), &granted),
                Err(RefreshGrantError::InvalidScope),
                "{invalid:?}"
            );
        }
    }
}

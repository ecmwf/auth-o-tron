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
    audit::{FamilyEnd, NO_FAMILY, family_event, family_ref},
    authentication::projection,
    refresh::{
        Presented, RefreshFamily, RefreshGrant, RefreshStoreError, RefreshToken, Repetition,
        Revocation, Rotated, Rotation, effective_absolute,
    },
    refresh_store::MemoryRefreshStore,
    retry_key::RetryKey,
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
use std::sync::Arc;

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
pub(super) use refresh_dispatch;

/// Consecutive rotations answered again from which a family logs
/// `oauth.refresh_token.retry_pattern`.
const RETRY_PATTERN_STREAK: u32 = 3;

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

/// Answers a refresh of the family's previous token with the current one, which the
/// latest rotation sealed by that token: a response that was lost, or a concurrent
/// refresh. A sealed token that does not open to the current one is rejected.
fn answer_again(
    retry_key: &RetryKey,
    presented: &RefreshToken,
    family: &RefreshFamily,
    repetition: &Repetition,
    response: TokenResponse,
    metrics: &Metrics,
) -> Result<TokenResponse, RefreshGrantError> {
    let next = presented
        .open_successor(retry_key, &family.family_id, &repetition.sealed)
        .filter(|next| next.hash() == repetition.current)
        .ok_or(RefreshGrantError::InvalidGrant)?;
    let reference = family_ref(&family.family_id);
    family_event!(
        info,
        family.grant,
        reference,
        event_name = "oauth.refresh_token.retried",
        retries = repetition.retries,
        "rotated refresh token presented again; answered with its successor"
    );
    if repetition.retries == 1 && repetition.streak >= RETRY_PATTERN_STREAK {
        family_event!(
            warn,
            family.grant,
            reference,
            event_name = "oauth.refresh_token.retry_pattern",
            streak = repetition.streak,
            "consecutive rotations were each answered again: the token may be shared or copied"
        );
    }
    metrics.record_refresh_token(RefreshTokenEvent::Retried);
    Ok(response.with_refresh_token(&next))
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
            if let Some(sealed) = upstream {
                self.revoke_sealed(grant, sealed, NO_FAMILY, browser, metrics);
            }
        };
        let (Some(backend), Some(policy), Some(method)) = (
            &self.refresh,
            self.refresh_policy(&grant.client_id),
            browser.method(&grant.method),
        ) else {
            unheld();
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
                self.families_ended(evicted, FamilyEnd::PerUserCap, browser, metrics);
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
                unheld();
                response
            }
        }
    }

    pub(crate) async fn refresh(
        self: &Arc<Self>,
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
        // `rotated_at` is set for the family's previous token: when it was rotated.
        let (family, rotated_at) = match refresh_dispatch!(backend, lookup(&hash, now))? {
            Presented::Current(family) => (family, None),
            Presented::Previous(family, rotated_at) => (family, Some(rotated_at)),
            Presented::Reused(ended) => {
                metrics.record_refresh_token(RefreshTokenEvent::ReuseDetected);
                self.families_ended([*ended], FamilyEnd::ReuseDetected, browser, metrics);
                return Err(InvalidGrant);
            }
            Presented::Missing => return Err(InvalidGrant),
        };
        // A token presented by another client is rejected without touching the family.
        if family.grant.client_id != request.client_id {
            return Err(InvalidGrant);
        }
        let family_id = family.family_id.clone();
        let revoke = move |reason: FamilyEnd| async move {
            let ended = refresh_dispatch!(backend, revoke_family(&family_id))?;
            self.families_ended(ended, reason, browser, metrics);
            Err::<TokenResponse, _>(InvalidGrant)
        };
        // A client opt-out or a removed login method ends the family.
        let Some(policy) = self.refresh_policy(request.client_id) else {
            return revoke(FamilyEnd::ClientDisabled).await;
        };
        // The previous token past its client's retry window is reuse, as an older one.
        let retry_window_ms = policy.retry_window_seconds * 1000;
        if rotated_at.is_some_and(|at| now >= at.saturating_add(retry_window_ms)) {
            metrics.record_refresh_token(RefreshTokenEvent::ReuseDetected);
            return revoke(FamilyEnd::ReuseDetected).await;
        }
        let Some(method) = browser.method(&family.grant.method) else {
            return revoke(FamilyEnd::MethodRemoved).await;
        };
        let policy = &method_policy(policy, method);
        let ceiling =
            match effective_absolute(family.created_at_ms, family.absolute_expires_at_ms, policy) {
                Some(ceiling) if now < ceiling => ceiling,
                _ => return revoke(FamilyEnd::LifetimeExceeded).await,
            };
        // Providers that can tell (plain password users) end families of removed accounts.
        if method.account_still_exists(&family.grant.username) == Some(false) {
            return revoke(FamilyEnd::AccountRemoved).await;
        }
        if request
            .resource
            .is_some_and(|resource| resource != family.grant.resource)
        {
            return Err(InvalidTarget);
        }
        let scopes = narrowed_scopes(request.scope, &family.grant.scopes)?;
        // A coupled family renews its upstream grant and takes the refreshed roles. The
        // previous token starts from the roles its rotation stored, without the provider.
        let provider_roles = match (family.grant.upstream_coupled, method.oidc()) {
            (true, None) => return revoke(FamilyEnd::MethodRemoved).await,
            (true, Some(oidc)) if rotated_at.is_none() => {
                self.refresh_upstream(backend, &family, &hash, oidc, browser, metrics)
                    .await?
            }
            _ => family.grant.provider_roles.clone(),
        };
        let user = User::new(
            family.grant.realm.clone(),
            family.grant.username.clone(),
            Some(provider_roles.clone()),
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
        // Augmentation can take seconds: the store's checks measure windows and
        // deadlines from now, not from the start of the refresh.
        let now = self.now().await.map_err(|_| Unavailable)?;
        // The previous token is answered with the current one if the store still
        // confirms it, within the window and cap, as the last step.
        if rotated_at.is_some() {
            let repetition = refresh_dispatch!(backend, repeat(&hash, retry_window_ms, now))?
                .ok_or(InvalidGrant)?;
            let key = &self.retry_key;
            return answer_again(key, &presented, &family, &repetition, response, metrics);
        }
        let next = RefreshToken::generate()?;
        // The successor carries the provider roles this refresh started from.
        let grant = RefreshGrant {
            provider_roles,
            ..family.grant.clone()
        };
        let sealed = presented.seal_successor(&self.retry_key, &family.family_id, &next)?;
        let rotation = Rotation {
            next: next.hash(),
            sealed: &sealed,
            grant: &grant,
            idle_ttl_seconds: policy.idle_ttl_seconds,
            ceiling,
            retry_window_ms,
        };
        match refresh_dispatch!(backend, rotate(&hash, &rotation, now))? {
            Rotated::Rotated => {
                metrics.record_refresh_token(RefreshTokenEvent::Rotated);
                Ok(response.with_refresh_token(&next))
            }
            // A concurrent refresh of the same token rotated it first: answer as for a
            // retry. An earlier run of this rotation reports `Rotated`.
            Rotated::Repeated(repetition) => answer_again(
                &self.retry_key,
                &presented,
                &family,
                &repetition,
                response,
                metrics,
            ),
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
            self.families_ended([*ended], FamilyEnd::ClientRevoke, browser, metrics);
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
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use rsa::pkcs8::{EncodePrivateKey, LineEnding};
    use std::{io::Write, sync::Arc, time::Duration};

    async fn runtime() -> (tempfile::NamedTempFile, ConfigV2, Arc<OAuthRuntime>) {
        runtime_with(|_| {}).await
    }
    /// The runtime, with `edit` applied to the `desktop` client's refresh-token policy.
    async fn runtime_with(
        edit: impl FnOnce(&mut serde_json::Value),
    ) -> (tempfile::NamedTempFile, ConfigV2, Arc<OAuthRuntime>) {
        runtime_from(|value| edit(&mut value["oauth"]["clients"][0]["refresh_tokens"])).await
    }
    /// The runtime, with `edit` applied to the whole configuration.
    async fn runtime_from(
        edit: impl FnOnce(&mut serde_json::Value),
    ) -> (tempfile::NamedTempFile, ConfigV2, Arc<OAuthRuntime>) {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        let pem = super::super::keys::tests::keys()[0]
            .to_pkcs8_pem(LineEnding::LF)
            .unwrap();
        file.write_all(pem.as_bytes()).unwrap();
        let mut value = serde_json::json!({
            "store": {"enabled": false}, "services": [], "augmenters": [],
            "providers": [{"type": "plain", "name": "basic", "realm": "local", "users": [{"username": "alice", "password": "fixture-only"}], "browser": {"id": "password", "label": "Password"}}],
            "server": {"port": 0}, "jwt": {"iss": "fixture", "exp": 300, "secret": "fixture-only"}, "logging": {"level": "warn", "format": "console"},
            "ui": {"enabled": true, "browser_session": {"public_origin": "https://login.example.org", "backend": {"type": "memory"}}},
            "oauth": {"enabled": true, "issuer": "https://login.example.org/", "signing": {"active_kid": "k", "keys": [{"kid": "k", "private_key_file": file.path()}]},
                "clients": [{"client_id": "desktop", "display_name": "Desktop", "redirect_uris": ["https://app.example.org/cb"],
                    "resources": [{"resource": "https://mcp.example.org/mcp", "scopes": ["read"]}],
                    "refresh_tokens": {"enabled": true, "idle_ttl_seconds": 600, "absolute_ttl_seconds": 3600}}],
                "resources": [{"resource": "https://mcp.example.org/mcp", "allowed_realms": ["local"], "scopes": [{"name": "read", "required_roles": ["reader"]}]}]}
        });
        edit(&mut value);
        let config: ConfigV2 = serde_json::from_value(value).unwrap();
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
    #[tracing_test::traced_test]
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
        for reason in ["account_removed", "method_removed"] {
            assert!(logs_contain(&format!("reason=\"{reason}\"")), "{reason}");
        }
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn revoked_families_are_logged_with_their_reason_but_no_token() {
        let (_file, config, runtime) = runtime().await;
        let metrics = Metrics::new();
        let browser = browser(&config);
        let granting = auth(
            &config,
            serde_json::json!([{"type": "plain", "name": "r", "realm": "local", "roles": {"reader": ["alice"]}}]),
        );
        let next = |response: TokenResponse| {
            serde_json::to_value(response).unwrap()["refresh_token"]
                .as_str()
                .map(|token| RefreshToken::parse(token).unwrap())
                .unwrap()
        };
        let first = family(&runtime, &grant()).await;
        let RefreshBackend::Memory(store) = runtime.refresh.as_ref().unwrap() else {
            unreachable!()
        };
        let now = runtime.now().await.unwrap();
        let Presented::Current(reused) = store.lookup(&first.hash(), now).await.unwrap() else {
            panic!("expected the new family");
        };
        let second = runtime.refresh(request(&first), &granting, &browser, &metrics);
        let second = next(second.await.unwrap());
        let third = runtime.refresh(request(&second), &granting, &browser, &metrics);
        next(third.await.unwrap());
        // The first token is neither current nor the previous one: reuse.
        assert!(
            runtime
                .refresh(request(&first), &granting, &browser, &metrics)
                .await
                .is_err()
        );
        let revoked = family(&runtime, &grant()).await;
        runtime
            .revoke(revoked.as_secret_str(), "desktop", &browser, &metrics)
            .await
            .unwrap();
        let reference = super::super::audit::family_ref(&reused.family_id);
        logs_assert(|lines: &[&str]| {
            let event = |reason: &str| {
                lines
                    .iter()
                    .find(|line| {
                        line.contains("oauth.refresh_token.family_revoked")
                            && line.contains(&format!("reason=\"{reason}\""))
                    })
                    .copied()
                    .ok_or(format!("no {reason} line"))
            };
            let reuse = event("reuse_detected")?;
            let revoke = event("client_revoke")?;
            for (line, level) in [(reuse, " WARN "), (revoke, " INFO ")] {
                for field in [
                    level,
                    "client_id=desktop",
                    "method=password",
                    "realm=local",
                    "username=alice",
                ] {
                    if !line.contains(field) {
                        return Err(format!("{field} missing: {line}"));
                    }
                }
            }
            if !reuse.contains(&format!("family={reference}")) {
                return Err(format!("family reference missing: {reuse}"));
            }
            Ok(())
        });
        for secret in [
            first.as_secret_str(),
            second.as_secret_str(),
            revoked.as_secret_str(),
            &reused.family_id,
        ] {
            assert!(!logs_contain(secret));
        }
    }

    /// The refresh response of `token` as JSON.
    async fn refreshed(
        runtime: &Arc<OAuthRuntime>,
        token: &RefreshToken,
        auth: &Auth,
        browser: &BrowserLoginState,
        metrics: &Metrics,
    ) -> Result<serde_json::Value, RefreshGrantError> {
        let response = runtime
            .refresh(request(token), auth, browser, metrics)
            .await?;
        Ok(serde_json::to_value(response).unwrap())
    }
    fn refresh_token(response: &serde_json::Value) -> RefreshToken {
        RefreshToken::parse(response["refresh_token"].as_str().unwrap()).unwrap()
    }
    fn granting(config: &ConfigV2) -> Auth {
        auth(
            config,
            serde_json::json!([{"type": "plain", "name": "r", "realm": "local", "roles": {"reader": ["alice"]}}]),
        )
    }
    fn counted(metrics: &Metrics, event: &str, count: u64) {
        let line = format!("authotron_oauth_refresh_tokens_total{{event=\"{event}\"}} {count}");
        assert!(metrics.render().unwrap().contains(&line), "{line}");
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn a_lost_refresh_response_is_answered_again_with_the_same_token() {
        let (_file, config, runtime) = runtime().await;
        let (metrics, browser, granting) = (Metrics::new(), browser(&config), granting(&config));
        let refresh = |token| refreshed(&runtime, token, &granting, &browser, &metrics);
        let first = family(&runtime, &grant()).await;
        let lost = refresh(&first).await.unwrap();
        // The client never received `lost` and presents its old token again.
        for _ in 0..2 {
            let retried = refresh(&first).await.unwrap();
            assert_eq!(retried["refresh_token"], lost["refresh_token"]);
            assert_ne!(retried["access_token"], lost["access_token"]);
            assert_eq!(retried["scope"], "read");
        }
        // Once the successor is used, the old token is reuse and ends the family.
        let second = refresh_token(&lost);
        let third = refresh_token(&refresh(&second).await.unwrap());
        let invalid = Some(RefreshGrantError::InvalidGrant);
        assert_eq!(refresh(&first).await.err(), invalid);
        assert_eq!(refresh(&third).await.err(), invalid);
        for (event, count) in [("rotated", 2), ("retried", 2), ("reuse_detected", 1)] {
            counted(&metrics, event, count);
        }
        logs_assert(|lines: &[&str]| {
            let retried: Vec<_> = lines
                .iter()
                .filter(|line| line.contains("oauth.refresh_token.retried"))
                .collect();
            let fields = [
                " INFO ",
                "client_id=desktop",
                "method=password",
                "username=alice",
            ];
            match retried.as_slice() {
                [a, b]
                    if [a, b]
                        .iter()
                        .all(|line| fields.iter().all(|f| line.contains(f))) =>
                {
                    Ok(())
                }
                other => Err(format!("unexpected retry lines: {other:?}")),
            }
        });
        for token in [&first, &second, &third] {
            assert!(!logs_contain(token.as_secret_str()));
        }
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn retries_are_capped_per_rotation_and_a_streak_of_them_is_reported() {
        let (_file, config, runtime) = runtime().await;
        let (metrics, browser, granting) = (Metrics::new(), browser(&config), granting(&config));
        let mut token = family(&runtime, &grant()).await;
        // Three rotations in a row, each answered again for its previous token.
        for rotation in 1..=3 {
            let refresh = || refreshed(&runtime, &token, &granting, &browser, &metrics);
            let next = refresh_token(&refresh().await.unwrap());
            for _ in 0..crate::oauth::refresh::MAX_RETRIES_PER_ROTATION {
                let retried = refresh_token(&refresh().await.unwrap());
                assert_eq!(retried.as_secret_str(), next.as_secret_str());
            }
            if rotation == 1 {
                // Past the cap the previous token is rejected; the family is kept.
                let refused = refresh().await.err();
                assert_eq!(refused, Some(RefreshGrantError::InvalidGrant));
            }
            token = next;
        }
        refreshed(&runtime, &token, &granting, &browser, &metrics)
            .await
            .unwrap();
        counted(&metrics, "retried", 9);
        logs_assert(|lines: &[&str]| {
            let pattern: Vec<_> = lines
                .iter()
                .filter(|line| line.contains("oauth.refresh_token.retry_pattern"))
                .collect();
            match pattern.as_slice() {
                [line] if line.contains(" WARN ") && line.contains("streak=3") => Ok(()),
                other => Err(format!("unexpected pattern lines: {other:?}")),
            }
        });
    }

    /// Holds every augmentation until two refreshes are augmenting at once.
    struct Rendezvous(tokio::sync::Barrier);
    #[async_trait::async_trait]
    impl crate::augmenters::base::Augmenter for Rendezvous {
        fn get_name(&self) -> &str {
            "rendezvous"
        }
        fn get_type(&self) -> &str {
            "rendezvous"
        }
        fn get_realm(&self) -> &str {
            "local"
        }
        async fn augment(&self, _: Arc<futures::lock::Mutex<User>>) -> Result<(), String> {
            self.0.wait().await;
            Ok(())
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_refreshes_of_one_token_both_get_its_successor() {
        let (_file, config, runtime) = runtime().await;
        let mut auth = granting(&config);
        auth.augmenters
            .push(Box::new(Rendezvous(tokio::sync::Barrier::new(2))));
        let (auth, browser, metrics) = (Arc::new(auth), Arc::new(browser(&config)), Metrics::new());
        let token = Arc::new(family(&runtime, &grant()).await);
        // Both look the token up as current before either rotates it.
        let refresh = || {
            let (runtime, auth, browser) = (runtime.clone(), auth.clone(), browser.clone());
            let (metrics, token) = (metrics.clone(), token.clone());
            tokio::spawn(
                async move { refreshed(&runtime, &token, &auth, &browser, &metrics).await },
            )
        };
        let (a, b) = (refresh(), refresh());
        let (a, b) = (a.await.unwrap().unwrap(), b.await.unwrap().unwrap());
        assert_eq!(a["refresh_token"], b["refresh_token"]);
        assert_ne!(a["access_token"], b["access_token"]);
        counted(&metrics, "rotated", 1);
        counted(&metrics, "retried", 1);
    }

    /// Sleeps in every augmentation.
    struct Slow(Duration);
    #[async_trait::async_trait]
    impl crate::augmenters::base::Augmenter for Slow {
        fn get_name(&self) -> &str {
            "slow"
        }
        fn get_type(&self) -> &str {
            "slow"
        }
        fn get_realm(&self) -> &str {
            "local"
        }
        async fn augment(&self, _: Arc<futures::lock::Mutex<User>>) -> Result<(), String> {
            tokio::time::sleep(self.0).await;
            Ok(())
        }
    }

    /// A family whose first token was rotated to a second `ago` ms before now, the
    /// successor sealed as a refresh seals it.
    async fn rotated_ago(runtime: &OAuthRuntime, ago: u64) -> (RefreshToken, RefreshToken) {
        let RefreshBackend::Memory(store) = runtime.refresh.as_ref().unwrap() else {
            unreachable!()
        };
        let now = runtime.now().await.unwrap();
        let (previous, next) = (
            RefreshToken::generate().unwrap(),
            RefreshToken::generate().unwrap(),
        );
        let policy = runtime.refresh_policy("desktop").unwrap();
        let at = now - ago;
        store
            .issue(&grant(), previous.hash(), at - 1_000, policy, None)
            .await
            .unwrap();
        let Presented::Current(family) = store.lookup(&previous.hash(), at).await.unwrap() else {
            panic!("expected a live family");
        };
        let sealed = previous
            .seal_successor(&runtime.retry_key, &family.family_id, &next)
            .unwrap();
        let fixture = grant();
        let rotation = Rotation {
            next: next.hash(),
            sealed: &sealed,
            grant: &fixture,
            idle_ttl_seconds: 600,
            ceiling: now + 3_600_000,
            retry_window_ms: 30_000,
        };
        let outcome = store.rotate(&previous.hash(), &rotation, at).await.unwrap();
        assert_eq!(outcome, Rotated::Rotated);
        (previous, next)
    }

    #[tokio::test]
    async fn the_previous_token_is_retry_within_the_clients_window_and_reuse_after_it() {
        let (_file, config, runtime) = runtime_with(|policy| {
            policy["retry_window_seconds"] = 5.into();
        })
        .await;
        let (metrics, browser, granting) = (Metrics::new(), browser(&config), granting(&config));
        let refresh = |token| refreshed(&runtime, token, &granting, &browser, &metrics);
        let (old, next) = rotated_ago(&runtime, 3_000).await;
        let retried = refresh(&old).await.unwrap();
        assert_eq!(
            refresh_token(&retried).as_secret_str(),
            next.as_secret_str()
        );
        // Past 5 seconds, though well within 30, presenting it is reuse.
        let (old, next) = rotated_ago(&runtime, 10_000).await;
        let invalid = Some(RefreshGrantError::InvalidGrant);
        assert_eq!(refresh(&old).await.err(), invalid);
        assert_eq!(refresh(&next).await.err(), invalid);
        counted(&metrics, "retried", 1);
        counted(&metrics, "reuse_detected", 1);
    }

    #[tokio::test]
    async fn the_retry_window_is_measured_when_the_store_answers() {
        let (_file, config, runtime) = runtime_with(|policy| {
            policy["retry_window_seconds"] = 1.into();
        })
        .await;
        let mut auth = granting(&config);
        auth.augmenters
            .push(Box::new(Slow(Duration::from_millis(800))));
        let (metrics, browser) = (Metrics::new(), browser(&config));
        // Within the window when the refresh starts, past it once augmentation ends.
        let (old, next) = rotated_ago(&runtime, 500).await;
        let late = refreshed(&runtime, &old, &auth, &browser, &metrics).await;
        assert_eq!(late.err(), Some(RefreshGrantError::InvalidGrant));
        refreshed(&runtime, &next, &auth, &browser, &metrics)
            .await
            .unwrap();
        counted(&metrics, "retried", 0);
    }

    /// Holds the first augmentation after it is armed until the test releases it.
    #[derive(Default)]
    struct Pause {
        armed: std::sync::atomic::AtomicBool,
        entered: tokio::sync::Notify,
        release: tokio::sync::Notify,
    }
    struct Paused(Arc<Pause>);
    #[async_trait::async_trait]
    impl crate::augmenters::base::Augmenter for Paused {
        fn get_name(&self) -> &str {
            "paused"
        }
        fn get_type(&self) -> &str {
            "paused"
        }
        fn get_realm(&self) -> &str {
            "local"
        }
        async fn augment(&self, _: Arc<futures::lock::Mutex<User>>) -> Result<(), String> {
            if self
                .0
                .armed
                .swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                let released = self.0.release.notified();
                self.0.entered.notify_one();
                released.await;
            }
            Ok(())
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_retry_fails_when_its_successor_is_used_or_its_family_ends_meanwhile() {
        let (_file, config, runtime) = runtime().await;
        let pause = Arc::new(Pause::default());
        let mut auth = granting(&config);
        auth.augmenters.push(Box::new(Paused(pause.clone())));
        let (auth, browser, metrics) = (Arc::new(auth), Arc::new(browser(&config)), Metrics::new());
        let invalid = Some(RefreshGrantError::InvalidGrant);
        for revoke in [false, true] {
            let first = family(&runtime, &grant()).await;
            let second = refreshed(&runtime, &first, &auth, &browser, &metrics).await;
            let second = refresh_token(&second.unwrap());
            // The retry of the first token waits in augmentation.
            pause.armed.store(true, std::sync::atomic::Ordering::SeqCst);
            let entered = pause.entered.notified();
            let retry = {
                let (runtime, auth, browser) = (runtime.clone(), auth.clone(), browser.clone());
                let metrics = metrics.clone();
                tokio::spawn(
                    async move { refreshed(&runtime, &first, &auth, &browser, &metrics).await },
                )
            };
            entered.await;
            let third = if revoke {
                let token = second.as_secret_str();
                runtime
                    .revoke(token, "desktop", &browser, &metrics)
                    .await
                    .unwrap();
                None
            } else {
                let third = refreshed(&runtime, &second, &auth, &browser, &metrics).await;
                Some(refresh_token(&third.unwrap()))
            };
            pause.release.notify_one();
            assert_eq!(retry.await.unwrap().err(), invalid, "revoked: {revoke}");
            // A used successor keeps the family; a revoked family stays ended.
            let next = third.as_ref().unwrap_or(&second);
            let outcome = refreshed(&runtime, next, &auth, &browser, &metrics).await;
            assert_eq!(outcome.is_ok(), !revoke);
        }
        counted(&metrics, "retried", 0);
        counted(&metrics, "reuse_detected", 0);
    }

    #[tokio::test]
    async fn refreshed_identity_claims_follow_the_rechecked_roles() {
        let (_file, config, runtime) = runtime_from(|value| {
            value["oauth"]["resources"][0]["identity_claims"] =
                serde_json::json!({"roles": ["reader", "writer"]});
        })
        .await;
        let (metrics, browser) = (Metrics::new(), browser(&config));
        let claims = |response: &serde_json::Value| -> serde_json::Value {
            let token = response["access_token"].as_str().unwrap();
            let payload = token.split('.').nth(1).unwrap();
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap()
        };
        let first = family(&runtime, &grant()).await;
        let reader = refreshed(&runtime, &first, &granting(&config), &browser, &metrics)
            .await
            .unwrap();
        let claimed = claims(&reader);
        assert_eq!(
            (&claimed["realm"], &claimed["roles"]),
            (&"local".into(), &serde_json::json!(["reader"]))
        );
        // The next refresh carries the roles augmentation grants then.
        let writer = auth(
            &config,
            serde_json::json!([{"type": "plain", "name": "r", "realm": "local",
                "roles": {"reader": ["alice"], "writer": ["alice"], "other": ["alice"]}}]),
        );
        let next = refresh_token(&reader);
        let both = refreshed(&runtime, &next, &writer, &browser, &metrics)
            .await
            .unwrap();
        assert_eq!(
            claims(&both)["roles"],
            serde_json::json!(["reader", "writer"])
        );
    }

    #[tokio::test]
    async fn without_a_retry_window_the_previous_token_is_reuse_at_once() {
        let (_file, config, runtime) = runtime_with(|policy| {
            policy["retry_window_seconds"] = 0.into();
        })
        .await;
        let (metrics, browser, granting) = (Metrics::new(), browser(&config), granting(&config));
        let refresh = |token| refreshed(&runtime, token, &granting, &browser, &metrics);
        let invalid = Some(RefreshGrantError::InvalidGrant);
        let first = family(&runtime, &grant()).await;
        let second = refresh_token(&refresh(&first).await.unwrap());
        assert_eq!(refresh(&first).await.err(), invalid);
        assert_eq!(refresh(&second).await.err(), invalid);
        counted(&metrics, "reuse_detected", 1);
    }

    #[tokio::test]
    async fn the_previous_token_past_its_window_or_sealed_otherwise_is_not_answered() {
        let (_file, config, runtime) = runtime().await;
        let (metrics, browser, granting) = (Metrics::new(), browser(&config), granting(&config));
        let refresh = |token| refreshed(&runtime, token, &granting, &browser, &metrics);
        let invalid = Some(RefreshGrantError::InvalidGrant);
        let RefreshBackend::Memory(store) = runtime.refresh.as_ref().unwrap() else {
            unreachable!()
        };
        let now = runtime.now().await.unwrap();
        let fixture = grant();
        // Rotated just over the window ago: presenting it again is reuse.
        let rotated = |token: RefreshToken, at, sealed: String| {
            let fixture = &fixture;
            async move {
                let next = RefreshToken::generate().unwrap();
                let rotation = Rotation {
                    next: next.hash(),
                    sealed: &sealed,
                    grant: fixture,
                    idle_ttl_seconds: 600,
                    ceiling: now + 3_600_000,
                    retry_window_ms: 30_000,
                };
                let outcome = store.rotate(&token.hash(), &rotation, at).await.unwrap();
                assert_eq!(outcome, Rotated::Rotated);
                (token, next)
            }
        };
        let issued = RefreshToken::generate().unwrap();
        let policy = runtime.refresh_policy("desktop").unwrap();
        store
            .issue(&grant(), issued.hash(), now - 60_000, policy, None)
            .await
            .unwrap();
        let (old, next) = rotated(issued, now - 30_001, "unused".into()).await;
        assert_eq!(refresh(&old).await.err(), invalid);
        assert_eq!(refresh(&next).await.err(), invalid);
        // Moments ago, but sealed by another token: rejected, the family is kept.
        let (old, next) = rotated(family(&runtime, &grant()).await, now, {
            let other = RefreshToken::generate().unwrap();
            other
                .seal_successor(&runtime.retry_key, "family", &other)
                .unwrap()
        })
        .await;
        assert_eq!(refresh(&old).await.err(), invalid);
        // Another client presenting the previous token is rejected too.
        let other = RefreshRequest {
            client_id: "other",
            ..request(&old)
        };
        let response = runtime.refresh(other, &granting, &browser, &metrics).await;
        assert_eq!(response.err(), invalid);
        refresh(&next).await.unwrap();
        counted(&metrics, "retried", 0);
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

// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! Explicit opt-in authorization-server runtime; dispatch retains backend atomic contracts.

use super::{
    authorization::ValidatedAuthorizationRequest,
    codes::{AuthorizationCode, CodeIssueOutcome, CodeStoreError},
    consent::ConsentToken,
    context::AuthenticatedAuthorization,
    keys::KeyManager,
    rate_limit::EndpointRateLimiter,
    records::BoundAuthorizationTransaction,
    refresh_durability::{self, Durability},
    refresh_grant::RefreshBackend,
    refresh_store::MemoryRefreshStore,
    retry_key::{self, RetryKey},
    store::{
        CreatedTransaction, MemoryTransactionStore, RedeemedAuthorization, StoreError,
        TransactionId,
    },
    tokens::{TokenError, TokenIssuer, TokenResponse},
    upstream::Upstream,
    valkey_refresh::ValkeyRefreshStore,
    valkey_transactions::ValkeyTransactionStore,
};
use crate::{
    config::{ConfigV2, OAuthConfig, ui::BrowserBackendConfig},
    oidc::upstream::UpstreamCipher,
};
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

/// State of the authorization flow bound to a browser cookie pair.
pub(crate) enum ActiveFlow {
    /// Awaiting login.
    Pending(Box<BoundAuthorizationTransaction>),
    /// Logged in; awaiting or showing consent.
    PastPending(Box<AuthenticatedAuthorization>),
    /// Expired, consumed, or bound to another browser.
    Missing,
}
impl ActiveFlow {
    /// `None` for `Missing`; otherwise whether the stored request equals `request`.
    pub(crate) fn same_request(&self, request: &ValidatedAuthorizationRequest) -> Option<bool> {
        let stored = match self {
            Self::Pending(bound) => bound.transaction().request(),
            Self::PastPending(context) => context.transaction().request(),
            Self::Missing => return None,
        };
        Some(stored.same_request(request))
    }
}
enum Backend {
    Memory(Box<MemoryTransactionStore>),
    Valkey(Box<ValkeyTransactionStore>),
}
pub struct OAuthRuntime {
    pub(crate) config: Arc<OAuthConfig>,
    pub(crate) keys: KeyManager,
    pub(crate) origin: String,
    backend: Backend,
    pub(crate) rate_limit: EndpointRateLimiter,
    /// Present only when at least one client enables refresh tokens.
    pub(super) refresh: Option<RefreshBackend>,
    /// Present when `upstream_token_encryption` is configured.
    pub(super) upstream: Option<Upstream>,
    pub(super) retry_key: RetryKey,
}
macro_rules! dispatch {
    ($self:expr, $method:ident($($arg:expr),*)) => {
        match &$self.backend {
            Backend::Memory(store) => store.$method($($arg),*).await,
            Backend::Valkey(store) => store.$method($($arg),*).await,
        }
    };
}
impl OAuthRuntime {
    pub(crate) fn nonce() -> Result<TransactionId, StoreError> {
        TransactionId::generate()
    }
    pub(crate) fn validate(config: &ConfigV2) -> Result<(), &'static str> {
        config.oauth.validate()?;
        if !config.oauth.enabled {
            return Ok(());
        }
        if !config.ui.enabled
            || crate::config::browser_methods(&config.providers, &config.ui.oidc).is_empty()
        {
            return Err("OAuth requires enabled UI and at least one browser sign-in method");
        }
        if config.oauth.signing.is_none()
            || config.oauth.clients.is_empty()
            || config.oauth.resources.is_empty()
        {
            return Err("OAuth requires signing keys, preregistered clients and resources");
        }
        retry_key::validate(config)?;
        if config.oauth.max_authorization_transactions < config.oauth.clients.len() {
            return Err("OAuth transaction capacity must reserve at least one slot per client");
        }
        let session = config
            .ui
            .browser_session
            .as_ref()
            .ok_or("OAuth requires browser session settings")?;
        session.validate()?;
        let issuer = config
            .oauth
            .issuer
            .as_deref()
            .ok_or("OAuth requires issuer")?;
        if issuer.len() > 2048
            || url::Url::parse(issuer)
                .map_err(|_| "invalid issuer")?
                .origin()
                .ascii_serialization()
                != session.origin()?
        {
            return Err("OAuth issuer and browser public origin must match");
        }
        Ok(())
    }
    pub(crate) async fn initialize(
        config: &ConfigV2,
    ) -> Result<Option<Arc<Self>>, Box<dyn std::error::Error>> {
        Self::validate(config)?;
        if !config.oauth.enabled {
            return Ok(None);
        }
        let cfg = Arc::new((*config.oauth).clone());
        let keys = KeyManager::load(cfg.signing.as_ref().ok_or("missing signing config")?)?;
        TokenIssuer::new(&cfg, &keys)?;
        let retry_key = RetryKey::load(config)?;
        let session = config
            .ui
            .browser_session
            .as_ref()
            .ok_or("missing browser config")?;
        let backend = match &session.backend {
            BrowserBackendConfig::Memory {} => Backend::Memory(Box::new(
                MemoryTransactionStore::new(cfg.clone()).map_err(|_| "OAuth memory unavailable")?,
            )),
            backend => Backend::Valkey(Box::new(
                ValkeyTransactionStore::new(cfg.clone(), backend)
                    .await
                    .map_err(|_| "OAuth Valkey unavailable")?,
            )),
        };
        let refresh = if !cfg
            .clients
            .iter()
            .any(|client| client.refresh_tokens.enabled)
        {
            None
        } else if let BrowserBackendConfig::Memory {} = &session.backend {
            Some(RefreshBackend::Memory(Box::new(MemoryRefreshStore::new(
                cfg.max_refresh_token_families_per_user,
            ))))
        } else {
            Some(RefreshBackend::Valkey(Box::new(
                ValkeyRefreshStore::new(&session.backend, cfg.max_refresh_token_families_per_user)
                    .await
                    .map_err(|_| "OAuth refresh-token Valkey unavailable")?,
            )))
        };
        match &refresh {
            Some(RefreshBackend::Memory(_)) => refresh_durability::report(Durability::Memory),
            Some(RefreshBackend::Valkey(store)) => {
                refresh_durability::report(store.durability().await)
            }
            None => {}
        }
        let upstream = match &cfg.upstream_token_encryption {
            Some(encryption) => Some(Upstream::start(UpstreamCipher::load(encryption)?)),
            None => None,
        };
        let rate_limit = EndpointRateLimiter::new(&cfg.endpoint_rate_limit)?;
        Ok(Some(Arc::new(Self {
            config: cfg,
            keys,
            origin: session.origin()?,
            backend,
            rate_limit,
            refresh,
            upstream,
            retry_key,
        })))
    }
    pub(crate) async fn create(
        &self,
        request: ValidatedAuthorizationRequest,
        hash: [u8; 32],
    ) -> Result<CreatedTransaction, StoreError> {
        dispatch!(self, create(request, hash))
    }
    pub(crate) async fn bound(
        &self,
        id: &TransactionId,
        hash: &[u8; 32],
    ) -> Result<BoundAuthorizationTransaction, StoreError> {
        dispatch!(self, lookup_bound(id, hash))
    }
    /// Atomically consumes a pending transaction, e.g. after a policy denial at login.
    pub(crate) async fn consume_pending(
        &self,
        id: &TransactionId,
        hash: &[u8; 32],
    ) -> Result<super::records::AuthorizationTransaction, StoreError> {
        dispatch!(self, consume(id, hash))
    }
    /// Atomically removes a post-login record that current policy no longer permits.
    pub(crate) async fn reject_ineligible(
        &self,
        id: &TransactionId,
        hash: &[u8; 32],
    ) -> Result<super::records::AuthorizationTransaction, StoreError> {
        dispatch!(self, reject_ineligible(id, hash))
    }
    pub(crate) async fn promote(
        &self,
        id: &TransactionId,
        hash: &[u8; 32],
        context: AuthenticatedAuthorization,
    ) -> Result<(), StoreError> {
        dispatch!(self, promote_authenticated(id, hash, context))
    }
    /// Reads the post-login state: a promoted (authenticated) context, or a consent-ready one.
    pub(crate) async fn authenticated_or_consent(
        &self,
        id: &TransactionId,
        hash: &[u8; 32],
    ) -> Result<AuthenticatedAuthorization, StoreError> {
        match dispatch!(self, lookup_authenticated(id, hash)) {
            Ok(context) => Ok(context),
            Err(StoreError::Missing) => self.consent_context(id, hash).await,
            Err(error) => Err(error),
        }
    }
    /// Classifies the browser-bound flow with one pending lookup and, only when that is
    /// missing, one post-login lookup. Backend failures are returned unchanged.
    pub(crate) async fn active_flow(
        &self,
        id: &TransactionId,
        hash: &[u8; 32],
    ) -> Result<ActiveFlow, StoreError> {
        match self.bound(id, hash).await {
            Ok(bound) => return Ok(ActiveFlow::Pending(Box::new(bound))),
            Err(StoreError::Missing) => {}
            Err(error) => return Err(error),
        }
        match self.authenticated_or_consent(id, hash).await {
            Ok(context) => Ok(ActiveFlow::PastPending(Box::new(context))),
            Err(StoreError::Missing) => Ok(ActiveFlow::Missing),
            Err(error) => Err(error),
        }
    }
    pub(crate) async fn prepare(
        &self,
        id: &TransactionId,
        hash: &[u8; 32],
    ) -> Result<ConsentToken, StoreError> {
        dispatch!(self, prepare_consent(id, hash))
    }
    pub(crate) async fn consent_context(
        &self,
        id: &TransactionId,
        hash: &[u8; 32],
    ) -> Result<AuthenticatedAuthorization, StoreError> {
        dispatch!(self, consent_context(id, hash))
    }
    pub(crate) async fn issue(
        &self,
        id: &TransactionId,
        hash: &[u8; 32],
        csrf: &str,
        decision: &str,
    ) -> Result<CodeIssueOutcome, CodeStoreError> {
        dispatch!(self, issue_code(id, hash, csrf, decision))
    }
    pub(crate) async fn redeem(
        &self,
        code: &AuthorizationCode,
        client: &str,
        callback: &str,
        resource: &str,
        verifier: &str,
    ) -> Result<RedeemedAuthorization, CodeStoreError> {
        dispatch!(
            self,
            redeem_code(code, client, callback, resource, verifier)
        )
    }
    pub(crate) async fn now(&self) -> Result<u64, StoreError> {
        match &self.backend {
            Backend::Valkey(store) => store.server_now_ms().await,
            Backend::Memory(_) => SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()
                .and_then(|time| u64::try_from(time.as_millis()).ok())
                .filter(|ms| super::records::valid_time(*ms))
                .ok_or(StoreError::Unavailable),
        }
    }
    pub(crate) fn token(&self, proof: RedeemedAuthorization) -> Result<TokenResponse, TokenError> {
        TokenIssuer::new(&self.config, &self.keys)?.issue_from_redeemed(proof)
    }
}

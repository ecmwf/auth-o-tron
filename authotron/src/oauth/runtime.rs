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
    records::BoundAuthorizationTransaction,
    store::{
        CreatedTransaction, MemoryTransactionStore, RedeemedAuthorization, StoreError,
        TransactionId,
    },
    tokens::{TokenError, TokenIssuer, TokenResponse},
    valkey_transactions::ValkeyTransactionStore,
};
use crate::config::{ConfigV2, OAuthConfig, ui::BrowserBackendConfig};
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

enum Backend {
    Memory(Box<MemoryTransactionStore>),
    Valkey(Box<ValkeyTransactionStore>),
}
pub struct OAuthRuntime {
    pub(crate) config: Arc<OAuthConfig>,
    pub(crate) keys: KeyManager,
    pub(crate) origin: String,
    backend: Backend,
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
        if !config.ui.enabled || !config.ui.has_direct_login() {
            return Err("OAuth requires enabled UI and a direct login provider");
        }
        if config.oauth.signing.is_none()
            || config.oauth.clients.is_empty()
            || config.oauth.resources.is_empty()
        {
            return Err("OAuth requires signing keys, preregistered clients and resources");
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
        Ok(Some(Arc::new(Self {
            config: cfg,
            keys,
            origin: session.origin()?,
            backend,
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
    pub(crate) async fn promote(
        &self,
        id: &TransactionId,
        hash: &[u8; 32],
        context: AuthenticatedAuthorization,
    ) -> Result<(), StoreError> {
        dispatch!(self, promote_authenticated(id, hash, context))
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

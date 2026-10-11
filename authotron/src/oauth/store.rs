// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! Explicit development-only transaction storage; not shared across replicas.

use super::{
    authorization::ValidatedAuthorizationRequest,
    consent::{ConsentError, ConsentOutcome, ConsentSession, ConsentToken},
    context::AuthenticatedAuthorization,
    records::{AuthorizationTransaction, BoundAuthorizationTransaction, valid_time},
};
use crate::config::OAuthConfig;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rsa::rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, hash_map::Entry},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreError {
    Configuration,
    Missing,
    Limited,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentStoreError {
    Missing,
    InvalidToken,
    InvalidDecision,
    Unavailable,
}

/// Bearer-like identifier, deliberately not Debug/Serialize. Browser binding is also required.
pub struct TransactionId(String);
impl TransactionId {
    pub(super) fn generate() -> Result<Self, StoreError> {
        let mut random = [0; 32];
        OsRng
            .try_fill_bytes(&mut random)
            .map_err(|_| StoreError::Unavailable)?;
        Ok(Self(URL_SAFE_NO_PAD.encode(random)))
    }
    pub fn parse(value: &str) -> Result<Self, StoreError> {
        if value.len() != 43 {
            return Err(StoreError::Missing);
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|_| StoreError::Missing)?;
        if bytes.len() != 32 || URL_SAFE_NO_PAD.encode(bytes) != value {
            return Err(StoreError::Missing);
        }
        Ok(Self(value.into()))
    }
    pub fn as_secret_str(&self) -> &str {
        &self.0
    }
    pub(super) fn hash(&self) -> [u8; 32] {
        Sha256::digest(self.0.as_bytes()).into()
    }
}

pub struct CreatedTransaction {
    pub id: TransactionId,
    pub expires_at_ms: u64,
}
enum StoredKind {
    Pending,
    Authenticated,
    ConsentReady,
}
struct Stored {
    kind: StoredKind,
    bytes: Vec<u8>,
    expires_at_ms: u64,
}
pub struct MemoryTransactionStore {
    config: Arc<OAuthConfig>,
    entries: Mutex<HashMap<[u8; 32], Stored>>,
}

fn now_ms() -> Result<u64, StoreError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| StoreError::Unavailable)?
        .as_millis()
        .try_into()
        .map_err(|_| StoreError::Unavailable)
}

impl MemoryTransactionStore {
    /// Explicit opt-in for development: no default/fallback, startup hook or background task.
    pub fn new(config: Arc<OAuthConfig>) -> Result<Self, StoreError> {
        config.validate().map_err(|_| StoreError::Configuration)?;
        if config
            .issuer
            .as_ref()
            .is_none_or(|issuer| issuer.len() > 2048)
        {
            return Err(StoreError::Configuration);
        }
        Ok(Self {
            config,
            entries: Mutex::new(HashMap::new()),
        })
    }
    pub async fn create(
        &self,
        request: ValidatedAuthorizationRequest,
        browser_hash: [u8; 32],
    ) -> Result<CreatedTransaction, StoreError> {
        self.create_at(request, browser_hash, now_ms)
    }
    pub async fn lookup(
        &self,
        id: &TransactionId,
        browser_hash: &[u8; 32],
    ) -> Result<AuthorizationTransaction, StoreError> {
        self.access_at(id, browser_hash, now_ms, false)
    }
    pub async fn lookup_bound(
        &self,
        id: &TransactionId,
        browser_hash: &[u8; 32],
    ) -> Result<BoundAuthorizationTransaction, StoreError> {
        let transaction = self.lookup(id, browser_hash).await?;
        Ok(BoundAuthorizationTransaction::from_store(
            transaction,
            id.hash(),
        ))
    }
    pub async fn consume(
        &self,
        id: &TransactionId,
        browser_hash: &[u8; 32],
    ) -> Result<AuthorizationTransaction, StoreError> {
        self.access_at(id, browser_hash, now_ms, true)
    }
    pub async fn promote_authenticated(
        &self,
        id: &TransactionId,
        browser_hash: &[u8; 32],
        context: AuthenticatedAuthorization,
    ) -> Result<(), StoreError> {
        self.promote_at(id, browser_hash, context, now_ms)
    }
    pub async fn lookup_authenticated(
        &self,
        id: &TransactionId,
        browser_hash: &[u8; 32],
    ) -> Result<AuthenticatedAuthorization, StoreError> {
        self.authenticated_at(id, browser_hash, now_ms, false)
    }
    pub async fn consume_authenticated(
        &self,
        id: &TransactionId,
        browser_hash: &[u8; 32],
    ) -> Result<AuthenticatedAuthorization, StoreError> {
        self.authenticated_at(id, browser_hash, now_ms, true)
    }
    pub async fn prepare_consent(
        &self,
        id: &TransactionId,
        browser_hash: &[u8; 32],
    ) -> Result<ConsentToken, StoreError> {
        self.prepare_consent_at(id, browser_hash, now_ms)
    }
    pub async fn decide_consent(
        &self,
        id: &TransactionId,
        browser_hash: &[u8; 32],
        submitted_csrf: &str,
        decision: &str,
    ) -> Result<ConsentOutcome, ConsentStoreError> {
        self.decide_consent_at(id, browser_hash, submitted_csrf, decision, now_ms)
    }
    fn create_at(
        &self,
        request: ValidatedAuthorizationRequest,
        binding: [u8; 32],
        clock: impl FnOnce() -> Result<u64, StoreError>,
    ) -> Result<CreatedTransaction, StoreError> {
        let mut entries = self.entries.lock().map_err(|_| StoreError::Unavailable)?;
        let now = clock()?;
        if !valid_time(now) {
            return Err(StoreError::Unavailable);
        }
        let expiry = now
            .checked_add(
                self.config
                    .authorization_transaction_ttl_seconds
                    .checked_mul(1000)
                    .ok_or(StoreError::Unavailable)?,
            )
            .ok_or(StoreError::Unavailable)?;
        let record = AuthorizationTransaction::new(request, binding, expiry)
            .map_err(|_| StoreError::Unavailable)?;
        let bytes = record.encode().map_err(|_| StoreError::Unavailable)?;
        AuthorizationTransaction::decode(&bytes, &self.config, now)
            .map_err(|_| StoreError::Unavailable)?;
        entries.retain(|_, record| record.expires_at_ms > now);
        if entries.len() >= self.config.max_authorization_transactions {
            return Err(StoreError::Limited);
        }
        for _ in 0..4 {
            let id = TransactionId::generate()?;
            if let Entry::Vacant(slot) = entries.entry(id.hash()) {
                slot.insert(Stored {
                    kind: StoredKind::Pending,
                    bytes,
                    expires_at_ms: expiry,
                });
                return Ok(CreatedTransaction {
                    id,
                    expires_at_ms: expiry,
                });
            }
        }
        Err(StoreError::Unavailable)
    }
    fn access_at(
        &self,
        id: &TransactionId,
        binding: &[u8; 32],
        clock: impl FnOnce() -> Result<u64, StoreError>,
        consume: bool,
    ) -> Result<AuthorizationTransaction, StoreError> {
        let mut entries = self.entries.lock().map_err(|_| StoreError::Unavailable)?;
        let now = clock()?;
        if !valid_time(now) {
            return Err(StoreError::Unavailable);
        }
        entries.retain(|_, record| record.expires_at_ms > now);
        let key = id.hash();
        let stored = entries.get(&key).ok_or(StoreError::Missing)?;
        if !matches!(stored.kind, StoredKind::Pending) {
            return Err(StoreError::Missing);
        }
        let record = AuthorizationTransaction::decode(&stored.bytes, &self.config, now)
            .map_err(|_| StoreError::Unavailable)?;
        if !record.matches_browser_binding(binding) {
            return Err(StoreError::Missing);
        }
        // No await while locked: validation and removal share one critical section.
        if consume {
            entries.remove(&key);
        }
        Ok(record)
    }
    fn promote_at(
        &self,
        id: &TransactionId,
        binding: &[u8; 32],
        context: AuthenticatedAuthorization,
        clock: impl FnOnce() -> Result<u64, StoreError>,
    ) -> Result<(), StoreError> {
        let mut entries = self.entries.lock().map_err(|_| StoreError::Unavailable)?;
        let now = clock()?;
        if !valid_time(now) {
            return Err(StoreError::Unavailable);
        }
        entries.retain(|_, entry| entry.expires_at_ms > now);
        let stored = entries.get_mut(&id.hash()).ok_or(StoreError::Missing)?;
        if !matches!(stored.kind, StoredKind::Pending) {
            return Err(StoreError::Missing);
        }
        let pending = AuthorizationTransaction::decode(&stored.bytes, &self.config, now)
            .map_err(|_| StoreError::Unavailable)?;
        if !pending.matches_browser_binding(binding) {
            return Err(StoreError::Missing);
        }
        if !context.matches_source(&id.hash()) {
            return Err(StoreError::Unavailable);
        }
        let source = context
            .transaction()
            .encode()
            .map_err(|_| StoreError::Unavailable)?;
        if source != stored.bytes || pending.expires_at_ms() != stored.expires_at_ms {
            return Err(StoreError::Unavailable);
        }
        let bytes = context.encode().map_err(|_| StoreError::Unavailable)?;
        let checked = AuthenticatedAuthorization::decode(&bytes, &self.config, binding, now)
            .map_err(|_| StoreError::Unavailable)?;
        if checked.expires_at_ms() > stored.expires_at_ms {
            return Err(StoreError::Unavailable);
        }
        // All checks precede replacement; the hashed key and capacity slot remain unchanged.
        *stored = Stored {
            kind: StoredKind::Authenticated,
            bytes,
            expires_at_ms: checked.expires_at_ms(),
        };
        Ok(())
    }
    fn authenticated_at(
        &self,
        id: &TransactionId,
        binding: &[u8; 32],
        clock: impl FnOnce() -> Result<u64, StoreError>,
        consume: bool,
    ) -> Result<AuthenticatedAuthorization, StoreError> {
        let mut entries = self.entries.lock().map_err(|_| StoreError::Unavailable)?;
        let now = clock()?;
        if !valid_time(now) {
            return Err(StoreError::Unavailable);
        }
        entries.retain(|_, entry| entry.expires_at_ms > now);
        let key = id.hash();
        let stored = entries.get(&key).ok_or(StoreError::Missing)?;
        if !matches!(stored.kind, StoredKind::Authenticated) {
            return Err(StoreError::Missing);
        }
        let context = AuthenticatedAuthorization::decode(&stored.bytes, &self.config, binding, now)
            .map_err(|error| match error {
                super::context::ContextError::Binding => StoreError::Missing,
                _ => StoreError::Unavailable,
            })?;
        if !context.matches_source(&key) || context.expires_at_ms() > stored.expires_at_ms {
            return Err(StoreError::Unavailable);
        }
        if consume {
            entries.remove(&key);
        }
        Ok(context)
    }
    fn prepare_consent_at(
        &self,
        id: &TransactionId,
        binding: &[u8; 32],
        clock: impl FnOnce() -> Result<u64, StoreError>,
    ) -> Result<ConsentToken, StoreError> {
        let mut entries = self.entries.lock().map_err(|_| StoreError::Unavailable)?;
        let now = clock()?;
        if !valid_time(now) {
            return Err(StoreError::Unavailable);
        }
        entries.retain(|_, entry| entry.expires_at_ms > now);
        let key = id.hash();
        let stored = entries.get_mut(&key).ok_or(StoreError::Missing)?;
        let (session, token) = match stored.kind {
            StoredKind::Pending => return Err(StoreError::Missing),
            StoredKind::Authenticated => {
                let context =
                    AuthenticatedAuthorization::decode(&stored.bytes, &self.config, binding, now)
                        .map_err(|error| match error {
                        super::context::ContextError::Binding => StoreError::Missing,
                        _ => StoreError::Unavailable,
                    })?;
                if !context.matches_source(&key) {
                    return Err(StoreError::Unavailable);
                }
                ConsentSession::from_stored_context(
                    context,
                    id,
                    &self.config,
                    binding,
                    now,
                    stored.expires_at_ms,
                )
            }
            StoredKind::ConsentReady => {
                let session = ConsentSession::decode(&stored.bytes, id, &self.config, binding, now)
                    .map_err(|_| StoreError::Unavailable)?;
                if session.expires_at_ms() > stored.expires_at_ms {
                    return Err(StoreError::Unavailable);
                }
                session.renew(id, &self.config, binding, now)
            }
        }
        .map_err(|_| StoreError::Unavailable)?;
        let bytes = session.encode().map_err(|_| StoreError::Unavailable)?;
        *stored = Stored {
            kind: StoredKind::ConsentReady,
            bytes,
            expires_at_ms: session.expires_at_ms().min(stored.expires_at_ms),
        };
        Ok(token)
    }
    fn decide_consent_at(
        &self,
        id: &TransactionId,
        binding: &[u8; 32],
        submitted: &str,
        decision: &str,
        clock: impl FnOnce() -> Result<u64, StoreError>,
    ) -> Result<ConsentOutcome, ConsentStoreError> {
        use ConsentStoreError::*;
        let mut entries = self.entries.lock().map_err(|_| Unavailable)?;
        let now = clock().map_err(|_| Unavailable)?;
        if !valid_time(now) {
            return Err(Unavailable);
        }
        entries.retain(|_, entry| entry.expires_at_ms > now);
        let key = id.hash();
        let stored = entries.get(&key).ok_or(Missing)?;
        if !matches!(stored.kind, StoredKind::ConsentReady) {
            return Err(Missing);
        }
        let session = ConsentSession::decode(&stored.bytes, id, &self.config, binding, now)
            .map_err(|_| Unavailable)?;
        if session.expires_at_ms() > stored.expires_at_ms {
            return Err(Unavailable);
        }
        let outcome = session
            .decide(submitted, decision, id, binding, &self.config, now)
            .map_err(|error| match error {
                ConsentError::InvalidToken => InvalidToken,
                ConsentError::InvalidDecision => InvalidDecision,
                _ => Unavailable,
            })?;
        // No await while locked; only validated explicit decisions remove the record.
        entries.remove(&key);
        Ok(outcome)
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::oauth::authorization::validate_authorization_request;
    use serde_json::json;

    pub(in crate::oauth) fn config() -> Arc<OAuthConfig> {
        Arc::new(serde_json::from_value(json!({"issuer": "https://login.example.org", "authorization_transaction_ttl_seconds": 30, "max_authorization_transactions": 1,
            "clients": [{"client_id": "desktop", "display_name": "Desktop", "redirect_uris": ["https://app.example.org/cb"], "resources": [{"resource": "https://mcp.example.org/mcp", "scopes": ["read"]}]}],
            "resources": [{"resource": "https://mcp.example.org/mcp", "allowed_realms": ["local"], "scopes": [{"name": "read", "required_roles": ["reader"]}]}]})).unwrap())
    }
    pub(in crate::oauth) fn request(config: &OAuthConfig) -> ValidatedAuthorizationRequest {
        validate_authorization_request(config, b"client_id=desktop&redirect_uri=https://app.example.org/cb&response_type=code&resource=https://mcp.example.org/mcp&scope=read&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256").unwrap()
    }
    fn at(now: u64) -> impl FnOnce() -> Result<u64, StoreError> {
        move || Ok(now)
    }
    async fn authenticated_fixture() -> (
        MemoryTransactionStore,
        CreatedTransaction,
        AuthenticatedAuthorization,
        u64,
    ) {
        let (mut config, _, identity) = super::super::context::tests::fixture().await;
        config.max_authorization_transactions = 1;
        config.max_authentication_age_seconds = 1;
        let now = identity.verified_at_ms();
        let config = Arc::new(config);
        let store = MemoryTransactionStore::new(config.clone()).unwrap();
        let created = store.create_at(request(&config), [7; 32], at(now)).unwrap();
        let source = store.lookup_bound(&created.id, &[7; 32]).await.unwrap();
        let context =
            AuthenticatedAuthorization::new_bound(source, identity, &[7; 32], &config, now)
                .unwrap();
        (store, created, context, now)
    }
    #[tokio::test]
    async fn consent_preparation_rotation_capacity_and_invalid_decisions_preserve_state() {
        let (store, created, context, now) = authenticated_fixture().await;
        assert_eq!(
            store.prepare_consent(&created.id, &[7; 32]).await.err(),
            Some(StoreError::Missing)
        );
        store
            .promote_at(&created.id, &[7; 32], context, at(now))
            .unwrap();
        let first = store.prepare_consent(&created.id, &[7; 32]).await.unwrap();
        let second = store
            .prepare_consent_at(&created.id, &[7; 32], at(now + 500))
            .unwrap();
        let bytes = store.entries.lock().unwrap()[&created.id.hash()]
            .bytes
            .clone();
        assert!(
            !std::str::from_utf8(&bytes)
                .unwrap()
                .contains(second.as_secret_str())
        );
        assert_eq!(store.entries.lock().unwrap().len(), 1);
        assert_eq!(
            store.entries.lock().unwrap()[&created.id.hash()].expires_at_ms,
            now + 1000
        );
        assert_eq!(
            store
                .create_at(request(&store.config), [7; 32], at(now + 500))
                .err(),
            Some(StoreError::Limited)
        );
        assert_eq!(
            store.lookup(&created.id, &[7; 32]).await.err(),
            Some(StoreError::Missing)
        );
        assert_eq!(
            store
                .lookup_authenticated(&created.id, &[7; 32])
                .await
                .err(),
            Some(StoreError::Missing)
        );
        for (token, decision, hash, expected) in [
            (
                first.as_secret_str(),
                "approve",
                [7; 32],
                ConsentStoreError::InvalidToken,
            ),
            (
                second.as_secret_str(),
                "other",
                [7; 32],
                ConsentStoreError::InvalidDecision,
            ),
            (
                second.as_secret_str(),
                "approve",
                [8; 32],
                ConsentStoreError::Unavailable,
            ),
        ] {
            assert_eq!(
                store
                    .decide_consent_at(&created.id, &hash, token, decision, at(now + 500))
                    .err(),
                Some(expected)
            );
            assert!(store.entries.lock().unwrap()[&created.id.hash()].bytes == bytes);
        }
        let outcome = store
            .decide_consent(&created.id, &[7; 32], second.as_secret_str(), "approve")
            .await
            .unwrap();
        assert!(matches!(outcome, ConsentOutcome::Approved(_)));
        assert_eq!(
            store
                .decide_consent(&created.id, &[7; 32], second.as_secret_str(), "approve")
                .await
                .err(),
            Some(ConsentStoreError::Missing)
        );
        assert!(store.create(request(&store.config), [7; 32]).await.is_ok());
    }
    #[tokio::test]
    async fn consent_expiry_denial_corruption_and_failed_preparation_are_fail_closed() {
        let (store, created, context, now) = authenticated_fixture().await;
        store
            .promote_at(&created.id, &[7; 32], context, at(now))
            .unwrap();
        let original = store.entries.lock().unwrap()[&created.id.hash()]
            .bytes
            .clone();
        assert_eq!(
            store
                .prepare_consent_at(&created.id, &[8; 32], at(now))
                .err(),
            Some(StoreError::Missing)
        );
        assert!(store.entries.lock().unwrap()[&created.id.hash()].bytes == original);
        let token = store
            .prepare_consent_at(&created.id, &[7; 32], at(now))
            .unwrap();
        assert!(matches!(
            store.decide_consent_at(
                &created.id,
                &[7; 32],
                token.as_secret_str(),
                "deny",
                at(now)
            ),
            Ok(ConsentOutcome::Denied)
        ));
        assert_eq!(store.entries.lock().unwrap().len(), 0);
        let (store, created, context, now) = authenticated_fixture().await;
        store
            .promote_at(&created.id, &[7; 32], context, at(now))
            .unwrap();
        let token = store
            .prepare_consent_at(&created.id, &[7; 32], at(now))
            .unwrap();
        assert_eq!(
            store
                .decide_consent_at(
                    &created.id,
                    &[7; 32],
                    token.as_secret_str(),
                    "approve",
                    at(now + 1000)
                )
                .err(),
            Some(ConsentStoreError::Missing)
        );
        assert!(
            store
                .create_at(request(&store.config), [7; 32], at(now + 1000))
                .is_ok()
        );
        let (store, created, context, now) = authenticated_fixture().await;
        store
            .promote_at(&created.id, &[7; 32], context, at(now))
            .unwrap();
        let token = store
            .prepare_consent_at(&created.id, &[7; 32], at(now))
            .unwrap();
        store
            .entries
            .lock()
            .unwrap()
            .get_mut(&created.id.hash())
            .unwrap()
            .bytes = b"invalid consent".to_vec();
        assert_eq!(
            store
                .prepare_consent_at(&created.id, &[7; 32], at(now))
                .err(),
            Some(StoreError::Unavailable)
        );
        assert_eq!(
            store
                .decide_consent_at(
                    &created.id,
                    &[7; 32],
                    token.as_secret_str(),
                    "approve",
                    at(now)
                )
                .err(),
            Some(ConsentStoreError::Unavailable)
        );
        assert_eq!(store.entries.lock().unwrap().len(), 1);
    }
    #[tokio::test]
    async fn concurrent_consent_decisions_have_exactly_one_approved_winner() {
        let (store, created, context, now) = authenticated_fixture().await;
        store
            .promote_at(&created.id, &[7; 32], context, at(now))
            .unwrap();
        let token = Arc::new(
            store
                .prepare_consent_at(&created.id, &[7; 32], at(now))
                .unwrap(),
        );
        let store = Arc::new(store);
        let id = Arc::new(created.id);
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let workers = (0..2)
            .map(|_| {
                let (store, id, token, barrier) =
                    (store.clone(), id.clone(), token.clone(), barrier.clone());
                std::thread::spawn(move || {
                    barrier.wait();
                    match store.decide_consent_at(
                        &id,
                        &[7; 32],
                        token.as_secret_str(),
                        "approve",
                        at(now),
                    ) {
                        Ok(ConsentOutcome::Approved(_)) => Ok(()),
                        Err(error) => Err(error),
                        _ => panic!("approval unexpectedly denied"),
                    }
                })
            })
            .collect::<Vec<_>>();
        let outcomes = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            outcomes
                .iter()
                .filter(|result| **result == Err(ConsentStoreError::Missing))
                .count(),
            1
        );
        assert_eq!(store.entries.lock().unwrap().len(), 0);
    }
    #[tokio::test]
    async fn source_witness_prevents_identical_payload_id_aliasing_and_cache_copy() {
        let (mut config, _, identity) = super::super::context::tests::fixture().await;
        config.max_authorization_transactions = 2;
        let now = identity.verified_at_ms();
        let store = MemoryTransactionStore::new(Arc::new(config)).unwrap();
        let a = store
            .create_at(request(&store.config), [7; 32], at(now))
            .unwrap();
        let b = store
            .create_at(request(&store.config), [7; 32], at(now))
            .unwrap();
        assert!(a.id.hash() != b.id.hash());
        {
            let entries = store.entries.lock().unwrap();
            assert!(entries[&a.id.hash()].bytes == entries[&b.id.hash()].bytes);
            assert_eq!(
                entries[&a.id.hash()].expires_at_ms,
                entries[&b.id.hash()].expires_at_ms
            );
        }
        let source = store.lookup_bound(&a.id, &[7; 32]).await.unwrap();
        let context =
            AuthenticatedAuthorization::new_bound(source, identity, &[7; 32], &store.config, now)
                .unwrap();
        let saved = context.encode().unwrap();
        assert_eq!(
            store.promote_at(&b.id, &[7; 32], context, at(now)).err(),
            Some(StoreError::Unavailable)
        );
        assert!(store.access_at(&a.id, &[7; 32], at(now), false).is_ok());
        assert!(store.access_at(&b.id, &[7; 32], at(now), false).is_ok());
        let restored =
            AuthenticatedAuthorization::decode(&saved, &store.config, &[7; 32], now).unwrap();
        store
            .promote_at(&a.id, &[7; 32], restored, at(now))
            .unwrap();
        assert!(
            store
                .authenticated_at(&a.id, &[7; 32], at(now), false)
                .is_ok()
        );
        {
            let mut entries = store.entries.lock().unwrap();
            let original = &entries[&a.id.hash()];
            let copied = Stored {
                kind: StoredKind::Authenticated,
                bytes: original.bytes.clone(),
                expires_at_ms: original.expires_at_ms,
            };
            entries.insert(b.id.hash(), copied);
        }
        for consume in [false, true] {
            assert_eq!(
                store
                    .authenticated_at(&b.id, &[7; 32], at(now), consume)
                    .err(),
                Some(StoreError::Unavailable)
            );
        }
        assert_eq!(store.entries.lock().unwrap().len(), 2);
        assert!(
            store
                .authenticated_at(&a.id, &[7; 32], at(now), true)
                .is_ok()
        );
    }
    #[tokio::test]
    async fn unbound_policy_context_cannot_be_promoted_even_when_all_facts_match() {
        let (config, transaction, identity) = super::super::context::tests::fixture().await;
        let now = identity.verified_at_ms();
        let store = MemoryTransactionStore::new(Arc::new(config)).unwrap();
        let created = store
            .create_at(request(&store.config), [7; 32], at(now))
            .unwrap();
        let context =
            AuthenticatedAuthorization::new(transaction, identity, &[7; 32], &store.config, now)
                .unwrap();
        assert!(
            context.transaction().encode().unwrap()
                == store.entries.lock().unwrap()[&created.id.hash()].bytes
        );
        assert_eq!(
            store
                .promote_at(&created.id, &[7; 32], context, at(now))
                .err(),
            Some(StoreError::Unavailable)
        );
        assert!(store.lookup_bound(&created.id, &[7; 32]).await.is_ok());
        let absent = TransactionId::parse(&URL_SAFE_NO_PAD.encode([0; 32])).unwrap();
        assert_eq!(
            store.lookup_bound(&absent, &[7; 32]).await.err(),
            Some(StoreError::Missing)
        );
    }
    #[tokio::test]
    async fn public_promotion_keeps_one_capacity_slot_and_typed_access() {
        let (store, created, context, now) = authenticated_fixture().await;
        assert_eq!(
            store
                .lookup_authenticated(&created.id, &[7; 32])
                .await
                .err(),
            Some(StoreError::Missing)
        );
        store
            .promote_authenticated(&created.id, &[7; 32], context)
            .await
            .unwrap();
        assert_eq!(
            store.lookup(&created.id, &[7; 32]).await.err(),
            Some(StoreError::Missing)
        );
        assert_eq!(
            store.consume(&created.id, &[7; 32]).await.err(),
            Some(StoreError::Missing)
        );
        let context = store
            .lookup_authenticated(&created.id, &[7; 32])
            .await
            .unwrap();
        assert_eq!(context.as_user().username, "alice");
        assert_eq!(context.authorized_scopes(), &["read"]);
        assert_eq!(context.expires_at_ms(), now + 1000);
        assert_eq!(store.entries.lock().unwrap().len(), 1);
        assert_eq!(
            store.create(request(&store.config), [7; 32]).await.err(),
            Some(StoreError::Limited)
        );
        assert_eq!(
            store
                .consume_authenticated(&created.id, &[8; 32])
                .await
                .err(),
            Some(StoreError::Missing)
        );
        assert!(
            store
                .consume_authenticated(&created.id, &[7; 32])
                .await
                .is_ok()
        );
        assert_eq!(
            store
                .consume_authenticated(&created.id, &[7; 32])
                .await
                .err(),
            Some(StoreError::Missing)
        );
        assert!(store.create(request(&store.config), [7; 32]).await.is_ok());
    }
    #[tokio::test]
    async fn promotion_failures_preserve_pending_and_expiry_shrink_reclaims_capacity() {
        let (store, created, context, now) = authenticated_fixture().await;
        let pending = store.entries.lock().unwrap()[&created.id.hash()]
            .bytes
            .clone();
        assert_eq!(
            store
                .promote_at(&created.id, &[8; 32], context, at(now))
                .err(),
            Some(StoreError::Missing)
        );
        assert!(
            store
                .access_at(&created.id, &[7; 32], at(now), false)
                .is_ok()
        );
        assert!(store.entries.lock().unwrap()[&created.id.hash()].bytes == pending);
        let (store, created, context, now) = authenticated_fixture().await;
        let changed = {
            let mut entries = store.entries.lock().unwrap();
            let entry = entries.get_mut(&created.id.hash()).unwrap();
            let mut value: serde_json::Value = serde_json::from_slice(&entry.bytes).unwrap();
            value["state"] = json!("different-canonical-request");
            entry.bytes = serde_json::to_vec(&value).unwrap();
            entry.bytes.clone()
        };
        assert_eq!(
            store
                .access_at(&created.id, &[7; 32], at(now), false)
                .unwrap()
                .request()
                .state(),
            Some("different-canonical-request")
        );
        assert_eq!(
            store
                .promote_at(&created.id, &[7; 32], context, at(now))
                .err(),
            Some(StoreError::Unavailable)
        );
        {
            let entries = store.entries.lock().unwrap();
            let entry = entries.get(&created.id.hash()).unwrap();
            assert!(matches!(entry.kind, StoredKind::Pending));
            assert!(entry.bytes == changed);
        }
        for corrupt in ["payload", "expiry"] {
            let (store, created, context, now) = authenticated_fixture().await;
            {
                let mut entries = store.entries.lock().unwrap();
                let entry = entries.get_mut(&created.id.hash()).unwrap();
                if corrupt == "payload" {
                    entry.bytes = b"invalid pending".to_vec();
                } else {
                    entry.expires_at_ms += 1;
                }
            }
            assert_eq!(
                store
                    .promote_at(&created.id, &[7; 32], context, at(now))
                    .err(),
                Some(StoreError::Unavailable)
            );
            assert!(matches!(
                store.entries.lock().unwrap()[&created.id.hash()].kind,
                StoredKind::Pending
            ));
        }
        let (mut config, transaction, identity) = super::super::context::tests::fixture().await;
        config.max_authentication_age_seconds = 1;
        let now = identity.verified_at_ms();
        let store = MemoryTransactionStore::new(Arc::new(config.clone())).unwrap();
        let created = store
            .create_at(request(&config), [7; 32], at(now + 1))
            .unwrap();
        let mismatch =
            AuthenticatedAuthorization::new(transaction, identity, &[7; 32], &config, now).unwrap();
        assert_eq!(
            store
                .promote_at(&created.id, &[7; 32], mismatch, at(now + 1))
                .err(),
            Some(StoreError::Unavailable)
        );
        assert!(
            store
                .access_at(&created.id, &[7; 32], at(now + 1), false)
                .is_ok()
        );
        let (store, created, context, now) = authenticated_fixture().await;
        assert_eq!(
            store
                .promote_at(&created.id, &[7; 32], context, at(now + 1000))
                .err(),
            Some(StoreError::Unavailable)
        );
        assert!(
            store
                .access_at(&created.id, &[7; 32], at(now + 1000), false)
                .is_ok()
        );
        let (original, _, _, now) = authenticated_fixture().await;
        let mut denied = (*original.config).clone();
        denied.resources[0].scopes[0]
            .required_roles
            .push("absent".into());
        let denied = MemoryTransactionStore::new(Arc::new(denied)).unwrap();
        let created = denied
            .create_at(request(&denied.config), [7; 32], at(now))
            .unwrap();
        let source = denied.lookup_bound(&created.id, &[7; 32]).await.unwrap();
        let (_, _, identity) = super::super::context::tests::fixture().await;
        let context = AuthenticatedAuthorization::new_bound(
            source,
            identity,
            &[7; 32],
            &original.config,
            now,
        )
        .unwrap();
        assert_eq!(
            denied
                .promote_at(&created.id, &[7; 32], context, at(now))
                .err(),
            Some(StoreError::Unavailable)
        );
        assert!(
            denied
                .access_at(&created.id, &[7; 32], at(now), false)
                .is_ok()
        );
        let (store, created, context, now) = authenticated_fixture().await;
        store
            .promote_at(&created.id, &[7; 32], context, at(now))
            .unwrap();
        assert_eq!(
            store
                .authenticated_at(&created.id, &[7; 32], at(now + 999), false)
                .unwrap()
                .expires_at_ms(),
            now + 1000
        );
        assert_eq!(
            store
                .authenticated_at(&created.id, &[7; 32], at(now + 1000), true)
                .err(),
            Some(StoreError::Missing)
        );
        assert!(
            store
                .create_at(request(&store.config), [7; 32], at(now + 1000))
                .is_ok()
        );
    }
    #[tokio::test]
    async fn concurrent_promotion_has_one_winner_and_bad_authenticated_data_is_not_consumed() {
        let (store, created, first, now) = authenticated_fixture().await;
        let (_, _, identity) = super::super::context::tests::fixture().await;
        let source = store.lookup_bound(&created.id, &[7; 32]).await.unwrap();
        let second =
            AuthenticatedAuthorization::new_bound(source, identity, &[7; 32], &store.config, now)
                .unwrap();
        let store = Arc::new(store);
        let id = Arc::new(created.id);
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let workers = [first, second]
            .into_iter()
            .map(|context| {
                let (store, id, barrier) = (store.clone(), id.clone(), barrier.clone());
                std::thread::spawn(move || {
                    barrier.wait();
                    store.promote_at(&id, &[7; 32], context, at(now))
                })
            })
            .collect::<Vec<_>>();
        let outcomes = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            outcomes
                .iter()
                .filter(|result| **result == Err(StoreError::Missing))
                .count(),
            1
        );
        store
            .entries
            .lock()
            .unwrap()
            .get_mut(&id.hash())
            .unwrap()
            .bytes = b"invalid context".to_vec();
        assert_eq!(
            store.authenticated_at(&id, &[7; 32], at(now), true).err(),
            Some(StoreError::Unavailable)
        );
        assert_eq!(store.entries.lock().unwrap().len(), 1);
    }
    #[tokio::test]
    async fn explicit_public_api_uses_server_clock_and_one_use_ids() {
        let config = config();
        let store = MemoryTransactionStore::new(config.clone()).unwrap();
        let before = now_ms().unwrap();
        let created = store.create(request(&config), [7; 32]).await.unwrap();
        assert!(created.expires_at_ms >= before + 30000);
        assert!(created.expires_at_ms <= now_ms().unwrap() + 30000);
        let parsed = TransactionId::parse(created.id.as_secret_str()).unwrap();
        assert!(store.lookup(&parsed, &[7; 32]).await.is_ok());
        assert!(store.consume(&parsed, &[7; 32]).await.is_ok());
        assert_eq!(
            store.consume(&parsed, &[7; 32]).await.err(),
            Some(StoreError::Missing)
        );
    }
    #[test]
    fn capacity_expiry_binding_and_hashed_keys_do_not_slide_or_burn() {
        let config = config();
        let store = MemoryTransactionStore::new(config.clone()).unwrap();
        let created = store
            .create_at(request(&config), [7; 32], || {
                assert!(store.entries.try_lock().is_err());
                Ok(1000)
            })
            .unwrap();
        assert_eq!(created.expires_at_ms, 31000);
        assert!(
            store
                .entries
                .lock()
                .unwrap()
                .contains_key(&created.id.hash())
        );
        let raw = URL_SAFE_NO_PAD.decode(created.id.as_secret_str()).unwrap();
        assert!(created.id.hash().as_slice() != raw.as_slice());
        assert_eq!(
            store.create_at(request(&config), [7; 32], at(1001)).err(),
            Some(StoreError::Limited)
        );
        assert_eq!(
            store.access_at(&created.id, &[8; 32], at(1001), true).err(),
            Some(StoreError::Missing)
        );
        let record = store
            .access_at(&created.id, &[7; 32], at(30999), false)
            .unwrap();
        assert_eq!(record.expires_at_ms(), 31000);
        assert_eq!(
            store
                .access_at(&created.id, &[7; 32], at(31000), true)
                .err(),
            Some(StoreError::Missing)
        );
        assert!(
            store
                .create_at(request(&config), [7; 32], at(31000))
                .is_ok()
        );
        assert!(TransactionId::parse("not-an-id").is_err());
        assert_eq!(
            store
                .create_at(request(&config), [7; 32], at(u64::MAX))
                .err(),
            Some(StoreError::Unavailable)
        );
        assert_eq!(
            store
                .create_at(request(&config), [7; 32], at(253402300799999))
                .err(),
            Some(StoreError::Unavailable)
        );
    }
    #[test]
    fn concurrent_consumers_have_exactly_one_winner() {
        let config = config();
        let store = Arc::new(MemoryTransactionStore::new(config.clone()).unwrap());
        let created = store
            .create_at(request(&config), [7; 32], at(1000))
            .unwrap();
        let id = Arc::new(created.id);
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let workers = (0..2)
            .map(|_| {
                let (store, id, barrier) = (store.clone(), id.clone(), barrier.clone());
                std::thread::spawn(move || {
                    barrier.wait();
                    store.access_at(&id, &[7; 32], at(1001), true).is_ok()
                })
            })
            .collect::<Vec<_>>();
        assert_eq!(
            workers
                .into_iter()
                .map(|worker| worker.join().unwrap())
                .filter(|won| *won)
                .count(),
            1
        );
    }
    #[test]
    fn invalid_records_and_cross_config_requests_never_become_consumed_proofs() {
        let config = config();
        let store = MemoryTransactionStore::new(config.clone()).unwrap();
        let created = store
            .create_at(request(&config), [7; 32], at(1000))
            .unwrap();
        store
            .entries
            .lock()
            .unwrap()
            .get_mut(&created.id.hash())
            .unwrap()
            .bytes = b"invalid record".to_vec();
        assert_eq!(
            store.access_at(&created.id, &[7; 32], at(1001), true).err(),
            Some(StoreError::Unavailable)
        );
        assert_eq!(store.entries.lock().unwrap().len(), 1);
        let mut changed = (*config).clone();
        changed.clients[0].resources.clear();
        let other = MemoryTransactionStore::new(Arc::new(changed)).unwrap();
        assert_eq!(
            other.create_at(request(&config), [7; 32], at(1000)).err(),
            Some(StoreError::Unavailable)
        );
        assert!(MemoryTransactionStore::new(Arc::new(OAuthConfig::default())).is_err());
    }

    #[test]
    fn malformed_ids_and_poisoned_lock_fail_closed() {
        assert!(TransactionId::parse(&URL_SAFE_NO_PAD.encode([0; 32])).is_ok());
        for value in [
            format!("{}!", "A".repeat(42)),
            format!("{}B", "A".repeat(42)),
            format!("{}=", "A".repeat(42)),
        ] {
            assert_eq!(
                TransactionId::parse(&value).err(),
                Some(StoreError::Missing)
            );
        }
        let config = config();
        let store = Arc::new(MemoryTransactionStore::new(config.clone()).unwrap());
        let created = store
            .create_at(request(&config), [7; 32], at(1000))
            .unwrap();
        let worker = store.clone();
        assert!(
            std::thread::spawn(move || {
                let _guard = worker.entries.lock().unwrap();
                panic!("synthetic lock poisoning");
            })
            .join()
            .is_err()
        );
        assert_eq!(
            store.create_at(request(&config), [7; 32], at(1001)).err(),
            Some(StoreError::Unavailable)
        );
        for consume in [false, true] {
            assert_eq!(
                store
                    .access_at(&created.id, &[7; 32], at(1001), consume)
                    .err(),
                Some(StoreError::Unavailable)
            );
        }
        assert_eq!(store.entries.lock().err().unwrap().into_inner().len(), 1);
    }
}

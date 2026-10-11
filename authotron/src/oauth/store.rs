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
    records::{AuthorizationTransaction, valid_time},
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

/// Bearer-like identifier, deliberately not Debug/Serialize. Browser binding is also required.
pub struct TransactionId(String);
impl TransactionId {
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
    fn hash(&self) -> [u8; 32] {
        Sha256::digest(self.0.as_bytes()).into()
    }
}

pub struct CreatedTransaction {
    pub id: TransactionId,
    pub expires_at_ms: u64,
}
struct Stored {
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
    pub async fn consume(
        &self,
        id: &TransactionId,
        browser_hash: &[u8; 32],
    ) -> Result<AuthorizationTransaction, StoreError> {
        self.access_at(id, browser_hash, now_ms, true)
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
            let mut random = [0; 32];
            OsRng
                .try_fill_bytes(&mut random)
                .map_err(|_| StoreError::Unavailable)?;
            let id = TransactionId(URL_SAFE_NO_PAD.encode(random));
            if let Entry::Vacant(slot) = entries.entry(id.hash()) {
                slot.insert(Stored {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::authorization::validate_authorization_request;
    use serde_json::json;

    fn config() -> Arc<OAuthConfig> {
        Arc::new(serde_json::from_value(json!({"issuer": "https://login.example.org", "authorization_transaction_ttl_seconds": 30, "max_authorization_transactions": 1,
            "clients": [{"client_id": "desktop", "display_name": "Desktop", "redirect_uris": ["https://app.example.org/cb"], "resources": [{"resource": "https://mcp.example.org/mcp", "scopes": ["read"]}]}],
            "resources": [{"resource": "https://mcp.example.org/mcp", "allowed_realms": ["local"], "scopes": [{"name": "read", "required_roles": ["reader"]}]}]})).unwrap())
    }
    fn request(config: &OAuthConfig) -> ValidatedAuthorizationRequest {
        validate_authorization_request(config, b"client_id=desktop&redirect_uri=https://app.example.org/cb&response_type=code&resource=https://mcp.example.org/mcp&scope=read&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256").unwrap()
    }
    fn at(now: u64) -> impl FnOnce() -> Result<u64, StoreError> {
        move || Ok(now)
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

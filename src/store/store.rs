use std::sync::Arc;

use async_trait::async_trait;
use tracing::{debug, error, info};

use super::{mongodb_store::MongoDBStore, no_store::NoStore};
use crate::auth::Provider;
use crate::config::{StoreBackend, StoreConfig};
use crate::models::{Token, User};

/// The Store trait abstracts token storage (add, retrieve, delete).
#[async_trait]
pub trait Store: Send + Sync {
    async fn add_token(&self, token: &Token, user: &User, expiry: i64) -> Result<(), String>;
    async fn get_tokens(&self, user: &User) -> Result<Vec<Token>, String>;
    async fn get_user(&self, token: &str) -> Result<Option<User>, String>;
    async fn delete_token(&self, token: &str) -> Result<(), String>;
}

/// Creates a concrete store implementation based on the StoreConfig.
/// If `store.enabled = false`, returns NoStore. Otherwise, picks the specified backend.
pub async fn create_store(config: &StoreConfig) -> Arc<dyn Store> {
    if !config.enabled {
        info!("Token store is disabled. Using NoStore.");
        return Arc::new(NoStore::new());
    }

    match &config.backend {
        Some(StoreBackend::MongoDB(mongo_config)) => match MongoDBStore::new(mongo_config).await {
            Ok(store) => {
                info!("Successfully created MongoDB store.");
                Arc::new(store)
            }
            Err(e) => {
                error!("Failed to create MongoDB store: {}", e);
                std::process::exit(1);
            }
        },
        None => {
            error!("Store is enabled, but no backend config is provided!");
            std::process::exit(1);
        }
    }
}

/// We also implement the auth::Provider trait for Arc<dyn Store>, so token-based auth is possible.
/// That way, the store can be one of your Auth providers.
#[async_trait]
impl Provider for Arc<dyn Store> {
    async fn authenticate(&self, token: &str) -> Result<User, String> {
        debug!("Authenticating using token-store with token='{}'", token);
        match self.get_user(token).await {
            Ok(Some(user)) => {
                debug!("Token found, returning user.");
                Ok(user)
            }
            Ok(None) => {
                debug!("Token not found in store.");
                Err("Token not found".to_string())
            }
            Err(e) => {
                error!("Error while looking up user by token: {}", e);
                Err(e)
            }
        }
    }

    fn get_name(&self) -> &str {
        "token-store"
    }

    fn get_type(&self) -> &str {
        "Bearer"
    }
}

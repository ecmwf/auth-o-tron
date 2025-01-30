use std::sync::Arc;

use async_trait::async_trait;
use tracing::{debug, error, info};

use crate::auth::Provider;
use crate::config::{StoreBackend, StoreConfig};
use crate::models::{Token, User};
use crate::store::mongodb_store::MongoDBStore;
use crate::store::no_store::NoStore;

/// The `Store` trait abstracts our token storage.
/// Different implementations (e.g., MongoDB) can fulfill this.
#[async_trait]
pub trait Store: Send + Sync {
    /// Adds a token for a given user, with a specified TTL (expiry).
    async fn add_token(&self, token: &Token, user: &User, expiry: i64) -> Result<(), String>;

    /// Retrieves all tokens associated with a user.
    async fn get_tokens(&self, user: &User) -> Result<Vec<Token>, String>;

    /// Looks up a user by token string.
    async fn get_user(&self, token: &str) -> Result<Option<User>, String>;

    /// Deletes a token from the store.
    async fn delete_token(&self, token: &str) -> Result<(), String>;
}

/// Creates a store implementation based on the `StoreConfig`.
/// - If `enabled = false`, returns a `NoStore`.
/// - If `enabled = true`, we use the specified backend (e.g., MongoDB).
pub async fn create_store(config: &StoreConfig) -> Arc<dyn Store> {
    if !config.enabled {
        // Return a disabled store
        info!("Token store is disabled. Using NoStore.");
        return Arc::new(NoStore::new());
    }

    // If enabled, we must have a backend
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

/// We also implement `Provider` for any `Arc<dyn Store>`.
/// This means the `Store` can be used as an Auth Provider (by token).
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
                error!("Error while getting user by token: {}", e);
                Err(e)
            }
        }
    }

    fn get_name(&self) -> &str {
        "token-store"
    }

    /// The store acts as a "Bearer" provider
    fn get_type(&self) -> &str {
        "Bearer"
    }
}

pub mod mongodb_store;
pub mod no_store;

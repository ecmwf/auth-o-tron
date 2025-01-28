use std::sync::Arc;

use async_trait::async_trait;
use tracing::{debug, error, info, warn};

use crate::auth::Provider;
use crate::config::TokenStoreConfig;
use crate::models::{Token, User};

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

/// Creates a store implementation based on the `TokenStoreConfig`.
/// If creation fails, we log an error and exit.
pub async fn create_store(config: &TokenStoreConfig) -> Arc<dyn Store> {
    match config {
        TokenStoreConfig::MongoDB(mongo_config) => {
            // Attempt to create a MongoDB-backed store.
            match crate::store::mongodb_store::MongoDBStore::new(mongo_config).await {
                Ok(store) => {
                    info!("Successfully created MongoDB store.");
                    Arc::new(store)
                }
                Err(e) => {
                    error!("Failed to create MongoDB store: {}", e);
                    std::process::exit(1);
                }
            }
        } // If we add more store types in the future, we can handle them here.
    }
}

/// We also implement `Provider` for any `Arc<dyn Store>`.
/// This means the `Store` can be used as an Auth Provider (by token).
#[async_trait]
impl Provider for Arc<dyn Store> {
    /// If we have a token, we try to retrieve the associated `User`.
    /// If `None` is returned, we treat it as "token not found".
    async fn authenticate(&self, token: &str) -> Result<User, String> {
        debug!("Authenticating using token-store with token='{}'", token);
        match self.get_user(token).await {
            Ok(Some(user)) => {
                debug!("Token found, returning user.");
                Ok(user)
            }
            Ok(None) => {
                warn!("Token not found in store.");
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

    /// The store acts as a "Bearer" provider,
    /// so we match the "Bearer" type in `Auth::authenticate`.
    fn get_type(&self) -> &str {
        "Bearer"
    }
}

pub mod mongodb_store;

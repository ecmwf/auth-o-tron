use std::sync::Arc;

use crate::auth::Provider;
use crate::config::TokenStoreConfig;
use crate::models::{Token, User};
use async_trait::async_trait;

//The Store trait itself
#[async_trait]
pub trait Store: Send + Sync {
    async fn add_token(&self, token: &Token, user: &User, expiry: i64) -> Result<(), String>;
    async fn get_tokens(&self, user: &User) -> Result<Vec<Token>, String>;
    async fn get_user(&self, token: &str) -> Result<Option<User>, String>;
    async fn delete_token(&self, token: &str) -> Result<(), String>;
}

pub async fn create_store(config: &TokenStoreConfig) -> Arc<dyn Store> {
    match config {
        TokenStoreConfig::MongoDB(mongo_config) => {
            // Call into the MongoDBStore
            match crate::store::mongodb_store::MongoDBStore::new(mongo_config).await {
                Ok(store) => Arc::new(store),
                Err(e) => {
                    eprintln!("💥 Failed to create store: {}", e);
                    std::process::exit(1);
                }
            }
        } // More store types can be added here
    }
}

#[async_trait]
impl Provider for Arc<dyn Store> {
    async fn authenticate(&self, token: &str) -> Result<User, String> {
        match self.get_user(token).await {
            Ok(Some(user)) => Ok(user),
            Ok(None) => Err("Token not found".to_string()),
            Err(e) => Err(e),
        }
    }

    fn get_name(&self) -> &str {
        "token-store"
    }

    fn get_type(&self) -> &str {
        "Bearer"
    }
}

pub mod mongodb_store;

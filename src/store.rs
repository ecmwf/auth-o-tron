use std::sync::Arc;

use crate::config::TokenStoreConfig;
use crate::models::Token;
use crate::models::User;
use async_trait::async_trait;

#[async_trait]
pub trait Store: Send + Sync {
    async fn add_token(&self, token: &str, user: &User, expiry: i64) -> Result<(), String>;
    async fn get_tokens(&self, user: &User) -> Result<Vec<Token>, String>;
    async fn get_user(&self, token: &str) -> Result<Option<User>, String>;
    async fn delete_token(&self, token: &str) -> Result<(), String>;
}

pub fn create_store(config: &TokenStoreConfig) -> Arc<dyn Store> {
    match config {
        TokenStoreConfig::MongoDB(mongo_config) => Arc::new(MongoDBStore::new(mongo_config)),
    }
}

#[derive(serde::Deserialize, serde::Serialize, Debug)]
pub struct MongoDBConfig {
    pub uri: String,
}

pub struct MongoDBStore {}

impl MongoDBStore {
    pub fn new(_config: &MongoDBConfig) -> Self {
        Self {}
    }
}

#[async_trait]
impl Store for MongoDBStore {
    async fn add_token(&self, _token: &str, _user: &User, _expiry: i64) -> Result<(), String> {
        todo!()
    }

    async fn get_tokens(&self, _user: &User) -> Result<Vec<Token>, String> {
        todo!()
    }

    async fn get_user(&self, _token: &str) -> Result<Option<User>, String> {
        todo!()
    }

    async fn delete_token(&self, _token: &str) -> Result<(), String> {
        todo!()
    }
}

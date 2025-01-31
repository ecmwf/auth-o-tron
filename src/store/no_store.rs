use super::Store;
use crate::models::{Token, User};
use async_trait::async_trait;

/// A no-op store that always returns an error if called,
/// indicating the store is disabled.
pub struct NoStore;

impl NoStore {
    pub fn new() -> Self {
        NoStore
    }
}

#[async_trait]
impl Store for NoStore {
    async fn add_token(&self, _token: &Token, _user: &User, _expiry: i64) -> Result<(), String> {
        Err("Token store is disabled".into())
    }

    async fn get_tokens(&self, _user: &User) -> Result<Vec<Token>, String> {
        Err("Token store is disabled".into())
    }

    async fn get_user(&self, _token: &str) -> Result<Option<User>, String> {
        Err("Token store is disabled".into())
    }

    async fn delete_token(&self, _token: &str) -> Result<(), String> {
        Err("Token store is disabled".into())
    }
}

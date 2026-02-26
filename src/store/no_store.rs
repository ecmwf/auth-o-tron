use super::Store;
use crate::models::{token::Token, user::User};
use async_trait::async_trait;

/// A no-op store that always returns an error if called,
/// indicating the store is disabled.
pub struct NoStore;

impl NoStore {
    pub fn new() -> Self {
        NoStore
    }
}

impl Default for NoStore {
    fn default() -> Self {
        Self::new()
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

    fn is_enabled(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{token::Token, user::User};

    /// Test that adding a token with NoStore returns an error.
    #[tokio::test]
    async fn test_no_store_add_token() {
        let no_store = NoStore::new();
        let token = Token::new("dummy".to_string(), Default::default(), None);
        let user = User::new(
            "test".to_string(),
            "user".to_string(),
            None,
            None,
            None,
            Some(1),
        );
        let res = no_store.add_token(&token, &user, 3600).await;
        assert!(res.is_err(), "Expected add_token to return an error");
    }

    /// Test that retrieving tokens with NoStore returns an error.
    #[tokio::test]
    async fn test_no_store_get_tokens() {
        let no_store = NoStore::new();
        let user = User::new(
            "test".to_string(),
            "user".to_string(),
            None,
            None,
            None,
            Some(1),
        );
        let res = no_store.get_tokens(&user).await;
        assert!(res.is_err(), "Expected get_tokens to return an error");
    }

    /// Test that retrieving a user with NoStore returns an error.
    #[tokio::test]
    async fn test_no_store_get_user() {
        let no_store = NoStore::new();
        // Attempt to retrieve a user using any token string.
        let res = no_store.get_user("dummy_token").await;
        assert!(res.is_err(), "Expected get_user to return an error");
    }

    /// Test that deleting a token with NoStore returns an error.
    #[tokio::test]
    async fn test_no_store_delete_token() {
        let no_store = NoStore::new();
        let res = no_store.delete_token("dummy_token").await;
        assert!(res.is_err(), "Expected delete_token to return an error");
    }
}

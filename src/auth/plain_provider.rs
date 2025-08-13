use async_trait::async_trait;
use base64::{engine::general_purpose, Engine as _};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::models::User;
use crate::providers::Provider;

/// PlainAuthConfig defines the data for Basic authentication.
#[derive(Deserialize, Serialize, Debug, JsonSchema, Clone)]
pub struct PlainAuthConfig {
    /// A friendly name for logs.
    pub name: String,
    /// The realm associated with this provider.
    pub realm: String,
    /// A list of username/password pairs.
    pub users: Vec<PlainUserEntry>,
}

/// Represents a single user entry (username + password).
#[derive(Deserialize, Serialize, Debug, JsonSchema, Clone)]
pub struct PlainUserEntry {
    pub username: String,
    pub password: String,
    pub roles: Option<Vec<String>>,
}

/// A `PlainAuthProvider` that implements Basic authentication by
/// comparing credentials to the user list in `PlainAuthConfig`.
pub struct PlainAuthProvider {
    pub config: PlainAuthConfig,
}

impl PlainAuthProvider {
    /// Create a new `PlainAuthProvider` from the config struct.
    pub fn new(config: &PlainAuthConfig) -> Self {
        Self {
            config: config.clone(),
        }
    }
}

#[async_trait]
impl Provider for PlainAuthProvider {
    /// The display name for logs/debug.  
    fn get_name(&self) -> &str {
        &self.config.name
    }

    /// Return "Basic" so that `Auth::authenticate` will match
    /// `auth_type == "Basic"` to this provider.
    fn get_type(&self) -> &str {
        "Basic"
    }

    /// Return the realm associated with this provider.
    fn get_realm(&self) -> Option<&str> {
        Some(&self.config.realm)
    }

    /// Decode the credentials (base64-encoded "username:password") and check
    /// against the config’s user list. Return a `User` on success.
    async fn authenticate(&self, credentials: &str) -> Result<User, String> {
        // 1) Decode base64 -> bytes
        let decoded_bytes = match general_purpose::STANDARD.decode(credentials) {
            Ok(b) => b,
            Err(e) => {
                warn!("Base64 decode error: {}", e);
                return Err("Invalid base64 in Basic auth".to_string());
            }
        };

        // 2) Convert bytes -> UTF-8 string
        let decoded_str = match String::from_utf8(decoded_bytes) {
            Ok(s) => s,
            Err(e) => {
                warn!("Invalid UTF-8 in Basic auth: {}", e);
                return Err("Invalid UTF-8 in Basic auth".to_string());
            }
        };

        // 3) Split into "username:password"
        let mut parts = decoded_str.splitn(2, ':');
        let user_part = parts.next().unwrap_or("");
        let pass_part = parts.next().unwrap_or("");

        if user_part.is_empty() {
            return Err("No username in Basic credentials".to_string());
        }

        // 4) Compare with the user list in config
        debug!("Basic auth attempt for user '{}'", user_part);
        for entry in &self.config.users {
            if entry.username == user_part && entry.password == pass_part {
                // Found a match! Return a new user object.
                return Ok(User::new(
                    self.config.realm.clone(),
                    user_part.to_string(),
                    entry.roles.clone(), // roles
                    None,                // attributes
                    None,                // scopes
                    Some(1),
                ));
            }
        }

        Err("Wrong username or password".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose;

    fn create_test_config() -> PlainAuthConfig {
        PlainAuthConfig {
            name: "TestPlain".to_string(),
            realm: "test".to_string(),
            users: vec![
                PlainUserEntry {
                    username: "admin".to_string(),
                    password: "admin123".to_string(),
                    roles: Some(vec!["admin".to_string(), "user".to_string()]),
                },
                PlainUserEntry {
                    username: "user1".to_string(),
                    password: "password1".to_string(),
                    roles: Some(vec!["user".to_string()]),
                },
                PlainUserEntry {
                    username: "guest".to_string(),
                    password: "guest123".to_string(),
                    roles: None, // No roles
                },
                PlainUserEntry {
                    username: "empty_roles".to_string(),
                    password: "password".to_string(),
                    roles: Some(vec![]), // Empty roles vector
                },
            ],
        }
    }

    fn create_special_chars_config() -> PlainAuthConfig {
        PlainAuthConfig {
            name: "TestPlain".to_string(),
            realm: "test".to_string(),
            users: vec![PlainUserEntry {
                username: "user@domain.com".to_string(),
                password: "p@ssw0rd!#$".to_string(),
                roles: Some(vec!["special".to_string()]),
            }],
        }
    }

    fn create_unicode_config() -> PlainAuthConfig {
        PlainAuthConfig {
            name: "TestPlain".to_string(),
            realm: "test".to_string(),
            users: vec![PlainUserEntry {
                username: "用户".to_string(),
                password: "密码".to_string(),
                roles: Some(vec!["unicode".to_string()]),
            }],
        }
    }

    fn create_empty_users_config() -> PlainAuthConfig {
        PlainAuthConfig {
            name: "TestPlain".to_string(),
            realm: "test".to_string(),
            users: vec![],
        }
    }

    /// Test that valid credentials (username:password) are correctly authenticated.
    #[tokio::test]
    async fn test_authenticate_valid_credentials() {
        let provider = PlainAuthProvider::new(&create_test_config());
        let credentials = general_purpose::STANDARD.encode("user1:password1");

        let result = provider.authenticate(&credentials).await;

        assert!(result.is_ok());
        let user = result.unwrap();
        assert_eq!(user.username, "user1");
        assert_eq!(user.realm, "test");
        assert_eq!(user.roles, vec!["user"]);
        assert_eq!(user.version, 1);
    }

    /// Test that an invalid password returns an error.
    #[tokio::test]
    async fn test_authenticate_invalid_credentials() {
        let provider = PlainAuthProvider::new(&create_test_config());
        let credentials = general_purpose::STANDARD.encode("user1:wrongpassword");

        let result = provider.authenticate(&credentials).await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Wrong username or password");
    }

    /// Test that credentials that are not valid base64 yield an error.
    #[tokio::test]
    async fn test_authenticate_invalid_base64() {
        let provider = PlainAuthProvider::new(&create_empty_users_config());
        let credentials = "not_base64";

        let result = provider.authenticate(credentials).await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Invalid base64 in Basic auth");
    }

    /// Test that valid credentials with multiple roles are correctly authenticated.
    #[tokio::test]
    async fn test_authenticate_valid_credentials_with_multiple_roles() {
        let provider = PlainAuthProvider::new(&create_test_config());
        let credentials = general_purpose::STANDARD.encode("admin:admin123");

        let result = provider.authenticate(&credentials).await;

        assert!(result.is_ok());
        let user = result.unwrap();
        assert_eq!(user.username, "admin");
        assert_eq!(user.realm, "test");
        assert_eq!(user.roles, vec!["admin", "user"]);
        assert_eq!(user.version, 1);
    }

    /// Test that valid credentials with no roles are correctly authenticated.
    #[tokio::test]
    async fn test_authenticate_valid_credentials_with_no_roles() {
        let provider = PlainAuthProvider::new(&create_test_config());
        let credentials = general_purpose::STANDARD.encode("guest:guest123");

        let result = provider.authenticate(&credentials).await;

        assert!(result.is_ok());
        let user = result.unwrap();
        assert_eq!(user.username, "guest");
        assert_eq!(user.realm, "test");
        assert!(user.roles.is_empty());
    }

    /// Test that valid credentials with empty roles vector are correctly authenticated.
    #[tokio::test]
    async fn test_authenticate_valid_credentials_with_empty_roles() {
        let provider = PlainAuthProvider::new(&create_test_config());
        let credentials = general_purpose::STANDARD.encode("empty_roles:password");

        let result = provider.authenticate(&credentials).await;

        assert!(result.is_ok());
        let user = result.unwrap();
        assert_eq!(user.username, "empty_roles");
        assert_eq!(user.realm, "test");
        assert!(user.roles.is_empty());
    }

    /// Test that an invalid username returns an error.
    #[tokio::test]
    async fn test_authenticate_invalid_username() {
        let provider = PlainAuthProvider::new(&create_test_config());
        let credentials = general_purpose::STANDARD.encode("nonexistent:password1");

        let result = provider.authenticate(&credentials).await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Wrong username or password");
    }

    /// Test that both invalid username and password return an error.
    #[tokio::test]
    async fn test_authenticate_both_invalid() {
        let provider = PlainAuthProvider::new(&create_test_config());
        let credentials = general_purpose::STANDARD.encode("nonexistent:wrongpassword");

        let result = provider.authenticate(&credentials).await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Wrong username or password");
    }

    /// Test that credentials without colon separator return an error.
    #[tokio::test]
    async fn test_authenticate_no_colon_separator() {
        let provider = PlainAuthProvider::new(&create_test_config());
        let credentials = general_purpose::STANDARD.encode("usernamepassword");

        let result = provider.authenticate(&credentials).await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Wrong username or password");
    }

    /// Test that credentials with empty username return an error.
    #[tokio::test]
    async fn test_authenticate_empty_username() {
        let provider = PlainAuthProvider::new(&create_test_config());
        let credentials = general_purpose::STANDARD.encode(":password");

        let result = provider.authenticate(&credentials).await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "No username in Basic credentials");
    }

    /// Test that credentials with empty password are handled correctly.
    #[tokio::test]
    async fn test_authenticate_empty_password() {
        let provider = PlainAuthProvider::new(&create_test_config());
        let credentials = general_purpose::STANDARD.encode("admin:");

        let result = provider.authenticate(&credentials).await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Wrong username or password");
    }

    /// Test that completely empty credentials return an error.
    #[tokio::test]
    async fn test_authenticate_empty_credentials() {
        let provider = PlainAuthProvider::new(&create_test_config());
        let credentials = general_purpose::STANDARD.encode(":");

        let result = provider.authenticate(&credentials).await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "No username in Basic credentials");
    }

    /// Test that credentials with multiple colons are handled correctly.
    #[tokio::test]
    async fn test_authenticate_multiple_colons() {
        let provider = PlainAuthProvider::new(&create_test_config());
        let credentials = general_purpose::STANDARD.encode("user:pass:word");

        let result = provider.authenticate(&credentials).await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Wrong username or password");
    }

    /// Test that invalid UTF-8 in credentials returns an error.
    #[tokio::test]
    async fn test_authenticate_invalid_utf8() {
        let provider = PlainAuthProvider::new(&create_test_config());
        // Create invalid UTF-8 bytes
        let invalid_utf8_bytes = vec![0xFF, 0xFE, 0xFD];
        let credentials = general_purpose::STANDARD.encode(&invalid_utf8_bytes);

        let result = provider.authenticate(&credentials).await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Invalid UTF-8 in Basic auth");
    }

    /// Test that provider metadata is correct.
    #[tokio::test]
    async fn test_provider_metadata() {
        let provider = PlainAuthProvider::new(&create_test_config());

        assert_eq!(provider.get_name(), "TestPlain");
        assert_eq!(provider.get_type(), "Basic");
        assert_eq!(provider.get_realm(), Some("test"));
    }

    /// Test authentication with special characters in username and password.
    #[tokio::test]
    async fn test_authenticate_special_characters() {
        let provider = PlainAuthProvider::new(&create_special_chars_config());
        let credentials = general_purpose::STANDARD.encode("user@domain.com:p@ssw0rd!#$");

        let result = provider.authenticate(&credentials).await;

        assert!(result.is_ok());
        let user = result.unwrap();
        assert_eq!(user.username, "user@domain.com");
        assert_eq!(user.roles, vec!["special"]);
    }

    /// Test authentication with unicode characters.
    #[tokio::test]
    async fn test_authenticate_unicode_characters() {
        let provider = PlainAuthProvider::new(&create_unicode_config());
        let credentials = general_purpose::STANDARD.encode("用户:密码");

        let result = provider.authenticate(&credentials).await;

        assert!(result.is_ok());
        let user = result.unwrap();
        assert_eq!(user.username, "用户");
        assert_eq!(user.roles, vec!["unicode"]);
    }

    /// Test with empty user list.
    #[tokio::test]
    async fn test_authenticate_empty_user_list() {
        let provider = PlainAuthProvider::new(&create_empty_users_config());
        let credentials = general_purpose::STANDARD.encode("anyuser:anypassword");

        let result = provider.authenticate(&credentials).await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Wrong username or password");
    }

    /// Test case sensitivity in username and password.
    #[tokio::test]
    async fn test_authenticate_case_sensitivity() {
        let provider = PlainAuthProvider::new(&create_test_config());

        // Test uppercase username
        let credentials = general_purpose::STANDARD.encode("ADMIN:admin123");
        let result = provider.authenticate(&credentials).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Wrong username or password");

        // Test uppercase password
        let credentials = general_purpose::STANDARD.encode("admin:ADMIN123");
        let result = provider.authenticate(&credentials).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Wrong username or password");
    }

    /// Test that user attributes are properly initialized.
    #[tokio::test]
    async fn test_user_attributes_initialization() {
        let provider = PlainAuthProvider::new(&create_test_config());
        let credentials = general_purpose::STANDARD.encode("admin:admin123");

        let result = provider.authenticate(&credentials).await;

        assert!(result.is_ok());
        let user = result.unwrap();
        assert!(user.attributes.is_empty());
        assert!(user.scopes.is_none());
        assert_eq!(user.version, 1);
    }

    /// Test authentication with whitespace in credentials.
    #[tokio::test]
    async fn test_authenticate_whitespace_handling() {
        let provider = PlainAuthProvider::new(&create_test_config());

        // Test username with spaces (should fail)
        let credentials = general_purpose::STANDARD.encode(" admin :admin123");
        let result = provider.authenticate(&credentials).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Wrong username or password");
    }

    /// Test that roles are properly cloned and not shared between users.
    #[tokio::test]
    async fn test_roles_independence() {
        let provider = PlainAuthProvider::new(&create_test_config());

        // Authenticate admin user
        let credentials1 = general_purpose::STANDARD.encode("admin:admin123");
        let result1 = provider.authenticate(&credentials1).await;
        assert!(result1.is_ok());
        let user1 = result1.unwrap();

        // Authenticate regular user
        let credentials2 = general_purpose::STANDARD.encode("user1:password1");
        let result2 = provider.authenticate(&credentials2).await;
        assert!(result2.is_ok());
        let user2 = result2.unwrap();

        // Verify roles are different and independent
        assert_eq!(user1.roles, vec!["admin", "user"]);
        assert_eq!(user2.roles, vec!["user"]);
        assert_ne!(user1.roles, user2.roles);
    }

    /// Test provider creation and configuration.
    #[tokio::test]
    async fn test_provider_creation() {
        let config = create_test_config();
        let provider = PlainAuthProvider::new(&config);

        // Verify provider was created with correct configuration
        assert_eq!(provider.config.name, "TestPlain");
        assert_eq!(provider.config.realm, "test");
        assert_eq!(provider.config.users.len(), 4);
    }
}

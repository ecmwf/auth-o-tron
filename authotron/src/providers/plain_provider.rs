// (C) Copyright 2025- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

use std::{borrow::Cow, fmt};

use argon2::{Argon2, PasswordHash, PasswordVerifier};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose};
use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tracing::{debug, warn};

use crate::models::user::User;
use crate::providers::Provider;

/// PlainAuthConfig defines the data for Basic authentication.
#[derive(Deserialize, Serialize, Debug, JsonSchema, Clone)]
pub struct PlainAuthConfig {
    /// A friendly name for logs.
    pub name: String,
    /// The realm associated with this provider.
    pub realm: String,
    /// A list of users and their password credentials.
    pub users: Vec<PlainUserEntry>,
}

/// Represents a single user entry and its password credential.
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct PlainUserEntry {
    pub username: String,
    /// Exactly one Argon2id hash or deprecated plaintext password.
    #[serde(flatten)]
    pub credential: PlainCredential,
    pub roles: Option<Vec<String>>,
}

impl JsonSchema for PlainUserEntry {
    fn schema_name() -> Cow<'static, str> {
        "PlainUserEntry".into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "description": "A plain-provider user with exactly one password credential.",
            "type": "object",
            "properties": {
                "username": { "type": "string" },
                "password_hash": {
                    "description": "An Argon2id hash in PHC string format (recommended).",
                    "type": "string"
                },
                "password": {
                    "description": "Deprecated plaintext password. Use password_hash instead.",
                    "type": "string",
                    "deprecated": true
                },
                "roles": {
                    "type": ["array", "null"],
                    "items": { "type": "string" }
                }
            },
            "required": ["username"],
            "oneOf": [
                { "required": ["password_hash"] },
                { "required": ["password"] }
            ],
            "additionalProperties": false
        })
    }
}

/// Password configuration for a plain-provider user.
#[derive(Deserialize, Serialize, JsonSchema, Clone)]
#[serde(untagged)]
pub enum PlainCredential {
    /// Preferred Argon2id PHC string.
    Argon2id(Argon2idCredential),
    /// Deprecated plaintext compatibility.
    Plaintext(PlaintextCredential),
}

#[derive(Deserialize, Serialize, JsonSchema, Clone)]
#[serde(deny_unknown_fields)]
pub struct Argon2idCredential {
    /// An Argon2id hash in PHC string format.
    pub password_hash: String,
}

#[derive(Deserialize, Serialize, JsonSchema, Clone)]
#[serde(deny_unknown_fields)]
pub struct PlaintextCredential {
    /// Deprecated: plaintext password. Use `password_hash` instead.
    pub password: String,
}

impl fmt::Debug for PlainCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PlainCredential([REDACTED])")
    }
}

impl PlainCredential {
    async fn verify(&self, candidate: &str) -> bool {
        match self {
            Self::Argon2id(credential) => {
                let password_hash = credential.password_hash.clone();
                let candidate = candidate.as_bytes().to_vec();
                tokio::task::spawn_blocking(move || verify_argon2id(&password_hash, &candidate))
                    .await
                    .unwrap_or(false)
            }
            Self::Plaintext(credential) => credential
                .password
                .as_bytes()
                .ct_eq(candidate.as_bytes())
                .into(),
        }
    }
}

fn verify_argon2id(password_hash: &str, candidate: &[u8]) -> bool {
    let Ok(parsed_hash) = PasswordHash::new(password_hash) else {
        return false;
    };

    if parsed_hash.algorithm.as_str() != "argon2id" {
        return false;
    }

    Argon2::default()
        .verify_password(candidate, &parsed_hash)
        .is_ok()
}

/// A `PlainAuthProvider` that implements Basic authentication by
/// comparing credentials to the user list in `PlainAuthConfig`.
pub struct PlainAuthProvider {
    pub config: PlainAuthConfig,
}

impl PlainAuthProvider {
    /// Create a new `PlainAuthProvider` from the config struct.
    pub fn new(config: &PlainAuthConfig) -> Self {
        if config
            .users
            .iter()
            .any(|entry| matches!(&entry.credential, PlainCredential::Plaintext(_)))
        {
            warn!(
                event_name = "providers.plain.plaintext_password.deprecated",
                event_domain = "providers",
                provider_name = config.name.as_str(),
                realm = config.realm.as_str(),
                "plain provider uses deprecated plaintext passwords; use Argon2id password_hash entries"
            );
        }

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
                debug!(
                    event_name = "providers.plain.decode.failed",
                    event_domain = "providers",
                    error = e.to_string(),
                    "basic auth base64 decode failed"
                );
                return Err("Invalid base64 in Basic auth".to_string());
            }
        };

        // 2) Convert bytes -> UTF-8 string
        let decoded_str = match String::from_utf8(decoded_bytes) {
            Ok(s) => s,
            Err(e) => {
                debug!(
                    event_name = "providers.plain.decode.failed",
                    event_domain = "providers",
                    error = e.to_string(),
                    "basic auth payload is not valid UTF-8"
                );
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
        debug!(
            event_name = "providers.plain.authenticate.started",
            event_domain = "providers",
            realm = self.config.realm.as_str(),
            username = user_part,
            "basic authentication attempt"
        );
        for entry in &self.config.users {
            if entry.username == user_part && entry.credential.verify(pass_part).await {
                return Ok(User::new(
                    self.config.realm.clone(),
                    user_part.to_string(),
                    entry.roles.clone(),
                    None,
                    None,
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
    use argon2::{Algorithm, Params, PasswordHasher, Version, password_hash::SaltString};
    use base64::engine::general_purpose;

    fn plaintext(password: &str) -> PlainCredential {
        PlainCredential::Plaintext(PlaintextCredential {
            password: password.to_string(),
        })
    }

    fn argon2id(password: &str) -> PlainCredential {
        let params = Params::new(1024, 1, 1, None).expect("valid test Argon2 parameters");
        let hasher = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let salt = SaltString::encode_b64(b"authotron-tests!").expect("valid test salt");
        let password_hash = hasher
            .hash_password(password.as_bytes(), &salt)
            .expect("test password should hash")
            .to_string();
        PlainCredential::Argon2id(Argon2idCredential { password_hash })
    }

    fn create_test_config() -> PlainAuthConfig {
        PlainAuthConfig {
            name: "TestPlain".to_string(),
            realm: "test".to_string(),
            users: vec![
                PlainUserEntry {
                    username: "admin".to_string(),
                    credential: plaintext("admin123"),
                    roles: Some(vec!["admin".to_string(), "user".to_string()]),
                },
                PlainUserEntry {
                    username: "user1".to_string(),
                    credential: plaintext("password1"),
                    roles: Some(vec!["user".to_string()]),
                },
                PlainUserEntry {
                    username: "guest".to_string(),
                    credential: plaintext("guest123"),
                    roles: None, // No roles
                },
                PlainUserEntry {
                    username: "empty_roles".to_string(),
                    credential: plaintext("password"),
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
                credential: plaintext("p@ssw0rd!#$"),
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
                credential: plaintext("密码"),
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
        assert!(user.scopes.is_empty());
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
    #[tokio::test]
    async fn test_authenticate_correct_argon2id_hash() {
        let provider = PlainAuthProvider::new(&PlainAuthConfig {
            name: "Hashed".to_string(),
            realm: "test".to_string(),
            users: vec![PlainUserEntry {
                username: "hashed-user".to_string(),
                credential: argon2id("correct horse battery staple"),
                roles: Some(vec!["user".to_string()]),
            }],
        });
        let credentials =
            general_purpose::STANDARD.encode("hashed-user:correct horse battery staple");

        let user = provider
            .authenticate(&credentials)
            .await
            .expect("correct password should authenticate");

        assert_eq!(user.username, "hashed-user");
        assert_eq!(user.roles, vec!["user"]);
    }

    #[tokio::test]
    async fn test_authenticate_incorrect_argon2id_password() {
        let provider = PlainAuthProvider::new(&PlainAuthConfig {
            name: "Hashed".to_string(),
            realm: "test".to_string(),
            users: vec![PlainUserEntry {
                username: "hashed-user".to_string(),
                credential: argon2id("right-password"),
                roles: None,
            }],
        });
        let credentials = general_purpose::STANDARD.encode("hashed-user:wrong-password");

        let result = provider.authenticate(&credentials).await;

        assert_eq!(result.unwrap_err(), "Wrong username or password");
    }

    #[tokio::test]
    async fn test_authenticate_malformed_argon2id_hash() {
        let provider = PlainAuthProvider::new(&PlainAuthConfig {
            name: "Hashed".to_string(),
            realm: "test".to_string(),
            users: vec![PlainUserEntry {
                username: "hashed-user".to_string(),
                credential: PlainCredential::Argon2id(Argon2idCredential {
                    password_hash: "$argon2id$malformed".to_string(),
                }),
                roles: None,
            }],
        });
        let credentials = general_purpose::STANDARD.encode("hashed-user:any-password");

        let result = provider.authenticate(&credentials).await;

        assert_eq!(result.unwrap_err(), "Wrong username or password");
    }

    #[tokio::test]
    async fn test_authenticate_unicode_argon2id_password() {
        let provider = PlainAuthProvider::new(&PlainAuthConfig {
            name: "Hashed".to_string(),
            realm: "test".to_string(),
            users: vec![PlainUserEntry {
                username: "unicode-user".to_string(),
                credential: argon2id("密码🔐"),
                roles: None,
            }],
        });
        let credentials = general_purpose::STANDARD.encode("unicode-user:密码🔐");

        let result = provider.authenticate(&credentials).await;

        assert!(result.is_ok());
    }

    #[test]
    fn test_plaintext_credential_deserializes_for_compatibility() {
        let entry: PlainUserEntry = serde_json::from_str(
            r#"{"username":"legacy","password":"still-supported","roles":[]}"#,
        )
        .expect("deprecated plaintext credential should remain supported");

        assert!(matches!(entry.credential, PlainCredential::Plaintext(_)));
    }

    #[test]
    fn test_credential_rejects_hash_and_plaintext() {
        let result = serde_json::from_str::<PlainUserEntry>(
            r#"{"username":"ambiguous","password_hash":"$argon2id$...","password":"secret"}"#,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_credential_rejects_missing_hash_and_plaintext() {
        let result = serde_json::from_str::<PlainUserEntry>(r#"{"username":"missing"}"#);

        assert!(result.is_err());
    }
}

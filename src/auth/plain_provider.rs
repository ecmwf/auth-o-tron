use async_trait::async_trait;
use base64::{engine::general_purpose, Engine as _};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use super::{Provider, User};

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
                    None, // roles
                    None, // attributes
                    None, // scopes
                    Some(1),
                ));
            }
        }

        Err("Wrong username or password".to_string())
    }
}
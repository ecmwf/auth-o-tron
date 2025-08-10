use async_trait::async_trait;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

use super::Augmenter;
use crate::models::User;

/// PlainAugConfig defines the data for additional r.
#[derive(Deserialize, Serialize, Debug, JsonSchema, Clone)]
pub struct PlainAugConfig {
    /// A friendly name for logs.
    pub name: String,
    /// The realm associated with this provider.
    pub realm: String,
    /// A list of roles and users.
    pub roles: Vec<PlainRole>,
}

#[derive(Deserialize, Serialize, Debug, JsonSchema, Clone)]
pub struct PlainRole {
    pub name: String,
    pub users: Vec<String>,
}

/// A `PlainAugProvider` that adds custom roles to specific users
pub struct PlainAugProvider {
    pub config: PlainAugConfig,
}

impl PlainAugProvider {
    /// Create a new `PlainAugProvider` from the config struct.
    pub fn new(config: &PlainAugConfig) -> Self {
        Self {
            config: config.clone(),
        }
    }
}
#[async_trait]
impl Augmenter for PlainAugProvider {
    /// Augment the user with additional roles based on the configuration.
    async fn augment(&self, user: &mut User) -> Result<(), String> {
        debug!("Augmenting user {} with roles", user.username);

        // Find roles for the user in the config
        for role in &self.config.roles {
            if role.users.contains(&user.username) {
                info!("Adding role {} to user {}", role.name, user.username);
                user.roles.push(role.name.clone());
            }
        }

        if user.roles.is_empty() {
            debug!("No additional roles found for user {}", user.username);
        }

        Ok(())
    }

    fn get_name(&self) -> &str {
        &self.config.name
    }

    fn get_type(&self) -> &str {
        "plain"
    }

    fn get_realm(&self) -> &str {
        &self.config.realm
    }
}

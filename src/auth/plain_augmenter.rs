use std::collections::HashMap;

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
    pub roles: HashMap<String, Vec<String>>,
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

        if user.realm != self.config.realm {
            debug!(
                "User {} is in realm {}, but this provider is for realm {}",
                user.username, user.realm, self.config.realm
            );
            return Ok(()); // No roles to add if realms don't match
        }

        // Find roles for the user in the config
        for (role_name, users) in &self.config.roles {
            if users.contains(&user.username) {
                info!("Adding role {} to user {}", role_name, user.username);
                user.roles.push(role_name.clone());
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

#[cfg(test)]
mod tests {
    use figment::{
        providers::{Format, Yaml},
        Figment,
    };

    use super::*;

    fn make_test_config() -> PlainAugConfig {
        let config_str = r#"
name: TestProvider
realm: test-realm
roles:
    admin:
        - alice
        - bob
    user:
        - bob
        - carol
"#;
        Figment::new()
            .merge(Yaml::string(config_str))
            .extract()
            .expect("Failed to parse test config")
    }

    #[tokio::test]
    async fn test_augment_adds_roles() {
        let config = make_test_config();
        let provider = PlainAugProvider::new(&config);

        let mut user = User {
            username: "bob".to_string(),
            roles: vec![],
            realm: "test-realm".to_string(),
            ..Default::default()
        };

        provider.augment(&mut user).await.unwrap();
        assert!(user.roles.contains(&"admin".to_string()));
        assert!(user.roles.contains(&"user".to_string()));
    }

    #[tokio::test]
    async fn test_augment_no_roles_for_diff_realm() {
        let config = make_test_config();
        let provider = PlainAugProvider::new(&config);

        let mut user = User {
            username: "bob".to_string(),
            roles: vec![],
            realm: "other-realm".to_string(),
            ..Default::default()
        };

        provider.augment(&mut user).await.unwrap();
        assert!(user.roles.is_empty());
    }

    #[tokio::test]
    async fn test_augment_user_gets_single_role() {
        let config = make_test_config();
        let provider = PlainAugProvider::new(&config);

        let mut user = User {
            username: "alice".to_string(),
            roles: vec![],
            realm: "test-realm".to_string(),
            ..Default::default()
        };

        provider.augment(&mut user).await.unwrap();
        assert_eq!(user.roles.len(), 1);
        assert!(user.roles.contains(&"admin".to_string()));
        assert!(!user.roles.contains(&"user".to_string()));
    }

    #[tokio::test]
    async fn test_augment_no_roles() {
        let config = make_test_config();
        let provider = PlainAugProvider::new(&config);

        let mut user = User {
            username: "dave".to_string(),
            roles: vec![],
            ..Default::default()
        };

        provider.augment(&mut user).await.unwrap();
        assert!(user.roles.is_empty());
    }

    #[tokio::test]
    async fn test_get_name_type_realm() {
        let config = make_test_config();
        let provider = PlainAugProvider::new(&config);

        assert_eq!(provider.get_name(), "TestProvider");
        assert_eq!(provider.get_type(), "plain");
        assert_eq!(provider.get_realm(), "test-realm");
    }
}

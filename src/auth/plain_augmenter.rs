use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use futures::lock::Mutex;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

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
        info!(
            "Creating PlainAugProvider for realm='{}', name='{}'",
            config.realm, config.name
        );
        Self {
            config: config.clone(),
        }
    }
}
#[async_trait]
impl Augmenter for PlainAugProvider {
    /// Augment the user with additional roles based on the configuration.
    async fn augment(&self, user: Arc<Mutex<User>>) -> Result<(), String> {
        let user_guard = user.lock().await;
        let username = &user_guard.username.clone();
        let realm = &user_guard.realm.clone();
        drop(user_guard); // Release the lock before doing work
        info!("Augmenting user {} with roles", username);

        if *realm != self.config.realm {
            warn!(
                "User {} is in realm {}, but this provider is for realm {}",
                username, realm, self.config.realm
            );
            return Ok(()); // No roles to add if realms don't match
        }

        // Find roles for the user in the config
        let mut additional_roles = Vec::new();
        for (role_name, users) in &self.config.roles {
            if users.contains(username) {
                info!("Adding role {} to user {}", role_name, username);
                additional_roles.push(role_name.clone());
            }
        }

        if additional_roles.is_empty() {
            info!("No additional roles found for user {}", username);
        } else {
            info!("Adding roles to user {}: {:?}", username, additional_roles);
            user.lock().await.roles.extend(additional_roles);
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

        let user = Arc::new(Mutex::new(User {
            username: "bob".to_string(),
            roles: vec![],
            realm: "test-realm".to_string(),
            ..Default::default()
        }));

        provider.augment(user.clone()).await.unwrap();
        let user_guard = user.lock().await;
        assert!(user_guard.roles.contains(&"admin".to_string()));
        assert!(user_guard.roles.contains(&"user".to_string()));
    }

    #[tokio::test]
    async fn test_augment_no_roles_for_diff_realm() {
        let config = make_test_config();
        let provider = PlainAugProvider::new(&config);
        let user = Arc::new(Mutex::new(User {
            username: "bob".to_string(),
            roles: vec![],
            realm: "other-realm".to_string(),
            ..Default::default()
        }));

        provider.augment(user.clone()).await.unwrap();
        let user_guard = user.lock().await;
        assert!(user_guard.roles.is_empty());
    }

    #[tokio::test]
    async fn test_augment_user_gets_single_role() {
        let config = make_test_config();
        let provider = PlainAugProvider::new(&config);
        let user = Arc::new(Mutex::new(User {
            username: "alice".to_string(),
            roles: vec![],
            realm: "test-realm".to_string(),
            ..Default::default()
        }));

        provider.augment(user.clone()).await.unwrap();
        let user_guard = user.lock().await;
        assert_eq!(user_guard.roles.len(), 1);
        assert!(user_guard.roles.contains(&"admin".to_string()));
        assert!(!user_guard.roles.contains(&"user".to_string()));
    }

    #[tokio::test]
    async fn test_augment_no_roles() {
        let config = make_test_config();
        let user = Arc::new(Mutex::new(User {
            username: "dave".to_string(),
            roles: vec![],
            ..Default::default()
        }));
        let provider = PlainAugProvider::new(&config);

        provider.augment(user.clone()).await.unwrap();
        let user_guard = user.lock().await;
        assert!(user_guard.roles.is_empty());
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

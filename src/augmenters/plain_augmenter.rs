use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use futures::lock::Mutex;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::augmenters::Augmenter;
use crate::models::user::User;

/// PlainAugmenterConfig defines the data for additional roles.
#[derive(Deserialize, Serialize, Debug, JsonSchema, Clone)]
pub struct PlainAugmenterConfig {
    /// A friendly name for logs.
    pub name: String,
    /// The realm associated with this provider.
    pub realm: String,
    /// A list of roles and users.
    pub roles: HashMap<String, Vec<String>>,
}

/// A `PlainAugmenter` that adds custom roles to specific users
pub struct PlainAugmenter {
    pub config: PlainAugmenterConfig,
}

impl PlainAugmenter {
    /// Create a new `PlainAugmenter` from the config struct.
    pub fn new(config: &PlainAugmenterConfig) -> Self {
        warn!(
            "Plain augmenters are being deprecated in favour of advanced plain augmenters - please migrate your configuration"
        );
        info!(
            "Creating PlainAugmenter for realm='{}', name='{}'",
            config.realm, config.name
        );
        Self {
            config: config.clone(),
        }
    }
}
#[async_trait]
impl Augmenter for PlainAugmenter {
    /// Augment the user with additional roles based on the configuration.
    async fn augment(&self, user: Arc<Mutex<User>>) -> Result<(), String> {
        let user_guard = user.lock().await;
        let username = user_guard.username.clone();
        let realm = user_guard.realm.clone();
        drop(user_guard); // Release the lock before doing work

        if realm != self.config.realm {
            debug!(
                event_name = "augmenters.plain.realm_mismatch",
                event_domain = "augmenters",
                augmenter_name = self.config.name.as_str(),
                augmenter_type = "plain",
                username = username.as_str(),
                user_realm = realm.as_str(),
                augmenter_realm = self.config.realm.as_str(),
                "skipping plain augmenter because realms do not match"
            );
            return Ok(()); // No roles to add if realms don't match
        }

        // Find roles for the user in the config
        let mut additional_roles = Vec::new();
        for (role_name, users) in &self.config.roles {
            if users.contains(&username) {
                additional_roles.push(role_name.clone());
            }
        }

        if additional_roles.is_empty() {
            debug!(
                event_name = "augmenters.plain.no_change",
                event_domain = "augmenters",
                augmenter_name = self.config.name.as_str(),
                augmenter_type = "plain",
                username = username.as_str(),
                realm = realm.as_str(),
                "plain augmenter made no role changes"
            );
        } else {
            let added_count = additional_roles.len();
            let added_roles = additional_roles.clone();
            user.lock().await.roles.extend(additional_roles);
            info!(
                event_name = "augmenters.plain.roles_added",
                event_domain = "augmenters",
                augmenter_name = self.config.name.as_str(),
                augmenter_type = "plain",
                username = username.as_str(),
                realm = realm.as_str(),
                added_roles_count = added_count,
                added_roles = ?added_roles,
                "plain augmenter added roles"
            );
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
        Figment,
        providers::{Format, Yaml},
    };

    use super::*;

    fn make_test_config() -> PlainAugmenterConfig {
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
        let provider = PlainAugmenter::new(&config);

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
        let provider = PlainAugmenter::new(&config);
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
        let provider = PlainAugmenter::new(&config);
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
        let provider = PlainAugmenter::new(&config);

        provider.augment(user.clone()).await.unwrap();
        let user_guard = user.lock().await;
        assert!(user_guard.roles.is_empty());
    }

    #[tokio::test]
    async fn test_get_name_type_realm() {
        let config = make_test_config();
        let provider = PlainAugmenter::new(&config);

        assert_eq!(provider.get_name(), "TestProvider");
        assert_eq!(provider.get_type(), "plain");
        assert_eq!(provider.get_realm(), "test-realm");
    }
}

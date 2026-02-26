use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use async_trait::async_trait;
use futures::lock::Mutex;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

use crate::augmenters::Augmenter;
use crate::models::user::User;

#[derive(Deserialize, Serialize, Debug, JsonSchema, Clone, Default)]
pub struct PlainAdvancedAugmenterMatcher {
    /// Users whose names trigger augmentation.
    #[serde(default)]
    pub username: Vec<String>,
    /// Existing roles that trigger augmentation.
    #[serde(default)]
    pub role: Vec<String>,
}

#[derive(Deserialize, Serialize, Debug, JsonSchema, Clone, Default)]
pub struct PlainAdvancedAugmenterAugment {
    /// Roles to append (deduped).
    #[serde(default)]
    pub roles: Vec<String>,
    /// Attributes to upsert (overwrite existing keys).
    #[serde(default)]
    pub attributes: HashMap<String, String>,
}

/// PlainAdvancedAugmenterConfig defines matching and augmentation rules.
#[derive(Deserialize, Serialize, Debug, JsonSchema, Clone)]
pub struct PlainAdvancedAugmenterConfig {
    pub name: String,
    pub realm: String,
    pub r#match: PlainAdvancedAugmenterMatcher,
    pub augment: PlainAdvancedAugmenterAugment,
}

/// A `PlainAdvancedAugmenter` that conditionally adds roles and attributes.
pub struct PlainAdvancedAugmenter {
    pub config: PlainAdvancedAugmenterConfig,
}

impl PlainAdvancedAugmenter {
    pub fn new(config: &PlainAdvancedAugmenterConfig) -> Self {
        info!(
            "Creating PlainAdvancedAugmenter for realm='{}', name='{}'",
            config.realm, config.name
        );
        Self {
            config: config.clone(),
        }
    }
}

#[async_trait]
impl Augmenter for PlainAdvancedAugmenter {
    async fn augment(&self, user: Arc<Mutex<User>>) -> Result<(), String> {
        let user_guard = user.lock().await;
        let username = user_guard.username.clone();
        let realm = user_guard.realm.clone();
        let existing_roles = user_guard.roles.clone();
        drop(user_guard);

        if realm != self.config.realm {
            debug!(
                event_name = "augmenters.plain_advanced.realm_mismatch",
                event_domain = "augmenters",
                augmenter_name = self.config.name.as_str(),
                augmenter_type = "plain_advanced",
                username = username.as_str(),
                user_realm = realm.as_str(),
                augmenter_realm = self.config.realm.as_str(),
                "skipping advanced plain augmenter because realms do not match"
            );
            return Ok(());
        }

        let username_match = self.config.r#match.username.contains(&username);
        let role_match = existing_roles.iter().any(|role| {
            self.config
                .r#match
                .role
                .iter()
                .any(|configured_role| configured_role == role)
        });

        if !username_match && !role_match {
            debug!(
                event_name = "augmenters.plain_advanced.no_match",
                event_domain = "augmenters",
                augmenter_name = self.config.name.as_str(),
                augmenter_type = "plain_advanced",
                username = username.as_str(),
                realm = realm.as_str(),
                "advanced plain augmenter did not match user"
            );
            return Ok(());
        }

        let mut dedup: HashSet<String> = existing_roles.iter().cloned().collect();
        let mut roles_to_add = Vec::new();
        for role in &self.config.augment.roles {
            if dedup.insert(role.clone()) {
                roles_to_add.push(role.clone());
            }
        }

        let mut added_roles_count = 0usize;
        let added_roles_for_log = roles_to_add.clone();
        let mut user_guard = user.lock().await;
        if !roles_to_add.is_empty() {
            added_roles_count = roles_to_add.len();
            user_guard.roles.extend(roles_to_add);
        }

        let mut upserted_attributes_count = 0usize;
        if !self.config.augment.attributes.is_empty() {
            upserted_attributes_count = self.config.augment.attributes.len();
            for (key, value) in &self.config.augment.attributes {
                user_guard.attributes.insert(key.clone(), value.clone());
            }
        }

        if added_roles_count == 0 && upserted_attributes_count == 0 {
            debug!(
                event_name = "augmenters.plain_advanced.no_change",
                event_domain = "augmenters",
                augmenter_name = self.config.name.as_str(),
                augmenter_type = "plain_advanced",
                username = username.as_str(),
                realm = realm.as_str(),
                "advanced plain augmenter made no changes"
            );
        } else {
            info!(
                event_name = "augmenters.plain_advanced.applied",
                event_domain = "augmenters",
                augmenter_name = self.config.name.as_str(),
                augmenter_type = "plain_advanced",
                username = username.as_str(),
                realm = realm.as_str(),
                added_roles_count,
                added_roles = ?added_roles_for_log,
                upserted_attributes_count,
                "advanced plain augmenter applied changes"
            );
        }

        Ok(())
    }

    fn get_name(&self) -> &str {
        &self.config.name
    }

    fn get_type(&self) -> &str {
        "plain_advanced"
    }

    fn get_realm(&self) -> &str {
        &self.config.realm
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use figment::{
        Figment,
        providers::{Format, Yaml},
    };

    fn make_test_config(yaml: &str) -> PlainAdvancedAugmenterConfig {
        Figment::new()
            .merge(Yaml::string(yaml))
            .extract()
            .expect("Failed to parse test config")
    }

    static YAML_1: &str = r#"
name: "Polytope plain admin augmenter"
realm: "ecmwf"
type: "plain_advanced"
match:
  role: [admin]
  username: [adam]
augment:
  roles: [observer, admin]
  attributes:
    team: polytope
    location: cloud
"#;
    #[tokio::test]
    async fn adds_roles_and_attributes_when_username_matches() {
        // matches on username list and applies configured augmentation
        let config = make_test_config(YAML_1);
        let augmenter = PlainAdvancedAugmenter::new(&config);
        let adam = Arc::new(Mutex::new(User {
            username: "adam".to_string(),
            realm: "ecmwf".to_string(),
            roles: vec![],
            ..Default::default()
        }));

        augmenter.augment(adam.clone()).await.unwrap();

        let user_guard = adam.lock().await;
        assert_eq!(
            user_guard.roles.len(),
            2,
            "Expected 2 roles, found {}",
            user_guard.roles.len()
        );
        assert!(user_guard.roles.contains(&"observer".to_string()));
        assert!(user_guard.roles.contains(&"admin".to_string()));
        assert_eq!(
            user_guard.attributes.get("team"),
            Some(&"polytope".to_string())
        );
        assert_eq!(
            user_guard.attributes.get("location"),
            Some(&"cloud".to_string())
        );
    }

    #[tokio::test]
    async fn adds_roles_and_attributes_when_role_matches() {
        // matches on existing role even when username is not listed
        let config = make_test_config(YAML_1);
        let augmenter = PlainAdvancedAugmenter::new(&config);
        let eve = Arc::new(Mutex::new(User {
            username: "eve".to_string(),
            realm: "ecmwf".to_string(),
            roles: vec!["admin".to_string()],
            ..Default::default()
        }));

        augmenter.augment(eve.clone()).await.unwrap();

        let user_guard = eve.lock().await;
        assert!(user_guard.roles.contains(&"observer".to_string()));
        assert!(user_guard.roles.contains(&"admin".to_string()));
        assert_eq!(
            user_guard.attributes.get("team"),
            Some(&"polytope".to_string())
        );
        assert_eq!(
            user_guard.attributes.get("location"),
            Some(&"cloud".to_string())
        );
    }

    #[tokio::test]
    async fn no_change_when_no_match() {
        // neither username nor role matches
        let config = make_test_config(YAML_1);
        let augmenter = PlainAdvancedAugmenter::new(&config);
        let user = Arc::new(Mutex::new(User {
            username: "eve".to_string(),
            realm: "ecmwf".to_string(),
            roles: vec!["guest".to_string()],
            ..Default::default()
        }));

        augmenter.augment(user.clone()).await.unwrap();
        let user_guard = user.lock().await;
        assert_eq!(user_guard.roles, vec!["guest".to_string()]);
        assert!(user_guard.attributes.is_empty());
    }

    #[tokio::test]
    async fn skips_when_realm_differs() {
        // realm mismatch means no augmentation
        let config = make_test_config(YAML_1);
        let augmenter = PlainAdvancedAugmenter::new(&config);
        let user = Arc::new(Mutex::new(User {
            username: "adam".to_string(),
            realm: "other".to_string(),
            ..Default::default()
        }));

        augmenter.augment(user.clone()).await.unwrap();
        let user_guard = user.lock().await;
        assert!(user_guard.roles.is_empty());
        assert!(user_guard.attributes.is_empty());
    }

    #[tokio::test]
    async fn overwrites_attributes_on_conflict() {
        // attribute keys are overwritten when present
        let config = make_test_config(YAML_1);
        let augmenter = PlainAdvancedAugmenter::new(&config);
        let user = Arc::new(Mutex::new(User {
            username: "adam".to_string(),
            realm: "ecmwf".to_string(),
            attributes: HashMap::from([(String::from("team"), String::from("legacy"))]),
            ..Default::default()
        }));

        augmenter.augment(user.clone()).await.unwrap();
        let user_guard = user.lock().await;
        assert_eq!(
            user_guard.attributes.get("team"),
            Some(&"polytope".to_string())
        );
    }

    #[tokio::test]
    async fn avoids_duplicate_roles() {
        // roles already present are not duplicated
        let config = make_test_config(YAML_1);
        let augmenter = PlainAdvancedAugmenter::new(&config);
        let user = Arc::new(Mutex::new(User {
            username: "adam".to_string(),
            realm: "ecmwf".to_string(),
            roles: vec!["admin".to_string()],
            ..Default::default()
        }));

        augmenter.augment(user.clone()).await.unwrap();
        let user_guard = user.lock().await;
        let admin_count = user_guard.roles.iter().filter(|r| *r == "admin").count();
        assert_eq!(admin_count, 1);
    }
}

use std::sync::Arc;

use futures::lock::Mutex;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{
    ldap_augmenter::{LDAPAugmenter, LDAPAugmenterConfig},
    plain_augmenter::{PlainAugmenter, PlainAugmenterConfig},
};
use crate::models::user::User;

/// Configuration options for augmenters (e.g. an LDAP roles augmenter).
#[derive(Deserialize, Serialize, JsonSchema, Debug)]
#[serde(tag = "type")]
pub enum AugmenterConfig {
    #[serde(rename = "ldap")]
    LDAPAugmenterConfig(LDAPAugmenterConfig),

    #[serde(rename = "plain")]
    PlainAugmenterConfig(PlainAugmenterConfig),
}

/// An augmenter can add extra roles or info to an already-authenticated User.
#[async_trait::async_trait]
pub trait Augmenter: Send + Sync {
    fn get_name(&self) -> &str;
    fn get_type(&self) -> &str;
    fn get_realm(&self) -> &str;
    async fn augment(&self, user: Arc<Mutex<User>>) -> Result<(), String>;
}

/// Create an augmenter from a given config.
pub fn create_auth_augmenter(config: &AugmenterConfig) -> Box<dyn Augmenter> {
    match config {
        AugmenterConfig::LDAPAugmenterConfig(cfg) => Box::new(LDAPAugmenter::new(cfg)),
        AugmenterConfig::PlainAugmenterConfig(cfg) => Box::new(PlainAugmenter::new(cfg)),
    }
}

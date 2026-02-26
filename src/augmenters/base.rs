use std::sync::Arc;

use crate::state::AppState;
use axum::{
    Json,
    extract::{ConnectInfo, State},
};
use futures::lock::Mutex;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::net::SocketAddr;
use tracing::debug;

use super::{
    ldap_augmenter::{LDAPAugmenter, LDAPAugmenterConfig},
    plain_advanced_augmenter::{PlainAdvancedAugmenter, PlainAdvancedAugmenterConfig},
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

    #[serde(rename = "plain_advanced")]
    PlainAdvancedAugmenterConfig(PlainAdvancedAugmenterConfig),
}

/// An augmenter can add extra roles or info to an already-authenticated User.
#[async_trait::async_trait]
pub trait Augmenter: Send + Sync {
    #[allow(dead_code)]
    fn get_name(&self) -> &str;
    #[allow(dead_code)]
    fn get_type(&self) -> &str;
    fn get_realm(&self) -> &str;
    async fn augment(&self, user: Arc<Mutex<User>>) -> Result<(), String>;
}

/// Create an augmenter from a given config.
pub fn create_auth_augmenter(config: &AugmenterConfig) -> Box<dyn Augmenter> {
    match config {
        AugmenterConfig::LDAPAugmenterConfig(cfg) => Box::new(LDAPAugmenter::new(cfg)),
        AugmenterConfig::PlainAugmenterConfig(cfg) => Box::new(PlainAugmenter::new(cfg)),
        AugmenterConfig::PlainAdvancedAugmenterConfig(cfg) => {
            Box::new(PlainAdvancedAugmenter::new(cfg))
        }
    }
}

/// Lists configured augmenters with sanitized configuration.
pub async fn list_augmenters(
    State(state): State<AppState>,
    ConnectInfo(client_addr): ConnectInfo<SocketAddr>,
) -> Json<Value> {
    let client_ip = client_addr.ip();
    debug!(
        event_name = "augmenters.list.started",
        event_domain = "augmenters",
        client_ip = client_ip.to_string(),
        "listing configured augmenters"
    );

    let augmenters: Vec<Value> = state
        .config
        .augmenters
        .iter()
        .map(|augmenter| {
            let augmenter_json =
                serde_json::to_value(augmenter).expect("Failed to serialize augmenter config");

            if let Value::Object(mut map) = augmenter_json {
                let name = map.remove("name").unwrap_or_default();
                let augmenter_type = map.remove("type").unwrap_or_default();
                let realm = map.remove("realm").unwrap_or_default();

                json!({
                    "name": name,
                    "type": augmenter_type,
                    "realm": realm,
                })
            } else {
                json!({})
            }
        })
        .collect();

    debug!(
        event_name = "augmenters.list.completed",
        event_domain = "augmenters",
        client_ip = client_ip.to_string(),
        augmenter_count = augmenters.len(),
        "augmenter listing completed"
    );

    Json(json!({
        "augmenters": augmenters
    }))
}

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
use tracing::info;

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
    }
}

/// Lists configured augmenters with sanitized configuration.
pub async fn list_augmenters(
    State(state): State<AppState>,
    ConnectInfo(client_addr): ConnectInfo<SocketAddr>,
) -> Json<Value> {
    let client_ip = client_addr.ip();
    info!("Received request for augmenter list from IP: {}", client_ip);

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

    info!(
        "Returning sanitized augmenter list to IP: {}. Number of augmenters: {}",
        client_ip,
        augmenters.len()
    );

    Json(json!({
        "augmenters": augmenters
    }))
}

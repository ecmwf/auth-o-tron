use super::{
    ecmwfapi_provider::{EcmwfApiProvider, EcmwfApiProviderConfig},
    jwt_provider::{JWTAuthConfig, JWTProvider},
    openid_offline_provider::{OpenIDOfflineProvider, OpenIDOfflineProviderConfig},
    plain_provider::{PlainAuthConfig, PlainAuthProvider},
};
use crate::{models::User, AppState};
use axum::{
    extract::{ConnectInfo, State},
    Json,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::net::SocketAddr;
use tracing::{debug, info};

/// Configuration options for each authentication provider.
#[derive(Deserialize, Serialize, JsonSchema, Debug)]
#[serde(tag = "type")]
pub enum ProviderConfig {
    #[serde(rename = "ecmwf-api")]
    EcmwfApiAuthConfig(EcmwfApiProviderConfig),

    #[serde(rename = "jwt")]
    JWTAuthConfig(JWTAuthConfig),

    #[serde(rename = "openid-offline")]
    OpenIDOfflineAuthConfig(OpenIDOfflineProviderConfig),

    #[serde(rename = "plain")]
    PlainAuthConfig(PlainAuthConfig),
}

/// An authentication provider must be able to return a User or an error.
#[async_trait::async_trait]
pub trait Provider: Send + Sync {
    fn get_name(&self) -> &str;
    fn get_type(&self) -> &str;
    /// Providers that support realm-based filtering should override this.
    fn get_realm(&self) -> Option<&str> {
        None
    }
    async fn authenticate(&self, credentials: &str) -> Result<User, String>;
}

/// Create an authentication provider from a given config.
pub fn create_auth_provider(config: &ProviderConfig) -> Box<dyn Provider> {
    match config {
        ProviderConfig::EcmwfApiAuthConfig(cfg) => Box::new(EcmwfApiProvider::new(cfg)),
        ProviderConfig::JWTAuthConfig(cfg) => Box::new(JWTProvider::new(cfg)),
        ProviderConfig::OpenIDOfflineAuthConfig(cfg) => Box::new(OpenIDOfflineProvider::new(cfg)),
        ProviderConfig::PlainAuthConfig(cfg) => Box::new(PlainAuthProvider::new(cfg)),
    }
}

/// GET /providers endpoint: returns only the provider "name", "type" and "realm" fields
/// by converting each provider config into JSON and extracting the fields.
pub async fn list_providers(
    State(state): State<AppState>,
    ConnectInfo(client_addr): ConnectInfo<SocketAddr>,
) -> Json<Value> {
    let client_ip = client_addr.ip();
    info!("Received request for provider list from IP: {}", client_ip);

    let providers: Vec<Value> = state
        .config
        .providers
        .iter()
        .map(|provider| {
            let provider_json =
                serde_json::to_value(provider).expect("Failed to serialize provider config");
            if let Value::Object(mut map) = provider_json {
                let name = map.remove("name").unwrap_or_default();
                let provider_type = map.remove("type").unwrap_or_default();
                // Extract realm: check for "realm" first, then fallback to "iam_realm"
                let realm = if let Some(r) = map.remove("realm") {
                    r
                } else if let Some(r) = map.remove("iam_realm") {
                    r
                } else {
                    Value::Null
                };
                json!({
                    "name": name,
                    "type": provider_type,
                    "realm": realm,
                })
            } else {
                debug!("Provider configuration was not an object: {:?}", provider);
                json!({})
            }
        })
        .collect();

    info!(
        "Returning sanitized provider list to IP: {}. Number of providers: {}",
        client_ip,
        providers.len()
    );
    Json(json!({ "providers": providers }))
}

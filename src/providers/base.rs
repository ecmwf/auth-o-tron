use super::{
    ecmwf_token_generator_provider::{
        EcmwfTokenGeneratorProvider, EcmwfTokenGeneratorProviderConfig,
    },
    ecmwfapi_provider::{EcmwfApiProvider, EcmwfApiProviderConfig},
    efasapi_provider::{EFASApiProviderConfig, EfasApiProvider},
    jwt_provider::{JWTAuthConfig, JWTProvider},
    openid_offline_provider::{OpenIDOfflineProvider, OpenIDOfflineProviderConfig},
    plain_provider::{PlainAuthConfig, PlainAuthProvider},
};
use crate::{models::user::User, state::AppState};
use axum::{
    Json,
    extract::{ConnectInfo, State},
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::net::SocketAddr;
use tracing::debug;

/// Configuration options for each authentication provider.
#[derive(Deserialize, Serialize, JsonSchema, Debug)]
#[serde(tag = "type")]
pub enum ProviderConfig {
    #[serde(rename = "ecmwf-api")]
    EcmwfApi(EcmwfApiProviderConfig),
    #[serde(rename = "ecmwf-token-generator")]
    EcmwfTokenGenerator(EcmwfTokenGeneratorProviderConfig),
    #[serde(rename = "efas-api")]
    EfasApiProvider(EFASApiProviderConfig),
    #[serde(rename = "jwt")]
    Jwt(JWTAuthConfig),
    #[serde(rename = "openid-offline")]
    OpenIDOffline(OpenIDOfflineProviderConfig),
    #[serde(rename = "plain")]
    Plain(PlainAuthConfig),
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
        ProviderConfig::EcmwfApi(cfg) => Box::new(EcmwfApiProvider::new(cfg)),
        ProviderConfig::EcmwfTokenGenerator(cfg) => Box::new(EcmwfTokenGeneratorProvider::new(cfg)),
        ProviderConfig::EfasApiProvider(cfg) => Box::new(EfasApiProvider::new(cfg)),
        ProviderConfig::Jwt(cfg) => Box::new(JWTProvider::new(cfg)),
        ProviderConfig::OpenIDOffline(cfg) => Box::new(OpenIDOfflineProvider::new(cfg)),
        ProviderConfig::Plain(cfg) => Box::new(PlainAuthProvider::new(cfg)),
    }
}

/// GET /providers endpoint: returns only the provider "name", "type" and "realm" fields
/// by converting each provider config into JSON and extracting the fields.
pub async fn list_providers(
    State(state): State<AppState>,
    ConnectInfo(client_addr): ConnectInfo<SocketAddr>,
) -> Json<Value> {
    let client_ip = client_addr.ip();
    debug!(
        event_name = "providers.list.started",
        event_domain = "providers",
        client_ip = client_ip.to_string(),
        "listing configured providers"
    );

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
                debug!(
                    event_name = "providers.list.invalid_config_shape",
                    event_domain = "providers",
                    "provider configuration was not an object"
                );
                json!({})
            }
        })
        .collect();

    debug!(
        event_name = "providers.list.completed",
        event_domain = "providers",
        client_ip = client_ip.to_string(),
        provider_count = providers.len(),
        "provider listing completed"
    );
    Json(json!({ "providers": providers }))
}

use crate::AppState;
use axum::{
    extract::{ConnectInfo, State},
    Json,
};
use serde_json::{json, Value};
use std::net::SocketAddr;
use tracing::{debug, info};

/// GET /providers endpoint: returns only the provider "name" and "type" fields
/// by converting each provider config into JSON and extracting the fields.
pub async fn list_providers(
    State(state): State<AppState>,
    ConnectInfo(client_addr): ConnectInfo<SocketAddr>, // Extract client IP
) -> Json<Value> {
    let client_ip = client_addr.ip();
    info!("Received request for provider list from IP: {}", client_ip);

    let providers: Vec<Value> = state
        .config
        .providers
        .iter()
        .map(|provider| {
            // Convert the provider config to a serde_json::Value.
            let provider_json =
                serde_json::to_value(provider).expect("Failed to serialize provider config");
            if let Value::Object(mut map) = provider_json {
                // Remove all keys except for "name" and "type".
                let name = map.remove("name").unwrap_or_default();
                let provider_type = map.remove("type").unwrap_or_default();
                json!({
                    "name": name,
                    "type": provider_type,
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

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{debug, info};

use super::User;
use cached::proc_macro::cached;
use reqwest;

/// The config needed for the ECMWF API provider:
/// - `uri` indicates the who-am-i endpoint
/// - `realm` is the user realm
/// - `name` is this provider’s display name
#[derive(Deserialize, Serialize, Debug, JsonSchema, Clone)]
pub struct EcmwfApiProviderConfig {
    pub uri: String,
    pub realm: String,
    pub name: String,
}

/// A provider that queries the ECMWF API (`who-am-i`) endpoint to authenticate a token.
pub struct EcmwfApiProvider {
    pub config: EcmwfApiProviderConfig,
}

impl EcmwfApiProvider {
    /// Creates a new ECMWF API provider.
    pub fn new(config: &EcmwfApiProviderConfig) -> Self {
        info!(
            "Creating EcmwfApiAuth provider for realm '{}', name='{}'",
            config.realm, config.name
        );
        Self {
            config: config.clone(),
        }
    }
}

#[async_trait::async_trait]
impl super::Provider for EcmwfApiProvider {
    /// Provider type is typically "Bearer".
    fn get_type(&self) -> &str {
        "Bearer"
    }

    /// Makes an HTTP call to the ECMWF API to validate the token and retrieve user info.
    async fn authenticate(&self, token: &str) -> Result<User, String> {
        query(
            self.config.uri.to_string(),
            token.to_string(),
            self.config.realm.to_string(),
        )
        .await
    }

    /// The display name for this provider, used in logs or debugging.
    fn get_name(&self) -> &str {
        &self.config.name
    }
}

/// This function calls the ECMWF `who-am-i` endpoint with the provided token.
/// We cache results for 60 seconds.
#[cached(time = 60, sync_writes = true)]
async fn query(uri: String, token: String, realm: String) -> Result<User, String> {
    let client = reqwest::Client::new();
    let url = format!("{}/who-am-i?token={}", uri, token);

    debug!("Sending ECMWF who-am-i request to: {}", url);
    let response = match client.get(&url).send().await {
        Ok(r) => r,
        Err(e) => return Err(format!("Error sending request: {}", e)),
    };

    if response.status().is_success() {
        // Parse the JSON body
        let body = response
            .text()
            .await
            .map_err(|e| format!("Error reading response body: {}", e))?;
        let user_info: Value =
            serde_json::from_str(&body).map_err(|e| format!("Error parsing JSON: {}", e))?;

        let username = user_info["uid"].as_str().unwrap_or_default().to_string();

        let user = User::new(realm, username, None, None, None, None);
        Ok(user)
    } else if response.status() == 403 {
        Err("Invalid API token".to_string())
    } else {
        Err(format!("Unexpected status code: {}", response.status()))
    }
}

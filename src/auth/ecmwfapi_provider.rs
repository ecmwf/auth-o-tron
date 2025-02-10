use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{debug, info};

use crate::models::User;
use cached::proc_macro::cached;
use reqwest;

/// The config needed for the ECMWF API provider (who-am-i endpoint).
#[derive(Deserialize, Serialize, Debug, JsonSchema, Clone)]
pub struct EcmwfApiProviderConfig {
    pub uri: String,
    pub realm: String,
    pub name: String,
}

/// A provider that calls the ECMWF who-am-i endpoint to validate a token.
pub struct EcmwfApiProvider {
    pub config: EcmwfApiProviderConfig,
}

impl EcmwfApiProvider {
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
    fn get_type(&self) -> &str {
        "Bearer"
    }

    async fn authenticate(&self, token: &str) -> Result<User, String> {
        query(
            self.config.uri.clone(),
            token.to_string(),
            self.config.realm.clone(),
        )
        .await
    }

    fn get_name(&self) -> &str {
        &self.config.name
    }
}

/// Queries the ECMWF who-am-i endpoint with the provided token, returning a User on success.
#[cfg_attr(not(test), cached(time = 60, sync_writes = true))]
async fn query(uri: String, token: String, realm: String) -> Result<User, String> {
    let client = reqwest::Client::new();
    let url = format!("{}/who-am-i?token={}", uri, token);

    debug!("Sending ECMWF who-am-i request to: {}", url);
    let response = match client.get(&url).send().await {
        Ok(r) => r,
        Err(e) => return Err(format!("Error sending request: {}", e)),
    };

    if response.status().is_success() {
        let body = response
            .text()
            .await
            .map_err(|e| format!("Error reading response body: {}", e))?;
        let user_info: Value =
            serde_json::from_str(&body).map_err(|e| format!("Error parsing JSON: {}", e))?;

        let username = user_info["uid"].as_str().unwrap_or_default().to_string();
        Ok(User::new(realm, username, None, None, None, None))
    } else if response.status() == 403 {
        Err("Invalid API token".to_string())
    } else {
        Err(format!("Unexpected status code: {}", response.status()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::Server;
    use tokio;

    /// Test that a valid token returns a User with the expected UID.
    #[tokio::test]
    async fn test_ecmwf_api_provider_success() {
        let token = "valid_token";
        let response_body = r#"{"uid": "user_ecmwf"}"#;
        let realm = "test";

        // Create an async mock server (mutable).
        let mut server = Server::new_async().await;
        // Build the expected path for the who-am-i endpoint.
        let path = format!("/who-am-i?token={}", token);
        // Create a mock for the GET request.
        let m = server
            .mock("GET", path.as_str())
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(response_body)
            .create_async()
            .await;

        // Get the base URL from the mock server.
        let uri = server.url();
        let result = query(uri, token.to_string(), realm.to_string()).await;
        m.assert_async().await;
        assert!(result.is_ok());
        let user = result.unwrap();
        assert_eq!(user.username, "user_ecmwf");
        assert_eq!(user.realm, realm);
    }

    /// Test that an invalid token (simulated with a 403 response) returns an error.
    #[tokio::test]
    async fn test_ecmwf_api_provider_invalid_token() {
        let token = "invalid_token";
        let realm = "test";
        let response_body = "Forbidden";

        let mut server = Server::new_async().await;
        let path = format!("/who-am-i?token={}", token);
        let m = server
            .mock("GET", path.as_str())
            .with_status(403)
            .with_body(response_body)
            .create_async()
            .await;

        let uri = server.url();
        let result = query(uri, token.to_string(), realm.to_string()).await;
        m.assert_async().await;
        assert!(result.is_err());
    }
}

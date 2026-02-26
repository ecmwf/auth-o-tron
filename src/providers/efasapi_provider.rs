use std::collections::HashMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Duration;
use tracing::{debug, info};

use crate::utils::log_throttle::should_emit;
use crate::{models::user::User, providers::Provider, utils::value::value_to_string};
use cached::Return;
#[allow(unused_imports)]
use cached::proc_macro::cached;
use reqwest;
const CACHE_HIT_LOG_WINDOW: Duration = Duration::from_secs(30);

#[derive(Deserialize, Serialize, Debug, JsonSchema, Clone)]
pub struct EFASApiProviderConfig {
    pub uri: String,
    pub name: String,
    pub realm: String,
}

/// A provider that calls the EFAS user-details endpoint to validate a token.
pub struct EfasApiProvider {
    pub config: EFASApiProviderConfig,
}

#[derive(Deserialize, Debug)]
struct EfasUserDetailsResponse {
    username: String,
    #[serde(default)]
    roles: Vec<String>,
    #[serde(flatten)]
    extra: HashMap<String, Value>,
}

impl EfasApiProvider {
    pub fn new(config: &EFASApiProviderConfig) -> Self {
        info!("Creating EFASApiAuth provider for realm");
        Self {
            config: config.clone(),
        }
    }
}

#[async_trait::async_trait]
impl Provider for EfasApiProvider {
    fn get_type(&self) -> &str {
        "Bearer"
    }

    fn get_realm(&self) -> Option<&str> {
        Some("efas")
    }

    async fn authenticate(&self, token: &str) -> Result<User, String> {
        let cached_user = query(
            self.config.uri.clone(),
            token.to_string(),
            self.config.realm.clone(),
        )
        .await?;
        if cached_user.was_cached
            && let Some(suppressed_count) =
                should_emit("providers.efas_api.cache.hit", CACHE_HIT_LOG_WINDOW)
        {
            debug!(
                event_name = "providers.efas_api.cache.hit",
                event_domain = "providers",
                provider_name = self.config.name.as_str(),
                realm = self.config.realm.as_str(),
                cache_result = "hit",
                cache_ttl_seconds = 60,
                cache_key_type = "token",
                suppressed_count,
                "provider authentication result served from cache"
            );
        }
        Ok((*cached_user).clone())
    }

    fn get_name(&self) -> &str {
        &self.config.name
    }
}

/// Queries the EFAS auth url
#[cfg_attr(
    not(test),
    cached(
        time = 60,
        result = true,
        with_cached_flag = true,
        sync_writes = "default"
    )
)]
async fn query(uri: String, token: String, realm: String) -> Result<Return<User>, String> {
    let client = reqwest::Client::new();
    let url = format!("{}?token={}", uri, token);

    debug!("Sending EFAS user-details request to: {}", url);
    let response = match client.get(&url).send().await {
        Ok(r) => r,
        Err(e) => return Err(format!("Error sending request: {}", e)),
    };

    if response.status().is_success() {
        let body = response
            .text()
            .await
            .map_err(|e| format!("Error reading response body: {}", e))?;
        let user_info: EfasUserDetailsResponse =
            serde_json::from_str(&body).map_err(|e| format!("Error parsing JSON: {}", e))?;

        let username = user_info.username;
        let roles = user_info.roles;
        let attributes = user_info
            .extra
            .into_iter()
            .map(|(k, v)| (k, value_to_string(v)))
            .collect();
        Ok(Return::new(User::new(
            realm,
            username,
            Some(roles),
            Some(attributes),
            None,
            None,
        )))
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
    use tracing_test::traced_test;

    /// Test that a valid token returns a User with the expected UID.
    #[tokio::test]
    #[traced_test]
    async fn test_ecmwf_api_provider_success() {
        let token = "valid_token";
        let response_body = r#"{
            "user_id": 1,
            "username": "user_ecmwf",
            "first_name": "Test",
            "last_name": "User",
            "email": "user@example.com",
            "partner_abbr": "ECMWF",
            "partner_country": "N/A",
            "partner_name": "ECMWF",
            "roles": ["admin"]
        }"#;
        let realm = "test";

        // Create an async mock server (mutable).
        let mut server = Server::new_async().await;
        // Build the expected path for the user-details endpoint.
        let path = format!("/?token={}", token);
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
        let user = result.unwrap();
        assert_eq!(user.username, "user_ecmwf");
        assert_eq!(user.realm, realm);
        assert_eq!(user.roles, vec!["admin".to_string()]);
        assert_eq!(
            user.attributes.get("email"),
            Some(&"user@example.com".to_string())
        );
    }

    /// Test that an invalid token (simulated with a 403 response) returns an error.
    #[tokio::test]
    async fn test_efas_api_provider_invalid_token() {
        let token = "invalid_token";
        let realm = "test";
        let response_body = "Invalid access token";

        let mut server = Server::new_async().await;
        let path = format!("/?token={}", token);
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

#[allow(unused_imports)]
use cached::proc_macro::cached;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
#[cfg(not(test))]
use std::time::Duration;
use tracing::{debug, info};

use super::jwt_provider::{JWTAuthConfig, JWTProvider};
use crate::models::user::User;
use crate::providers::Provider;

/// Config for an OpenID provider that also supports offline tokens.
#[derive(Deserialize, Debug, Serialize, JsonSchema, Hash, Clone, PartialEq, Eq)]
pub struct OpenIDOfflineProviderConfig {
    pub name: String,
    pub cert_uri: String,
    pub public_client_id: String,
    pub private_client_id: String,
    pub private_client_secret: String,
    pub iam_url: String,
    pub realm: String,
}

/// A provider that validates offline_access tokens and then fetches
/// an online access token to pass to an internal JWTProvider.
pub struct OpenIDOfflineProvider {
    config: OpenIDOfflineProviderConfig,
    jwt_auth: JWTProvider,
}

impl OpenIDOfflineProvider {
    /// Creates a new `OpenIDOfflineProvider`, internally using a `JWTProvider` for final validation.
    pub fn new(config: &OpenIDOfflineProviderConfig) -> Self {
        info!(
            "Creating OpenIDOfflineProvider for realm '{}', name='{}'",
            config.realm, config.name
        );

        // The nested JWT auth will handle the final token validation
        let jwt_auth = JWTProvider::new(&JWTAuthConfig {
            cert_uri: config.cert_uri.clone(),
            realm: config.realm.clone(),
            name: config.name.clone(),
            iam_realm: config.realm.clone(),
        });

        Self {
            config: config.clone(),
            jwt_auth,
        }
    }
}

/// Checks if the given token has "offline_access" scope. If valid, returns true.
#[cfg_attr(not(test), cached(time = 120, sync_writes = "default"))]
async fn check_offline_access_token(
    config: OpenIDOfflineProviderConfig,
    token: String,
) -> Result<bool, String> {
    debug!("Checking offline access token at realm='{}'", config.realm);

    let introspection_url = format!(
        "{}/realms/{}/protocol/openid-connect/token/introspect",
        config.iam_url, config.realm
    );
    let client = reqwest::Client::new();

    let resp = client
        .post(&introspection_url)
        .basic_auth(config.private_client_id, Some(config.private_client_secret))
        .form(&[("token", token)])
        .send()
        .await
        .map_err(|e| format!("Failed to call introspection endpoint: {}", e))?
        .json::<Value>()
        .await
        .map_err(|e| format!("Failed to parse introspection JSON: {}", e))?;

    // If "active" is true and "scope" includes "offline_access", we consider it valid
    let active = resp["active"].as_bool().unwrap_or(false);
    let scope = resp["scope"].as_str().unwrap_or("");

    Ok(active && scope.contains("offline_access"))
}

/// Exchanges the offline token for a regular access token using a refresh call.
#[cfg_attr(not(test), cached(time = 10, sync_writes = "default"))]
async fn get_access_token(
    config: OpenIDOfflineProviderConfig,
    refresh_token: String,
) -> Result<String, String> {
    debug!(
        "Exchanging offline token for an online access token at realm='{}'",
        config.realm
    );

    let refresh_data = [
        ("client_id", config.public_client_id.as_str()),
        ("grant_type", "refresh_token"),
        ("refresh_token", &refresh_token),
    ];
    let token_endpoint = format!(
        "{}/realms/{}/protocol/openid-connect/token",
        config.iam_url, config.realm
    );

    let client = reqwest::Client::new();
    let resp = client
        .post(&token_endpoint)
        .basic_auth(config.private_client_id, Some(config.private_client_secret))
        .form(&refresh_data)
        .send()
        .await
        .map_err(|e| format!("Failed to exchange token: {}", e))?;

    let json_body = resp
        .json::<Value>()
        .await
        .map_err(|e| format!("Failed to parse access token JSON: {}", e))?;

    let access_token = json_body
        .get("access_token")
        .and_then(|t| t.as_str())
        .ok_or_else(|| "Failed to retrieve access token from response".to_string())?
        .to_string();

    Ok(access_token)
}

#[async_trait::async_trait]
impl Provider for OpenIDOfflineProvider {
    fn get_type(&self) -> &str {
        "Bearer"
    }

    fn get_realm(&self) -> Option<&str> {
        Some(&self.config.realm)
    }

    fn get_name(&self) -> &str {
        &self.config.name
    }

    /// First checks if the token is valid offline token, then uses it to fetch an online token,
    /// and finally calls the internal `jwt_auth` to authenticate.
    async fn authenticate(&self, credentials: &str) -> Result<User, String> {
        if !check_offline_access_token(self.config.clone(), credentials.to_string()).await? {
            return Err("Not a valid offline_access token".into());
        }

        let access_token = get_access_token(self.config.clone(), credentials.to_string()).await?;
        self.jwt_auth.authenticate(&access_token).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::Server;
    use tokio;

    /// Test that check_offline_access_token returns true
    /// when the introspection endpoint indicates a valid offline token.
    #[tokio::test]
    async fn test_check_offline_access_token_valid() {
        // Define the expected introspection response.
        let response_body = r#"{"active": true, "scope": "offline_access other_scope"}"#;
        let realm = "test";

        // Create an asynchronous mock server.
        let mut server = Server::new_async().await;
        // Build the path for the introspection endpoint.
        let path = format!("/realms/{}/protocol/openid-connect/token/introspect", realm);
        let m = server
            .mock("POST", path.as_str())
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(response_body)
            .create_async()
            .await;

        // Use the mock server's URL as iam_url.
        let config = OpenIDOfflineProviderConfig {
            name: "TestOpenID".to_string(),
            cert_uri: "".to_string(),
            public_client_id: "public".to_string(),
            private_client_id: "private".to_string(),
            private_client_secret: "secret".to_string(),
            iam_url: server.url(),
            realm: realm.to_string(),
        };

        let result = check_offline_access_token(config, "dummy_token".to_string()).await;
        m.assert_async().await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), true);
    }

    /// Test that check_offline_access_token returns false when the introspection endpoint indicates an inactive token.
    #[tokio::test]
    async fn test_check_offline_access_token_invalid() {
        let response_body = r#"{"active": false, "scope": ""}"#;
        let realm = "test";

        let mut server = Server::new_async().await;
        let path = format!("/realms/{}/protocol/openid-connect/token/introspect", realm);
        let m = server
            .mock("POST", path.as_str())
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(response_body)
            .create_async()
            .await;

        let config = OpenIDOfflineProviderConfig {
            name: "TestOpenID".to_string(),
            cert_uri: "".to_string(),
            public_client_id: "public".to_string(),
            private_client_id: "private".to_string(),
            private_client_secret: "secret".to_string(),
            iam_url: server.url(),
            realm: realm.to_string(),
        };

        let result = check_offline_access_token(config, "dummy_token".to_string()).await;
        m.assert_async().await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), false);
    }

    /// Test that get_access_token successfully exchanges a refresh token for an access token.
    #[tokio::test]
    async fn test_get_access_token_success() {
        let response_body = r#"{"access_token": "new_access_token"}"#;
        let realm = "test";

        let mut server = Server::new_async().await;
        let path = format!("/realms/{}/protocol/openid-connect/token", realm);
        let m = server
            .mock("POST", path.as_str())
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(response_body)
            .create_async()
            .await;

        let config = OpenIDOfflineProviderConfig {
            name: "TestOpenID".to_string(),
            cert_uri: "".to_string(),
            public_client_id: "public".to_string(),
            private_client_id: "private".to_string(),
            private_client_secret: "secret".to_string(),
            iam_url: server.url(),
            realm: realm.to_string(),
        };

        let result = get_access_token(config, "dummy_refresh_token".to_string()).await;
        m.assert_async().await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "new_access_token".to_string());
    }
}

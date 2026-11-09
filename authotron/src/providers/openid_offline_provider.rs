// (C) Copyright 2024- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

use cached::Return;
#[allow(unused_imports)]
use cached::proc_macro::cached;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::LazyLock;
use std::time::Duration;
use tracing::{debug, info};

use super::jwt_provider::{JWTAuthConfig, JWTProvider};
use crate::models::user::User;
use crate::providers::Provider;
use crate::utils::log_throttle::should_emit;
const CACHE_HIT_LOG_WINDOW: Duration = Duration::from_secs(30);

/// Shared client for DESP IAM calls (offline-token introspection and refresh
/// exchange). Reusing one client (and its connection pool) avoids a fresh
/// TCP+TLS handshake on every cache-miss, which under load churned connections
/// and amplified pressure on the upstream DESP identity provider.
static HTTP_CLIENT: LazyLock<reqwest::Client> = LazyLock::new(reqwest::Client::new);

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
            event_name = "providers.openid_offline.initialization",
            event_domain = "providers",
            provider_name = config.name.as_str(),
            realm = config.realm.as_str(),
            "creating OpenID offline provider"
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
#[cfg_attr(
    not(test),
    cached(
        time = 120,
        result = true,
        with_cached_flag = true,
        sync_writes = "default"
    )
)]
async fn check_offline_access_token(
    config: OpenIDOfflineProviderConfig,
    token: String,
) -> Result<Return<bool>, String> {
    debug!(
        event_name = "providers.openid_offline.introspection.started",
        event_domain = "providers",
        realm = config.realm.as_str(),
        "checking offline access token"
    );

    let introspection_url = format!(
        "{}/realms/{}/protocol/openid-connect/token/introspect",
        config.iam_url, config.realm
    );
    let resp = HTTP_CLIENT
        .post(&introspection_url)
        .basic_auth(config.private_client_id, Some(config.private_client_secret))
        .form(&[("token", token)])
        .send()
        .await
        .map_err(|e| format!("Failed to call introspection endpoint: {}", e))?;

    // A failed call (e.g. wrong client credentials) is an error, not an invalid
    // token: it must not be cached as a negative result.
    if !resp.status().is_success() {
        return Err(format!(
            "Introspection endpoint returned status {}",
            resp.status()
        ));
    }
    let body = resp
        .json::<Value>()
        .await
        .map_err(|e| format!("Failed to parse introspection JSON: {}", e))?;

    // Valid if "active" is true and "offline_access" is one of the scopes
    let active = body["active"].as_bool().unwrap_or(false);
    let has_offline_scope = body["scope"]
        .as_str()
        .unwrap_or("")
        .split_whitespace()
        .any(|s| s == "offline_access");

    Ok(Return::new(active && has_offline_scope))
}

/// Exchanges the offline token for a regular access token using a refresh call.
/// Returns `None` when the identity server rejects the token.
#[cfg_attr(
    not(test),
    cached(
        time = 10,
        result = true,
        with_cached_flag = true,
        sync_writes = "default"
    )
)]
async fn get_access_token(
    config: OpenIDOfflineProviderConfig,
    refresh_token: String,
) -> Result<Return<Option<String>>, String> {
    debug!(
        event_name = "providers.openid_offline.exchange.started",
        event_domain = "providers",
        realm = config.realm.as_str(),
        "exchanging offline token for access token"
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

    let resp = HTTP_CLIENT
        .post(&token_endpoint)
        .basic_auth(config.private_client_id, Some(config.private_client_secret))
        .form(&refresh_data)
        .send()
        .await
        .map_err(|e| format!("Failed to exchange token: {}", e))?;

    let status = resp.status();
    // RFC 6749 section 5.2: a rejected grant is a 400 with error "invalid_grant",
    // cached like a valid result. Other errors (e.g. "invalid_client") point at
    // our configuration and are not cached.
    if status == reqwest::StatusCode::BAD_REQUEST {
        let body = resp.json::<Value>().await.unwrap_or_default();
        if body["error"].as_str() == Some("invalid_grant") {
            return Ok(Return::new(None));
        }
        return Err(format!(
            "Token exchange failed: {}",
            body["error"].as_str().unwrap_or("unknown error")
        ));
    }
    if !status.is_success() {
        return Err(format!("Token endpoint returned status {}", status));
    }

    let json_body = resp
        .json::<Value>()
        .await
        .map_err(|e| format!("Failed to parse access token JSON: {}", e))?;

    let access_token = json_body
        .get("access_token")
        .and_then(|t| t.as_str())
        .ok_or_else(|| "Failed to retrieve access token from response".to_string())?
        .to_string();

    Ok(Return::new(Some(access_token)))
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
        let offline_check =
            check_offline_access_token(self.config.clone(), credentials.to_string()).await?;
        if offline_check.was_cached
            && let Some(suppressed_count) = should_emit(
                "providers.openid_offline.introspection.cache.hit",
                CACHE_HIT_LOG_WINDOW,
            )
        {
            debug!(
                event_name = "providers.openid_offline.introspection.cache.hit",
                event_domain = "providers",
                provider_name = self.config.name.as_str(),
                realm = self.config.realm.as_str(),
                cache_result = "hit",
                cache_ttl_seconds = 120,
                cache_key_type = "token",
                suppressed_count,
                "offline token introspection served from cache"
            );
        }

        if !*offline_check {
            return Err("Not a valid offline_access token".into());
        }

        let access_token = get_access_token(self.config.clone(), credentials.to_string()).await?;
        if access_token.was_cached
            && let Some(suppressed_count) = should_emit(
                "providers.openid_offline.exchange.cache.hit",
                CACHE_HIT_LOG_WINDOW,
            )
        {
            debug!(
                event_name = "providers.openid_offline.exchange.cache.hit",
                event_domain = "providers",
                provider_name = self.config.name.as_str(),
                realm = self.config.realm.as_str(),
                cache_result = "hit",
                cache_ttl_seconds = 10,
                cache_key_type = "token",
                suppressed_count,
                "offline token exchange served from cache"
            );
        }
        let access_token = access_token
            .as_ref()
            .ok_or_else(|| "Offline token rejected by the identity server".to_string())?;
        self.jwt_auth.authenticate(access_token).await
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
        assert!(*result.unwrap());
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
        assert!(!*result.unwrap());
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
        assert_eq!(*result.unwrap(), Some("new_access_token".to_string()));
    }

    fn config_for(server: &Server) -> OpenIDOfflineProviderConfig {
        OpenIDOfflineProviderConfig {
            name: "TestOpenID".to_string(),
            cert_uri: "".to_string(),
            public_client_id: "public".to_string(),
            private_client_id: "private".to_string(),
            private_client_secret: "secret".to_string(),
            iam_url: server.url(),
            realm: "test".to_string(),
        }
    }

    async fn mock_post(
        server: &mut Server,
        path: &str,
        status: usize,
        body: &str,
    ) -> mockito::Mock {
        server
            .mock("POST", path)
            .with_status(status)
            .with_header("content-type", "application/json")
            .with_body(body)
            .create_async()
            .await
    }

    const INTROSPECT_PATH: &str = "/realms/test/protocol/openid-connect/token/introspect";
    const TOKEN_PATH: &str = "/realms/test/protocol/openid-connect/token";

    /// The scope must contain "offline_access" as a whole word.
    #[tokio::test]
    async fn test_check_offline_access_token_rejects_scope_substring() {
        let mut server = Server::new_async().await;
        let body = r#"{"active": true, "scope": "openid no_offline_access_x"}"#;
        let m = mock_post(&mut server, INTROSPECT_PATH, 200, body).await;
        let result = check_offline_access_token(config_for(&server), "dummy".to_string()).await;
        m.assert_async().await;
        assert!(!*result.unwrap());
    }

    /// A failed introspection call is an error, so it is not cached as an invalid token.
    #[tokio::test]
    async fn test_check_offline_access_token_error_status() {
        let mut server = Server::new_async().await;
        let body = r#"{"error": "invalid_request", "error_description": "Authentication failed."}"#;
        let m = mock_post(&mut server, INTROSPECT_PATH, 401, body).await;
        let result = check_offline_access_token(config_for(&server), "dummy".to_string()).await;
        m.assert_async().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_get_access_token_invalid_grant() {
        let mut server = Server::new_async().await;
        let body = r#"{"error": "invalid_grant", "error_description": "Invalid refresh token"}"#;
        let m = mock_post(&mut server, TOKEN_PATH, 400, body).await;
        let result = get_access_token(config_for(&server), "dummy".to_string()).await;
        m.assert_async().await;
        assert_eq!(*result.unwrap(), None);
    }

    #[tokio::test]
    async fn test_get_access_token_invalid_client() {
        let mut server = Server::new_async().await;
        let m = mock_post(
            &mut server,
            TOKEN_PATH,
            400,
            r#"{"error": "invalid_client"}"#,
        )
        .await;
        let result = get_access_token(config_for(&server), "dummy".to_string()).await;
        m.assert_async().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_get_access_token_server_error() {
        let mut server = Server::new_async().await;
        let m = mock_post(&mut server, TOKEN_PATH, 503, "").await;
        let result = get_access_token(config_for(&server), "dummy".to_string()).await;
        m.assert_async().await;
        assert!(result.is_err());
    }
}

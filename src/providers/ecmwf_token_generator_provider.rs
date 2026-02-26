use cached::Return;
#[allow(unused_imports)]
use cached::proc_macro::cached;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Duration;
use tracing::{debug, info};

use super::jwt_provider::{JWTAuthConfig, JWTProvider};
use crate::models::user::User;
use crate::providers::Provider;
use crate::utils::log_throttle::should_emit;
const CACHE_HIT_LOG_WINDOW: Duration = Duration::from_secs(30);

/// Config for an ECMWF Token Generator provider that validates tokens through the token generator API.
#[derive(Deserialize, Debug, Serialize, JsonSchema, Hash, Clone, PartialEq, Eq)]
pub struct EcmwfTokenGeneratorProviderConfig {
    pub name: String,
    pub cert_uri: String,
    pub client_id: String,
    pub client_secret: String,
    pub token_generator_url: String,
    pub realm: String,
}

/// A provider that validates tokens through the ECMWF Token Generator API and then uses a JWTProvider for final validation.
/// This provider supports exchanging offline refresh tokens for access tokens via the ECMWF Token Generator Keycloak wrapper.
pub struct EcmwfTokenGeneratorProvider {
    config: EcmwfTokenGeneratorProviderConfig,
    jwt_auth: JWTProvider,
}

impl EcmwfTokenGeneratorProvider {
    /// Creates a new `EcmwfTokenGeneratorProvider`, internally using a `JWTProvider` for final validation.
    pub fn new(config: &EcmwfTokenGeneratorProviderConfig) -> Self {
        info!(
            "Creating EcmwfTokenGeneratorProvider for realm '{}', name='{}'",
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

/// Validates a token using the ECMWF Token Generator validate-token endpoint.
/// Caches results for 240 seconds (tokens valid for 300) to reduce load on the token generator.
#[cfg_attr(
    not(test),
    cached(
        time = 240,
        result = true,
        with_cached_flag = true,
        sync_writes = "default"
    )
)]
async fn validate_token_with_generator(
    config: EcmwfTokenGeneratorProviderConfig,
    token: String,
) -> Result<Return<bool>, String> {
    debug!(
        "Validating token with ECMWF Token Generator at '{}' for realm='{}'",
        config.token_generator_url, config.realm
    );

    let validate_url = format!("{}/validate-token", config.token_generator_url);
    let client = reqwest::Client::new();

    let request_body = serde_json::json!({
        "token": token,
        "client_id": config.client_id
    });

    let resp = client
        .post(&validate_url)
        .header("Content-Type", "application/json")
        .json(&request_body)
        .send()
        .await
        .map_err(|e| format!("Failed to call token validation endpoint: {}", e))?
        .json::<Value>()
        .await
        .map_err(|e| format!("Failed to parse validation JSON: {}", e))?;

    // Check if the token is active
    let active = resp["active"].as_bool().unwrap_or(false);
    debug!("Token validation completed: active={}", active);
    Ok(Return::new(active))
}

/// Exchanges an offline/refresh token for an access token using the ECMWF Token Generator API.
/// Caches results for 240 seconds (tokens valid for 300) to reduce load on the token generator.
#[cfg_attr(
    not(test),
    cached(
        time = 240,
        result = true,
        with_cached_flag = true,
        sync_writes = "default"
    )
)]
async fn get_access_token_from_generator(
    config: EcmwfTokenGeneratorProviderConfig,
    refresh_token: String,
) -> Result<Return<String>, String> {
    debug!(
        "Exchanging refresh token for access token via ECMWF Token Generator at '{}'",
        config.token_generator_url
    );

    let refresh_url = format!("{}/admin/refresh-access-token", config.token_generator_url);
    let client = reqwest::Client::new();

    let request_body = serde_json::json!({
        "client_id": config.client_id,
        "client_secret": config.client_secret,
        "refresh_token": refresh_token
    });

    // Set the refresh token as Authorization header
    let resp = client
        .post(&refresh_url)
        .header("Content-Type", "application/json")
        .json(&request_body)
        .send()
        .await
        .map_err(|e| format!("Failed to exchange token via generator: {}", e))?
        .json::<Value>()
        .await
        .map_err(|e| format!("Failed to parse access token response: {}", e))?;

    let access_token = resp
        .get("access_token")
        .and_then(|t| t.as_str())
        .ok_or_else(|| "Failed to retrieve access token from generator response".to_string())?
        .to_string();

    debug!("Access token exchange completed successfully");
    Ok(Return::new(access_token))
}

#[async_trait::async_trait]
impl Provider for EcmwfTokenGeneratorProvider {
    fn get_type(&self) -> &str {
        "Bearer"
    }

    fn get_realm(&self) -> Option<&str> {
        Some(&self.config.realm)
    }

    fn get_name(&self) -> &str {
        &self.config.name
    }

    /// First validates the token with the ECMWF Token Generator API.
    /// If it's an offline token, exchanges it for an access token.
    /// Finally calls the internal jwt_auth to authenticate and get user info.
    async fn authenticate(&self, credentials: &str) -> Result<User, String> {
        // First, validate the token with the ECMWF Token Generator
        let validation =
            validate_token_with_generator(self.config.clone(), credentials.to_string()).await?;
        if validation.was_cached
            && let Some(suppressed_count) = should_emit(
                "providers.ecmwf_token_generator.validate.cache.hit",
                CACHE_HIT_LOG_WINDOW,
            )
        {
            debug!(
                event_name = "providers.ecmwf_token_generator.validate.cache.hit",
                event_domain = "providers",
                provider_name = self.config.name.as_str(),
                realm = self.config.realm.as_str(),
                cache_result = "hit",
                cache_ttl_seconds = 240,
                cache_key_type = "token",
                suppressed_count,
                "token-generator validation served from cache"
            );
        }
        if !*validation {
            return Err("Token is not valid according to ECMWF Token Generator".into());
        }

        // Get access token from token generator
        let access_token =
            get_access_token_from_generator(self.config.clone(), credentials.to_string()).await?;
        if access_token.was_cached
            && let Some(suppressed_count) = should_emit(
                "providers.ecmwf_token_generator.exchange.cache.hit",
                CACHE_HIT_LOG_WINDOW,
            )
        {
            debug!(
                event_name = "providers.ecmwf_token_generator.exchange.cache.hit",
                event_domain = "providers",
                provider_name = self.config.name.as_str(),
                realm = self.config.realm.as_str(),
                cache_result = "hit",
                cache_ttl_seconds = 240,
                cache_key_type = "token",
                suppressed_count,
                "token-generator exchange served from cache"
            );
        }

        // Now authenticate with the access token
        self.jwt_auth.authenticate(&access_token).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::Server;

    /// Helper to create test config with custom URL
    fn create_test_config(url: String) -> EcmwfTokenGeneratorProviderConfig {
        EcmwfTokenGeneratorProviderConfig {
            name: "TestEcmwfTokenGenerator".to_string(),
            cert_uri: "https://example.com/certs".to_string(),
            client_id: "test_client".to_string(),
            client_secret: "test_secret".to_string(),
            token_generator_url: url,
            realm: "test".to_string(),
        }
    }

    // ========== validate_token_with_generator tests ==========

    #[tokio::test]
    async fn test_validate_token_valid() {
        let mut server = Server::new_async().await;
        let m = server
            .mock("POST", "/validate-token")
            .match_header("content-type", "application/json")
            .match_body(mockito::Matcher::Json(serde_json::json!({
                "token": "valid_token",
                "client_id": "test_client"
            })))
            .with_status(200)
            .with_body(r#"{"active": true}"#)
            .create_async()
            .await;

        let result = validate_token_with_generator(
            create_test_config(server.url()),
            "valid_token".to_string(),
        )
        .await;

        m.assert_async().await;
        assert!(result.is_ok(), "Expected successful validation");
        assert!(*result.unwrap(), "Expected token to be active");
    }

    #[tokio::test]
    async fn test_validate_token_inactive() {
        let mut server = Server::new_async().await;
        server
            .mock("POST", "/validate-token")
            .with_status(200)
            .with_body(r#"{"active": false}"#)
            .create_async()
            .await;

        let result = validate_token_with_generator(
            create_test_config(server.url()),
            "invalid_token".to_string(),
        )
        .await;

        assert!(result.is_ok(), "Request should succeed");
        assert!(!*result.unwrap(), "Expected token to be inactive");
    }

    #[tokio::test]
    async fn test_validate_token_http_error() {
        let mut server = Server::new_async().await;
        server
            .mock("POST", "/validate-token")
            .with_status(500)
            .create_async()
            .await;

        let result =
            validate_token_with_generator(create_test_config(server.url()), "token".to_string())
                .await;

        assert!(result.is_err(), "Expected error on HTTP 500");
    }

    // ========== get_access_token_from_generator tests ==========

    #[tokio::test]
    async fn test_exchange_token_success() {
        let mut server = Server::new_async().await;
        let m = server
            .mock("POST", "/admin/refresh-access-token")
            .match_header("content-type", "application/json")
            .match_body(mockito::Matcher::Json(serde_json::json!({
                "client_id": "test_client",
                "client_secret": "test_secret",
                "refresh_token": "refresh_token_123"
            })))
            .with_status(200)
            .with_body(r#"{"access_token": "new_access_token", "expires_in": 300}"#)
            .create_async()
            .await;

        let result = get_access_token_from_generator(
            create_test_config(server.url()),
            "refresh_token_123".to_string(),
        )
        .await;

        m.assert_async().await;
        assert!(result.is_ok(), "Expected successful token exchange");
        assert_eq!(*result.unwrap(), "new_access_token");
    }

    #[tokio::test]
    async fn test_exchange_token_http_error() {
        let mut server = Server::new_async().await;
        server
            .mock("POST", "/admin/refresh-access-token")
            .with_status(401)
            .create_async()
            .await;

        let result = get_access_token_from_generator(
            create_test_config(server.url()),
            "refresh_token".to_string(),
        )
        .await;

        assert!(result.is_err(), "Expected error on HTTP 401");
    }

    #[tokio::test]
    async fn test_authenticate_fails_when_validation_fails() {
        let mut server = Server::new_async().await;
        server
            .mock("POST", "/validate-token")
            .with_status(200)
            .with_body(r#"{"active": false}"#)
            .create_async()
            .await;

        let config = create_test_config(server.url());
        let provider = EcmwfTokenGeneratorProvider::new(&config);

        let result = provider.authenticate("invalid_token").await;

        assert!(
            result.is_err(),
            "Expected authentication to fail for invalid token"
        );
        assert!(
            result
                .unwrap_err()
                .contains("not valid according to ECMWF Token Generator"),
            "Error should indicate validation failure"
        );
    }
}

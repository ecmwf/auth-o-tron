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
use tracing::{debug, info};

use super::jwt_provider::{JWTAuthConfig, JWTProvider};
use crate::models::user::User;
use crate::providers::Provider;
use crate::utils::cache::log_cache_hit;
use crate::utils::http_client::PROVIDER_HTTP_CLIENT;

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

/// Checks if the given token has the exact `offline_access` scope. Only valid
/// results are cached, so random inactive tokens cannot consume cache entries.
#[cached(time = 120, size = 100_000, result = true, with_cached_flag = true)]
async fn check_offline_access_token(
    config: OpenIDOfflineProviderConfig,
    token: String,
) -> Result<Return<()>, String> {
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
    let resp = PROVIDER_HTTP_CLIENT
        .post(&introspection_url)
        .basic_auth(config.private_client_id, Some(config.private_client_secret))
        .form(&[("token", token)])
        .send()
        .await
        .map_err(|e| format!("Failed to call introspection endpoint: {}", e))?
        .json::<Value>()
        .await
        .map_err(|e| format!("Failed to parse introspection JSON: {}", e))?;

    let active = resp["active"].as_bool().unwrap_or(false);
    let has_offline_access = resp["scope"]
        .as_str()
        .unwrap_or("")
        .split_whitespace()
        .any(|scope| scope == "offline_access");

    if !active || !has_offline_access {
        return Err("Not a valid offline_access token".to_string());
    }

    Ok(Return::new(()))
}

/// Exchanges the offline token for a regular access token using a refresh call.
#[cached(time = 10, size = 100_000, result = true, with_cached_flag = true)]
async fn get_access_token(
    config: OpenIDOfflineProviderConfig,
    refresh_token: String,
) -> Result<Return<String>, String> {
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

    let resp = PROVIDER_HTTP_CLIENT
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

    Ok(Return::new(access_token))
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
        log_cache_hit(
            offline_check.was_cached,
            "providers.openid_offline.introspection.cache.hit",
            |suppressed_count| {
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
            },
        );

        let access_token = get_access_token(self.config.clone(), credentials.to_string()).await?;
        log_cache_hit(
            access_token.was_cached,
            "providers.openid_offline.exchange.cache.hit",
            |suppressed_count| {
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
            },
        );
        self.jwt_auth.authenticate(&access_token).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cached::Cached;
    use mockito::Server;
    use tokio;

    use crate::utils::cache::ATTACKER_KEYED_CACHE_SIZE;

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
        result.expect("offline_access token should be valid");
    }

    /// Inactive tokens are rejected and are not cached.
    #[tokio::test]
    async fn test_check_offline_access_token_invalid() {
        let response_body = r#"{"active": false, "scope": ""}"#;
        let realm = "test";

        let mut server = Server::new_async().await;
        let path = format!("/realms/{}/protocol/openid-connect/token/introspect", realm);
        let m = server
            .mock("POST", path.as_str())
            .expect(2)
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

        let first = check_offline_access_token(config.clone(), "dummy_token".to_string()).await;
        let second = check_offline_access_token(config, "dummy_token".to_string()).await;
        m.assert_async().await;
        assert_eq!(
            first.err().as_deref(),
            Some("Not a valid offline_access token")
        );
        assert_eq!(
            second.err().as_deref(),
            Some("Not a valid offline_access token")
        );
    }

    #[tokio::test]
    async fn test_offline_scope_requires_exact_whitespace_delimited_membership() {
        for scope in ["not_offline_access", "offline_accessory", "offline-access"] {
            let mut server = Server::new_async().await;
            let mock = server
                .mock(
                    "POST",
                    "/realms/test/protocol/openid-connect/token/introspect",
                )
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body(format!(r#"{{"active":true,"scope":"{scope}"}}"#))
                .create_async()
                .await;
            let config = OpenIDOfflineProviderConfig {
                name: "TestOpenID".to_string(),
                cert_uri: String::new(),
                public_client_id: "public".to_string(),
                private_client_id: "private".to_string(),
                private_client_secret: "secret".to_string(),
                iam_url: server.url(),
                realm: "test".to_string(),
            };

            let result = check_offline_access_token(config, scope.to_string()).await;

            mock.assert_async().await;
            assert!(result.is_err(), "scope {scope:?} must not match");
        }

        let mut server = Server::new_async().await;
        let mock = server
            .mock(
                "POST",
                "/realms/test/protocol/openid-connect/token/introspect",
            )
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"active":true,"scope":"read\toffline_access\nwrite"}"#)
            .create_async()
            .await;
        let config = OpenIDOfflineProviderConfig {
            name: "TestOpenID".to_string(),
            cert_uri: String::new(),
            public_client_id: "public".to_string(),
            private_client_id: "private".to_string(),
            private_client_secret: "secret".to_string(),
            iam_url: server.url(),
            realm: "test".to_string(),
        };

        let result = check_offline_access_token(config, "whitespace-token".to_string()).await;

        mock.assert_async().await;
        assert!(result.is_ok());
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
        assert_eq!(*result.unwrap(), "new_access_token".to_string());
    }

    #[tokio::test]
    async fn token_caches_match_shared_capacity_limit() {
        assert_eq!(
            CHECK_OFFLINE_ACCESS_TOKEN.lock().await.cache_capacity(),
            Some(ATTACKER_KEYED_CACHE_SIZE)
        );
        assert_eq!(
            GET_ACCESS_TOKEN.lock().await.cache_capacity(),
            Some(ATTACKER_KEYED_CACHE_SIZE)
        );
    }
}

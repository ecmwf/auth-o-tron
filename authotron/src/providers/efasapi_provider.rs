// (C) Copyright 2024- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

use std::collections::HashMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

use crate::utils::cache::log_cache_hit;
use crate::utils::http_client::PROVIDER_HTTP_CLIENT;
use crate::{models::user::User, providers::Provider};
use cached::Return;
#[allow(unused_imports)]
use cached::proc_macro::cached;

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
    #[serde(default)]
    email: Option<String>,
}

impl EfasApiProvider {
    pub fn new(config: &EFASApiProviderConfig) -> Self {
        info!(
            event_name = "providers.efas_api.initialization",
            event_domain = "providers",
            provider_name = config.name.as_str(),
            realm = config.realm.as_str(),
            "creating EFAS API provider"
        );
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
        log_cache_hit(
            cached_user.was_cached,
            "providers.efas_api.cache.hit",
            |suppressed_count| {
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
            },
        );
        Ok((*cached_user).clone())
    }

    fn get_name(&self) -> &str {
        &self.config.name
    }
}

/// Queries the EFAS auth url
#[cached(time = 60, size = 100_000, result = true, with_cached_flag = true)]
async fn query(uri: String, token: String, realm: String) -> Result<Return<User>, String> {
    let url = uri.clone();

    debug!(
        event_name = "providers.efas_api.query.started",
        event_domain = "providers",
        base_uri = uri.as_str(),
        realm = realm.as_str(),
        "sending EFAS user-details request"
    );
    let response = match PROVIDER_HTTP_CLIENT
        .get(&url)
        .query(&[("token", token.as_str())])
        .send()
        .await
    {
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
        let mut attributes = HashMap::new();
        if let Some(email) = user_info.email {
            attributes.insert("email".to_string(), email);
        }
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
    use cached::Cached;
    use mockito::Server;
    use tokio;

    use crate::utils::cache::ATTACKER_KEYED_CACHE_SIZE;
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
        assert_eq!(user.attributes.len(), 1);
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

    #[tokio::test]
    async fn test_efas_api_provider_percent_encodes_token_query_parameter() {
        for token in ["token&x=y", "token#fragment"] {
            let mut server = Server::new_async().await;
            let mock = server
                .mock("GET", "/")
                .match_query(mockito::Matcher::UrlEncoded(
                    "token".to_string(),
                    token.to_string(),
                ))
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body(r#"{"username":"encoded-user"}"#)
                .create_async()
                .await;

            let result = query(server.url(), token.to_string(), "test".to_string()).await;

            mock.assert_async().await;
            assert_eq!(result.unwrap().username, "encoded-user");
        }
    }

    #[tokio::test]
    async fn query_cache_capacity_matches_shared_limit() {
        assert_eq!(
            QUERY.lock().await.cache_capacity(),
            Some(ATTACKER_KEYED_CACHE_SIZE)
        );
    }
}

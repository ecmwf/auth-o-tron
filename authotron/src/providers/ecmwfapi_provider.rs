// (C) Copyright 2024- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use tracing::{debug, info};

use crate::utils::cache::log_cache_hit;
use crate::utils::http_client::PROVIDER_HTTP_CLIENT;
use crate::{models::user::User, providers::Provider};
use cached::Return;
#[allow(unused_imports)]
use cached::proc_macro::cached;

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
            event_name = "providers.ecmwf_api.initialization",
            event_domain = "providers",
            provider_name = config.name.as_str(),
            realm = config.realm.as_str(),
            "creating ECMWF API provider"
        );
        Self {
            config: config.clone(),
        }
    }
}

#[async_trait::async_trait]
impl Provider for EcmwfApiProvider {
    fn get_type(&self) -> &str {
        "Bearer"
    }

    fn get_realm(&self) -> Option<&str> {
        Some(&self.config.realm)
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
            "providers.ecmwf_api.cache.hit",
            |suppressed_count| {
                debug!(
                    event_name = "providers.ecmwf_api.cache.hit",
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

/// Queries the ECMWF who-am-i endpoint with the provided token, returning a User on success.
#[cached(time = 60, size = 100_000, result = true, with_cached_flag = true)]
async fn query(uri: String, token: String, realm: String) -> Result<Return<User>, String> {
    let url = format!("{}/who-am-i", uri);

    debug!(
        event_name = "providers.ecmwf_api.query.started",
        event_domain = "providers",
        base_uri = uri.as_str(),
        realm = realm.as_str(),
        "sending ECMWF who-am-i request"
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
        let user_info: Value =
            serde_json::from_str(&body).map_err(|e| format!("Error parsing JSON: {}", e))?;

        let username = user_info["uid"].as_str().unwrap_or_default().to_string();
        let email = user_info["email"].as_str().map(|s| s.to_string());
        // The raw API key must not be stored as a user attribute: attributes
        // propagate into JWT claims and identity responses, which would expose the
        // long-lived credential to anyone who can read an issued JWT.
        let mut attributes = HashMap::new();
        if let Some(email) = email {
            attributes.insert("ecmwf-email".to_string(), email);
        }
        Ok(Return::new(User::new(
            realm,
            username,
            None,
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
    use std::sync::mpsc;
    use std::time::Duration;
    use tokio;

    use crate::utils::cache::ATTACKER_KEYED_CACHE_SIZE;

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
        assert!(
            !user.attributes.contains_key("ecmwf-apikey"),
            "the ecmwf-apikey attribute must not be present"
        );
        assert!(
            user.attributes.values().all(|v| !v.contains(token)),
            "the raw API key must not appear in any attribute value"
        );
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

    #[tokio::test]
    async fn test_ecmwf_api_provider_percent_encodes_token_query_parameter() {
        for token in ["token&x=y", "token#fragment"] {
            let mut server = Server::new_async().await;
            let mock = server
                .mock("GET", "/who-am-i")
                .match_query(mockito::Matcher::UrlEncoded(
                    "token".to_string(),
                    token.to_string(),
                ))
                .with_status(200)
                .with_header("content-type", "application/json")
                .with_body(r#"{"uid":"encoded-user"}"#)
                .create_async()
                .await;

            let result = query(server.url(), token.to_string(), "test".to_string()).await;

            mock.assert_async().await;
            assert_eq!(result.unwrap().username, "encoded-user");
        }
    }

    #[tokio::test]
    async fn unrelated_cache_misses_do_not_serialize_upstream_requests() {
        let (slow_started_tx, slow_started_rx) = mpsc::channel();
        let mut slow_server = Server::new_async().await;
        let slow_mock = slow_server
            .mock("GET", "/who-am-i")
            .match_query(mockito::Matcher::UrlEncoded(
                "token".to_string(),
                "slow-token".to_string(),
            ))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_chunked_body(move |writer| {
                slow_started_tx.send(()).map_err(std::io::Error::other)?;
                std::thread::sleep(Duration::from_millis(750));
                writer.write_all(br#"{"uid":"slow-user"}"#)
            })
            .create_async()
            .await;

        let slow_request = tokio::spawn(query(
            slow_server.url(),
            "slow-token".to_string(),
            "test".to_string(),
        ));
        tokio::task::spawn_blocking(move || {
            slow_started_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("slow upstream request should start")
        })
        .await
        .expect("start notification task should finish");

        let mut fast_server = Server::new_async().await;
        let fast_mock = fast_server
            .mock("GET", "/who-am-i")
            .match_query(mockito::Matcher::UrlEncoded(
                "token".to_string(),
                "fast-token".to_string(),
            ))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"uid":"fast-user"}"#)
            .create_async()
            .await;

        let fast_result = tokio::time::timeout(
            Duration::from_millis(250),
            query(
                fast_server.url(),
                "fast-token".to_string(),
                "test".to_string(),
            ),
        )
        .await
        .expect("an unrelated cache miss must not wait for the slow request")
        .expect("fast upstream request should succeed");

        assert_eq!(fast_result.username, "fast-user");
        fast_mock.assert_async().await;
        let slow_result = slow_request
            .await
            .expect("slow request task should finish")
            .expect("slow upstream request should succeed");
        assert_eq!(slow_result.username, "slow-user");
        slow_mock.assert_async().await;
    }

    #[tokio::test]
    async fn query_cache_capacity_matches_shared_limit() {
        assert_eq!(
            QUERY.lock().await.cache_capacity(),
            Some(ATTACKER_KEYED_CACHE_SIZE)
        );
    }
}

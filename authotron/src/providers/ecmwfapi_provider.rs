// (C) Copyright 2024- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

use std::collections::HashMap;
use std::sync::LazyLock;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Duration;
use tracing::{debug, info};

use crate::utils::log_throttle::should_emit;
use crate::{models::user::User, providers::Provider};
use cached::Return;
#[allow(unused_imports)]
use cached::proc_macro::cached;
use reqwest;
const CACHE_HIT_LOG_WINDOW: Duration = Duration::from_secs(30);
const BROWSER_BODY_LIMIT: usize = 64 * 1024;
const BROWSER_UID_LIMIT: usize = 256;
const BROWSER_EMAIL_LIMIT: usize = 320;

/// Shared client for who-am-i calls. Reusing one client (and its connection
/// pool) avoids a fresh TCP+TLS handshake on every cache-miss, which under load
/// churned connections and amplified pressure on the upstream ECMWF API.
static HTTP_CLIENT: LazyLock<reqwest::Client> = LazyLock::new(reqwest::Client::new);

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
    /// Verify with browser body/identity bounds, without retaining credentials
    /// in the CLI query cache. The caller supplies the browser client policy.
    pub async fn authenticate_uncached(
        &self,
        client: &reqwest::Client,
        credential: &str,
    ) -> Result<User, String> {
        verify(
            client,
            &self.config.uri,
            credential,
            &self.config.realm,
            true,
        )
        .await
    }

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
        if cached_user.was_cached
            && let Some(suppressed_count) =
                should_emit("providers.ecmwf_api.cache.hit", CACHE_HIT_LOG_WINDOW)
        {
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
        }
        Ok((*cached_user).clone())
    }

    fn get_name(&self) -> &str {
        &self.config.name
    }
}

/// Queries the ECMWF who-am-i endpoint with the provided token, returning a User on success.
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
    verify(&HTTP_CLIENT, &uri, &token, &realm, false)
        .await
        .map(Return::new)
}

async fn verify(
    client: &reqwest::Client,
    uri: &str,
    token: &str,
    realm: &str,
    browser_limited: bool,
) -> Result<User, String> {
    let url = format!("{}/who-am-i", uri.trim_end_matches('/'));

    debug!(
        event_name = "providers.ecmwf_api.query.started",
        event_domain = "providers",
        base_uri = uri,
        realm = realm,
        "sending ECMWF who-am-i request"
    );
    let mut response = match client.get(&url).query(&[("token", &token)]).send().await {
        Ok(r) => r,
        Err(e) => return Err(format!("Error sending request: {}", e.without_url())),
    };

    if response.status().is_success() {
        let body = if browser_limited {
            if response
                .content_length()
                .is_some_and(|len| len > BROWSER_BODY_LIMIT as u64)
            {
                return Err("Invalid who-am-i response: body too large".to_string());
            }
            let mut bytes = Vec::new();
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|e| format!("Error reading response body: {}", e.without_url()))?
            {
                if chunk.len() > BROWSER_BODY_LIMIT - bytes.len() {
                    return Err("Invalid who-am-i response: body too large".to_string());
                }
                bytes.extend_from_slice(&chunk);
            }
            bytes
        } else {
            response
                .text()
                .await
                .map_err(|e| format!("Error reading response body: {}", e.without_url()))?
                .into_bytes()
        };
        // Do not include parser diagnostics: upstream bodies can echo credentials.
        let user_info: Value = serde_json::from_slice(&body)
            .map_err(|_| "Error parsing JSON: invalid who-am-i response".to_string())?;

        // Valid: {"uid":"user_ecmwf"}. Invalid: {"uid":" "} or {"error":"denied"}.
        // Preserve the upstream identity verbatim; trimming only detects blank UIDs.
        let username = user_info
            .get("uid")
            .and_then(Value::as_str)
            .filter(|uid| !uid.trim().is_empty() && !uid.chars().any(char::is_control))
            .filter(|_| user_info.get("error").is_none())
            .ok_or_else(|| "Invalid who-am-i response: expected a nonempty UID".to_string())?;
        let email = user_info["email"].as_str();
        if browser_limited
            && (username.len() > BROWSER_UID_LIMIT
                || email.is_some_and(|email| email.len() > BROWSER_EMAIL_LIMIT))
        {
            return Err("Invalid who-am-i response: identity too large".to_string());
        }
        let username = username.to_string();
        // The raw API key must not be stored as a user attribute: attributes
        // propagate into JWT claims, the token store, and identity responses,
        // which would expose the long-lived credential to anyone who can read
        // an issued JWT.
        let mut attributes = HashMap::new();
        if let Some(email) = email {
            attributes.insert("ecmwf-email".to_string(), email.to_string());
        }
        Ok(User::new(
            realm.to_owned(),
            username,
            None,
            Some(attributes),
            None,
            None,
        ))
    } else if response.status() == 403 {
        Err("Invalid API token".to_string())
    } else {
        Err(format!("Unexpected status code: {}", response.status()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::{Matcher, Server};

    // Public, synthetic fixtures only; no ECMWF credentials or local configuration.
    const TOKEN: &str = "public-fixture-api-key";
    const REALM: &str = "test";

    fn provider(uri: String) -> EcmwfApiProvider {
        EcmwfApiProvider::new(&EcmwfApiProviderConfig {
            uri,
            realm: REALM.to_string(),
            name: "mock-ecmwf".to_string(),
        })
    }

    async fn authenticate_response(status: usize, body: &str) -> Result<User, String> {
        let mut server = Server::new_async().await;
        let mock = server
            .mock("GET", "/who-am-i")
            .match_query(Matcher::UrlEncoded("token".to_string(), TOKEN.to_string()))
            .with_status(status)
            .with_header("content-type", "application/json")
            .with_body(body)
            .create_async()
            .await;
        let result = provider(server.url()).authenticate(TOKEN).await;
        mock.assert_async().await;
        result
    }

    /// Test that a valid token returns a User with the expected UID.
    #[tokio::test]
    async fn test_ecmwf_api_provider_success() {
        let body = format!(
            r#"{{"uid":"user_ecmwf","email":"user@example.test","token":"{TOKEN}","ecmwf-apikey":"{TOKEN}"}}"#
        );
        let user = authenticate_response(200, &body).await.unwrap();
        assert_eq!(user.username, "user_ecmwf");
        assert_eq!(user.realm, REALM);
        assert_eq!(
            user.attributes,
            HashMap::from([("ecmwf-email".to_string(), "user@example.test".to_string())])
        );
        assert!(!serde_json::to_string(&user).unwrap().contains(TOKEN));
    }

    /// Test that an invalid token (simulated with a 403 response) returns an error.
    #[tokio::test]
    async fn test_ecmwf_api_provider_invalid_token() {
        assert_eq!(
            authenticate_response(403, TOKEN).await.unwrap_err(),
            "Invalid API token"
        );
    }

    #[tokio::test]
    async fn test_ecmwf_api_provider_malformed_json() {
        let body = format!(r#"{{"uid":"{TOKEN}""#);
        let error = authenticate_response(200, &body).await.unwrap_err();
        assert_eq!(error, "Error parsing JSON: invalid who-am-i response");
        assert!(!error.contains(TOKEN));
    }

    #[tokio::test]
    async fn test_ecmwf_api_provider_invalid_identity_responses() {
        for body in [
            r#"{}"#,
            r#"{"uid":null}"#,
            r#"{"uid":123}"#,
            r#"{"uid":""}"#,
            r#"{"uid":"   "}"#,
            r#"{"uid":"user\nname"}"#,
            r#"[{"uid":"user_ecmwf"}]"#,
            r#"{"error":"denied"}"#,
            r#"{"uid":"user_ecmwf","error":"denied"}"#,
        ] {
            let error = authenticate_response(200, body).await.unwrap_err();
            assert_eq!(error, "Invalid who-am-i response: expected a nonempty UID");
            assert!(!error.contains(TOKEN));
        }
    }

    #[tokio::test]
    async fn test_ecmwf_api_provider_preserves_uid_without_email() {
        let user = authenticate_response(200, r#"{"uid":" user_ecmwf "}"#)
            .await
            .unwrap();
        assert_eq!(user.username, " user_ecmwf ");
        assert!(user.attributes.is_empty());
    }

    #[tokio::test]
    async fn test_ecmwf_api_provider_encoded_query_and_trailing_slash() {
        const SPECIAL_TOKEN: &str = "public&+#=?fixture";
        let mut server = Server::new_async().await;
        let mock = server
            .mock("GET", "/api/who-am-i")
            .match_query(Matcher::Exact(
                "token=public%26%2B%23%3D%3Ffixture".to_string(),
            ))
            .with_status(200)
            .with_body(r#"{"uid":"user_ecmwf"}"#)
            .create_async()
            .await;
        let user = provider(format!("{}/api/", server.url()))
            .authenticate(SPECIAL_TOKEN)
            .await
            .unwrap();
        mock.assert_async().await;
        assert_eq!(user.username, "user_ecmwf");
        assert!(
            !serde_json::to_string(&user)
                .unwrap()
                .contains(SPECIAL_TOKEN)
        );
    }

    #[tokio::test]
    async fn test_ecmwf_api_provider_transport_error_redacts_token() {
        // Reserve a unique loopback port, then close it to exercise a send failure.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let error = provider(format!("http://{address}"))
            .authenticate(TOKEN)
            .await
            .unwrap_err();
        assert!(error.starts_with("Error sending request:"));
        assert!(!error.contains(TOKEN));
        assert!(!error.contains("token="));
        assert!(!error.contains("/who-am-i"));
    }

    #[tokio::test]
    async fn test_ecmwf_api_provider_unexpected_status() {
        for status in [400, 401, 500] {
            let error = authenticate_response(status, TOKEN).await.unwrap_err();
            assert!(error.starts_with(&format!("Unexpected status code: {status}")));
            assert!(!error.contains(TOKEN));
        }
    }

    #[tokio::test]
    async fn browser_identity_limits_leave_cli_behavior_intact() {
        for body in [
            serde_json::json!({"uid": "u".repeat(BROWSER_UID_LIMIT + 1)}).to_string(),
            serde_json::json!({"uid": "public-user", "email": "e".repeat(BROWSER_EMAIL_LIMIT + 1)})
                .to_string(),
        ] {
            let mut server = Server::new_async().await;
            let mock = server
                .mock("GET", "/who-am-i")
                .match_query(Matcher::Any)
                .with_body(body)
                .expect(2)
                .create_async()
                .await;
            let provider = provider(server.url());
            let error = provider
                .authenticate_uncached(&reqwest::Client::new(), TOKEN)
                .await
                .unwrap_err();
            assert_eq!(error, "Invalid who-am-i response: identity too large");
            assert!(!error.contains(TOKEN));
            assert!(provider.authenticate(TOKEN).await.is_ok());
            mock.assert_async().await;
        }
    }

    #[tokio::test]
    async fn browser_bounds_bodies_with_and_without_content_length() {
        for chunked in [false, true] {
            let mut server = Server::new_async().await;
            let mock = server.mock("GET", "/who-am-i").match_query(Matcher::Any);
            let mock = if chunked {
                mock.with_chunked_body(|writer| {
                    for _ in 0..65 {
                        writer.write_all(&[b' '; 1024])?;
                    }
                    Ok(())
                })
            } else {
                mock.with_body(" ".repeat(BROWSER_BODY_LIMIT + 1))
            }
            .create_async()
            .await;
            let error = provider(server.url())
                .authenticate_uncached(&reqwest::Client::new(), TOKEN)
                .await
                .unwrap_err();
            assert_eq!(error, "Invalid who-am-i response: body too large");
            assert!(!error.contains(TOKEN));
            mock.assert_async().await;
        }
    }

    #[tokio::test]
    async fn browser_accepts_identity_byte_limits_verbatim() {
        let mut server = Server::new_async().await;
        let uid = format!(" {} ", "u".repeat(BROWSER_UID_LIMIT - 2));
        let email = "e".repeat(BROWSER_EMAIL_LIMIT);
        let mock = server
            .mock("GET", "/who-am-i")
            .match_query(Matcher::Any)
            .with_body(serde_json::json!({"uid": uid, "email": email}).to_string())
            .create_async()
            .await;
        let user = provider(server.url())
            .authenticate_uncached(&reqwest::Client::new(), TOKEN)
            .await
            .unwrap();
        assert_eq!(user.username, uid);
        assert_eq!(user.attributes["ecmwf-email"], email);
        mock.assert_async().await;
    }
}

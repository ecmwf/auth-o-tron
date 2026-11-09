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
use tracing::{debug, error, info};

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
    /// Client the offline tokens were issued to; used for the token exchange.
    pub public_client_id: String,
    /// Confidential client used for introspection. Not needed with `skip_introspection`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_client_secret: Option<String>,
    pub iam_url: String,
    /// Realm given to authenticated users.
    pub realm: String,
    /// Realm on the identity server. Defaults to `realm`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iam_realm: Option<String>,
    /// Exchange the token without introspecting it first. Use only when no
    /// confidential client is available: any refresh token of the public client
    /// is then accepted, not only offline tokens.
    #[serde(default)]
    pub skip_introspection: bool,
}

impl OpenIDOfflineProviderConfig {
    fn iam_realm(&self) -> &str {
        self.iam_realm.as_deref().unwrap_or(&self.realm)
    }

    /// The private client credentials, when both are set and non-empty.
    fn private_client(&self) -> Option<(&str, &str)> {
        match (
            self.private_client_id.as_deref(),
            self.private_client_secret.as_deref(),
        ) {
            (Some(id), Some(secret)) if !id.is_empty() && !secret.is_empty() => Some((id, secret)),
            _ => None,
        }
    }
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
            iam_realm = config.iam_realm(),
            skip_introspection = config.skip_introspection,
            "creating OpenID offline provider"
        );
        if !config.skip_introspection && config.private_client().is_none() {
            error!(
                event_name = "providers.openid_offline.config.invalid",
                event_domain = "providers",
                provider_name = config.name.as_str(),
                "introspection needs private_client_id and private_client_secret; \
                 every token will be rejected"
            );
        }

        // The nested JWT auth will handle the final token validation
        let jwt_auth = JWTProvider::new(&JWTAuthConfig {
            cert_uri: config.cert_uri.clone(),
            realm: config.realm.clone(),
            name: config.name.clone(),
            iam_realm: config.iam_realm().to_string(),
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

    let (client_id, client_secret) = config.private_client().ok_or_else(|| {
        "Introspection needs private_client_id and private_client_secret".to_string()
    })?;
    let introspection_url = format!(
        "{}/realms/{}/protocol/openid-connect/token/introspect",
        config.iam_url,
        config.iam_realm()
    );
    let resp = HTTP_CLIENT
        .post(&introspection_url)
        .basic_auth(client_id, Some(client_secret))
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

    Ok(Return::new(active && scope.contains("offline_access")))
}

/// Exchanges the offline token for a regular access token using a refresh call.
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
        config.iam_url,
        config.iam_realm()
    );

    // Without a private client, the public client alone exchanges the token.
    let mut request = HTTP_CLIENT.post(&token_endpoint).form(&refresh_data);
    if let Some((client_id, client_secret)) = config.private_client() {
        request = request.basic_auth(client_id, Some(client_secret));
    }
    let resp = request
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
        if !self.config.skip_introspection {
            self.check_offline_token(credentials).await?;
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
        self.jwt_auth.authenticate(&access_token).await
    }
}

impl OpenIDOfflineProvider {
    /// Introspects the token and fails unless it is an active offline token.
    async fn check_offline_token(&self, credentials: &str) -> Result<(), String> {
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
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use mockito::{Matcher, Server, ServerGuard};
    use serde_json::json;
    use tokio;

    const INTROSPECT_PATH: &str = "/realms/test/protocol/openid-connect/token/introspect";
    const TOKEN_PATH: &str = "/realms/test/protocol/openid-connect/token";
    const JWKS_PATH: &str = "/certs";

    fn test_config(server: &ServerGuard) -> OpenIDOfflineProviderConfig {
        OpenIDOfflineProviderConfig {
            name: "TestOpenID".to_string(),
            cert_uri: format!("{}{}", server.url(), JWKS_PATH),
            public_client_id: "public".to_string(),
            private_client_id: Some("private".to_string()),
            private_client_secret: Some("secret".to_string()),
            iam_url: server.url(),
            realm: "test".to_string(),
            iam_realm: None,
            skip_introspection: false,
        }
    }

    /// No confidential client, and a user realm different from the identity server realm.
    fn public_only_config(server: &ServerGuard) -> OpenIDOfflineProviderConfig {
        OpenIDOfflineProviderConfig {
            private_client_id: None,
            private_client_secret: None,
            realm: "mch".to_string(),
            iam_realm: Some("test".to_string()),
            skip_introspection: true,
            ..test_config(server)
        }
    }

    async fn mock_introspection(server: &mut ServerGuard, body: &str) -> mockito::Mock {
        server
            .mock("POST", INTROSPECT_PATH)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(body)
            .create_async()
            .await
    }

    fn signed_access_token() -> String {
        let claims = json!({
            "sub": "f3b0c4a2",
            "preferred_username": "jdoe",
            "scope": "openid offline_access",
            "exp": 4102444800usize,
            "realm_access": {"roles": ["polytope_read"]}
        });
        let mut header = Header::new(Algorithm::HS512);
        header.kid = Some("testkid".to_string());
        encode(&header, &claims, &EncodingKey::from_secret(b"secret")).unwrap()
    }

    #[tokio::test]
    async fn test_check_offline_access_token_valid() {
        let mut server = Server::new_async().await;
        let m = mock_introspection(
            &mut server,
            r#"{"active": true, "scope": "offline_access other_scope"}"#,
        )
        .await;

        let result = check_offline_access_token(test_config(&server), "dummy".to_string()).await;
        m.assert_async().await;
        assert!(*result.unwrap());
    }

    #[tokio::test]
    async fn test_check_offline_access_token_invalid() {
        let mut server = Server::new_async().await;
        let m = mock_introspection(&mut server, r#"{"active": false, "scope": ""}"#).await;

        let result = check_offline_access_token(test_config(&server), "dummy".to_string()).await;
        m.assert_async().await;
        assert!(!*result.unwrap());
    }

    #[tokio::test]
    async fn test_check_offline_access_token_needs_private_client() {
        let mut server = Server::new_async().await;
        let m = server
            .mock("POST", INTROSPECT_PATH)
            .expect(0)
            .create_async()
            .await;
        let config = OpenIDOfflineProviderConfig {
            private_client_id: Some(String::new()),
            private_client_secret: Some(String::new()),
            ..test_config(&server)
        };

        let result = check_offline_access_token(config, "dummy".to_string()).await;
        m.assert_async().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_get_access_token_success() {
        let mut server = Server::new_async().await;
        let m = server
            .mock("POST", TOKEN_PATH)
            .match_header("authorization", Matcher::Regex("^Basic ".to_string()))
            .match_body(Matcher::UrlEncoded(
                "client_id".to_string(),
                "public".to_string(),
            ))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"access_token": "new_access_token"}"#)
            .create_async()
            .await;

        let result = get_access_token(test_config(&server), "dummy".to_string()).await;
        m.assert_async().await;
        assert_eq!(*result.unwrap(), "new_access_token".to_string());
    }

    /// Without a private client the exchange uses the public client only, and
    /// the identity server realm is used in the URL.
    #[tokio::test]
    async fn test_get_access_token_public_client_only() {
        let mut server = Server::new_async().await;
        let m = server
            .mock("POST", TOKEN_PATH)
            .match_header("authorization", Matcher::Missing)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"access_token": "new_access_token"}"#)
            .create_async()
            .await;

        let result = get_access_token(public_only_config(&server), "dummy".to_string()).await;
        m.assert_async().await;
        assert_eq!(*result.unwrap(), "new_access_token".to_string());
    }

    #[tokio::test]
    async fn test_authenticate_without_introspection() {
        let mut server = Server::new_async().await;
        let introspect = server
            .mock("POST", INTROSPECT_PATH)
            .expect(0)
            .create_async()
            .await;
        let jwks = server
            .mock("GET", JWKS_PATH)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"keys": [{"kty": "oct", "k": "c2VjcmV0", "alg": "HS512", "kid": "testkid"}]}"#,
            )
            .create_async()
            .await;
        let token = server
            .mock("POST", TOKEN_PATH)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!({"access_token": signed_access_token()}).to_string())
            .create_async()
            .await;

        let provider = OpenIDOfflineProvider::new(&public_only_config(&server));
        let user = provider.authenticate("offline-token").await.unwrap();
        introspect.assert_async().await;
        jwks.assert_async().await;
        token.assert_async().await;

        assert_eq!(user.realm, "mch");
        assert_eq!(user.username, "jdoe");
        assert_eq!(user.roles, vec!["polytope_read"]);
    }

    /// With introspection on, an inactive token is never exchanged.
    #[tokio::test]
    async fn test_authenticate_introspection_rejects() {
        let mut server = Server::new_async().await;
        let introspect = mock_introspection(&mut server, r#"{"active": false}"#).await;
        let token = server
            .mock("POST", TOKEN_PATH)
            .expect(0)
            .create_async()
            .await;

        let provider = OpenIDOfflineProvider::new(&test_config(&server));
        assert!(provider.authenticate("offline-token").await.is_err());
        introspect.assert_async().await;
        token.assert_async().await;
    }

    #[test]
    fn test_config_defaults_and_empty_private_client() {
        let config: OpenIDOfflineProviderConfig = serde_json::from_value(json!({
            "name": "oid",
            "cert_uri": "https://iam.example.com/certs",
            "public_client_id": "api-token",
            "private_client_id": "",
            "iam_url": "https://iam.example.com",
            "realm": "mch"
        }))
        .unwrap();
        assert!(!config.skip_introspection);
        assert_eq!(config.iam_realm(), "mch");
        assert!(config.private_client().is_none());
    }
}

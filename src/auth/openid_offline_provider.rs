use cached::proc_macro::cached;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{debug, info};

use super::jwt_provider::{JWTAuthConfig, JWTProvider};
use super::Provider;
use crate::models::User;

/// Config for an OpenID provider that also supports offline tokens.
#[derive(Deserialize, Debug, Serialize, JsonSchema, Hash, Clone, PartialEq, Eq)]
pub struct OpenIDOfflineProviderConfig {
    pub name: String,
    pub cert_uri: String,
    pub public_client_id: String,
    pub private_client_id: String,
    pub private_client_secret: String,
    pub iam_url: String,
    pub iam_realm: String,
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
            config.iam_realm, config.name
        );

        // The nested JWT auth will handle the final token validation
        let jwt_auth = JWTProvider::new(&JWTAuthConfig {
            cert_uri: config.cert_uri.clone(),
            realm: config.iam_realm.clone(),
            name: config.name.clone(),
            iam_realm: config.iam_realm.clone(),
        });

        Self {
            config: config.clone(),
            jwt_auth,
        }
    }
}

/// Checks if the given token has "offline_access" scope. If valid, returns true.
#[cached(time = 120, sync_writes = true)]
async fn check_offline_access_token(
    config: OpenIDOfflineProviderConfig,
    token: String,
) -> Result<bool, String> {
    debug!(
        "Checking offline access token at realm='{}'",
        config.iam_realm
    );

    let introspection_url = format!(
        "{}/realms/{}/protocol/openid-connect/token/introspect",
        config.iam_url, config.iam_realm
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
#[cached(time = 10, sync_writes = true)]
async fn get_access_token(
    config: OpenIDOfflineProviderConfig,
    refresh_token: String,
) -> Result<String, String> {
    debug!(
        "Exchanging offline token for an online access token at realm='{}'",
        config.iam_realm
    );

    let refresh_data = [
        ("client_id", config.public_client_id.as_str()),
        ("grant_type", "refresh_token"),
        ("refresh_token", &refresh_token),
    ];
    let token_endpoint = format!(
        "{}/realms/{}/protocol/openid-connect/token",
        config.iam_url, config.iam_realm
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

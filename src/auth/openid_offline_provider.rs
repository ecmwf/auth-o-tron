use cached::proc_macro::cached;
use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;

use crate::models::User;

use super::jwt_provider::JWTAuthConfig;
use super::jwt_provider::JWTProvider;
use super::Provider;

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

pub struct OpenIDOfflineProvider {
    config: OpenIDOfflineProviderConfig,
    jwt_auth: JWTProvider,
}

impl OpenIDOfflineProvider {
    pub fn new(config: &OpenIDOfflineProviderConfig) -> Self {
        // nested JWT auth will do the validation on the final access token
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

#[cached(time = 120, sync_writes = true)]
async fn check_offline_access_token(
    config: OpenIDOfflineProviderConfig,
    token: String,
) -> Result<bool, String> {
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
        .map_err(|e| e.to_string())?
        .json::<Value>()
        .await
        .map_err(|e| e.to_string())?;

    Ok(resp["active"].as_bool().unwrap_or(false) && resp["token_type"] == "Offline")
}

#[cached(time = 10, sync_writes = true)]
async fn get_access_token(
    config: OpenIDOfflineProviderConfig,
    refresh_token: String,
) -> Result<String, String> {
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
        .form(&refresh_data)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    let json_value = resp.json::<Value>().await.map_err(|e| e.to_string())?;

    let access_token = json_value
        .get("access_token")
        .and_then(|token| token.as_str())
        .ok_or_else(|| "failed to retrieve access token")?
        .to_string();

    Ok(access_token.to_string())
}

#[async_trait::async_trait]
impl Provider for OpenIDOfflineProvider {
    fn get_type(&self) -> &str {
        "Bearer"
    }

    fn get_name(&self) -> &str {
        self.config.name.as_str()
    }

    async fn authenticate(&self, credentials: &str) -> Result<User, String> {
        if !check_offline_access_token(self.config.clone(), credentials.to_string()).await? {
            return Err("not a valid offline_access token".into());
        }

        let access_token = get_access_token(self.config.clone(), credentials.to_string()).await?;

        self.jwt_auth.authenticate(&access_token).await
    }
}

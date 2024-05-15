use serde::Deserialize;
use serde_json::Value;

use super::User;
use cached::proc_macro::cached;
use inline_colorization::*;

// --- Config

#[derive(Deserialize, Debug, Clone)]
pub struct EcmwfApiProviderConfig {
    pub uri: String,
    pub realm: String,
    pub name: String,
}

// --- Provider

pub struct EcmwfApiProvider {
    pub config: EcmwfApiProviderConfig,
}

impl EcmwfApiProvider {
    pub fn new(config: &EcmwfApiProviderConfig) -> Self {
        println!("  🔑 Creating {style_bold}{color_cyan}EcmwfApiAuth{style_reset}{color_reset} for realm {}", config.realm);
        Self { config: config.clone() }
    }
}

#[async_trait::async_trait]
impl super::Provider for EcmwfApiProvider {
    async fn authenticate(&self, token: &str) -> Result<User, String> {
        query(
            self.config.uri.to_string(),
            token.to_string(),
            self.config.realm.to_string(),
        )
        .await
    }

    fn get_name(&self) -> &str {
        &self.config.name
    }

    fn get_type(&self) -> &str {
        "Bearer"
    }
}

#[cached(time = 60, sync_writes = true)]
async fn query(uri: String, token: String, realm: String) -> Result<User, String> {
    let client = reqwest::Client::new();
    let url = format!("{}/who-am-i?token={}", uri, token);
    let res = client.get(&url).send().await;
    match res {
        Ok(response) if response.status().is_success() => {
            let body = response.text().await.unwrap();
            let user_info: Value = serde_json::from_str(&body).unwrap();
            let username = user_info["uid"].as_str().unwrap_or_default().to_string();

            let user = Ok(User::new(realm, username, None, None, None, None));
            user
        }
        Ok(response) if response.status() == 403 => Err(format!("invalid API token")),
        Ok(response) => Err(format!("unexpected status code: {}", response.status())),
        Err(e) => Err(format!("error sending request: {}", e)),
    }
}

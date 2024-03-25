use serde_json::Value;

use super::User;

pub struct EcmwfApiAuth {
    pub endpoint: String,
}

impl EcmwfApiAuth {
    pub fn new(endpoint: String) -> Self {
        println!("Creating EcmwfApiAuth with endpoint: {}", endpoint);
        Self { endpoint }
    }

    pub async fn authenticate(&self, token: &str) -> Option<User> {
        println!("Authenticating bearer token with ECMWF API: {}", token);
        println!("Endpoint: {}", self.endpoint);
        let client = reqwest::Client::new();
        let url = format!("{}/who-am-i?token={}", self.endpoint, token);

        let res = client.get(&url).send().await;

        match res {
            Ok(response) if response.status().is_success() => {
                let body = response.text().await.ok()?;
                println!("Raw response body: {}", body);
                let user_info: Value = serde_json::from_str(&body).ok()?;
                let username = user_info["uid"].as_str().unwrap_or_default().to_string();
                Some(User {
                    username,
                    realm: "ecmwf".to_string(),
                })
            }
            Ok(response) => {
                println!("Non-success status code received: {}", response.status());
                None
            }
            Err(e) => {
                println!("Error sending request: {}", e);
                None
            }
        }
    }
}

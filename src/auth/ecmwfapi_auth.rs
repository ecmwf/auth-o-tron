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
    
        let res = client.get(&url).send().await.ok()?;
    
        if res.status().is_success() {
            // let user_info = res.json::<User>().await?;
            None
        } else {
            None
        }
    }
}


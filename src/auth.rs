pub mod ecmwfapi_auth;
use crate::auth::ecmwfapi_auth::EcmwfApiAuth;

pub struct Auth {
    pub handlers: Vec<AuthHandler>,
}


pub struct User {
    pub username: String,
    pub realm: String,

}

pub enum AuthHandler {
    EcmwfApiAuth(EcmwfApiAuth),
    // Add other authentication handlers here
}

impl AuthHandler {
    pub async fn authenticate(&self, credentials: &str) -> Option<User> {
        match self {
            AuthHandler::EcmwfApiAuth(handler) => handler.authenticate(credentials).await,
        }
    }
}

impl Auth {
    pub fn new() -> Self {
        Self {
            handlers: vec![
                AuthHandler::EcmwfApiAuth(EcmwfApiAuth::new("https://api.ecmwf.int".to_string())),
                // Add other handlers as needed
            ],
        }
    }

    pub async fn authenticate(&self, auth_header: &str) -> Option<User> {
        let parts: Vec<&str> = auth_header.split_whitespace().collect();
        
        if parts.len() != 2 {
            return None;
        }

        let auth_type = parts[0];
        let auth_credentials = parts[1];

        // Example of handling bearer authentication
        if auth_type == "Bearer" {
            for handler in &self.handlers {
                if let Some(user) = handler.authenticate(auth_credentials).await {
                    return Some(user);
                }
            }
        }

        None
    }
}
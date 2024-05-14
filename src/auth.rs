pub mod ecmwfapi_auth;
pub mod jwt_auth;

use serde::Deserialize;

use crate::auth::ecmwfapi_auth::EcmwfApiAuthConfig;
use crate::auth::ecmwfapi_auth::EcmwfApiAuth;
use crate::auth::jwt_auth::JWTAuthConfig;
use crate::auth::jwt_auth::JWTAuth;
use crate::models::User;
use futures::future::join_all;

use inline_colorization::*;

// --- Config

#[derive(Deserialize, Debug)]
#[serde(tag = "type")]
pub enum AuthHandlerConfig {
    
    #[serde(rename = "ecmwf-api")]
    EcmwfApiAuthConfig(EcmwfApiAuthConfig),
    
    #[serde(rename = "jwt")]
    JWTAuthConfig(JWTAuthConfig),
    
}

// --- Handlers

pub enum AuthHandler {
    EcmwfApiAuth(EcmwfApiAuth),
    JWTAuth(JWTAuth),
}

impl AuthHandler {

    pub fn new(config: AuthHandlerConfig) -> Self {
        match config {
            AuthHandlerConfig::EcmwfApiAuthConfig(config) => {
                let handler = EcmwfApiAuth::new(config);
                AuthHandler::EcmwfApiAuth(handler)
            }
            AuthHandlerConfig::JWTAuthConfig(config) => {
                let handler = JWTAuth::new(config);
                AuthHandler::JWTAuth(handler)
            }
        }
    }

    pub fn get_name(&self) -> &str {
        match self {
            AuthHandler::EcmwfApiAuth(handler) => &handler.config.realm,
            AuthHandler::JWTAuth(handler) => &handler.config.realm,
        }
    }

    pub async fn authenticate(&self, credentials: &str) -> Result<User, String> {
        match self {
            AuthHandler::EcmwfApiAuth(handler) => handler.authenticate(credentials).await,
            AuthHandler::JWTAuth(handler) => handler.authenticate(credentials).await,
        }
    }
}

// --- 

pub struct Auth {
    pub handlers: Vec<AuthHandler>,
}


impl Auth {
    pub fn new(config: Vec<AuthHandlerConfig>) -> Self {

        println!("{color_magenta}{style_bold}Creating auth handlers...{color_reset}{style_reset}");

        let handlers = config.into_iter().map(AuthHandler::new).collect();
        Auth { handlers }
    }

    pub async fn authenticate(&self, auth_header: &str, ip: &str) -> Option<User> {
        let parts: Vec<&str> = auth_header.split_whitespace().collect();

        if parts.len() != 2 {
            return None;
        }

        let auth_type = parts[0];
        let auth_credentials = parts[1];
        
        let mut first: Option<User> = None;

        println!("🔐 Authenticating with {style_bold}{}{style_reset} header from {}...", auth_type, ip);

        // Example of handling bearer authentication
        if auth_type == "Bearer" {

            let futures: Vec<_> = self.handlers.iter().map(|handler| handler.authenticate(auth_credentials)).collect();
            let results = join_all(futures).await;


            for (handler, result) in self.handlers.iter().zip(results) {

                match result {
                    Ok(user) => {
                        println!("  🟢 {style_bold}{}{style_reset} authentication succeeded", handler.get_name());
                        first = Some(user);
                    }
                    Err(e) => {
                        println!("  🟠 {style_bold}{}{style_reset} authentication failed ({})", handler.get_name(), e);
                    }
                }
            }

        }

        match first {
            Some(ref user) => {
                println!("✅ Authenticated user: {:?}", user);
            }
            None => {
                println!("❌ No provider could authenticate the user.");
            }
        }

        first

    }
}

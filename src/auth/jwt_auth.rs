use std::error::Error;

use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;

use super::User;
use jsonwebtoken::decode;
use jsonwebtoken::decode_header;
use jsonwebtoken::Algorithm;
use jsonwebtoken::DecodingKey;
use jsonwebtoken::Validation;
use inline_colorization::*;

// --- Config

#[derive(Deserialize, Debug)]
pub struct JWTAuthConfig {
    pub cert_uri: String,
    pub realm: String,
}

// --- Handler

pub struct JWTAuth {
    pub config: JWTAuthConfig,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    roles: Vec<String>,
}

impl JWTAuth {
    pub fn new(config: JWTAuthConfig) -> Self {
        println!("  🔑 Creating {style_bold}{color_cyan}JWTAuth{style_reset}{color_reset} for realm {}", config.realm);
        Self {
            config,
        }
    }

    pub async fn authenticate(&self, token: &str) -> Result<User, String> {

        return Err("not implemented".to_string());

        // let certs = self.get_certs().await.ok()?;
        // let header = decode_header(token).ok()?;
        // let alg = match header.alg {
        //     Algorithm::RS256 => "RS256",
        //     _ => return None,
        // };

        // let _decoded = decode::<Claims>(
        //     token,
        //     &DecodingKey::from_rsa_pem(certs.as_bytes()).ok()?,
        //     &Validation::new(alg.parse().ok()?),
        // )
        // .ok()?;

        // let user = User::new(
        //     self.config.realm.to_string(),
        //     _decoded.claims.sub,
        //     Some(_decoded.claims.roles),
        //     None,
        //     None,
        //     None
        // );

        // Some(user)
    }

    async fn get_certs(&self) -> Result<String, Box<dyn Error>> {
        let res: Value = reqwest::get(&self.config.cert_uri)
            .await?
            .json()
            .await?;
        Ok(res.to_string())
    }
}

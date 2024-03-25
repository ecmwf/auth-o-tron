use std::error::Error;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::User;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};

pub struct JWTAuth {
    pub certificate_endpoint: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
}

impl JWTAuth {
    pub fn new(certificate_endpoint: String) -> Self {
        println!("Creating JWTAuth with endpoint: {}", certificate_endpoint);
        Self {
            certificate_endpoint,
        }
    }

    pub async fn authenticate(&self, token: &str) -> Option<User> {
        let certs = self.get_certs().await.ok()?;
        let header = decode_header(token).ok()?;
        let alg = match header.alg {
            Algorithm::RS256 => "RS256",
            _ => return None,
        };

        let decoded = decode::<Claims>(
            token,
            &DecodingKey::from_rsa_pem(certs.as_bytes()).ok()?,
            &Validation::new(alg.parse().ok()?),
        )
        .ok()?;

        let user = User {
            username: decoded.claims.sub,
            realm: "ecmwf".to_string(),
        };

        println!("Found user {} from decoded JWT", user.username);
        Some(user)
    }

    async fn get_certs(&self) -> Result<String, Box<dyn Error>> {
        let res: Value = reqwest::get(&self.certificate_endpoint)
            .await?
            .json()
            .await?;
        Ok(res.to_string())
    }
}

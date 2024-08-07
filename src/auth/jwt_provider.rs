use std::collections::HashMap;

use cached::proc_macro::cached;
use jsonwebtoken::jwk::JwkSet;
use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;

use super::User;
use inline_colorization::*;
use jsonwebtoken::decode;
use jsonwebtoken::decode_header;
use jsonwebtoken::Algorithm;
use jsonwebtoken::DecodingKey;
use jsonwebtoken::Validation;

// --- Config

#[derive(Deserialize, Serialize, JsonSchema, Debug, Clone)]
pub struct JWTAuthConfig {
    pub cert_uri: String,
    pub realm: String,
    pub name: String,
    pub iam_realm: String,
}

// --- Provider

pub struct JWTProvider {
    pub config: JWTAuthConfig,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    resource_access: Option<HashMap<String, RolesContainer>>,
    scope: String,
    realm_access: Option<RolesContainer>,
    entitlements: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct RolesContainer {
    roles: Vec<String>,
}

impl JWTProvider {
    pub fn new(config: &JWTAuthConfig) -> Self {
        println!(
            "  🔑 Creating {style_bold}{color_cyan}JWTAuth{style_reset}{color_reset} for realm {}",
            config.realm
        );
        Self {
            config: config.clone(),
        }
    }
}

#[async_trait::async_trait]
impl super::Provider for JWTProvider {
    fn get_type(&self) -> &str {
        "Bearer"
    }

    async fn authenticate(&self, token: &str) -> Result<User, String> {
        let certs = get_certs(self.config.cert_uri.to_string()).await?;

        let header = match decode_header(token) {
            Ok(header) => header,
            Err(e) => return Err(format!("failed to decode JWT header: {}", e)),
        };

        let alg = match header.alg {
            Algorithm::RS256 => "RS256",
            Algorithm::HS512 => "HS512",
            Algorithm::RS512 => "RS512",
            _ => return Err(format!("unsupported JWT algorithm: {:?}", header.alg)),
        };

        let jwks: JwkSet = serde_json::from_str(&certs)
            .map_err(|e| format!("failed to parse certificates: {}", e))?;

        let kid = header.kid.ok_or("missing kid in JWT header")?;

        let jwk = jwks.find(&kid).ok_or(format!(
            "failed to find certificate with matching kid {}",
            kid
        ))?;

        let decoding_key = DecodingKey::from_jwk(&jwk).expect("failed to create decoding key");

        let mut validation = Validation::new(alg.parse::<Algorithm>().unwrap());

        validation.validate_aud = false;
        let decoded = match decode::<Claims>(token, &decoding_key, &validation) {
            Ok(decoded) => decoded,
            Err(e) => return Err(format!("failed to decode JWT: {}", e)),
        };

        let mut roles = decoded
            .claims
            .realm_access
            .and_then(|realm_access| Some(realm_access.roles))
            .unwrap_or_default();

        roles.extend(decoded.claims.entitlements.unwrap_or_default());
        if let Some(resource_access) = decoded.claims.resource_access {
            for (_, roles_container) in resource_access {
                roles.extend(roles_container.roles);
            }
        }
        let user = User::new(
            self.config.realm.to_string(),
            decoded.claims.sub,
            Some(roles),
            None,
            Some(HashMap::from([(
                self.config.name.clone(),
                decoded
                    .claims
                    .scope
                    .split_whitespace()
                    .map(|s| s.to_string())
                    .collect::<Vec<String>>(),
            )])),
            None,
        );

        Ok(user)
    }

    fn get_name(&self) -> &str {
        &self.config.name
    }
}

#[cached(time = 600, sync_writes = true)]
pub async fn get_certs(cert_uri: String) -> Result<String, String> {
    let res = reqwest::get(&cert_uri)
        .await
        .map_err(|e| format!("failed to download certificates: {}", e))?;

    if res.status().is_success() {
        let json: Value = res
            .json()
            .await
            .map_err(|e| format!("failed to download certificates: {}", e))?;

        Ok(json.to_string())
    } else {
        Err(format!("failed to download certificates: {}", res.status()))
    }
}

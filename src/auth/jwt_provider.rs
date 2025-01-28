use std::collections::HashMap;

use cached::proc_macro::cached;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{debug, info};

use super::User;

/// JWT config structure for external usage
#[derive(Deserialize, Serialize, JsonSchema, Debug, Clone)]
pub struct JWTAuthConfig {
    pub cert_uri: String,
    pub realm: String,
    pub name: String,
    pub iam_realm: String,
}

/// Provider that validates JWTs using downloaded keys (JWK) from `cert_uri`.
pub struct JWTProvider {
    pub config: JWTAuthConfig,
}

/// Helper struct to read claims from the JWT.
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    resource_access: Option<HashMap<String, RolesContainer>>,
    scope: String,
    realm_access: Option<RolesContainer>,
    entitlements: Option<Vec<String>>,
}

/// Used to unify roles from different sections of the claim.
#[derive(Debug, Serialize, Deserialize)]
struct RolesContainer {
    roles: Vec<String>,
}

impl JWTProvider {
    /// Creates a new JWTProvider with the given config.
    pub fn new(config: &JWTAuthConfig) -> Self {
        info!(
            "Creating JWTAuth provider for realm '{}', name='{}'",
            config.realm, config.name
        );
        Self {
            config: config.clone(),
        }
    }
}

#[async_trait::async_trait]
impl super::Provider for JWTProvider {
    /// For consistency, we treat these tokens as "Bearer" type.
    fn get_type(&self) -> &str {
        "Bearer"
    }

    /// Authenticates a token by decoding its header, fetching the right key, and validating.
    async fn authenticate(&self, token: &str) -> Result<User, String> {
        debug!(
            "Attempting JWT decode for realm='{}', name='{}'",
            self.config.realm, self.config.name
        );

        // Fetch the JWK set (cached)
        let certs = get_certs(self.config.cert_uri.to_string()).await?;
        let header =
            decode_header(token).map_err(|e| format!("Failed to decode JWT header: {}", e))?;

        // Match the expected algorithm
        let alg = match header.alg {
            Algorithm::RS256 => "RS256",
            Algorithm::HS512 => "HS512",
            Algorithm::RS512 => "RS512",
            _ => return Err(format!("Unsupported JWT algorithm: {:?}", header.alg)),
        };

        // Parse the downloaded JWKS
        let jwks: JwkSet = serde_json::from_str(&certs)
            .map_err(|e| format!("Failed to parse certificates: {}", e))?;

        let kid = header.kid.ok_or("Missing 'kid' in JWT header")?;
        let jwk = jwks.find(&kid).ok_or(format!(
            "Failed to find certificate with matching kid {}",
            kid
        ))?;

        let decoding_key = DecodingKey::from_jwk(&jwk)
            .map_err(|_| "Failed to create decoding key from JWK".to_string())?;

        let mut validation = Validation::new(alg.parse::<Algorithm>().unwrap());
        validation.validate_aud = false; // Possibly enable if you want to check "aud"

        let decoded = decode::<Claims>(token, &decoding_key, &validation)
            .map_err(|e| format!("Failed to decode JWT: {}", e))?;

        // Collect roles from various places
        let mut roles = decoded
            .claims
            .realm_access
            .map(|ra| ra.roles)
            .unwrap_or_default();

        roles.extend(decoded.claims.entitlements.unwrap_or_default());
        if let Some(resource_access) = decoded.claims.resource_access {
            for (_, roles_container) in resource_access {
                roles.extend(roles_container.roles);
            }
        }

        // Build the final `User` object
        let user = User::new(
            self.config.realm.to_string(),
            decoded.claims.sub,
            Some(roles),
            None,
            // We store the 'scope' claim in user attributes under the provider name
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

    /// A display name for logs/debugging.
    fn get_name(&self) -> &str {
        &self.config.name
    }
}

/// Retrieves the certificates (JWKS) from a remote URI. Cached for 600s to avoid repeated fetches.
#[cached(time = 600, sync_writes = true)]
pub async fn get_certs(cert_uri: String) -> Result<String, String> {
    let res = reqwest::get(&cert_uri)
        .await
        .map_err(|e| format!("Failed to download certificates: {}", e))?;

    if res.status().is_success() {
        let json: Value = res
            .json()
            .await
            .map_err(|e| format!("Failed to parse certificate JSON: {}", e))?;
        Ok(json.to_string())
    } else {
        Err(format!("Failed to download certificates: {}", res.status()))
    }
}

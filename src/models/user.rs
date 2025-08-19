use std::collections::HashMap;

use crate::config::JWTConfig;
use crate::utils::http_helpers::HTTPError;
use crate::AppState;
use axum::async_trait;
use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::StatusCode;
use chrono::Utc;
use http::request::Parts;
use jsonwebtoken::{encode, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tracing::warn;

/// The User struct represents an authenticated user in the system.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct User {
    pub version: i32,
    pub realm: String,
    pub username: String,
    pub roles: Vec<String>,
    pub attributes: HashMap<String, String>,
    /// A map of service -> scopes
    pub scopes: Option<HashMap<String, Vec<String>>>,
}

impl User {
    /// Construct a new User with optional roles, attributes, scopes.
    pub fn new(
        realm: String,
        username: String,
        roles: Option<Vec<String>>,
        attributes: Option<HashMap<String, String>>,
        scopes: Option<HashMap<String, Vec<String>>>,
        version: Option<i32>,
    ) -> Self {
        User {
            version: version.unwrap_or(1),
            realm,
            username,
            roles: roles.unwrap_or_default(),
            attributes: attributes.unwrap_or_default(),
            scopes,
        }
    }

    /// Convert a User into a signed JWT string, using the config from `JWTConfig`.
    pub fn to_jwt(&self, jwtconfig: &JWTConfig) -> String {
        #[derive(Serialize)]
        struct Claims<'a> {
            sub: &'a String,
            iss: &'a String,
            exp: i64,
            iat: i64,

            roles: &'a Vec<String>,
            username: &'a String,
            scopes: &'a Option<HashMap<String, Vec<String>>>,
            realm: &'a String,
            attributes: &'a HashMap<String, String>,
        }

        let now = Utc::now().timestamp();
        let sub = format!("{}-{}", self.realm, self.username);

        let claims = Claims {
            sub: &sub,
            iss: &jwtconfig.iss,
            exp: now + jwtconfig.exp,
            iat: now,
            roles: &self.roles,
            username: &self.username,
            scopes: &self.scopes,
            realm: &self.realm,
            attributes: &self.attributes,
        };

        let encoding_key = EncodingKey::from_secret(jwtconfig.secret.as_ref());
        encode(&Header::default(), &claims, &encoding_key).expect("Failed to encode JWT")
    }
}

/// Implementation of the request extractor for User.
/// When authentication fails, we return an HTTPError that includes a
/// dynamic WWW-Authenticate challenge generated from the available providers.
#[async_trait]
impl FromRequestParts<AppState> for User {
    type Rejection = HTTPError;
    async fn from_request_parts<'a, 'b>(
        parts: &'a mut Parts,
        state: &'b AppState,
    ) -> Result<User, HTTPError> {
        // Extract the Authorization header.
        let auth_header = parts
            .headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .to_string();

        // Extract the optional X-Auth-Realm header.
        let realm_filter = parts
            .headers
            .get("x-auth-realm")
            .and_then(|value| value.to_str().ok());

        // Retrieve the client IP (for logging purposes).
        let client_ip = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ConnectInfo(addr)| addr.ip())
            .unwrap_or_else(|| {
                warn!("Unable to determine client IP address.");
                "unknown".parse().unwrap()
            });

        // Attempt to authenticate using our Auth implementation.
        match state
            .auth
            .authenticate(&auth_header, &client_ip.to_string(), realm_filter)
            .await
        {
            Some(user) => Ok(user),
            None => {
                // Generate a dynamic challenge header from the available providers.
                let challenge = state.auth.generate_challenge_header();
                Err(HTTPError::new(
                    StatusCode::UNAUTHORIZED,
                    "Unauthorized access",
                    Some(challenge),
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::JWTConfig;
    use jsonwebtoken::{decode, DecodingKey, Validation};

    /// Test that converting a User to a JWT and then decoding it yields the expected claims.
    ///
    /// Note: We disable audience validation in this test (as in production code)
    /// by setting `validation.validate_aud = false`. This prevents the decoder from
    /// failing with an "InvalidAudience" error.
    #[test]
    fn test_to_jwt_and_decode() {
        // Create a user with test data.
        let user = User::new(
            "test".to_string(),
            "user1".to_string(),
            Some(vec!["role1".to_string()]),
            None,
            None,
            Some(1),
        );
        // Create a JWT configuration with an audience.
        let jwt_config = JWTConfig {
            iss: "test_issuer".to_string(),
            aud: None,
            exp: 3600,
            secret: "secretkey".to_string(),
        };
        // Convert the user into a JWT.
        let token = user.to_jwt(&jwt_config);

        // Create a default validation instance and disable audience validation.
        let mut validation = Validation::default();
        validation.validate_aud = false;

        // Decode the token using the secret from jwt_config.
        let token_data = decode::<serde_json::Value>(
            &token,
            &DecodingKey::from_secret(jwt_config.secret.as_ref()),
            &validation,
        )
        .expect("Failed to decode JWT");

        let claims = token_data.claims;
        // Assert that the issuer claim matches.
        assert_eq!(claims["iss"], jwt_config.iss);
        // Assert that the username claim matches.
        assert_eq!(claims["username"], user.username);
    }
}

use std::collections::HashMap;

use chrono::Utc;
use jsonwebtoken::{encode, EncodingKey, Header};
use serde::{Deserialize, Serialize};

use crate::config::JWTConfig;

/// The User struct represents an authenticated user in the system.
#[derive(Serialize, Deserialize, Debug, Clone)]
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
            aud: &'a Option<String>,
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
            aud: &jwtconfig.aud,
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

/// A token stored in a database for lookup/revocation.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Token {
    pub version: i32,
    pub token_string: String,
    /// A map from service -> scopes
    pub scopes: HashMap<String, Vec<String>>,
}

impl Token {
    /// Create a new Token with optional version.
    /// We automatically generate a new token_string (UUID).
    pub fn new(
        _suggested_token_str: String,
        scopes: HashMap<String, Vec<String>>,
        version: Option<i32>,
    ) -> Self {
        Token {
            version: version.unwrap_or(1),
            token_string: uuid::Uuid::new_v4().to_string(),
            scopes,
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
            aud: Some("test_audience".to_string()),
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
        // (Optionally) Assert that the audience claim is present and equals what we set.
        assert_eq!(claims["aud"], jwt_config.aud.unwrap());
    }
}

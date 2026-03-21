// (C) Copyright 2024- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! Server-side extensions for the shared [`User`] type.
//!
//! Re-exports [`authotron_types::User`] and adds:
//! - [`UserJwtExt::to_jwt`] for signing a user into a JWT
//! - [`FromRequestParts`] extractor for Axum handlers

use std::collections::HashMap;

use crate::config::JWTConfig;
use crate::state::AppState;
use crate::utils::http_helpers::HTTPError;
use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::StatusCode;
use chrono::Utc;
use http::request::Parts;
use jsonwebtoken::{EncodingKey, Header, encode};
use serde::Serialize;
use std::net::SocketAddr;
use tracing::warn;

// Re-export the canonical User type so existing `use crate::models::user::User`
// imports continue to work throughout the codebase.
pub use authotron_types::User;

/// Extension trait that adds JWT signing to `User`.
///
/// This is an extension trait rather than an inherent method because `User` is
/// defined in `authotron-types`. The JWT signing logic depends on `JWTConfig`
/// from the server crate and therefore cannot live in the types crate.
pub trait UserJwtExt {
    /// Convert a User into a signed JWT string, using the config from `JWTConfig`.
    fn to_jwt(&self, jwtconfig: &JWTConfig) -> String;
}

impl UserJwtExt for User {
    fn to_jwt(&self, jwtconfig: &JWTConfig) -> String {
        #[derive(Serialize)]
        struct Claims<'a> {
            sub: &'a String,
            iss: &'a String,
            exp: i64,
            iat: i64,

            roles: &'a Vec<String>,
            username: &'a String,
            scopes: &'a HashMap<String, Vec<String>>,
            realm: &'a String,
            attributes: &'a HashMap<String, String>,
        }

        let now = Utc::now().timestamp();
        let sub = format!("{}-{}", self.realm, self.username);

        let mut expiry = now + jwtconfig.exp;
        if let Some(attr_exp) = self.attributes.get("exp")
            && let Ok(attr_exp) = attr_exp.parse::<i64>()
        {
            // Set expiry to the minimum of the two values
            expiry = std::cmp::min(expiry, attr_exp);
        }
        let claims = Claims {
            sub: &sub,
            iss: &jwtconfig.iss,
            exp: expiry,
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
impl FromRequestParts<AppState> for User {
    type Rejection = HTTPError;
    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<User, HTTPError> {
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
                warn!(
                    event_name = "auth.request.client_ip.missing",
                    event_domain = "auth",
                    "unable to determine client IP address"
                );
                "unknown".parse().unwrap()
            });

        // Attempt to authenticate using our Auth implementation.
        match state
            .auth
            .authenticate(
                &auth_header,
                &client_ip.to_string(),
                realm_filter,
                &state.metrics,
            )
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
    use jsonwebtoken::{DecodingKey, Validation, decode};

    /// Test that converting a User to a JWT and then decoding it yields the expected claims.
    ///
    /// Note: We disable audience validation in this test (as in production code)
    /// by setting `validation.validate_aud = false`. This prevents the decoder from
    /// failing with an "InvalidAudience" error.
    fn decode_claims(token: &str, jwt_config: &JWTConfig) -> serde_json::Value {
        let mut validation = Validation::default();
        validation.validate_aud = false;

        decode::<serde_json::Value>(
            token,
            &DecodingKey::from_secret(jwt_config.secret.as_ref()),
            &validation,
        )
        .expect("Failed to decode JWT")
        .claims
    }

    fn default_jwt_config() -> JWTConfig {
        JWTConfig {
            iss: "test_issuer".to_string(),
            aud: None,
            exp: 3600,
            secret: "secretkey".to_string(),
        }
    }

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
        let jwt_config = default_jwt_config();
        // Convert the user into a JWT.
        let token = user.to_jwt(&jwt_config);

        // Decode the token using the secret from jwt_config.
        let claims = decode_claims(&token, &jwt_config);
        // Assert that the issuer claim matches.
        assert_eq!(claims["iss"], jwt_config.iss);
        // Assert that the username claim matches.
        assert_eq!(claims["username"], user.username);
    }

    // Test that if the exp attribute is set in User attributes, it affects the JWT expiry.
    #[test]
    fn test_to_jwt_with_exp_attribute() {
        let mut attributes = HashMap::new();
        let custom_exp = Utc::now().timestamp() + 1800; // 30 minutes from now
        attributes.insert("exp".to_string(), custom_exp.to_string());
        let user = User::new(
            "test".to_string(),
            "user2".to_string(),
            Some(vec!["role2".to_string()]),
            Some(attributes),
            None,
            Some(1),
        );
        let jwt_config = default_jwt_config();
        let token = user.to_jwt(&jwt_config);
        let claims = decode_claims(&token, &jwt_config);
        let exp_claim = claims["exp"]
            .as_i64()
            .expect("exp claim should be an integer");
        // Assert that the exp claim matches the custom exp attribute.
        assert_eq!(exp_claim, custom_exp);
    }
}

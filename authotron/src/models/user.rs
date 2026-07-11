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
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde::Serialize;
use std::net::SocketAddr;
use tracing::warn;

// Re-export the canonical User type so existing `use crate::models::user::User`
// imports continue to work throughout the codebase.
pub use authotron_types::User;

/// A parsed RS256 private key used to sign issued JWTs.
pub struct JwtSigner {
    encoding_key: EncodingKey,
}

/// Errors produced while configuring or using the JWT signer.
#[derive(Debug)]
pub enum JwtSigningError {
    InvalidPrivateKey(jsonwebtoken::errors::Error),
    Signing(jsonwebtoken::errors::Error),
}

impl std::fmt::Display for JwtSigningError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPrivateKey(error) => write!(f, "invalid JWT RSA private key: {error}"),
            Self::Signing(error) => write!(f, "failed to sign JWT: {error}"),
        }
    }
}

impl std::error::Error for JwtSigningError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidPrivateKey(error) | Self::Signing(error) => Some(error),
        }
    }
}

impl JwtSigner {
    /// Parse an RSA private key from PEM. Call this once during startup.
    pub fn from_private_pem(pem: &[u8]) -> Result<Self, JwtSigningError> {
        let encoding_key =
            EncodingKey::from_rsa_pem(pem).map_err(JwtSigningError::InvalidPrivateKey)?;
        Ok(Self { encoding_key })
    }
}

/// Extension trait that adds JWT signing to `User`.
pub trait UserJwtExt {
    /// Convert a user into an RS256-signed JWT.
    fn to_jwt(&self, jwt_config: &JWTConfig, signer: &JwtSigner)
    -> Result<String, JwtSigningError>;
}

impl UserJwtExt for User {
    fn to_jwt(
        &self,
        jwt_config: &JWTConfig,
        signer: &JwtSigner,
    ) -> Result<String, JwtSigningError> {
        #[derive(Serialize)]
        struct Claims<'a> {
            sub: &'a String,
            iss: &'a String,
            aud: &'a String,
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

        let mut expiry = now + jwt_config.exp;
        if let Some(attr_exp) = self.attributes.get("exp")
            && let Ok(attr_exp) = attr_exp.parse::<i64>()
        {
            expiry = std::cmp::min(expiry, attr_exp);
        }
        let claims = Claims {
            sub: &sub,
            iss: &jwt_config.iss,
            aud: &jwt_config.aud,
            exp: expiry,
            iat: now,
            roles: &self.roles,
            username: &self.username,
            scopes: &self.scopes,
            realm: &self.realm,
            attributes: &self.attributes,
        };

        encode(
            &Header::new(Algorithm::RS256),
            &claims,
            &signer.encoding_key,
        )
        .map_err(JwtSigningError::Signing)
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
    use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};

    const PRIVATE_KEY: &[u8] = include_bytes!("../../tests/fixtures/test-rsa-private.pem");
    const PUBLIC_KEY: &[u8] = include_bytes!("../../tests/fixtures/test-rsa-public.pem");

    fn decode_claims(token: &str, jwt_config: &JWTConfig) -> serde_json::Value {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&jwt_config.iss]);
        validation.set_audience(&[&jwt_config.aud]);

        decode::<serde_json::Value>(
            token,
            &DecodingKey::from_rsa_pem(PUBLIC_KEY).expect("valid test public key"),
            &validation,
        )
        .expect("JWT should decode")
        .claims
    }

    fn default_jwt_config() -> JWTConfig {
        JWTConfig {
            iss: "test_issuer".to_string(),
            aud: "test_audience".to_string(),
            exp: 3600,
            private_key: String::from_utf8(PRIVATE_KEY.to_vec()).expect("PEM is UTF-8"),
        }
    }

    #[test]
    fn test_to_jwt_and_decode() {
        let user = User::new(
            "test".to_string(),
            "user1".to_string(),
            Some(vec!["role1".to_string()]),
            None,
            None,
            Some(1),
        );
        let jwt_config = default_jwt_config();
        let signer = JwtSigner::from_private_pem(jwt_config.private_key.as_bytes()).unwrap();
        let token = user.to_jwt(&jwt_config, &signer).unwrap();

        let header = jsonwebtoken::decode_header(&token).unwrap();
        assert_eq!(header.alg, Algorithm::RS256);
        let claims = decode_claims(&token, &jwt_config);
        assert_eq!(claims["iss"], jwt_config.iss);
        assert_eq!(claims["aud"], jwt_config.aud);
        assert_eq!(claims["username"], user.username);
    }

    #[test]
    fn test_to_jwt_with_exp_attribute() {
        let mut attributes = HashMap::new();
        let custom_exp = Utc::now().timestamp() + 1800;
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
        let signer = JwtSigner::from_private_pem(jwt_config.private_key.as_bytes()).unwrap();
        let token = user.to_jwt(&jwt_config, &signer).unwrap();
        let claims = decode_claims(&token, &jwt_config);
        assert_eq!(claims["exp"].as_i64(), Some(custom_exp));
    }

    #[test]
    fn malformed_private_key_is_typed_error() {
        let result = JwtSigner::from_private_pem(b"not a PEM key");
        assert!(matches!(result, Err(JwtSigningError::InvalidPrivateKey(_))));
    }
}

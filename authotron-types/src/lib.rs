// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! Shared authentication DTOs for the auth-o-tron ecosystem.
//!
//! These types represent the stable wire format for authenticated user data
//! that flows between auth-o-tron, polytope-server, and bits-broker.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Authenticated user context, the canonical DTO carried across service boundaries.
///
/// This struct represents the subset of user data that consumers need.
/// It is intentionally smaller than the server-side `User` (which also has
/// `version`, `to_jwt()`, and `FromRequestParts`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthUser {
    pub username: String,
    pub realm: String,
    pub roles: Vec<String>,
    #[serde(default)]
    pub attributes: HashMap<String, String>,
    #[serde(default)]
    pub scopes: HashMap<String, Vec<String>>,
}

/// Authentication errors shared across the ecosystem.
#[derive(Debug)]
pub enum AuthError {
    /// The token was rejected by the auth provider (HTTP 401).
    Unauthorized {
        message: String,
        www_authenticate: String,
    },
    /// The JWT could not be decoded or validated.
    InvalidJwt { message: String },
    /// The auth service is unreachable or timed out.
    ServiceUnavailable { message: String },
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::Unauthorized { message, .. } => write!(f, "unauthorized: {}", message),
            AuthError::InvalidJwt { message } => write!(f, "invalid JWT: {}", message),
            AuthError::ServiceUnavailable { message } => {
                write!(f, "auth service unavailable: {}", message)
            }
        }
    }
}

impl std::error::Error for AuthError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_user_serde_roundtrip() {
        let user = AuthUser {
            username: "testuser".to_string(),
            realm: "ecmwf".to_string(),
            roles: vec!["admin".to_string(), "default".to_string()],
            attributes: HashMap::from([("org".to_string(), "ecmwf".to_string())]),
            scopes: HashMap::from([(
                "data".to_string(),
                vec!["read".to_string(), "write".to_string()],
            )]),
        };

        let json = serde_json::to_string(&user).unwrap();
        let deserialized: AuthUser = serde_json::from_str(&json).unwrap();
        assert_eq!(user, deserialized);
    }

    #[test]
    fn test_auth_user_default_attributes() {
        let json = r#"{"username":"u","realm":"r","roles":[]}"#;
        let user: AuthUser = serde_json::from_str(json).unwrap();
        assert!(user.attributes.is_empty());
        assert!(user.scopes.is_empty());
    }

    #[test]
    fn test_auth_user_default_scopes() {
        let json = r#"{"username":"u","realm":"r","roles":["a"],"attributes":{"k":"v"}}"#;
        let user: AuthUser = serde_json::from_str(json).unwrap();
        assert_eq!(user.attributes.get("k").unwrap(), "v");
        assert!(user.scopes.is_empty());
    }

    #[test]
    fn test_auth_user_missing_optional_fields_backward_compat() {
        // Simulates a JWT or serialized user that predates the scopes field
        let json = r#"{"username":"alice","realm":"test","roles":["user"]}"#;
        let user: AuthUser = serde_json::from_str(json).unwrap();
        assert_eq!(user.username, "alice");
        assert_eq!(user.realm, "test");
        assert_eq!(user.roles, vec!["user"]);
        assert!(user.attributes.is_empty());
        assert!(user.scopes.is_empty());
    }

    #[test]
    fn test_auth_user_ignores_unknown_fields() {
        // Future-proofing: unknown fields should not break deserialization
        let json =
            r#"{"username":"u","realm":"r","roles":[],"version":1,"future_field":"whatever"}"#;
        // This will fail because we don't have deny_unknown_fields — which is what we want
        let result: Result<AuthUser, _> = serde_json::from_str(json);
        assert!(result.is_ok());
    }

    #[test]
    fn test_auth_error_display() {
        let err = AuthError::Unauthorized {
            message: "bad token".to_string(),
            www_authenticate: "Bearer".to_string(),
        };
        assert_eq!(format!("{}", err), "unauthorized: bad token");

        let err = AuthError::InvalidJwt {
            message: "expired".to_string(),
        };
        assert_eq!(format!("{}", err), "invalid JWT: expired");

        let err = AuthError::ServiceUnavailable {
            message: "timeout".to_string(),
        };
        assert_eq!(format!("{}", err), "auth service unavailable: timeout");
    }
}

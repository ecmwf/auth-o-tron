// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! Shared authentication types for the auth-o-tron ecosystem.
//!
//! [`User`] is the canonical representation of an authenticated user that flows
//! between auth-o-tron, polytope-server, and bits-broker.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

fn default_version() -> i32 {
    1
}

/// Authenticated user — the single canonical type used across all services.
///
/// Carries identity, roles, attributes, and scopes. The `version` field exists
/// for storage compatibility (MongoDB documents) and defaults to `1`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct User {
    #[serde(default = "default_version")]
    pub version: i32,
    pub username: String,
    pub realm: String,
    pub roles: Vec<String>,
    #[serde(default)]
    pub attributes: HashMap<String, String>,
    #[serde(default)]
    pub scopes: HashMap<String, Vec<String>>,
}

impl Default for User {
    fn default() -> Self {
        User {
            version: 1,
            username: String::new(),
            realm: String::new(),
            roles: Vec::new(),
            attributes: HashMap::new(),
            scopes: HashMap::new(),
        }
    }
}

impl User {
    /// Construct a new User with optional roles, attributes, scopes.
    ///
    /// This preserves the original constructor signature so that existing
    /// provider call-sites don't need to change.
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
            scopes: scopes.unwrap_or_default(),
        }
    }
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
    fn test_user_serde_roundtrip() {
        let user = User {
            version: 1,
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
        let deserialized: User = serde_json::from_str(&json).unwrap();
        assert_eq!(user, deserialized);
    }

    #[test]
    fn test_user_default_attributes() {
        let json = r#"{"username":"u","realm":"r","roles":[]}"#;
        let user: User = serde_json::from_str(json).unwrap();
        assert!(user.attributes.is_empty());
        assert!(user.scopes.is_empty());
        assert_eq!(user.version, 1);
    }

    #[test]
    fn test_user_default_scopes() {
        let json = r#"{"username":"u","realm":"r","roles":["a"],"attributes":{"k":"v"}}"#;
        let user: User = serde_json::from_str(json).unwrap();
        assert_eq!(user.attributes.get("k").unwrap(), "v");
        assert!(user.scopes.is_empty());
    }

    #[test]
    fn test_user_missing_optional_fields_backward_compat() {
        // Simulates a JWT or serialized user that predates the scopes field
        let json = r#"{"username":"alice","realm":"test","roles":["user"]}"#;
        let user: User = serde_json::from_str(json).unwrap();
        assert_eq!(user.username, "alice");
        assert_eq!(user.realm, "test");
        assert_eq!(user.roles, vec!["user"]);
        assert!(user.attributes.is_empty());
        assert!(user.scopes.is_empty());
        assert_eq!(user.version, 1);
    }

    #[test]
    fn test_user_ignores_unknown_fields() {
        let json =
            r#"{"username":"u","realm":"r","roles":[],"version":2,"future_field":"whatever"}"#;
        let result: Result<User, _> = serde_json::from_str(json);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().version, 2);
    }

    #[test]
    fn test_user_new_constructor() {
        let user = User::new(
            "ecmwf".to_string(),
            "alice".to_string(),
            Some(vec!["admin".to_string()]),
            None,
            None,
            Some(1),
        );
        assert_eq!(user.realm, "ecmwf");
        assert_eq!(user.username, "alice");
        assert_eq!(user.roles, vec!["admin"]);
        assert!(user.attributes.is_empty());
        assert!(user.scopes.is_empty());
        assert_eq!(user.version, 1);
    }

    #[test]
    fn test_user_new_defaults() {
        let user = User::new("r".to_string(), "u".to_string(), None, None, None, None);
        assert!(user.roles.is_empty());
        assert!(user.attributes.is_empty());
        assert!(user.scopes.is_empty());
        assert_eq!(user.version, 1);
    }

    #[test]
    fn test_user_default_impl() {
        let user = User::default();
        assert_eq!(user.version, 1);
        assert!(user.username.is_empty());
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

use std::collections::HashMap;

use chrono::Utc;
use jsonwebtoken::{encode, EncodingKey, Header};
use serde::{Deserialize, Serialize};

use crate::config::JWTConfig;

/// The `User` struct defines the authenticated user,
/// including realm, username, roles, attributes, and optional scopes.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct User {
    pub version: i32,
    pub realm: String,
    pub username: String,
    pub roles: Vec<String>,
    pub attributes: HashMap<String, String>,
    pub scopes: Option<HashMap<Service, Scopes>>,
}

/// A simple type alias for service names.
type Service = String;
/// Another alias for scopes, which is a vector of strings.
type Scopes = Vec<String>;

/// A `Token` struct that holds metadata about an issued token.
/// This is often stored in the database for easy revocation or lookup.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Token {
    pub version: i32,
    pub token_string: String,
    pub scopes: HashMap<Service, Scopes>,
}

impl User {
    /// Create a new `User` with optional roles, attributes, scopes, and version.
    pub fn new(
        realm: String,
        username: String,
        roles: Option<Vec<String>>,
        attributes: Option<HashMap<String, String>>,
        scopes: Option<HashMap<Service, Scopes>>,
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

    /// Convert a `User` into a signed JWT string, using the provided JWT config.
    pub fn to_jwt(&self, jwtconfig: &JWTConfig) -> String {
        #[derive(Serialize)]
        struct Claims<'a> {
            // Registered Claims
            sub: &'a String,
            iss: &'a String,
            aud: &'a Option<String>,
            exp: i64,
            iat: i64,

            // Public Claims
            roles: &'a Vec<String>,
            username: &'a String,
            scopes: &'a Option<HashMap<Service, Scopes>>,

            // Private Claims
            realm: &'a String,
            attributes: &'a HashMap<String, String>,
        }

        let sub = format!("{}-{}", self.realm, self.username);
        let now = Utc::now().timestamp();

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

#[allow(dead_code, unused_variables)]
impl Token {
    /// Creates a new `Token` with optional version,
    /// automatically generating a new UUID token string.
    pub fn new(
        token_string: String,
        scopes: HashMap<Service, Scopes>,
        version: Option<i32>,
    ) -> Self {
        Token {
            version: version.unwrap_or(1),
            // Overwrites the passed-in token_string with a new UUID
            token_string: uuid::Uuid::new_v4().to_string(),
            scopes,
        }
    }
}

// Simple tests to verify the `User` struct and JWT encoding.
#[test]
fn test_user_new() {
    let user = User::new(
        "realm".to_string(),
        "username".to_string(),
        Some(vec!["role1".to_string(), "role2".to_string()]),
        Some(
            [("key1".to_string(), "value1".to_string())]
                .iter()
                .cloned()
                .collect(),
        ),
        Some(
            [("service1".to_string(), vec!["scope1".to_string()])]
                .iter()
                .cloned()
                .collect(),
        ),
        Some(1),
    );

    assert_eq!(user.version, 1);
    assert_eq!(user.realm, "realm");
    assert_eq!(user.username, "username");
    assert_eq!(user.roles, vec!["role1", "role2"]);
    assert_eq!(
        user.attributes,
        [("key1".to_string(), "value1".to_string())]
            .iter()
            .cloned()
            .collect()
    );
    assert_eq!(
        user.scopes,
        Some(
            [("service1".to_string(), vec!["scope1".to_string()])]
                .iter()
                .cloned()
                .collect()
        )
    );
}

#[test]
fn test_user_to_jwt() {
    let user = User::new(
        "realm".to_string(),
        "username".to_string(),
        Some(vec!["role1".to_string(), "role2".to_string()]),
        Some(
            [("key1".to_string(), "value1".to_string())]
                .iter()
                .cloned()
                .collect(),
        ),
        Some(
            [("service1".to_string(), vec!["scope1".to_string()])]
                .iter()
                .cloned()
                .collect(),
        ),
        Some(1),
    );

    let jwtconfig = JWTConfig {
        iss: "issuer".to_string(),
        aud: Some("audience".to_string()),
        exp: 3600,
        secret: "secret".to_string(),
    };

    let jwt = user.to_jwt(&jwtconfig);
    assert!(!jwt.is_empty());
    println!("JWT: {}", jwt)
}

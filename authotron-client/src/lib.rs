// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! HTTP client for auth-o-tron: JWT decode, cache, and EmailKey conversion.
//!
//! This crate provides [`AuthClient`], which calls an auth-o-tron server's
//! `/authenticate` endpoint, decodes the returned JWT, caches the result, and
//! returns an [`User`].

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use jsonwebtoken::{DecodingKey, Validation, decode};
use moka::future::Cache;
use reqwest::Client;
use reqwest::header::{self, HeaderValue};
use serde::Deserialize;

// Re-exports for consumer convenience
pub use authotron_types::AuthError;
pub use authotron_types::User;

// ---------------------------------------------------------------------------
// JWT decode
// ---------------------------------------------------------------------------

/// Raw JWT claims as they appear in auth-o-tron's signed token.
///
/// `attributes` is `HashMap<String, serde_json::Value>` because auth-o-tron's
/// JWT may contain non-string attribute values. The decode step converts them
/// to `HashMap<String, String>` for the canonical `User`.
#[derive(Debug, Deserialize)]
struct Claims {
    username: String,
    realm: String,
    #[serde(default)]
    roles: Vec<String>,
    #[serde(default)]
    attributes: HashMap<String, serde_json::Value>,
    #[serde(default)]
    scopes: Option<HashMap<String, Vec<String>>>,
    #[allow(dead_code)]
    exp: usize,
}

/// Decode a JWT token into a [`User`].
///
/// This is a JWT-decode detail: the `"default"` role is injected here so that
/// every user decoded from a JWT always has it. Consumers deserializing
/// `User` from JSON (e.g. from `job.user`) should NOT assume `"default"`
/// is present — it is only guaranteed when the JWT decode path was used.
pub fn decode_jwt(token: &str, secret: &[u8]) -> Result<User, AuthError> {
    let mut validation = Validation::new(jsonwebtoken::Algorithm::HS256);
    validation.validate_aud = false;
    validation.leeway = 5;

    let token_data = decode::<Claims>(token, &DecodingKey::from_secret(secret), &validation)
        .map_err(|e| AuthError::InvalidJwt {
            message: e.to_string(),
        })?;

    let claims = token_data.claims;

    // Inject the synthetic "default" role (deduped via HashSet).
    let mut roles_set: HashSet<String> = claims.roles.into_iter().collect();
    roles_set.insert("default".to_string());
    let roles: Vec<String> = roles_set.into_iter().collect();

    // Convert attributes from Value → String using the canonical conversion rule:
    // - Strings pass through directly
    // - Numbers/bools become their JSON representation
    // - null → "null"
    // - Objects/arrays → JSON string form
    let attributes: HashMap<String, String> = claims
        .attributes
        .into_iter()
        .map(|(k, v)| {
            let s = v
                .as_str()
                .map(String::from)
                .unwrap_or_else(|| serde_json::to_string(&v).unwrap_or_default());
            (k, s)
        })
        .collect();

    let scopes = claims.scopes.unwrap_or_default();

    Ok(User {
        version: 1,
        username: claims.username,
        realm: claims.realm,
        roles,
        attributes,
        scopes,
    })
}

// ---------------------------------------------------------------------------
// EmailKey conversion
// ---------------------------------------------------------------------------

/// Convert an `EmailKey user@example.com:token` header to `Bearer token`.
///
/// Non-EmailKey headers are returned unchanged.
pub fn convert_email_key(auth_header: &str) -> String {
    if auth_header.starts_with("EmailKey ") {
        if let Some(colon_pos) = auth_header.find(':') {
            let part_after_colon = &auth_header[colon_pos + 1..];
            return format!("Bearer {}", part_after_colon);
        }
    }
    auth_header.to_string()
}

// ---------------------------------------------------------------------------
// AuthClient
// ---------------------------------------------------------------------------

/// HTTP client that calls auth-o-tron's `/authenticate` endpoint, decodes the
/// returned JWT, and caches the result.
pub struct AuthClient {
    http: Client,
    url: String,
    secret: Vec<u8>,
    cache: Cache<String, User>,
}

const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(60);
const DEFAULT_CACHE_CAPACITY: u64 = 10_000;

impl AuthClient {
    pub fn new(
        url: &str,
        secret: &[u8],
        timeout: Duration,
        cache_ttl: Option<Duration>,
        cache_capacity: Option<u64>,
    ) -> Self {
        let http = Client::builder()
            .timeout(timeout)
            .build()
            .expect("failed to build HTTP client");

        let cache = Cache::builder()
            .max_capacity(cache_capacity.unwrap_or(DEFAULT_CACHE_CAPACITY))
            .time_to_live(cache_ttl.unwrap_or(DEFAULT_CACHE_TTL))
            .build();

        Self {
            http,
            url: url.to_string(),
            secret: secret.to_vec(),
            cache,
        }
    }

    /// Authenticate using the given `Authorization` header value.
    ///
    /// 1. Converts `EmailKey` headers to `Bearer` format
    /// 2. Checks the TTL cache
    /// 3. On miss: calls auth-o-tron's `/authenticate` endpoint
    /// 4. Decodes the JWT from the response
    /// 5. Caches and returns the [`User`]
    pub async fn authenticate(&self, auth_header: &str) -> Result<User, AuthError> {
        let converted = convert_email_key(auth_header);

        if let Some(user) = self.cache.get(&converted).await {
            return Ok(user);
        }

        let response = self
            .http
            .get(format!("{}/authenticate", self.url.trim_end_matches('/')))
            .header("Authorization", &converted)
            .send()
            .await
            .map_err(|e| AuthError::ServiceUnavailable {
                message: format!("auth service error: {}", e),
            })?;

        if !response.status().is_success() {
            let www_auth = response
                .headers()
                .get(header::WWW_AUTHENTICATE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("Bearer")
                .to_string();
            return Err(AuthError::Unauthorized {
                message: "authentication failed".to_string(),
                www_authenticate: www_auth,
            });
        }

        let raw_header: &HeaderValue =
            response
                .headers()
                .get(header::AUTHORIZATION)
                .ok_or_else(|| AuthError::InvalidJwt {
                    message: "missing Authorization header in auth-o-tron response".to_string(),
                })?;

        let auth_response_header = raw_header
            .to_str()
            .map_err(|_| AuthError::InvalidJwt {
                message: "non-UTF-8 Authorization header in auth-o-tron response".to_string(),
            })?
            .to_string();

        let jwt_token = auth_response_header
            .strip_prefix("Bearer ")
            .ok_or_else(|| AuthError::InvalidJwt {
                message: "Authorization header is not Bearer scheme".to_string(),
            })?;

        let user = decode_jwt(jwt_token, &self.secret)?;

        self.cache.insert(converted, user.clone()).await;

        Ok(user)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{EncodingKey, Header};
    use serde::Serialize;

    #[derive(Debug, Serialize)]
    struct TestClaims {
        username: String,
        realm: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        roles: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        attributes: Option<HashMap<String, serde_json::Value>>,
        exp: usize,
    }

    fn make_token(claims: &TestClaims, secret: &[u8]) -> String {
        jsonwebtoken::encode(
            &Header::default(),
            claims,
            &EncodingKey::from_secret(secret),
        )
        .unwrap()
    }

    fn make_test_jwt(secret: &str) -> String {
        let claims = TestClaims {
            username: "testuser".to_string(),
            realm: "testrealm".to_string(),
            roles: Some(vec!["admin".to_string()]),
            attributes: None,
            exp: (chrono::Utc::now().timestamp() as usize) + 3600,
        };
        make_token(&claims, secret.as_bytes())
    }

    // ── JWT decode tests ──────────────────────────────────────────────

    #[test]
    fn test_decode_valid_jwt() {
        let secret = b"my_test_secret";
        let exp = chrono::Utc::now().timestamp() as usize + 3600;
        let claims = TestClaims {
            username: "testuser".to_string(),
            realm: "testrealm".to_string(),
            roles: Some(vec!["admin".to_string()]),
            attributes: Some(HashMap::from([(
                "org".to_string(),
                serde_json::json!("ecmwf"),
            )])),
            exp,
        };
        let token = make_token(&claims, secret);
        let user = decode_jwt(&token, secret).unwrap();

        assert_eq!(user.username, "testuser");
        assert_eq!(user.realm, "testrealm");
        assert!(user.roles.contains(&"admin".to_string()));
        assert!(user.roles.contains(&"default".to_string()));
        assert_eq!(user.attributes["org"], "ecmwf");
    }

    #[test]
    fn test_decode_jwt_no_roles() {
        let secret = b"my_test_secret";
        let exp = chrono::Utc::now().timestamp() as usize + 3600;
        let claims = TestClaims {
            username: "testuser".to_string(),
            realm: "testrealm".to_string(),
            roles: None,
            attributes: None,
            exp,
        };
        let token = make_token(&claims, secret);
        let user = decode_jwt(&token, secret).unwrap();

        assert_eq!(user.roles, vec!["default".to_string()]);
    }

    #[test]
    fn test_decode_jwt_default_role_dedup() {
        let secret = b"my_test_secret";
        let exp = chrono::Utc::now().timestamp() as usize + 3600;
        let claims = TestClaims {
            username: "testuser".to_string(),
            realm: "testrealm".to_string(),
            roles: Some(vec!["default".to_string(), "admin".to_string()]),
            attributes: None,
            exp,
        };
        let token = make_token(&claims, secret);
        let user = decode_jwt(&token, secret).unwrap();

        let default_count = user.roles.iter().filter(|r| *r == "default").count();
        assert_eq!(default_count, 1, "default role should appear exactly once");
        assert!(user.roles.contains(&"admin".to_string()));
    }

    #[test]
    fn test_decode_wrong_secret() {
        let exp = chrono::Utc::now().timestamp() as usize + 3600;
        let claims = TestClaims {
            username: "testuser".to_string(),
            realm: "testrealm".to_string(),
            roles: None,
            attributes: None,
            exp,
        };
        let token = make_token(&claims, b"secret_a");
        let result = decode_jwt(&token, b"secret_b");

        assert!(matches!(result, Err(AuthError::InvalidJwt { .. })));
    }

    #[test]
    fn test_decode_expired_jwt() {
        let secret = b"my_test_secret";
        let exp = chrono::Utc::now().timestamp() as usize - 3600;
        let claims = TestClaims {
            username: "testuser".to_string(),
            realm: "testrealm".to_string(),
            roles: None,
            attributes: None,
            exp,
        };
        let token = make_token(&claims, secret);
        let result = decode_jwt(&token, secret);

        assert!(matches!(result, Err(AuthError::InvalidJwt { .. })));
    }

    #[test]
    fn test_decode_missing_username() {
        #[derive(Serialize)]
        struct NoUsernameClaims {
            realm: String,
            exp: usize,
        }
        let secret = b"my_test_secret";
        let exp = chrono::Utc::now().timestamp() as usize + 3600;
        let claims = NoUsernameClaims {
            realm: "testrealm".to_string(),
            exp,
        };
        let token = jsonwebtoken::encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(secret),
        )
        .unwrap();
        let result = decode_jwt(&token, secret);

        assert!(matches!(result, Err(AuthError::InvalidJwt { .. })));
    }

    // ── Attribute conversion tests ────────────────────────────────────

    #[test]
    fn test_attributes_non_string_values() {
        let secret = b"my_test_secret";
        let exp = chrono::Utc::now().timestamp() as usize + 3600;

        #[derive(Serialize)]
        struct MixedAttrClaims {
            username: String,
            realm: String,
            roles: Vec<String>,
            attributes: HashMap<String, serde_json::Value>,
            exp: usize,
        }

        let mut attrs = HashMap::new();
        attrs.insert("str_val".to_string(), serde_json::json!("hello"));
        attrs.insert("num_val".to_string(), serde_json::json!(42));
        attrs.insert("bool_val".to_string(), serde_json::json!(true));
        attrs.insert("null_val".to_string(), serde_json::Value::Null);
        attrs.insert(
            "obj_val".to_string(),
            serde_json::json!({"nested": "value"}),
        );

        let claims = MixedAttrClaims {
            username: "u".to_string(),
            realm: "r".to_string(),
            roles: vec![],
            attributes: attrs,
            exp,
        };
        let token = jsonwebtoken::encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(secret),
        )
        .unwrap();

        let user = decode_jwt(&token, secret).unwrap();

        assert_eq!(user.attributes["str_val"], "hello");
        assert_eq!(user.attributes["num_val"], "42");
        assert_eq!(user.attributes["bool_val"], "true");
        assert_eq!(user.attributes["null_val"], "null");
        assert_eq!(user.attributes["obj_val"], r#"{"nested":"value"}"#);
    }

    #[test]
    fn test_default_role_injected() {
        let secret = b"my_test_secret";
        let exp = chrono::Utc::now().timestamp() as usize + 3600;
        // JWT with only "viewer" role — no "default"
        let claims = TestClaims {
            username: "u".to_string(),
            realm: "r".to_string(),
            roles: Some(vec!["viewer".to_string()]),
            attributes: None,
            exp,
        };
        let token = make_token(&claims, secret);
        let user = decode_jwt(&token, secret).unwrap();

        assert!(
            user.roles.contains(&"default".to_string()),
            "default role must be injected by decode_jwt"
        );
        assert!(user.roles.contains(&"viewer".to_string()));
    }

    // ── EmailKey conversion tests ─────────────────────────────────────

    #[test]
    fn test_email_key_conversion() {
        let result = convert_email_key("EmailKey user@test.com:abc123");
        assert_eq!(result, "Bearer abc123");
    }

    #[test]
    fn test_email_key_passthrough() {
        let result = convert_email_key("Bearer xyz");
        assert_eq!(result, "Bearer xyz");
    }

    #[test]
    fn test_email_key_malformed_no_colon() {
        let result = convert_email_key("EmailKey user@example.com");
        assert_eq!(
            result, "EmailKey user@example.com",
            "malformed EmailKey without colon should pass through unchanged"
        );
    }

    // ── AuthClient tests ──────────────────────────────────────────────

    #[tokio::test]
    async fn test_successful_auth() {
        let mut server = mockito::Server::new_async().await;
        let jwt = make_test_jwt("testsecret");

        server
            .mock("GET", "/authenticate")
            .with_status(200)
            .with_header("Authorization", &format!("Bearer {}", jwt))
            .create_async()
            .await;

        let client = AuthClient::new(
            &server.url(),
            b"testsecret",
            Duration::from_secs(5),
            None,
            None,
        );
        let user = client.authenticate("Bearer sometoken").await.unwrap();

        assert_eq!(user.username, "testuser");
        assert_eq!(user.realm, "testrealm");
        assert!(user.roles.contains(&"admin".to_string()));
        assert!(user.roles.contains(&"default".to_string()));
    }

    #[tokio::test]
    async fn test_auth_failure_401() {
        let mut server = mockito::Server::new_async().await;

        server
            .mock("GET", "/authenticate")
            .with_status(401)
            .with_header("WWW-Authenticate", r#"Bearer realm="test""#)
            .create_async()
            .await;

        let client = AuthClient::new(
            &server.url(),
            b"testsecret",
            Duration::from_secs(5),
            None,
            None,
        );
        let result = client.authenticate("Bearer badtoken").await;

        match result {
            Err(AuthError::Unauthorized {
                www_authenticate, ..
            }) => {
                assert_eq!(www_authenticate, r#"Bearer realm="test""#);
            }
            other => panic!("expected Unauthorized, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_cache_hit() {
        let mut server = mockito::Server::new_async().await;
        let jwt = make_test_jwt("testsecret");

        let mock = server
            .mock("GET", "/authenticate")
            .with_status(200)
            .with_header("Authorization", &format!("Bearer {}", jwt))
            .expect(1)
            .create_async()
            .await;

        let client = AuthClient::new(
            &server.url(),
            b"testsecret",
            Duration::from_secs(5),
            None,
            None,
        );

        let user1 = client.authenticate("Bearer cachedtoken").await.unwrap();
        let user2 = client.authenticate("Bearer cachedtoken").await.unwrap();

        assert_eq!(user1.username, user2.username);
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_auth_service_unreachable() {
        let client = AuthClient::new(
            "http://127.0.0.1:1",
            b"testsecret",
            Duration::from_secs(1),
            None,
            None,
        );
        let result = client.authenticate("Bearer token").await;

        assert!(matches!(result, Err(AuthError::ServiceUnavailable { .. })));
    }

    #[tokio::test]
    async fn test_missing_authorization_in_response() {
        let mut server = mockito::Server::new_async().await;

        server
            .mock("GET", "/authenticate")
            .with_status(200)
            .create_async()
            .await;

        let client = AuthClient::new(
            &server.url(),
            b"testsecret",
            Duration::from_secs(5),
            None,
            None,
        );
        let result = client.authenticate("Bearer sometoken").await;

        match result {
            Err(AuthError::InvalidJwt { message }) => {
                assert!(
                    message.contains("missing"),
                    "expected 'missing' in message, got: {}",
                    message
                );
            }
            other => panic!("expected InvalidJwt, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_non_bearer_authorization_in_response() {
        let mut server = mockito::Server::new_async().await;

        server
            .mock("GET", "/authenticate")
            .with_status(200)
            .with_header("Authorization", "Basic dXNlcjpwYXNz")
            .create_async()
            .await;

        let client = AuthClient::new(
            &server.url(),
            b"testsecret",
            Duration::from_secs(5),
            None,
            None,
        );
        let result = client.authenticate("Bearer sometoken").await;

        match result {
            Err(AuthError::InvalidJwt { message }) => {
                assert!(
                    message.contains("not Bearer"),
                    "expected 'not Bearer' in message, got: {}",
                    message
                );
            }
            other => panic!("expected InvalidJwt, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_invalid_jwt_response() {
        let mut server = mockito::Server::new_async().await;

        server
            .mock("GET", "/authenticate")
            .with_status(200)
            .with_header("Authorization", "Bearer not_a_valid_jwt")
            .create_async()
            .await;

        let client = AuthClient::new(
            &server.url(),
            b"testsecret",
            Duration::from_secs(5),
            None,
            None,
        );
        let result = client.authenticate("Bearer sometoken").await;

        assert!(matches!(result, Err(AuthError::InvalidJwt { .. })));
    }
}

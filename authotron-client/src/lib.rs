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

use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
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

/// Parsed RS256 verifier with an exact issuer and audience contract.
#[derive(Clone)]
pub struct JwtVerifier {
    decoding_key: DecodingKey,
    issuer: String,
    audience: String,
}

impl JwtVerifier {
    /// Parse an RSA public PEM key and configure exact claim validation.
    pub fn new(public_key_pem: &[u8], issuer: &str, audience: &str) -> Result<Self, AuthError> {
        let decoding_key = DecodingKey::from_rsa_pem(public_key_pem).map_err(|error| {
            AuthError::InvalidPublicKey {
                message: error.to_string(),
            }
        })?;

        Ok(Self {
            decoding_key,
            issuer: issuer.to_string(),
            audience: audience.to_string(),
        })
    }

    /// Verify an RS256 token and convert its claims into a [`User`].
    pub fn decode(&self, token: &str) -> Result<User, AuthError> {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[&self.audience]);
        validation.required_spec_claims.insert("iss".to_string());
        validation.required_spec_claims.insert("aud".to_string());
        validation.leeway = 5;

        let token_data =
            decode::<Claims>(token, &self.decoding_key, &validation).map_err(|error| {
                AuthError::InvalidJwt {
                    message: error.to_string(),
                }
            })?;
        let claims = token_data.claims;

        let mut roles_set: HashSet<String> = claims.roles.into_iter().collect();
        roles_set.insert("default".to_string());
        let roles: Vec<String> = roles_set.into_iter().collect();

        let attributes: HashMap<String, String> = claims
            .attributes
            .into_iter()
            .map(|(key, value)| {
                let value = value
                    .as_str()
                    .map(String::from)
                    .unwrap_or_else(|| serde_json::to_string(&value).unwrap_or_default());
                (key, value)
            })
            .collect();

        Ok(User {
            version: 1,
            username: claims.username,
            realm: claims.realm,
            roles,
            attributes,
            scopes: claims.scopes.unwrap_or_default(),
        })
    }
}

/// Parse an RSA public PEM and verify a JWT with exact issuer and audience checks.
pub fn decode_jwt(
    token: &str,
    public_key_pem: &[u8],
    issuer: &str,
    audience: &str,
) -> Result<User, AuthError> {
    JwtVerifier::new(public_key_pem, issuer, audience)?.decode(token)
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

/// HTTP client that calls auth-o-tron's `/authenticate` endpoint, verifies the
/// returned RS256 JWT, and caches the result.
#[derive(Clone)]
pub struct AuthClient {
    http: Client,
    url: String,
    verifier: JwtVerifier,
    cache: Cache<String, User>,
}

const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(60);
const DEFAULT_CACHE_CAPACITY: u64 = 10_000;

impl AuthClient {
    /// Build a client and parse its RSA public key once.
    pub fn new(
        url: &str,
        public_key_pem: &[u8],
        issuer: &str,
        audience: &str,
        timeout: Duration,
        cache_ttl: Option<Duration>,
        cache_capacity: Option<u64>,
    ) -> Result<Self, AuthError> {
        let verifier = JwtVerifier::new(public_key_pem, issuer, audience)?;
        let http = Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|error| AuthError::ServiceUnavailable {
                message: format!("failed to build HTTP client: {error}"),
            })?;

        let cache = Cache::builder()
            .max_capacity(cache_capacity.unwrap_or(DEFAULT_CACHE_CAPACITY))
            .time_to_live(cache_ttl.unwrap_or(DEFAULT_CACHE_TTL))
            .build();

        Ok(Self {
            http,
            url: url.to_string(),
            verifier,
            cache,
        })
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

        // Single-flight fill: moka runs the loader once per key, so concurrent
        // misses for the same credential share one upstream call instead of
        // stampeding the provider. Errors are not cached (no negative caching).
        self.cache
            .try_get_with(converted.clone(), self.fetch_user(converted))
            .await
            .map_err(|err| (*err).clone())
    }

    /// Cache loader for [`Self::authenticate`]: calls `/authenticate` and
    /// decodes the JWT. moka runs it at most once per key across concurrent callers.
    async fn fetch_user(&self, converted: String) -> Result<User, AuthError> {
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

        self.verifier.decode(jwt_token)
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

    const ISSUER: &str = "authotron-test";
    const AUDIENCE: &str = "authotron-consumer";
    const PRIVATE_KEY: &[u8] =
        include_bytes!("../../authotron/tests/fixtures/test-rsa-private.pem");
    const PUBLIC_KEY: &[u8] = include_bytes!("../../authotron/tests/fixtures/test-rsa-public.pem");

    #[derive(Debug, Serialize)]
    struct TestClaims {
        username: String,
        realm: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        roles: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        attributes: Option<HashMap<String, serde_json::Value>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        iss: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        aud: Option<String>,
        exp: usize,
    }

    fn claims() -> TestClaims {
        TestClaims {
            username: "testuser".to_string(),
            realm: "testrealm".to_string(),
            roles: Some(vec!["admin".to_string()]),
            attributes: None,
            iss: Some(ISSUER.to_string()),
            aud: Some(AUDIENCE.to_string()),
            exp: chrono::Utc::now().timestamp() as usize + 3600,
        }
    }

    fn make_token(claims: &TestClaims) -> String {
        jsonwebtoken::encode(
            &Header::new(Algorithm::RS256),
            claims,
            &EncodingKey::from_rsa_pem(PRIVATE_KEY).expect("valid test private key"),
        )
        .unwrap()
    }

    fn make_test_jwt() -> String {
        make_token(&claims())
    }

    fn decode(token: &str) -> Result<User, AuthError> {
        decode_jwt(token, PUBLIC_KEY, ISSUER, AUDIENCE)
    }

    fn test_client(url: &str) -> AuthClient {
        AuthClient::new(
            url,
            PUBLIC_KEY,
            ISSUER,
            AUDIENCE,
            Duration::from_secs(5),
            None,
            None,
        )
        .unwrap()
    }

    #[test]
    fn decode_valid_rs256_jwt() {
        let mut test_claims = claims();
        test_claims.attributes = Some(HashMap::from([(
            "org".to_string(),
            serde_json::json!("ecmwf"),
        )]));
        let user = decode(&make_token(&test_claims)).unwrap();

        assert_eq!(user.username, "testuser");
        assert_eq!(user.realm, "testrealm");
        assert!(user.roles.contains(&"admin".to_string()));
        assert!(user.roles.contains(&"default".to_string()));
        assert_eq!(user.attributes["org"], "ecmwf");
    }

    #[test]
    fn decode_injects_and_deduplicates_default_role() {
        let mut test_claims = claims();
        test_claims.roles = Some(vec!["default".to_string(), "admin".to_string()]);
        let user = decode(&make_token(&test_claims)).unwrap();
        assert_eq!(
            user.roles.iter().filter(|role| *role == "default").count(),
            1
        );
    }

    #[test]
    fn decode_injects_default_when_roles_are_missing() {
        let mut test_claims = claims();
        test_claims.roles = None;
        let user = decode(&make_token(&test_claims)).unwrap();
        assert_eq!(user.roles, vec!["default".to_string()]);
    }

    #[test]
    fn decode_converts_non_string_attributes() {
        let mut test_claims = claims();
        test_claims.attributes = Some(HashMap::from([
            ("string".to_string(), serde_json::json!("value")),
            ("number".to_string(), serde_json::json!(42)),
            ("boolean".to_string(), serde_json::json!(true)),
            ("null".to_string(), serde_json::Value::Null),
            ("array".to_string(), serde_json::json!([1, 2])),
            ("object".to_string(), serde_json::json!({"nested": "value"})),
        ]));
        let user = decode(&make_token(&test_claims)).unwrap();
        assert_eq!(user.attributes["string"], "value");
        assert_eq!(user.attributes["number"], "42");
        assert_eq!(user.attributes["boolean"], "true");
        assert_eq!(user.attributes["null"], "null");
        assert_eq!(user.attributes["array"], "[1,2]");
        assert_eq!(user.attributes["object"], r#"{"nested":"value"}"#);
    }

    #[test]
    fn rejects_claims_without_username() {
        #[derive(Serialize)]
        struct ClaimsWithoutUsername<'a> {
            realm: &'a str,
            iss: &'a str,
            aud: &'a str,
            exp: usize,
        }

        let token = jsonwebtoken::encode(
            &Header::new(Algorithm::RS256),
            &ClaimsWithoutUsername {
                realm: "testrealm",
                iss: ISSUER,
                aud: AUDIENCE,
                exp: chrono::Utc::now().timestamp() as usize + 3600,
            },
            &EncodingKey::from_rsa_pem(PRIVATE_KEY).unwrap(),
        )
        .unwrap();
        assert!(matches!(decode(&token), Err(AuthError::InvalidJwt { .. })));
    }

    #[test]
    fn rejects_wrong_or_missing_audience() {
        let mut wrong = claims();
        wrong.aud = Some("other-audience".to_string());
        assert!(matches!(
            decode(&make_token(&wrong)),
            Err(AuthError::InvalidJwt { .. })
        ));

        let mut missing = claims();
        missing.aud = None;
        assert!(matches!(
            decode(&make_token(&missing)),
            Err(AuthError::InvalidJwt { .. })
        ));
    }

    #[test]
    fn rejects_wrong_or_missing_issuer() {
        let mut wrong = claims();
        wrong.iss = Some("other-issuer".to_string());
        assert!(matches!(
            decode(&make_token(&wrong)),
            Err(AuthError::InvalidJwt { .. })
        ));

        let mut missing = claims();
        missing.iss = None;
        assert!(matches!(
            decode(&make_token(&missing)),
            Err(AuthError::InvalidJwt { .. })
        ));
    }

    #[test]
    fn rejects_token_signed_by_wrong_rsa_key() {
        let other_private_key =
            include_bytes!("../../authotron/tests/fixtures/test-rsa-private-2.pem");
        let token = jsonwebtoken::encode(
            &Header::new(Algorithm::RS256),
            &claims(),
            &EncodingKey::from_rsa_pem(other_private_key).unwrap(),
        )
        .unwrap();
        assert!(matches!(decode(&token), Err(AuthError::InvalidJwt { .. })));
    }

    #[test]
    fn rejects_hs256_token_without_fallback() {
        let token = jsonwebtoken::encode(
            &Header::new(Algorithm::HS256),
            &claims(),
            &EncodingKey::from_secret(b"legacy-shared-secret"),
        )
        .unwrap();
        assert!(matches!(decode(&token), Err(AuthError::InvalidJwt { .. })));
    }

    #[test]
    fn rejects_expired_token() {
        let mut expired = claims();
        expired.exp = chrono::Utc::now().timestamp() as usize - 3600;
        assert!(matches!(
            decode(&make_token(&expired)),
            Err(AuthError::InvalidJwt { .. })
        ));
    }

    #[test]
    fn malformed_public_key_is_typed_error() {
        let result = JwtVerifier::new(b"not a PEM key", ISSUER, AUDIENCE);
        assert!(matches!(result, Err(AuthError::InvalidPublicKey { .. })));
    }

    #[test]
    fn email_key_conversion_and_passthrough() {
        assert_eq!(
            convert_email_key("EmailKey user@test.com:abc123"),
            "Bearer abc123"
        );
        assert_eq!(convert_email_key("Bearer xyz"), "Bearer xyz");
        assert_eq!(
            convert_email_key("EmailKey user@example.com"),
            "EmailKey user@example.com"
        );
    }

    #[tokio::test]
    async fn successful_auth_verifies_issued_token() {
        let mut server = mockito::Server::new_async().await;
        let jwt = make_test_jwt();
        server
            .mock("GET", "/authenticate")
            .with_status(200)
            .with_header("Authorization", &format!("Bearer {jwt}"))
            .create_async()
            .await;

        let user = test_client(&server.url())
            .authenticate("Bearer sometoken")
            .await
            .unwrap();
        assert_eq!(user.username, "testuser");
    }

    #[tokio::test]
    async fn concurrent_auth_is_single_flight_and_cached() {
        let mut server = mockito::Server::new_async().await;
        let jwt = make_test_jwt();
        let mock = server
            .mock("GET", "/authenticate")
            .with_status(200)
            .with_header("Authorization", &format!("Bearer {jwt}"))
            .expect(1)
            .create_async()
            .await;
        let client = test_client(&server.url());

        let mut handles = Vec::new();
        for _ in 0..32 {
            let client = client.clone();
            handles.push(tokio::spawn(async move {
                client.authenticate("Bearer cached-token").await
            }));
        }
        for handle in handles {
            assert_eq!(handle.await.unwrap().unwrap().username, "testuser");
        }
        client.authenticate("Bearer cached-token").await.unwrap();
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn propagates_auth_failure() {
        let mut server = mockito::Server::new_async().await;
        server
            .mock("GET", "/authenticate")
            .with_status(401)
            .with_header("WWW-Authenticate", r#"Bearer realm="test""#)
            .create_async()
            .await;

        let result = test_client(&server.url()).authenticate("Bearer bad").await;
        assert!(matches!(result, Err(AuthError::Unauthorized { .. })));
    }

    #[tokio::test]
    async fn reports_unreachable_service() {
        let client = AuthClient::new(
            "http://127.0.0.1:1",
            PUBLIC_KEY,
            ISSUER,
            AUDIENCE,
            Duration::from_secs(1),
            None,
            None,
        )
        .unwrap();
        assert!(matches!(
            client.authenticate("Bearer token").await,
            Err(AuthError::ServiceUnavailable { .. })
        ));
    }

    #[tokio::test]
    async fn rejects_missing_non_bearer_and_invalid_response_tokens() {
        for authorization in [None, Some("Basic dXNlcjpwYXNz"), Some("Bearer invalid.jwt")] {
            let mut server = mockito::Server::new_async().await;
            let mut mock = server.mock("GET", "/authenticate").with_status(200);
            if let Some(value) = authorization {
                mock = mock.with_header("Authorization", value);
            }
            mock.create_async().await;

            let result = test_client(&server.url())
                .authenticate("Bearer input")
                .await;
            assert!(matches!(result, Err(AuthError::InvalidJwt { .. })));
        }
    }
}

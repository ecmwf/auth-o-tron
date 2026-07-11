// (C) Copyright 2024- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

use cached::Return;
#[allow(unused_imports)]
use cached::proc_macro::cached;
use jsonwebtoken::jwk::{JwkSet, KeyAlgorithm};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use tracing::{debug, info};

use crate::utils::cache::log_cache_hit;
use crate::utils::http_client::PROVIDER_HTTP_CLIENT;
use crate::{models::user::User, providers::Provider, utils::value::value_to_string};

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
#[derive(Debug, Serialize, Deserialize, Clone)]
struct Claims {
    sub: String,
    resource_access: Option<HashMap<String, RolesContainer>>,
    #[serde(default)]
    scope: String,
    realm_access: Option<RolesContainer>,
    entitlements: Option<Vec<String>>,
    /// Any additional claim fields we don't explicitly model.
    #[serde(flatten)]
    extra: HashMap<String, Value>,
}

/// Used to unify roles from different sections of the claim.
#[derive(Debug, Serialize, Deserialize, Clone)]
struct RolesContainer {
    roles: Vec<String>,
}

impl JWTProvider {
    /// Creates a new JWTProvider with the given config.
    pub fn new(config: &JWTAuthConfig) -> Self {
        info!(
            event_name = "providers.jwt.initialization",
            event_domain = "providers",
            provider_name = config.name.as_str(),
            realm = config.realm.as_str(),
            "creating JWT provider"
        );
        Self {
            config: config.clone(),
        }
    }
}

#[async_trait::async_trait]
impl Provider for JWTProvider {
    /// For consistency, we treat these tokens as "Bearer" type.
    fn get_type(&self) -> &str {
        "Bearer"
    }

    fn get_realm(&self) -> Option<&str> {
        Some(&self.config.realm)
    }

    /// Authenticates a token by decoding its header, fetching the right key, and validating.
    async fn authenticate(&self, token: &str) -> Result<User, String> {
        debug!(
            event_name = "providers.jwt.decode.started",
            event_domain = "providers",
            provider_name = self.config.name.as_str(),
            realm = self.config.realm.as_str(),
            "attempting JWT decode"
        );

        let header =
            decode_header(token).map_err(|e| format!("Failed to decode JWT header: {}", e))?;

        // Remote JWKS providers deliberately accept only asymmetric RSA
        // algorithms. Symmetric keys in a remote JWKS would give every party
        // that can verify a token the ability to mint one.
        let (algorithm, key_algorithm) = match header.alg {
            Algorithm::RS256 => (Algorithm::RS256, KeyAlgorithm::RS256),
            Algorithm::RS512 => (Algorithm::RS512, KeyAlgorithm::RS512),
            _ => return Err(format!("Unsupported JWT algorithm: {:?}", header.alg)),
        };

        // Fetch the already-parsed JWK set (cached).
        let jwks = get_certs(self.config.cert_uri.to_string()).await?;
        log_cache_hit(
            jwks.was_cached,
            "providers.jwt.jwks.cache.hit",
            |suppressed_count| {
                debug!(
                    event_name = "providers.jwt.jwks.cache.hit",
                    event_domain = "providers",
                    provider_name = self.config.name.as_str(),
                    realm = self.config.realm.as_str(),
                    cache_result = "hit",
                    cache_ttl_seconds = 600,
                    cache_key_type = "jwks_uri",
                    suppressed_count,
                    "JWT JWK set served from cache"
                );
            },
        );

        let kid = header.kid.ok_or("Missing 'kid' in JWT header")?;
        debug!(
            event_name = "providers.jwt.decode.kid_selected",
            event_domain = "providers",
            kid = kid.as_str(),
            "selected key identifier for JWT validation"
        );
        let jwk = jwks.find(&kid).ok_or(format!(
            "Failed to find certificate with matching kid {}",
            kid
        ))?;
        if jwk.common.key_algorithm != Some(key_algorithm) {
            return Err(format!(
                "JWK algorithm for kid {} must explicitly match {:?}",
                kid, algorithm
            ));
        }

        let decoding_key = DecodingKey::from_jwk(jwk)
            .map_err(|_| "Failed to create decoding key from JWK".to_string())?;

        let mut validation = Validation::new(algorithm);
        validation.validate_aud = false; // Possibly enable if you want to check "aud"

        let decoded = decode::<Claims>(token, &decoding_key, &validation)
            .map_err(|e| format!("Failed to decode JWT: {}", e))?;
        debug!(
            event_name = "providers.jwt.decode.success",
            event_domain = "providers",
            provider_name = self.config.name.as_str(),
            realm = self.config.realm.as_str(),
            alg = ?algorithm,
            "JWT decoded successfully"
        );

        let claims = decoded.claims;
        // Collect roles from various places
        let mut roles = claims.realm_access.map(|ra| ra.roles).unwrap_or_default();

        roles.extend(claims.entitlements.unwrap_or_default());
        if let Some(resource_access) = claims.resource_access {
            for (_, roles_container) in resource_access {
                roles.extend(roles_container.roles);
            }
        }

        let username = claims
            .extra
            .get("preferred_username")
            .and_then(|v| v.as_str())
            .unwrap_or(&claims.sub)
            .to_string();
        let additional_attributes: HashMap<String, String> = claims
            .extra
            .into_iter()
            .map(|(key, value)| (key, value_to_string(value)))
            .collect();
        let attributes = if additional_attributes.is_empty() {
            None
        } else {
            Some(additional_attributes)
        };

        // Build the final `User` object
        let user = User::new(
            self.config.realm.to_string(),
            username,
            Some(roles),
            attributes,
            // We store the 'scope' claim in user attributes under the provider name
            Some(HashMap::from([(
                self.config.name.clone(),
                claims
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
#[cfg_attr(
    not(test),
    cached(
        time = 600,
        size = 100_000,
        result = true,
        with_cached_flag = true,
        sync_writes = "default"
    )
)]
pub async fn get_certs(cert_uri: String) -> Result<Return<JwkSet>, String> {
    debug!(
        event_name = "providers.jwt.jwks.fetch.started",
        event_domain = "providers",
        cert_uri = cert_uri.as_str(),
        "fetching JWK set from certificate URI"
    );
    let res = PROVIDER_HTTP_CLIENT
        .get(&cert_uri)
        .send()
        .await
        .map_err(|e| format!("Failed to download certificates: {}", e))?;

    if res.status().is_success() {
        let jwks = res
            .json::<JwkSet>()
            .await
            .map_err(|e| format!("Failed to parse certificate JSON: {}", e))?;
        Ok(Return::new(jwks))
    } else {
        Err(format!("Failed to download certificates: {}", res.status()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::Server;
    use serde_json::json;
    use tokio;

    /// Test that `get_certs` returns the expected JSON when the endpoint is successful.
    #[tokio::test]
    async fn test_get_certs_success() {
        let jwks = r#"{"keys": []}"#;
        // Create an async mock server.
        let mut server = Server::new_async().await;
        let m = server
            .mock("GET", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(jwks)
            .create_async()
            .await;
        let url = server.url();
        let result = get_certs(url.to_string()).await;
        m.assert_async().await;
        assert!(result.is_ok());

        let actual = result.expect("JWKS should parse");
        assert!(actual.keys.is_empty());
    }

    /// Test that `get_certs` returns an error when the endpoint returns a failure status.
    #[tokio::test]
    async fn test_get_certs_failure() {
        let mut server = Server::new_async().await;
        let m = server
            .mock("GET", "/")
            .with_status(500)
            .with_body("Internal Server Error")
            .create_async()
            .await;
        let url = server.url();
        let result = get_certs(url.to_string()).await;
        m.assert_async().await;
        assert!(result.is_err());
    }

    /// Test that JWTProvider::authenticate fails with an invalid token.
    #[tokio::test]
    async fn test_jwt_provider_invalid_token() {
        let config = JWTAuthConfig {
            cert_uri: "http://127.0.0.1:9/must-not-be-fetched".to_string(),
            realm: "test".to_string(),
            name: "TestJWT".to_string(),
            iam_realm: "test".to_string(),
        };
        let provider = JWTProvider::new(&config);

        let result = provider.authenticate("invalid.token").await;

        assert!(result.is_err());
    }

    /// Symmetric JWT algorithms are rejected before any remote JWKS is used.
    #[tokio::test]
    async fn test_jwt_provider_rejects_hs512() {
        let config = JWTAuthConfig {
            cert_uri: "http://127.0.0.1:9/must-not-be-fetched".to_string(),
            realm: "test".to_string(),
            name: "TestJWT".to_string(),
            iam_realm: "test".to_string(),
        };
        let provider = JWTProvider::new(&config);
        let claims = json!({
            "sub": "user1",
            "scope": "read write",
            "exp": 4102444800usize,
        });
        let mut header = jsonwebtoken::Header::new(Algorithm::HS512);
        header.kid = Some("testkid".to_string());
        let token = jsonwebtoken::encode(
            &header,
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(b"secret"),
        )
        .expect("Failed to create token");

        let error = provider.authenticate(&token).await.unwrap_err();

        assert!(error.contains("Unsupported JWT algorithm: HS512"));
    }

    #[tokio::test]
    async fn test_rs256_token_without_scope_authenticates_with_empty_scope() {
        const PRIVATE_KEY: &str = include_str!("../../tests/fixtures/rsa-private-key.pem");

        let encoding_key = jsonwebtoken::EncodingKey::from_rsa_pem(PRIVATE_KEY.as_bytes())
            .expect("test RSA key should parse");
        let mut jwk = jsonwebtoken::jwk::Jwk::from_encoding_key(&encoding_key, Algorithm::RS256)
            .expect("public JWK should be derived");
        jwk.common.key_id = Some("rs256-test".to_string());

        let mut server = Server::new_async().await;
        let mock = server
            .mock("GET", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(json!({"keys": [jwk]}).to_string())
            .create_async()
            .await;
        let provider = JWTProvider::new(&JWTAuthConfig {
            cert_uri: server.url(),
            realm: "test".to_string(),
            name: "TestJWT".to_string(),
            iam_realm: "test".to_string(),
        });
        let claims = json!({
            "sub": "user-without-scope",
            "preferred_username": "alice",
            "custom": "preserved",
            "exp": 4102444800usize,
        });
        let mut header = jsonwebtoken::Header::new(Algorithm::RS256);
        header.kid = Some("rs256-test".to_string());
        let token = jsonwebtoken::encode(&header, &claims, &encoding_key)
            .expect("RS256 token should encode");

        let user = provider
            .authenticate(&token)
            .await
            .expect("RS256 token without scope should authenticate");

        mock.assert_async().await;
        assert_eq!(user.username, "alice");
        assert_eq!(user.scopes.get("TestJWT"), Some(&Vec::<String>::new()));
        assert_eq!(
            user.attributes.get("custom"),
            Some(&"preserved".to_string())
        );
    }

    #[test]
    fn test_claims_default_missing_scope_to_empty() {
        let claims: Claims = serde_json::from_value(json!({
            "sub": "user-without-scope",
            "exp": 4102444800usize,
        }))
        .expect("scope should be optional");

        assert!(claims.scope.is_empty());
    }
}

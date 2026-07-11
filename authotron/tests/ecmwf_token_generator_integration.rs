use authotron::config::{Config, ConfigV2};
use axum::http::{Method, StatusCode};
use figment::{
    Figment,
    providers::{Format, Yaml},
};
use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use mockito::{Matcher, Server};
use serde_json::{Value, json};
use tower::ServiceExt;

mod common;

use common::{build_app, decode_claims, request_with_bearer};

const CLIENT_ID: &str = "polytope";
const CLIENT_SECRET: &str = "polytope-secret";
const TEST_HOST: &str = "127.0.0.1";
const TEST_PORT: u16 = 8082;
const FUTURE_EXP: i64 = 4_102_444_800; // Far in the future to avoid flakiness.

fn build_config(generator_url: &str, cert_url: &str) -> ConfigV2 {
    let yaml = format!(
        r#"
version: "2.0.0"
logging:
  level: "warn"
  format: "json"
auth:
  timeout_in_ms: 3000
providers:
  - name: "ECMWF Token Generator"
    type: "ecmwf-token-generator"
    cert_uri: "{cert_url}"
    client_id: "{CLIENT_ID}"
    client_secret: "{CLIENT_SECRET}"
    token_generator_url: "{generator_url}"
    realm: "ecmwf"
augmenters: []
jwt:
  exp: 3600
  iss: authotron-test
  aud: authotron-consumer
  kid: test-key
  private_key: test-key-injected-by-test
server:
  host: "{TEST_HOST}"
  port: {TEST_PORT}
metrics:
  enabled: false
"#
    );

    let config: Config = Figment::new()
        .merge(Yaml::string(&yaml))
        .extract()
        .expect("Failed to parse integration test config");

    let Config::ConfigV2(mut cfg) = config else {
        panic!("expected ConfigV2");
    };
    cfg.jwt.private_key = include_str!("fixtures/test-rsa-private.pem").to_string();
    cfg
}

fn rsa_encoding_key() -> EncodingKey {
    EncodingKey::from_rsa_pem(include_bytes!("fixtures/rsa-private-key.pem"))
        .expect("test RSA key should parse")
}

fn build_jwks(kid: &str, encoding_key: &EncodingKey) -> String {
    let mut jwk = Jwk::from_encoding_key(encoding_key, Algorithm::RS256)
        .expect("public JWK should be derived");
    jwk.common.key_id = Some(kid.to_string());
    json!({ "keys": [jwk] }).to_string()
}

fn encode_hs512_token(claims: Value, kid: &str, secret: &[u8]) -> String {
    let mut header = Header::new(Algorithm::HS512);
    header.kid = Some(kid.to_string());
    encode(&header, &claims, &EncodingKey::from_secret(secret)).expect("Failed to encode JWT")
}

fn encode_rs256_token(claims: Value, kid: &str, encoding_key: &EncodingKey) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_string());
    encode(&header, &claims, encoding_key).expect("Failed to encode JWT")
}

fn example_claims(scope: &str) -> Value {
    json!({
        "sub": "adam",
        "scope": scope,
        "exp": FUTURE_EXP,
        "iat": FUTURE_EXP - 10,
        "iss": "https://SomeECMWFAuthServer/auth/realms/ecmwf",
        "jti": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "azp": CLIENT_ID,
        "client_id": CLIENT_ID,
        "session_state": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "sid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "typ": "Offline",
        "username": "demo-user",
        "realm_access": { "roles": ["user", "admin"] },
    })
}

#[tokio::test]
async fn integration_ecmwf_token_generator_exchanges_refresh_token() {
    let mut server = Server::new_async().await;
    let kid = "access-key";
    let signing_key = rsa_encoding_key();
    let jwks_body = build_jwks(kid, &signing_key);

    // Mock JWKS (certs) endpoint
    let jwks_mock = server
        .mock("GET", "/jwks")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(jwks_body)
        .expect(1)
        .create_async()
        .await;

    // Mock token validation endpoint
    let refresh_claims = example_claims("offline_access email");
    // Encode refresh token with a different secret so the first JWT validation fails and triggers exchange.
    let refresh_token = encode_hs512_token(refresh_claims, "refresh-key", b"wrong-secret");

    let validate_refresh_mock = server
        .mock("POST", "/validate-token")
        .match_header("content-type", "application/json")
        .match_body(Matcher::PartialJson(json!({
            "token": refresh_token.clone(),
            "client_id": CLIENT_ID
        })))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"active": true}"#)
        .create_async()
        .await;

    // Mock token exchange endpoint
    let exchanged_claims = example_claims("offline_access email profile");
    let exchanged_access_token = encode_rs256_token(exchanged_claims, kid, &signing_key);
    let exchange_mock = server
        .mock("POST", "/admin/refresh-access-token")
        .match_header("content-type", "application/json")
        .match_body(Matcher::PartialJson(json!({
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "refresh_token": refresh_token.clone()
        })))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(
            json!({
                "access_token": exchanged_access_token,
                "expires_in": 300
            })
            .to_string(),
        )
        .create_async()
        .await;

    let (app, config) = build_app(build_config(
        &server.url(),
        &format!("{}/jwks", server.url()),
    ))
    .await;

    // Perform authentication request
    let response = app
        .clone()
        .oneshot(request_with_bearer(
            "/authenticate",
            &refresh_token,
            Method::GET,
        ))
        .await
        .expect("request should succeed");

    assert_eq!(response.status(), StatusCode::OK);

    let auth_header = response
        .headers()
        .get("Authorization")
        .expect("Authorization header missing")
        .to_str()
        .expect("Authorization header not valid UTF-8");
    let token = auth_header
        .strip_prefix("Bearer ")
        .expect("Authorization header missing Bearer prefix");

    let claims = decode_claims(token, &config.jwt);
    assert_eq!(claims.claims.realm.as_deref(), Some("ecmwf"));
    assert!(claims.claims.roles.contains(&"user".to_string()));

    jwks_mock.assert_async().await;
    validate_refresh_mock.assert_async().await;
    exchange_mock.assert_async().await;
}

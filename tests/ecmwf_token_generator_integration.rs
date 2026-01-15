use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use authotron::auth::Auth;
use authotron::config::{AuthConfig, Config, ConfigV1};
use authotron::metrics::Metrics;
use authotron::routes::create_router;
use authotron::state::AppState;
use authotron::store::create_store;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Method, Request, StatusCode};
use axum::Router;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use figment::{Figment, providers::{Format, Yaml}};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation, decode, encode};
use mockito::{Matcher, Server};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tower::ServiceExt;

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Claims {
    sub: Option<String>,
    username: Option<String>,
    exp: Option<i64>,
    iss: Option<String>,
    roles: Vec<String>,
    realm: Option<String>,
}

const CLIENT_ID: &str = "polytope";
const CLIENT_SECRET: &str = "polytope-secret";
const TEST_BIND_ADDRESS: &str = "127.0.0.1:8082";
const FUTURE_EXP: i64 = 4_102_444_800; // Far in the future to avoid flakiness.

fn build_config(generator_url: &str, cert_url: &str) -> ConfigV1 {
    let yaml = format!(
        r#"
version: "1.0.0"
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
store:
  enabled: false
services: []
jwt:
  exp: 3600
  iss: authotron-test
  secret: test-secret
bind_address: {TEST_BIND_ADDRESS}
"#
    );

    let config: Config = Figment::new()
        .merge(Yaml::string(&yaml))
        .extract()
        .expect("Failed to parse integration test config");

    match config {
        Config::ConfigV1(cfg) => cfg,
    }
}

async fn build_app(config: ConfigV1) -> (Router, Arc<ConfigV1>) {
    let config = Arc::new(config);
    let store = create_store(&config.store).await;
    let auth = Arc::new(Auth::new(
        &config.providers,
        &config.augmenters,
        store.clone(),
        AuthConfig {
            timeout_in_ms: config.auth.timeout_in_ms,
        },
    ));
    let metrics = Metrics::new();

    let state = AppState {
        config: config.clone(),
        auth,
        store,
        metrics,
    };

    (create_router(state), config)
}

fn bearer_request(path: &str, token: &str, method: Method) -> Request<Body> {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("Authorization", format!("Bearer {}", token))
        .body(Body::empty())
        .expect("failed to build request");

    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            0,
        )));

    request
}

fn build_jwks(kid: &str, secret: &[u8]) -> String {
    json!({
        "keys": [
            {
                "kty": "oct",
                "k": URL_SAFE_NO_PAD.encode(secret),
                "alg": "HS512",
                "kid": kid,
            }
        ]
    })
    .to_string()
}

fn encode_hs512_token(claims: Value, kid: &str, secret: &[u8]) -> String {
    let mut header = Header::new(Algorithm::HS512);
    header.kid = Some(kid.to_string());
    encode(&header, &claims, &EncodingKey::from_secret(secret))
        .expect("Failed to encode JWT")
}

fn decode_response_token(token: &str, secret: &str) -> TokenData<Claims> {
    let mut validation = Validation::default();
    validation.validate_aud = false;

    decode(
        token,
        &DecodingKey::from_secret(secret.as_ref()),
        &validation,
    )
    .expect("JWT should decode")
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
    let signing_secret = b"super-secret-signing-key";
    let jwks_body = build_jwks(kid, signing_secret);

    // Mock JWKS (certs) endpoint
    let jwks_mock = server
        .mock("GET", "/jwks")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(jwks_body)
        .expect(2)
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
    let exchanged_access_token = encode_hs512_token(exchanged_claims, kid, signing_secret);
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
        .with_body(json!({
            "access_token": exchanged_access_token,
            "expires_in": 300
        }).to_string())
        .create_async()
        .await;

    let (app, config) = build_app(build_config(&server.url(), &format!("{}/jwks", server.url()))).await;
    
    // Perform authentication request
    let response = app
        .clone()
        .oneshot(bearer_request("/authenticate", &refresh_token, Method::GET))
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

    let claims = decode_response_token(token, &config.jwt.secret);
    assert_eq!(claims.claims.realm.as_deref(), Some("ecmwf"));
    assert!(claims.claims.roles.contains(&"user".to_string()));

    jwks_mock.assert_async().await;
    validate_refresh_mock.assert_async().await;
    exchange_mock.assert_async().await;
}

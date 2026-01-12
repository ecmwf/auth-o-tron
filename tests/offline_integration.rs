use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use authotron::auth::Auth;
use authotron::config::{AuthConfig, Config, ConfigV1};
use authotron::metrics::Metrics;
use authotron::routes::create_router;
use authotron::state::AppState;
use authotron::store::create_store;
use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Method, Request, StatusCode};
use base64::{Engine as _, engine::general_purpose};
use figment::{
    Figment,
    providers::{Format, Yaml},
};
use jsonwebtoken::{DecodingKey, TokenData, Validation, decode};
use serde::{Deserialize, Serialize};
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

const TEST_CONFIG: &str = r#"
version: "1.0.0"
logging:
  level: "debug"
  format: "json"
auth:
  timeout_in_ms: 3000
providers:
  - name: "ECMWF API Provider"
    type: "ecmwf-api"
    uri: https://api.ecmwf.int/v1
    realm: "ecmwf"
  - name: "Plain provider"
    type: "plain"
    realm: "ecmwf"
    users:
        - username: adam
          password: admin
          roles:
            - user1
        - username: eve
          password: admin
          roles:
            - superuser
  - name: "Plain provider"
    type: "plain"
    realm: "other"
    users:
        - username: adam
          password: other
          roles:
            - user

augmenters:
  - name: "Polytope plain admin augmenter"
    type: "plain"
    realm: "ecmwf"
    roles:
        admin:
            - eve
            - adam
        
store:
  enabled: false
services: []
jwt:
  exp: 3600
  iss: authotron-test
  secret: test-secret
bind_address: 127.0.0.1:8081
"#;

fn load_test_config() -> ConfigV1 {
    let config: Config = Figment::new()
        .merge(Yaml::string(TEST_CONFIG))
        .extract()
        .expect("Failed to parse test config YAML");

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

fn build_request(path: &str, credentials: &str, method: Method) -> Request<Body> {
    let encoded = general_purpose::STANDARD.encode(credentials);
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("Authorization", format!("Basic {}", encoded))
        .body(Body::empty())
        .expect("failed to build request");

    request.extensions_mut().insert(ConnectInfo(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        0,
    )));

    request
}

#[tokio::test]
async fn integration_plain_auth_flow() {
    let (app, config) = build_app(load_test_config()).await;

    let response = app
        .clone()
        .oneshot(build_request("/authenticate", "adam:admin", Method::GET))
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

    let mut validation = Validation::default();
    validation.validate_aud = false;

    let claims: TokenData<Claims> = decode(
        token,
        &DecodingKey::from_secret(config.jwt.secret.as_ref()),
        &validation,
    )
    .expect("JWT should decode");

    assert_eq!(claims.claims.roles.len(), 2);
    assert!(claims.claims.roles.iter().any(|r| r == "user"));
    assert!(claims.claims.roles.iter().any(|r| r == "admin"));
}

#[tokio::test]
async fn integration_plain_auth_failure() {
    let (app, _config) = build_app(load_test_config()).await;

    let response = app
        .clone()
        .oneshot(build_request(
            "/authenticate",
            "adam:wrongpassword",
            Method::GET,
        ))
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn integration_plain_auth_realm_separation() {
    let (app, config) = build_app(load_test_config()).await;

    let response = app
        .clone()
        .oneshot(build_request("/authenticate", "adam:other", Method::GET))
        .await
        .expect("request should complete");

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

    let mut validation = Validation::default();
    validation.validate_aud = false;

    let claims: TokenData<Claims> = decode(
        token,
        &DecodingKey::from_secret(config.jwt.secret.as_ref()),
        &validation,
    )
    .expect("JWT should decode");

    assert_eq!(claims.claims.roles.len(), 1);
    assert!(
        claims.claims.roles.iter().all(|r| r == "user"),
        "adam should only be 'user' in 'other' realm, but got roles: {:?}",
        claims.claims.roles
    );
}

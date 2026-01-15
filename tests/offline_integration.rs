use authotron::config::{Config, ConfigV1};
use axum::http::{Method, StatusCode};
use figment::{
    Figment,
    providers::{Format, Yaml},
};
use tower::ServiceExt;

mod common;

use common::{build_app, decode_claims, request_with_basic};

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
            - user
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

#[tokio::test]
async fn integration_plain_auth_flow() {
    let (app, config) = build_app(load_test_config()).await;

    let response = app
        .clone()
        .oneshot(request_with_basic(
            "/authenticate",
            "adam:admin",
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

    let claims = decode_claims(token, &config.jwt.secret);

    assert_eq!(claims.claims.roles.len(), 2);
    assert!(claims.claims.roles.iter().any(|r| r == "user"));
    assert!(claims.claims.roles.iter().any(|r| r == "admin"));
}

#[tokio::test]
async fn integration_plain_auth_failure() {
    let (app, _config) = build_app(load_test_config()).await;

    let response = app
        .clone()
        .oneshot(request_with_basic(
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
        .oneshot(request_with_basic(
            "/authenticate",
            "adam:other",
            Method::GET,
        ))
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

    let claims = decode_claims(token, &config.jwt.secret);

    assert_eq!(claims.claims.roles.len(), 1);
    assert!(
        claims.claims.roles.iter().all(|r| r == "user"),
        "Expected only 'user' role but got {:?}",
        claims.claims.roles
    );
}

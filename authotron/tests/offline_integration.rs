use authotron::config::{Config, ConfigV2};
use axum::http::{Method, StatusCode};
use figment::{
    Figment,
    providers::{Format, Yaml},
};
use tower::ServiceExt;

mod common;

use common::{build_app, decode_claims, request_with_basic};

const TEST_CONFIG: &str = r#"
version: "2.0.0"
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
        
jwt:
  exp: 3600
  iss: authotron-test
  aud: authotron-consumer
  kid: test-key
  private_key: test-key-injected-by-test
server:
  host: "127.0.0.1"
  port: 8081
metrics:
  enabled: false
"#;

fn load_test_config() -> ConfigV2 {
    let config: Config = Figment::new()
        .merge(Yaml::string(TEST_CONFIG))
        .extract()
        .expect("Failed to parse test config YAML");

    let Config::ConfigV2(mut cfg) = config else {
        panic!("expected ConfigV2");
    };
    cfg.jwt.private_key = include_str!("fixtures/test-rsa-private.pem").to_string();
    cfg
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

    let claims = decode_claims(token, &config.jwt);
    assert_eq!(claims.claims.iss.as_deref(), Some(config.jwt.iss.as_str()));
    assert_eq!(claims.claims.aud.as_deref(), Some(config.jwt.aud.as_str()));

    let public_keys = [authotron_client::JwtPublicKey::new(
        &config.jwt.kid,
        include_bytes!("fixtures/test-rsa-public.pem"),
    )];
    let verified_user =
        authotron_client::decode_jwt(token, &public_keys, &config.jwt.iss, &config.jwt.aud)
            .expect("authotron-client should verify the issued RS256 token");
    assert_eq!(verified_user.username, "adam");

    assert_eq!(claims.claims.roles.len(), 2);
    assert!(claims.claims.roles.iter().any(|r| r == "user"));
    assert!(claims.claims.roles.iter().any(|r| r == "admin"));
}

#[tokio::test]
async fn integration_whoami_returns_identity() {
    let (app, _config) = build_app(load_test_config()).await;

    let response = app
        .clone()
        .oneshot(request_with_basic("/whoami", "adam:admin", Method::GET))
        .await
        .expect("request should succeed");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("cache-control")
            .expect("Cache-Control header missing")
            .to_str()
            .expect("Cache-Control header not valid UTF-8"),
        "no-store"
    );

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body should be readable");
    let user: serde_json::Value = serde_json::from_slice(&body).expect("body should be valid JSON");

    assert_eq!(user["username"], "adam");
    assert_eq!(user["realm"], "ecmwf");
    let mut roles: Vec<&str> = user["roles"]
        .as_array()
        .expect("roles should be an array")
        .iter()
        .map(|r| r.as_str().expect("roles should be strings"))
        .collect();
    roles.sort_unstable();
    assert_eq!(
        roles,
        ["admin", "user"],
        "expected the exact role set granted by the provider and augmenter"
    );
}

#[tokio::test]
async fn integration_whoami_requires_authentication() {
    let (app, _config) = build_app(load_test_config()).await;

    let response = app
        .clone()
        .oneshot(request_with_basic(
            "/whoami",
            "adam:wrongpassword",
            Method::GET,
        ))
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
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

    let claims = decode_claims(token, &config.jwt);

    assert_eq!(claims.claims.roles.len(), 1);
    assert!(
        claims.claims.roles.iter().all(|r| r == "user"),
        "Expected only 'user' role but got {:?}",
        claims.claims.roles
    );
}

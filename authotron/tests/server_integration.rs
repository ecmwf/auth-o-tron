#[allow(dead_code)]
mod common;

use authotron::config::{Config, ConfigV2, MetricsConfig, ServerConfig};
use authotron::startup;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use figment::{
    Figment,
    providers::{Format, Yaml},
};
use std::sync::Arc;
use tower::ServiceExt;

fn base_config(server_port: u16, metrics_enabled: bool, metrics_port: u16) -> ConfigV2 {
    let yaml = r#"
version: "2.0.0"
store:
  enabled: false
providers: []
augmenters: []
server:
  port: 0
jwt:
  iss: "issuer"
  aud: "audience"
  exp: 3600
  private_key: "test-key-injected-by-test"
logging:
  level: "warn"
  format: "console"
services: []
    "#;

    let config: Config = Figment::new()
        .merge(Yaml::string(yaml))
        .extract()
        .expect("Failed to parse config");

    let Config::ConfigV2(mut cfg) = config else {
        panic!("expected ConfigV2");
    };

    cfg.server = ServerConfig {
        host: "127.0.0.1".to_owned(),
        port: server_port,
    };
    cfg.metrics = MetricsConfig {
        enabled: metrics_enabled,
        port: metrics_port,
    };

    cfg.jwt.private_key = include_str!("fixtures/test-rsa-private.pem").to_string();
    cfg
}

#[tokio::test]
async fn startup_rejects_port_collision() {
    let config = Arc::new(base_config(9500, true, 9500));
    let result = startup::run(config).await;

    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("must be different"),
        "expected port collision error, got: {err}"
    );
}

#[tokio::test]
async fn startup_rejects_malformed_rsa_private_key() {
    let mut config = base_config(0, false, 0);
    config.jwt.private_key = "not a PEM key".to_string();

    let error = match startup::build_app(Arc::new(config)).await {
        Ok(_) => panic!("malformed private key must fail startup"),
        Err(error) => error,
    };
    assert!(
        error.to_string().contains("invalid JWT RSA private key"),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn homepage_returns_html_with_version() {
    let config = base_config(0, false, 0);
    let (app, _) = common::build_app(config).await;

    let response = app
        .oneshot(Request::get("/").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let headers = response.headers();
    assert_eq!(
        headers.get("content-type").unwrap(),
        "text/html; charset=utf-8"
    );

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let html = String::from_utf8(body.to_vec()).unwrap();
    assert!(
        html.contains(env!("CARGO_PKG_VERSION")),
        "homepage should contain the crate version"
    );
    assert!(
        !html.contains("{{version}}"),
        "version placeholder should be replaced"
    );
}

#[tokio::test]
async fn http_metrics_record_matched_route_and_status() {
    let config = base_config(0, false, 0);
    let (app, _, state) = common::build_app_with_state(config).await;

    let response = app
        .oneshot(Request::get("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let output = state.metrics.render().expect("render ok");
    assert!(
        output.contains(
            r#"authotron_http_requests_total{method="GET",route="/",status_code="200"} 1"#
        ),
        "expected the homepage request counted under its matched route:\n{output}"
    );
    assert!(
        output.contains(r#"authotron_http_request_duration_seconds_count{method="GET",route="/"}"#),
        "expected a duration observation for the matched route:\n{output}"
    );
    assert!(
        output.contains(r#"authotron_http_requests_in_flight{method="GET"} 0"#),
        "in-flight gauge must return to zero after the request completes:\n{output}"
    );
}

#[tokio::test]
async fn http_metrics_collapse_unrouted_requests() {
    let config = base_config(0, false, 0);
    let (app, _, state) = common::build_app_with_state(config).await;

    let response = app
        .oneshot(Request::get("/does-not-exist").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let output = state.metrics.render().expect("render ok");
    assert!(
        output.contains(
            r#"authotron_http_requests_total{method="GET",route="unmatched",status_code="404"} 1"#
        ),
        "unrouted requests must collapse into route=\"unmatched\":\n{output}"
    );
}

#[tokio::test]
async fn logo_returns_png() {
    let config = base_config(0, false, 0);
    let (app, _) = common::build_app(config).await;

    let response = app
        .oneshot(
            Request::get("/static/logo.png")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers().get("content-type").unwrap(), "image/png");
}

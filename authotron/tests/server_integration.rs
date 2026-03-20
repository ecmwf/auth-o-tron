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
  exp: 3600
  secret: "secret"
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

use authotron::config::{Config, ConfigV2, MetricsConfig, ServerConfig};
use authotron::startup;
use figment::{
    Figment,
    providers::{Format, Yaml},
};
use std::sync::Arc;

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

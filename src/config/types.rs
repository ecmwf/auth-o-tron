use figment::Figment;
use figment::providers::{Env, Format, Yaml};
use schemars::{JsonSchema, schema_for};
use serde::{Deserialize, Serialize};
use std::env;

use super::logging::LoggingConfig;
use super::store::StoreConfig;
use crate::augmenters::AugmenterConfig;
use crate::providers::ProviderConfig;

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(tag = "version")]
pub enum Config {
    #[serde(rename = "1.0.0")]
    ConfigV1(ConfigV1),
    #[serde(rename = "2.0.0")]
    ConfigV2(ConfigV2),
}

#[derive(Deserialize, Serialize, Debug, JsonSchema)]
pub struct ConfigV1 {
    pub store: StoreConfig,
    pub services: Vec<ServiceConfig>,
    pub providers: Vec<ProviderConfig>,
    #[serde(default)]
    pub augmenters: Vec<AugmenterConfig>,
    pub bind_address: String,
    pub jwt: JWTConfig,
    pub include_legacy_headers: Option<bool>,
    pub logging: LoggingConfig,
    #[serde(default)]
    pub auth: AuthConfig,
}

#[derive(Deserialize, Serialize, Debug, JsonSchema)]
pub struct ConfigV2 {
    pub store: StoreConfig,
    pub services: Vec<ServiceConfig>,
    pub providers: Vec<ProviderConfig>,
    #[serde(default)]
    pub augmenters: Vec<AugmenterConfig>,
    pub server: ServerConfig,
    #[serde(default)]
    pub metrics: MetricsConfig,
    pub jwt: JWTConfig,
    pub include_legacy_headers: Option<bool>,
    pub logging: LoggingConfig,
    #[serde(default)]
    pub auth: AuthConfig,
}

fn default_host() -> String {
    "0.0.0.0".to_owned()
}

#[derive(Deserialize, Serialize, Debug, JsonSchema)]
pub struct ServerConfig {
    #[serde(default = "default_host")]
    pub host: String,
    pub port: u16,
}

fn default_metrics_enabled() -> bool {
    true
}

fn default_metrics_port() -> u16 {
    9090
}

/// Controls the dedicated metrics/health server on a separate port.
#[derive(Deserialize, Serialize, Debug, JsonSchema)]
pub struct MetricsConfig {
    #[serde(default = "default_metrics_enabled")]
    pub enabled: bool,
    #[serde(default = "default_metrics_port")]
    pub port: u16,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        MetricsConfig {
            enabled: default_metrics_enabled(),
            port: default_metrics_port(),
        }
    }
}

/// Loads versioned config from `AOT_CONFIG_PATH` (default `./config.yaml`),
/// merges `AOT_`-prefixed env overrides, and converts v1 configs to v2.
pub fn load_config() -> ConfigV2 {
    let config_path = env::var("AOT_CONFIG_PATH").unwrap_or_else(|_| "./config.yaml".to_owned());

    let figment = Figment::new()
        .merge(Yaml::file(config_path))
        .merge(Env::prefixed("AOT_").split("__"));

    let config = match figment.extract::<Config>() {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("Error loading configuration: {}", e);
            std::process::exit(1);
        }
    };

    match config {
        Config::ConfigV1(v1) => convert_v1_to_v2(v1),
        Config::ConfigV2(v2) => v2,
    }
}

fn convert_v1_to_v2(v1: ConfigV1) -> ConfigV2 {
    let (host, port) = parse_bind_address(&v1.bind_address);
    ConfigV2 {
        store: v1.store,
        services: v1.services,
        providers: v1.providers,
        augmenters: v1.augmenters,
        server: ServerConfig { host, port },
        metrics: MetricsConfig::default(),
        jwt: v1.jwt,
        include_legacy_headers: v1.include_legacy_headers,
        logging: v1.logging,
        auth: v1.auth,
    }
}

fn parse_bind_address(addr: &str) -> (String, u16) {
    let colon_pos = addr
        .rfind(':')
        .unwrap_or_else(|| panic!("bind_address must be in host:port format, got: {addr}"));
    let host = &addr[..colon_pos];
    if host.is_empty() {
        panic!("bind_address has empty host, got: {addr}");
    }
    let port = addr[colon_pos + 1..]
        .parse::<u16>()
        .unwrap_or_else(|_| panic!("invalid port in bind_address: {addr}"));
    (host.to_owned(), port)
}

/// Print the JSON schema for the configuration to stdout.
pub fn print_schema() {
    let schema = schema_for!(Config);
    println!("{}", serde_json::to_string_pretty(&schema).unwrap());
}

/// A simple definition for JWT usage in tokens.
#[derive(Deserialize, Serialize, Debug, JsonSchema)]
pub struct JWTConfig {
    pub iss: String,
    pub aud: Option<String>,
    pub exp: i64,
    pub secret: String,
}

/// A declaration of services we might need (e.g., to store scopes).
#[derive(Deserialize, Serialize, JsonSchema, Debug)]
pub struct ServiceConfig {
    pub name: String,
    pub scopes: Vec<String>,
}

/// Returns the default timeout value (5000 ms).
fn default_timeout_in_ms() -> u64 {
    5000
}

/// Configuration for the authentication timeout.
/// This is used for select_ok operations in the auth module,
/// and we kill ongoing futures if they take too long.
///
/// Note:
/// - The attribute `#[serde(default = "default_timeout_in_ms")]` ensures that if
///   the `timeout_in_ms` key is missing during deserialization, it gets set to 5000.
/// - However, when the entire auth section is omitted, Serde calls `AuthConfig::default()`.
///   Therefore, we manually implement Default for AuthConfig so that AuthConfig::default()
///   returns a timeout of 5000 instead of the primitive default (0).
#[derive(Deserialize, Serialize, Debug, JsonSchema, Clone)]
pub struct AuthConfig {
    #[serde(default = "default_timeout_in_ms")]
    pub timeout_in_ms: u64,
}

// Manually implement Default for AuthConfig so that AuthConfig::default()
// returns a timeout_in_ms of 5000 ms.
impl Default for AuthConfig {
    fn default() -> Self {
        AuthConfig {
            timeout_in_ms: default_timeout_in_ms(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use figment::providers::Yaml;
    use serde_json;

    /// Test that the printed JSON schema is valid JSON and represents an object.
    #[test]
    fn test_print_schema_parses() {
        let schema = schema_for!(Config);
        let schema_str = serde_json::to_string_pretty(&schema).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&schema_str).unwrap();
        assert!(
            parsed.is_object(),
            "Schema should be a JSON object, got: {}",
            schema_str
        );
    }

    #[test]
    fn test_v2_config_deserialization_minimal() {
        let yaml = r#"
version: "2.0.0"
store:
  enabled: false
providers: []
augmenters: []
server:
  host: "127.0.0.1"
  port: 3000
jwt:
  iss: "issuer"
  exp: 3600
  secret: "secret"
logging:
  level: "info"
  format: "console"
services: []
        "#;
        let figment = Figment::new().merge(Yaml::string(yaml));
        let config: Config = figment.extract().expect("Should parse config");
        let Config::ConfigV2(c) = config else {
            panic!("expected ConfigV2");
        };
        assert_eq!(c.server.host, "127.0.0.1");
        assert_eq!(c.server.port, 3000);
        assert!(c.metrics.enabled);
        assert_eq!(c.metrics.port, 9090);
        assert_eq!(c.logging.level, "info");
        assert_eq!(c.jwt.iss, "issuer");
        assert_eq!(c.auth.timeout_in_ms, 5000);
    }

    #[test]
    fn test_v2_config_deserialization_missing_server() {
        let yaml = r#"
version: "2.0.0"
store:
  enabled: false
providers: []
augmenters: []
jwt:
  iss: "issuer"
  exp: 3600
  secret: "secret"
logging:
  level: "info"
  format: "console"
services: []
        "#;
        let figment = Figment::new().merge(Yaml::string(yaml));
        let result = figment.extract::<Config>();
        assert!(
            result.is_err(),
            "should fail when server section is missing"
        );
    }

    #[test]
    fn test_v2_auth_timeout_override() {
        let yaml = r#"
version: "2.0.0"
store:
  enabled: false
providers: []
augmenters: []
server:
  port: 3000
jwt:
  iss: "issuer"
  exp: 3600
  secret: "secret"
logging:
  level: "info"
  format: "console"
services: []
auth:
  timeout_in_ms: 8000
        "#;
        let figment = Figment::new().merge(Yaml::string(yaml));
        let config: Config = figment.extract().expect("Should parse config");
        let Config::ConfigV2(c) = config else {
            panic!("expected ConfigV2");
        };
        assert_eq!(c.auth.timeout_in_ms, 8000);
    }

    #[test]
    fn test_v2_auth_defaults_when_omitted() {
        let yaml = r#"
version: "2.0.0"
store:
  enabled: false
providers: []
augmenters: []
server:
  port: 3000
jwt:
  iss: "issuer"
  exp: 3600
  secret: "secret"
logging:
  level: "info"
  format: "console"
services: []
        "#;
        let figment = Figment::new().merge(Yaml::string(yaml));
        let config: Config = figment.extract().expect("Should parse config");
        let Config::ConfigV2(c) = config else {
            panic!("expected ConfigV2");
        };
        assert_eq!(c.auth.timeout_in_ms, 5000);
    }

    #[test]
    fn test_v2_metrics_defaults_when_omitted() {
        let yaml = r#"
version: "2.0.0"
store:
  enabled: false
providers: []
augmenters: []
server:
  port: 3000
jwt:
  iss: "issuer"
  exp: 3600
  secret: "secret"
logging:
  level: "info"
  format: "console"
services: []
        "#;
        let figment = Figment::new().merge(Yaml::string(yaml));
        let config: Config = figment.extract().expect("Should parse config");
        let Config::ConfigV2(c) = config else {
            panic!("expected ConfigV2");
        };
        assert!(c.metrics.enabled);
        assert_eq!(c.metrics.port, 9090);
        assert_eq!(c.server.host, "0.0.0.0");
    }

    #[test]
    fn test_v2_metrics_explicit_disabled() {
        let yaml = r#"
version: "2.0.0"
store:
  enabled: false
providers: []
augmenters: []
server:
  port: 3000
metrics:
  enabled: false
jwt:
  iss: "issuer"
  exp: 3600
  secret: "secret"
logging:
  level: "info"
  format: "console"
services: []
        "#;
        let figment = Figment::new().merge(Yaml::string(yaml));
        let config: Config = figment.extract().expect("Should parse config");
        let Config::ConfigV2(c) = config else {
            panic!("expected ConfigV2");
        };
        assert!(!c.metrics.enabled);
    }

    #[test]
    fn test_v2_metrics_custom_port() {
        let yaml = r#"
version: "2.0.0"
store:
  enabled: false
providers: []
augmenters: []
server:
  port: 3000
metrics:
  port: 9999
jwt:
  iss: "issuer"
  exp: 3600
  secret: "secret"
logging:
  level: "info"
  format: "console"
services: []
        "#;
        let figment = Figment::new().merge(Yaml::string(yaml));
        let config: Config = figment.extract().expect("Should parse config");
        let Config::ConfigV2(c) = config else {
            panic!("expected ConfigV2");
        };
        assert!(c.metrics.enabled);
        assert_eq!(c.metrics.port, 9999);
    }

    #[test]
    fn test_v1_backward_compat_bind_address() {
        let yaml = r#"
version: "1.0.0"
store:
  enabled: false
providers: []
augmenters: []
bind_address: "127.0.0.1:8080"
jwt:
  iss: "issuer"
  exp: 3600
  secret: "secret"
logging:
  level: "info"
  format: "console"
services: []
        "#;
        let figment = Figment::new().merge(Yaml::string(yaml));
        let config: Config = figment.extract().expect("Should parse v1 config");
        let Config::ConfigV1(v1) = config else {
            panic!("expected ConfigV1");
        };
        let v2 = convert_v1_to_v2(v1);
        assert_eq!(v2.server.host, "127.0.0.1");
        assert_eq!(v2.server.port, 8080);
        assert!(v2.metrics.enabled);
        assert_eq!(v2.metrics.port, 9090);
        assert_eq!(v2.jwt.iss, "issuer");
    }

    #[test]
    fn test_v1_backward_compat_ipv6() {
        let yaml = r#"
version: "1.0.0"
store:
  enabled: false
providers: []
augmenters: []
bind_address: "::1:3000"
jwt:
  iss: "issuer"
  exp: 3600
  secret: "secret"
logging:
  level: "info"
  format: "console"
services: []
        "#;
        let figment = Figment::new().merge(Yaml::string(yaml));
        let config: Config = figment.extract().expect("Should parse v1 config");
        let Config::ConfigV1(v1) = config else {
            panic!("expected ConfigV1");
        };
        let v2 = convert_v1_to_v2(v1);
        assert_eq!(v2.server.host, "::1");
        assert_eq!(v2.server.port, 3000);
    }

    #[test]
    #[should_panic(expected = "empty host")]
    fn test_v1_rejects_empty_host() {
        parse_bind_address(":3000");
    }

    #[test]
    #[should_panic(expected = "host:port format")]
    fn test_v1_rejects_missing_port() {
        parse_bind_address("localhost");
    }

    #[test]
    fn test_v2_env_variable_override() {
        use figment::providers::{Env, Yaml};
        use std::env;

        let original_jwt_iss = env::var("AOT_JWT__ISS").ok();

        unsafe {
            env::set_var("AOT_JWT__ISS", "overridden-issuer");
        }

        let yaml = r#"
version: "2.0.0"
store:
  enabled: false
providers: []
augmenters: []
server:
  port: 3000
jwt:
  iss: "issuer"
  exp: 3600
  secret: "secret"
logging:
  level: "info"
  format: "console"
services: []
        "#;

        let figment = figment::Figment::new()
            .merge(Yaml::string(yaml))
            .merge(Env::prefixed("AOT_").split("__"));

        let config = figment
            .extract::<super::Config>()
            .expect("Failed to parse config");

        let super::Config::ConfigV2(c) = config else {
            panic!("expected ConfigV2");
        };
        assert_eq!(c.jwt.iss, "overridden-issuer");

        if let Some(val) = original_jwt_iss {
            unsafe {
                env::set_var("AOT_JWT__ISS", val);
            }
        } else {
            unsafe {
                env::remove_var("AOT_JWT__ISS");
            }
        }
    }
}

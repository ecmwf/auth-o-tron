use figment::providers::{Env, Format, Yaml};
use figment::Figment;
use schemars::{schema_for, JsonSchema};
use serde::{Deserialize, Serialize};
use std::env;

use super::logging::LoggingConfig;
use super::store::StoreConfig;
use crate::augmenters::AugmenterConfig;
use crate::providers::ProviderConfig;

/// A top-level enum for versioned configurations.
#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(tag = "version")]
pub enum Config {
    #[serde(rename = "1.0.0")]
    ConfigV1(ConfigV1),
}

/// Main config for v1.0.0, containing store, providers, augmenters, etc.
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
    // If the YAML omits the auth section, Serde calls AuthConfig::default().
    #[serde(default)]
    pub auth: AuthConfig,
}

/// Load configuration using a flexible approach:
/// - Reads the YAML file path from the CONFIG_PATH environment variable, defaulting to "./config.yaml".
/// - Merges environment variable overrides (prefixed with "AOT_" and using "__" to denote nested keys).
pub fn load_config() -> ConfigV1 {
    // Get the config file path from the environment variable `CONFIG_PATH` or default to "./config.yaml"
    let config_path = env::var("AOT_CONFIG_PATH").unwrap_or_else(|_| "./config.yaml".to_owned());

    // Create a Figment provider that:
    // 1. Loads configuration from the YAML file at `config_path`.
    // 2. Merges environment variable overrides with the prefix "AOT_".
    //    (For nested keys, use "__", e.g., AOT_JWT__ISS to override jwt.iss)
    let figment = Figment::new()
        .merge(Yaml::file(config_path))
        .merge(Env::prefixed("AOT_").split("__"));

    // Extract the configuration. Exit the process with an error if extraction fails.
    let config = match figment.extract::<Config>() {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("Error loading configuration: {}", e);
            std::process::exit(1);
        }
    };

    // Match on the versioned configuration and return the appropriate config struct.
    match config {
        Config::ConfigV1(c) => c,
    }
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

    /// Test that a minimal valid configuration in YAML is deserialized properly.
    #[test]
    fn test_config_deserialization_minimal() {
        let yaml = r#"
version: "1.0.0"
store:
  enabled: false
providers: []
augmenters: []
bind_address: "127.0.0.1:3000"
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
        match config {
            Config::ConfigV1(c) => {
                // Check that basic fields are deserialized as expected.
                assert_eq!(c.bind_address, "127.0.0.1:3000");
                assert_eq!(c.logging.level, "info");
                assert_eq!(c.jwt.iss, "issuer");
                assert_eq!(c.jwt.exp, 3600);
                assert_eq!(c.jwt.secret, "secret");
                // Since the auth section is omitted, we expect AuthConfig::default()
                // to be used, which sets timeout_in_ms to 5000.
                assert_eq!(c.auth.timeout_in_ms, 5000);
            }
        }
    }

    /// Test that deserialization fails when a required field (e.g., bind_address) is missing.
    #[test]
    fn test_config_deserialization_missing_fields() {
        let yaml = r#"
version: "1.0.0"
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
        // Extraction should fail because bind_address is required.
        let result = figment.extract::<Config>();
        assert!(
            result.is_err(),
            "Deserialization should fail when bind_address is missing"
        );
    }

    /// Test that a configuration with an "auth" section correctly deserializes the auth timeout.
    #[test]
    fn test_config_auth_defaults() {
        let yaml = r#"
version: "1.0.0"
store:
  enabled: false
providers: []
augmenters: []
bind_address: "127.0.0.1:3000"
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
        let config: Config = figment.extract().expect("Should parse config with auth");
        match config {
            Config::ConfigV1(c) => {
                // Here, the auth section is provided, so timeout_in_ms should be as specified.
                assert_eq!(c.auth.timeout_in_ms, 8000);
            }
        }
    }

    /// Test that if the auth section is omitted, the default AuthConfig is used.
    #[test]
    fn test_config_auth_absence() {
        // When the auth section is omitted, our manual Default implementation
        // for AuthConfig should set timeout_in_ms to 5000.
        let yaml = r#"
version: "1.0.0"
store:
  enabled: false
providers: []
augmenters: []
bind_address: "127.0.0.1:3000"
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
        let config: Config = figment.extract().expect("Should parse config without auth");
        match config {
            Config::ConfigV1(c) => {
                // Expect the default auth configuration.
                assert_eq!(c.auth.timeout_in_ms, 5000);
            }
        }
    }

    #[test]
    fn test_env_variable_override() {
        use figment::providers::{Env, Yaml};
        use std::env;

        // Save any previous value for cleanup
        let original_jwt_iss = env::var("APP_JWT__ISS").ok();

        // Set the environment variable to override jwt.iss.
        unsafe { env::set_var("APP_JWT__ISS", "overridden-issuer"); }

        // Use a YAML string that has a default "issuer" value for jwt.iss.
        let yaml = r#"
version: "1.0.0"
store:
  enabled: false
providers: []
augmenters: []
bind_address: "127.0.0.1:3000"
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

        // Create a Figment that merges the YAML and the environment overrides.
        let figment = figment::Figment::new()
            .merge(Yaml::string(yaml))
            .merge(Env::prefixed("APP_").split("__"));

        // Extract the configuration.
        let config = figment
            .extract::<super::Config>()
            .expect("Failed to parse config");

        // Verify that the jwt.iss value is overridden by the environment variable.
        match config {
            super::Config::ConfigV1(c) => {
                assert_eq!(c.jwt.iss, "overridden-issuer");
            }
        }

        // Clean up by restoring the original env variable (if any).
        if let Some(val) = original_jwt_iss {
            unsafe { env::set_var("APP_JWT__ISS", val); }
        } else {
            unsafe { env::remove_var("APP_JWT__ISS"); }
        }
    }
}

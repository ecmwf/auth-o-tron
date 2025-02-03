use figment::providers::{Format, Yaml};
use figment::Figment;
use schemars::{schema_for, JsonSchema};
use serde::{Deserialize, Serialize};

use super::logging::LoggingConfig;
use super::store::StoreConfig;
use crate::auth::{AugmenterConfig, ProviderConfig};

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
    pub auth: Option<AuthConfig>,
}

/// Load config from a YAML file named "config.yaml" in the current directory.
pub fn load_config() -> ConfigV1 {
    let figment = Figment::new().merge(Yaml::file("./config.yaml"));
    let config = match figment.extract::<Config>() {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("Error loading configuration: {}", e);
            std::process::exit(1);
        }
    };
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

fn default_timeout_in_ms() -> u64 {
    5000 // default to 5000 ms
}

/// Configuration for the authentication timeout.
/// This is used for select_ok operation in the auth module.
/// We kill ongoing futures if they take too long.
#[derive(Deserialize, Serialize, Debug, JsonSchema, Clone, Default)]
pub struct AuthConfig {
    #[serde(default = "default_timeout_in_ms")]
    pub timeout_in_ms: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    // Import the Yaml provider from figment.
    use figment::providers::Yaml;
    use serde_json;

    /// Test that the printed JSON schema is valid JSON and represents an object.
    #[test]
    fn test_print_schema_parses() {
        // Generate the JSON schema for the Config enum.
        let schema = schema_for!(Config);
        let schema_str = serde_json::to_string_pretty(&schema).unwrap();
        // Parse the schema back into a serde_json::Value.
        let parsed: serde_json::Value = serde_json::from_str(&schema_str).unwrap();
        // Assert that the parsed schema is a JSON object.
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
        // Use the Yaml provider to merge the YAML string.
        let figment = Figment::new().merge(Yaml::string(yaml));
        let config: Config = figment.extract().expect("Should parse config");
        match config {
            Config::ConfigV1(c) => {
                // Check that the bind address, logging, and JWT fields are as expected.
                assert_eq!(c.bind_address, "127.0.0.1:3000");
                assert_eq!(c.logging.level, "info");
                assert_eq!(c.jwt.iss, "issuer");
                assert_eq!(c.jwt.exp, 3600);
                assert_eq!(c.jwt.secret, "secret");
                // Since "aud" is not provided, it should be None.
                assert!(c.jwt.aud.is_none());
                // "auth" is not provided in the YAML, so it should be None.
                assert!(c.auth.is_none());
            }
        }
    }

    /// Test that deserialization fails when a required field (e.g., bind_address) is missing.
    #[test]
    fn test_config_deserialization_missing_fields() {
        // YAML missing the required "bind_address" field.
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
                // Verify that the auth section is present and that the timeout is correctly set.
                assert!(c.auth.is_some(), "Auth section should be present");
                let auth = c.auth.unwrap();
                assert_eq!(auth.timeout_in_ms, 8000);
            }
        }
    }

    /// Test that if the auth section is not provided, it remains None.
    #[test]
    fn test_config_auth_absence() {
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
                // Since no auth section was provided, auth should be None.
                assert!(
                    c.auth.is_none(),
                    "Auth section should be absent when not provided"
                );
            }
        }
    }
}

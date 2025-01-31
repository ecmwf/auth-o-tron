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

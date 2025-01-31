use crate::auth::{AugmenterConfig, ProviderConfig};
use crate::store::mongodb_store::MongoDBConfig;
use figment::providers::{Format, Yaml};
use figment::Figment;
use schemars::{schema_for, JsonSchema};
use serde::{Deserialize, Serialize};

/// This enum defines the application config
#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(tag = "version")]
pub enum Config {
    /// Our first version of the config.
    #[serde(rename = "1.0.0")]
    ConfigV1(ConfigV1),
}

/// This struct holds the logging settings for the application.
///
/// - `level`: The log verbosity level (trace, debug, info, warn, error).
/// - `format`: The output format ("console" or "json").
#[derive(Deserialize, Serialize, Debug, JsonSchema)]
pub struct LoggingConfig {
    pub level: String,
    pub format: String,
}

/// This struct represents the entire configuration for version 1.0.0.
///
/// It includes the token store, any services, providers, augmenters,
/// bind address, JWT settings, and logging preferences.
#[derive(Deserialize, Serialize, Debug, JsonSchema)]
pub struct ConfigV1 {
    pub store: TokenStoreConfig,
    pub services: Vec<ServiceConfig>,
    pub providers: Vec<ProviderConfig>,
    #[serde(default)]
    pub augmenters: Vec<AugmenterConfig>,
    pub bind_address: String,
    pub jwt: JWTConfig,
    pub include_legacy_headers: Option<bool>,
    pub logging: LoggingConfig,
}

/// Loads the config from `./config.yaml` and returns a `ConfigV1`.
/// If loading fails, it prints an error and exits the process.
pub fn load_config() -> ConfigV1 {
    // We use `Figment` to load and parse config.yaml
    let figment = Figment::new().merge(Yaml::file("./config.yaml"));
    let config = figment.extract::<Config>();

    let config = match config {
        Ok(config) => config,
        Err(e) => {
            // We haven't initialized logging yet, so eprintln is safer.
            eprintln!("Error loading configuration: {}", e);
            std::process::exit(1);
        }
    };

    // If we have multiple versions of config, match on them here.
    match config {
        Config::ConfigV1(c) => c,
    }
}

/// Prints the JSON schema for this config to stdout.
/// Useful for generating schema docs or validations externally.
pub fn print_schema() {
    let schema = schema_for!(Config);
    println!("{}", serde_json::to_string_pretty(&schema).unwrap());
}

// --- Subconfigs

/// JWT settings to use for token generation and validation.
#[derive(Deserialize, Serialize, JsonSchema, Debug)]
pub struct JWTConfig {
    pub iss: String,
    pub aud: Option<String>,
    pub exp: i64,
    pub secret: String,
}

/// Each `ServiceConfig` holds the name of the service and a list of scopes.
#[derive(Deserialize, Serialize, JsonSchema, Debug)]
pub struct ServiceConfig {
    pub name: String,
    pub scopes: Vec<String>,
}

/// Defines which token store to use (Mongo, etc.).
/// Additional store types can be added in the future.
#[derive(Deserialize, Serialize, JsonSchema, Debug)]
#[serde(tag = "type")]
pub enum TokenStoreConfig {
    #[serde(rename = "mongo")]
    MongoDB(MongoDBConfig),
}

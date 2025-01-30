use crate::store::mongodb_store::MongoDBConfig;
use figment::providers::{Format, Yaml};
use figment::Figment;
use schemars::{schema_for, JsonSchema};
use serde::{Deserialize, Serialize};

use crate::auth::{AugmenterConfig, ProviderConfig};

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(tag = "version")]
pub enum Config {
    #[serde(rename = "1.0.0")]
    ConfigV1(ConfigV1),
}

/// Main config for v1.0.0, including store, providers, etc.
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

/// Loads config from `config.yaml`
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

/// Prints the JSON schema for this config.
pub fn print_schema() {
    let schema = schema_for!(Config);
    println!("{}", serde_json::to_string_pretty(&schema).unwrap());
}

/// A wrapper for the store configuration.  
/// - `enabled`: if false, the store is effectively disabled (NoStore).
/// - `backend`: actual store backend config, if any.
#[derive(Deserialize, Serialize, Debug, JsonSchema)]
pub struct StoreConfig {
    pub enabled: bool,

    /// The store backend definition. We flatten so that `type: mongo` etc. is recognized.
    #[serde(flatten)]
    pub backend: Option<StoreBackend>,
}

/// The existing store backend(s), using `#[serde(tag = "type")]`.
#[derive(Deserialize, Serialize, Debug, JsonSchema)]
#[serde(tag = "type")]
pub enum StoreBackend {
    #[serde(rename = "mongo")]
    MongoDB(MongoDBConfig),
}

#[derive(Deserialize, Serialize, Debug, JsonSchema)]
pub struct JWTConfig {
    pub iss: String,
    pub aud: Option<String>,
    pub exp: i64,
    pub secret: String,
}

#[derive(Deserialize, Serialize, JsonSchema, Debug)]
pub struct ServiceConfig {
    pub name: String,
    pub scopes: Vec<String>,
}

#[derive(Deserialize, Serialize, Debug, JsonSchema)]
pub struct LoggingConfig {
    pub level: String,
    pub format: String,
}

use crate::auth::AuthHandlerConfig;
use crate::store::MongoDBConfig;
use figment::providers::Format;
use figment::providers::Yaml;
use figment::Figment;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(tag = "version")]
pub enum Config {
    #[serde(rename = "1.0.0")]
    ConfigV1(ConfigV1),
}

#[derive(serde::Deserialize, Debug)]
pub struct ConfigV1 {
    pub store: TokenStoreConfig,
    pub services: Vec<ServiceConfig>,
    pub providers: Vec<AuthHandlerConfig>,
    pub bind_address: String,
}

pub fn load_config() -> ConfigV1 {
    let figment = Figment::new().merge(Yaml::file("./config.yaml"));

    let config = figment.extract::<Config>();

    let config = match config {
        Ok(config) => config,
        Err(e) => {
            eprintln!("Error loading configuration: {}", e);
            std::process::exit(1);
        }
    };

    match config {
        Config::ConfigV1(c) => {
            // println!("Loaded configuration: {:?}", c);
            c
        }
    }

    // handle configuration migration between versions here when necessary
}

// --- Subconfigs

#[derive(Deserialize, Debug)]
pub struct JWTConfig {
    pub issuer_name: String,
}

#[derive(Deserialize, Debug)]
pub struct ServiceConfig {
    pub name: String,
    pub scopes: Vec<String>,
}

#[derive(Deserialize, Debug)]
#[serde(tag = "type")]
pub enum TokenStoreConfig {
    #[serde(rename = "mongo")]
    MongoDB(MongoDBConfig),
}



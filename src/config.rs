use crate::auth::AugmenterConfig;
use crate::auth::ProviderConfig;
use crate::store::mongodb_store::MongoDBConfig;
use figment::providers::Format;
use figment::providers::Yaml;
use figment::Figment;
use schemars::schema_for;
use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;

#[derive(Deserialize, Serialize, JsonSchema)]
#[serde(tag = "version")]
pub enum Config {
    #[serde(rename = "1.0.0")]
    ConfigV1(ConfigV1),
}

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

pub fn print_schema() -> () {
    let schema = schema_for!(Config);
    println!("{}", serde_json::to_string_pretty(&schema).unwrap());
}

// --- Subconfigs

#[derive(Deserialize, Serialize, JsonSchema, Debug)]
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

#[derive(Deserialize, Serialize, JsonSchema, Debug)]
#[serde(tag = "type")]
pub enum TokenStoreConfig {
    #[serde(rename = "mongo")]
    MongoDB(MongoDBConfig),
}

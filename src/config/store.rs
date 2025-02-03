use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::store::mongodb_store::MongoDBConfig;

/// A wrapper for the store configuration:
/// - enabled: if false, the store is effectively disabled (NoStore).
/// - backend: the actual store backend (MongoDB, etc.).
#[derive(Deserialize, Serialize, Debug, JsonSchema)]
pub struct StoreConfig {
    pub enabled: bool,
    #[serde(flatten)]
    pub backend: Option<StoreBackend>,
}

/// The existing store backends. We differentiate them via a "type" tag in the YAML.
#[derive(Deserialize, Serialize, Debug, JsonSchema)]
#[serde(tag = "type")]
pub enum StoreBackend {
    #[serde(rename = "mongo")]
    MongoDB(MongoDBConfig),
    // Add more variants here as needed, like:
    // #[serde(rename = "awesome")]
    // AwesomeStore(AwesomeStoreConfig),
}

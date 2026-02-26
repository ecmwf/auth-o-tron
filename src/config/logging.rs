use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// LoggingConfig controls how we initialize tracing/logging.
#[derive(Deserialize, Serialize, Debug, JsonSchema)]
pub struct LoggingConfig {
    pub level: String,  // e.g. "info", "debug", "warn"
    pub format: String, // e.g. "json", "console"
    #[serde(default = "default_service_name")]
    pub service_name: String,
    #[serde(default = "default_service_version")]
    pub service_version: String,
}

fn default_service_name() -> String {
    env!("CARGO_PKG_NAME").to_string()
}

fn default_service_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// LoggingConfig controls how we initialize tracing/logging.
#[derive(Deserialize, Serialize, Debug, JsonSchema)]
pub struct LoggingConfig {
    pub level: String,  // e.g. "info", "debug", "warn"
    pub format: String, // e.g. "json", "console"
}

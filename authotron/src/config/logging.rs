// (C) Copyright 2025- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

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

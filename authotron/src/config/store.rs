// (C) Copyright 2025- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

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

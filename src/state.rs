// (C) Copyright 2025- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! Shared application state.
//!
//! Contains the state that is shared across all request handlers,
//! including configuration, authentication, and token storage.

use crate::auth::Auth;
use crate::config::ConfigV2;
use crate::metrics::Metrics;
use crate::store::Store;
use std::sync::Arc;

/// Application state shared across all HTTP handlers.
///
/// This state is cloned for each request handler and contains
/// references to the configuration, authentication system, and token store.
#[derive(Clone)]
pub struct AppState {
    /// Application configuration loaded at startup.
    pub config: Arc<ConfigV2>,
    /// Authentication system handling provider and augmenter chains.
    pub auth: Arc<Auth>,
    /// Token store for managing persistent authentication tokens.
    pub store: Arc<dyn Store>,
    /// Prometheus style metrics
    pub metrics: Metrics,
}

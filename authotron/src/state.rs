// (C) Copyright 2025- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! Shared application state.
//!
//! Contains the state shared across all request handlers, including configuration
//! and authentication.

use crate::auth::Auth;
use crate::config::ConfigV2;
use crate::metrics::Metrics;
use std::sync::Arc;

/// Application state shared across all HTTP handlers.
///
/// This state is cloned for each request handler and contains references to the
/// configuration and authentication system.
#[derive(Clone)]
pub struct AppState {
    /// Application configuration loaded at startup.
    pub config: Arc<ConfigV2>,
    /// Authentication system handling provider and augmenter chains.
    pub auth: Arc<Auth>,
    /// Prometheus style metrics
    pub metrics: Metrics,
}

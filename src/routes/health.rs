// (C) Copyright 2025- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! Health check endpoints.

use crate::state::AppState;
use axum::{
    Router,
    body::Body,
    response::{IntoResponse, Response},
    routing::get,
};

/// Registers health check routes.
pub fn routes() -> Router<AppState> {
    Router::new().route("/health", get(health_check))
}

/// Simple health check endpoint.
///
/// Returns a 200 OK status to indicate the service is running.
async fn health_check() -> impl IntoResponse {
    Response::new(Body::from("OK"))
}

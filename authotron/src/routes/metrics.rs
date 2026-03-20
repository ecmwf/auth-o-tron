// (C) Copyright 2025- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! Metrics exposition endpoint.

use crate::state::AppState;
use axum::{Router, extract::State, http::StatusCode, response::IntoResponse, routing::get};

/// Creates the metrics route.
pub fn routes() -> Router<AppState> {
    Router::new().route("/metrics", get(metrics_handler))
}

/// Handler for the /metrics endpoint.
///
/// Returns all collected metrics in Prometheus text format.
/// This endpoint should be restricted via Ingress to prevent public access
/// when/if auth-o-tron is exposed through an ingress
async fn metrics_handler(State(state): State<AppState>) -> impl IntoResponse {
    let metrics_text = state.metrics.render();

    (
        StatusCode::OK,
        [("Content-Type", "text/plain; version=0.0.4; charset=utf-8")],
        metrics_text,
    )
}

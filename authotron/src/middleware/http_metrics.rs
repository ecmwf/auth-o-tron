// (C) Copyright 2025- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! Per-request RED metrics (`authotron_http_requests_total`,
//! `authotron_http_request_duration_seconds`,
//! `authotron_http_requests_in_flight`) for every route.
//!
//! The `route` label is the matched route pattern (from [`MatchedPath`]),
//! never the raw request path, so cardinality stays bounded under path scans:
//! unrouted requests collapse into `route="unmatched"`. The in-flight gauge is
//! labelled by method only, because the route pattern is not known until
//! routing completes, by which point the request is already in flight.

use std::time::Instant;

use axum::{
    extract::{MatchedPath, State},
    http::{Method, Request},
    middleware::Next,
    response::Response,
};

use crate::metrics::MetricsRecorder;
use crate::state::AppState;

/// Collapse arbitrary HTTP methods to a fixed set so the `method` label has
/// bounded cardinality (HTTP permits arbitrary extension tokens).
fn method_label(method: &Method) -> &'static str {
    match method.as_str() {
        "GET" => "GET",
        "POST" => "POST",
        "PUT" => "PUT",
        "DELETE" => "DELETE",
        "PATCH" => "PATCH",
        "HEAD" => "HEAD",
        "OPTIONS" => "OPTIONS",
        "CONNECT" => "CONNECT",
        "TRACE" => "TRACE",
        _ => "other",
    }
}

/// Records request count, duration, and in-flight gauge for each request.
///
/// The in-flight guard decrements on drop, covering the normal, error, and
/// client-disconnect (cancellation) paths.
pub async fn record_http_metrics(
    State(state): State<AppState>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let method = method_label(request.method());
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map(|p| p.as_str().to_owned())
        .unwrap_or_else(|| "unmatched".to_owned());

    let _in_flight = state.metrics.http_in_flight_guard(method);
    let started_at = Instant::now();

    let response = next.run(request).await;

    state.metrics.record_http_request(
        &route,
        method,
        response.status().as_str(),
        started_at.elapsed().as_secs_f64(),
    );

    response
}

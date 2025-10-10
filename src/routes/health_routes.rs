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

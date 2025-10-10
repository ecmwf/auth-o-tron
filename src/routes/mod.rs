//! HTTP route definitions and handlers.
//!
//! This module organizes all HTTP endpoints into logical groups:
//! authentication, token management, provider information, and health checks.

mod augmenter_routes;
mod auth_routes;
mod health_routes;
mod provider_routes;
mod token_routes;

use crate::state::AppState;
use axum::Router;

/// Creates the application router with all configured routes.
///
/// Combines all route modules into a single router and attaches
/// the application state for access in handlers.
pub fn create_router(state: AppState) -> Router {
    Router::new()
        .merge(auth_routes::routes())
        .merge(token_routes::routes())
        .merge(provider_routes::routes())
        .merge(augmenter_routes::routes())
        .merge(health_routes::routes())
        .with_state(state)
}

//! HTTP route definitions and handlers.
//!
//! This module organizes all HTTP endpoints into logical groups:
//! authentication, token management, provider information, and health checks.

mod augmenters;
mod auth;
mod health;
mod providers;
mod tokens;

use crate::state::AppState;
use axum::Router;

/// Creates the application router with all configured routes.
///
/// Combines all route modules into a single router and attaches
/// the application state for access in handlers.
pub fn create_router(state: AppState) -> Router {
    Router::new()
        .merge(auth::routes())
        .merge(tokens::routes())
        .merge(providers::routes())
        .merge(augmenters::routes())
        .merge(health::routes())
        .with_state(state)
}

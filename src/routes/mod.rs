//! HTTP route definitions and handlers.
//!
//! This module organizes all HTTP endpoints into logical groups:
//! authentication, token management, provider information, and health checks.

mod augmenters;
mod auth;
mod health;
mod metrics;
mod providers;
mod tokens;

use crate::state::AppState;
use axum::Router;

pub fn create_app_router(state: AppState) -> Router {
    Router::new()
        .merge(auth::routes())
        .merge(tokens::routes())
        .merge(providers::routes())
        .merge(augmenters::routes())
        .merge(health::routes())
        .with_state(state)
}

pub fn create_metrics_router(state: AppState) -> Router {
    Router::new()
        .merge(health::routes())
        .merge(metrics::routes())
        .with_state(state)
}

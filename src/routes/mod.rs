//! HTTP route definitions and handlers.
//!
//! Application routes and metrics routes are served on separate ports.
//! Health is registered on both so K8s probes and external uptime monitors
//! can reach it regardless of which port they target.

mod augmenters;
mod auth;
mod health;
mod homepage;
mod metrics;
mod providers;
mod tokens;

use crate::state::AppState;
use axum::Router;

pub fn create_app_router(state: AppState) -> Router {
    Router::new()
        .merge(homepage::routes())
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

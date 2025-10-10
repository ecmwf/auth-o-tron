//! Augmenter information endpoints.

use axum::{Router, routing::get};

use crate::augmenters::list_augmenters;
use crate::state::AppState;

/// Registers augmenter information routes.
pub fn routes() -> Router<AppState> {
    Router::new().route("/augmenters", get(list_augmenters))
}

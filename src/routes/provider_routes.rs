//! Authentication provider information endpoints.

use axum::{Router, routing::get};

use crate::providers::list_providers;
use crate::state::AppState;

/// Registers provider information routes.
pub fn routes() -> Router<AppState> {
    Router::new().route("/providers", get(list_providers))
}

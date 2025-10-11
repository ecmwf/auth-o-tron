//! Auth-o-tron: A flexible authentication and authorization service.

mod augmenters;
mod auth;
mod config;
mod models;
mod providers;
mod routes;
mod startup;
mod state;
mod store;
mod utils;

use crate::config::{load_config, print_schema};
use crate::utils::logger::init_logging;
use std::env;
use std::sync::Arc;

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();

    if args.contains(&"--schema".to_string()) {
        print_schema();
        return;
    }

    let config = Arc::new(load_config());
    init_logging(&config.logging);

    if let Err(e) = startup::run(config).await {
        tracing::error!("Server error: {}", e);
        std::process::exit(1);
    }
}

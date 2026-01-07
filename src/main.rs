//! Auth-o-tron: A flexible authentication and authorization service.

mod augmenters;
mod auth;
mod config;
mod metrics;
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

    if args.contains(&"--help".to_string()) {
        println!("Auth-o-tron - A flexible authentication and authorization service.");
        println!();
        println!("Usage: auth-o-tron [OPTIONS]");
        println!();
        println!("Options:");
        println!("  --help            Show this help message and exit");
        println!("  --schema          Print the JSON schema for the configuration");
        println!("  --config <PATH>   Load configuration from the specified YAML file");
        return;
    }

    if args.contains(&"--schema".to_string()) {
        print_schema();
        return;
    }

    let mut _config: Arc<config::ConfigV1>;

    if args.contains(&"--config".to_string()) {
        let config_index = args.iter().position(|x| x == "--config").unwrap();
        if let Some(config_path) = args.get(config_index + 1) {
            _config = Arc::new(load_config(Some(config_path.clone())));
            println!("Loaded configuration from {}:\n{:#?}", config_path, _config);
        } else {
            eprintln!("Error: --config flag provided but no path specified.");
            std::process::exit(1);
        }
    }
    else {
        _config = Arc::new(load_config(None));
    }
    init_logging(&_config.logging);

    if let Err(e) = startup::run(_config).await {
        tracing::error!("Server error: {}", e);
        std::process::exit(1);
    }
}

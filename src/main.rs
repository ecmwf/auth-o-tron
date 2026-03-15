//! Auth-o-tron: A flexible authentication and authorization service.

use authotron::config::{load_config, print_schema};
use authotron::startup;
use authotron::utils::logger::init_logging;
use std::env;
use std::sync::Arc;
use tracing::error;

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
        error!(
            event_name = "startup.server.failed",
            event_domain = "startup",
            error = %e,
            "server error"
        );
        std::process::exit(1);
    }
}

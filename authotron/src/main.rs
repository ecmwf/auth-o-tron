// (C) Copyright 2024- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! Auth-o-tron: A flexible authentication and authorization service.

use authotron::admin;
use authotron::config::{load_config, print_schema};
use authotron::startup;
use authotron::utils::logger::{init_logging, init_logging_to_stderr};
use std::env;
use std::sync::Arc;
use tracing::error;

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();

    if args.get(1).is_some_and(|command| command == "admin") {
        std::process::exit(run_admin(&args[2..]).await);
    }

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

/// `authotron admin ...`, whose exit status is 0 when done, 1 when it failed and 2 for
/// invalid arguments. The report goes to standard output and the log to standard error.
async fn run_admin(args: &[String]) -> i32 {
    let command = match admin::parse(args) {
        Ok(command) => command,
        Err(error) => {
            eprintln!("authotron admin: {error}\n{}", admin::USAGE);
            return 2;
        }
    };
    let config = load_config();
    init_logging_to_stderr(&config.logging);
    match admin::run(&config, &command, &mut std::io::stdout()).await {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("authotron admin: {error}");
            1
        }
    }
}

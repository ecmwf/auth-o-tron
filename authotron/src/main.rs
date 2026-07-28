// (C) Copyright 2024- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! Auth-o-tron: A flexible authentication and authorization service.

use authotron::config::{load_config, print_schema};
use authotron::startup;
use authotron::utils::logger::init_logging;
use std::env;
use std::process::ExitCode;
use std::sync::Arc;

use tracing::error;

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();

    if args.contains(&"--schema".to_string()) {
        print_schema();
        return ExitCode::SUCCESS;
    }

    let config = Arc::new(load_config());
    if let Err(error) = init_logging(&config.logging) {
        eprintln!("Error initializing logging: {error}");
        return ExitCode::FAILURE;
    }

    if let Err(error) = startup::run(config).await {
        error!(
            event_name = "startup.server.failed",
            event_domain = "startup",
            error = %error,
            "server error"
        );
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}

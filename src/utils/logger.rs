use tracing::level_filters::LevelFilter;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

use crate::config::LoggingConfig;

pub fn init_logging(logging_config: &LoggingConfig) {
    // Parse level string -> LevelFilter
    let level_filter = match logging_config.level.to_lowercase().as_str() {
        "trace" => LevelFilter::TRACE,
        "debug" => LevelFilter::DEBUG,
        "warn" => LevelFilter::WARN,
        "error" => LevelFilter::ERROR,
        // default to INFO
        _ => LevelFilter::INFO,
    };

    // This can be used to allow env-based overrides, plus the default:
    let filter_layer = EnvFilter::default().add_directive(level_filter.into());

    match logging_config.format.to_lowercase().as_str() {
        "json" => {
            // JSON output
            tracing_subscriber::registry()
                .with(filter_layer)
                .with(
                    fmt::layer().json().flatten_event(true), // lift event fields to the top level
                )
                .init();
        }
        "console" => {
            // Human-readable console output with ANSI colors
            tracing_subscriber::registry()
                .with(filter_layer)
                .with(fmt::layer().pretty())
                .init();
        }
        _ => {
            // Fallback to console if unknown
            tracing_subscriber::registry()
                .with(filter_layer)
                .with(fmt::layer().pretty())
                .init();
        }
    }
}

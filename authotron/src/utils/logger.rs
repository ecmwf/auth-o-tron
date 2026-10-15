// (C) Copyright 2025- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

use tracing::level_filters::LevelFilter;
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields, MakeWriter};
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

use crate::config::LoggingConfig;
use chrono::{SecondsFormat, Utc};
use serde_json::{Map, Value};
use tracing::field::{Field, Visit};

#[derive(Default)]
struct JsonFieldVisitor {
    fields: Map<String, Value>,
}

impl JsonFieldVisitor {
    fn insert(&mut self, field: &Field, value: Value) {
        self.fields.insert(field.name().to_string(), value);
    }
}

impl Visit for JsonFieldVisitor {
    fn record_i64(&mut self, field: &Field, value: i64) {
        self.insert(field, Value::from(value));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.insert(field, Value::from(value));
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.insert(field, Value::from(value));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.insert(field, Value::from(value));
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        self.insert(field, Value::from(value));
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.insert(field, Value::from(format!("{:?}", value)));
    }
}

#[derive(Clone)]
struct OtelJsonEventFormatter {
    service_name: String,
    service_version: String,
}

impl OtelJsonEventFormatter {
    fn severity_number(level: &Level) -> u64 {
        match *level {
            Level::TRACE => 1,
            Level::DEBUG => 5,
            Level::INFO => 9,
            Level::WARN => 13,
            Level::ERROR => 17,
        }
    }
}

impl<S, N> FormatEvent<S, N> for OtelJsonEventFormatter
where
    S: Subscriber + for<'lookup> LookupSpan<'lookup>,
    N: for<'writer> FormatFields<'writer> + 'static,
{
    fn format_event(
        &self,
        _ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> std::fmt::Result {
        let metadata = event.metadata();
        let mut visitor = JsonFieldVisitor::default();
        event.record(&mut visitor);

        let mut attributes = visitor.fields;
        if let Some(v) = attributes.remove("event_name") {
            attributes.insert("event.name".to_string(), v);
        }
        if let Some(v) = attributes.remove("event_domain") {
            attributes.insert("event.domain".to_string(), v);
        }
        if let Some(file) = metadata.file() {
            attributes.insert("code.filepath".to_string(), Value::from(file));
        }
        if let Some(line) = metadata.line() {
            attributes.insert("code.lineno".to_string(), Value::from(line));
        }
        attributes.insert("code.target".to_string(), Value::from(metadata.target()));

        let body = attributes
            .remove("message")
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_else(|| metadata.name().to_string());

        let mut resource = Map::new();
        resource.insert(
            "service.name".to_string(),
            Value::from(self.service_name.clone()),
        );
        resource.insert(
            "service.version".to_string(),
            Value::from(self.service_version.clone()),
        );

        let mut root = Map::new();
        root.insert(
            "timestamp".to_string(),
            Value::from(Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)),
        );
        root.insert(
            "severityText".to_string(),
            Value::from(metadata.level().as_str()),
        );
        root.insert(
            "severityNumber".to_string(),
            Value::from(Self::severity_number(metadata.level())),
        );
        root.insert("body".to_string(), Value::from(body));
        root.insert("resource".to_string(), Value::Object(resource));
        root.insert("attributes".to_string(), Value::Object(attributes));

        let json = Value::Object(root);
        let serialized = serde_json::to_string(&json).map_err(|_| std::fmt::Error)?;
        writer.write_str(&serialized)?;
        writer.write_char('\n')?;
        Ok(())
    }
}

/// Logs to standard output, as the server does.
pub fn init_logging(logging_config: &LoggingConfig) {
    init(logging_config, std::io::stdout, &[]);
}

/// Logs in the same format and at the same level to standard error, so that standard
/// output carries only a command's own report; events of `at_least_info`, module paths
/// such as `authotron::oauth::audit`, are logged at INFO even with a WARN or ERROR
/// level.
pub fn init_logging_to_stderr(logging_config: &LoggingConfig, at_least_info: &[&str]) {
    init(logging_config, std::io::stderr, at_least_info);
}

/// The configured `level` for every target, but at least INFO for `at_least_info`.
fn filter(level: LevelFilter, at_least_info: &[&str]) -> EnvFilter {
    let floor = level.max(LevelFilter::INFO);
    at_least_info.iter().fold(
        EnvFilter::default().add_directive(level.into()),
        |filter, target| {
            let directive = format!("{target}={floor}")
                .parse()
                .expect("a module path and a level form a directive");
            filter.add_directive(directive)
        },
    )
}

fn init<W>(logging_config: &LoggingConfig, writer: W, at_least_info: &[&str])
where
    W: for<'writer> MakeWriter<'writer> + Send + Sync + 'static,
{
    // Parse level string -> LevelFilter
    let level_filter = match logging_config.level.trim().to_lowercase().as_str() {
        "trace" => LevelFilter::TRACE,
        "debug" => LevelFilter::DEBUG,
        "info" => LevelFilter::INFO,
        "warn" => LevelFilter::WARN,
        "error" => LevelFilter::ERROR,
        _ => {
            panic!(
                "Invalid logging.level '{}'. Valid values: trace, debug, info, warn, error",
                logging_config.level
            );
        }
    };

    let filter_layer = filter(level_filter, at_least_info);

    match logging_config.format.to_lowercase().as_str() {
        "json" => {
            // OTel-aligned structured JSON output
            tracing_subscriber::registry()
                .with(filter_layer)
                .with(
                    fmt::layer()
                        .with_writer(writer)
                        .event_format(OtelJsonEventFormatter {
                            service_name: logging_config.service_name.clone(),
                            service_version: logging_config.service_version.clone(),
                        }),
                )
                .init();
        }
        "console" => {
            // Human-readable console output with ANSI colors
            tracing_subscriber::registry()
                .with(filter_layer)
                .with(fmt::layer().with_writer(writer).pretty())
                .init();
        }
        _ => {
            // Fallback to console if unknown
            tracing_subscriber::registry()
                .with(filter_layer)
                .with(fmt::layer().with_writer(writer).pretty())
                .init();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn listed_targets_log_info_whatever_the_level() {
        let lines = Arc::new(Mutex::new(Vec::new()));
        let writer = {
            let lines = Arc::clone(&lines);
            move || SharedWriter(Arc::clone(&lines))
        };
        let subscriber = tracing_subscriber::registry()
            .with(filter(LevelFilter::WARN, &["authotron::oauth::audit"]))
            .with(fmt::layer().with_writer(writer).without_time());
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(target: "authotron::oauth::audit", "audit-info");
            tracing::debug!(target: "authotron::oauth::audit", "audit-debug");
            tracing::info!(target: "authotron::oauth::runtime", "other-info");
            tracing::warn!(target: "authotron::oauth::runtime", "other-warn");
        });
        let output = String::from_utf8(lines.lock().unwrap().clone()).unwrap();
        assert!(output.contains("audit-info"));
        assert!(output.contains("other-warn"));
        assert!(!output.contains("audit-debug"));
        assert!(!output.contains("other-info"));
        // A more verbose level stays in force for them.
        let filter = filter(LevelFilter::DEBUG, &["authotron::oauth::audit"]);
        assert_eq!(filter.to_string(), "authotron::oauth::audit=debug,debug");
    }

    struct SharedWriter(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for SharedWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
}

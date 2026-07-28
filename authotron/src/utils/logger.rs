// (C) Copyright 2025- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

use std::error::Error;
use std::fmt::{Display, Formatter};

use tracing::level_filters::LevelFilter;
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields};
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

/// Errors that can occur while configuring the global tracing subscriber.
#[derive(Debug)]
pub enum LoggingInitError {
    /// The configured logging level is not supported.
    InvalidLevel { level: String },
    /// The tracing subscriber could not be installed globally.
    SubscriberInitialization {
        source: Box<dyn Error + Send + Sync>,
    },
}

impl Display for LoggingInitError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidLevel { level } => write!(
                formatter,
                "invalid logging.level '{level}'; valid values: trace, debug, info, warn, error"
            ),
            Self::SubscriberInitialization { source } => {
                write!(
                    formatter,
                    "could not initialize logging subscriber: {source}"
                )
            }
        }
    }
}

impl Error for LoggingInitError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidLevel { .. } => None,
            Self::SubscriberInitialization { source } => Some(source.as_ref()),
        }
    }
}

type BoxedSubscriber = Box<dyn Subscriber + Send + Sync>;

fn parse_level(level: &str) -> Result<LevelFilter, LoggingInitError> {
    match level.trim().to_lowercase().as_str() {
        "trace" => Ok(LevelFilter::TRACE),
        "debug" => Ok(LevelFilter::DEBUG),
        "info" => Ok(LevelFilter::INFO),
        "warn" => Ok(LevelFilter::WARN),
        "error" => Ok(LevelFilter::ERROR),
        _ => Err(LoggingInitError::InvalidLevel {
            level: level.to_owned(),
        }),
    }
}

fn init_logging_with(
    logging_config: &LoggingConfig,
    initialize: impl FnOnce(BoxedSubscriber) -> Result<(), Box<dyn Error + Send + Sync>>,
) -> Result<(), LoggingInitError> {
    let level_filter = parse_level(&logging_config.level)?;
    let filter_layer = EnvFilter::default().add_directive(level_filter.into());

    let subscriber: BoxedSubscriber = match logging_config.format.to_lowercase().as_str() {
        "json" => Box::new(tracing_subscriber::registry().with(filter_layer).with(
            fmt::layer().event_format(OtelJsonEventFormatter {
                service_name: logging_config.service_name.clone(),
                service_version: logging_config.service_version.clone(),
            }),
        )),
        _ => Box::new(
            tracing_subscriber::registry()
                .with(filter_layer)
                .with(fmt::layer().pretty()),
        ),
    };

    initialize(subscriber).map_err(|source| LoggingInitError::SubscriberInitialization { source })
}

/// Configure and install the process-wide tracing subscriber.
pub fn init_logging(logging_config: &LoggingConfig) -> Result<(), LoggingInitError> {
    init_logging_with(logging_config, |subscriber| {
        tracing::subscriber::set_global_default(subscriber)
            .map_err(|error| Box::new(error) as Box<dyn Error + Send + Sync>)
    })
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::*;

    fn logging_config(level: &str) -> LoggingConfig {
        LoggingConfig {
            level: level.to_owned(),
            format: "console".to_owned(),
            service_name: "authotron-test".to_owned(),
            service_version: "test".to_owned(),
        }
    }

    #[test]
    fn accepts_all_supported_levels() {
        for level in ["trace", "debug", "info", "warn", "error"] {
            let result = init_logging_with(&logging_config(level), |_| Ok(()));
            assert!(result.is_ok(), "expected {level} to be supported");
        }
    }

    #[test]
    fn rejects_invalid_level() {
        let result = init_logging_with(&logging_config("verbose"), |_| Ok(()));

        assert!(matches!(
            result,
            Err(LoggingInitError::InvalidLevel { level }) if level == "verbose"
        ));
    }

    #[test]
    fn reports_subscriber_initialization_failure() {
        let result = init_logging_with(&logging_config("info"), |_| {
            Err(Box::new(io::Error::other("subscriber already installed"))
                as Box<dyn Error + Send + Sync>)
        });

        assert!(matches!(
            &result,
            Err(LoggingInitError::SubscriberInitialization { .. })
        ));
        assert_eq!(
            result.unwrap_err().to_string(),
            "could not initialize logging subscriber: subscriber already installed"
        );
    }
}

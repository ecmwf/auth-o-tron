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
            Value::from(Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)),
        );
        root.insert(
            "severity_text".to_string(),
            Value::from(metadata.level().as_str()),
        );
        root.insert(
            "severity_number".to_string(),
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

pub fn init_logging(logging_config: &LoggingConfig) {
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

    // This can be used to allow env-based overrides, plus the default:
    let filter_layer = EnvFilter::default().add_directive(level_filter.into());

    match logging_config.format.to_lowercase().as_str() {
        "json" => {
            // OTel-aligned structured JSON output
            tracing_subscriber::registry()
                .with(filter_layer)
                .with(fmt::layer().event_format(OtelJsonEventFormatter {
                    service_name: logging_config.service_name.clone(),
                    service_version: logging_config.service_version.clone(),
                }))
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

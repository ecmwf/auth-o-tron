use authotron::config::LoggingConfig;
use authotron::utils::logger::{LoggingInitError, init_logging};

fn logging_config() -> LoggingConfig {
    LoggingConfig {
        level: "info".to_owned(),
        format: "console".to_owned(),
        service_name: "authotron-test".to_owned(),
        service_version: "test".to_owned(),
    }
}

#[test]
fn init_logging_reports_global_subscriber_conflict() {
    init_logging(&logging_config()).expect("first subscriber initialization succeeds");

    let result = init_logging(&logging_config());

    assert!(matches!(
        result,
        Err(LoggingInitError::SubscriberInitialization { .. })
    ));
}

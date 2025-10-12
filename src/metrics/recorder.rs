//! Metrics recording implementation using Prometheus.

use prometheus::{
    CounterVec, Encoder, HistogramVec, Opts, Registry, TextEncoder,
    register_counter_vec_with_registry, register_histogram_vec_with_registry,
};
use std::sync::Arc;

/// Trait for recording application metrics.
pub trait MetricsRecorder: Clone + Send + Sync + 'static {
    /// Records an authentication attempt with its outcome.
    fn record_auth_attempt(&self, result: &str, realm: &str);

    /// Records the duration of an authentication request.
    fn record_auth_duration(&self, duration_secs: f64, result: &str, realm: &str);

    /// Records a provider authentication attempt.
    fn record_provider_attempt(
        &self,
        provider_name: &str,
        provider_type: &str,
        realm: &str,
        result: &str,
    );

    /// Records the duration of a provider authentication attempt.
    fn record_provider_duration(
        &self,
        provider_name: &str,
        provider_type: &str,
        realm: &str,
        duration_secs: f64,
    );

    /// Records an augmenter execution.
    fn record_augmenter_attempt(
        &self,
        augmenter_name: &str,
        augmenter_type: &str,
        realm: &str,
        result: &str,
    );

    /// Records the duration of an augmenter execution.
    fn record_augmenter_duration(&self, augmenter_type: &str, realm: &str, duration_secs: f64);
}

/// Prometheus metrics collector.
#[derive(Clone)]
pub struct Metrics {
    registry: Arc<Registry>,

    // Authentication metrics
    auth_requests_total: CounterVec,
    auth_duration_seconds: HistogramVec,

    // Provider metrics
    provider_attempts_total: CounterVec,
    provider_duration_seconds: HistogramVec,

    // Augmenter metrics
    augmenter_attempts_total: CounterVec,
    augmenter_duration_seconds: HistogramVec,
}

impl Metrics {
    /// Creates a new metrics instance with a Prometheus registry.
    pub fn new() -> Self {
        let registry = Arc::new(Registry::new());

        // Authentication metrics
        let auth_requests_total = register_counter_vec_with_registry!(
            Opts::new(
                "auth_requests_total",
                "Total number of authentication attempts"
            ),
            &["result", "realm"],
            registry.clone()
        )
        .expect("Failed to register auth_requests_total");

        let auth_duration_seconds = register_histogram_vec_with_registry!(
            "auth_duration_seconds",
            "Authentication request duration in seconds",
            &["result", "realm"],
            vec![
                0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0
            ],
            registry.clone()
        )
        .expect("Failed to register auth_duration_seconds");

        // Provider metrics
        let provider_attempts_total = register_counter_vec_with_registry!(
            Opts::new(
                "auth_provider_attempts_total",
                "Total authentication attempts per provider"
            ),
            &["provider_name", "provider_type", "realm", "result"],
            registry.clone()
        )
        .expect("Failed to register provider_attempts_total");

        let provider_duration_seconds = register_histogram_vec_with_registry!(
            "auth_provider_duration_seconds",
            "Provider authentication duration in seconds",
            &["provider_name", "provider_type", "realm"],
            vec![
                0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0
            ],
            registry.clone()
        )
        .expect("Failed to register provider_duration_seconds");

        // Augmenter metrics
        let augmenter_attempts_total = register_counter_vec_with_registry!(
            Opts::new("augmenter_attempts_total", "Total augmenter executions"),
            &["augmenter_name", "augmenter_type", "realm", "result"],
            registry.clone()
        )
        .expect("Failed to register augmenter_attempts_total");

        let augmenter_duration_seconds = register_histogram_vec_with_registry!(
            "augmenter_duration_seconds",
            "Augmenter execution duration in seconds",
            &["augmenter_type", "realm"],
            vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5],
            registry.clone()
        )
        .expect("Failed to register augmenter_duration_seconds");

        Metrics {
            registry,
            auth_requests_total,
            auth_duration_seconds,
            provider_attempts_total,
            provider_duration_seconds,
            augmenter_attempts_total,
            augmenter_duration_seconds,
        }
    }

    /// Renders all metrics in Prometheus text format.
    pub fn render(&self) -> String {
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buffer = Vec::new();
        encoder
            .encode(&metric_families, &mut buffer)
            .expect("Failed to encode metrics");
        String::from_utf8(buffer).expect("Metrics encoding produced invalid UTF-8")
    }
}

impl MetricsRecorder for Metrics {
    fn record_auth_attempt(&self, result: &str, realm: &str) {
        self.auth_requests_total
            .with_label_values(&[result, realm])
            .inc();
    }

    fn record_auth_duration(&self, duration_secs: f64, result: &str, realm: &str) {
        self.auth_duration_seconds
            .with_label_values(&[result, realm])
            .observe(duration_secs);
    }

    fn record_provider_attempt(
        &self,
        provider_name: &str,
        provider_type: &str,
        realm: &str,
        result: &str,
    ) {
        self.provider_attempts_total
            .with_label_values(&[provider_name, provider_type, realm, result])
            .inc();
    }

    fn record_provider_duration(
        &self,
        provider_name: &str,
        provider_type: &str,
        realm: &str,
        duration_secs: f64,
    ) {
        self.provider_duration_seconds
            .with_label_values(&[provider_name, provider_type, realm])
            .observe(duration_secs);
    }

    fn record_augmenter_attempt(
        &self,
        augmenter_name: &str,
        augmenter_type: &str,
        realm: &str,
        result: &str,
    ) {
        self.augmenter_attempts_total
            .with_label_values(&[augmenter_name, augmenter_type, realm, result])
            .inc();
    }

    fn record_augmenter_duration(&self, augmenter_type: &str, realm: &str, duration_secs: f64) {
        self.augmenter_duration_seconds
            .with_label_values(&[augmenter_type, realm])
            .observe(duration_secs);
    }
}

// (C) Copyright 2025- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! Metrics recording implementation using Prometheus.

use prometheus::{
    CounterVec, Encoder, HistogramVec, Opts, Registry, TextEncoder,
    register_counter_vec_with_registry, register_histogram_vec_with_registry,
    register_int_gauge_vec_with_registry,
};
use std::collections::BTreeSet;
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
    pub(crate) registry: Arc<Registry>,

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

        // Build info: constant-1 gauge carrying the crate version as a label,
        // for deploy annotations on dashboards (standard `*_build_info`
        // convention). Prefixed `authotron_` to avoid colliding with other
        // services' `build_info` series in a shared Prometheus. Not stored on
        // the struct: the registry holds the registered clone, and the value
        // is set once here and never changes.
        let build_info = register_int_gauge_vec_with_registry!(
            Opts::new(
                "authotron_build_info",
                "Build information; constant 1 with the crate version as a label"
            ),
            &["version"],
            registry.clone()
        )
        .expect("Failed to register authotron_build_info");
        build_info
            .with_label_values(&[env!("CARGO_PKG_VERSION")])
            .set(1);

        // Process metrics (CPU, memory, open FDs) on the service's own
        // registry. Linux-only: the collector reads /proc.
        #[cfg(target_os = "linux")]
        {
            let collector = prometheus::process_collector::ProcessCollector::for_self();
            if let Err(e) = registry.register(Box::new(collector)) {
                tracing::warn!(
                    event_name = "metrics.process_collector.registration_failed",
                    event_domain = "metrics",
                    error = %e,
                    "failed to register process metrics collector; process metrics will be absent"
                );
            }
        }

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
    ///
    /// Returns an error if encoding fails so the scrape handler can surface a
    /// 500 instead of panicking the process. The UTF-8 step is lossy and
    /// cannot fail (Prometheus text exposition is ASCII).
    pub fn render(&self) -> Result<String, prometheus::Error> {
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buffer = Vec::new();
        encoder.encode(&metric_families, &mut buffer)?;
        Ok(String::from_utf8_lossy(&buffer).into_owned())
    }

    /// Pre-initialise bounded label series to zero at startup so
    /// `rate(...{result="error"}[5m]) > 0` alert rules evaluate against an
    /// existing zero baseline instead of a missing series. Only label
    /// combinations the code can actually emit are created: provider/augmenter
    /// series from the configured set, auth failures only with
    /// `realm="unknown"`, and auth successes with each configured realm.
    ///
    /// `providers` and `augmenters` are `(name, type, realm)` descriptors.
    pub fn preinit_series(
        &self,
        providers: &[(String, String, String)],
        augmenters: &[(String, String, String)],
    ) {
        for (name, provider_type, realm) in providers {
            for result in ["success", "error", "timeout"] {
                self.provider_attempts_total.with_label_values(&[
                    name.as_str(),
                    provider_type.as_str(),
                    realm.as_str(),
                    result,
                ]);
            }
            self.provider_duration_seconds.with_label_values(&[
                name.as_str(),
                provider_type.as_str(),
                realm.as_str(),
            ]);
        }

        for (name, augmenter_type, realm) in augmenters {
            for result in ["success", "error"] {
                self.augmenter_attempts_total.with_label_values(&[
                    name.as_str(),
                    augmenter_type.as_str(),
                    realm.as_str(),
                    result,
                ]);
            }
            self.augmenter_duration_seconds
                .with_label_values(&[augmenter_type.as_str(), realm.as_str()]);
        }

        // Pre-resolution auth failures are only ever recorded with realm="unknown".
        for result in ["no_auth_header", "invalid_header", "all_failed"] {
            self.auth_requests_total
                .with_label_values(&[result, "unknown"]);
            self.auth_duration_seconds
                .with_label_values(&[result, "unknown"]);
        }

        // Successful auth carries the resolved realm; pre-init each configured
        // realm plus "unknown" (a provider without a realm resolves to "unknown").
        // Best-effort: a provider whose issued realm differs from its filter
        // realm (get_realm) only gets its success series created at first
        // success. Failure series above are exact, which is what alerts watch.
        let mut realms: BTreeSet<&str> = BTreeSet::new();
        realms.insert("unknown");
        for (_, _, realm) in providers.iter().chain(augmenters) {
            realms.insert(realm.as_str());
        }
        for realm in realms {
            self.auth_requests_total
                .with_label_values(&["success", realm]);
            self.auth_duration_seconds
                .with_label_values(&["success", realm]);
        }
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_is_fallible_and_succeeds() {
        let metrics = Metrics::new();
        assert!(metrics.render().is_ok());
    }

    #[test]
    fn build_info_is_exposed_with_crate_version() {
        let metrics = Metrics::new();
        let output = metrics.render().expect("render ok");
        assert!(
            output.contains(&format!(
                "authotron_build_info{{version=\"{}\"}} 1",
                env!("CARGO_PKG_VERSION")
            )),
            "build_info should carry the crate version:\n{output}"
        );
    }

    #[test]
    fn preinit_series_creates_zero_baseline_for_reachable_labels() {
        let metrics = Metrics::new();
        let providers = vec![(
            "plain1".to_string(),
            "plain".to_string(),
            "realm1".to_string(),
        )];
        let augmenters = vec![(
            "aug1".to_string(),
            "plain".to_string(),
            "realm1".to_string(),
        )];
        metrics.preinit_series(&providers, &augmenters);

        let output = metrics.render().expect("render ok");
        for series in [
            // provider error/timeout pre-initialised at zero
            r#"auth_provider_attempts_total{provider_name="plain1",provider_type="plain",realm="realm1",result="error"} 0"#,
            r#"auth_provider_attempts_total{provider_name="plain1",provider_type="plain",realm="realm1",result="timeout"} 0"#,
            // augmenter error pre-initialised at zero
            r#"augmenter_attempts_total{augmenter_name="aug1",augmenter_type="plain",realm="realm1",result="error"} 0"#,
            // auth failure recorded only with realm="unknown"
            r#"auth_requests_total{realm="unknown",result="all_failed"} 0"#,
            // auth success with the configured realm
            r#"auth_requests_total{realm="realm1",result="success"} 0"#,
        ] {
            assert!(
                output.contains(series),
                "expected pre-initialised series: {series}\n{output}"
            );
        }
    }

    #[test]
    fn preinit_does_not_create_failure_series_for_configured_realms() {
        // Failures only ever carry realm="unknown"; pre-init must not invent
        // e.g. all_failed for a configured realm.
        let metrics = Metrics::new();
        let providers = vec![(
            "plain1".to_string(),
            "plain".to_string(),
            "realm1".to_string(),
        )];
        metrics.preinit_series(&providers, &[]);

        let output = metrics.render().expect("render ok");
        assert!(
            !output.contains(r#"auth_requests_total{realm="realm1",result="all_failed"}"#),
            "must not pre-init failure×configured-realm combos:\n{output}"
        );
    }
}

// (C) Copyright 2024- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! Authentication pipeline: provider chain execution and augmenter application.

use crate::augmenters::{Augmenter, AugmenterConfig, create_auth_augmenter};
use crate::config::AuthConfig;
use crate::metrics::{Metrics, MetricsRecorder};
use crate::models::user::User;
use crate::providers::{Provider, ProviderConfig, create_auth_provider};
use crate::utils::log_throttle::should_emit;
use futures::future::{FutureExt, join_all, select_ok};
use futures::lock::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;
use tokio::time::timeout;
use tracing::{debug, info, warn};

const AUTH_LOG_SUPPRESSION_WINDOW: Duration = Duration::from_secs(30);

/// Holds all authentication providers and augmenters.
pub struct Auth {
    pub providers: Vec<Box<dyn Provider>>,
    pub augmenters: Vec<Box<dyn Augmenter>>,
    config: AuthConfig,
}

/// Map the `Plain` compatibility alias to the provider's `Basic` type.
/// All other scheme spelling is preserved; provider matching is case-insensitive.
fn header_to_provider_type(scheme: &str) -> String {
    if scheme.eq_ignore_ascii_case("plain") {
        "Basic".to_string()
    } else {
        scheme.to_string()
    }
}

impl Auth {
    /// Initialize the Auth struct by creating providers and augmenters from the configurations.
    pub fn new(
        provider_config: &[ProviderConfig],
        augmenter_config: &[AugmenterConfig],
        config: AuthConfig,
    ) -> Self {
        info!(
            event_name = "auth.initialization.providers.started",
            event_domain = "auth",
            "creating auth providers"
        );
        // Convert configs into providers
        let providers: Vec<Box<dyn Provider>> =
            provider_config.iter().map(create_auth_provider).collect();

        info!(
            event_name = "auth.initialization.augmenters.started",
            event_domain = "auth",
            "creating auth augmenters"
        );
        let augmenters = augmenter_config.iter().map(create_auth_augmenter).collect();

        Auth {
            providers,
            augmenters,
            config,
        }
    }

    /// Generate a dynamic challenge header based on the available authentication providers.
    /// Iterates over `self.providers`, collects each provider's scheme and realm, and returns
    /// a comma-separated string of challenges (e.g., `Bearer realm="some-bearer-realm", Basic realm="localrealm"`).
    pub fn generate_challenge_header(&self) -> String {
        use std::collections::HashSet;
        let mut seen = HashSet::new();
        let mut challenges = Vec::new();
        for provider in &self.providers {
            // Only include providers that advertise a realm.
            if let Some(realm) = provider.get_realm() {
                let scheme = provider.get_type();
                // Deduplicate challenges by scheme and realm.
                let key = format!("{}:{}", scheme, realm);
                if seen.insert(key) {
                    challenges.push(format!(r#"{} realm="{}""#, scheme, realm));
                }
            }
        }
        // If no provider advertises a realm, return a default challenge.
        if challenges.is_empty() {
            "Bearer".to_string()
        } else {
            challenges.join(", ")
        }
    }

    /// Function below is a bit long, so here's a summary of its steps:
    ///
    /// 1. **Header Validation:**
    ///    - Checks if the provided Authorization header is empty and returns `None` if so.
    ///    - Logs a warning if the header is missing or improperly formatted.
    ///
    /// 2. **Credential Parsing:**
    ///    - Splits the header into at most three comma-separated credentials, each containing a scheme
    ///      (e.g. "Bearer", "Plain", "Basic") and a credential.
    ///    - Maps the case-insensitive `Plain` compatibility alias to the `Basic` provider type.
    ///      Other scheme spelling is preserved and matched to provider types case-insensitively.
    ///    - Rejects the entire header if a normalized scheme occurs more than once. This includes
    ///      byte-identical parts, casing variants, and `Plain`/`Basic` alias collisions.
    ///
    /// 3. **Provider Filtering & Authentication:**
    ///    - For each (scheme, credential) pair, the function filters the available providers by comparing the provider's
    ///      `get_type()` (which returns the expected scheme, such as "Basic" or "Bearer") to the scheme
    ///      case-insensitively.
    ///    - Additionally, if a realm filter is provided (via the `X-Auth-Realm` header), only providers with an exact,
    ///      case-sensitive realm match are considered.
    ///    - For each matching provider, the function initiates an asynchronous authentication call wrapped in a timeout (configured by `timeout_in_ms`).
    ///    - It then uses `select_ok` to await the first provider that successfully authenticates the user.
    ///
    /// 4. **Outcome:**
    ///    - If a provider successfully authenticates the credential, the function logs the successful authentication (including the client IP)
    ///      and returns the authenticated `User`.
    ///    - If no provider can authenticate any of the provided credentials, the function returns `None`.
    ///
    /// Authenticates a user using the first provider that succeeds.
    /// Each provider call is wrapped in a timeout so that a slow or non-responsive provider
    /// won't block the others. If all providers fail or time out, returns None.
    ///
    /// - `auth_header`: The value from the Authorization header (may contain comma-separated credentials).
    /// - `ip`: The client IP address (logged for debugging purposes).
    /// - `realm_filter`: An optional realm string taken from the X-Auth-Realm header.
    /// - `metrics`: Metrics recorder for tracking authentication attempts and outcomes.
    pub async fn authenticate(
        &self,
        auth_header: &str,
        ip: &str,
        realm_filter: Option<&str>,
        metrics: &Metrics,
    ) -> Option<User> {
        let start = Instant::now();

        if auth_header.trim().is_empty() {
            if let Some(suppressed_count) =
                should_emit("auth.header.missing", AUTH_LOG_SUPPRESSION_WINDOW)
            {
                debug!(
                    event_name = "auth.header.missing",
                    event_domain = "auth",
                    suppressed_count,
                    "authorization header is missing"
                );
            }
            // For metrics, use "unknown" since we don't know the realm yet
            metrics.record_auth_attempt("no_auth_header", "unknown");
            metrics.record_auth_duration(
                start.elapsed().as_secs_f64(),
                "no_auth_header",
                "unknown",
            );
            return None;
        }

        // Log the client's IP address for debugging purposes.
        debug!(
            event_name = "auth.request.started",
            event_domain = "auth",
            client_ip = ip,
            realm_filter = realm_filter.unwrap_or("none"),
            "auth request received"
        );

        // Store credentials by provider scheme while tracking normalized schemes separately.
        let mut creds_map: HashMap<String, String> = HashMap::new();
        let mut seen_schemes = std::collections::HashSet::new();
        let mut credential_count = 0;

        // Split the header on commas to allow multiple auth credentials.
        for part in auth_header.split(',') {
            let trimmed = part.trim();
            credential_count += 1;
            if credential_count > 3 {
                if let Some(suppressed_count) = should_emit(
                    "auth.header.too_many_credentials",
                    AUTH_LOG_SUPPRESSION_WINDOW,
                ) {
                    warn!(
                        event_name = "auth.header.invalid",
                        event_domain = "auth",
                        reason = "too_many_credentials",
                        suppressed_count,
                        max_credentials = 3,
                        "too many authorization credentials"
                    );
                }
                metrics.record_auth_attempt("invalid_header", "unknown");
                metrics.record_auth_duration(
                    start.elapsed().as_secs_f64(),
                    "invalid_header",
                    "unknown",
                );
                return None;
            }
            // Each part should be in the format: <scheme> <credentials>
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() != 2 {
                if let Some(suppressed_count) =
                    should_emit("auth.header.invalid_format", AUTH_LOG_SUPPRESSION_WINDOW)
                {
                    warn!(
                        event_name = "auth.header.invalid",
                        event_domain = "auth",
                        reason = "invalid_format",
                        suppressed_count,
                        "invalid authorization header format"
                    );
                }
                metrics.record_auth_attempt("invalid_header", "unknown");
                metrics.record_auth_duration(
                    start.elapsed().as_secs_f64(),
                    "invalid_header",
                    "unknown",
                );
                return None;
            }
            let raw_scheme = parts[0];
            let credential = parts[1];
            let normalized_scheme = header_to_provider_type(raw_scheme);
            if !seen_schemes.insert(normalized_scheme.to_ascii_lowercase()) {
                if let Some(suppressed_count) =
                    should_emit("auth.header.duplicate_scheme", AUTH_LOG_SUPPRESSION_WINDOW)
                {
                    warn!(
                        event_name = "auth.header.invalid",
                        event_domain = "auth",
                        reason = "duplicate_scheme",
                        scheme = raw_scheme,
                        suppressed_count,
                        "duplicate authorization scheme"
                    );
                }
                metrics.record_auth_attempt("invalid_header", "unknown");
                metrics.record_auth_duration(
                    start.elapsed().as_secs_f64(),
                    "invalid_header",
                    "unknown",
                );
                return None;
            }
            creds_map.insert(normalized_scheme, credential.to_string());
        }

        let result = self.check_providers(creds_map, realm_filter, metrics).await;

        let user = match result {
            Some(u) => u,
            None => {
                // Use "unknown" for failed auth where we don't have a realm
                metrics.record_auth_attempt("all_failed", "unknown");
                metrics.record_auth_duration(
                    start.elapsed().as_secs_f64(),
                    "all_failed",
                    "unknown",
                );
                return None;
            }
        };

        let user = self.check_augmenters(user, metrics).await?;

        // Record successful authentication with the actual realm from the user
        let user_realm = &user.realm;
        metrics.record_auth_attempt("success", user_realm);
        metrics.record_auth_duration(start.elapsed().as_secs_f64(), "success", user_realm);
        info!(
            event_name = "auth.request.authenticated",
            event_domain = "auth",
            username = user.username.as_str(),
            realm = user.realm.as_str(),
            roles_count = user.roles.len(),
            roles = user.roles.join(","),
            attributes_count = user.attributes.len(),
            scopes_services_count = user.scopes.len(),
            "authentication request succeeded"
        );

        Some(user)
    }

    /// Returns (User, provider_realm) on success
    async fn check_providers(
        &self,
        creds_map: HashMap<String, String>,
        realm_filter: Option<&str>,
        metrics: &Metrics,
    ) -> Option<User> {
        // Try each provided credential until one provider successfully authenticates.
        for (scheme, credential) in creds_map.into_iter() {
            // Set the timeout duration based on the configuration.
            let timeout_duration = std::time::Duration::from_millis(self.config.timeout_in_ms);
            let timeout_ms = self.config.timeout_in_ms;
            // Match scheme names case-insensitively, but realm identifiers exactly.
            let futures = self
                .providers
                .iter()
                .filter(|p| {
                    p.get_type().eq_ignore_ascii_case(&scheme)
                        && match realm_filter {
                            Some(r) => p.get_realm().map(|pr| pr == r).unwrap_or(false),
                            None => true,
                        }
                })
                .map(|provider| {
                    let name = provider.get_name().to_owned();
                    let provider_type = provider.get_type().to_owned();
                    let provider_realm = provider.get_realm().unwrap_or("unknown").to_owned();
                    let cred = credential.clone();
                    let metrics = metrics.clone();

                    async move {
                        let start = Instant::now();

                        match timeout(timeout_duration, provider.authenticate(&cred)).await {
                            Ok(Ok(user)) => {
                                let duration = start.elapsed().as_secs_f64();
                                metrics.record_provider_attempt(
                                    &name,
                                    &provider_type,
                                    &provider_realm,
                                    "success",
                                );
                                metrics.record_provider_duration(
                                    &name,
                                    &provider_type,
                                    &provider_realm,
                                    duration,
                                );
                                Ok((name, user, provider_realm))
                            }
                            Ok(Err(e)) => {
                                let duration = start.elapsed().as_secs_f64();
                                metrics.record_provider_attempt(
                                    &name,
                                    &provider_type,
                                    &provider_realm,
                                    "error",
                                );
                                metrics.record_provider_duration(
                                    &name,
                                    &provider_type,
                                    &provider_realm,
                                    duration,
                                );
                                debug!(
                                    event_name = "auth.provider.failed",
                                    event_domain = "auth",
                                    provider_name = name.as_str(),
                                    error = e.as_str(),
                                    "provider failed to authenticate request"
                                );
                                Err(format!("Provider '{}' failed: {}", name, e))
                            }
                            Err(_) => {
                                metrics.record_provider_attempt(
                                    &name,
                                    &provider_type,
                                    &provider_realm,
                                    "timeout",
                                );
                                debug!(
                                    event_name = "auth.provider.timeout",
                                    event_domain = "auth",
                                    provider_name = name.as_str(),
                                    timeout_ms,
                                    "provider authentication timed out"
                                );
                                Err(format!("Provider '{}' timed out", name))
                            }
                        }
                    }
                    .boxed()
                })
                .collect::<Vec<_>>();

            // If no providers matched, try the next credential.
            if futures.is_empty() {
                debug!(
                    event_name = "auth.provider.not_found",
                    event_domain = "auth",
                    scheme = scheme.as_str(),
                    realm_filter = realm_filter.unwrap_or("none"),
                    "no providers matched scheme and realm filter"
                );
                continue;
            }

            // Use select_ok to await the first future that completes successfully.
            match select_ok(futures).await {
                Ok(((provider_name, user, _), _)) => {
                    debug!(
                        event_name = "auth.provider.success",
                        event_domain = "auth",
                        provider_name = provider_name.as_str(),
                        realm = user.realm.as_str(),
                        "provider authenticated request"
                    );
                    return Some(user);
                }
                Err(e) => {
                    if let Some(suppressed_count) = should_emit(
                        &format!("auth.provider.all_failed.{}", scheme.to_lowercase()),
                        AUTH_LOG_SUPPRESSION_WINDOW,
                    ) {
                        warn!(
                            event_name = "auth.provider.all_failed",
                            event_domain = "auth",
                            scheme = scheme.as_str(),
                            suppressed_count,
                            last_error = e.to_string(),
                            "all providers failed for scheme"
                        );
                    }
                    // Continue with the next credential if available.
                }
            }
        }
        None
    }

    async fn run_augmenter(
        &self,
        augmenter: &dyn Augmenter,
        user: Arc<Mutex<User>>,
        metrics: &Metrics,
        realm: &str,
    ) {
        let metrics = metrics.clone();
        let name = augmenter.get_name().to_string();
        let aug_type = augmenter.get_type().to_string();

        let start = Instant::now();
        let result = augmenter.augment(user).await;
        let duration = start.elapsed().as_secs_f64();

        match result {
            Ok(_) => {
                metrics.record_augmenter_attempt(&name, &aug_type, realm, "success");
                metrics.record_augmenter_duration(&aug_type, realm, duration);
            }
            Err(e) => {
                if let Some(suppressed_count) = should_emit(
                    &format!("auth.augmenter.failed.{}.{}", realm, name),
                    AUTH_LOG_SUPPRESSION_WINDOW,
                ) {
                    warn!(
                        event_name = "auth.augmenter.failed",
                        event_domain = "auth",
                        augmenter_name = name.as_str(),
                        augmenter_type = aug_type.as_str(),
                        realm,
                        suppressed_count,
                        error = e.as_str(),
                        "augmenter failed"
                    );
                }
                metrics.record_augmenter_attempt(&name, &aug_type, realm, "error");
                metrics.record_augmenter_duration(&aug_type, realm, duration);
            }
        }
    }

    async fn check_augmenters(&self, user: User, metrics: &Metrics) -> Option<User> {
        debug!(
            event_name = "auth.augmenters.started",
            event_domain = "auth",
            realm = user.realm.as_str(),
            "applying augmenters for authenticated user"
        );
        let realm = user.realm.clone();
        let user = Arc::new(Mutex::new(user));

        // Partition: run advanced-plain synchronously afterwards
        let (serial, parallel): (Vec<_>, Vec<_>) = self
            .augmenters
            .iter()
            .filter(|a| a.get_realm() == realm)
            .partition(|a| a.get_type().eq_ignore_ascii_case("plain_advanced"));

        // Run non-advanced in parallel
        join_all(
            parallel
                .iter()
                .map(|aug| self.run_augmenter(aug.as_ref(), user.clone(), metrics, &realm)),
        )
        .await;

        // Then run advanced-plain synchronously
        for aug in serial {
            self.run_augmenter(aug.as_ref(), user.clone(), metrics, &realm)
                .await;
        }

        Some(user.lock().await.clone())
    }
}

#[cfg(test)]
mod tests {
    use crate::augmenters::plain_advanced_augmenter::{
        PlainAdvancedAugmenter, PlainAdvancedAugmenterAugment, PlainAdvancedAugmenterConfig,
        PlainAdvancedAugmenterMatcher,
    };
    use crate::augmenters::plain_augmenter::{PlainAugmenter, PlainAugmenterConfig};

    use super::*;
    use crate::models::user::User;
    use async_trait::async_trait;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::time::{Duration, sleep};

    /// Checks if a metric's labels match all the expected label pairs.
    ///
    /// This helper verifies that a Prometheus metric has all the labels
    /// specified in the `expected_labels` slice, with matching values.
    fn labels_match(metric: &prometheus::proto::Metric, expected_labels: &[(&str, &str)]) -> bool {
        // Check each expected label key-value pair
        for (key, expected_val) in expected_labels {
            // Search for this label in the metric's label set
            // get_label() returns a Vec of LabelPair structs
            let found = metric.get_label().iter().any(|label_pair| {
                // Both the label name and value must match exactly
                label_pair.name() == *key && label_pair.value() == *expected_val
            });

            // If any expected label is missing or has wrong value, labels don't match
            if !found {
                return false;
            }
        }

        // All expected labels matched
        true
    }

    /// Retrieves the value of a Prometheus counter metric with specific labels.
    ///
    /// This helper function queries the Prometheus registry for a counter metric
    /// and returns its current value. It's used in tests to verify that metrics
    /// are being recorded with the correct values.
    fn get_counter_value(metrics: &Metrics, name: &str, labels: &[(&str, &str)]) -> f64 {
        // Gather all metric families from the registry
        // A MetricFamily groups all time series with the same metric name
        let metric_families = metrics.registry.gather();

        // Search through each metric family (e.g., authotron_auth_requests_total,
        // authotron_auth_duration_seconds)
        for mf in metric_families {
            // Check if this is the metric we're looking for
            if mf.name() == name {
                // Each metric family contains multiple time series (one per label combination)
                // For example, authotron_auth_requests_total has separate series for:
                //   - {result="success", realm="test"}
                //   - {result="failed", realm="test"}
                //   - etc.
                for m in mf.get_metric() {
                    // Use the helper to check if this metric's labels match
                    if labels_match(m, labels) {
                        return m.get_counter().value();
                    }
                }
            }
        }

        // Metric not found or labels didn't match - return 0.0
        // This is safe because counters start at 0 if they haven't been incremented
        0.0
    }

    /// Retrieves the sample count from a Prometheus histogram metric with specific labels.
    ///
    /// Histograms in Prometheus automatically track three things:
    /// 1. Buckets - distribution of values across predefined ranges
    /// 2. Sum - total sum of all observed values
    /// 3. Count - total number of observations
    ///
    /// This function extracts the "count" field, which tells you how many times
    /// a value has been recorded to the histogram.
    fn get_histogram_count(metrics: &Metrics, name: &str, labels: &[(&str, &str)]) -> u64 {
        // Gather all registered metrics from Prometheus
        let metric_families = metrics.registry.gather();

        // Iterate through all metric families to find our histogram
        for mf in metric_families {
            // Check if this metric family matches our metric name
            if mf.name() == name {
                // Iterate through the time series within this metric family
                // Each time series represents a unique label combination
                for m in mf.get_metric() {
                    // Use the helper to check if this metric's labels match
                    if labels_match(m, labels) {
                        // get_histogram() returns the histogram data structure
                        // get_sample_count() gives us the total number of observations
                        // This is equivalent to the "_count" metric in Prometheus output
                        return m.get_histogram().get_sample_count();
                    }
                }
            }
        }

        // No matching histogram found - return 0
        // This is safe because histograms start with 0 samples
        0
    }

    #[tokio::test]
    async fn test_metrics_record_successful_authentication() {
        let provider = Box::new(DummyProvider {
            name: "TestProvider".to_string(),
            provider_type: "Basic".to_string(),
            realm: Some("testrealm".to_string()),
            expected_credential: "validcred".to_string(),
        });

        let auth = Auth {
            providers: vec![provider],
            augmenters: vec![],
            config: AuthConfig {
                timeout_in_ms: 1000,
            },
        };

        let metrics = Metrics::new();

        // Perform authentication
        let result = auth
            .authenticate("Basic validcred", "127.0.0.1", Some("testrealm"), &metrics)
            .await;

        assert!(result.is_some(), "Authentication should succeed");

        // Verify exact metric values
        let success_count = get_counter_value(
            &metrics,
            "authotron_auth_requests_total",
            &[("result", "success"), ("realm", "testrealm")],
        );
        assert_eq!(
            success_count, 1.0,
            "Should have exactly 1 successful auth attempt"
        );

        let provider_success = get_counter_value(
            &metrics,
            "authotron_auth_provider_attempts_total",
            &[
                ("provider_name", "TestProvider"),
                ("provider_type", "Basic"),
                ("realm", "testrealm"),
                ("result", "success"),
            ],
        );
        assert_eq!(
            provider_success, 1.0,
            "Provider should have exactly 1 success"
        );

        let duration_count = get_histogram_count(
            &metrics,
            "authotron_auth_duration_seconds",
            &[("result", "success"), ("realm", "testrealm")],
        );
        assert_eq!(duration_count, 1, "Should have exactly 1 duration sample");
    }

    #[tokio::test]
    async fn test_metrics_record_failed_authentication() {
        let provider = Box::new(DummyProvider {
            name: "TestProvider".to_string(),
            provider_type: "Basic".to_string(),
            realm: Some("testrealm".to_string()),
            expected_credential: "validcred".to_string(),
        });

        let auth = Auth {
            providers: vec![provider],
            augmenters: vec![],
            config: AuthConfig {
                timeout_in_ms: 1000,
            },
        };

        let metrics = Metrics::new();

        // Attempt with wrong credentials
        let result = auth
            .authenticate("Basic wrongcred", "127.0.0.1", Some("testrealm"), &metrics)
            .await;

        assert!(result.is_none(), "Authentication should fail");

        // Verify failure was recorded
        let failed_count = get_counter_value(
            &metrics,
            "authotron_auth_requests_total",
            &[("result", "all_failed"), ("realm", "unknown")],
        );
        assert_eq!(failed_count, 1.0, "Should record 1 failed attempt");

        let provider_error = get_counter_value(
            &metrics,
            "authotron_auth_provider_attempts_total",
            &[
                ("provider_name", "TestProvider"),
                ("provider_type", "Basic"),
                ("realm", "testrealm"),
                ("result", "error"),
            ],
        );
        assert_eq!(provider_error, 1.0, "Provider should record 1 error");

        // Verify no success was recorded
        let success_count = get_counter_value(
            &metrics,
            "authotron_auth_requests_total",
            &[("result", "success"), ("realm", "testrealm")],
        );
        assert_eq!(success_count, 0.0, "Should have 0 successful attempts");
    }

    #[tokio::test]
    async fn test_metrics_record_no_auth_header() {
        let auth = Auth {
            providers: vec![],
            augmenters: vec![],
            config: AuthConfig {
                timeout_in_ms: 1000,
            },
        };

        let metrics = Metrics::new();

        let result = auth.authenticate("", "127.0.0.1", None, &metrics).await;

        assert!(result.is_none(), "Should fail with empty header");

        let no_header_count = get_counter_value(
            &metrics,
            "authotron_auth_requests_total",
            &[("result", "no_auth_header"), ("realm", "unknown")],
        );
        assert_eq!(no_header_count, 1.0, "Should record no_auth_header");
    }

    #[tokio::test]
    async fn test_metrics_record_invalid_header() {
        let auth = Auth {
            providers: vec![],
            augmenters: vec![],
            config: AuthConfig {
                timeout_in_ms: 1000,
            },
        };

        let metrics = Metrics::new();

        let result = auth
            .authenticate("InvalidFormat", "127.0.0.1", None, &metrics)
            .await;

        assert!(result.is_none(), "Should fail with invalid header");

        let invalid_count = get_counter_value(
            &metrics,
            "authotron_auth_requests_total",
            &[("result", "invalid_header"), ("realm", "unknown")],
        );
        assert_eq!(invalid_count, 1.0, "Should record invalid_header");
    }

    #[tokio::test]
    async fn test_metrics_multiple_authentications() {
        let provider = Box::new(DummyProvider {
            name: "TestProvider".to_string(),
            provider_type: "Basic".to_string(),
            realm: Some("test".to_string()),
            expected_credential: "validcred".to_string(),
        });

        let auth = Auth {
            providers: vec![provider],
            augmenters: vec![],
            config: AuthConfig {
                timeout_in_ms: 1000,
            },
        };

        let metrics = Metrics::new();

        // Perform 3 successful authentications
        for _ in 0..3 {
            auth.authenticate("Basic validcred", "127.0.0.1", Some("test"), &metrics)
                .await;
        }

        // Perform 2 failed authentications
        for _ in 0..2 {
            auth.authenticate("Basic wrongcred", "127.0.0.1", Some("test"), &metrics)
                .await;
        }

        let success_count = get_counter_value(
            &metrics,
            "authotron_auth_requests_total",
            &[("result", "success"), ("realm", "test")],
        );
        assert_eq!(success_count, 3.0, "Should have exactly 3 successes");

        let failed_count = get_counter_value(
            &metrics,
            "authotron_auth_requests_total",
            &[("result", "all_failed"), ("realm", "unknown")],
        );
        assert_eq!(failed_count, 2.0, "Should have exactly 2 failures");

        let total_duration_samples = get_histogram_count(
            &metrics,
            "authotron_auth_duration_seconds",
            &[("result", "success"), ("realm", "test")],
        );
        assert_eq!(
            total_duration_samples, 3,
            "Should have 3 duration samples for successes"
        );
    }

    #[tokio::test]
    async fn test_metrics_augmenter_execution() {
        let provider = Box::new(DummyProvider {
            name: "TestProvider".to_string(),
            provider_type: "Basic".to_string(),
            realm: Some("r1".to_string()),
            expected_credential: "validcred".to_string(),
        });

        let aug = PlainAugmenter::new(&make_plain_augmenter_config(
            "test-aug",
            "r1",
            &[("admin", &["dummy"])],
        ));

        let auth = Auth {
            providers: vec![provider],
            augmenters: vec![Box::new(aug)],
            config: AuthConfig {
                timeout_in_ms: 1000,
            },
        };

        let metrics = crate::metrics::Metrics::new();

        let result = auth
            .authenticate("Basic validcred", "127.0.0.1", Some("r1"), &metrics)
            .await;

        assert!(result.is_some(), "Authentication should succeed");

        let augmenter_count = get_counter_value(
            &metrics,
            "authotron_augmenter_attempts_total",
            &[
                ("augmenter_name", "test-aug"),
                ("augmenter_type", "plain"),
                ("realm", "r1"),
                ("result", "success"),
            ],
        );

        assert_eq!(augmenter_count, 1.0, "Augmenter should execute once");

        let aug_duration_samples = get_histogram_count(
            &metrics,
            "authotron_augmenter_duration_seconds",
            &[("augmenter_type", "plain"), ("realm", "r1")],
        );
        assert_eq!(aug_duration_samples, 1, "Should record augmenter duration");

        // Verify the user actually got the role
        let user = result.unwrap();
        assert!(
            user.roles.contains(&"admin".to_string()),
            "User should have admin role from augmenter"
        );
    }

    #[tokio::test]
    async fn test_metrics_different_realms() {
        let provider1 = Box::new(DummyProvider {
            name: "Provider1".to_string(),
            provider_type: "Basic".to_string(),
            realm: Some("realm1".to_string()),
            expected_credential: "cred1".to_string(),
        });

        let provider2 = Box::new(DummyProvider {
            name: "Provider2".to_string(),
            provider_type: "Basic".to_string(),
            realm: Some("realm2".to_string()),
            expected_credential: "cred2".to_string(),
        });

        let auth = Auth {
            providers: vec![provider1, provider2],
            augmenters: vec![],
            config: AuthConfig {
                timeout_in_ms: 1000,
            },
        };

        let metrics = Metrics::new();

        // Authenticate with realm1
        auth.authenticate("Basic cred1", "127.0.0.1", Some("realm1"), &metrics)
            .await;

        // Authenticate with realm2
        auth.authenticate("Basic cred2", "127.0.0.1", Some("realm2"), &metrics)
            .await;

        let realm1_count = get_counter_value(
            &metrics,
            "authotron_auth_requests_total",
            &[("result", "success"), ("realm", "realm1")],
        );
        assert_eq!(realm1_count, 1.0, "realm1 should have 1 success");

        let realm2_count = get_counter_value(
            &metrics,
            "authotron_auth_requests_total",
            &[("result", "success"), ("realm", "realm2")],
        );
        assert_eq!(realm2_count, 1.0, "realm2 should have 1 success");
    }

    fn make_plain_augmenter_config(
        name: &str,
        realm: &str,
        roles: &[(&str, &[&str])],
    ) -> PlainAugmenterConfig {
        let mut roles_map = HashMap::new();
        for (role, users) in roles {
            roles_map.insert(
                (*role).to_string(),
                users.iter().map(|u| (*u).to_string()).collect(),
            );
        }
        PlainAugmenterConfig {
            name: name.to_string(),
            realm: realm.to_string(),
            roles: roles_map,
        }
    }

    #[tokio::test]
    async fn test_check_augmenters_applies_roles_for_matching_realm() {
        let aug1 = PlainAugmenter::new(&make_plain_augmenter_config(
            "aug1",
            "r1",
            &[("admin", &["alice", "bob"])],
        ));
        let aug2 = PlainAugmenter::new(&make_plain_augmenter_config(
            "aug2",
            "r1",
            &[("user", &["bob", "carol"])],
        ));
        let aug3 = PlainAugmenter::new(&make_plain_augmenter_config(
            "aug3",
            "r2",
            &[("other", &["bob"])],
        ));

        let auth = Auth {
            providers: vec![],
            augmenters: vec![Box::new(aug1), Box::new(aug2), Box::new(aug3)],
            config: AuthConfig { timeout_in_ms: 5 },
        };

        let metrics = Metrics::new();
        let user = User {
            username: "bob".to_string(),
            roles: vec![],
            realm: "r1".to_string(),
            ..Default::default()
        };
        let user = auth.check_augmenters(user, &metrics).await.unwrap();
        assert!(user.roles.contains(&"admin".to_string()));
        assert!(user.roles.contains(&"user".to_string()));
        assert!(!user.roles.contains(&"other".to_string()));
    }

    #[tokio::test]
    async fn test_check_augmenters_ignores_nonmatching_realm() {
        let aug = PlainAugmenter::new(&make_plain_augmenter_config(
            "aug",
            "r1",
            &[("admin", &["bob"])],
        ));
        let auth = Auth {
            providers: vec![],
            augmenters: vec![Box::new(aug)],
            config: AuthConfig { timeout_in_ms: 5 },
        };
        let metrics = Metrics::new();
        let user = User {
            username: "bob".to_string(),
            roles: vec![],
            realm: "r2".to_string(),
            ..Default::default()
        };
        let user = auth.check_augmenters(user, &metrics).await.unwrap();
        assert!(user.roles.is_empty());
    }

    #[tokio::test]
    async fn test_check_augmenters_no_roles_for_user() {
        let aug = PlainAugmenter::new(&make_plain_augmenter_config(
            "aug",
            "r1",
            &[("admin", &["alice"])],
        ));
        let auth = Auth {
            providers: vec![],
            augmenters: vec![Box::new(aug)],
            config: AuthConfig { timeout_in_ms: 5 },
        };
        let metrics = Metrics::new();
        let user = User {
            username: "bob".to_string(),
            roles: vec![],
            realm: "r1".to_string(),
            ..Default::default()
        };
        let user = auth.check_augmenters(user, &metrics).await.unwrap();
        assert!(user.roles.is_empty());
    }

    struct DelayedPlainAugmenter {
        name: String,
        realm: String,
        username: String,
        role: String,
        delay: Duration,
    }

    #[async_trait]
    impl Augmenter for DelayedPlainAugmenter {
        async fn augment(&self, user: Arc<Mutex<User>>) -> Result<(), String> {
            let mismatch = {
                let u = user.lock().await;
                u.realm != self.realm || u.username != self.username
            }; // guard is dropped here

            if mismatch {
                return Ok(());
            }

            sleep(self.delay).await;

            let mut user_guard = user.lock().await;
            user_guard.roles.push(self.role.clone());
            Ok(())
        }

        fn get_name(&self) -> &str {
            &self.name
        }

        fn get_type(&self) -> &str {
            "plain"
        }

        fn get_realm(&self) -> &str {
            &self.realm
        }
    }

    #[tokio::test]
    async fn test_plain_then_advanced_runs_sequentially() {
        let delayed_plain = DelayedPlainAugmenter {
            name: "delayed_plain".to_string(),
            realm: "r1".to_string(),
            username: "bob".to_string(),
            role: "base".to_string(),
            delay: Duration::from_millis(100),
        };

        let advanced_config = PlainAdvancedAugmenterConfig {
            name: "advanced".to_string(),
            realm: "r1".to_string(),
            r#match: PlainAdvancedAugmenterMatcher {
                role: vec!["base".to_string()],
                ..Default::default()
            },
            augment: PlainAdvancedAugmenterAugment {
                roles: vec!["derived".to_string()],
                ..Default::default()
            },
        };

        let auth = Auth {
            providers: vec![],
            augmenters: vec![
                Box::new(delayed_plain),
                Box::new(PlainAdvancedAugmenter::new(&advanced_config)),
            ],
            config: AuthConfig { timeout_in_ms: 5 },
        };

        let metrics = Metrics::new();
        let user = User {
            username: "bob".to_string(),
            roles: vec![],
            realm: "r1".to_string(),
            ..Default::default()
        };

        let user = auth.check_augmenters(user, &metrics).await.unwrap();

        assert!(user.roles.contains(&"base".to_string()));
        assert!(user.roles.contains(&"derived".to_string()));
    }
    /// A dummy Provider implementation for testing.
    struct DummyProvider {
        name: String,
        provider_type: String,
        realm: Option<String>,
        expected_credential: String,
    }

    #[async_trait]
    impl Provider for DummyProvider {
        fn get_name(&self) -> &str {
            &self.name
        }
        fn get_type(&self) -> &str {
            &self.provider_type
        }
        fn get_realm(&self) -> Option<&str> {
            self.realm.as_deref()
        }
        async fn authenticate(&self, credentials: &str) -> Result<User, String> {
            if credentials == self.expected_credential {
                Ok(User {
                    realm: self.realm.clone().unwrap_or_default(),
                    username: "dummy".to_string(),
                    roles: vec![],
                    attributes: HashMap::new(),
                    ..Default::default()
                })
            } else {
                Err("Invalid credentials".to_string())
            }
        }
    }

    #[tokio::test]
    async fn test_header_to_provider_type_only_aliases_plain() {
        assert_eq!(header_to_provider_type("plain"), "Basic");
        assert_eq!(header_to_provider_type("PlAiN"), "Basic");
        assert_eq!(header_to_provider_type("Basic"), "Basic");
        assert_eq!(header_to_provider_type("basic"), "basic");
        assert_eq!(header_to_provider_type("Bearer"), "Bearer");
        assert_eq!(header_to_provider_type("bearer"), "bearer");
        assert_eq!(header_to_provider_type("UnKnOwN"), "UnKnOwN");
    }

    #[tokio::test]
    async fn test_generate_challenge_header() {
        // Create a dummy Auth instance with two dummy providers.
        let provider1 = Box::new(DummyProvider {
            name: "TestBearer".to_string(),
            provider_type: "Bearer".to_string(),
            realm: Some("realm1".to_string()),
            expected_credential: "token1".to_string(),
        });
        let provider2 = Box::new(DummyProvider {
            name: "TestBasic".to_string(),
            provider_type: "Basic".to_string(),
            realm: Some("realm2".to_string()),
            expected_credential: "credential1".to_string(),
        });
        let auth = Auth {
            providers: vec![provider1, provider2],
            augmenters: vec![],
            config: AuthConfig { timeout_in_ms: 5 },
        };

        let challenge = auth.generate_challenge_header();
        // Since the order is not guaranteed, check that both expected challenge strings are present.
        assert!(challenge.contains(r#"Bearer realm="realm1""#));
        assert!(challenge.contains(r#"Basic realm="realm2""#));
    }

    #[tokio::test]
    async fn test_authenticate_single_valid_credential() {
        // Create a dummy Auth instance with one provider expecting a specific credential.
        let provider = Box::new(DummyProvider {
            name: "TestBasic".to_string(),
            provider_type: "Basic".to_string(),
            realm: Some("localrealm".to_string()),
            // Using "ZHVtbXk6ZHVtbXk=" as dummy Base64 credential (for "dummy:dummy")
            expected_credential: "ZHVtbXk6ZHVtbXk=".to_string(),
        });
        let auth = Auth {
            providers: vec![provider],
            augmenters: vec![],
            config: AuthConfig { timeout_in_ms: 5 },
        };

        let metrics = Metrics::new();
        // Test authentication with a valid Basic credential.
        let user = auth
            .authenticate(
                "Basic ZHVtbXk6ZHVtbXk=",
                "127.0.0.1",
                Some("localrealm"),
                &metrics,
            )
            .await;
        assert!(user.is_some());
        assert_eq!(user.unwrap().username, "dummy");
    }

    #[tokio::test]
    async fn test_authentication_scheme_matching_and_plain_alias() {
        let auth = Auth {
            providers: vec![Box::new(DummyProvider {
                name: "TestBasic".to_string(),
                provider_type: "Basic".to_string(),
                realm: Some("localrealm".to_string()),
                expected_credential: "credential".to_string(),
            })],
            augmenters: vec![],
            config: AuthConfig { timeout_in_ms: 5 },
            token_store: Arc::new(DummyStore),
        };
        let metrics = Metrics::new();

        for header in ["bAsIc credential", "pLaIn credential"] {
            let user = auth
                .authenticate(header, "127.0.0.1", Some("localrealm"), &metrics)
                .await;
            assert!(user.is_some(), "scheme was not matched for {header:?}");
        }
    }

    #[tokio::test]
    async fn test_authenticate_multiple_credentials() {
        // Create dummy providers for both Basic and Bearer.
        let basic_provider = Box::new(DummyProvider {
            name: "TestBasic".to_string(),
            provider_type: "Basic".to_string(),
            realm: Some("localrealm".to_string()),
            // Dummy credential for Basic provider.
            expected_credential: "ZHVtbXk6ZHVtbXk=".to_string(),
        });
        let bearer_provider = Box::new(DummyProvider {
            name: "TestBearer".to_string(),
            provider_type: "Bearer".to_string(),
            realm: Some("localrealm".to_string()),
            // Dummy credential for Bearer provider.
            expected_credential: "someBearerToken".to_string(),
        });

        let auth = Auth {
            providers: vec![basic_provider, bearer_provider],
            augmenters: vec![],
            config: AuthConfig { timeout_in_ms: 5 },
        };

        let metrics = crate::metrics::Metrics::new();
        // Test with a comma-separated header that contains both credentials.
        // The dummy bearer provider is expected to succeed with "someBearerToken".
        // The dummy basic provider is expected to succeed with "ZHVtbXk6ZHVtbXk=".
        // We use select_ok select_ok, which returns the first successful future it finds
        let header = "Bearer someBearerToken, Basic ZHVtbXk6ZHVtbXk=";
        let user = auth
            .authenticate(header, "127.0.0.1", Some("localrealm"), &metrics)
            .await;
        assert!(user.is_some());
        assert_eq!(user.unwrap().username, "dummy");
    }

    #[tokio::test]
    async fn test_authenticate_realm_filter() {
        // Create two dummy providers with identical expected credentials,
        // but with different realms.
        let local_provider = Box::new(DummyProvider {
            name: "LocalBasic".to_string(),
            provider_type: "Basic".to_string(),
            realm: Some("localrealm".to_string()),
            // Using "ZHVtbXk6ZHVtbXk=" as our dummy Base64 credential for "dummy:dummy"
            expected_credential: "ZHVtbXk6ZHVtbXk=".to_string(),
        });
        let other_provider = Box::new(DummyProvider {
            name: "OtherBasic".to_string(),
            provider_type: "Basic".to_string(),
            realm: Some("otherrealm".to_string()),
            // Using the same dummy credential for testing purposes.
            expected_credential: "ZHVtbXk6ZHVtbXk=".to_string(),
        });

        let auth = Auth {
            providers: vec![local_provider, other_provider],
            augmenters: vec![],
            config: AuthConfig { timeout_in_ms: 5 },
        };

        let metrics = crate::metrics::Metrics::new();
        // When the realm filter is "localrealm", only the provider with that realm should be used.
        let header = "Basic ZHVtbXk6ZHVtbXk=";
        let user_local = auth
            .authenticate(header, "127.0.0.1", Some("localrealm"), &metrics)
            .await;
        assert!(
            user_local.is_some(),
            "Authentication should succeed for realm 'localrealm'"
        );

        // When the realm filter is "otherrealm", only the other provider should be used.
        let user_other = auth
            .authenticate(header, "127.0.0.1", Some("otherrealm"), &metrics)
            .await;
        assert!(
            user_other.is_some(),
            "Authentication should succeed for realm 'otherrealm'"
        );

        // Realm identifiers are exact and case-sensitive, matching augmenter semantics.
        let user_none = auth
            .authenticate(header, "127.0.0.1", Some("LOCALREALM"), &metrics)
            .await;
        assert!(
            user_none.is_none(),
            "Authentication should fail when only the realm casing differs"
        );

        // A realm not configured on any provider also fails.
        let user_none = auth
            .authenticate(header, "127.0.0.1", Some("nonexistent"), &metrics)
            .await;
        assert!(
            user_none.is_none(),
            "Authentication should fail for a non-matching realm"
        );
    }

    #[tokio::test]
    async fn test_identical_duplicate_header_parts_are_rejected() {
        let auth = Auth {
            providers: vec![Box::new(DummyProvider {
                name: "TestBasic".to_string(),
                provider_type: "Basic".to_string(),
                realm: Some("localrealm".to_string()),
                expected_credential: "correct".to_string(),
            })],
            augmenters: vec![],
            config: AuthConfig { timeout_in_ms: 5 },
        };
        let metrics = Metrics::new();

        let user = auth
            .authenticate(
                "Basic correct, Basic correct",
                "127.0.0.1",
                Some("localrealm"),
                &metrics,
            )
            .await;

        assert!(
            user.is_none(),
            "byte-identical duplicate parts were accepted"
        );
    }

    #[tokio::test]
    async fn test_duplicate_normalized_schemes_are_rejected() {
        let auth = Auth {
            providers: vec![Box::new(DummyProvider {
                name: "TestBasic".to_string(),
                provider_type: "Basic".to_string(),
                realm: Some("localrealm".to_string()),
                expected_credential: "correct".to_string(),
            })],
            augmenters: vec![],
            config: AuthConfig { timeout_in_ms: 5 },
            token_store: Arc::new(DummyStore),
        };
        let metrics = Metrics::new();

        for header in [
            "Basic wrong, Basic correct",
            "Basic wrong, bAsIc correct",
            "Plain wrong, Basic correct",
            "pLaIn wrong, basic correct",
        ] {
            let user = auth
                .authenticate(header, "127.0.0.1", Some("localrealm"), &metrics)
                .await;
            assert!(
                user.is_none(),
                "duplicate normalized scheme accepted in {header:?}"
            );
        }
    }

    #[tokio::test]
    async fn test_too_many_unique_headers_rejected() {
        let provider = Box::new(DummyProvider {
            name: "TestBasic".to_string(),
            provider_type: "Basic".to_string(),
            realm: Some("localrealm".to_string()),
            expected_credential: "correct".to_string(),
        });
        let auth = Auth {
            providers: vec![provider],
            augmenters: vec![],
            config: AuthConfig { timeout_in_ms: 5 },
        };
        let metrics = Metrics::new();

        let header = "Bearer a, Basic correct, Digest b, ApiKey c";
        let user = auth
            .authenticate(header, "127.0.0.1", Some("localrealm"), &metrics)
            .await;
        assert!(
            user.is_none(),
            "More than 3 unique headers should be rejected"
        );

        let header = "Bearer a, Digest b, Basic correct";
        let user = auth
            .authenticate(header, "127.0.0.1", Some("localrealm"), &metrics)
            .await;
        assert!(
            user.is_some(),
            "Up to 3 unique headers should still be accepted"
        );
    }
}

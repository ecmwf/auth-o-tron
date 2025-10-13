use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use crate::augmenters::{Augmenter, AugmenterConfig, create_auth_augmenter};
use crate::config::AuthConfig;
use crate::metrics::{Metrics, MetricsRecorder};
use crate::models::user::User;
use crate::providers::{Provider, ProviderConfig, create_auth_provider};
use crate::store::Store;
use futures::future::{FutureExt, join_all, select_ok};
use futures::lock::Mutex;
use tokio::time::timeout;
use tracing::{debug, info, warn};

/// Holds all authentication providers, augmenters, and a reference to the store.
pub struct Auth {
    pub providers: Vec<Box<dyn Provider>>,
    pub augmenters: Vec<Box<dyn Augmenter>>,
    config: AuthConfig,
    #[allow(dead_code)]
    token_store: Arc<dyn Store>,
}

/// Helper function to map header scheme values to the expected provider type.
/// For example, a header "Plain" is mapped to "Basic" so that providers
/// that return "Basic" in their `get_type()` match correctly.
fn header_to_provider_type(scheme: &str) -> String {
    match scheme.to_lowercase().as_str() {
        "bearer" => "Bearer".to_string(),
        "plain" => "Basic".to_string(),
        "basic" => "Basic".to_string(),
        other => other.to_string(),
    }
}

impl Auth {
    /// Initialize the Auth struct by creating providers and augmenters from the configurations.
    pub fn new(
        provider_config: &[ProviderConfig],
        augmenter_config: &[AugmenterConfig],
        token_store: Arc<dyn Store>,
        config: AuthConfig,
    ) -> Self {
        info!("Creating auth providers...");
        // Convert configs into providers
        let mut providers: Vec<Box<dyn Provider>> =
            provider_config.iter().map(create_auth_provider).collect();

        // Only add token store as provider if it's enabled
        if token_store.is_enabled() {
            info!("Token store is enabled, adding as Bearer provider");
            providers.push(Box::new(token_store.clone()) as Box<dyn Provider>);
        } else {
            info!("Token store is disabled, skipping as provider");
        }

        info!("Creating auth augmenters...");
        let augmenters = augmenter_config.iter().map(create_auth_augmenter).collect();

        Auth {
            providers,
            augmenters,
            token_store,
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
    ///    - Splits the header on commas to allow multiple credentials.
    ///    - For each segment, splits the segment on whitespace into a scheme (e.g. "Bearer", "Plain", "Basic")
    ///      and a credential.
    ///    - Normalizes the scheme using the helper `header_to_provider_type` (which converts "plain" to "Basic").
    ///    - This normalization ensures that if you supply "Basic" or "plain", both are treated as "Basic", while "Bearer"
    ///      remains "Bearer".
    ///    - Uses a `HashMap` to ensure only one credential per scheme is provided; if multiple credentials for the same
    ///      scheme are detected, it returns `None`.
    ///
    /// 3. **Provider Filtering & Authentication:**
    ///    - For each (scheme, credential) pair, the function filters the available providers by comparing the provider's
    ///      `get_type()` (which returns the expected scheme, such as "Basic" or "Bearer") to the normalized scheme.
    ///      This ensures that if you supply a "Basic" credential, only providers that return "Basic" are tried, and likewise for "Bearer".
    ///    - Additionally, if a realm filter is provided (via the `X-Auth-Realm` header), only providers with a matching realm are considered.
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
            warn!("No Authorization header provided.");
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
            "Authenticating request with auth header {} from IP {} Realm filter {}",
            auth_header,
            ip,
            realm_filter.unwrap_or("None")
        );

        // Use a HashMap with owned Strings for credentials.
        let mut creds_map: HashMap<String, String> = HashMap::new();
        let mut seen_trimmed = std::collections::HashSet::new();
        let mut unique_count = 0;

        // Split the header on commas to allow multiple auth credentials.
        for part in auth_header.split(',') {
            let trimmed = part.trim();
            // Discard duplicate trimmed parts
            if !seen_trimmed.insert(trimmed.to_string()) {
                warn!(
                    "Duplicate auth header part detected and discarded: '{}'",
                    trimmed
                );
                continue;
            }
            unique_count += 1;
            if unique_count > 3 {
                warn!("Too many unique Authorization header credentials (>{})", 3);
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
                warn!("Invalid auth part format: '{}'", trimmed);
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
            // Filter providers by matching type and (if provided) realm.
            let futures = self
                .providers
                .iter()
                .filter(|p| {
                    p.get_type().eq_ignore_ascii_case(&scheme)
                        && match realm_filter {
                            Some(r) => {
                                // Only consider providers with a realm matching the filter.
                                p.get_realm()
                                    .map(|pr| pr.eq_ignore_ascii_case(r))
                                    .unwrap_or(false)
                            }
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
                                debug!("Provider '{}' failed to authenticate: {}", name, e);
                                Err(format!("Provider '{}' failed: {}", name, e))
                            }
                            Err(_) => {
                                metrics.record_provider_attempt(
                                    &name,
                                    &provider_type,
                                    &provider_realm,
                                    "timeout",
                                );
                                debug!("Provider '{}' timed out during authentication", name);
                                Err(format!("Provider '{}' timed out", name))
                            }
                        }
                    }
                    .boxed()
                })
                .collect::<Vec<_>>();

            // If no providers matched, log a warning and try the next credential.
            if futures.is_empty() {
                warn!(
                    "No providers found for auth scheme '{}' with realm filter {:?}",
                    scheme, realm_filter
                );
                continue;
            }

            // Use select_ok to await the first future that completes successfully.
            match select_ok(futures).await {
                Ok(((provider_name, user, _), _)) => {
                    info!(
                        "Provider '{}' successfully authenticated user '{}'",
                        provider_name, user.username
                    );
                    return Some(user);
                }
                Err(e) => {
                    warn!(
                        "All providers failed for scheme '{}'; last error: {}",
                        scheme, e
                    );
                    // Continue with the next credential if available.
                }
            }
        }
        None
    }

    async fn check_augmenters(&self, user: User, metrics: &Metrics) -> Option<User> {
        info!("Applying augmentations for user '{}'", user.username);
        let realm = user.realm.clone();
        let user = Arc::new(Mutex::new(user));

        let futures = self
            .augmenters
            .iter()
            .filter(|a| a.get_realm() == realm)
            .map(|augmenter| {
                let metrics = metrics.clone();
                let realm = realm.clone();
                let name = augmenter.get_name().to_string();
                let aug_type = augmenter.get_type().to_string();
                let user_ref = user.clone();

                async move {
                    let start = Instant::now();
                    let result = augmenter.augment(user_ref).await;
                    let duration = start.elapsed().as_secs_f64();

                    match result {
                        Ok(_) => {
                            metrics.record_augmenter_attempt(&name, &aug_type, &realm, "success");
                            metrics.record_augmenter_duration(&aug_type, &realm, duration);
                        }
                        Err(e) => {
                            warn!("Augmenter '{}' failed: {}", name, e);
                            metrics.record_augmenter_attempt(&name, &aug_type, &realm, "error");
                            metrics.record_augmenter_duration(&aug_type, &realm, duration);
                        }
                    }
                }
            });

        let _ = join_all(futures).await;

        // Return the authenticated user.
        Some(user.lock().await.clone())
    }
}

#[cfg(test)]
mod tests {
    use crate::augmenters::plain_augmenter::{PlainAugmenter, PlainAugmenterConfig};

    use super::*;
    use crate::models::user::User;
    use async_trait::async_trait;
    use std::collections::HashMap;
    use std::sync::Arc;

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

        // Search through each metric family (e.g., auth_requests_total, auth_duration_seconds)
        for mf in metric_families {
            // Check if this is the metric we're looking for
            if mf.name() == name {
                // Each metric family contains multiple time series (one per label combination)
                // For example, auth_requests_total has separate series for:
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
            token_store: Arc::new(DummyStore),
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
            "auth_requests_total",
            &[("result", "success"), ("realm", "testrealm")],
        );
        assert_eq!(
            success_count, 1.0,
            "Should have exactly 1 successful auth attempt"
        );

        let provider_success = get_counter_value(
            &metrics,
            "auth_provider_attempts_total",
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
            "auth_duration_seconds",
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
            token_store: Arc::new(DummyStore),
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
            "auth_requests_total",
            &[("result", "all_failed"), ("realm", "unknown")],
        );
        assert_eq!(failed_count, 1.0, "Should record 1 failed attempt");

        let provider_error = get_counter_value(
            &metrics,
            "auth_provider_attempts_total",
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
            "auth_requests_total",
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
            token_store: Arc::new(DummyStore),
        };

        let metrics = Metrics::new();

        let result = auth.authenticate("", "127.0.0.1", None, &metrics).await;

        assert!(result.is_none(), "Should fail with empty header");

        let no_header_count = get_counter_value(
            &metrics,
            "auth_requests_total",
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
            token_store: Arc::new(DummyStore),
        };

        let metrics = Metrics::new();

        let result = auth
            .authenticate("InvalidFormat", "127.0.0.1", None, &metrics)
            .await;

        assert!(result.is_none(), "Should fail with invalid header");

        let invalid_count = get_counter_value(
            &metrics,
            "auth_requests_total",
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
            token_store: Arc::new(DummyStore),
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
            "auth_requests_total",
            &[("result", "success"), ("realm", "test")],
        );
        assert_eq!(success_count, 3.0, "Should have exactly 3 successes");

        let failed_count = get_counter_value(
            &metrics,
            "auth_requests_total",
            &[("result", "all_failed"), ("realm", "unknown")],
        );
        assert_eq!(failed_count, 2.0, "Should have exactly 2 failures");

        let total_duration_samples = get_histogram_count(
            &metrics,
            "auth_duration_seconds",
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
            token_store: Arc::new(DummyStore),
        };

        let metrics = crate::metrics::Metrics::new();

        let result = auth
            .authenticate("Basic validcred", "127.0.0.1", Some("r1"), &metrics)
            .await;

        assert!(result.is_some(), "Authentication should succeed");

        let augmenter_count = get_counter_value(
            &metrics,
            "augmenter_attempts_total",
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
            "augmenter_duration_seconds",
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
            token_store: Arc::new(DummyStore),
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
            "auth_requests_total",
            &[("result", "success"), ("realm", "realm1")],
        );
        assert_eq!(realm1_count, 1.0, "realm1 should have 1 success");

        let realm2_count = get_counter_value(
            &metrics,
            "auth_requests_total",
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
            token_store: Arc::new(DummyStore),
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
            token_store: Arc::new(DummyStore),
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
            token_store: Arc::new(DummyStore),
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
                    version: 1,
                    realm: self.realm.clone().unwrap_or_default(),
                    username: "dummy".to_string(),
                    roles: vec![],
                    attributes: HashMap::new(),
                    scopes: None,
                })
            } else {
                Err("Invalid credentials".to_string())
            }
        }
    }

    /// A dummy Store implementation for testing.
    struct DummyStore;

    #[async_trait]
    impl crate::store::Store for DummyStore {
        async fn add_token(
            &self,
            _token: &crate::models::token::Token,
            _user: &User,
            _expiry: i64,
        ) -> Result<(), String> {
            Ok(())
        }
        async fn get_tokens(
            &self,
            _user: &User,
        ) -> Result<Vec<crate::models::token::Token>, String> {
            Ok(vec![])
        }
        async fn get_user(&self, _token: &str) -> Result<Option<User>, String> {
            Ok(None)
        }
        async fn delete_token(&self, _token: &str) -> Result<(), String> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_header_to_provider_type() {
        // Test normalization of header schemes.
        assert_eq!(header_to_provider_type("plain"), "Basic");
        assert_eq!(header_to_provider_type("Basic"), "Basic");
        assert_eq!(header_to_provider_type("Bearer"), "Bearer");
        assert_eq!(header_to_provider_type("unknown"), "unknown");
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
            token_store: Arc::new(DummyStore),
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
            token_store: Arc::new(DummyStore),
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
            token_store: Arc::new(DummyStore),
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
            token_store: Arc::new(DummyStore),
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

        // When the realm filter does not match any provider, authentication should fail.
        let user_none = auth
            .authenticate(header, "127.0.0.1", Some("nonexistent"), &metrics)
            .await;
        assert!(
            user_none.is_none(),
            "Authentication should fail for a non-matching realm"
        );
    }

    #[tokio::test]
    async fn test_duplicate_headers_checked_once() {
        let provider = Box::new(DummyProvider {
            name: "TestBasic".to_string(),
            provider_type: "Basic".to_string(),
            realm: Some("localrealm".to_string()),
            expected_credential: "ZHVtbXk6ZHVtbXk=".to_string(),
        });
        let auth = Auth {
            providers: vec![provider],
            augmenters: vec![],
            config: AuthConfig { timeout_in_ms: 5 },
            token_store: Arc::new(DummyStore),
        };
        let metrics = crate::metrics::Metrics::new();
        // Duplicate header part (should only check once, and succeed)
        let header = "Basic ZHVtbXk6ZHVtbXk=, Basic ZHVtbXk6ZHVtbXk=";
        let user = auth
            .authenticate(header, "127.0.0.1", Some("localrealm"), &metrics)
            .await;
        assert!(
            user.is_some(),
            "Duplicate headers should be checked just once and succeed"
        );

        // duplicate wrong header gets rejected
        let wrong_header = "Basic wrong, Basic wrong";
        let user = auth
            .authenticate(wrong_header, "127.0.0.1", Some("localrealm"), &metrics)
            .await;
        assert!(user.is_none(), "Duplicate wrong headers should be rejected");
    }

    #[tokio::test]
    async fn test_too_many_unique_headers_rejected() {
        let provider = Box::new(DummyProvider {
            name: "TestBasic".to_string(),
            provider_type: "Basic".to_string(),
            realm: Some("localrealm".to_string()),
            expected_credential: "ZHVtbXk6ZHVtbXk=".to_string(),
        });
        let auth = Auth {
            providers: vec![provider],
            augmenters: vec![],
            config: AuthConfig { timeout_in_ms: 5 },
            token_store: Arc::new(DummyStore),
        };
        let metrics = crate::metrics::Metrics::new();
        // 4 unique header parts (should be rejected)
        let header = "Basic a, Basic b, Basic ZHVtbXk6ZHVtbXk=, Basic c";
        let user = auth
            .authenticate(header, "127.0.0.1", Some("localrealm"), &metrics)
            .await;
        assert!(
            user.is_none(),
            "More than 3 unique headers should be rejected"
        );
        // check that if correct header is third user is authenticated
        let header = "Basic a, Basic b, Basic ZHVtbXk6ZHVtbXk=";
        let user = auth
            .authenticate(header, "127.0.0.1", Some("localrealm"), &metrics)
            .await;
        assert!(
            user.is_some(),
            "User should be authenticated with the correct header"
        );
    }
}

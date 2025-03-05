use std::collections::HashMap;
use std::sync::Arc;

use crate::config::AuthConfig;
use crate::models::User;
use crate::store::Store;
use futures::future::{select_ok, FutureExt};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tokio::time::timeout;
use tracing::{info, warn};

use super::ecmwfapi_provider::{EcmwfApiProvider, EcmwfApiProviderConfig};
use super::jwt_provider::{JWTAuthConfig, JWTProvider};
use super::ldap_augmenter::{LDAPAugmenter, LDAPAugmenterConfig};
use super::openid_offline_provider::{OpenIDOfflineProvider, OpenIDOfflineProviderConfig};
use super::plain_provider::{PlainAuthConfig, PlainAuthProvider};

/// Configuration options for each authentication provider.
#[derive(Deserialize, Serialize, JsonSchema, Debug)]
#[serde(tag = "type")]
pub enum ProviderConfig {
    #[serde(rename = "ecmwf-api")]
    EcmwfApiAuthConfig(EcmwfApiProviderConfig),

    #[serde(rename = "jwt")]
    JWTAuthConfig(JWTAuthConfig),

    #[serde(rename = "openid-offline")]
    OpenIDOfflineAuthConfig(OpenIDOfflineProviderConfig),

    #[serde(rename = "plain")]
    PlainAuthConfig(PlainAuthConfig),
}

/// Configuration options for augmenters (e.g. an LDAP roles augmenter).
#[derive(Deserialize, Serialize, JsonSchema, Debug)]
#[serde(tag = "type")]
pub enum AugmenterConfig {
    #[serde(rename = "ldap")]
    LDAPAugmenterConfig(LDAPAugmenterConfig),
}

/// An authentication provider must be able to return a User or an error.
#[async_trait::async_trait]
pub trait Provider: Send + Sync {
    fn get_name(&self) -> &str;
    fn get_type(&self) -> &str;
    /// Providers that support realm-based filtering should override this.
    fn get_realm(&self) -> Option<&str> {
        None
    }
    async fn authenticate(&self, credentials: &str) -> Result<User, String>;
}

/// An augmenter can add extra roles or info to an already-authenticated User.
#[async_trait::async_trait]
pub trait Augmenter: Send + Sync {
    fn get_name(&self) -> &str;
    fn get_type(&self) -> &str;
    fn get_realm(&self) -> &str;
    async fn augment(&self, user: &mut User) -> Result<(), String>;
}

/// Create an authentication provider from a given config.
pub fn create_auth_provider(config: &ProviderConfig) -> Box<dyn Provider> {
    match config {
        ProviderConfig::EcmwfApiAuthConfig(cfg) => Box::new(EcmwfApiProvider::new(cfg)),
        ProviderConfig::JWTAuthConfig(cfg) => Box::new(JWTProvider::new(cfg)),
        ProviderConfig::OpenIDOfflineAuthConfig(cfg) => Box::new(OpenIDOfflineProvider::new(cfg)),
        ProviderConfig::PlainAuthConfig(cfg) => Box::new(PlainAuthProvider::new(cfg)),
    }
}

/// Create an augmenter from a given config.
pub fn create_auth_augmenter(config: &AugmenterConfig) -> Box<dyn Augmenter> {
    match config {
        AugmenterConfig::LDAPAugmenterConfig(cfg) => Box::new(LDAPAugmenter::new(cfg)),
    }
}

/// Holds all authentication providers, augmenters, and a reference to the store.
pub struct Auth {
    pub providers: Vec<Box<dyn Provider>>,
    pub augmenters: Vec<Box<dyn Augmenter>>,
    config: AuthConfig,
    #[allow(dead_code)]
    token_store: Arc<dyn Store>,
}

/// Helper function to map header scheme values to the expected provider type.
/// For example, a header "Plain" is mapped to "Basic" so that only providers
/// with get_type() returning "Basic" are used.
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
        // Convert configs into providers, plus add a provider that uses the token_store directly.
        let providers = provider_config
            .iter()
            .map(create_auth_provider)
            .chain(std::iter::once(
                Box::new(token_store.clone()) as Box<dyn Provider>
            ))
            .collect();

        info!("Creating auth augmenters...");
        let augmenters = augmenter_config.iter().map(create_auth_augmenter).collect();

        Auth {
            providers,
            augmenters,
            token_store,
            config,
        }
    }

    /// Authenticates a user using the first provider that succeeds.
    /// Each provider call is wrapped in a timeout so that a slow or non-responsive provider
    /// won't block the others. If all providers fail or time out, returns None.
    ///
    /// - `auth_header`: the value from the Authorization header (may contain comma-separated values)
    /// - `ip`: client IP (for logging; currently unused)
    /// - `realm_filter`: an optional realm string taken from the X-Auth-Realm header
    pub async fn authenticate(
        &self,
        auth_header: &str,
        _ip: &str, // IP is currently unused; rename to _ip to suppress warnings.
        realm_filter: Option<&str>,
    ) -> Option<User> {
        if auth_header.trim().is_empty() {
            warn!("No Authorization header provided.");
            return None;
        }

        // Use an explicit HashMap with owned Strings for credentials.
        let mut creds_map: HashMap<String, String> = HashMap::new();

        // Split the header on commas to allow multiple auth credentials.
        for part in auth_header.split(',') {
            let trimmed = part.trim();
            // Each part should be in the format: <scheme> <credentials>
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() != 2 {
                warn!("Invalid auth part format: '{}'", trimmed);
                return None;
            }
            let raw_scheme = parts[0];
            let credential = parts[1];
            let normalized_scheme = header_to_provider_type(raw_scheme);
            // Error out if the same scheme appears more than once.
            if creds_map.contains_key(&normalized_scheme) {
                warn!(
                    "Multiple credentials provided for scheme '{}'. Only one per scheme is allowed.",
                    normalized_scheme
                );
                return None;
            }
            creds_map.insert(normalized_scheme, credential.to_string());
        }

        // Try each provided credential until one provider successfully authenticates.
        for (scheme, credential) in creds_map.into_iter() {
            // Set the timeout duration based on the configuration.
            let timeout_duration = std::time::Duration::from_secs(self.config.timeout_in_ms);
            // Instead of storing into a temporary vector, iterate directly over self.providers,
            // filtering by type and the optional realm.
            let futures = self
                .providers
                .iter()
                .filter(|p| {
                    p.get_type().eq_ignore_ascii_case(&scheme)
                        && match realm_filter {
                            Some(r) => {
                                // Only consider providers that define a realm and that match the filter.
                                p.get_realm()
                                    .map(|pr| pr.eq_ignore_ascii_case(r))
                                    .unwrap_or(false)
                            }
                            None => true,
                        }
                })
                .map(|provider| {
                    let name = provider.get_name().to_owned();
                    // Clone the credential for each async block to avoid moving it.
                    let cred = credential.clone();
                    async move {
                        match timeout(timeout_duration, provider.authenticate(&cred)).await {
                            Ok(Ok(user)) => Ok((name, user)),
                            Ok(Err(e)) => Err(format!("Provider '{}' failed: {}", name, e)),
                            Err(_) => Err(format!("Provider '{}' timed out", name)),
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
                Ok(((provider_name, user), _)) => {
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
                    // Try next credential if available.
                }
            }
        }
        None
    }
}

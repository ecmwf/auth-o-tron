use std::sync::Arc;

use crate::config::AuthConfig;
use crate::models::User;
use crate::store::Store;
use futures::future::{select_ok, FutureExt};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tokio::time::timeout;
use tracing::{debug, info, warn};

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

    /// Authenticates a user using the first provider that succeeds. We wrap each provider
    /// call in a timeout so a slow or non-responsive provider won't block the others.
    /// If all fail or time out, returns None.
    pub async fn authenticate(&self, auth_header: &str, ip: &str) -> Option<User> {
        let parts: Vec<&str> = auth_header.split_whitespace().collect();
        if parts.len() != 2 {
            warn!("Authorization header invalid format: '{}'", auth_header);
            return None;
        }

        let auth_type = parts[0];
        let auth_credentials = parts[1];

        debug!(
            "Authenticating with auth_type='{}' from IP='{}'",
            auth_type, ip
        );

        // Collect all providers that match the type in the Authorization header.
        let valid_providers: Vec<_> = self
            .providers
            .iter()
            .filter(|p| p.get_type().eq_ignore_ascii_case(auth_type))
            .collect();

        if valid_providers.is_empty() {
            warn!("No providers found for auth type: '{}'", auth_type);
            return None;
        }

        let timeout_duration = std::time::Duration::from_secs(self.config.timeout_in_ms);
        // Wrap each provider future in a timeout and box it so we can use select_ok.
        let futures = valid_providers
            .iter()
            .map(|provider| {
                let name = provider.get_name().to_owned();
                async move {
                    match timeout(timeout_duration, provider.authenticate(auth_credentials)).await {
                        Ok(Ok(user)) => Ok((name, user)),
                        Ok(Err(e)) => Err(format!("Provider '{}' failed: {}", name, e)),
                        Err(_) => Err(format!("Provider '{}' timed out", name)),
                    }
                }
                .boxed()
            })
            .collect::<Vec<_>>();

        // select_ok returns on the first successful authentication, dropping unused futures.
        let mut user = match select_ok(futures).await {
            Ok(((provider_name, user), _remaining)) => {
                info!(
                    "Provider '{}' authenticated user '{}'",
                    provider_name, user.username
                );
                user
            }
            Err(e) => {
                warn!("All providers failed; last error: {}", e);
                return None;
            }
        };

        // Augment the user if there's an augmenter whose realm matches the authenticated user's realm.
        let realm = user.realm.clone();
        let matching_augmenters = self
            .augmenters
            .iter()
            .filter(|aug| aug.get_realm() == realm);

        for aug in matching_augmenters {
            match aug.augment(&mut user).await {
                Ok(_) => info!(
                    "Augmenter '{}' succeeded for '{}'",
                    aug.get_name(),
                    user.username
                ),
                Err(err) => warn!("Augmenter '{}' failed: {}", aug.get_name(), err),
            }
        }

        debug!("Final user after augmenters: {:?}", user);
        Some(user)
    }
}

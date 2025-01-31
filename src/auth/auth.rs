use std::sync::Arc;

use crate::models::User;
use crate::store::Store;
use futures::future;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use super::ecmwfapi_provider::{EcmwfApiProvider, EcmwfApiProviderConfig};
use super::jwt_provider::{JWTAuthConfig, JWTProvider};
use super::ldap_augmenter::{LDAPAugmenter, LDAPAugmenterConfig};
use super::openid_offline_provider::{OpenIDOfflineProvider, OpenIDOfflineProviderConfig};
use super::plain_provider::{PlainAuthConfig, PlainAuthProvider};

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

#[derive(Deserialize, Serialize, JsonSchema, Debug)]
#[serde(tag = "type")]
pub enum AugmenterConfig {
    #[serde(rename = "ldap")]
    LDAPAugmenterConfig(LDAPAugmenterConfig),
}

/// Trait describing a basic authentication provider.
#[async_trait::async_trait]
pub trait Provider: Send + Sync {
    fn get_name(&self) -> &str;
    fn get_type(&self) -> &str;
    async fn authenticate(&self, credentials: &str) -> Result<User, String>;
}

/// Trait describing an augmenter (e.g. retrieving LDAP roles).
#[async_trait::async_trait]
pub trait Augmenter: Send + Sync {
    fn get_name(&self) -> &str;
    fn get_type(&self) -> &str;
    fn get_realm(&self) -> &str;
    async fn augment(&self, user: &mut User) -> Result<(), String>;
}

/// Produces a boxed provider based on the config variant.
pub fn create_auth_provider(config: &ProviderConfig) -> Box<dyn Provider> {
    match config {
        ProviderConfig::EcmwfApiAuthConfig(cfg) => Box::new(EcmwfApiProvider::new(cfg)),
        ProviderConfig::JWTAuthConfig(cfg) => Box::new(JWTProvider::new(cfg)),
        ProviderConfig::OpenIDOfflineAuthConfig(cfg) => Box::new(OpenIDOfflineProvider::new(cfg)),
        ProviderConfig::PlainAuthConfig(cfg) => Box::new(PlainAuthProvider::new(cfg)),
    }
}

/// Produces a boxed augmenter based on the config variant.
pub fn create_auth_augmenter(config: &AugmenterConfig) -> Box<dyn Augmenter> {
    match config {
        AugmenterConfig::LDAPAugmenterConfig(cfg) => Box::new(LDAPAugmenter::new(cfg)),
    }
}

/// The main Auth struct, holding all providers, augmenters, and a reference to the store.
pub struct Auth {
    pub providers: Vec<Box<dyn Provider>>,
    pub augmenters: Vec<Box<dyn Augmenter>>,
    #[allow(dead_code)]
    token_store: Arc<dyn Store>,
}

impl Auth {
    pub fn new(
        provider_config: &[ProviderConfig],
        augmenter_config: &[AugmenterConfig],
        token_store: Arc<dyn Store>,
    ) -> Self {
        info!("Creating auth providers...");
        // Convert each config to a provider, plus add the store-based token provider
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
        }
    }

    /// Attempts authentication across all matching providers, returning the first successful User,
    /// then enriches the user using augmenters for that realm, or returns None if no provider succeeds.
    pub async fn authenticate(&self, auth_header: &str, ip: &str) -> Option<User> {
        // Basic checking of the header format
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

        // Filter providers that match the auth header type
        let valid_providers: Vec<_> = self
            .providers
            .iter()
            .filter(|p| p.get_type().eq_ignore_ascii_case(auth_type))
            .collect();

        if valid_providers.is_empty() {
            warn!("No providers found for auth type: '{}'", auth_type);
            return None;
        }

        // Run them in parallel
        let futures: Vec<_> = valid_providers
            .iter()
            .map(|provider| provider.authenticate(auth_credentials))
            .collect();
        let results = future::join_all(futures).await;

        let mut user_opt: Option<User> = None;
        for (provider, result) in valid_providers.iter().zip(results) {
            match result {
                Ok(u) => {
                    info!(
                        "Provider '{}' authenticated user '{}'",
                        provider.get_name(),
                        u.username
                    );
                    user_opt = Some(u);
                    break;
                }
                Err(e) => warn!("Provider '{}' failed: {}", provider.get_name(), e),
            }
        }

        let mut user = match user_opt {
            Some(u) => u,
            None => {
                warn!("All providers failed; no authentication succeeded.");
                return None;
            }
        };

        // Augment the user if any augmenters match the user's realm
        let realm = user.realm.clone();
        let matching_augmenters = self
            .augmenters
            .iter()
            .filter(|aug| aug.get_realm() == realm);

        for aug in matching_augmenters {
            match aug.augment(&mut user).await {
                Ok(_) => info!(
                    "Augmenter '{}' succeeded for '{}'!",
                    aug.get_name(),
                    user.username
                ),
                Err(e) => warn!("Augmenter '{}' failed: {}", aug.get_name(), e),
            }
        }

        debug!("Final user after augmenters: {:?}", user);
        Some(user)
    }
}

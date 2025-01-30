use std::sync::Arc;

use futures::future;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::models::User;
use crate::store::Store;

pub mod ecmwfapi_provider;
pub mod jwt_provider;
pub mod ldap_augmenter;
pub mod openid_offline_provider;
pub mod plain_provider;

use ecmwfapi_provider::{EcmwfApiProvider, EcmwfApiProviderConfig};
use jwt_provider::{JWTAuthConfig, JWTProvider};
use ldap_augmenter::LDAPAugmenterConfig;
use openid_offline_provider::{OpenIDOfflineProvider, OpenIDOfflineProviderConfig};
use plain_provider::{PlainAuthConfig, PlainAuthProvider};


/// A config enum to select which provider we use (ECMWF API, JWT, OpenID Offline, Plain).
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

/// A config enum to select which augmenter we use (LDAP, etc.).
#[derive(Deserialize, Serialize, JsonSchema, Debug)]
#[serde(tag = "type")]
pub enum AugmenterConfig {
    #[serde(rename = "ldap")]
    LDAPAugmenterConfig(LDAPAugmenterConfig),
}

/// Trait describing a basic authentication provider (Bearer, Basic, etc.).
#[async_trait::async_trait]
pub trait Provider: Send + Sync {
    fn get_name(&self) -> &str;
    fn get_type(&self) -> &str;
    async fn authenticate(&self, credentials: &str) -> Result<User, String>;
}

/// Trait describing an augmenter that can enrich an authenticated user.
#[async_trait::async_trait]
pub trait Augmenter: Send + Sync {
    fn get_name(&self) -> &str;
    #[allow(unused)]
    fn get_type(&self) -> &str;
    fn get_realm(&self) -> &str;
    async fn augment(&self, user: &mut User) -> Result<(), String>;
}

/// Creates a dynamic auth provider based on the given provider config.
pub fn create_auth_provider(config: &ProviderConfig) -> Box<dyn Provider> {
    match config {
        ProviderConfig::EcmwfApiAuthConfig(cfg) => Box::new(EcmwfApiProvider::new(cfg)),
        ProviderConfig::JWTAuthConfig(cfg) => Box::new(JWTProvider::new(cfg)),
        ProviderConfig::OpenIDOfflineAuthConfig(cfg) => Box::new(OpenIDOfflineProvider::new(cfg)),
        ProviderConfig::PlainAuthConfig(cfg) => Box::new(PlainAuthProvider::new(cfg)),
    }
}

/// Creates a dynamic auth augmenter based on the given augmenter config.
pub fn create_auth_augmenter(config: &AugmenterConfig) -> Box<dyn Augmenter> {
    match config {
        AugmenterConfig::LDAPAugmenterConfig(cfg) => {
            Box::new(ldap_augmenter::LDAPAugmenter::new(cfg))
        }
    }
}

/// The main Auth struct, holding all providers and augmenters, plus a token store.
pub struct Auth {
    pub providers: Vec<Box<dyn Provider>>,
    pub augmenters: Vec<Box<dyn Augmenter>>,
    #[allow(dead_code)]
    token_store: Arc<dyn Store>,
}

impl Auth {
    /// Constructs a new `Auth` with the given provider/augmenter configs, plus a reference to the token store.
    pub fn new(
        provider_config: &[ProviderConfig],
        augmenter_config: &[AugmenterConfig],
        token_store: Arc<dyn Store>,
    ) -> Self {
        info!("Creating auth providers...");
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

    /// Orchestrates authentication by:
    /// 1) Parsing the `Authorization` header.
    /// 2) Finding all providers that match the "type" in the header.
    /// 3) Attempting to authenticate with each matching provider **in parallel** (to avoid blocking on a slow/offline one).
    /// 4) Once all complete, we pick the first success in provider order.
    /// 5) If successfully authenticated, run augmenters matching the user's realm.
    /// 6) Return `Some(User)` on success, or `None` on failure.
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

        // Find providers that match the auth_type
        let valid_providers: Vec<&Box<dyn Provider>> = self
            .providers
            .iter()
            .filter(|p| p.get_type().eq_ignore_ascii_case(auth_type))
            .collect();

        if valid_providers.is_empty() {
            warn!("No providers found for auth type: '{}'", auth_type);
            return None;
        }

        // Spawn all provider authenticates in parallel via join_all.
        let futures: Vec<_> = valid_providers
            .iter()
            .map(|provider| provider.authenticate(auth_credentials))
            .collect();

        let results = future::join_all(futures).await;

        // Iterate over results in the same order as the providers were listed.
        let mut user_opt: Option<User> = None;
        for (provider, result) in valid_providers.iter().zip(results) {
            match result {
                Ok(user) => {
                    info!(
                        "Provider '{}' authenticated user '{}'",
                        provider.get_name(),
                        user.username
                    );
                    user_opt = Some(user);
                    break;
                }
                Err(e) => {
                    warn!(
                        "Provider '{}' failed to authenticate: {}",
                        provider.get_name(),
                        e
                    );
                }
            }
        }

        let mut user = match user_opt {
            Some(u) => u,
            None => {
                warn!("All providers failed; no authentication succeeded.");
                return None;
            }
        };

        // If we have a user, run augmenters for that user's realm.
        let realm = user.realm.clone();
        let valid_augmenters = self
            .augmenters
            .iter()
            .filter(|augmenter| augmenter.get_realm() == realm);

        for augmenter in valid_augmenters {
            match augmenter.augment(&mut user).await {
                Ok(_) => {
                    info!(
                        "Augmenter '{}' succeeded for user '{}'",
                        augmenter.get_name(),
                        user.username
                    );
                }
                Err(e) => {
                    warn!(
                        "Augmenter '{}' failed for user '{}': {}",
                        augmenter.get_name(),
                        user.username,
                        e
                    );
                }
            }
        }

        debug!("Final user object after augmentation: {:?}", user);
        Some(user)
    }
}

pub mod ecmwfapi_provider;
pub mod jwt_provider;
pub mod ldap_augmenter;
pub mod openid_offline_provider;

use std::sync::Arc;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use self::ecmwfapi_provider::{EcmwfApiProvider, EcmwfApiProviderConfig};
use self::jwt_provider::{JWTAuthConfig, JWTProvider};
use self::openid_offline_provider::{OpenIDOfflineProvider, OpenIDOfflineProviderConfig};
use crate::models::User;
use crate::store::Store;
use futures::future::join_all;
use tracing::{debug, info, warn};

use self::ldap_augmenter::LDAPAugmenterConfig;

// --- Config

#[derive(Deserialize, Serialize, JsonSchema, Debug)]
#[serde(tag = "type")]
pub enum ProviderConfig {
    #[serde(rename = "ecmwf-api")]
    EcmwfApiAuthConfig(EcmwfApiProviderConfig),

    #[serde(rename = "jwt")]
    JWTAuthConfig(JWTAuthConfig),

    #[serde(rename = "openid-offline")]
    OpenIDOfflineAuthConfig(OpenIDOfflineProviderConfig),
}

#[derive(Deserialize, Serialize, JsonSchema, Debug)]
#[serde(tag = "type")]
pub enum AugmenterConfig {
    #[serde(rename = "ldap")]
    LDAPAugmenterConfig(LDAPAugmenterConfig),
}

// --- Providers

#[async_trait::async_trait]
pub trait Provider: Send + Sync {
    fn get_name(&self) -> &str;
    fn get_type(&self) -> &str;
    async fn authenticate(&self, credentials: &str) -> Result<User, String>;
}

#[async_trait::async_trait]
pub trait Augmenter: Send + Sync {
    fn get_name(&self) -> &str;
    #[allow(unused)]
    fn get_type(&self) -> &str;
    fn get_realm(&self) -> &str;
    async fn augment(&self, user: &mut User) -> Result<(), String>;
}

// ---

pub struct Auth {
    pub providers: Vec<Box<dyn Provider>>,
    pub augmenters: Vec<Box<dyn Augmenter>>,
    #[allow(dead_code)]
    token_store: Arc<dyn Store>,
}

pub fn create_auth_provider(config: &ProviderConfig) -> Box<dyn Provider> {
    match config {
        ProviderConfig::EcmwfApiAuthConfig(config) => {
            Box::new(EcmwfApiProvider::new(config)) as Box<dyn Provider>
        }
        ProviderConfig::JWTAuthConfig(config) => {
            Box::new(JWTProvider::new(config)) as Box<dyn Provider>
        }
        ProviderConfig::OpenIDOfflineAuthConfig(config) => {
            Box::new(OpenIDOfflineProvider::new(config)) as Box<dyn Provider>
        }
    }
}

pub fn create_auth_augmenter(config: &AugmenterConfig) -> Box<dyn Augmenter> {
    match config {
        AugmenterConfig::LDAPAugmenterConfig(config) => {
            Box::new(self::ldap_augmenter::LDAPAugmenter::new(config)) as Box<dyn Augmenter>
        }
    }
}

impl Auth {
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

    pub async fn authenticate(&self, auth_header: &str, ip: &str) -> Option<User> {
        let parts: Vec<&str> = auth_header.split_whitespace().collect();
        if parts.len() != 2 {
            warn!("Authorization header invalid format: '{}'", auth_header);
            return None;
        }

        let auth_type = parts[0];
        let auth_credentials = parts[1];
        let mut first: Option<User> = None;

        debug!("Authenticating with '{}' header from {}", auth_type, ip);

        // Filter providers by matching auth_type
        let valid_providers: Vec<&Box<dyn Provider>> = self
            .providers
            .iter()
            .filter(|provider| provider.get_type().eq_ignore_ascii_case(auth_type))
            .collect();

        if valid_providers.is_empty() {
            warn!("No providers found for auth type: '{}'", auth_type);
            return None;
        }

        // Attempt authentication in parallel for all providers of this type
        let futures: Vec<_> = valid_providers
            .iter()
            .map(|provider| provider.authenticate(auth_credentials))
            .collect();

        let results = join_all(futures).await;
        for (provider, result) in valid_providers.iter().zip(results) {
            match result {
                Ok(user) => {
                    info!(
                        "Provider '{}' authentication succeeded for user '{}'",
                        provider.get_name(),
                        user.username
                    );
                    first = Some(user);
                }
                Err(e) => {
                    warn!(
                        "Provider '{}' authentication failed: {}",
                        provider.get_name(),
                        e
                    );
                }
            }
        }

        let mut user = match first {
            Some(user) => {
                info!(
                    "User '{}' authenticated in realm '{}'",
                    user.username, user.realm
                );
                user
            }
            None => {
                warn!("No provider could authenticate the user.");
                return None;
            }
        };

        // Augment user data if we have augmenters for this realm
        let realm = user.realm.clone();
        let valid_augmenters = self
            .augmenters
            .iter()
            .filter(|augmenter| augmenter.get_realm() == realm);

        for augmenter in valid_augmenters {
            match augmenter.augment(&mut user).await {
                Ok(_) => {
                    info!("Augmenter '{}' succeeded", augmenter.get_name());
                }
                Err(e) => {
                    warn!("Augmenter '{}' failed: {}", augmenter.get_name(), e);
                }
            }
        }

        debug!("Final user object after augmentation: {:?}", user);
        Some(user)
    }
}

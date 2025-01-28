pub mod ecmwfapi_provider;
pub mod jwt_provider;
pub mod ldap_augmenter;
pub mod openid_offline_provider;

use std::sync::Arc;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use self::ecmwfapi_provider::{EcmwfApiProvider, EcmwfApiProviderConfig};
use self::jwt_provider::{JWTAuthConfig, JWTProvider};
use self::openid_offline_provider::{OpenIDOfflineProvider, OpenIDOfflineProviderConfig};
use crate::models::User;
use crate::store::Store;

use self::ldap_augmenter::LDAPAugmenterConfig;

/// A config enum to select which provider we use (ECMWF API, JWT, or OpenID Offline).
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

/// A config enum to select which augmenter we use (LDAP, etc.).
#[derive(Deserialize, Serialize, JsonSchema, Debug)]
#[serde(tag = "type")]
pub enum AugmenterConfig {
    #[serde(rename = "ldap")]
    LDAPAugmenterConfig(LDAPAugmenterConfig),
}

/// A Provider is responsible for authenticating user credentials (e.g., a token).
#[async_trait::async_trait]
pub trait Provider: Send + Sync {
    /// A descriptive name for the provider (for logs/debug).
    fn get_name(&self) -> &str;

    /// The "type" (e.g., "Bearer", "Basic") to match against in the Authorization header.
    fn get_type(&self) -> &str;

    /// Given some credentials (e.g., a token), tries to produce a `User`.
    async fn authenticate(&self, credentials: &str) -> Result<User, String>;
}

/// An Augmenter can modify/enrich a `User` record after basic auth is done.
#[async_trait::async_trait]
pub trait Augmenter: Send + Sync {
    fn get_name(&self) -> &str;
    #[allow(unused)]
    fn get_type(&self) -> &str;
    fn get_realm(&self) -> &str;

    /// Modifies the given `User` (e.g., fetch extra roles from LDAP).
    async fn augment(&self, user: &mut User) -> Result<(), String>;
}

/// Takes a `ProviderConfig` and produces a boxed provider instance.
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

/// Takes an `AugmenterConfig` and produces a boxed augmenter instance.
pub fn create_auth_augmenter(config: &AugmenterConfig) -> Box<dyn Augmenter> {
    match config {
        AugmenterConfig::LDAPAugmenterConfig(config) => {
            Box::new(self::ldap_augmenter::LDAPAugmenter::new(config)) as Box<dyn Augmenter>
        }
    }
}

/// The main Auth struct holds multiple providers and augmenters, plus
/// a reference to the store for tokens.
///
/// - `providers`: A list of possible ways to authenticate (JWT, ECMWF, Bearer tokens from DB, etc.).
/// - `augmenters`: A list of ways to enrich user data if the realm matches (e.g., LDAP).
/// - `token_store`: The store is also a provider, so it's appended as well.
pub struct Auth {
    pub providers: Vec<Box<dyn Provider>>,
    pub augmenters: Vec<Box<dyn Augmenter>>,
    #[allow(dead_code)]
    token_store: Arc<dyn Store>,
}

impl Auth {
    /// Creates a new `Auth` instance from the provider/augmenter configs and token store.
    pub fn new(
        provider_config: &[ProviderConfig],
        augmenter_config: &[AugmenterConfig],
        token_store: Arc<dyn Store>,
    ) -> Self {
        info!("Creating auth providers...");
        let providers = provider_config
            .iter()
            .map(create_auth_provider)
            // Also treat the token store as a Bearer provider
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
    /// 3) Attempting to authenticate using each provider (in **sequence**, stopping on the first success**).
    /// 4) If authenticated, run any augmenters that match the user's realm.
    /// 5) Return `Some(User)` on success, or `None` on failure.
    pub async fn authenticate(&self, auth_header: &str, ip: &str) -> Option<User> {
        // Example: "Bearer <token_value>"
        let parts: Vec<&str> = auth_header.split_whitespace().collect();
        if parts.len() != 2 {
            // Possibly a misconfigured or missing header
            warn!("Authorization header invalid format: '{}'", auth_header);
            return None;
        }

        let auth_type = parts[0];
        let auth_credentials = parts[1];

        debug!(
            "Authenticating with auth_type='{}' from IP='{}'",
            auth_type, ip
        );

        // Find providers that claim to handle this type (case-insensitive match).
        let valid_providers: Vec<&Box<dyn Provider>> = self
            .providers
            .iter()
            .filter(|provider| provider.get_type().eq_ignore_ascii_case(auth_type))
            .collect();

        if valid_providers.is_empty() {
            // We have no providers that match this auth_type => can't authenticate
            warn!("No providers found for auth type: '{}'", auth_type);
            return None;
        }

        // We'll try each matching provider in sequence, stopping at the first success.
        let mut first_successful_user: Option<User> = None;
        for provider in valid_providers {
            match provider.authenticate(auth_credentials).await {
                Ok(user) => {
                    // Found a valid user from this provider; log success and break.
                    info!(
                        "Provider '{}' authenticated user '{}'",
                        provider.get_name(),
                        user.username
                    );
                    first_successful_user = Some(user);
                    break;
                }
                Err(e) => {
                    debug!(
                        "Provider '{}' failed to authenticate: {}",
                        provider.get_name(),
                        e
                    );
                }
            }
        }

        // If no providers succeeded, return None
        let mut user = match first_successful_user {
            Some(u) => u,
            None => {
                warn!("All providers failed; no authentication succeeded.");
                return None;
            }
        };

        // Now run any augmenters that match the user's realm,
        // to add roles/attributes from external sources (e.g., LDAP).
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

        // Return the authenticated and augmented user
        Some(user)
    }
}

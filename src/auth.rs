pub mod ecmwfapi_provider;
pub mod jwt_provider;
pub mod openid_offline_provider;
pub mod ldap_augmenter;

use serde::Deserialize;

use self::ecmwfapi_provider::EcmwfApiProvider;
use self::ecmwfapi_provider::EcmwfApiProviderConfig;
use self::jwt_provider::JWTProvider;
use self::jwt_provider::JWTAuthConfig;
use self::openid_offline_provider::OpenIDOfflineProviderConfig;
use self::openid_offline_provider::OpenIDOfflineProvider;
use crate::models::User;
use futures::future::join_all;

use inline_colorization::*;

use self::ldap_augmenter::LDAPAugmenterConfig;

// --- Config

#[derive(Deserialize, Debug)]
#[serde(tag = "type")]
pub enum ProviderConfig {
    #[serde(rename = "ecmwf-api")]
    EcmwfApiAuthConfig(EcmwfApiProviderConfig),

    #[serde(rename = "jwt")]
    JWTAuthConfig(JWTAuthConfig),

    #[serde(rename = "openid-offline")]
    OpenIDOfflineAuthConfig(OpenIDOfflineProviderConfig),
}

#[derive(Deserialize, Debug)]
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
    fn get_type(&self) -> &str;
    fn get_realm(&self) -> &str;
    async fn augment(&self, user: &mut User) -> Result<(), String>;
}


// ---

pub struct Auth {
    pub providers: Vec<Box<dyn Provider>>,
    pub augmenters: Vec<Box<dyn Augmenter>>,
}

pub fn create_auth_provider(config: ProviderConfig) -> Box<dyn Provider> {
    match config {
        ProviderConfig::EcmwfApiAuthConfig(config) => {
            let provider = EcmwfApiProvider::new(config);
            Box::new(provider) as Box<dyn Provider>
        }
        ProviderConfig::JWTAuthConfig(config) => {
            let provider = JWTProvider::new(config);
            Box::new(provider) as Box<dyn Provider>
        }
        ProviderConfig::OpenIDOfflineAuthConfig(config) => {
            let provider = OpenIDOfflineProvider::new(config);
            Box::new(provider) as Box<dyn Provider>
        }
    }
}

pub fn create_auth_augmenter(config: AugmenterConfig) -> Box<dyn Augmenter> {
    match config {
        AugmenterConfig::LDAPAugmenterConfig(config) => {
            let augmenter = ldap_augmenter::LDAPAugmenter::new(config);
            Box::new(augmenter) as Box<dyn Augmenter>
        }
    }
}

impl Auth {
    pub fn new(provider_config: Vec<ProviderConfig>, augmenter_config: Vec<AugmenterConfig>) -> Self {
        println!("{color_magenta}{style_bold}Creating auth providers...{color_reset}{style_reset}");
        let providers = provider_config.into_iter().map(create_auth_provider).collect();
        println!("{color_magenta}{style_bold}Creating auth augmenters...{color_reset}{style_reset}");
        let augmenters = augmenter_config.into_iter().map(create_auth_augmenter).collect();
        Auth { providers, augmenters }
    }

    pub async fn authenticate(&self, auth_header: &str, ip: &str) -> Option<User> {
        let parts: Vec<&str> = auth_header.split_whitespace().collect();

        if parts.len() != 2 {
            println!(
                "❌ Authorization header could not be split into auth_type and credentials: {}",
                auth_header
            );
            return None;
        }

        let auth_type = parts[0];
        let auth_credentials = parts[1];

        let mut first: Option<User> = None;

        println!(
            "🛡️  Authenticating with {style_bold}{}{style_reset} header from {}...",
            auth_type, ip
        );

        let valid_providers: Vec<&Box<dyn Provider>> = self
            .providers
            .iter()
            .filter(|provider| provider.get_type().to_lowercase() == auth_type.to_lowercase())
            .collect();

        if valid_providers.len() == 0 {
            println!("❌ No providers found for auth type: {}", auth_type);
            return None;
        }

        let futures: Vec<_> = valid_providers
            .iter()
            .map(|provider| provider.authenticate(auth_credentials))
            .collect();
        let results = join_all(futures).await;

        for (provider, result) in valid_providers.iter().zip(results) {
            match result {
                Ok(user) => {
                    println!(
                        "  🟢 {style_bold}{}{style_reset} authentication succeeded",
                        provider.get_name()
                    );
                    first = Some(user);
                }
                Err(e) => {
                    println!(
                        "  🟠 {style_bold}{}{style_reset} authentication failed ({})",
                        provider.get_name(),
                        e
                    );
                }
            }
        }

        let mut user = match first {
            Some(user) => {
                println!("  👤 found user {style_bold}{color_bright_magenta}{}{color_reset}{style_reset} in realm {style_bold}{}{style_reset}", user.username, user.realm);
                user
            },
            None => {
                println!("  ❌ no provider could authenticate the user.");
                return None;
            }
        };

        let realm = user.realm.clone();

        let valid_augmenters = self.augmenters.iter().filter(|augmenter| {
            augmenter.get_realm() == realm
        });

        for augmenter in valid_augmenters {

            match augmenter.augment(&mut user).await {
                Ok(_) => {
                    println!(
                        "  🟢 {style_bold}{}{style_reset} augmentation succeeded",
                        augmenter.get_name()
                    );
                }
                Err(e) => {
                    println!(
                        "  🟠 {style_bold}{}{style_reset} augmentation failed ({})",
                        augmenter.get_name(),
                        e
                    );
                }
            
            }
        }
        
        println!("  🎉 authenticated user: {:?}", user);

        Some(user)
    }
}

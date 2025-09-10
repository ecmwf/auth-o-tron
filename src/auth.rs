use std::collections::HashMap;
use std::sync::Arc;

use crate::augmenters::{create_auth_augmenter, Augmenter, AugmenterConfig};
use crate::config::AuthConfig;
use crate::models::user::User;
use crate::providers::{create_auth_provider, Provider, ProviderConfig};
use crate::store::Store;
use futures::future::{join_all, select_ok, FutureExt};
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

    /// Authenticates a user using the first provider that succeeds.
    /// Each provider call is wrapped in a timeout so that a slow or non-responsive provider
    /// won't block the others. If all providers fail or time out, returns None.
    ///
    /// - `auth_header`: The value from the Authorization header (may contain comma-separated credentials).
    /// - `ip`: The client IP address (logged for debugging purposes).
    /// - `realm_filter`: An optional realm string taken from the X-Auth-Realm header.
    pub async fn authenticate(
        &self,
        auth_header: &str,
        ip: &str,
        realm_filter: Option<&str>,
    ) -> Option<User> {
        if auth_header.trim().is_empty() {
            warn!("No Authorization header provided.");
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
                return None;
            }
            // Each part should be in the format: <scheme> <credentials>
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() != 2 {
                warn!("Invalid auth part format: '{}'", trimmed);
                return None;
            }
            let raw_scheme = parts[0];
            let credential = parts[1];
            let normalized_scheme = header_to_provider_type(raw_scheme);
            creds_map.insert(normalized_scheme, credential.to_string());
        }

        let user = self.check_providers(creds_map, realm_filter).await?;
        let user = self.check_augmenters(user).await?;

        return Some(user);
    }

    async fn check_providers(
        &self,
        creds_map: HashMap<String, String>,
        realm_filter: Option<&str>,
    ) -> Option<User> {
        // Try each provided credential until one provider successfully authenticates.
        for (scheme, credential) in creds_map.into_iter() {
            // Set the timeout duration based on the configuration.
            let timeout_duration = std::time::Duration::from_secs(self.config.timeout_in_ms);
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
                    let cred = credential.clone();
                    async move {
                        match timeout(timeout_duration, provider.authenticate(&cred)).await {
                            Ok(Ok(user)) => Ok((name, user)),
                            Ok(Err(e)) => {
                                debug!("Provider '{}' failed to authenticate: {}", name, e);
                                Err(format!("Provider '{}' failed: {}", name, e))
                            }
                            Err(_) => {
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
                    // Continue with the next credential if available.
                }
            }
        }
        None
    }

    async fn check_augmenters(&self, user: User) -> Option<User> {
        info!("Applying augmentations for user '{}'", user.username);
        let realm = user.realm.clone();
        let user = Arc::new(Mutex::new(user));
        let futures = self
            .augmenters
            .iter()
            .filter(|a| a.get_realm() == realm)
            .map(|augmenter| augmenter.augment(user.clone()));
        let _ = join_all(futures).await;

        // Return the authenticated user.
        return Some(user.lock().await.clone());
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

        let user = User {
            username: "bob".to_string(),
            roles: vec![],
            realm: "r1".to_string(),
            ..Default::default()
        };
        let user = auth.check_augmenters(user).await.unwrap();
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
        let user = User {
            username: "bob".to_string(),
            roles: vec![],
            realm: "r2".to_string(),
            ..Default::default()
        };
        let user = auth.check_augmenters(user).await.unwrap();
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
        let user = User {
            username: "bob".to_string(),
            roles: vec![],
            realm: "r1".to_string(),
            ..Default::default()
        };
        let user = auth.check_augmenters(user).await.unwrap();
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

        // Test authentication with a valid Basic credential.
        let user = auth
            .authenticate("Basic ZHVtbXk6ZHVtbXk=", "127.0.0.1", Some("localrealm"))
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

        // Test with a comma-separated header that contains both credentials.
        // The dummy bearer provider is expected to succeed with "someBearerToken".
        // The dummy basic provider is expected to succeed with "ZHVtbXk6ZHVtbXk=".
        // We use select_ok select_ok, which returns the first successful future it finds
        let header = "Bearer someBearerToken, Basic ZHVtbXk6ZHVtbXk=";
        let user = auth
            .authenticate(header, "127.0.0.1", Some("localrealm"))
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

        // When the realm filter is "localrealm", only the provider with that realm should be used.
        let header = "Basic ZHVtbXk6ZHVtbXk=";
        let user_local = auth
            .authenticate(header, "127.0.0.1", Some("localrealm"))
            .await;
        assert!(
            user_local.is_some(),
            "Authentication should succeed for realm 'localrealm'"
        );

        // When the realm filter is "otherrealm", only the other provider should be used.
        let user_other = auth
            .authenticate(header, "127.0.0.1", Some("otherrealm"))
            .await;
        assert!(
            user_other.is_some(),
            "Authentication should succeed for realm 'otherrealm'"
        );

        // When the realm filter does not match any provider, authentication should fail.
        let user_none = auth
            .authenticate(header, "127.0.0.1", Some("nonexistent"))
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
        // Duplicate header part (should only check once, and succeed)
        let header = "Basic ZHVtbXk6ZHVtbXk=, Basic ZHVtbXk6ZHVtbXk=";
        let user = auth
            .authenticate(header, "127.0.0.1", Some("localrealm"))
            .await;
        assert!(
            user.is_some(),
            "Duplicate headers should be checked just once and succeed"
        );

        // duplicate wrong header gets rejected
        let wrong_header = "Basic wrong, Basic wrong";
        let user = auth
            .authenticate(wrong_header, "127.0.0.1", Some("localrealm"))
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
        // 4 unique header parts (should be rejected)
        let header = "Basic a, Basic b, Basic ZHVtbXk6ZHVtbXk=, Basic c";
        let user = auth
            .authenticate(header, "127.0.0.1", Some("localrealm"))
            .await;
        assert!(
            user.is_none(),
            "More than 3 unique headers should be rejected"
        );
        // check that if correct header is third user is authenticated
        let header = "Basic a, Basic b, Basic ZHVtbXk6ZHVtbXk=";
        let user = auth
            .authenticate(header, "127.0.0.1", Some("localrealm"))
            .await;
        assert!(
            user.is_some(),
            "User should be authenticated with the correct header"
        );
    }
}

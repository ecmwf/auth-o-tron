// (C) Copyright 2025- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

use std::{
    borrow::Cow,
    fmt,
    sync::{Arc, OnceLock},
};

use argon2::{Argon2, PasswordHash, PasswordVerifier};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose};
use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::sync::Semaphore;
use tracing::{debug, warn};

use crate::models::user::User;
use crate::providers::Provider;

/// PlainAuthConfig defines the data for Basic authentication.
#[derive(Deserialize, Serialize, Debug, JsonSchema, Clone)]
pub struct PlainAuthConfig {
    /// A friendly name for logs.
    pub name: String,
    /// The realm associated with this provider.
    pub realm: String,
    /// A list of users and their password credentials.
    pub users: Vec<PlainUserEntry>,
}

/// Represents a single user entry and its password credential.
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct PlainUserEntry {
    pub username: String,
    /// Exactly one Argon2id hash or deprecated plaintext password.
    #[serde(flatten)]
    pub credential: PlainCredential,
    pub roles: Option<Vec<String>>,
}

impl JsonSchema for PlainUserEntry {
    fn schema_name() -> Cow<'static, str> {
        "PlainUserEntry".into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "description": "A plain-provider user with exactly one password credential.",
            "type": "object",
            "properties": {
                "username": { "type": "string" },
                "password_hash": {
                    "description": "An Argon2id hash in PHC string format (recommended).",
                    "type": "string"
                },
                "password": {
                    "description": "Deprecated plaintext password. Use password_hash instead.",
                    "type": "string",
                    "deprecated": true
                },
                "roles": {
                    "type": ["array", "null"],
                    "items": { "type": "string" }
                }
            },
            "required": ["username"],
            "oneOf": [
                { "required": ["password_hash"] },
                { "required": ["password"] }
            ],
            "additionalProperties": false
        })
    }
}

/// Password configuration for a plain-provider user.
#[derive(Deserialize, Serialize, JsonSchema, Clone)]
#[serde(untagged)]
pub enum PlainCredential {
    /// Preferred Argon2id PHC string.
    Argon2id(Argon2idCredential),
    /// Deprecated plaintext compatibility.
    Plaintext(PlaintextCredential),
}

#[derive(Deserialize, Serialize, JsonSchema, Clone)]
#[serde(deny_unknown_fields)]
pub struct Argon2idCredential {
    /// An Argon2id hash in PHC string format.
    pub password_hash: String,
}

#[derive(Deserialize, Serialize, JsonSchema, Clone)]
#[serde(deny_unknown_fields)]
pub struct PlaintextCredential {
    /// Deprecated: plaintext password. Use `password_hash` instead.
    pub password: String,
}

impl fmt::Debug for PlainCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PlainCredential([REDACTED])")
    }
}

const MAX_CONCURRENT_ARGON2_JOBS: usize = 2;
const DUMMY_ARGON2ID_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$YXV0aG90cm9uLWRvYy0wMA$nIbsJAh7Dy4U3lp30gdyZp5xIvGEixDw6egf5H1ckpQ";
const DUMMY_PLAINTEXT: &[u8] = b"authotron-dummy-plaintext-password";

type Argon2Verification = dyn Fn(&str, &[u8]) -> bool + Send + Sync;

struct BoundedArgon2Verifier {
    permits: Arc<Semaphore>,
    verification: Arc<Argon2Verification>,
}

impl BoundedArgon2Verifier {
    fn new<F>(concurrency: usize, verification: F) -> Self
    where
        F: Fn(&str, &[u8]) -> bool + Send + Sync + 'static,
    {
        Self {
            permits: Arc::new(Semaphore::new(concurrency.max(1))),
            verification: Arc::new(verification),
        }
    }

    async fn verify(&self, password_hash: &str, candidate: &[u8]) -> bool {
        let Ok(permit) = self.permits.clone().acquire_owned().await else {
            return false;
        };
        let password_hash = password_hash.to_owned();
        let candidate = candidate.to_vec();
        let verification = Arc::clone(&self.verification);

        tokio::task::spawn_blocking(move || {
            // The blocking closure owns the permit so cancellation or request timeout
            // cannot release capacity while Argon2 work is still running.
            let _permit = permit;
            verification(&password_hash, &candidate)
        })
        .await
        .unwrap_or(false)
    }
}

fn shared_argon2_verifier() -> Arc<BoundedArgon2Verifier> {
    static VERIFIER: OnceLock<Arc<BoundedArgon2Verifier>> = OnceLock::new();
    Arc::clone(VERIFIER.get_or_init(|| {
        let cpu_limit = std::thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(1);
        Arc::new(BoundedArgon2Verifier::new(
            cpu_limit.min(MAX_CONCURRENT_ARGON2_JOBS),
            verify_argon2id,
        ))
    }))
}

fn verify_argon2id(password_hash: &str, candidate: &[u8]) -> bool {
    if let Some(result) = verify_valid_argon2id(password_hash, candidate) {
        return result;
    }

    // Invalid configured hashes still consume work comparable to an unknown username.
    let _ = verify_valid_argon2id(DUMMY_ARGON2ID_HASH, candidate);
    false
}

fn verify_valid_argon2id(password_hash: &str, candidate: &[u8]) -> Option<bool> {
    let parsed_hash = PasswordHash::new(password_hash).ok()?;
    if parsed_hash.algorithm.as_str() != "argon2id" {
        return None;
    }

    Some(
        Argon2::default()
            .verify_password(candidate, &parsed_hash)
            .is_ok(),
    )
}

fn password_digest(password: &[u8]) -> [u8; 32] {
    Sha256::digest(password).into()
}

struct PreparedUser {
    username: String,
    credential: PreparedCredential,
    roles: Option<Vec<String>>,
}

enum PreparedCredential {
    Argon2id(String),
    PlaintextDigest([u8; 32]),
}

impl From<&PlainUserEntry> for PreparedUser {
    fn from(entry: &PlainUserEntry) -> Self {
        let credential = match &entry.credential {
            PlainCredential::Argon2id(credential) => {
                PreparedCredential::Argon2id(credential.password_hash.clone())
            }
            PlainCredential::Plaintext(credential) => {
                PreparedCredential::PlaintextDigest(password_digest(credential.password.as_bytes()))
            }
        };

        Self {
            username: entry.username.clone(),
            credential,
            roles: entry.roles.clone(),
        }
    }
}

/// A `PlainAuthProvider` that implements Basic authentication by
/// comparing credentials to the user list in `PlainAuthConfig`.
pub struct PlainAuthProvider {
    pub config: PlainAuthConfig,
    users: Vec<PreparedUser>,
    argon2_verifier: Arc<BoundedArgon2Verifier>,
    dummy_plaintext_digest: [u8; 32],
}

impl PlainAuthProvider {
    /// Create a new `PlainAuthProvider` from the config struct.
    pub fn new(config: &PlainAuthConfig) -> Self {
        Self::with_argon2_verifier(config, shared_argon2_verifier())
    }

    fn with_argon2_verifier(
        config: &PlainAuthConfig,
        argon2_verifier: Arc<BoundedArgon2Verifier>,
    ) -> Self {
        if config
            .users
            .iter()
            .any(|entry| matches!(&entry.credential, PlainCredential::Plaintext(_)))
        {
            warn!(
                event_name = "providers.plain.plaintext_password.deprecated",
                event_domain = "providers",
                provider_name = config.name.as_str(),
                realm = config.realm.as_str(),
                "plain provider uses deprecated plaintext passwords; use Argon2id password_hash entries"
            );
        }

        Self {
            config: config.clone(),
            users: config.users.iter().map(PreparedUser::from).collect(),
            argon2_verifier,
            dummy_plaintext_digest: password_digest(DUMMY_PLAINTEXT),
        }
    }
}

#[async_trait]
impl Provider for PlainAuthProvider {
    /// The display name for logs/debug.  
    fn get_name(&self) -> &str {
        &self.config.name
    }

    /// Return "Basic" so that `Auth::authenticate` will match
    /// `auth_type == "Basic"` to this provider.
    fn get_type(&self) -> &str {
        "Basic"
    }

    /// Return the realm associated with this provider.
    fn get_realm(&self) -> Option<&str> {
        Some(&self.config.realm)
    }

    /// Decode the credentials (base64-encoded "username:password") and check
    /// against the config’s user list. Return a `User` on success.
    async fn authenticate(&self, credentials: &str) -> Result<User, String> {
        // 1) Decode base64 -> bytes
        let decoded_bytes = match general_purpose::STANDARD.decode(credentials) {
            Ok(b) => b,
            Err(e) => {
                debug!(
                    event_name = "providers.plain.decode.failed",
                    event_domain = "providers",
                    error = e.to_string(),
                    "basic auth base64 decode failed"
                );
                return Err("Invalid base64 in Basic auth".to_string());
            }
        };

        // 2) Convert bytes -> UTF-8 string
        let decoded_str = match String::from_utf8(decoded_bytes) {
            Ok(s) => s,
            Err(e) => {
                debug!(
                    event_name = "providers.plain.decode.failed",
                    event_domain = "providers",
                    error = e.to_string(),
                    "basic auth payload is not valid UTF-8"
                );
                return Err("Invalid UTF-8 in Basic auth".to_string());
            }
        };

        // 3) Split into "username:password"
        let mut parts = decoded_str.splitn(2, ':');
        let user_part = parts.next().unwrap_or("");
        let pass_part = parts.next().unwrap_or("");

        if user_part.is_empty() {
            return Err("No username in Basic credentials".to_string());
        }

        // 4) Compare with the user list in config
        debug!(
            event_name = "providers.plain.authenticate.started",
            event_domain = "providers",
            realm = self.config.realm.as_str(),
            username = user_part,
            "basic authentication attempt"
        );
        let candidate_digest = password_digest(pass_part.as_bytes());
        let Some(entry) = self.users.iter().find(|entry| entry.username == user_part) else {
            let _ = self
                .argon2_verifier
                .verify(DUMMY_ARGON2ID_HASH, pass_part.as_bytes())
                .await;
            std::hint::black_box(
                self.dummy_plaintext_digest
                    .ct_eq(&candidate_digest)
                    .unwrap_u8(),
            );
            return Err("Wrong username or password".to_string());
        };

        let password_matches = match &entry.credential {
            PreparedCredential::Argon2id(password_hash) => {
                self.argon2_verifier
                    .verify(password_hash, pass_part.as_bytes())
                    .await
            }
            PreparedCredential::PlaintextDigest(expected_digest) => {
                let _ = self
                    .argon2_verifier
                    .verify(DUMMY_ARGON2ID_HASH, pass_part.as_bytes())
                    .await;
                expected_digest.ct_eq(&candidate_digest).into()
            }
        };

        if password_matches {
            return Ok(User::new(
                self.config.realm.clone(),
                user_part.to_string(),
                entry.roles.clone(),
                None,
                None,
                Some(1),
            ));
        }

        Err("Wrong username or password".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use argon2::{Algorithm, Params, PasswordHasher, Version, password_hash::SaltString};
    use base64::engine::general_purpose;
    use std::{
        sync::{
            Mutex,
            atomic::{AtomicUsize, Ordering},
            mpsc,
        },
        task::Poll,
    };

    struct BlockingVerifierHarness {
        verifier: Arc<BoundedArgon2Verifier>,
        started: tokio::sync::mpsc::UnboundedReceiver<()>,
        release: mpsc::Sender<()>,
        active: Arc<AtomicUsize>,
        maximum_active: Arc<AtomicUsize>,
    }

    fn blocking_verifier_harness(concurrency: usize) -> BlockingVerifierHarness {
        let (started_tx, started) = tokio::sync::mpsc::unbounded_channel();
        let (release, release_rx) = mpsc::channel();
        let release_rx = Arc::new(Mutex::new(release_rx));
        let active = Arc::new(AtomicUsize::new(0));
        let maximum_active = Arc::new(AtomicUsize::new(0));
        let closure_active = Arc::clone(&active);
        let closure_maximum = Arc::clone(&maximum_active);

        let verifier = Arc::new(BoundedArgon2Verifier::new(concurrency, move |_, _| {
            let active_now = closure_active.fetch_add(1, Ordering::SeqCst) + 1;
            closure_maximum.fetch_max(active_now, Ordering::SeqCst);
            started_tx
                .send(())
                .expect("test receiver should remain open");
            release_rx
                .lock()
                .expect("release mutex should not be poisoned")
                .recv()
                .expect("test should release each verification");
            closure_active.fetch_sub(1, Ordering::SeqCst);
            true
        }));

        BlockingVerifierHarness {
            verifier,
            started,
            release,
            active,
            maximum_active,
        }
    }

    fn plaintext(password: &str) -> PlainCredential {
        PlainCredential::Plaintext(PlaintextCredential {
            password: password.to_string(),
        })
    }

    fn argon2id(password: &str) -> PlainCredential {
        let params = Params::new(1024, 1, 1, None).expect("valid test Argon2 parameters");
        let hasher = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let salt = SaltString::encode_b64(b"authotron-tests!").expect("valid test salt");
        let password_hash = hasher
            .hash_password(password.as_bytes(), &salt)
            .expect("test password should hash")
            .to_string();
        PlainCredential::Argon2id(Argon2idCredential { password_hash })
    }

    fn create_test_config() -> PlainAuthConfig {
        PlainAuthConfig {
            name: "TestPlain".to_string(),
            realm: "test".to_string(),
            users: vec![
                PlainUserEntry {
                    username: "admin".to_string(),
                    credential: plaintext("admin123"),
                    roles: Some(vec!["admin".to_string(), "user".to_string()]),
                },
                PlainUserEntry {
                    username: "user1".to_string(),
                    credential: plaintext("password1"),
                    roles: Some(vec!["user".to_string()]),
                },
                PlainUserEntry {
                    username: "guest".to_string(),
                    credential: plaintext("guest123"),
                    roles: None, // No roles
                },
                PlainUserEntry {
                    username: "empty_roles".to_string(),
                    credential: plaintext("password"),
                    roles: Some(vec![]), // Empty roles vector
                },
            ],
        }
    }

    fn create_special_chars_config() -> PlainAuthConfig {
        PlainAuthConfig {
            name: "TestPlain".to_string(),
            realm: "test".to_string(),
            users: vec![PlainUserEntry {
                username: "user@domain.com".to_string(),
                credential: plaintext("p@ssw0rd!#$"),
                roles: Some(vec!["special".to_string()]),
            }],
        }
    }

    fn create_unicode_config() -> PlainAuthConfig {
        PlainAuthConfig {
            name: "TestPlain".to_string(),
            realm: "test".to_string(),
            users: vec![PlainUserEntry {
                username: "用户".to_string(),
                credential: plaintext("密码"),
                roles: Some(vec!["unicode".to_string()]),
            }],
        }
    }

    fn create_empty_users_config() -> PlainAuthConfig {
        PlainAuthConfig {
            name: "TestPlain".to_string(),
            realm: "test".to_string(),
            users: vec![],
        }
    }

    /// Test that valid credentials (username:password) are correctly authenticated.
    #[tokio::test]
    async fn test_authenticate_valid_credentials() {
        let provider = PlainAuthProvider::new(&create_test_config());
        let credentials = general_purpose::STANDARD.encode("user1:password1");

        let result = provider.authenticate(&credentials).await;

        assert!(result.is_ok());
        let user = result.unwrap();
        assert_eq!(user.username, "user1");
        assert_eq!(user.realm, "test");
        assert_eq!(user.roles, vec!["user"]);
        assert_eq!(user.version, 1);
    }

    /// Test that an invalid password returns an error.
    #[tokio::test]
    async fn test_authenticate_invalid_credentials() {
        let provider = PlainAuthProvider::new(&create_test_config());
        let credentials = general_purpose::STANDARD.encode("user1:wrongpassword");

        let result = provider.authenticate(&credentials).await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Wrong username or password");
    }

    /// Test that credentials that are not valid base64 yield an error.
    #[tokio::test]
    async fn test_authenticate_invalid_base64() {
        let provider = PlainAuthProvider::new(&create_empty_users_config());
        let credentials = "not_base64";

        let result = provider.authenticate(credentials).await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Invalid base64 in Basic auth");
    }

    /// Test that valid credentials with multiple roles are correctly authenticated.
    #[tokio::test]
    async fn test_authenticate_valid_credentials_with_multiple_roles() {
        let provider = PlainAuthProvider::new(&create_test_config());
        let credentials = general_purpose::STANDARD.encode("admin:admin123");

        let result = provider.authenticate(&credentials).await;

        assert!(result.is_ok());
        let user = result.unwrap();
        assert_eq!(user.username, "admin");
        assert_eq!(user.realm, "test");
        assert_eq!(user.roles, vec!["admin", "user"]);
        assert_eq!(user.version, 1);
    }

    /// Test that valid credentials with no roles are correctly authenticated.
    #[tokio::test]
    async fn test_authenticate_valid_credentials_with_no_roles() {
        let provider = PlainAuthProvider::new(&create_test_config());
        let credentials = general_purpose::STANDARD.encode("guest:guest123");

        let result = provider.authenticate(&credentials).await;

        assert!(result.is_ok());
        let user = result.unwrap();
        assert_eq!(user.username, "guest");
        assert_eq!(user.realm, "test");
        assert!(user.roles.is_empty());
    }

    /// Test that valid credentials with empty roles vector are correctly authenticated.
    #[tokio::test]
    async fn test_authenticate_valid_credentials_with_empty_roles() {
        let provider = PlainAuthProvider::new(&create_test_config());
        let credentials = general_purpose::STANDARD.encode("empty_roles:password");

        let result = provider.authenticate(&credentials).await;

        assert!(result.is_ok());
        let user = result.unwrap();
        assert_eq!(user.username, "empty_roles");
        assert_eq!(user.realm, "test");
        assert!(user.roles.is_empty());
    }

    /// Test that an invalid username returns an error.
    #[tokio::test]
    async fn test_authenticate_invalid_username() {
        let provider = PlainAuthProvider::new(&create_test_config());
        let credentials = general_purpose::STANDARD.encode("nonexistent:password1");

        let result = provider.authenticate(&credentials).await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Wrong username or password");
    }

    /// Test that both invalid username and password return an error.
    #[tokio::test]
    async fn test_authenticate_both_invalid() {
        let provider = PlainAuthProvider::new(&create_test_config());
        let credentials = general_purpose::STANDARD.encode("nonexistent:wrongpassword");

        let result = provider.authenticate(&credentials).await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Wrong username or password");
    }

    /// Test that credentials without colon separator return an error.
    #[tokio::test]
    async fn test_authenticate_no_colon_separator() {
        let provider = PlainAuthProvider::new(&create_test_config());
        let credentials = general_purpose::STANDARD.encode("usernamepassword");

        let result = provider.authenticate(&credentials).await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Wrong username or password");
    }

    /// Test that credentials with empty username return an error.
    #[tokio::test]
    async fn test_authenticate_empty_username() {
        let provider = PlainAuthProvider::new(&create_test_config());
        let credentials = general_purpose::STANDARD.encode(":password");

        let result = provider.authenticate(&credentials).await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "No username in Basic credentials");
    }

    /// Test that credentials with empty password are handled correctly.
    #[tokio::test]
    async fn test_authenticate_empty_password() {
        let provider = PlainAuthProvider::new(&create_test_config());
        let credentials = general_purpose::STANDARD.encode("admin:");

        let result = provider.authenticate(&credentials).await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Wrong username or password");
    }

    /// Test that completely empty credentials return an error.
    #[tokio::test]
    async fn test_authenticate_empty_credentials() {
        let provider = PlainAuthProvider::new(&create_test_config());
        let credentials = general_purpose::STANDARD.encode(":");

        let result = provider.authenticate(&credentials).await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "No username in Basic credentials");
    }

    /// Test that credentials with multiple colons are handled correctly.
    #[tokio::test]
    async fn test_authenticate_multiple_colons() {
        let provider = PlainAuthProvider::new(&create_test_config());
        let credentials = general_purpose::STANDARD.encode("user:pass:word");

        let result = provider.authenticate(&credentials).await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Wrong username or password");
    }

    /// Test that invalid UTF-8 in credentials returns an error.
    #[tokio::test]
    async fn test_authenticate_invalid_utf8() {
        let provider = PlainAuthProvider::new(&create_test_config());
        // Create invalid UTF-8 bytes
        let invalid_utf8_bytes = vec![0xFF, 0xFE, 0xFD];
        let credentials = general_purpose::STANDARD.encode(&invalid_utf8_bytes);

        let result = provider.authenticate(&credentials).await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Invalid UTF-8 in Basic auth");
    }

    /// Test that provider metadata is correct.
    #[tokio::test]
    async fn test_provider_metadata() {
        let provider = PlainAuthProvider::new(&create_test_config());

        assert_eq!(provider.get_name(), "TestPlain");
        assert_eq!(provider.get_type(), "Basic");
        assert_eq!(provider.get_realm(), Some("test"));
    }

    /// Test authentication with special characters in username and password.
    #[tokio::test]
    async fn test_authenticate_special_characters() {
        let provider = PlainAuthProvider::new(&create_special_chars_config());
        let credentials = general_purpose::STANDARD.encode("user@domain.com:p@ssw0rd!#$");

        let result = provider.authenticate(&credentials).await;

        assert!(result.is_ok());
        let user = result.unwrap();
        assert_eq!(user.username, "user@domain.com");
        assert_eq!(user.roles, vec!["special"]);
    }

    /// Test authentication with unicode characters.
    #[tokio::test]
    async fn test_authenticate_unicode_characters() {
        let provider = PlainAuthProvider::new(&create_unicode_config());
        let credentials = general_purpose::STANDARD.encode("用户:密码");

        let result = provider.authenticate(&credentials).await;

        assert!(result.is_ok());
        let user = result.unwrap();
        assert_eq!(user.username, "用户");
        assert_eq!(user.roles, vec!["unicode"]);
    }

    /// Test with empty user list.
    #[tokio::test]
    async fn test_authenticate_empty_user_list() {
        let provider = PlainAuthProvider::new(&create_empty_users_config());
        let credentials = general_purpose::STANDARD.encode("anyuser:anypassword");

        let result = provider.authenticate(&credentials).await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Wrong username or password");
    }

    /// Test case sensitivity in username and password.
    #[tokio::test]
    async fn test_authenticate_case_sensitivity() {
        let provider = PlainAuthProvider::new(&create_test_config());

        // Test uppercase username
        let credentials = general_purpose::STANDARD.encode("ADMIN:admin123");
        let result = provider.authenticate(&credentials).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Wrong username or password");

        // Test uppercase password
        let credentials = general_purpose::STANDARD.encode("admin:ADMIN123");
        let result = provider.authenticate(&credentials).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Wrong username or password");
    }

    /// Test that user attributes are properly initialized.
    #[tokio::test]
    async fn test_user_attributes_initialization() {
        let provider = PlainAuthProvider::new(&create_test_config());
        let credentials = general_purpose::STANDARD.encode("admin:admin123");

        let result = provider.authenticate(&credentials).await;

        assert!(result.is_ok());
        let user = result.unwrap();
        assert!(user.attributes.is_empty());
        assert!(user.scopes.is_empty());
        assert_eq!(user.version, 1);
    }

    /// Test authentication with whitespace in credentials.
    #[tokio::test]
    async fn test_authenticate_whitespace_handling() {
        let provider = PlainAuthProvider::new(&create_test_config());

        // Test username with spaces (should fail)
        let credentials = general_purpose::STANDARD.encode(" admin :admin123");
        let result = provider.authenticate(&credentials).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Wrong username or password");
    }

    /// Test that roles are properly cloned and not shared between users.
    #[tokio::test]
    async fn test_roles_independence() {
        let provider = PlainAuthProvider::new(&create_test_config());

        // Authenticate admin user
        let credentials1 = general_purpose::STANDARD.encode("admin:admin123");
        let result1 = provider.authenticate(&credentials1).await;
        assert!(result1.is_ok());
        let user1 = result1.unwrap();

        // Authenticate regular user
        let credentials2 = general_purpose::STANDARD.encode("user1:password1");
        let result2 = provider.authenticate(&credentials2).await;
        assert!(result2.is_ok());
        let user2 = result2.unwrap();

        // Verify roles are different and independent
        assert_eq!(user1.roles, vec!["admin", "user"]);
        assert_eq!(user2.roles, vec!["user"]);
        assert_ne!(user1.roles, user2.roles);
    }

    /// Test provider creation and configuration.
    #[tokio::test]
    async fn test_provider_creation() {
        let config = create_test_config();
        let provider = PlainAuthProvider::new(&config);

        // Verify provider was created with correct configuration
        assert_eq!(provider.config.name, "TestPlain");
        assert_eq!(provider.config.realm, "test");
        assert_eq!(provider.config.users.len(), 4);
    }
    #[tokio::test]
    async fn test_authenticate_correct_argon2id_hash() {
        let provider = PlainAuthProvider::new(&PlainAuthConfig {
            name: "Hashed".to_string(),
            realm: "test".to_string(),
            users: vec![PlainUserEntry {
                username: "hashed-user".to_string(),
                credential: argon2id("correct horse battery staple"),
                roles: Some(vec!["user".to_string()]),
            }],
        });
        let credentials =
            general_purpose::STANDARD.encode("hashed-user:correct horse battery staple");

        let user = provider
            .authenticate(&credentials)
            .await
            .expect("correct password should authenticate");

        assert_eq!(user.username, "hashed-user");
        assert_eq!(user.roles, vec!["user"]);
    }

    #[tokio::test]
    async fn test_authenticate_incorrect_argon2id_password() {
        let provider = PlainAuthProvider::new(&PlainAuthConfig {
            name: "Hashed".to_string(),
            realm: "test".to_string(),
            users: vec![PlainUserEntry {
                username: "hashed-user".to_string(),
                credential: argon2id("right-password"),
                roles: None,
            }],
        });
        let credentials = general_purpose::STANDARD.encode("hashed-user:wrong-password");

        let result = provider.authenticate(&credentials).await;

        assert_eq!(result.unwrap_err(), "Wrong username or password");
    }

    #[tokio::test]
    async fn test_authenticate_malformed_argon2id_hash() {
        let provider = PlainAuthProvider::new(&PlainAuthConfig {
            name: "Hashed".to_string(),
            realm: "test".to_string(),
            users: vec![PlainUserEntry {
                username: "hashed-user".to_string(),
                credential: PlainCredential::Argon2id(Argon2idCredential {
                    password_hash: "$argon2id$malformed".to_string(),
                }),
                roles: None,
            }],
        });
        let credentials = general_purpose::STANDARD.encode("hashed-user:any-password");

        let result = provider.authenticate(&credentials).await;

        assert_eq!(result.unwrap_err(), "Wrong username or password");
    }

    #[tokio::test]
    async fn test_authenticate_unicode_argon2id_password() {
        let provider = PlainAuthProvider::new(&PlainAuthConfig {
            name: "Hashed".to_string(),
            realm: "test".to_string(),
            users: vec![PlainUserEntry {
                username: "unicode-user".to_string(),
                credential: argon2id("密码🔐"),
                roles: None,
            }],
        });
        let credentials = general_purpose::STANDARD.encode("unicode-user:密码🔐");

        let result = provider.authenticate(&credentials).await;

        assert!(result.is_ok());
    }

    #[test]
    fn test_plaintext_credential_deserializes_for_compatibility() {
        let entry: PlainUserEntry = serde_json::from_str(
            r#"{"username":"legacy","password":"still-supported","roles":[]}"#,
        )
        .expect("deprecated plaintext credential should remain supported");

        assert!(matches!(entry.credential, PlainCredential::Plaintext(_)));
    }

    #[test]
    fn test_credential_rejects_hash_and_plaintext() {
        let result = serde_json::from_str::<PlainUserEntry>(
            r#"{"username":"ambiguous","password_hash":"$argon2id$...","password":"secret"}"#,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_credential_rejects_missing_hash_and_plaintext() {
        let result = serde_json::from_str::<PlainUserEntry>(r#"{"username":"missing"}"#);

        assert!(result.is_err());
    }
    #[tokio::test]
    async fn test_unknown_username_runs_one_dummy_argon2_verification() {
        let observed_hashes = Arc::new(Mutex::new(Vec::new()));
        let closure_hashes = Arc::clone(&observed_hashes);
        let verifier = Arc::new(BoundedArgon2Verifier::new(1, move |password_hash, _| {
            closure_hashes
                .lock()
                .expect("hash mutex should not be poisoned")
                .push(password_hash.to_owned());
            false
        }));
        let provider = PlainAuthProvider::with_argon2_verifier(&create_test_config(), verifier);
        let credentials = general_purpose::STANDARD.encode("not-configured:attempt");

        let result = provider.authenticate(&credentials).await;

        assert_eq!(result.unwrap_err(), "Wrong username or password");
        assert_eq!(
            observed_hashes
                .lock()
                .expect("hash mutex should not be poisoned")
                .as_slice(),
            [DUMMY_ARGON2ID_HASH]
        );
    }

    #[tokio::test]
    async fn test_plaintext_compatibility_runs_dummy_argon2_verification() {
        let observed_hashes = Arc::new(Mutex::new(Vec::new()));
        let closure_hashes = Arc::clone(&observed_hashes);
        let verifier = Arc::new(BoundedArgon2Verifier::new(1, move |password_hash, _| {
            closure_hashes
                .lock()
                .expect("hash mutex should not be poisoned")
                .push(password_hash.to_owned());
            false
        }));
        let provider = PlainAuthProvider::with_argon2_verifier(&create_test_config(), verifier);
        let credentials = general_purpose::STANDARD.encode("user1:password1");

        let result = provider.authenticate(&credentials).await;

        assert!(result.is_ok());
        assert_eq!(
            observed_hashes
                .lock()
                .expect("hash mutex should not be poisoned")
                .as_slice(),
            [DUMMY_ARGON2ID_HASH]
        );
    }

    #[test]
    fn test_plaintext_comparison_uses_fixed_size_digests() {
        let expected = password_digest("short".as_bytes());
        let matching = password_digest("short".as_bytes());
        let different_length = password_digest("a much longer password".as_bytes());

        assert_eq!(expected.len(), 32);
        assert!(bool::from(expected.ct_eq(&matching)));
        assert!(!bool::from(expected.ct_eq(&different_length)));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_argon2_concurrency_is_bounded_without_timing_assumptions() {
        let mut harness = blocking_verifier_harness(2);
        let provider = Arc::new(PlainAuthProvider::with_argon2_verifier(
            &PlainAuthConfig {
                name: "Bounded".to_string(),
                realm: "test".to_string(),
                users: vec![PlainUserEntry {
                    username: "user".to_string(),
                    credential: PlainCredential::Argon2id(Argon2idCredential {
                        password_hash: DUMMY_ARGON2ID_HASH.to_string(),
                    }),
                    roles: None,
                }],
            },
            Arc::clone(&harness.verifier),
        ));
        let credentials = general_purpose::STANDARD.encode("user:password");
        let tasks: Vec<_> = (0..3)
            .map(|_| {
                let provider = Arc::clone(&provider);
                let credentials = credentials.clone();
                tokio::spawn(async move { provider.authenticate(&credentials).await })
            })
            .collect();

        harness
            .started
            .recv()
            .await
            .expect("first verification should start");
        harness
            .started
            .recv()
            .await
            .expect("second verification should start");
        assert_eq!(harness.active.load(Ordering::SeqCst), 2);
        assert_eq!(harness.maximum_active.load(Ordering::SeqCst), 2);
        assert_eq!(harness.verifier.permits.available_permits(), 0);

        harness
            .release
            .send(())
            .expect("first verification should be releasable");
        harness
            .started
            .recv()
            .await
            .expect("third verification should start after a permit is released");
        assert_eq!(harness.maximum_active.load(Ordering::SeqCst), 2);

        harness
            .release
            .send(())
            .expect("second verification should be releasable");
        harness
            .release
            .send(())
            .expect("third verification should be releasable");
        for task in tasks {
            assert!(
                task.await
                    .expect("authentication task should not panic")
                    .is_ok()
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_cancelled_request_keeps_permit_until_blocking_work_finishes() {
        let mut harness = blocking_verifier_harness(1);
        let first_verifier = Arc::clone(&harness.verifier);
        let first = tokio::spawn(async move {
            first_verifier
                .verify(DUMMY_ARGON2ID_HASH, b"first-attempt")
                .await
        });
        harness
            .started
            .recv()
            .await
            .expect("first verification should start");

        first.abort();
        assert!(
            first
                .await
                .expect_err("task should be cancelled")
                .is_cancelled()
        );

        let second_verifier = Arc::clone(&harness.verifier);
        let mut second = Box::pin(async move {
            second_verifier
                .verify(DUMMY_ARGON2ID_HASH, b"second-attempt")
                .await
        });
        assert!(matches!(futures::poll!(&mut second), Poll::Pending));
        assert_eq!(harness.verifier.permits.available_permits(), 0);
        assert_eq!(harness.active.load(Ordering::SeqCst), 1);

        harness
            .release
            .send(())
            .expect("cancelled verification should be releasable");
        let second = tokio::spawn(second);
        harness
            .started
            .recv()
            .await
            .expect("second verification should start after blocking work ends");
        harness
            .release
            .send(())
            .expect("second verification should be releasable");
        assert!(second.await.expect("second task should not panic"));
        assert_eq!(harness.maximum_active.load(Ordering::SeqCst), 1);
    }
    #[test]
    fn test_config_debug_output_redacts_credentials() {
        let config = PlainAuthConfig {
            name: "Redacted".to_string(),
            realm: "test".to_string(),
            users: vec![
                PlainUserEntry {
                    username: "legacy".to_string(),
                    credential: plaintext("plaintext-must-not-appear"),
                    roles: None,
                },
                PlainUserEntry {
                    username: "hashed".to_string(),
                    credential: PlainCredential::Argon2id(Argon2idCredential {
                        password_hash: "hash-must-not-appear".to_string(),
                    }),
                    roles: None,
                },
            ],
        };

        let output = format!("{config:?}");

        assert!(!output.contains("plaintext-must-not-appear"));
        assert!(!output.contains("hash-must-not-appear"));
        assert_eq!(output.matches("[REDACTED]").count(), 2);
    }
}

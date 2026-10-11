// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! Fresh selected-provider verification and strict augmentation, not consent or grant proof.

use super::records::valid_time;
use crate::{
    auth::Auth,
    browser::{BrowserCredentials, BrowserLoginState, BrowserVerifyError},
    metrics::Metrics,
    models::user::User,
};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthenticationError {
    Rejected,
    Limited,
    Timeout,
    Unavailable,
}

/// Constructed by verification or OAuth-internal trusted snapshot restoration only.
/// No Debug, Clone, Serialize or Deserialize.
pub struct VerifiedOAuthIdentity {
    user: User,
    verified_at_ms: u64,
}
impl VerifiedOAuthIdentity {
    pub fn as_user(&self) -> &User {
        &self.user
    }
    pub fn verified_at_ms(&self) -> u64 {
        self.verified_at_ms
    }
}

/// Callers must enforce Origin/CSRF and the bound OAuth transaction before invoking this.
/// Uses fresh credentials, never existing sessions; no cookie, consent, code or grant is created.
pub async fn verify_identity(
    credentials: BrowserCredentials<'_>,
    browser: &BrowserLoginState,
    auth: &Auth,
    metrics: &Metrics,
) -> Result<VerifiedOAuthIdentity, AuthenticationError> {
    let deadline = tokio::time::Instant::now() + browser.verification_timeout();
    let result = tokio::time::timeout_at(deadline, async {
        let user = browser
            .verify_identity_strict(credentials, auth, metrics, projection)
            .await
            .map_err(|error| match error {
                BrowserVerifyError::Rejected => AuthenticationError::Rejected,
                BrowserVerifyError::Limited => AuthenticationError::Limited,
                BrowserVerifyError::Timeout => AuthenticationError::Timeout,
                BrowserVerifyError::Unavailable | BrowserVerifyError::Capacity => {
                    AuthenticationError::Unavailable
                }
            })?;
        let verified_at_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|time| u64::try_from(time.as_millis()).ok())
            .filter(|ms| valid_time(*ms))
            .ok_or(AuthenticationError::Unavailable)?;
        if tokio::time::Instant::now() >= deadline {
            return Err(AuthenticationError::Timeout);
        }
        Ok(VerifiedOAuthIdentity {
            user,
            verified_at_ms,
        })
    })
    .await
    .unwrap_or(Err(AuthenticationError::Timeout));
    // Tokio timeouts are cooperative; even a late ready error must not replace Timeout.
    if tokio::time::Instant::now() >= deadline {
        Err(AuthenticationError::Timeout)
    } else {
        result
    }
}

fn projection(user: &User) -> Result<User, BrowserVerifyError> {
    validate_identity_fields(&user.username, &user.realm, &user.roles)?;
    Ok(User::new(
        user.realm.clone(),
        user.username.clone(),
        Some(user.roles.to_vec()),
        None,
        None,
        None,
    ))
}

fn validate_identity_fields(
    username: &str,
    realm: &str,
    roles: &[String],
) -> Result<(), BrowserVerifyError> {
    let bounded = |value: &str| {
        !value.trim().is_empty() && value.len() <= 128 && !value.chars().any(char::is_control)
    };
    if !bounded(username)
        || !bounded(realm)
        || roles.len() > 64
        || !roles.iter().all(|role| bounded(role))
    {
        return Err(BrowserVerifyError::Rejected);
    }
    Ok(())
}

/// Trusted OAuth cache snapshots only: no provider or augmenter is re-executed.
pub(super) fn restore_from_trusted_storage(
    username: String,
    realm: String,
    roles: Vec<String>,
    verified_at_ms: u64,
) -> Result<VerifiedOAuthIdentity, AuthenticationError> {
    validate_identity_fields(&username, &realm, &roles)
        .map_err(|_| AuthenticationError::Rejected)?;
    if !valid_time(verified_at_ms) {
        return Err(AuthenticationError::Unavailable);
    }
    Ok(VerifiedOAuthIdentity {
        user: User::new(realm, username, Some(roles), None, None, None),
        verified_at_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{augmenters::Augmenter, config::ConfigV2, store::no_store::NoStore};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    const PASSWORD: &str = "päss:秘密";
    struct FixtureAugmenter {
        calls: Arc<AtomicUsize>,
        fail: bool,
        stall: bool,
    }
    #[async_trait::async_trait]
    impl Augmenter for FixtureAugmenter {
        fn get_name(&self) -> &str {
            "fixture"
        }
        fn get_type(&self) -> &str {
            "plain"
        }
        fn get_realm(&self) -> &str {
            "local"
        }
        async fn augment(&self, user: Arc<futures::lock::Mutex<User>>) -> Result<(), String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.stall {
                std::future::pending::<()>().await;
            }
            let mut user = user.lock().await;
            user.roles.push("derived".into());
            user.attributes
                .insert("display_name".into(), "visible only in browser".into());
            user.scopes
                .insert("hidden".into(), vec!["not-permission".into()]);
            if self.fail {
                Err("fixture failure".into())
            } else {
                Ok(())
            }
        }
    }
    fn fixture(
        uri: &str,
        username: &str,
        fail: bool,
        stall: bool,
    ) -> (BrowserLoginState, Auth, Metrics, Arc<AtomicUsize>) {
        let config: ConfigV2 = serde_json::from_value(serde_json::json!({
            "store": {"enabled": false}, "services": [], "augmenters": [],
            "providers": [{"type": "plain", "name": "basic", "realm": "local", "users": [{"username": username, "password": PASSWORD, "roles": ["base"]}]}, {"type": "ecmwf-api", "name": "api", "realm": "local", "uri": uri}],
            "server": {"port": 0}, "jwt": {"iss": "fixture", "exp": 300, "secret": "fixture-only"}, "logging": {"level": "warn", "format": "console"},
            "ui": {"basic": {"provider_name": "basic"}, "ecmwf_api_key": {"provider_name": "api"}, "browser_session": {"public_origin": "https://login.example.org", "backend": {"type": "memory"}, "max_inflight_logins": 1, "verification_timeout_seconds": 1}}
        })).unwrap();
        let browser = BrowserLoginState::new(&config).unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let mut auth = Auth::new(&config.providers, &[], Arc::new(NoStore), config.auth);
        auth.augmenters.push(Box::new(FixtureAugmenter {
            calls: calls.clone(),
            fail,
            stall,
        }));
        (browser, auth, Metrics::new(), calls)
    }
    fn basic(username: &str) -> BrowserCredentials<'_> {
        BrowserCredentials::Basic {
            username,
            password: PASSWORD,
        }
    }
    fn idle(metrics: &Metrics) {
        assert!(
            metrics
                .render()
                .unwrap()
                .contains("authotron_browser_logins_inflight 0")
        );
    }
    #[tokio::test]
    async fn strict_failures_do_not_return_identity_but_browser_keeps_best_effort() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/who-am-i")
            .match_query(mockito::Matcher::UrlEncoded(
                "token".into(),
                "fixture-key".into(),
            ))
            .with_body(r#"{"uid":"alice"}"#)
            .expect(2)
            .create_async()
            .await;
        let (browser, auth, metrics, calls) = fixture(&server.url(), "alice", true, false);
        assert_eq!(
            verify_identity(basic("alice"), &browser, &auth, &metrics)
                .await
                .err(),
            Some(AuthenticationError::Rejected)
        );
        let legacy = browser
            .verify_identity(basic("alice"), &auth, &metrics)
            .await
            .unwrap();
        assert_eq!(legacy.roles, ["base", "derived"]);
        assert!(!legacy.attributes.is_empty());
        assert_eq!(
            verify_identity(
                BrowserCredentials::ApiKey("fixture-key"),
                &browser,
                &auth,
                &metrics
            )
            .await
            .err(),
            Some(AuthenticationError::Rejected)
        );
        assert!(
            browser
                .verify_identity(BrowserCredentials::ApiKey("fixture-key"), &auth, &metrics)
                .await
                .is_ok()
        );
        mock.assert_async().await;
        assert_eq!(calls.load(Ordering::SeqCst), 4);
        idle(&metrics);
    }
    #[tokio::test]
    async fn fresh_basic_and_api_proofs_are_bounded_and_uncached() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/who-am-i")
            .match_query(mockito::Matcher::UrlEncoded(
                "token".into(),
                "fixture-key".into(),
            ))
            .with_body(r#"{"uid":"alice","email":"hidden@example.org"}"#)
            .expect(2)
            .create_async()
            .await;
        let (browser, auth, metrics, calls) = fixture(&server.url(), "alice", false, false);
        for credentials in [
            basic("alice"),
            BrowserCredentials::ApiKey("fixture-key"),
            BrowserCredentials::ApiKey("fixture-key"),
        ] {
            let before = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis();
            let proof = verify_identity(credentials, &browser, &auth, &metrics)
                .await
                .unwrap();
            assert_eq!(proof.as_user().username, "alice");
            assert!(proof.as_user().roles.contains(&"derived".into()));
            assert!(proof.as_user().attributes.is_empty() && proof.as_user().scopes.is_empty());
            assert!(u128::from(proof.verified_at_ms()) >= before);
        }
        mock.assert_async().await;
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        idle(&metrics);
        assert_eq!(
            verify_identity(
                BrowserCredentials::Basic {
                    username: "alice",
                    password: "wrong"
                },
                &browser,
                &auth,
                &metrics
            )
            .await
            .err(),
            Some(AuthenticationError::Rejected)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        let name = "x".repeat(129);
        let (browser, auth, metrics, _) = fixture(&server.url(), &name, false, false);
        assert!(
            browser
                .verify_identity(basic(&name), &auth, &metrics)
                .await
                .is_ok()
        );
        assert_eq!(
            verify_identity(basic(&name), &browser, &auth, &metrics)
                .await
                .err(),
            Some(AuthenticationError::Rejected)
        );
    }
    #[tokio::test]
    async fn strict_timeout_and_cancellation_release_admission_and_gauge() {
        let (browser, mut auth, metrics, calls) =
            fixture("http://127.0.0.1:1", "alice", false, true);
        assert_eq!(
            verify_identity(basic("alice"), &browser, &auth, &metrics)
                .await
                .err(),
            Some(AuthenticationError::Timeout)
        );
        idle(&metrics);
        let mut pending = Box::pin(verify_identity(basic("alice"), &browser, &auth, &metrics));
        tokio::select! { _ = &mut pending => panic!("stalled augmentation completed"), _ = tokio::time::sleep(std::time::Duration::from_millis(20)) => {} }
        assert!(
            metrics
                .render()
                .unwrap()
                .contains("authotron_browser_logins_inflight 1")
        );
        assert_eq!(
            verify_identity(basic("alice"), &browser, &auth, &metrics)
                .await
                .err(),
            Some(AuthenticationError::Limited)
        );
        drop(pending);
        idle(&metrics);
        auth.augmenters.clear();
        assert!(
            verify_identity(basic("alice"), &browser, &auth, &metrics)
                .await
                .is_ok()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }
    #[test]
    fn oauth_projection_bounds_do_not_keep_hidden_fields() {
        let mut user = User::new(
            "r".repeat(128),
            "u".repeat(128),
            Some(vec!["x".repeat(128); 64]),
            None,
            None,
            None,
        );
        assert!(projection(&user).is_ok());
        for invalid in ["".into(), " ".into(), "u\n".into(), "u".repeat(129)] {
            user.username = invalid;
            assert_eq!(projection(&user).err(), Some(BrowserVerifyError::Rejected));
        }
        user.username = "u".into();
        user.roles.push("extra".into());
        assert!(projection(&user).is_err());
        user.roles = vec!["role\n".into()];
        assert!(projection(&user).is_err());
        user.roles = vec![];
        user.realm.clear();
        assert!(projection(&user).is_err());
    }
}

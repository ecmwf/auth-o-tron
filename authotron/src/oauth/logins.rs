// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! A user's logins: the live refresh-token families of one realm and username, as the
//! account page lists them, and their revocation by that user.

use super::{
    audit::{FamilyEnd, family_ref},
    refresh::{FamilySummary, RefreshStoreError, user_key},
    refresh_grant::{RefreshBackend, refresh_dispatch},
    runtime::OAuthRuntime,
};
use crate::{browser::BrowserLoginState, metrics::Metrics};

/// Which logins of a user to revoke.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Logins<'a> {
    All,
    /// The logins whose [`family_ref`] is this reference.
    Named(&'a str),
}

impl OAuthRuntime {
    /// Whether a client has refresh tokens, so that users have logins to list.
    pub fn has_logins(&self) -> bool {
        self.refresh.is_some()
    }

    /// The live logins of a user, newest first, at most the per-user family cap. Realm
    /// and username are compared exactly as the families store them.
    pub async fn logins(
        &self,
        realm: &str,
        username: &str,
    ) -> Result<Vec<FamilySummary>, RefreshStoreError> {
        let Some(backend) = &self.refresh else {
            return Ok(Vec::new());
        };
        let now = self
            .now()
            .await
            .map_err(|_| RefreshStoreError::Unavailable)?;
        let limit = self.config.max_refresh_token_families_per_user;
        refresh_dispatch!(backend, families_of(&user_key(realm, username), limit, now))
    }

    /// Revokes logins of a user as `user_revoke`, queueing revocation of their upstream
    /// grants. A reference that names none of the user's listed logins changes nothing:
    /// the families are looked up among this user's own, never by a posted id.
    pub async fn revoke_logins(
        &self,
        realm: &str,
        username: &str,
        which: Logins<'_>,
        browser: &BrowserLoginState,
        metrics: &Metrics,
    ) -> Result<(), RefreshStoreError> {
        let Some(backend) = &self.refresh else {
            return Ok(());
        };
        let now = self
            .now()
            .await
            .map_err(|_| RefreshStoreError::Unavailable)?;
        let key = user_key(realm, username);
        let (ended, failed) = match which {
            Logins::All => (refresh_dispatch!(backend, revoke_user(&key, now))?, None),
            Logins::Named(reference) => {
                let limit = self.config.max_refresh_token_families_per_user;
                let (mut ended, mut failed) = (Vec::new(), None);
                for family in refresh_dispatch!(backend, families_of(&key, limit, now))? {
                    if family_ref(&family.family_id) != reference {
                        continue;
                    }
                    match refresh_dispatch!(backend, revoke_family(&family.family_id)) {
                        Ok(family) => ended.extend(family),
                        Err(error) => {
                            failed = Some(error);
                            break;
                        }
                    }
                }
                (ended, failed)
            }
        };
        // Families revoked before a store failure are logged all the same.
        self.families_ended(ended, FamilyEnd::UserRevoke, browser, metrics);
        failed.map_or(Ok(()), Err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::ConfigV2,
        oauth::refresh::{RefreshGrant, RefreshToken},
    };
    use rsa::pkcs8::{EncodePrivateKey, LineEnding};
    use std::{io::Write, sync::Arc};

    async fn runtime() -> (tempfile::NamedTempFile, ConfigV2, Arc<OAuthRuntime>) {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        let pem = super::super::keys::tests::keys()[0]
            .to_pkcs8_pem(LineEnding::LF)
            .unwrap();
        file.write_all(pem.as_bytes()).unwrap();
        let config: ConfigV2 = serde_json::from_value(serde_json::json!({
            "store": {"enabled": false}, "services": [], "augmenters": [],
            "providers": [{"type": "plain", "name": "basic", "realm": "local", "users": [{"username": "alice", "password": "fixture-only"}], "browser": {"id": "password", "label": "Password"}}],
            "server": {"port": 0}, "jwt": {"iss": "fixture", "exp": 300, "secret": "fixture-only"}, "logging": {"level": "warn", "format": "console"},
            "ui": {"enabled": true, "browser_session": {"public_origin": "https://login.example.org", "backend": {"type": "memory"}}},
            "oauth": {"enabled": true, "issuer": "https://login.example.org/", "signing": {"active_kid": "k", "keys": [{"kid": "k", "private_key_file": file.path()}]},
                "max_refresh_token_families_per_user": 3,
                "clients": [{"client_id": "desktop", "display_name": "Desktop", "redirect_uris": ["http://127.0.0.1:8080/cb"], "application_type": "native",
                    "resources": [{"resource": "https://mcp.example.org/mcp", "scopes": ["read"]}], "refresh_tokens": {"enabled": true}}],
                "resources": [{"resource": "https://mcp.example.org/mcp", "allowed_realms": ["local"], "scopes": [{"name": "read", "required_roles": []}]}]}
        }))
        .unwrap();
        let runtime = OAuthRuntime::initialize(&config).await.unwrap().unwrap();
        (file, config, runtime)
    }

    /// Starts a family for `username` and returns its token.
    async fn issue(runtime: &OAuthRuntime, username: &str) -> RefreshToken {
        let grant = RefreshGrant {
            username: username.into(),
            ..super::super::refresh::tests::grant()
        };
        let token = RefreshToken::generate().unwrap();
        let now = runtime.now().await.unwrap();
        let policy = &runtime.config.clients[0].refresh_tokens;
        let backend = runtime.refresh.as_ref().unwrap();
        refresh_dispatch!(backend, issue(&grant, token.hash(), now, policy, None)).unwrap();
        token
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn users_revoke_their_own_logins_one_or_all() {
        let (_file, config, runtime) = runtime().await;
        let browser = BrowserLoginState::new(&config).unwrap();
        let metrics = Metrics::new();
        assert!(runtime.has_logins());
        for username in ["alice", "alice", "bob"] {
            issue(&runtime, username).await;
        }
        let listed = runtime.logins("local", "alice").await.unwrap();
        assert_eq!(listed.len(), 2);
        assert!(runtime.logins("local", "Alice").await.unwrap().is_empty());
        assert!(runtime.logins("other", "alice").await.unwrap().is_empty());
        let revoke = |which| runtime.revoke_logins("local", "alice", which, &browser, &metrics);
        // Bob's login is not among Alice's, whatever reference she posts.
        let bob = runtime.logins("local", "bob").await.unwrap();
        let bobs = family_ref(&bob[0].family_id);
        revoke(Logins::Named(&bobs)).await.unwrap();
        revoke(Logins::Named("000000000000")).await.unwrap();
        assert_eq!(runtime.logins("local", "bob").await.unwrap(), bob);
        assert_eq!(runtime.logins("local", "alice").await.unwrap(), listed);

        let older = family_ref(&listed[1].family_id);
        revoke(Logins::Named(&older)).await.unwrap();
        assert_eq!(runtime.logins("local", "alice").await.unwrap(), listed[..1]);
        issue(&runtime, "alice").await;
        revoke(Logins::All).await.unwrap();
        assert!(runtime.logins("local", "alice").await.unwrap().is_empty());
        assert_eq!(runtime.logins("local", "bob").await.unwrap(), bob);
        assert!(
            metrics
                .render()
                .unwrap()
                .contains("authotron_oauth_refresh_tokens_total{event=\"family_revoked\"} 3")
        );
        logs_assert(|lines: &[&str]| {
            let revoked = lines
                .iter()
                .filter(|line| {
                    line.contains("oauth.refresh_token.family_revoked")
                        && line.contains("reason=\"user_revoke\"")
                        && line.contains("username=alice")
                })
                .count();
            match revoked {
                3 => Ok(()),
                count => Err(format!("{count} user_revoke lines")),
            }
        });
    }

    /// Run explicitly: cargo test -p authotron disposable -- --ignored --test-threads=1.
    #[cfg(unix)]
    #[tokio::test]
    #[tracing_test::traced_test]
    #[ignore = "requires Docker; starts and removes its own isolated Valkey container"]
    async fn disposable_valkey_an_unreadable_login_does_not_hide_those_revoked_with_it() {
        use crate::{
            oauth::upstream::tests::{Valkey, coupled},
            oidc::mock::SUBJECT,
            utils::valkey::ValkeyConnection,
        };
        let valkey = Valkey::start("authotron:logins-test").await;
        let coupled = coupled(|config| {
            config["ui"]["browser_session"]["backend"] = valkey.backend.clone();
        })
        .await;
        let runtime = &coupled.runtime;
        let backend = runtime.refresh.as_ref().unwrap();
        let policy = &coupled.config.oauth.clients[0].refresh_tokens;
        let grant = coupled.grant();
        let mut upstream = Vec::new();
        for _ in 0..3 {
            let token = coupled.idp.state.offline_token(SUBJECT);
            let sealed = coupled.seal(&grant, &token);
            let hash = RefreshToken::generate().unwrap().hash();
            let now = runtime.now().await.unwrap();
            refresh_dispatch!(backend, issue(&grant, hash, now, policy, Some(&sealed))).unwrap();
            upstream.push(token);
        }
        // The middle login's stored grant no longer decodes.
        let (realm, username) = (&grant.realm, &grant.username);
        let unreadable = runtime.logins(realm, username).await.unwrap()[1]
            .family_id
            .clone();
        let settings = serde_json::from_value(valkey.backend.clone()).unwrap();
        let connection = ValkeyConnection::connect(&settings).await.unwrap();
        let pattern = format!("authotron:logins-test:*:family:{unreadable}");
        let keys: Vec<String> = connection
            .query(redis::cmd("KEYS").arg(pattern))
            .await
            .unwrap();
        let [key] = &keys[..] else {
            panic!("one family hash expected");
        };
        let _: i64 = connection
            .query(redis::cmd("HSET").arg(key).arg("grant").arg("{"))
            .await
            .unwrap();

        let (browser, metrics) = (&coupled.browser, &coupled.metrics);
        runtime
            .revoke_logins(realm, username, Logins::All, browser, metrics)
            .await
            .unwrap();
        // All three ended; the two readable ones are logged and their upstream grants
        // revoked, and the unreadable one is named in a warning.
        assert!(runtime.logins(realm, username).await.unwrap().is_empty());
        let revoked = &coupled.idp.state.revoked;
        for _ in 0..300 {
            if revoked.lock().unwrap().len() == 2 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let mut sent = revoked.lock().unwrap().clone();
        sent.sort();
        let mut expected = vec![upstream[0].clone(), upstream[2].clone()];
        expected.sort();
        assert_eq!(sent, expected);
        let reference = format!("family={}", family_ref(&unreadable));
        logs_assert(|lines: &[&str]| {
            let revoked = lines
                .iter()
                .filter(|line| line.contains("reason=\"user_revoke\""))
                .count();
            let warned = lines.iter().any(|line| {
                line.contains("oauth.refresh_token.family_unreadable") && line.contains(&reference)
            });
            match (revoked, warned) {
                (2, true) => Ok(()),
                _ => Err(format!("{revoked} user_revoke lines, warned: {warned}")),
            }
        });
    }
}

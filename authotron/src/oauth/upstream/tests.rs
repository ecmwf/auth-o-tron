// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! Coupled refresh families against the in-process identity provider.

use super::*;
use crate::{
    auth::Auth,
    config::ConfigV2,
    models::user::User,
    oauth::{
        refresh::RefreshToken,
        refresh_grant::{RefreshBackend, RefreshGrantError, RefreshRequest},
        tokens::{TokenIssuer, TokenResponse},
    },
    oidc::{
        mock::{CLIENT_ID, CLIENT_SECRET, MockIdp, SUBJECT, rsa_key},
        upstream::UpstreamGrant,
    },
    store::no_store::NoStore,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use rsa::pkcs8::{EncodePrivateKey, LineEnding};
use serde_json::{Value, json};
use std::{io::Write, time::Duration};
use tempfile::NamedTempFile;

pub(in crate::oauth) const RESOURCE: &str = "https://mcp.example.org/mcp";

/// An OAuth server whose only sign-in method is the OIDC method `sso` at a test
/// identity provider, with upstream token encryption and refresh tokens for `desktop`.
pub(in crate::oauth) struct Coupled {
    pub idp: MockIdp,
    pub config: ConfigV2,
    pub runtime: Arc<OAuthRuntime>,
    pub browser: BrowserLoginState,
    pub auth: Auth,
    pub metrics: Metrics,
    _files: [NamedTempFile; 4],
}

/// A disposable Valkey container for the browser-session backend, removed when dropped.
pub(crate) struct Valkey {
    container: String,
    /// The `backend` setting of `ui.browser_session` that reaches it.
    pub backend: Value,
}

impl Valkey {
    /// Starts the container and waits until it answers, with keys under `key_prefix`.
    pub(crate) async fn start(key_prefix: &str) -> Self {
        let docker = |args: &[&str]| {
            let output = std::process::Command::new("docker")
                .args(args)
                .output()
                .expect("Docker CLI required for disposable Valkey tests");
            assert!(output.status.success(), "Docker fixture command failed");
            String::from_utf8(output.stdout).unwrap().trim().to_owned()
        };
        let container = docker(&[
            "run",
            "--rm",
            "-d",
            "-p",
            "127.0.0.1::6379",
            "valkey/valkey:8",
            "valkey-server",
            "--requirepass",
            "public-disposable-fixture",
            "--save",
            "",
            "--appendonly",
            "no",
        ]);
        let address = docker(&["port", &container, "6379/tcp"]);
        let valkey = Self {
            container,
            backend: json!({"type": "valkey", "url": format!("redis://{address}/0"),
                "key_prefix": key_prefix, "password": "public-disposable-fixture"}),
        };
        let settings = serde_json::from_value(valkey.backend.clone()).unwrap();
        for _ in 0..100 {
            if crate::utils::valkey::ValkeyConnection::connect(&settings)
                .await
                .is_ok()
            {
                return valkey;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("disposable Valkey did not become ready");
    }
}

impl Drop for Valkey {
    fn drop(&mut self) {
        let _ = std::process::Command::new("docker")
            .args(["rm", "-f", &self.container])
            .output();
    }
}

fn file(content: &str) -> NamedTempFile {
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(content.as_bytes()).unwrap();
    file
}

/// `edit` adjusts the configuration JSON before the server starts.
pub(in crate::oauth) async fn coupled(edit: impl FnOnce(&mut Value)) -> Coupled {
    let idp = MockIdp::start().await;
    let signing = file(&rsa_key(1).to_pkcs8_pem(LineEnding::LF).unwrap());
    let secret = file(CLIENT_SECRET);
    let key = file(&STANDARD.encode([5u8; 32]));
    let retry = file(&STANDARD.encode([4u8; 32]));
    let mut value = json!({
        "store": {"enabled": false}, "services": [], "augmenters": [], "providers": [],
        "server": {"port": 0}, "jwt": {"iss": "fixture", "exp": 300, "secret": "fixture-only"},
        "logging": {"level": "warn", "format": "console"},
        "ui": {"enabled": true,
            "browser_session": {"public_origin": "https://login.example.org", "backend": {"type": "memory"}},
            "oidc": [{"id": "sso", "label": "SSO", "realm": "idp", "issuer": idp.issuer,
                "client_id": CLIENT_ID, "client_secret_file": secret.path()}]},
        "oauth": {"enabled": true, "issuer": "https://login.example.org/",
            "signing": {"active_kid": "k", "keys": [{"kid": "k", "private_key_file": signing.path()}]},
            "upstream_token_encryption": {"active_kid": "u1", "keys": [{"kid": "u1", "key_file": key.path()}]},
            "refresh_token_retry_key_file": retry.path(),
            "clients": [{"client_id": "desktop", "display_name": "Desktop", "redirect_uris": ["https://app.example.org/cb"],
                "resources": [{"resource": RESOURCE, "scopes": ["read"]}],
                "refresh_tokens": {"enabled": true, "idle_ttl_seconds": 600, "absolute_ttl_seconds": 3600}}],
            "resources": [{"resource": RESOURCE, "allowed_realms": ["idp"], "scopes": [{"name": "read", "required_roles": []}]}]}
    });
    edit(&mut value);
    let config: ConfigV2 = serde_json::from_value(value).unwrap();
    let runtime = OAuthRuntime::initialize(&config).await.unwrap().unwrap();
    let browser = BrowserLoginState::new(&config).unwrap();
    let auth = Auth::new(
        &config.providers,
        &[],
        Arc::new(NoStore),
        config.auth.clone(),
    );
    Coupled {
        idp,
        config,
        runtime,
        browser,
        auth,
        metrics: Metrics::new(),
        _files: [signing, secret, key, retry],
    }
}

impl Coupled {
    pub(in crate::oauth) fn grant(&self) -> RefreshGrant {
        RefreshGrant {
            client_id: "desktop".into(),
            resource: RESOURCE.into(),
            scopes: vec!["read".into()],
            username: SUBJECT.into(),
            realm: "idp".into(),
            provider_roles: vec![],
            method: "sso".into(),
            upstream_coupled: true,
        }
    }
    pub(in crate::oauth) fn seal(&self, grant: &RefreshGrant, upstream_token: &str) -> String {
        let method = self.browser.method("sso").unwrap().oidc().unwrap();
        let upstream = self.runtime.upstream.as_ref().unwrap();
        let sealed = UpstreamGrant::new(SUBJECT, Zeroizing::new(upstream_token.into()));
        upstream
            .cipher
            .seal(&binding(grant, method), &sealed)
            .unwrap()
    }
    /// Starts a coupled family at `now_ms` holding `upstream_token`.
    pub(in crate::oauth) async fn family_at(
        &self,
        upstream_token: &str,
        now_ms: u64,
    ) -> RefreshToken {
        let grant = self.grant();
        let sealed = self.seal(&grant, upstream_token);
        let token = RefreshToken::generate().unwrap();
        let Some(RefreshBackend::Memory(store)) = &self.runtime.refresh else {
            unreachable!()
        };
        let policy = &self.config.oauth.clients[0].refresh_tokens;
        store
            .issue(&grant, token.hash(), now_ms, policy, Some(&sealed))
            .await
            .unwrap();
        token
    }
    pub(in crate::oauth) async fn family(&self, upstream_token: &str) -> RefreshToken {
        self.family_at(upstream_token, self.runtime.now().await.unwrap())
            .await
    }
    pub(in crate::oauth) async fn refresh(
        &self,
        token: &RefreshToken,
    ) -> Result<RefreshToken, RefreshGrantError> {
        let request = RefreshRequest {
            token: token.as_secret_str(),
            client_id: "desktop",
            scope: None,
            resource: None,
        };
        let response = self
            .runtime
            .refresh(request, &self.auth, &self.browser, &self.metrics)
            .await?;
        let body = serde_json::to_value(response).unwrap();
        Ok(RefreshToken::parse(body["refresh_token"].as_str().unwrap()).unwrap())
    }
    /// Waits for the worker to send `count` revocations and returns them in order.
    pub(in crate::oauth) async fn revoked(&self, count: usize) -> Vec<String> {
        for _ in 0..300 {
            let revoked = self.idp.state.revoked.lock().unwrap().clone();
            if revoked.len() >= count {
                return revoked;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("expected {count} upstream revocations");
    }
    /// An access-token response for a new family of the signed-in user.
    fn response(&self, now_ms: u64) -> TokenResponse {
        let user = User::new("idp".into(), SUBJECT.into(), Some(vec![]), None, None, None);
        TokenIssuer::new(&self.runtime.config, &self.runtime.keys)
            .unwrap()
            .issue_refreshed("desktop", RESOURCE, &["read".into()], &user, now_ms)
            .unwrap()
    }
    pub(in crate::oauth) fn upstream_events(&self, event: &str) -> u64 {
        let output = self.metrics.render().unwrap();
        let line = format!("authotron_oauth_upstream_tokens_total{{event=\"{event}\"}} ");
        output
            .lines()
            .find_map(|candidate| candidate.strip_prefix(&line))
            .unwrap()
            .parse()
            .unwrap()
    }
}

#[tokio::test]
#[tracing_test::traced_test]
async fn reuse_detection_and_client_revocation_revoke_the_upstream_grant() {
    let coupled = coupled(|_| {}).await;
    let original = coupled.idp.state.offline_token(SUBJECT);
    let first = coupled.family(&original).await;
    let second = coupled.refresh(&first).await.unwrap();
    coupled.refresh(&second).await.unwrap();
    // A token two rotations old is reuse: the family ends with its newest upstream grant.
    assert_eq!(
        coupled.refresh(&first).await.err(),
        Some(RefreshGrantError::InvalidGrant)
    );
    let newest = &coupled.revoked(1).await[0];
    assert!(newest != &original && newest.starts_with("offline-"));
    assert!(!coupled.idp.state.refresh_token_live(newest));
    let other = coupled.family("offline-revoked").await;
    coupled
        .runtime
        .revoke(
            other.as_secret_str(),
            "desktop",
            &coupled.browser,
            &coupled.metrics,
        )
        .await
        .unwrap();
    assert_eq!(coupled.revoked(2).await[1], "offline-revoked");
    assert_eq!(coupled.upstream_events("revocation_sent"), 2);
    // The worker logs each outcome within the span of the request that ended the grant.
    logs_assert(|lines: &[&str]| {
        let sent: Vec<_> = lines
            .iter()
            .filter(|line| line.contains("oauth.upstream.revocation_sent"))
            .collect();
        let expected = [" INFO ", "client_id=desktop", "method=sso", "realm=idp"];
        match sent.as_slice() {
            [first, second]
                if [first, second].iter().all(|line| {
                    expected.iter().all(|field| line.contains(field))
                        && line.contains(&format!("username={SUBJECT}"))
                        && !line.contains("family=none")
                }) =>
            {
                Ok(())
            }
            other => Err(format!("unexpected revocation lines: {other:?}")),
        }
    });
    for token in [&original, newest, "offline-revoked"] {
        assert!(!logs_contain(token));
    }
}

#[tokio::test]
#[tracing_test::traced_test]
async fn unopenable_grants_are_skipped_and_unsupported_providers_counted() {
    let coupled = coupled(|_| {}).await;
    // Sealed for another client: the binding does not match the family's grant.
    let mut grant = coupled.grant();
    grant.client_id = "other".into();
    let sealed = coupled.seal(&grant, "offline-foreign");
    coupled.runtime.revoke_sealed(
        &coupled.grant(),
        &sealed,
        NO_FAMILY,
        &coupled.browser,
        &coupled.metrics,
    );
    assert_eq!(coupled.upstream_events("revocation_skipped"), 1);
    coupled
        .idp
        .state
        .revocation
        .store(false, std::sync::atomic::Ordering::SeqCst);
    let token = coupled.family("offline-kept").await;
    coupled
        .runtime
        .revoke(
            token.as_secret_str(),
            "desktop",
            &coupled.browser,
            &coupled.metrics,
        )
        .await
        .unwrap();
    for _ in 0..300 {
        if coupled.upstream_events("revocation_unsupported") == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(coupled.upstream_events("revocation_unsupported"), 1);
    assert!(coupled.idp.state.revoked.lock().unwrap().is_empty());
    logs_assert(|lines: &[&str]| {
        let line = |event: &str| {
            lines
                .iter()
                .find(|line| line.contains(event))
                .ok_or(format!("no {event} line"))
        };
        let skipped = line("oauth.upstream.revocation_skipped")?;
        let unsupported = line("oauth.upstream.revocation_unsupported")?;
        if !(skipped.contains(" WARN ") && skipped.contains("family=none")) {
            return Err(format!("skip line: {skipped}"));
        }
        if !(unsupported.contains(" INFO ") && unsupported.contains("client_id=desktop")) {
            return Err(format!("unsupported line: {unsupported}"));
        }
        Ok(())
    });
}

#[tokio::test]
async fn lifetime_caps_evictions_and_unheld_grants_revoke_upstream() {
    let coupled = coupled(|config| {
        config["oauth"]["max_refresh_token_families_per_user"] = json!(1);
        config["ui"]["oidc"][0]["refresh_max_lifetime_seconds"] = json!(300);
    })
    .await;
    let now = coupled.runtime.now().await.unwrap();
    // Older than the method's lifetime cap, though within the client's: policy ends it.
    let capped = coupled.family_at("offline-capped", now - 301_000).await;
    assert_eq!(
        coupled.refresh(&capped).await.err(),
        Some(RefreshGrantError::InvalidGrant)
    );
    assert_eq!(coupled.revoked(1).await, ["offline-capped"]);
    // At the per-user cap of one, a new family evicts the previous one.
    coupled.family("offline-evicted").await;
    let grant = coupled.grant();
    let sealed = coupled.seal(&grant, "offline-current");
    let response = coupled
        .runtime
        .with_new_family(
            coupled.response(now),
            &grant,
            Some(&sealed),
            &coupled.browser,
            &coupled.metrics,
        )
        .await;
    assert!(serde_json::to_value(response).unwrap()["refresh_token"].is_string());
    assert_eq!(coupled.revoked(2).await[1], "offline-evicted");
    // A grant that no family holds, here for a client without refresh tokens, is revoked.
    let mut unheld = coupled.grant();
    unheld.client_id = "no-refresh".into();
    let sealed = coupled.seal(&unheld, "offline-unheld");
    let response = coupled
        .runtime
        .with_new_family(
            coupled.response(now),
            &unheld,
            Some(&sealed),
            &coupled.browser,
            &coupled.metrics,
        )
        .await;
    assert!(serde_json::to_value(response).unwrap()["refresh_token"].is_null());
    assert_eq!(coupled.revoked(3).await[2], "offline-unheld");
    assert!(
        coupled
            .idp
            .state
            .revoked
            .lock()
            .unwrap()
            .iter()
            .all(|token| token != "offline-current")
    );
}

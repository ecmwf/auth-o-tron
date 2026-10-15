// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! The key rotation procedures of the OAuth documentation, step by step. Each step
//! restarts the server with new key settings on the same refresh-token store, as a
//! rollout on a shared Valkey does.

use super::{
    refresh::{Presented, RefreshGrant, RefreshToken},
    refresh_grant::{RefreshBackend, RefreshGrantError, refresh_dispatch},
    runtime::OAuthRuntime,
    upstream::tests::{Coupled, RESOURCE, Valkey, coupled},
};
use crate::{
    browser::BrowserLoginState,
    config::ConfigV2,
    oidc::mock::{SUBJECT, rsa_key},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use rsa::pkcs8::{EncodePrivateKey, LineEnding};
use serde_json::{Value, json};
use std::{io::Write, sync::Arc, sync::atomic::Ordering};
use tempfile::NamedTempFile;

fn file(content: &str) -> NamedTempFile {
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(content.as_bytes()).unwrap();
    file
}

impl Coupled {
    /// Restarts with `edit` applied to the configuration, keeping the refresh-token
    /// store.
    async fn restart(&mut self, edit: impl FnOnce(&mut Value)) {
        let mut value = serde_json::to_value(&self.config).unwrap();
        edit(&mut value);
        let config: ConfigV2 = serde_json::from_value(value).unwrap();
        let started = OAuthRuntime::initialize(&config).await.unwrap().unwrap();
        let mut next = Arc::into_inner(started).unwrap();
        let previous = Arc::get_mut(&mut self.runtime).unwrap();
        std::mem::swap(&mut next.refresh, &mut previous.refresh);
        self.runtime = Arc::new(next);
        self.browser = BrowserLoginState::new(&config).unwrap();
        self.config = config;
    }
    /// A family of the signed-in user that does not renew an upstream grant.
    async fn uncoupled_family(&self) -> RefreshToken {
        let grant = RefreshGrant {
            upstream_coupled: false,
            ..self.grant()
        };
        let token = RefreshToken::generate().unwrap();
        let Some(RefreshBackend::Memory(store)) = &self.runtime.refresh else {
            unreachable!()
        };
        let now = self.runtime.now().await.unwrap();
        let policy = &self.config.oauth.clients[0].refresh_tokens;
        store
            .issue(&grant, token.hash(), now, policy, None)
            .await
            .unwrap();
        token
    }
    /// The access and refresh token of a refresh of `token`.
    async fn refreshed(&self, token: &RefreshToken) -> (String, RefreshToken) {
        self.refreshed_by(&self.runtime, token).await
    }
    /// The same, refreshed by the replica `runtime`.
    async fn refreshed_by(
        &self,
        runtime: &Arc<OAuthRuntime>,
        token: &RefreshToken,
    ) -> (String, RefreshToken) {
        let request = super::refresh_grant::RefreshRequest {
            token: token.as_secret_str(),
            client_id: "desktop",
            scope: None,
            resource: None,
        };
        let response = runtime
            .refresh(request, &self.auth, &self.browser, &self.metrics)
            .await
            .unwrap();
        let body = serde_json::to_value(response).unwrap();
        let next = RefreshToken::parse(body["refresh_token"].as_str().unwrap()).unwrap();
        (body["access_token"].as_str().unwrap().to_owned(), next)
    }
    /// The published key ids, in order.
    fn published(&self) -> Vec<String> {
        let jwks = self.runtime.keys.jwks();
        jwks.keys.iter().map(|key| key.kid.clone()).collect()
    }
    /// Verifies `jwt` with the published key its header names, as a resource server
    /// does; `None` if no published key has that id.
    fn verify(&self, jwt: &str) -> Option<String> {
        let kid = decode_header(jwt).unwrap().kid.unwrap();
        let jwks = self.runtime.keys.jwks();
        let key = jwks.keys.iter().find(|key| key.kid == kid)?;
        let decoding = DecodingKey::from_rsa_components(&key.n, &key.e).unwrap();
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&["https://login.example.org/"]);
        validation.set_audience(&[RESOURCE]);
        decode::<Value>(jwt, &decoding, &validation).unwrap();
        Some(kid)
    }
    /// The sealed upstream grant the family of `token` holds.
    async fn sealed(&self, token: &RefreshToken) -> String {
        let backend = self.runtime.refresh.as_ref().unwrap();
        let now = self.runtime.now().await.unwrap();
        match refresh_dispatch!(backend, lookup(&token.hash(), now)).unwrap() {
            Presented::Current(family) => family.upstream.unwrap().sealed,
            other => panic!("expected a live family, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn signing_keys_rotate_without_ending_families_or_failing_issued_tokens() {
    let mut coupled = coupled(|_| {}).await;
    let token = coupled.uncoupled_family().await;
    let (old, token) = coupled.refreshed(&token).await;
    assert_eq!(coupled.verify(&old).as_deref(), Some("k"));
    // 1. Add the new key; it is published while `k` keeps signing.
    let added = file(&rsa_key(0).to_pkcs8_pem(LineEnding::LF).unwrap());
    coupled
        .restart(|config| {
            let keys = config["oauth"]["signing"]["keys"].as_array_mut().unwrap();
            keys.push(json!({"kid": "k2", "private_key_file": added.path()}));
        })
        .await;
    assert_eq!(coupled.published(), ["k", "k2"]);
    let (access, token) = coupled.refreshed(&token).await;
    assert_eq!(coupled.verify(&access).as_deref(), Some("k"));
    // 2. Switch active_kid: the family refreshes, signed with the new key, and tokens
    // signed with the old one still verify while it is published.
    coupled
        .restart(|config| config["oauth"]["signing"]["active_kid"] = json!("k2"))
        .await;
    assert_eq!(coupled.published(), ["k", "k2"]);
    let (access, token) = coupled.refreshed(&token).await;
    assert_eq!(coupled.verify(&access).as_deref(), Some("k2"));
    assert_eq!(coupled.verify(&old).as_deref(), Some("k"));
    // 3. Once the longest access-token lifetime has passed, remove the old key: tokens
    // it signed no longer verify, and the family refreshes on.
    coupled
        .restart(|config| {
            let keys = config["oauth"]["signing"]["keys"].as_array_mut().unwrap();
            keys.remove(0);
        })
        .await;
    assert_eq!(coupled.published(), ["k2"]);
    assert_eq!(coupled.verify(&old), None);
    let (access, _) = coupled.refreshed(&token).await;
    assert_eq!(coupled.verify(&access).as_deref(), Some("k2"));
}

#[tokio::test]
#[tracing_test::traced_test]
async fn upstream_keys_rotate_by_resealing_and_removing_one_ends_its_families() {
    let mut coupled = coupled(|_| {}).await;
    let state = &coupled.idp.state;
    let renewed = coupled.family(&state.offline_token(SUBJECT)).await;
    let idle = coupled.family(&state.offline_token(SUBJECT)).await;
    assert!(coupled.sealed(&renewed).await.starts_with("v1.u1."));
    // 1. Add the new key: every replica can open what it will seal; `u1` still seals.
    let added = file(&STANDARD.encode([6u8; 32]));
    coupled
        .restart(|config| {
            let encryption = &mut config["oauth"]["upstream_token_encryption"];
            let keys = encryption["keys"].as_array_mut().unwrap();
            keys.push(json!({"kid": "u2", "key_file": added.path()}));
        })
        .await;
    let (_, renewed) = coupled.refreshed(&renewed).await;
    assert!(coupled.sealed(&renewed).await.starts_with("v1.u1."));
    // 2. Switch active_kid: grants sealed under `u1` still open, and a refresh stores
    // the provider's rotation sealed under `u2`, as new sign-ins are sealed.
    coupled
        .restart(|config| {
            config["oauth"]["upstream_token_encryption"]["active_kid"] = json!("u2");
        })
        .await;
    let (_, renewed) = coupled.refreshed(&renewed).await;
    assert!(coupled.sealed(&renewed).await.starts_with("v1.u2."));
    assert!(coupled.sealed(&idle).await.starts_with("v1.u1."));
    let signed_in = coupled.seal(&coupled.grant(), "offline-new");
    assert!(signed_in.starts_with("v1.u2."));
    // 3. Remove `u1`: families refreshed since keep working; one still sealed under
    // `u1` fails closed at its next refresh, without asking the provider.
    coupled
        .restart(|config| {
            let encryption = &mut config["oauth"]["upstream_token_encryption"];
            encryption["keys"].as_array_mut().unwrap().remove(0);
        })
        .await;
    coupled.refreshed(&renewed).await;
    let requests = coupled.idp.state.refresh_requests.load(Ordering::SeqCst);
    for _ in 0..2 {
        assert_eq!(
            coupled.refresh(&idle).await.err(),
            Some(RefreshGrantError::InvalidGrant)
        );
    }
    let Some(RefreshBackend::Memory(store)) = &coupled.runtime.refresh else {
        unreachable!()
    };
    let now = coupled.runtime.now().await.unwrap();
    assert!(matches!(
        store.lookup(&idle.hash(), now).await.unwrap(),
        Presented::Missing
    ));
    assert_eq!(
        coupled.idp.state.refresh_requests.load(Ordering::SeqCst),
        requests
    );
    // The grant cannot be opened any more, so it is not revoked at the provider.
    assert_eq!(coupled.upstream_events("revocation_skipped"), 1);
    assert!(logs_contain("oauth.upstream.unopenable"));
    assert!(logs_contain("reason=\"upstream_unusable\""));
}

/// Run explicitly: cargo test -p authotron disposable -- --ignored --test-threads=1.
#[tokio::test]
#[ignore = "requires Docker; starts and removes its own isolated Valkey container"]
async fn disposable_valkey_replicas_on_different_active_upstream_keys_reseal_in_turn() {
    let valkey = Valkey::start("authotron:rotation-test").await;
    let added = file(&STANDARD.encode([6u8; 32]));
    // Replica `a` already seals with `u2`; replica `b` still with `u1`, as during step 2
    // of the rotation or after rolling it back. Both have both keys.
    let mut coupled = coupled(|config| {
        config["ui"]["browser_session"]["backend"] = valkey.backend.clone();
        let encryption = &mut config["oauth"]["upstream_token_encryption"];
        let keys = encryption["keys"].as_array_mut().unwrap();
        keys.push(json!({"kid": "u2", "key_file": added.path()}));
        encryption["active_kid"] = json!("u2");
    })
    .await;
    let encryption = coupled
        .config
        .oauth
        .upstream_token_encryption
        .as_mut()
        .unwrap();
    encryption.active_kid = "u1".into();
    let b = OAuthRuntime::initialize(&coupled.config)
        .await
        .unwrap()
        .unwrap();
    let encryption = coupled
        .config
        .oauth
        .upstream_token_encryption
        .as_mut()
        .unwrap();
    encryption.active_kid = "u2".into();
    let grant = coupled.grant();
    let sealed = coupled.seal(&grant, &coupled.idp.state.offline_token(SUBJECT));
    let token = RefreshToken::generate().unwrap();
    let backend = coupled.runtime.refresh.as_ref().unwrap();
    let now = coupled.runtime.now().await.unwrap();
    let policy = &coupled.config.oauth.clients[0].refresh_tokens;
    refresh_dispatch!(
        backend,
        issue(&grant, token.hash(), now, policy, Some(&sealed))
    )
    .unwrap();
    assert!(coupled.sealed(&token).await.starts_with("v1.u2."));
    // Each replica opens what the other sealed and stores the grant under its own
    // active key, whether the provider rotated its token or kept it.
    let (_, token) = coupled.refreshed_by(&b, &token).await;
    assert!(coupled.sealed(&token).await.starts_with("v1.u1."));
    let (_, token) = coupled.refreshed(&token).await;
    assert!(coupled.sealed(&token).await.starts_with("v1.u2."));
    let state = &coupled.idp.state;
    state.rotate_refresh_tokens.store(false, Ordering::SeqCst);
    let (_, token) = coupled.refreshed_by(&b, &token).await;
    assert!(coupled.sealed(&token).await.starts_with("v1.u1."));
    assert_eq!(coupled.upstream_events("resealed"), 1);
    assert_eq!(coupled.upstream_events("rotated"), 2);
    assert_eq!(coupled.upstream_events("reseal_failed"), 0);
}

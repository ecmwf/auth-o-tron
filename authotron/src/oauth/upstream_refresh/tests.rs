// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! Refreshing coupled families against the in-process identity provider.

use super::*;
use crate::{
    oauth::{
        refresh::RefreshToken,
        upstream::tests::{Coupled, coupled},
    },
    oidc::{mock::SUBJECT, upstream::UpstreamCipher},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::json;
use std::{io::Write, sync::atomic::Ordering, time::Duration};

/// The upstream refresh token the family of `token` currently holds.
async fn held(coupled: &Coupled, token: &RefreshToken) -> String {
    let Some(RefreshBackend::Memory(store)) = &coupled.runtime.refresh else {
        unreachable!()
    };
    let now = coupled.runtime.now().await.unwrap();
    let Presented::Current(family) = store.lookup(&token.hash(), now).await.unwrap() else {
        panic!("expected a live family");
    };
    let method = coupled.browser.method("sso").unwrap().oidc().unwrap();
    let upstream = coupled.runtime.upstream.as_ref().unwrap();
    let opened = upstream
        .cipher
        .open(
            &binding(&family.grant, method),
            &family.upstream.unwrap().sealed,
        )
        .unwrap();
    opened.refresh_token().to_owned()
}

/// A family holding a live upstream grant for the test subject.
async fn live_family(coupled: &Coupled) -> (RefreshToken, String) {
    let upstream = coupled.idp.state.offline_token(SUBJECT);
    (coupled.family(&upstream).await, upstream)
}

#[tokio::test]
#[tracing_test::traced_test]
async fn refresh_renews_the_upstream_grant_and_stores_its_rotation() {
    let coupled = coupled(|_| {}).await;
    let (first, original) = live_family(&coupled).await;
    let second = coupled.refresh(&first).await.unwrap();
    let rotated = held(&coupled, &second).await;
    assert_ne!(rotated, original);
    let state = &coupled.idp.state;
    assert!(state.refresh_token_live(&rotated) && !state.refresh_token_live(&original));
    // Provider unavailability keeps the family and its grant for a retry.
    *state.token_answer.lock().unwrap() = Some((503, json!({})));
    assert_eq!(
        coupled.refresh(&second).await.err(),
        Some(RefreshGrantError::Unavailable)
    );
    *state.token_answer.lock().unwrap() = None;
    let third = coupled.refresh(&second).await.unwrap();
    // A provider that keeps the refresh token leaves the stored grant unchanged.
    state.rotate_refresh_tokens.store(false, Ordering::SeqCst);
    let kept = held(&coupled, &third).await;
    let fourth = coupled.refresh(&third).await.unwrap();
    assert_eq!(held(&coupled, &fourth).await, kept);
    for (event, count) in [("refreshed", 3), ("rotated", 2), ("unavailable", 1)] {
        assert_eq!(coupled.upstream_events(event), count, "{event}");
    }
    // The locked section runs in its own task but logs within the refresh's span.
    assert!(logs_contain("oauth.upstream.refresh_unavailable"));
    assert!(logs_contain("reason=\"unavailable\""));
}

#[tokio::test]
#[tracing_test::traced_test]
async fn a_refused_grant_ends_the_family_and_is_revoked_at_the_provider() {
    let coupled = coupled(|_| {}).await;
    let (token, upstream) = live_family(&coupled).await;
    coupled
        .idp
        .state
        .disabled
        .lock()
        .unwrap()
        .insert(SUBJECT.into());
    assert_eq!(
        coupled.refresh(&token).await.err(),
        Some(RefreshGrantError::InvalidGrant)
    );
    // The refused token is still revoked: the provider may keep its session.
    assert_eq!(coupled.revoked(1).await, std::slice::from_ref(&upstream));
    assert!(!coupled.idp.state.refresh_token_live(&upstream));
    assert_eq!(coupled.upstream_events("revocation_sent"), 1);
    // The family is gone: no second refresh request.
    assert_eq!(
        coupled.refresh(&token).await.err(),
        Some(RefreshGrantError::InvalidGrant)
    );
    assert_eq!(coupled.idp.state.refresh_requests.load(Ordering::SeqCst), 1);
    assert_eq!(coupled.upstream_events("invalid_grant"), 1);
    // A grant the configured keys cannot open ends its family; it is skipped upstream.
    let mut foreign = coupled.grant();
    foreign.client_id = "other".into();
    let sealed = coupled.seal(&foreign, "offline-foreign");
    let unopenable = RefreshToken::generate().unwrap();
    let Some(RefreshBackend::Memory(store)) = &coupled.runtime.refresh else {
        unreachable!()
    };
    let now = coupled.runtime.now().await.unwrap();
    let policy = &coupled.config.oauth.clients[0].refresh_tokens;
    store
        .issue(
            &coupled.grant(),
            unopenable.hash(),
            now,
            policy,
            Some(&sealed),
        )
        .await
        .unwrap();
    assert_eq!(
        coupled.refresh(&unopenable).await.err(),
        Some(RefreshGrantError::InvalidGrant)
    );
    assert_eq!(coupled.idp.state.refresh_requests.load(Ordering::SeqCst), 1);
    assert_eq!(coupled.upstream_events("revocation_skipped"), 1);
    assert_eq!(coupled.idp.state.revoked.lock().unwrap().len(), 1);
    for reason in ["upstream_invalid_grant", "upstream_unusable"] {
        assert!(logs_contain(&format!("reason=\"{reason}\"")), "{reason}");
    }
    assert!(!logs_contain(&upstream));
    // The refusal and the revocation of the refused grant are logged with the family.
    logs_assert(|lines: &[&str]| {
        let rejected = lines
            .iter()
            .find(|line| line.contains("oauth.upstream.refresh_rejected"))
            .ok_or("no refresh_rejected line")?;
        for field in [
            " WARN ",
            "reason=\"invalid_grant\"",
            "client_id=desktop",
            "realm=idp",
        ] {
            if !rejected.contains(field) {
                return Err(format!("{field} missing: {rejected}"));
            }
        }
        let family = rejected
            .split("family=")
            .nth(1)
            .and_then(|rest| rest.get(..12));
        let revoked = lines.iter().any(|line| {
            line.contains("oauth.upstream.revocation_sent")
                && family.is_some_and(|family| line.contains(&format!("family={family}")))
        });
        if revoked {
            Ok(())
        } else {
            Err("no revocation line for the family".into())
        }
    });
}

#[tokio::test]
#[tracing_test::traced_test]
async fn a_changed_identity_ends_the_family_and_revokes_the_newest_grant() {
    let coupled = coupled(|_| {}).await;
    let (token, _) = live_family(&coupled).await;
    *coupled.idp.state.claims.lock().unwrap() = json!({"sub": "another-user"});
    assert_eq!(
        coupled.refresh(&token).await.err(),
        Some(RefreshGrantError::InvalidGrant)
    );
    // The provider rotated before the identity was checked: that rotation is revoked.
    let revoked = coupled.revoked(1).await;
    assert!(revoked[0].starts_with("offline-"));
    assert!(!coupled.idp.state.refresh_token_live(&revoked[0]));
    assert_eq!(coupled.upstream_events("identity_changed"), 1);
    assert_eq!(
        coupled.refresh(&token).await.err(),
        Some(RefreshGrantError::InvalidGrant)
    );
    assert!(logs_contain("reason=\"identity_changed\""));
}

#[tokio::test]
async fn refreshed_roles_replace_the_family_roles_and_need_an_id_token() {
    let coupled = coupled(|config| {
        let method = &mut config["ui"]["oidc"][0];
        method["roles_claim"] = json!("realm_access.roles");
        method["role_map"] = json!({"mcp-demo": "reader"});
        config["oauth"]["resources"][0]["scopes"][0]["required_roles"] = json!(["reader"]);
    })
    .await;
    let (token, _) = live_family(&coupled).await;
    let token = coupled.refresh(&token).await.unwrap();
    // The rotation keeps the refreshed roles, which the sign-in snapshot lacked.
    let Some(RefreshBackend::Memory(store)) = &coupled.runtime.refresh else {
        unreachable!()
    };
    let now = coupled.runtime.now().await.unwrap();
    let Presented::Current(family) = store.lookup(&token.hash(), now).await.unwrap() else {
        panic!("expected a live family");
    };
    let mut expected = coupled.grant();
    expected.provider_roles = vec!["reader".into()];
    assert_eq!(family.grant, expected);
    // Without an ID token the mapped roles cannot be re-checked: 503, family kept.
    coupled
        .idp
        .state
        .refresh_id_tokens
        .store(false, Ordering::SeqCst);
    assert_eq!(
        coupled.refresh(&token).await.err(),
        Some(RefreshGrantError::Unavailable)
    );
    coupled
        .idp
        .state
        .refresh_id_tokens
        .store(true, Ordering::SeqCst);
    // The role was removed upstream: current policy now denies the scope.
    *coupled.idp.state.claims.lock().unwrap() = json!({"realm_access": {"roles": []}});
    assert_eq!(
        coupled.refresh(&token).await.err(),
        Some(RefreshGrantError::InvalidGrant)
    );
}

#[tokio::test]
async fn a_retried_refresh_reuses_the_upstream_renewal_without_the_provider() {
    let coupled = coupled(|config| {
        let method = &mut config["ui"]["oidc"][0];
        method["roles_claim"] = json!("realm_access.roles");
        method["role_map"] = json!({"mcp-demo": "reader"});
        config["oauth"]["resources"][0]["scopes"][0]["required_roles"] = json!(["reader"]);
    })
    .await;
    let requests = || coupled.idp.state.refresh_requests.load(Ordering::SeqCst);
    let (first, _) = live_family(&coupled).await;
    let second = coupled.refresh(&first).await.unwrap();
    assert_eq!(requests(), 1);
    // The answer was lost. The retry gets the same token, and its access token the
    // stored refreshed role: the family's sign-in roles lack `reader`.
    let retried = coupled.refresh(&first).await.unwrap();
    assert_eq!(retried.as_secret_str(), second.as_secret_str());
    assert_eq!(requests(), 1);
    assert_eq!(coupled.upstream_events("refreshed"), 1);
    // The successor renews upstream as usual.
    coupled.refresh(&second).await.unwrap();
    assert_eq!(requests(), 2);
}

#[tokio::test]
async fn concurrent_refreshes_share_one_successor_and_renew_upstream_in_turn() {
    let coupled = coupled(|_| {}).await;
    let (token, _) = live_family(&coupled).await;
    let (a, b) = tokio::join!(coupled.refresh(&token), coupled.refresh(&token));
    // Both get the same rotated token; the provider never saw a spent token.
    let (a, b) = (a.unwrap(), b.unwrap());
    assert_eq!(a.as_secret_str(), b.as_secret_str());
    assert_eq!(coupled.upstream_events("invalid_grant"), 0);
    let held = held(&coupled, &a).await;
    assert!(coupled.idp.state.refresh_token_live(&held));
    coupled.refresh(&a).await.unwrap();
}

#[tokio::test]
async fn a_held_lock_makes_the_refresh_unavailable() {
    let coupled = coupled(|_| {}).await;
    let (token, _) = live_family(&coupled).await;
    let Some(RefreshBackend::Memory(store)) = &coupled.runtime.refresh else {
        unreachable!()
    };
    let now = coupled.runtime.now().await.unwrap();
    let Presented::Current(family) = store.lookup(&token.hash(), now).await.unwrap() else {
        panic!("expected a live family");
    };
    assert!(
        store
            .lock_upstream(&family.family_id, "other-replica", now, now + 60_000)
            .await
            .unwrap()
    );
    assert_eq!(
        coupled.refresh(&token).await.err(),
        Some(RefreshGrantError::Unavailable)
    );
    assert_eq!(coupled.idp.state.refresh_requests.load(Ordering::SeqCst), 0);
    store
        .unlock_upstream(&family.family_id, "other-replica")
        .await
        .unwrap();
    coupled.refresh(&token).await.unwrap();
}

#[tokio::test]
async fn an_unverified_refreshed_id_token_keeps_the_family_and_its_rotation() {
    let coupled = coupled(|_| {}).await;
    let (token, original) = live_family(&coupled).await;
    *coupled.idp.state.claims.lock().unwrap() = json!({"aud": "other-client"});
    assert_eq!(
        coupled.refresh(&token).await.err(),
        Some(RefreshGrantError::Unavailable)
    );
    let rotated = held(&coupled, &token).await;
    assert_ne!(rotated, original);
    assert!(coupled.idp.state.refresh_token_live(&rotated));
    *coupled.idp.state.claims.lock().unwrap() = json!({});
    coupled.refresh(&token).await.unwrap();
}

#[tokio::test]
async fn a_cancelled_refresh_still_stores_the_rotation_and_releases_the_lock() {
    let coupled = coupled(|_| {}).await;
    let (token, original) = live_family(&coupled).await;
    let state = &coupled.idp.state;
    state.token_delay_ms.store(300, Ordering::SeqCst);
    let abandoned = tokio::time::timeout(Duration::from_millis(100), coupled.refresh(&token));
    assert!(abandoned.await.is_err());
    tokio::time::sleep(Duration::from_millis(600)).await;
    state.token_delay_ms.store(0, Ordering::SeqCst);
    // The client's token was never rotated, but the provider's rotation was stored.
    let rotated = held(&coupled, &token).await;
    assert_ne!(rotated, original);
    assert!(state.refresh_token_live(&rotated));
    coupled.refresh(&token).await.unwrap();
}

#[tokio::test]
async fn a_kept_upstream_token_under_an_older_key_is_resealed_under_the_active_one() {
    let mut second = tempfile::NamedTempFile::new().unwrap();
    write!(second, "{}", STANDARD.encode([6u8; 32])).unwrap();
    let coupled = coupled(|config| {
        let encryption = &mut config["oauth"]["upstream_token_encryption"];
        let keys = encryption["keys"].as_array_mut().unwrap();
        keys.push(json!({"kid": "u2", "key_file": second.path()}));
        encryption["active_kid"] = json!("u2");
    })
    .await;
    let state = &coupled.idp.state;
    state.rotate_refresh_tokens.store(false, Ordering::SeqCst);
    // A grant sealed under `u1` before `u2` became active.
    let upstream = state.offline_token(SUBJECT);
    let before =
        UpstreamCipher::from_keys("u1", vec![("u1".into(), Zeroizing::new([5u8; 32]))]).unwrap();
    let method = coupled.browser.method("sso").unwrap().oidc().unwrap();
    let grant = UpstreamGrant::new(SUBJECT, Zeroizing::new(upstream.clone()));
    let sealed = before
        .seal(&binding(&coupled.grant(), method), &grant)
        .unwrap();
    let Some(RefreshBackend::Memory(store)) = &coupled.runtime.refresh else {
        unreachable!()
    };
    let now = coupled.runtime.now().await.unwrap();
    let token = RefreshToken::generate().unwrap();
    let policy = &coupled.config.oauth.clients[0].refresh_tokens;
    store
        .issue(&coupled.grant(), token.hash(), now, policy, Some(&sealed))
        .await
        .unwrap();
    let runtime = &coupled.runtime;
    let stored = |token: RefreshToken| async move {
        let now = runtime.now().await.unwrap();
        match store.lookup(&token.hash(), now).await.unwrap() {
            Presented::Current(family) => (token, family.upstream.unwrap()),
            other => panic!("expected a live family, got {other:?}"),
        }
    };
    // The provider keeps its token; it is stored again, sealed under the active key.
    let (next, resealed) = stored(coupled.refresh(&token).await.unwrap()).await;
    assert!(resealed.sealed.starts_with("v1.u2.") && resealed.generation == 1);
    assert_eq!(held(&coupled, &next).await, upstream);
    assert_eq!(coupled.upstream_events("resealed"), 1);
    assert_eq!(coupled.upstream_events("rotated"), 0);
    // Under the active key already, a kept token is left as it is.
    let (_, kept) = stored(coupled.refresh(&next).await.unwrap()).await;
    assert_eq!(kept, resealed);
    assert_eq!(coupled.upstream_events("resealed"), 1);
}

#[tokio::test]
#[tracing_test::traced_test]
async fn a_failed_reseal_is_reported_and_keeps_the_grant_under_its_old_key() {
    let mut second = tempfile::NamedTempFile::new().unwrap();
    write!(second, "{}", STANDARD.encode([6u8; 32])).unwrap();
    let coupled = coupled(|config| {
        let encryption = &mut config["oauth"]["upstream_token_encryption"];
        let keys = encryption["keys"].as_array_mut().unwrap();
        keys.push(json!({"kid": "u2", "key_file": second.path()}));
        encryption["active_kid"] = json!("u2");
    })
    .await;
    let state = &coupled.idp.state;
    state.rotate_refresh_tokens.store(false, Ordering::SeqCst);
    let upstream = state.offline_token(SUBJECT);
    let before =
        UpstreamCipher::from_keys("u1", vec![("u1".into(), Zeroizing::new([5u8; 32]))]).unwrap();
    let method = coupled.browser.method("sso").unwrap().oidc().unwrap();
    let grant = coupled.grant();
    let binding = binding(&grant, method);
    let seal = || {
        let grant = UpstreamGrant::new(SUBJECT, Zeroizing::new(upstream.clone()));
        before.seal(&binding, &grant).unwrap()
    };
    let Some(RefreshBackend::Memory(store)) = &coupled.runtime.refresh else {
        unreachable!()
    };
    let now = coupled.runtime.now().await.unwrap();
    let token = RefreshToken::generate().unwrap();
    let policy = &coupled.config.oauth.clients[0].refresh_tokens;
    store
        .issue(&coupled.grant(), token.hash(), now, policy, Some(&seal()))
        .await
        .unwrap();
    let Presented::Current(family) = store.lookup(&token.hash(), now).await.unwrap() else {
        panic!("expected a live family");
    };
    // While the provider answers slowly, the stored grant changes generation, so the
    // reseal no longer applies.
    state.token_delay_ms.store(300, Ordering::SeqCst);
    let replaced = async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        store
            .set_upstream(&family.family_id, 0, &seal(), now)
            .await
            .unwrap()
    };
    let (refreshed, replaced) = tokio::join!(coupled.refresh(&token), replaced);
    assert_eq!(replaced, UpstreamStored::Stored);
    let next = refreshed.unwrap();
    assert_eq!(coupled.upstream_events("reseal_failed"), 1);
    assert_eq!(coupled.upstream_events("resealed"), 0);
    assert!(logs_contain("oauth.upstream.reseal_failed"));
    let Presented::Current(family) = store.lookup(&next.hash(), now).await.unwrap() else {
        panic!("expected a live family");
    };
    assert!(family.upstream.unwrap().sealed.starts_with("v1.u1."));
}

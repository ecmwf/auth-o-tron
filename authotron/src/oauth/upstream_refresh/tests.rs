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
    oidc::mock::SUBJECT,
};
use serde_json::json;
use std::sync::atomic::Ordering;

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
}

#[tokio::test]
async fn a_refused_grant_ends_the_family_without_contacting_the_provider_again() {
    let coupled = coupled(|_| {}).await;
    let (token, _) = live_family(&coupled).await;
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
    // The family is gone: no second provider request.
    assert_eq!(
        coupled.refresh(&token).await.err(),
        Some(RefreshGrantError::InvalidGrant)
    );
    assert_eq!(coupled.idp.state.refresh_requests.load(Ordering::SeqCst), 1);
    assert_eq!(coupled.upstream_events("invalid_grant"), 1);
    assert!(coupled.idp.state.revoked.lock().unwrap().is_empty());
    // A grant the configured keys cannot open ends its family the same way.
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
}

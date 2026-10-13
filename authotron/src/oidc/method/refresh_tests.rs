// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! Refreshing and revoking upstream grants against the in-process identity provider.

use super::{
    OidcError, OidcMethod,
    tests::{method, sign_in},
};
use crate::oidc::mock::{MockIdp, SUBJECT};
use serde_json::json;
use std::{io::Write, sync::atomic::Ordering};
use zeroize::Zeroizing;

/// Signs in with `offline_access` and returns the issued refresh token.
async fn offline_token(idp: &MockIdp, method: &OidcMethod, state: &str) -> Zeroizing<String> {
    let signed_in = sign_in(idp, method, state, true).await.unwrap();
    assert_eq!(signed_in.subject, SUBJECT);
    signed_in
        .refresh_token
        .expect("offline sign-in issues a refresh token")
}

#[tokio::test]
async fn refresh_rotates_the_grant_and_validates_a_refreshed_identity() {
    let idp = MockIdp::start().await;
    let (_secret, method) = method(&idp, json!({"username_claim": "preferred_username"}));
    let first = offline_token(&idp, &method, "state-1").await;
    let refreshed = method.refresh(&first).await.unwrap();
    let second = refreshed.refresh_token.unwrap();
    assert_ne!(*second, *first);
    let (subject, user) = refreshed.identity.unwrap().unwrap();
    assert_eq!(
        (subject.as_str(), user.username.as_str()),
        (SUBJECT, "alice")
    );
    // Strict rotation: the presented token is spent.
    assert_eq!(
        method.refresh(&first).await.err(),
        Some(OidcError::Rejected)
    );
    // A provider may keep the token and omit the ID token.
    idp.state
        .rotate_refresh_tokens
        .store(false, Ordering::SeqCst);
    idp.state.refresh_id_tokens.store(false, Ordering::SeqCst);
    let kept = method.refresh(&second).await.unwrap();
    assert!(kept.refresh_token.is_none());
    assert!(matches!(kept.identity, Ok(None)));
    // An invalid refreshed ID token is reported beside the rotated token, which the
    // caller must still store or revoke.
    idp.state
        .rotate_refresh_tokens
        .store(true, Ordering::SeqCst);
    idp.state.refresh_id_tokens.store(true, Ordering::SeqCst);
    *idp.state.claims.lock().unwrap() = json!({"aud": "other-client"});
    let invalid = method.refresh(&second).await.unwrap();
    let third = invalid.refresh_token.unwrap();
    assert!(matches!(invalid.identity, Err(OidcError::InvalidIdToken)));
    *idp.state.claims.lock().unwrap() = json!({});
    *idp.state.token_answer.lock().unwrap() = Some((503, json!({})));
    assert_eq!(
        method.refresh(&third).await.err(),
        Some(OidcError::Unavailable)
    );
    *idp.state.token_answer.lock().unwrap() = None;
    // A disabled account's grant is refused at the provider.
    idp.state.disabled.lock().unwrap().insert(SUBJECT.into());
    assert_eq!(
        method.refresh(&third).await.err(),
        Some(OidcError::Rejected)
    );
    assert_eq!(idp.state.refresh_requests.load(Ordering::SeqCst), 5);
}

#[tokio::test]
async fn revocation_ends_the_grant_where_the_provider_supports_it() {
    let idp = MockIdp::start().await;
    let (_secret, sso) = method(&idp, json!({"client_auth": "client_secret_post"}));
    let token = offline_token(&idp, &sso, "state").await;
    assert!(idp.state.refresh_token_live(&token));
    assert_eq!(sso.revoke(&token).await, Ok(true));
    assert_eq!(*idp.state.revoked.lock().unwrap(), [token.as_str()]);
    assert!(!idp.state.refresh_token_live(&token));
    assert_eq!(sso.refresh(&token).await.err(), Some(OidcError::Rejected));
    // A wrong client secret is refused.
    let mut secret = tempfile::NamedTempFile::new().unwrap();
    writeln!(secret, "wrong-secret").unwrap();
    let mut config = sso.config().clone();
    config.client_secret_file = Some(secret.path().to_owned());
    let wrong = OidcMethod::new(&config, "https://login.example.org").unwrap();
    assert_eq!(wrong.revoke("token").await, Err(OidcError::ClientRejected));
    // Without an advertised endpoint nothing is sent.
    let silent = MockIdp::start().await;
    silent.state.revocation.store(false, Ordering::SeqCst);
    let (_secret, sso) = method(&silent, json!({}));
    assert_eq!(sso.revoke("token").await, Ok(false));
    assert!(silent.state.revoked.lock().unwrap().is_empty());
}

// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! OIDC sign-in with offline access: the sealed upstream grant travels through consent
//! and code exchange into a coupled refresh family, and is revoked at the provider when
//! the authorization ends otherwise.

use super::{
    authorization_tests::{
        CLIENT_CALLBACK, RESOURCE, VERIFIER, authorization_fixture_with, authorize, form, hidden,
        send,
    },
    tests::{Fixture, Jar, ORIGIN, get, local, location, start, text},
};
use axum::{
    http::{Request, StatusCode, header},
    response::Response,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::{io::Write, sync::atomic::Ordering, time::Duration};
use tempfile::NamedTempFile;
use url::Url;

/// The OIDC-only authorization server with sealing keys, an OIDC method allowing
/// offline access, and refresh tokens for `desktop`, coupled when `opted_in`.
async fn offline_fixture(opted_in: bool) -> (Fixture, [NamedTempFile; 2]) {
    let mut key = NamedTempFile::new().unwrap();
    writeln!(key, "{}", STANDARD.encode([9u8; 32])).unwrap();
    let path = key.path().to_owned();
    let (fixture, signing) = authorization_fixture_with(|config| {
        config["ui"]["oidc"][0]["offline_access"] = json!(true);
        let oauth = &mut config["oauth"];
        oauth["upstream_token_encryption"] =
            json!({"active_kid": "u1", "keys": [{"kid": "u1", "key_file": path}]});
        oauth["clients"][0]["refresh_tokens"] =
            json!({"enabled": true, "upstream_offline_access": opted_in});
    })
    .await;
    (fixture, [key, signing])
}

/// Starts an authorization, signs in at the provider and returns the callback's answer.
async fn sign_in(fixture: &Fixture, jar: &mut Jar) -> (Url, Response) {
    *jar = authorize(fixture).await;
    let request = start(fixture, jar).await;
    let response = get(&fixture.app, &local(&fixture.idp.authorize(&request)), jar).await;
    jar.update(&response);
    (request, response)
}

fn scope(request: &Url) -> String {
    request
        .query_pairs()
        .find(|(name, _)| name == "scope")
        .unwrap()
        .1
        .into_owned()
}

async fn decide(fixture: &Fixture, jar: &Jar, decision: &str) -> Url {
    let consent = text(get(&fixture.app, "/oauth/continue", jar).await).await;
    let response = send(
        fixture,
        Request::post("/oauth/consent")
            .header(header::COOKIE, jar.header())
            .header(header::ORIGIN, ORIGIN)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(form(&[
                ("csrf", &hidden(&consent, "csrf")),
                ("oauth_transaction", &hidden(&consent, "oauth_transaction")),
                ("decision", decision),
            ]))
            .unwrap(),
    )
    .await;
    Url::parse(&location(&response)).unwrap()
}

async fn post(fixture: &Fixture, path: &str, fields: &[(&str, &str)]) -> (StatusCode, Value) {
    let response = send(
        fixture,
        Request::post(path)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(form(fields))
            .unwrap(),
    )
    .await;
    let status = response.status();
    (
        status,
        serde_json::from_str(&text(response).await).unwrap_or_default(),
    )
}

/// Approves consent, exchanges the code and returns the refresh token.
async fn approve_and_exchange(fixture: &Fixture, jar: &Jar) -> String {
    let redirect = decide(fixture, jar, "approve").await;
    let code = redirect
        .query_pairs()
        .find(|(name, _)| name == "code")
        .unwrap()
        .1
        .into_owned();
    let (status, tokens) = post(
        fixture,
        "/oauth/token",
        &[
            ("grant_type", "authorization_code"),
            ("client_id", "desktop"),
            ("code", &code),
            ("redirect_uri", CLIENT_CALLBACK),
            ("resource", RESOURCE),
            ("code_verifier", VERIFIER),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    tokens["refresh_token"].as_str().unwrap().to_owned()
}

async fn refresh(fixture: &Fixture, token: &str) -> (StatusCode, Value) {
    post(
        fixture,
        "/oauth/token",
        &[
            ("grant_type", "refresh_token"),
            ("client_id", "desktop"),
            ("refresh_token", token),
        ],
    )
    .await
}

/// Waits for the background worker to send `count` upstream revocations.
async fn revoked(fixture: &Fixture, count: usize) -> Vec<String> {
    for _ in 0..300 {
        let revoked = fixture.idp.state.revoked.lock().unwrap().clone();
        if revoked.len() >= count {
            return revoked;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("expected {count} upstream revocations");
}

#[tokio::test]
async fn offline_sign_in_couples_the_refresh_family_to_the_upstream_grant() {
    let (fixture, _files) = offline_fixture(true).await;
    let mut jar = Jar::default();
    let (request, response) = sign_in(&fixture, &mut jar).await;
    assert_eq!(scope(&request), "openid offline_access");
    assert_eq!(location(&response), "/oauth/continue");
    let token = approve_and_exchange(&fixture, &jar).await;
    let (status, tokens) = refresh(&fixture, &token).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(fixture.idp.state.refresh_requests.load(Ordering::SeqCst), 1);
    let next = tokens["refresh_token"].as_str().unwrap();
    let (status, _) = post(
        &fixture,
        "/oauth/revoke",
        &[("token", next), ("client_id", "desktop")],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let revoked = revoked(&fixture, 1).await;
    assert!(!fixture.idp.state.refresh_token_live(&revoked[0]));
}

#[tokio::test]
async fn a_missing_offline_token_fails_the_sign_in() {
    let (fixture, _files) = offline_fixture(true).await;
    fixture
        .idp
        .state
        .issue_offline_tokens
        .store(false, Ordering::SeqCst);
    let mut jar = Jar::default();
    let (_, response) = sign_in(&fixture, &mut jar).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(text(response).await.contains("Sign-in not completed"));
}

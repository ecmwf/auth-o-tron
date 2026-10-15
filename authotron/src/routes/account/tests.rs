// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! The account page and its forms, through the application router.

use crate::{
    oauth::{audit::family_ref, refresh::FamilySummary},
    oidc::mock::SUBJECT,
    routes::oidc_login::{
        offline_tests::{approve_and_exchange, offline_fixture, refresh, revoked, sign_in},
        tests::{Fixture, Jar, ORIGIN, fixture, get, local, location, start, text},
    },
};
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
    response::Response,
};
use tower::ServiceExt;

const SESSION: &str = "__Host-authotron_session";

fn hidden(html: &str, name: &str) -> String {
    html.split(&format!("name=\"{name}\" value=\""))
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .into()
}

/// Posts `fields` from `origin`, if any, with the cookies of `jar`.
async fn post(
    fixture: &Fixture,
    path: &str,
    jar: &Jar,
    origin: Option<&str>,
    fields: &[(&str, &str)],
) -> Response {
    let mut body = url::form_urlencoded::Serializer::new(String::new());
    for (name, value) in fields {
        body.append_pair(name, value);
    }
    let mut request = Request::post(path)
        .header(header::COOKIE, jar.header())
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(origin) = origin {
        request = request.header(header::ORIGIN, origin);
    }
    let request = request.body(Body::from(body.finish())).unwrap();
    fixture.app.clone().oneshot(request).await.unwrap()
}

/// A browser signed in with the password method.
async fn signed_in(fixture: &Fixture) -> Jar {
    let mut jar = Jar::default();
    let response = get(&fixture.app, "/login/method/password", &jar).await;
    jar.update(&response);
    let csrf = hidden(&text(response).await, "csrf");
    let fields = [
        ("csrf", csrf.as_str()),
        ("username", "alice"),
        ("password", "fixture-only"),
    ];
    let response = post(
        fixture,
        "/login/method/password",
        &jar,
        Some(ORIGIN),
        &fields,
    )
    .await;
    assert_eq!(location(&response), "/login/account");
    jar.update(&response);
    jar
}

/// The account page's CSRF token, with its form-nonce cookie stored in `jar`.
async fn account_csrf(fixture: &Fixture, jar: &mut Jar) -> String {
    let response = get(&fixture.app, "/login/account", jar).await;
    assert_eq!(response.status(), StatusCode::OK);
    jar.update(&response);
    let html = text(response).await;
    assert!(html.contains("<form class=\"key-form\" method=\"post\" action=\"/login/logout\">"));
    hidden(&html, "csrf")
}

async fn signed_in_still(fixture: &Fixture, jar: &Jar) -> bool {
    get(&fixture.app, "/login/account", jar).await.status() == StatusCode::OK
}

#[tokio::test]
async fn signing_out_ends_the_session_and_clears_its_cookie() {
    let fixture = fixture(|_| {}).await;
    let mut jar = signed_in(&fixture).await;
    let sid = jar.0[SESSION].clone();
    let csrf = account_csrf(&fixture, &mut jar).await;
    let response = post(
        &fixture,
        "/login/logout",
        &jar,
        Some(ORIGIN),
        &[("csrf", &csrf)],
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&response), "/login?signed-out");
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let cleared = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|value| cookie::Cookie::parse(value.to_str().unwrap().to_owned()).unwrap())
        .find(|cookie| cookie.name() == SESSION)
        .unwrap();
    assert_eq!(cleared.value(), "");
    assert_eq!(cleared.max_age().unwrap().whole_seconds(), 0);
    assert_eq!(cleared.same_site(), Some(cookie::SameSite::Lax));
    assert_eq!(cleared.path(), Some("/"));
    assert!(cleared.domain().is_none());
    jar.update(&response);
    assert!(!jar.0.contains_key(SESSION));
    assert!(fixture.state.browser.lookup(&sid).await.unwrap().is_none());
    let notice = text(get(&fixture.app, "/login?signed-out", &jar).await).await;
    assert!(notice.contains("You are signed out."));
    for path in ["/login", "/login?signed-out=1", "/login?x&signed-out"] {
        assert!(
            !text(get(&fixture.app, path, &jar).await)
                .await
                .contains("signed out")
        );
    }
    // The old cookie no longer opens the account page.
    jar.0.insert(SESSION.into(), sid);
    assert_eq!(
        location(&get(&fixture.app, "/login/account", &jar).await),
        "/login"
    );
}

#[tokio::test]
async fn sign_out_refuses_forged_requests_and_keeps_the_session() {
    let fixture = fixture(|_| {}).await;
    let mut jar = signed_in(&fixture).await;
    let csrf = account_csrf(&fixture, &mut jar).await;
    let sign_in = hidden(
        &text(get(&fixture.app, "/login/method/password", &jar).await).await,
        "csrf",
    );
    let mut without_nonce = jar.clone();
    without_nonce.0.remove("__Host-authotron_form");
    let other = "https://attacker.example.test";
    let (token, forged) = (csrf.as_str(), sign_in.as_str());
    // The browser, Origin, fields and the status of its refusal.
    type Attempt<'a> = (
        &'a Jar,
        Option<&'a str>,
        &'a [(&'a str, &'a str)],
        StatusCode,
    );
    let refused: [Attempt; 8] = [
        (&jar, None, &[("csrf", token)], StatusCode::FORBIDDEN),
        (
            &jar,
            Some("null"),
            &[("csrf", token)],
            StatusCode::FORBIDDEN,
        ),
        (&jar, Some(other), &[("csrf", token)], StatusCode::FORBIDDEN),
        (
            &jar,
            Some(ORIGIN),
            &[("csrf", forged)],
            StatusCode::FORBIDDEN,
        ),
        (
            &without_nonce,
            Some(ORIGIN),
            &[("csrf", token)],
            StatusCode::FORBIDDEN,
        ),
        (&jar, Some(ORIGIN), &[], StatusCode::BAD_REQUEST),
        (
            &jar,
            Some(ORIGIN),
            &[("csrf", token), ("csrf", token)],
            StatusCode::BAD_REQUEST,
        ),
        (
            &jar,
            Some(ORIGIN),
            &[("csrf", token), ("session", "x")],
            StatusCode::BAD_REQUEST,
        ),
    ];
    for (jar, origin, fields, status) in refused {
        let response = post(&fixture, "/login/logout", jar, origin, fields).await;
        assert_eq!(response.status(), status, "{origin:?} {fields:?}");
        assert!(response.headers().get(header::SET_COOKIE).is_none());
        assert!(text(response).await.contains("Request not completed"));
    }
    assert!(signed_in_still(&fixture, &jar).await);
    // An account form cannot sign in either.
    let fields = [
        ("csrf", csrf.as_str()),
        ("username", "alice"),
        ("password", "fixture-only"),
    ];
    let response = post(
        &fixture,
        "/login/method/password",
        &jar,
        Some(ORIGIN),
        &fields,
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    // None of the refusals used the token up; it is spent once used.
    let response = post(
        &fixture,
        "/login/logout",
        &jar,
        Some(ORIGIN),
        &[("csrf", &csrf)],
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let response = post(
        &fixture,
        "/login/logout",
        &jar,
        Some(ORIGIN),
        &[("csrf", &csrf)],
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn signing_out_without_a_session_still_clears_the_cookie() {
    let fixture = fixture(|_| {}).await;
    let mut jar = signed_in(&fixture).await;
    let first = account_csrf(&fixture, &mut jar).await;
    let second = account_csrf(&fixture, &mut jar).await;
    let mut anonymous = jar.clone();
    anonymous.0.remove(SESSION);
    let response = post(
        &fixture,
        "/login/logout",
        &anonymous,
        Some(ORIGIN),
        &[("csrf", &first)],
    )
    .await;
    assert_eq!(location(&response), "/login?signed-out");
    assert!(response.headers().get(header::SET_COOKIE).is_some());
    // This browser's session is not known to that request and stays signed in.
    assert!(signed_in_still(&fixture, &jar).await);
    let sid = jar.0[SESSION].clone();
    fixture.state.browser.end_session(&sid).await.unwrap();
    let response = post(
        &fixture,
        "/login/logout",
        &jar,
        Some(ORIGIN),
        &[("csrf", &second)],
    )
    .await;
    assert_eq!(location(&response), "/login?signed-out");
}

const REVOKE: &str = "/login/account/logins/revoke";
/// The Origin, fields and status of a refused form.
type Refusal<'a> = (Option<&'a str>, &'a [(&'a str, &'a str)], StatusCode);

/// A browser signed in with the OIDC method, as the provider's current subject.
async fn oidc_session(fixture: &Fixture) -> Jar {
    let mut jar = Jar::default();
    let authorization = start(fixture, &mut jar).await;
    let callback = local(&fixture.idp.authorize(&authorization));
    let response = get(&fixture.app, &callback, &jar).await;
    assert_eq!(location(&response), "/login/account");
    jar.update(&response);
    jar
}

/// Starts `count` coupled logins of the provider's current subject; their refresh tokens.
async fn logins(fixture: &Fixture, count: usize) -> Vec<String> {
    let mut tokens = Vec::new();
    for _ in 0..count {
        let mut jar = Jar::default();
        sign_in(fixture, &mut jar).await;
        tokens.push(approve_and_exchange(&fixture.app, &jar).await);
    }
    tokens
}

async fn listed(fixture: &Fixture, username: &str) -> Vec<FamilySummary> {
    let runtime = fixture.state.oauth.as_ref().unwrap();
    runtime.logins("idp", username).await.unwrap()
}

/// How many of `tokens` still refresh. Each refresh rotates, so `tokens` are replaced
/// by their successors.
async fn refreshing(fixture: &Fixture, tokens: &mut [String]) -> usize {
    let mut live = 0;
    for token in tokens.iter_mut() {
        let (status, body) = refresh(&fixture.app, token).await;
        if status == StatusCode::OK {
            *token = body["refresh_token"].as_str().unwrap().into();
            live += 1;
        }
    }
    live
}

#[tokio::test]
async fn your_logins_are_listed_and_revoked_one_at_a_time_or_all_at_once() {
    let (fixture, _files) = offline_fixture(true).await;
    let mut tokens = logins(&fixture, 3).await;
    let mut jar = oidc_session(&fixture).await;
    let families = listed(&fixture, SUBJECT).await;
    assert_eq!(families.len(), 3);
    let response = get(&fixture.app, "/login/account", &jar).await;
    jar.update(&response);
    let html = text(response).await;
    assert!(html.contains("<h3 id=\"logins-title\">Your logins</h3>"));
    assert_eq!(html.matches("<h4>Desktop</h4>").count(), 3);
    assert_eq!(html.matches("<dd>Demo SSO</dd>").count(), 3);
    assert!(html.contains("<time datetime=\""));
    assert!(html.contains("Revoke all logins"));
    for family in &families {
        let reference = family_ref(&family.family_id);
        assert!(html.contains(&format!("name=\"login\" value=\"{reference}\"")));
        assert!(!html.contains(&family.family_id));
    }
    for token in &tokens {
        assert!(!html.contains(token.as_str()));
    }
    // One login: only that family ends, and its upstream grant is revoked.
    let csrf = hidden(&html, "csrf");
    let one = family_ref(&families[1].family_id);
    let fields = [("csrf", csrf.as_str()), ("login", one.as_str())];
    let response = post(&fixture, REVOKE, &jar, Some(ORIGIN), &fields).await;
    assert_eq!(location(&response), "/login/account?revoked");
    assert_eq!(revoked(&fixture, 1).await.len(), 1);
    assert_eq!(refreshing(&fixture, &mut tokens).await, 2);
    let remaining = listed(&fixture, SUBJECT).await;
    assert_eq!(remaining.len(), 2);
    assert!(
        remaining
            .iter()
            .all(|family| family.family_id != families[1].family_id)
    );
    let page = text(get(&fixture.app, "/login/account?revoked", &jar).await).await;
    assert!(page.contains("Revoked. An application whose login you revoked"));
    let html = text(get(&fixture.app, "/login/account", &jar).await).await;
    assert!(!html.contains("Revoked. An application"));
    // All of them.
    let csrf = hidden(&html, "csrf");
    let fields = [("csrf", csrf.as_str()), ("login", "all")];
    let response = post(&fixture, REVOKE, &jar, Some(ORIGIN), &fields).await;
    assert_eq!(location(&response), "/login/account?revoked");
    assert_eq!(revoked(&fixture, 3).await.len(), 3);
    assert_eq!(refreshing(&fixture, &mut tokens).await, 0);
    let html = text(get(&fixture.app, "/login/account", &jar).await).await;
    assert!(html.contains("No application is signed in."));
    assert!(!html.contains("Revoke all logins"));
}

#[tokio::test]
async fn logins_of_other_users_and_forged_forms_are_never_revoked() {
    let (fixture, _files) = offline_fixture(true).await;
    *fixture.idp.state.subject.lock().unwrap() = "other-subject".into();
    let mut theirs = logins(&fixture, 1).await;
    *fixture.idp.state.subject.lock().unwrap() = SUBJECT.into();
    let mut mine = logins(&fixture, 1).await;
    let mut jar = oidc_session(&fixture).await;
    let other = family_ref(&listed(&fixture, "other-subject").await[0].family_id);
    let html = text(get(&fixture.app, "/login/account", &jar).await).await;
    assert!(!html.contains(&other));
    let response = get(&fixture.app, "/login/account", &jar).await;
    jar.update(&response);
    let csrf = hidden(&text(response).await, "csrf");
    let token = csrf.as_str();
    let refused: [Refusal; 7] = [
        (
            None,
            &[("csrf", token), ("login", "all")],
            StatusCode::FORBIDDEN,
        ),
        (
            Some(ORIGIN),
            &[("csrf", "forged"), ("login", "all")],
            StatusCode::FORBIDDEN,
        ),
        (Some(ORIGIN), &[("csrf", token)], StatusCode::BAD_REQUEST),
        (
            Some(ORIGIN),
            &[("csrf", token), ("login", "ALL")],
            StatusCode::BAD_REQUEST,
        ),
        (
            Some(ORIGIN),
            &[("csrf", token), ("login", &other.to_uppercase())],
            StatusCode::BAD_REQUEST,
        ),
        (
            Some(ORIGIN),
            &[("csrf", token), ("login", &other[..11])],
            StatusCode::BAD_REQUEST,
        ),
        (
            Some(ORIGIN),
            &[("csrf", token), ("login", "all"), ("user", "x")],
            StatusCode::BAD_REQUEST,
        ),
    ];
    for (origin, fields, status) in refused {
        let response = post(&fixture, REVOKE, &jar, origin, fields).await;
        assert_eq!(response.status(), status, "{origin:?} {fields:?}");
        assert!(text(response).await.contains("Request not completed"));
    }
    // A forged reference to another user's login is accepted as a form, but matches
    // none of this user's logins.
    let fields = [("csrf", token), ("login", other.as_str())];
    let response = post(&fixture, REVOKE, &jar, Some(ORIGIN), &fields).await;
    assert_eq!(location(&response), "/login/account?revoked");
    assert_eq!(refreshing(&fixture, &mut theirs).await, 1);
    assert_eq!(refreshing(&fixture, &mut mine).await, 1);
    assert!(fixture.idp.state.revoked.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_store_failure_hides_only_the_logins() {
    let (fixture, _files) = offline_fixture(true).await;
    let runtime = fixture.state.oauth.as_ref().unwrap();
    let section = super::logins_section(&fixture.state, runtime, None, "csrf").into_string();
    assert!(section.contains("Your logins cannot be shown right now"));
    assert!(!section.contains("<form"));
}

#[tokio::test]
async fn without_refresh_tokens_the_account_page_lists_no_logins() {
    let fixture = fixture(|_| {}).await;
    let mut jar = signed_in(&fixture).await;
    let csrf = account_csrf(&fixture, &mut jar).await;
    let html = text(get(&fixture.app, "/login/account", &jar).await).await;
    assert!(!html.contains("Your logins"));
    let fields = [("csrf", csrf.as_str()), ("login", "all")];
    let response = post(&fixture, REVOKE, &jar, Some(ORIGIN), &fields).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

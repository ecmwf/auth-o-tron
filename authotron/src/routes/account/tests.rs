// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! The account page and its forms, through the application router.

use crate::routes::oidc_login::tests::{Fixture, Jar, ORIGIN, fixture, get, location, text};
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

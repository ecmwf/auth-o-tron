// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! OIDC sign-in routes against the in-process identity provider.

use crate::{
    config::ConfigV2,
    oidc::mock::{CLIENT_ID, CLIENT_SECRET, MockIdp, SUBJECT},
    state::AppState,
};
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use serde_json::{Value, json};
use std::{collections::HashMap, io::Write, sync::Arc};
use tower::ServiceExt;
use url::Url;

pub(super) const ORIGIN: &str = "https://login.example.test";

/// Cookies set by responses, sent back on later requests like a browser.
#[derive(Clone, Default)]
pub(super) struct Jar(pub(super) HashMap<String, String>);
impl Jar {
    pub(super) fn update(&mut self, response: &Response) {
        for value in response.headers().get_all(header::SET_COOKIE) {
            let cookie = cookie::Cookie::parse(value.to_str().unwrap()).unwrap();
            assert_eq!(cookie.secure(), Some(true));
            assert_eq!(cookie.http_only(), Some(true));
            if cookie.value().is_empty() {
                self.0.remove(cookie.name());
            } else {
                self.0.insert(cookie.name().into(), cookie.value().into());
            }
        }
    }
    pub(super) fn header(&self) -> String {
        self.0
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("; ")
    }
}

pub(super) struct Fixture {
    pub app: Router,
    pub state: AppState,
    pub idp: MockIdp,
    _secret: tempfile::NamedTempFile,
}

/// A password method and the `demo-sso` OIDC method; `edit` adjusts the JSON config.
pub(super) async fn fixture(edit: impl FnOnce(&mut Value)) -> Fixture {
    let idp = MockIdp::start().await;
    let mut secret = tempfile::NamedTempFile::new().unwrap();
    writeln!(secret, "{CLIENT_SECRET}").unwrap();
    let mut config = json!({
        "store": {"enabled": false}, "services": [], "augmenters": [],
        "providers": [{"type": "plain", "name": "basic", "realm": "local",
            "users": [{"username": "alice", "password": "fixture-only"}],
            "browser": {"id": "password", "label": "Password"}}],
        "server": {"port": 0}, "metrics": {"enabled": false},
        "jwt": {"iss": "fixture", "exp": 300, "secret": "fixture-only"},
        "logging": {"level": "warn", "format": "console"},
        "ui": {"enabled": true,
            "browser_session": {"public_origin": ORIGIN, "backend": {"type": "memory"}},
            "oidc": [{"id": "demo-sso", "label": "Demo SSO", "realm": "idp", "issuer": idp.issuer,
                "client_id": CLIENT_ID, "client_secret_file": secret.path(),
                "http_timeout_ms": 2000}]}
    });
    edit(&mut config);
    let config: ConfigV2 = serde_json::from_value(config).unwrap();
    let (app, state) = crate::startup::build_app(Arc::new(config)).await.unwrap();
    Fixture {
        app,
        state,
        idp,
        _secret: secret,
    }
}

pub(super) async fn get(app: &Router, target: &str, jar: &Jar) -> Response {
    app.clone()
        .oneshot(
            Request::get(target)
                .header(header::COOKIE, jar.header())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

pub(super) async fn text(response: Response) -> String {
    String::from_utf8(
        to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap()
}

pub(super) fn location(response: &Response) -> String {
    response.headers()[header::LOCATION]
        .to_str()
        .unwrap()
        .to_owned()
}

/// Path and query of a callback URL on [`ORIGIN`].
pub(super) fn local(callback: &str) -> String {
    callback
        .strip_prefix(ORIGIN)
        .expect("callback on the public origin")
        .to_owned()
}

/// Starts sign-in and returns the provider authorization URL.
pub(super) async fn start(fixture: &Fixture, jar: &mut Jar) -> Url {
    let response = get(&fixture.app, "/login/method/demo-sso", jar).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    jar.update(&response);
    Url::parse(&location(&response)).unwrap()
}

fn attempts(state: &AppState, outcome: &str, count: usize) -> bool {
    state.metrics.render().unwrap().contains(&format!(
        "authotron_browser_login_attempts_total{{flow=\"oidc\",method=\"demo-sso\",outcome=\"{outcome}\"}} {count}"
    ))
}

#[tokio::test]
async fn chooser_offers_oidc_methods_as_plain_navigation() {
    let fixture = fixture(|_| {}).await;
    let html = text(get(&fixture.app, "/login", &Jar::default()).await).await;
    assert!(
        html.contains("<a class=\"login-action\" href=\"/login/method/demo-sso\">Demo SSO</a>")
    );
    assert!(
        html.contains("href=\"/login/method/password\" data-login-dialog=\"method\">Password</a>")
    );
    assert!(oidc_up(&fixture.state, 1).await);
}

#[tokio::test]
async fn browser_sign_in_starts_a_session_for_the_provider_subject() {
    let fixture = fixture(|_| {}).await;
    let mut jar = Jar::default();
    let authorization = start(&fixture, &mut jar).await;
    let query: HashMap<String, String> = authorization.query_pairs().into_owned().collect();
    assert_eq!(
        query["redirect_uri"],
        format!("{ORIGIN}/login/method/demo-sso/callback")
    );
    assert_eq!(query["scope"], "openid");
    assert_eq!(query["code_challenge_method"], "S256");
    assert!(jar.0.contains_key("__Host-authotron_form"));
    let callback = local(&fixture.idp.authorize(&authorization));
    let response = get(&fixture.app, &callback, &jar).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&response), "/login/account");
    assert_eq!(
        response.headers()[header::CACHE_CONTROL].to_str().unwrap(),
        "no-store"
    );
    jar.update(&response);
    let account = text(get(&fixture.app, "/login/account", &jar).await).await;
    assert!(account.contains(SUBJECT));
    assert!(account.contains("<dt>Signed in as</dt><dd>alice</dd>"));
    assert!(account.contains("<dd>idp</dd>"));
    assert!(account.contains("alice@example.org"));
    assert!(attempts(&fixture.state, "success", 1));
    // The state is single-use.
    let replay = get(&fixture.app, &callback, &jar).await;
    assert_eq!(replay.status(), StatusCode::BAD_REQUEST);
    assert!(text(replay).await.contains("Sign-in expired"));
}

#[tokio::test]
async fn the_account_page_escapes_the_display_name_and_falls_back_to_the_username() {
    let fixture = fixture(|_| {}).await;
    for (claim, shown) in [
        (json!("<b>Ada</b>"), "&lt;b&gt;Ada&lt;/b&gt;".to_owned()),
        (json!("ada\u{1b}[31m"), SUBJECT.to_owned()),
        (json!("a".repeat(65)), SUBJECT.to_owned()),
    ] {
        *fixture.idp.state.claims.lock().unwrap() = json!({"preferred_username": claim});
        let mut jar = Jar::default();
        let authorization = start(&fixture, &mut jar).await;
        let callback = local(&fixture.idp.authorize(&authorization));
        let response = get(&fixture.app, &callback, &jar).await;
        assert_eq!(location(&response), "/login/account");
        jar.update(&response);
        let account = text(get(&fixture.app, "/login/account", &jar).await).await;
        assert!(
            account.contains(&format!("<dt>Signed in as</dt><dd>{shown}</dd>")),
            "{claim}"
        );
        assert!(account.contains(&format!("<dt>Username</dt><dd>{SUBJECT}</dd>")));
        assert!(!account.contains("<b>Ada</b>"));
    }
}

#[tokio::test]
async fn callbacks_complete_only_in_the_browser_that_started_them() {
    let fixture = fixture(|_| {}).await;
    let mut jar = Jar::default();
    let authorization = start(&fixture, &mut jar).await;
    let callback = local(&fixture.idp.authorize(&authorization));
    let mut other = Jar::default();
    start(&fixture, &mut other).await;
    for (cookies, target) in [
        (&other, callback.clone()),
        (&Jar::default(), callback.clone()),
        (&jar, callback.replace("state=", "state=x")),
        (&jar, "/login/method/demo-sso/callback".into()),
        (
            &jar,
            "/login/method/demo-sso/callback?code=a&error=b&state=c".into(),
        ),
    ] {
        let response = get(&fixture.app, &target, cookies).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{target}");
        assert!(text(response).await.contains("Sign-in expired"));
    }
    // Rejected attempts leave the browser's state usable.
    let response = get(&fixture.app, &callback, &jar).await;
    assert_eq!(location(&response), "/login/account");
    assert!(attempts(&fixture.state, "malformed", 2));
    assert!(attempts(&fixture.state, "csrf", 3));
}

#[tokio::test]
async fn provider_errors_and_failed_verification_show_generic_pages() {
    let fixture = fixture(|_| {}).await;
    let mut jar = Jar::default();
    let authorization = start(&fixture, &mut jar).await;
    let denied = local(&fixture.idp.deny(&authorization));
    let response = get(&fixture.app, &denied, &jar).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let page = text(response).await;
    assert!(page.contains("Sign-in not completed"));
    assert!(!page.contains("Declined") && !page.contains("access_denied"));
    assert!(attempts(&fixture.state, "idp_error", 1));
    assert_eq!(
        get(&fixture.app, &denied, &jar).await.status(),
        StatusCode::BAD_REQUEST
    );

    let mixed_up = {
        let authorization = start(&fixture, &mut jar).await;
        local(&fixture.idp.authorize(&authorization)).replace(
            &url::form_urlencoded::byte_serialize(fixture.idp.issuer.as_bytes())
                .collect::<String>(),
            "https%3A%2F%2Fattacker.example.org",
        )
    };
    let response = get(&fixture.app, &mixed_up, &jar).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(text(response).await.contains("could not be verified"));

    for (setup, status, page) in [
        (
            Some((500, json!({}))),
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily unavailable",
        ),
        (
            Some((401, json!({"error": "invalid_client"}))),
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily unavailable",
        ),
        (None, StatusCode::BAD_REQUEST, "could not be verified"),
    ] {
        *fixture.idp.state.token_answer.lock().unwrap() = setup.clone();
        if setup.is_none() {
            *fixture.idp.state.claims.lock().unwrap() = json!({"nonce": "replayed"});
        }
        let authorization = start(&fixture, &mut jar).await;
        let callback = local(&fixture.idp.authorize(&authorization));
        let response = get(&fixture.app, &callback, &jar).await;
        assert_eq!(response.status(), status);
        let body = text(response).await;
        assert!(body.contains(page), "{body}");
        assert!(!body.contains("mock-access-token") && !body.contains("invalid_client"));
    }
    *fixture.idp.state.claims.lock().unwrap() = json!({"sub": "s".repeat(129)});
    let authorization = start(&fixture, &mut jar).await;
    let callback = local(&fixture.idp.authorize(&authorization));
    let response = get(&fixture.app, &callback, &jar).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(text(response).await.contains("not permitted"));
    assert!(attempts(&fixture.state, "idp_unavailable", 2));
    assert!(attempts(&fixture.state, "rejected", 3));
}

#[tokio::test]
async fn unreachable_providers_are_refused_and_shown_unavailable() {
    let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let issuer = format!("http://{}/realms/test", closed.local_addr().unwrap());
    drop(closed);
    let fixture = fixture(|config| config["ui"]["oidc"][0]["issuer"] = json!(issuer)).await;
    let response = get(&fixture.app, "/login/method/demo-sso", &Jar::default()).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .next()
            .is_none()
    );
    assert!(text(response).await.contains("cannot be reached"));
    let html = text(get(&fixture.app, "/login", &Jar::default()).await).await;
    assert!(html.contains(
        "<button class=\"login-action\" type=\"button\" disabled>Demo SSO (temporarily unavailable)</button>"
    ));
    assert!(!html.contains("href=\"/login/method/demo-sso\""));
    assert!(oidc_up(&fixture.state, 0).await);
}

/// Waits for the discovery task to report `authotron_oidc_up` as `value`.
async fn oidc_up(state: &AppState, value: u8) -> bool {
    let line = format!("authotron_oidc_up{{method=\"demo-sso\"}} {value}");
    for _ in 0..200 {
        if state.metrics.render().unwrap().contains(&line) {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    false
}

#[tokio::test]
async fn credential_and_callback_routes_stay_separate() {
    let fixture = fixture(|_| {}).await;
    let jar = Jar::default();
    let post = fixture
        .app
        .clone()
        .oneshot(
            Request::post("/login/method/demo-sso")
                .header(header::ORIGIN, ORIGIN)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from("username=alice&password=fixture-only&csrf=x"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(post.status(), StatusCode::NOT_FOUND);
    for target in [
        "/login/method/password/callback?code=a&state=s",
        "/login/method/unknown/callback?code=a&state=s",
        "/login/method/demo%2Dsso/callback?code=a&state=s",
        "/login/method/demo-sso/callback/?code=a&state=s",
    ] {
        assert_eq!(
            get(&fixture.app, target, &jar).await.status(),
            StatusCode::NOT_FOUND,
            "{target}"
        );
    }
}

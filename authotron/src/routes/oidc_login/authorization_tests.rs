// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! OIDC sign-in completing OAuth authorization requests.

use super::tests::{Fixture, Jar, ORIGIN, fixture, get, local, location, start, text};
use crate::oidc::mock::{SUBJECT, rsa_key};
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
    response::Response,
};
use rsa::pkcs8::{EncodePrivateKey, LineEnding};
use serde_json::{Value, json};
use std::io::Write;
use tower::ServiceExt;
use url::Url;

pub(super) const CLIENT_CALLBACK: &str = "http://127.0.0.1:49152/callback";
pub(super) const RESOURCE: &str = "https://mcp.example.test/mcp";
pub(super) const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

/// The OIDC method as the only sign-in method of an OAuth server whose `read` scope
/// needs the `reader` role, granted only through the method's `role_map` from the
/// provider role `mcp-demo`. `edit` adjusts the JSON config afterwards.
pub(in crate::routes) async fn authorization_fixture_with(
    edit: impl FnOnce(&mut Value),
) -> (Fixture, tempfile::NamedTempFile) {
    let mut key = tempfile::NamedTempFile::new().unwrap();
    key.write_all(rsa_key(0).to_pkcs8_pem(LineEnding::LF).unwrap().as_bytes())
        .unwrap();
    let path = key.path().to_owned();
    let fixture = fixture(|config| {
        config["providers"] = json!([]);
        let method = &mut config["ui"]["oidc"][0];
        method["roles_claim"] = json!("realm_access.roles");
        method["role_map"] = json!({"mcp-demo": "reader"});
        config["oauth"] = json!({
            "enabled": true, "issuer": format!("{ORIGIN}/"),
            "signing": {"active_kid": "oauth", "keys": [{"kid": "oauth", "private_key_file": path}]},
            "clients": [{"client_id": "desktop", "display_name": "Desktop", "application_type": "native",
                "redirect_uris": [CLIENT_CALLBACK], "resources": [{"resource": RESOURCE, "scopes": ["read"]}]}],
            "resources": [{"resource": RESOURCE, "allowed_realms": ["idp"],
                "scopes": [{"name": "read", "required_roles": ["reader"]}]}]
        });
        edit(config);
    })
    .await;
    (fixture, key)
}

async fn authorization_fixture() -> (Fixture, tempfile::NamedTempFile) {
    authorization_fixture_with(|_| {}).await
}

/// Starts an authorization request from the client and returns the browser's cookies.
pub(super) async fn authorize(app: &Router) -> Jar {
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    for (name, value) in [
        ("client_id", "desktop"),
        ("redirect_uri", CLIENT_CALLBACK),
        ("response_type", "code"),
        ("resource", RESOURCE),
        ("scope", "read"),
        ("state", "client-state"),
        ("code_challenge", CHALLENGE),
        ("code_challenge_method", "S256"),
    ] {
        query.append_pair(name, value);
    }
    let mut jar = Jar::default();
    let response = get(app, &format!("/oauth/authorize?{}", query.finish()), &jar).await;
    assert_eq!(location(&response), "/login");
    jar.update(&response);
    jar
}

pub(super) async fn send(app: &Router, request: Request<Body>) -> Response {
    app.clone().oneshot(request).await.unwrap()
}

pub(super) fn form(fields: &[(&str, &str)]) -> Body {
    let mut form = url::form_urlencoded::Serializer::new(String::new());
    for (name, value) in fields {
        form.append_pair(name, value);
    }
    Body::from(form.finish())
}

pub(super) fn hidden(html: &str, name: &str) -> String {
    html.split(&format!("name=\"{name}\" value=\""))
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .into()
}

#[tokio::test]
async fn oidc_sign_in_continues_the_authorization_to_consent_and_tokens() {
    let (fixture, _key) = authorization_fixture().await;
    let mut jar = authorize(&fixture.app).await;
    let chooser = text(get(&fixture.app, "/login", &jar).await).await;
    assert!(chooser.contains("href=\"/login/method/demo-sso\">Demo SSO</a>"));
    let callback = local(&fixture.idp.authorize(&start(&fixture, &mut jar).await));
    let response = get(&fixture.app, &callback, &jar).await;
    assert_eq!(location(&response), "/oauth/continue");
    jar.update(&response);
    let consent = text(get(&fixture.app, "/oauth/continue", &jar).await).await;
    assert!(consent.contains("<p>Signed in as alice</p>"));
    let response = send(
        &fixture.app,
        Request::post("/oauth/consent")
            .header(header::COOKIE, jar.header())
            .header(header::ORIGIN, ORIGIN)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(form(&[
                ("csrf", &hidden(&consent, "csrf")),
                ("oauth_transaction", &hidden(&consent, "oauth_transaction")),
                ("decision", "approve"),
            ]))
            .unwrap(),
    )
    .await;
    let redirect = Url::parse(&location(&response)).unwrap();
    let code = redirect
        .query_pairs()
        .find(|(name, _)| name == "code")
        .unwrap()
        .1
        .into_owned();
    let response = send(
        &fixture.app,
        Request::post("/oauth/token")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(form(&[
                ("grant_type", "authorization_code"),
                ("client_id", "desktop"),
                ("code", &code),
                ("redirect_uri", CLIENT_CALLBACK),
                ("resource", RESOURCE),
                ("code_verifier", VERIFIER),
            ]))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let tokens: Value = serde_json::from_str(&text(response).await).unwrap();
    let access = tokens["access_token"].as_str().unwrap();
    let claims: Value = serde_json::from_slice(
        &base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            access.split('.').nth(1).unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(claims["scope"], "read");
    assert_eq!(claims["client_id"], "desktop");
    assert_eq!(claims["roles"], json!(["reader"]));
    assert!(
        claims["sub"]
            .as_str()
            .unwrap()
            .starts_with("urn:authotron:subject:")
    );
    // The display name stays on the consent page and out of the token.
    assert!(!claims.to_string().contains("alice"));
}

#[tokio::test]
async fn consent_escapes_the_display_name_and_falls_back_to_the_username() {
    let (fixture, _key) = authorization_fixture().await;
    for (claim, shown) in [
        (json!("<b>Ada</b>"), "&lt;b&gt;Ada&lt;/b&gt;".to_owned()),
        (json!("ada\u{7f}"), SUBJECT.to_owned()),
        (Value::Null, SUBJECT.to_owned()),
    ] {
        *fixture.idp.state.claims.lock().unwrap() = json!({
            "preferred_username": claim, "realm_access": {"roles": ["mcp-demo"]}
        });
        let mut jar = authorize(&fixture.app).await;
        let callback = local(&fixture.idp.authorize(&start(&fixture, &mut jar).await));
        let response = get(&fixture.app, &callback, &jar).await;
        assert_eq!(location(&response), "/oauth/continue");
        jar.update(&response);
        let consent = text(get(&fixture.app, "/oauth/continue", &jar).await).await;
        assert!(
            consent.contains(&format!("<p>Signed in as {shown}</p>")),
            "{claim}"
        );
    }
}

#[tokio::test]
async fn identities_without_the_mapped_role_end_the_authorization_with_access_denied() {
    let (fixture, _key) = authorization_fixture().await;
    *fixture.idp.state.claims.lock().unwrap() = json!({"realm_access": {"roles": ["other"]}});
    let mut jar = authorize(&fixture.app).await;
    let callback = local(&fixture.idp.authorize(&start(&fixture, &mut jar).await));
    let response = get(&fixture.app, &callback, &jar).await;
    let redirect = location(&response);
    assert!(
        redirect.starts_with(&format!(
            "{CLIENT_CALLBACK}?error=access_denied&state=client-state"
        )),
        "{redirect}"
    );
}

#[tokio::test]
async fn states_complete_only_the_flow_they_were_started_for() {
    let (fixture, _key) = authorization_fixture().await;
    let mut jar = authorize(&fixture.app).await;
    let callback = local(&fixture.idp.authorize(&start(&fixture, &mut jar).await));
    // Without its transaction cookies the state cannot become a browser session.
    let mut browser_only = jar.clone();
    browser_only
        .0
        .retain(|name, _| name == "__Host-authotron_form");
    let response = get(&fixture.app, &callback, &browser_only).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(text(response).await.contains("Sign-in expired"));
    // A browser-session state from the same browser cannot complete the authorization.
    let browser_callback = local(
        &fixture
            .idp
            .authorize(&start(&fixture, &mut browser_only).await),
    );
    assert_eq!(
        browser_only.0["__Host-authotron_form"],
        jar.0["__Host-authotron_form"]
    );
    assert_eq!(
        get(&fixture.app, &browser_callback, &jar).await.status(),
        StatusCode::BAD_REQUEST
    );
    // The rejected attempts did not consume the authorization's state.
    let response = get(&fixture.app, &callback, &jar).await;
    assert_eq!(location(&response), "/oauth/continue");
}

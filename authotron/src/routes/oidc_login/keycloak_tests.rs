// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! Interoperability with a disposable Keycloak: discovery, the code flow with PKCE,
//! nonce and RFC 9207 `iss`, client authentication, signing keys and role mapping, and
//! offline access coupled to OAuth refresh families. The realm mirrors the playground
//! client registration: a confidential client with the `basic`, `profile` and `email`
//! scopes and without full scope (a realm role reaches its tokens only through a scope
//! mapping, while `offline_access` comes with its client scope), a fixed user id, so
//! `sub` is stable, strict refresh-token rotation, and a service-account client that
//! administers users.

use super::{
    authorization_tests::{CLIENT_CALLBACK, RESOURCE, authorize},
    offline_tests::{approve_and_exchange, post, refresh},
    tests::{Jar, ORIGIN, get, local, location, text},
};
use crate::{config::ConfigV2, oidc::mock::rsa_key, state::AppState};
use axum::{Router, http::StatusCode};
use base64::{Engine, engine::general_purpose::STANDARD};
use rsa::pkcs8::{EncodePrivateKey, LineEnding};
use serde_json::{Value, json};
use std::{
    io::Write,
    os::unix::fs::PermissionsExt,
    process::Command,
    sync::Arc,
    time::{Duration, Instant},
};

/// Keycloak 26 multi-architecture index; `examples/browser-sso/render_sso.py` pins the
/// same digest for the playground identity provider.
const KEYCLOAK_IMAGE: &str = "quay.io/keycloak/keycloak@sha256:27b3230fbabb8c9ff3c66c864cf09dcd8a41aca82e5100679d109ef0eeb05741";
const REALM: &str = "authotron-test";
/// Disposable fixture credentials; they protect nothing.
const CLIENT_SECRET: &str = "fixture-client-secret";
const ADMIN_SECRET: &str = "fixture-admin-secret";
const PASSWORD: &str = "fixture-password";
const USER_ID: &str = "6f0c2b8e-4d55-4f3a-9a4c-2f1b8d7e5a01";

struct Container(String);
impl Drop for Container {
    fn drop(&mut self) {
        let _ = Command::new("docker").args(["rm", "-f", &self.0]).output();
    }
}

fn docker(args: &[&str]) -> String {
    let output = Command::new("docker")
        .args(args)
        .output()
        .expect("Docker CLI required for the disposable Keycloak test");
    assert!(output.status.success(), "Docker fixture command failed");
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

fn realm() -> Value {
    json!({
        "realm": REALM, "enabled": true, "registrationAllowed": false,
        "accessTokenLifespan": 60, "revokeRefreshToken": true, "refreshTokenMaxReuse": 0,
        "roles": {"realm": [{"name": "mcp-demo"}]},
        "scopeMappings": [{"client": "authotron", "roles": ["mcp-demo"]}],
        "clients": [{
            "clientId": "authotron", "enabled": true, "protocol": "openid-connect",
            "publicClient": false, "secret": CLIENT_SECRET, "fullScopeAllowed": false,
            "standardFlowEnabled": true, "directAccessGrantsEnabled": false,
            "implicitFlowEnabled": false, "serviceAccountsEnabled": false,
            "consentRequired": false,
            "redirectUris": [format!("{ORIGIN}/login/method/keycloak/callback")],
            "webOrigins": [],
            "defaultClientScopes": ["basic", "profile", "email"],
            "optionalClientScopes": ["offline_access"],
            "attributes": {"pkce.code.challenge.method": "S256"},
            "protocolMappers": [{
                "name": "realm-roles-in-id-token", "protocol": "openid-connect",
                "protocolMapper": "oidc-usermodel-realm-role-mapper",
                "config": {"claim.name": "realm_access.roles", "jsonType.label": "String",
                    "multivalued": "true", "id.token.claim": "true",
                    "access.token.claim": "false", "userinfo.token.claim": "false"}
            }]
        }, {
            "clientId": "authotron-e2e-admin", "enabled": true, "protocol": "openid-connect",
            "publicClient": false, "secret": ADMIN_SECRET, "standardFlowEnabled": false,
            "directAccessGrantsEnabled": false, "serviceAccountsEnabled": true
        }],
        "users": [{
            "id": USER_ID, "username": "alice", "enabled": true,
            "firstName": "Alice", "lastName": "Demo",
            "email": "alice@example.org", "emailVerified": true,
            "realmRoles": [format!("default-roles-{REALM}"), "mcp-demo", "offline_access"],
            "credentials": [{"type": "password", "value": PASSWORD, "temporary": false}]
        }, {
            "username": "service-account-authotron-e2e-admin", "enabled": true,
            "serviceAccountClientId": "authotron-e2e-admin",
            "clientRoles": {"realm-management": ["manage-users", "view-users", "view-clients"]}
        }]
    })
}

/// Cookies a provider sets on the browser, kept separately from Auth-O-Tron's.
#[derive(Default)]
struct ProviderCookies(Vec<(String, String)>);
impl ProviderCookies {
    fn update(&mut self, response: &reqwest::Response) {
        for value in response.headers().get_all(reqwest::header::SET_COOKIE) {
            let cookie = cookie::Cookie::parse(value.to_str().unwrap().to_owned()).unwrap();
            self.0.retain(|(name, _)| name != cookie.name());
            if !cookie.value().is_empty() {
                self.0.push((cookie.name().into(), cookie.value().into()));
            }
        }
    }
    fn header(&self) -> String {
        self.0
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("; ")
    }
}

/// Action URL of Keycloak's username/password form.
/// Valid: `<form id="kc-form-login" ... action="http://h/a?x=1&amp;y=2">` gives
/// `http://h/a?x=1&y=2`. Invalid: a page without `kc-form-login`.
fn login_action(html: &str) -> Option<String> {
    let form = &html[html.find("id=\"kc-form-login\"")?..];
    let action = &form[form.find("action=\"")? + "action=\"".len()..];
    Some(action[..action.find('"')?].replace("&amp;", "&"))
}

/// Signs in at Keycloak as the browser would and returns the callback URL it redirects to.
async fn provider_sign_in(authorization: &str) -> String {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let mut cookies = ProviderCookies::default();
    let page = client.get(authorization).send().await.unwrap();
    assert_eq!(page.status(), 200, "Keycloak login page");
    cookies.update(&page);
    let action = login_action(&page.text().await.unwrap()).expect("Keycloak login form");
    let submitted = client
        .post(action)
        .header(reqwest::header::COOKIE, cookies.header())
        .form(&[
            ("username", "alice"),
            ("password", PASSWORD),
            ("credentialId", ""),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(submitted.status(), 302, "Keycloak accepts the credentials");
    submitted.headers()[reqwest::header::LOCATION]
        .to_str()
        .unwrap()
        .to_owned()
}

/// Run explicitly: cargo test -p authotron disposable -- --ignored --test-threads=1.
#[tokio::test]
#[ignore = "requires Docker; pulls a pinned Keycloak image and removes its own container"]
async fn disposable_keycloak_signs_in_through_an_oidc_method() {
    let import = tempfile::tempdir().unwrap();
    std::fs::set_permissions(import.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let realm_file = import.path().join(format!("{REALM}-realm.json"));
    std::fs::write(&realm_file, realm().to_string()).unwrap();
    std::fs::set_permissions(&realm_file, std::fs::Permissions::from_mode(0o644)).unwrap();
    let mount = format!(
        "{}:/opt/keycloak/data/import:ro",
        import.path().to_str().unwrap()
    );
    let container = Container(docker(&[
        "run",
        "--rm",
        "-d",
        "-p",
        "127.0.0.1::8080",
        "-v",
        &mount,
        KEYCLOAK_IMAGE,
        "start-dev",
        "--import-realm",
    ]));
    let address = docker(&["port", &container.0, "8080/tcp"]);
    let issuer = format!("http://{address}/realms/{REALM}");
    let deadline = Instant::now() + Duration::from_secs(240);
    let discovery = format!("{issuer}/.well-known/openid-configuration");
    loop {
        if reqwest::get(&discovery)
            .await
            .is_ok_and(|response| response.status() == 200)
        {
            break;
        }
        assert!(Instant::now() < deadline, "Keycloak did not become ready");
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    let mut secret = tempfile::NamedTempFile::new().unwrap();
    writeln!(secret, "{CLIENT_SECRET}").unwrap();
    let mut signing = tempfile::NamedTempFile::new().unwrap();
    let pem = rsa_key(0).to_pkcs8_pem(LineEnding::LF).unwrap();
    signing.write_all(pem.as_bytes()).unwrap();
    let mut sealing = tempfile::NamedTempFile::new().unwrap();
    writeln!(sealing, "{}", STANDARD.encode([3u8; 32])).unwrap();
    let config: ConfigV2 = serde_json::from_value(json!({
        "store": {"enabled": false}, "services": [], "augmenters": [], "providers": [],
        "server": {"port": 0}, "metrics": {"enabled": false},
        "jwt": {"iss": "fixture", "exp": 300, "secret": "fixture-only"},
        "logging": {"level": "warn", "format": "console"},
        "ui": {"enabled": true,
            "browser_session": {"public_origin": ORIGIN, "backend": {"type": "memory"}},
            "oidc": [{"id": "keycloak", "label": "Keycloak", "realm": "keycloak-test",
                "issuer": issuer, "client_id": "authotron",
                "client_secret_file": secret.path(), "scopes": ["profile", "email"],
                "roles_claim": "realm_access.roles", "role_map": {"mcp-demo": "reader"},
                "max_authentication_age_seconds": 300, "offline_access": true}]},
        "oauth": {"enabled": true, "issuer": format!("{ORIGIN}/"),
            "signing": {"active_kid": "oauth", "keys": [{"kid": "oauth", "private_key_file": signing.path()}]},
            "upstream_token_encryption": {"active_kid": "u1", "keys": [{"kid": "u1", "key_file": sealing.path()}]},
            "clients": [{"client_id": "desktop", "display_name": "Desktop", "application_type": "native",
                "redirect_uris": [CLIENT_CALLBACK], "resources": [{"resource": RESOURCE, "scopes": ["read"]}],
                "refresh_tokens": {"enabled": true, "upstream_offline_access": true}}],
            "resources": [{"resource": RESOURCE, "allowed_realms": ["keycloak-test"],
                "scopes": [{"name": "read", "required_roles": ["reader"]}]}]}
    }))
    .unwrap();
    let (app, state) = crate::startup::build_app(Arc::new(config)).await.unwrap();

    let mut jar = Jar::default();
    let started = get(&app, "/login/method/keycloak", &jar).await;
    assert_eq!(started.status(), 303);
    jar.update(&started);
    let callback = provider_sign_in(&location(&started)).await;
    assert!(callback.contains("iss="), "Keycloak sends RFC 9207 iss");
    let finished = get(&app, &local(&callback), &jar).await;
    assert_eq!(location(&finished), "/login/account");
    jar.update(&finished);
    let account = text(get(&app, "/login/account", &jar).await).await;
    assert!(account.contains(USER_ID), "username is the stable subject");
    assert!(account.contains("<dd>keycloak-test</dd>"));
    assert!(account.contains("<li>reader</li>"));
    assert!(!account.contains("mcp-demo"));
    assert!(account.contains("alice@example.org"));
    // The code is single-use at Keycloak and the state at Auth-O-Tron.
    assert_eq!(get(&app, &local(&callback), &jar).await.status(), 400);
    offline_access(&app, &state, &address).await;
}

/// An OAuth sign-in with `offline_access`, then refreshes coupled to Keycloak's offline
/// session: strict rotation, a disabled account, and revocation by the client.
async fn offline_access(app: &Router, state: &AppState, address: &str) {
    let admin = Admin::new(address).await;
    let first = oauth_sign_in(app).await;
    assert_eq!(admin.offline_sessions().await, 1);
    let (status, tokens) = refresh(app, &first).await;
    assert_eq!(status, StatusCode::OK);
    let second = tokens["refresh_token"].as_str().unwrap().to_owned();
    assert_eq!(upstream_events(state, "refreshed"), 1);
    assert_eq!(upstream_events(state, "rotated"), 1);
    // Keycloak refuses a disabled account's offline token: the family ends with it.
    admin.set_enabled(false).await;
    let (status, error) = refresh(app, &second).await;
    assert_eq!(
        (status, error["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_grant"))
    );
    assert_eq!(upstream_events(state, "invalid_grant"), 1);
    assert_eq!(refresh(app, &second).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(upstream_events(state, "invalid_grant"), 1);
    // The refused token is revoked as well. Keycloak accepts that for the disabled
    // account and ends its offline session, which would otherwise outlive re-enabling.
    no_offline_session(&admin).await;
    assert_eq!(upstream_events(state, "revocation_sent"), 1);
    admin.set_enabled(true).await;
    assert_eq!(admin.offline_sessions().await, 0);
    // Revoking at Auth-O-Tron ends the new offline session at Keycloak too.
    let token = oauth_sign_in(app).await;
    assert_eq!(admin.offline_sessions().await, 1);
    let (status, _) = post(
        app,
        "/oauth/revoke",
        &[("token", &token), ("client_id", "desktop")],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    no_offline_session(&admin).await;
    assert_eq!(upstream_events(state, "revocation_sent"), 2);
}

/// Waits until the queued revocation has ended alice's offline sessions.
async fn no_offline_session(admin: &Admin) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while admin.offline_sessions().await > 0 {
        assert!(
            Instant::now() < deadline,
            "Keycloak offline session not revoked"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Authorizes `desktop`, signs in at Keycloak, approves and returns the refresh token.
async fn oauth_sign_in(app: &Router) -> String {
    let mut jar = authorize(app).await;
    let started = get(app, "/login/method/keycloak", &jar).await;
    jar.update(&started);
    assert!(location(&started).contains("offline_access"));
    let callback = provider_sign_in(&location(&started)).await;
    let finished = get(app, &local(&callback), &jar).await;
    assert_eq!(location(&finished), "/oauth/continue");
    jar.update(&finished);
    approve_and_exchange(app, &jar).await
}

fn upstream_events(state: &AppState, event: &str) -> u64 {
    let line = format!("authotron_oauth_upstream_tokens_total{{event=\"{event}\"}} ");
    let output = state.metrics.render().unwrap();
    output
        .lines()
        .find_map(|candidate| candidate.strip_prefix(&line))
        .unwrap()
        .parse()
        .unwrap()
}

/// Keycloak's admin API through the `authotron-e2e-admin` service account.
struct Admin {
    client: reqwest::Client,
    base: String,
    token: String,
}
impl Admin {
    async fn new(address: &str) -> Self {
        let client = reqwest::Client::new();
        let token: Value = client
            .post(format!(
                "http://{address}/realms/{REALM}/protocol/openid-connect/token"
            ))
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", "authotron-e2e-admin"),
                ("client_secret", ADMIN_SECRET),
            ])
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        Self {
            client,
            base: format!("http://{address}/admin/realms/{REALM}"),
            token: token["access_token"].as_str().unwrap().to_owned(),
        }
    }
    async fn set_enabled(&self, enabled: bool) {
        let response = self
            .client
            .put(format!("{}/users/{USER_ID}", self.base))
            .bearer_auth(&self.token)
            .json(&json!({"enabled": enabled}))
            .send()
            .await
            .unwrap();
        assert!(response.status().is_success(), "Keycloak updates the user");
    }
    /// Offline sessions of the user for the `authotron` client.
    async fn offline_sessions(&self) -> usize {
        let get = |url: String| {
            let request = self.client.get(url).bearer_auth(&self.token);
            async move { request.send().await.unwrap().json::<Value>().await.unwrap() }
        };
        let clients = get(format!("{}/clients?clientId=authotron", self.base)).await;
        let id = clients[0]["id"].as_str().unwrap();
        let sessions = get(format!(
            "{}/users/{USER_ID}/offline-sessions/{id}",
            self.base
        ))
        .await;
        sessions.as_array().unwrap().len()
    }
}

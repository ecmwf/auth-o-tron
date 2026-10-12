//! HTTP behaviour of the `refresh_token` grant and RFC 7009 revocation.

use authotron::{config::ConfigV2, startup, state::AppState};
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use cookie::Cookie;
use rsa::{
    RsaPrivateKey,
    pkcs8::{EncodePrivateKey, LineEnding},
    rand_core::OsRng,
};
use serde_json::{Value, json};
use std::{collections::HashMap, io::Write, sync::Arc};
use tower::ServiceExt;

const ORIGIN: &str = "https://login.example.test";
const ISSUER: &str = "https://login.example.test/";
const RESOURCE: &str = "https://mcp.example.test/mcp";
const CALLBACK: &str = "http://127.0.0.1:49152/callback";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

/// The provider grants `alice` only `unrelated`; `reader` comes from the augmenter, so a
/// successful refresh proves augmentation re-ran from provider roles.
fn fixture() -> (tempfile::NamedTempFile, ConfigV2) {
    let pem = RsaPrivateKey::new(&mut OsRng, 2048)
        .unwrap()
        .to_pkcs8_pem(LineEnding::LF)
        .unwrap();
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(pem.as_bytes()).unwrap();
    let client = |id: &str| {
        json!({"client_id": id, "display_name": id, "application_type": "native", "redirect_uris": [CALLBACK],
        "resources": [{"resource": RESOURCE, "scopes": ["read", "list"]}],
        "refresh_tokens": {"enabled": true, "idle_ttl_seconds": 600, "absolute_ttl_seconds": 3600}})
    };
    let config = serde_json::from_value(json!({
        "store": {"enabled": false}, "services": [],
        "providers": [{"type": "plain", "name": "basic", "realm": "local", "users": [{"username": "alice", "password": "public-fixture", "roles": ["unrelated"]}], "browser": {"id": "password", "label": "Password"}}],
        "augmenters": [{"type": "plain", "name": "reader", "realm": "local", "roles": {"reader": ["alice"]}}],
        "server": {"host": "127.0.0.1", "port": 0}, "metrics": {"enabled": false},
        "jwt": {"iss": "legacy", "exp": 300, "secret": "public-legacy-only"}, "logging": {"level": "warn", "format": "console"},
        "ui": {"enabled": true, "browser_session": {"public_origin": ORIGIN, "backend": {"type": "memory"}}},
        "oauth": {"enabled": true, "issuer": ISSUER, "signing": {"active_kid": "k", "keys": [{"kid": "k", "private_key_file": file.path()}]},
            "clients": [client("desktop"), client("other")],
            "resources": [{"resource": RESOURCE, "allowed_realms": ["local"], "scopes": [{"name": "read", "required_roles": ["reader"]}, {"name": "list", "required_roles": []}]}]}
    }))
    .unwrap();
    (file, config)
}

#[derive(Default)]
struct Jar(HashMap<String, String>);
impl Jar {
    fn update(&mut self, response: &Response) {
        for value in response.headers().get_all(header::SET_COOKIE) {
            let cookie = Cookie::parse(value.to_str().unwrap()).unwrap();
            if cookie.value().is_empty() {
                self.0.remove(cookie.name());
            } else {
                self.0.insert(cookie.name().into(), cookie.value().into());
            }
        }
    }
    fn header(&self) -> String {
        let pairs: Vec<_> = self.0.iter().map(|(n, v)| format!("{n}={v}")).collect();
        pairs.join("; ")
    }
}
fn encoded(fields: &[(&str, &str)]) -> String {
    let mut form = url::form_urlencoded::Serializer::new(String::new());
    for (name, value) in fields {
        form.append_pair(name, value);
    }
    form.finish()
}
async fn send(app: &Router, request: Request<Body>) -> Response {
    app.clone().oneshot(request).await.unwrap()
}
async fn get(app: &Router, path: &str, jar: &Jar) -> Response {
    let request = Request::get(path).header(header::COOKIE, jar.header());
    send(app, request.body(Body::empty()).unwrap()).await
}
async fn post(app: &Router, path: &str, jar: &Jar, fields: &[(&str, &str)]) -> Response {
    let request = Request::post(path)
        .header(header::COOKIE, jar.header())
        .header(header::ORIGIN, ORIGIN)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    send(app, request.body(Body::from(encoded(fields))).unwrap()).await
}
async fn text(response: Response) -> String {
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}
fn hidden(html: &str, name: &str) -> String {
    let rest = html
        .split(&format!("name=\"{name}\" value=\""))
        .nth(1)
        .unwrap();
    rest.split('"').next().unwrap().into()
}

/// Full browser authorization for `client`, returning the token-endpoint JSON.
async fn authorize(app: &Router, client: &str) -> Value {
    let mut jar = Jar::default();
    let query = encoded(&[
        ("client_id", client),
        ("redirect_uri", CALLBACK),
        ("response_type", "code"),
        ("resource", RESOURCE),
        ("scope", "read list"),
        ("code_challenge", CHALLENGE),
        ("code_challenge_method", "S256"),
    ]);
    let response = get(app, &format!("/oauth/authorize?{query}"), &jar).await;
    jar.update(&response);
    let response = get(app, "/login/method/password", &jar).await;
    jar.update(&response);
    let html = text(response).await;
    let (csrf, tx) = (hidden(&html, "csrf"), hidden(&html, "oauth_transaction"));
    let fields = [
        ("csrf", csrf.as_str()),
        ("oauth_transaction", tx.as_str()),
        ("username", "alice"),
        ("password", "public-fixture"),
    ];
    let response = post(app, "/login/method/password", &jar, &fields).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    jar.update(&response);
    let html = text(get(app, "/oauth/continue", &jar).await).await;
    let (csrf, tx) = (hidden(&html, "csrf"), hidden(&html, "oauth_transaction"));
    let fields = [
        ("csrf", csrf.as_str()),
        ("oauth_transaction", tx.as_str()),
        ("decision", "approve"),
    ];
    let response = post(app, "/oauth/consent", &jar, &fields).await;
    let callback = url::Url::parse(response.headers()[header::LOCATION].to_str().unwrap()).unwrap();
    let params: HashMap<_, _> = callback.query_pairs().into_owned().collect();
    let fields = [
        ("grant_type", "authorization_code"),
        ("client_id", client),
        ("code", params["code"].as_str()),
        ("redirect_uri", CALLBACK),
        ("resource", RESOURCE),
        ("code_verifier", VERIFIER),
    ];
    let response = post(app, "/oauth/token", &Jar::default(), &fields).await;
    assert_eq!(response.status(), StatusCode::OK);
    serde_json::from_str(&text(response).await).unwrap()
}
async fn refresh(app: &Router, fields: &[(&str, &str)]) -> (StatusCode, Value) {
    let mut body = vec![("grant_type", "refresh_token")];
    body.extend_from_slice(fields);
    let response = post(app, "/oauth/token", &Jar::default(), &body).await;
    let status = response.status();
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    (status, serde_json::from_str(&text(response).await).unwrap())
}
async fn refresh_as(app: &Router, client: &str, token: &str) -> (StatusCode, Value) {
    refresh(app, &[("client_id", client), ("refresh_token", token)]).await
}
fn refresh_token(value: &Value) -> String {
    let token = value["refresh_token"].as_str().unwrap();
    assert_eq!(token.len(), 43);
    token.into()
}
fn error(result: (StatusCode, Value), expected: &str) {
    assert_eq!(result.0, StatusCode::BAD_REQUEST);
    assert_eq!(result.1, json!({"error": expected}));
}
async fn app() -> (tempfile::NamedTempFile, Router, AppState) {
    let (key, config) = fixture();
    let (app, state) = startup::build_app(Arc::new(config)).await.unwrap();
    (key, app, state)
}

#[tokio::test]
async fn metadata_advertises_refresh_grant_and_revocation_endpoint() {
    let (_key, app, _) = app().await;
    let response = get(
        &app,
        "/.well-known/oauth-authorization-server",
        &Jar::default(),
    )
    .await;
    let metadata: Value = serde_json::from_str(&text(response).await).unwrap();
    assert_eq!(
        metadata["grant_types_supported"],
        json!(["authorization_code", "refresh_token"])
    );
    assert_eq!(
        metadata["revocation_endpoint"],
        "https://login.example.test/oauth/revoke"
    );
    assert_eq!(
        metadata["revocation_endpoint_auth_methods_supported"],
        json!(["none"])
    );
}

#[tokio::test]
async fn rotation_issues_new_pairs_and_reuse_revokes_the_family() {
    let (_key, app, state) = app().await;
    let first = authorize(&app, "desktop").await;
    let t1 = refresh_token(&first);
    let (status, second) = refresh_as(&app, "desktop", &t1).await;
    assert_eq!(status, StatusCode::OK);
    let t2 = refresh_token(&second);
    assert_ne!(t1, t2);
    assert_eq!(second["scope"], "read list");
    assert_eq!(second["token_type"], "Bearer");
    assert_ne!(second["access_token"], first["access_token"]);
    // The immediate predecessor within the grace window is rejected but harmless.
    error(refresh_as(&app, "desktop", &t1).await, "invalid_grant");
    let (status, third) = refresh_as(&app, "desktop", &t2).await;
    assert_eq!(status, StatusCode::OK);
    let t3 = refresh_token(&third);
    // An older ancestor is reuse: the whole family, including t3, is revoked.
    error(refresh_as(&app, "desktop", &t1).await, "invalid_grant");
    error(refresh_as(&app, "desktop", &t3).await, "invalid_grant");
    let metrics = state.metrics.render().unwrap();
    for line in [
        "authotron_oauth_refresh_tokens_total{event=\"issued\"} 1",
        "authotron_oauth_refresh_tokens_total{event=\"rotated\"} 2",
        "authotron_oauth_refresh_tokens_total{event=\"reuse_detected\"} 1",
        "authotron_oauth_refresh_tokens_total{event=\"family_revoked\"} 1",
    ] {
        assert!(metrics.contains(line), "{line}");
    }
}

#[tokio::test]
async fn refresh_binds_client_resource_and_narrows_scope() {
    let (_key, app, _) = app().await;
    let token = refresh_token(&authorize(&app, "desktop").await);
    error(refresh_as(&app, "other", &token).await, "invalid_grant");
    error(refresh_as(&app, "unknown", &token).await, "invalid_client");
    let with = |extra: (&'static str, &'static str), token: String| {
        let app = app.clone();
        async move {
            let fields = [("client_id", "desktop"), ("refresh_token", &token), extra];
            refresh(&app, &fields).await
        }
    };
    let other = ("resource", "https://other.example.test/mcp");
    error(with(other, token.clone()).await, "invalid_target");
    error(
        with(("scope", "admin"), token.clone()).await,
        "invalid_scope",
    );
    error(
        with(("scope", "read read"), token.clone()).await,
        "invalid_scope",
    );
    let (status, narrowed) = with(("scope", "list"), token.clone()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(narrowed["scope"], "list");
    let (status, bound) = with(("resource", RESOURCE), refresh_token(&narrowed)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(bound["scope"], "read list");
    error(
        refresh_as(&app, "desktop", "malformed").await,
        "invalid_grant",
    );
    error(
        refresh(&app, &[("client_id", "desktop")]).await,
        "invalid_request",
    );
}

#[tokio::test]
async fn revocation_is_client_bound_and_always_succeeds_for_unknown_tokens() {
    let (_key, app, _) = app().await;
    let token = refresh_token(&authorize(&app, "desktop").await);
    let revoke = |fields: Vec<(&'static str, String)>| {
        let app = app.clone();
        async move {
            let fields: Vec<_> = fields.iter().map(|(n, v)| (*n, v.as_str())).collect();
            let response = post(&app, "/oauth/revoke", &Jar::default(), &fields).await;
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            (response.status(), text(response).await)
        }
    };
    let pair = |client: &str, token: &str| {
        vec![
            ("token", token.to_string()),
            ("client_id", client.to_string()),
        ]
    };
    assert_eq!(revoke(pair("other", &token)).await.0, StatusCode::OK);
    assert_eq!(
        revoke(pair("desktop", &"A".repeat(43))).await.0,
        StatusCode::OK
    );
    assert_eq!(
        revoke(pair("desktop", "not-a-token")).await.0,
        StatusCode::OK
    );
    let (status, body) = revoke(pair("unknown", &token)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body, json!({"error": "invalid_client"}).to_string());
    let (status, body) = revoke(vec![("client_id", "desktop".into())]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body, json!({"error": "invalid_request"}).to_string());
    let (status, refreshed) = refresh_as(&app, "desktop", &token).await;
    assert_eq!(status, StatusCode::OK);
    let current = refresh_token(&refreshed);
    let mut hinted = pair("desktop", &token);
    hinted.push(("token_type_hint", "refresh_token".into()));
    let (status, body) = revoke(hinted).await;
    assert_eq!((status, body.as_str()), (StatusCode::OK, ""));
    error(refresh_as(&app, "desktop", &current).await, "invalid_grant");
}

#[tokio::test]
async fn token_and_revocation_endpoints_are_rate_limited_per_client_ip() {
    let (_key, mut config) = fixture();
    config.oauth.endpoint_rate_limit.token_requests_per_window = 2;
    config.oauth.endpoint_rate_limit.revoke_requests_per_window = 1;
    config.oauth.endpoint_rate_limit.trusted_proxies = vec!["10.0.0.0/8".into()];
    let (app, _) = startup::build_app(Arc::new(config)).await.unwrap();
    let call =
        |path: &'static str, peer: &'static str, forwarded: Option<&'static str>| {
            let app = app.clone();
            async move {
                let mut request = Request::post(path)
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
                if let Some(forwarded) = forwarded {
                    request = request.header("x-forwarded-for", forwarded);
                }
                let mut request = request
                    .body(Body::from(encoded(&[
                        ("client_id", "desktop"),
                        ("grant_type", "refresh_token"),
                        ("refresh_token", "unknown"),
                        ("token", "unknown"),
                    ])))
                    .unwrap();
                request.extensions_mut().insert(axum::extract::ConnectInfo(
                    std::net::SocketAddr::new(peer.parse().unwrap(), 443),
                ));
                send(&app, request).await
            }
        };
    for _ in 0..2 {
        let response = call("/oauth/token", "192.0.2.1", None).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
    let limited = call("/oauth/token", "192.0.2.1", None).await;
    assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(limited.headers()[header::CACHE_CONTROL], "no-store");
    let retry: u64 = limited.headers()[header::RETRY_AFTER]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!((1..=60).contains(&retry));
    assert_eq!(
        text(limited).await,
        json!({"error": "temporarily_unavailable"}).to_string()
    );
    // A spoofed X-Forwarded-For from an untrusted peer is ignored.
    let spoofed = call("/oauth/token", "192.0.2.1", Some("198.51.100.9")).await;
    assert_eq!(spoofed.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        call("/oauth/token", "192.0.2.2", None).await.status(),
        StatusCode::BAD_REQUEST
    );
    // Behind a trusted proxy each forwarded client has its own window.
    for client in ["198.51.100.7", "198.51.100.8"] {
        for _ in 0..2 {
            let response = call("/oauth/token", "10.0.0.5", Some(client)).await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }
    }
    assert_eq!(
        call("/oauth/token", "10.0.0.5", Some("198.51.100.7"))
            .await
            .status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        call("/oauth/revoke", "192.0.2.1", None).await.status(),
        StatusCode::OK
    );
    assert_eq!(
        call("/oauth/revoke", "192.0.2.1", None).await.status(),
        StatusCode::TOO_MANY_REQUESTS
    );
}

struct Container(String);
impl Drop for Container {
    fn drop(&mut self) {
        let _ = std::process::Command::new("docker")
            .args(["rm", "-f", &self.0])
            .output();
    }
}
fn docker(args: &[&str]) -> String {
    let output = std::process::Command::new("docker")
        .args(args)
        .output()
        .expect("Docker CLI required");
    assert!(output.status.success(), "disposable Valkey fixture failed");
    String::from_utf8(output.stdout).unwrap().trim().into()
}

#[tokio::test]
#[ignore = "requires Docker; creates and removes its own Valkey fixture"]
async fn disposable_valkey_refresh_rotates_across_replicas() {
    let container = Container(docker(&[
        "run",
        "--rm",
        "-d",
        "-p",
        "127.0.0.1::6379",
        "valkey/valkey:8",
        "valkey-server",
        "--requirepass",
        "public-disposable-fixture",
        "--save",
        "",
        "--appendonly",
        "no",
    ]));
    let (_key, mut config) = fixture();
    config.ui.browser_session.as_mut().unwrap().backend =
        authotron::config::ui::BrowserBackendConfig::Valkey {
            url: format!("redis://{}/0", docker(&["port", &container.0, "6379/tcp"])),
            key_prefix: "authotron:refresh-http".into(),
            password: "public-disposable-fixture".into(),
            connect_timeout_ms: 2000,
            operation_timeout_ms: 1000,
        };
    let config = Arc::new(config);
    let mut ready = None;
    for _ in 0..100 {
        if let Ok((app, _)) = startup::build_app(config.clone()).await {
            ready = Some(app);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let a = ready.expect("disposable Valkey did not become ready");
    let (b, _) = startup::build_app(config.clone()).await.unwrap();
    let t1 = refresh_token(&authorize(&a, "desktop").await);
    let (status, second) = refresh_as(&b, "desktop", &t1).await;
    assert_eq!(status, StatusCode::OK);
    let t2 = refresh_token(&second);
    error(refresh_as(&a, "desktop", &t1).await, "invalid_grant");
    let (status, third) = refresh_as(&a, "desktop", &t2).await;
    assert_eq!(status, StatusCode::OK);
    let t3 = refresh_token(&third);
    error(refresh_as(&b, "desktop", &t1).await, "invalid_grant");
    error(refresh_as(&a, "desktop", &t3).await, "invalid_grant");
    let t4 = refresh_token(&authorize(&b, "desktop").await);
    let fields = [("token", t4.as_str()), ("client_id", "desktop")];
    let response = post(&a, "/oauth/revoke", &Jar::default(), &fields).await;
    assert_eq!(response.status(), StatusCode::OK);
    error(refresh_as(&b, "desktop", &t4).await, "invalid_grant");
}

use authotron::{
    config::{ConfigV2, ui::BrowserBackendConfig},
    startup,
};
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use cookie::Cookie;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use rsa::{
    RsaPrivateKey,
    pkcs8::{EncodePrivateKey, LineEnding},
    rand_core::OsRng,
};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    io::Write,
    process::{Command, Stdio},
    sync::{Arc, OnceLock},
};
use tower::ServiceExt;

const ORIGIN: &str = "https://login.example.test";
const ISSUER: &str = "https://login.example.test/";
const RESOURCE: &str = "https://mcp.example.test/mcp";
const CALLBACK: &str = "http://127.0.0.1:49152/callback?installation=test";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
fn fixture(uri: &str) -> (tempfile::NamedTempFile, ConfigV2) {
    static PEM: OnceLock<String> = OnceLock::new();
    let pem = PEM.get_or_init(|| {
        RsaPrivateKey::new(&mut OsRng, 2048)
            .unwrap()
            .to_pkcs8_pem(LineEnding::LF)
            .unwrap()
            .to_string()
    });
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(pem.as_bytes()).unwrap();
    let config = serde_json::from_value(json!({
        "store": {"enabled": false}, "services": [],
        "providers": [{"type": "plain", "name": "basic", "realm": "local", "users": [{"username": "alice", "password": "päss:秘密", "roles": ["reader", "unrelated"]}], "browser": {"id": "password", "label": "Password"}},
            {"type": "ecmwf-api", "name": "api", "realm": "ecmwf", "uri": uri, "browser": {"id": "ecmwf-api-key", "label": "ECMWF API key"}}],
        "augmenters": [{"type": "plain", "name": "reader", "realm": "ecmwf", "roles": {"reader": ["public-user"]}}],
        "server": {"host": "127.0.0.1", "port": 0}, "metrics": {"enabled": false},
        "jwt": {"iss": "legacy", "exp": 300, "secret": "public-legacy-only"}, "logging": {"level": "warn", "format": "console"},
        "ui": {"enabled": true,
            "browser_session": {"public_origin": ORIGIN, "backend": {"type": "memory"}}},
        "oauth": {"enabled": true, "issuer": ISSUER, "signing": {"active_kid": "http-test", "keys": [{"kid": "http-test", "private_key_file": file.path()}]},
            "clients": [{"client_id": "desktop", "display_name": "Desktop <MCP>", "application_type": "native", "redirect_uris": [CALLBACK], "resources": [{"resource": RESOURCE, "scopes": ["read"]}]}],
            "resources": [{"resource": RESOURCE, "allowed_realms": ["local", "ecmwf"], "scopes": [{"name": "read", "required_roles": ["reader"]}]}]}
    })).unwrap();
    (file, config)
}
#[derive(Default, Clone)]
struct Jar(HashMap<String, String>);
impl Jar {
    fn update(&mut self, response: &Response) {
        for value in response.headers().get_all(header::SET_COOKIE) {
            let cookie = Cookie::parse(value.to_str().unwrap()).unwrap();
            assert_eq!(cookie.secure(), Some(true));
            assert_eq!(cookie.http_only(), Some(true));
            assert!(cookie.domain().is_none());
            assert_eq!(cookie.path(), Some("/"));
            if cookie.value().is_empty() {
                self.0.remove(cookie.name());
            } else {
                self.0.insert(cookie.name().into(), cookie.value().into());
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
async fn send(app: &Router, request: Request<Body>) -> Response {
    app.clone().oneshot(request).await.unwrap()
}
async fn get(app: &Router, path: &str, jar: &Jar) -> Response {
    send(
        app,
        Request::get(path)
            .header(header::COOKIE, jar.header())
            .body(Body::empty())
            .unwrap(),
    )
    .await
}
fn encoded(fields: &[(&str, &str)]) -> String {
    let mut form = url::form_urlencoded::Serializer::new(String::new());
    for (name, value) in fields {
        form.append_pair(name, value);
    }
    form.finish()
}
fn post(path: &str, jar: &Jar, fields: &[(&str, &str)], origin: Option<&str>) -> Request<Body> {
    let mut request = Request::post(path)
        .header(header::COOKIE, jar.header())
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(origin) = origin {
        request = request.header(header::ORIGIN, origin);
    }
    request.body(Body::from(encoded(fields))).unwrap()
}
async fn text(response: Response) -> String {
    String::from_utf8(
        to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap()
}
fn hidden(html: &str, name: &str) -> String {
    html.split(&format!("name=\"{name}\" value=\""))
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .into()
}
fn authorize_query() -> String {
    encoded(&[
        ("client_id", "desktop"),
        ("redirect_uri", CALLBACK),
        ("response_type", "code"),
        ("resource", RESOURCE),
        ("scope", "read"),
        ("state", "opaque+client"),
        (
            "code_challenge",
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        ),
        ("code_challenge_method", "S256"),
    ])
}
async fn login_form(app: &Router, jar: &mut Jar, path: &str) -> (String, String) {
    let response = get(app, &format!("/oauth/authorize?{}", authorize_query()), jar).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers()[header::LOCATION], "/login");
    jar.update(&response);
    let response = get(app, path, jar).await;
    assert_eq!(response.status(), StatusCode::OK);
    jar.update(&response);
    let html = text(response).await;
    (hidden(&html, "csrf"), hidden(&html, "oauth_transaction"))
}
async fn consent_page(app: &Router, jar: &Jar) -> (String, String) {
    let response = get(app, "/oauth/continue", jar).await;
    assert_eq!(response.status(), StatusCode::OK);
    let html = text(response).await;
    assert!(html.contains("Desktop &lt;MCP&gt;"));
    assert!(!html.contains("opaque+client"));
    (hidden(&html, "csrf"), hidden(&html, "oauth_transaction"))
}

fn isolate_clients(config: &mut ConfigV2) {
    let mut other = config.oauth.clients[0].clone();
    other.client_id = "other".into();
    config.oauth.clients.push(other);
    config.oauth.max_authorization_transactions = 3;
}

async fn admission_isolation(a: &Router, b: &Router) {
    let path = format!("/oauth/authorize?{}", authorize_query());
    let mut attacker = Jar::default();
    let response = get(a, &path, &attacker).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    attacker.update(&response);
    let binding = attacker.header();
    for _ in 0..5 {
        let response = get(b, &path, &attacker).await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        attacker.update(&response);
        assert_eq!(attacker.header(), binding);
    }
    // Cookie-free requests can exhaust desktop's share (2), but not other's (1).
    assert_eq!(
        get(b, &path, &Jar::default()).await.status(),
        StatusCode::SEE_OTHER
    );
    for _ in 0..5 {
        assert_eq!(
            get(a, &path, &Jar::default()).await.status(),
            StatusCode::TOO_MANY_REQUESTS
        );
    }
    let other = path.replace("client_id=desktop", "client_id=other");
    assert_eq!(
        get(b, &other, &Jar::default()).await.status(),
        StatusCode::SEE_OTHER
    );
    assert_eq!(
        get(a, &other, &Jar::default()).await.status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        get(b, "/login/method/password", &attacker).await.status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn authorize_reserves_other_clients_capacity_and_reuses_live_browser_binding() {
    let (_key, mut config) = fixture("http://127.0.0.1:9");
    isolate_clients(&mut config);
    let (app, _) = startup::build_app(Arc::new(config)).await.unwrap();
    admission_isolation(&app, &app).await;
}

#[tokio::test]
async fn transaction_capacity_must_reserve_at_least_one_slot_per_client() {
    let (_key, mut config) = fixture("http://127.0.0.1:9");
    isolate_clients(&mut config);
    config.oauth.max_authorization_transactions = 1;
    assert!(startup::build_app(Arc::new(config)).await.is_err());
}

#[tokio::test]
async fn authorize_only_reuses_the_exact_validated_request_in_every_state() {
    let (_key, mut config) = fixture("http://127.0.0.1:9");
    isolate_clients(&mut config);
    let second_callback = "http://127.0.0.1:49152/other";
    config.oauth.clients[0]
        .redirect_uris
        .push(second_callback.into());
    let mut second_resource = config.oauth.resources[0].clone();
    second_resource.resource = "https://mcp.example.test/other".into();
    config.oauth.resources.push(second_resource);
    let mut grant = config.oauth.clients[0].resources[0].clone();
    grant.resource = "https://mcp.example.test/other".into();
    config.oauth.clients[0].resources.push(grant);
    let mut scope = config.oauth.resources[0].scopes[0].clone();
    scope.name = "write".into();
    config.oauth.resources[0].scopes.push(scope);
    config.oauth.clients[0].resources[0]
        .scopes
        .push("write".into());
    let (app, _) = startup::build_app(Arc::new(config)).await.unwrap();
    let mut jar = Jar::default();
    let (csrf, tx) = login_form(&app, &mut jar, "/login/method/password").await;
    for phase in 0..3 {
        if phase == 1 {
            let fields = [
                ("csrf", csrf.as_str()),
                ("oauth_transaction", tx.as_str()),
                ("username", "alice"),
                ("password", "päss:秘密"),
            ];
            let response = send(
                &app,
                post("/login/method/password", &jar, &fields, Some(ORIGIN)),
            )
            .await;
            assert_eq!(response.status(), StatusCode::SEE_OTHER);
            jar.update(&response);
        } else if phase == 2 {
            consent_page(&app, &jar).await;
        }
        let response = get(
            &app,
            &format!("/oauth/authorize?{}", authorize_query()),
            &jar,
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            response.headers()[header::LOCATION],
            if phase == 0 {
                "/login"
            } else {
                "/oauth/continue"
            }
        );
        for (field, value) in [
            ("client_id", "other"),
            ("redirect_uri", second_callback),
            ("resource", "https://mcp.example.test/other"),
            ("scope", "write"),
            ("state", "different-state"),
            (
                "code_challenge",
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            ),
        ] {
            let mut pairs: Vec<_> = url::form_urlencoded::parse(authorize_query().as_bytes())
                .into_owned()
                .collect();
            pairs.iter_mut().find(|(name, _)| name == field).unwrap().1 = value.into();
            let query = encoded(
                &pairs
                    .iter()
                    .map(|(name, value)| (name.as_str(), value.as_str()))
                    .collect::<Vec<_>>(),
            );
            let response = get(&app, &format!("/oauth/authorize?{query}"), &jar).await;
            assert_eq!(
                response.status(),
                StatusCode::CONFLICT,
                "{field}, phase {phase}"
            );
            assert!(!response.headers().contains_key(header::LOCATION));
            assert!(!response.headers().contains_key(header::SET_COOKIE));
            assert!(
                text(response)
                    .await
                    .contains("Continue current authorization")
            );
        }
    }
}

async fn assert_explicit_recovery(response: Response, jar: &Jar) {
    assert_eq!(response.status(), StatusCode::OK);
    assert!(!response.headers().contains_key(header::LOCATION));
    assert_eq!(
        response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .count(),
        2
    );
    let mut cleared = jar.clone();
    cleared.update(&response);
    assert!(!cleared.0.contains_key("__Host-authotron_oauth"));
    assert!(!cleared.0.contains_key("__Host-authotron_oauth_browser"));
    assert!(text(response).await.contains("Restart authorization"));
}

#[tokio::test]
async fn malformed_partial_and_duplicate_oauth_cookies_recover_only_on_get() {
    let (_key, config) = fixture("http://127.0.0.1:9");
    let (app, _) = startup::build_app(Arc::new(config)).await.unwrap();
    let mut jar = Jar::default();
    let (csrf, tx) = login_form(&app, &mut jar, "/login/method/password").await;
    let headers = [
        format!("__Host-authotron_oauth={tx}"),
        format!(
            "__Host-authotron_oauth_browser={}",
            jar.0["__Host-authotron_oauth_browser"]
        ),
        "__Host-authotron_oauth=malformed; __Host-authotron_oauth_browser=malformed".into(),
        format!("{}; __Host-authotron_oauth={tx}", jar.header()),
        format!(
            "{}; __Host-authotron_oauth_browser={}",
            jar.header(),
            jar.0["__Host-authotron_oauth_browser"]
        ),
    ];
    for cookies in headers {
        for path in [
            "/login",
            "/login/method/password",
            "/login/method/ecmwf-api-key",
        ] {
            let response = send(
                &app,
                Request::get(path)
                    .header(header::COOKIE, &cookies)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
            assert_explicit_recovery(response, &jar).await;
        }
        let mut request = post(
            "/login/method/password",
            &jar,
            &[
                ("csrf", &csrf),
                ("oauth_transaction", &tx),
                ("username", "alice"),
                ("password", "päss:秘密"),
            ],
            Some(ORIGIN),
        );
        request
            .headers_mut()
            .insert(header::COOKIE, cookies.parse().unwrap());
        let response = send(&app, request).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(!response.headers().contains_key(header::LOCATION));
    }
}

async fn consent_binding_recovery(app: &Router) {
    let mut jar = Jar::default();
    let (csrf, tx) = login_form(app, &mut jar, "/login/method/password").await;
    let response = send(
        app,
        post(
            "/login/method/password",
            &jar,
            &[
                ("csrf", &csrf),
                ("oauth_transaction", &tx),
                ("username", "alice"),
                ("password", "päss:秘密"),
            ],
            Some(ORIGIN),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    jar.update(&response);
    let (csrf, tx) = consent_page(app, &jar).await;
    let mut wrong = jar.clone();
    wrong.0.insert(
        "__Host-authotron_oauth_browser".into(),
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
    );
    let fields = [
        ("csrf", csrf.as_str()),
        ("oauth_transaction", tx.as_str()),
        ("decision", "deny"),
    ];
    let response = send(app, post("/oauth/consent", &wrong, &fields, Some(ORIGIN))).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(!response.headers().contains_key(header::LOCATION));
    for path in [
        "/login",
        "/login/method/password",
        "/login/method/ecmwf-api-key",
    ] {
        assert_explicit_recovery(get(app, path, &wrong).await, &wrong).await;
    }
    // Neither the rejected POST nor GET recovery consumes the legitimate flow.
    let response = send(app, post("/oauth/consent", &jar, &fields, Some(ORIGIN))).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(
        response.headers()[header::LOCATION]
            .to_str()
            .unwrap()
            .contains("access_denied")
    );
}

#[tokio::test]
async fn consent_ready_wrong_browser_recovers_without_accepting_post() {
    let (_key, config) = fixture("http://127.0.0.1:9");
    let (app, _) = startup::build_app(Arc::new(config)).await.unwrap();
    consent_binding_recovery(&app).await;
}

#[tokio::test]
async fn login_get_recovers_lost_state_and_resumes_advanced_state_without_post_downgrade() {
    let (_key, config) = fixture("http://127.0.0.1:9");
    let config = Arc::new(config);
    let (app, _) = startup::build_app(config.clone()).await.unwrap();
    let mut jar = Jar::default();
    let (csrf, tx) = login_form(&app, &mut jar, "/login/method/password").await;
    let fields = [
        ("csrf", csrf.as_str()),
        ("oauth_transaction", tx.as_str()),
        ("username", "alice"),
        ("password", "päss:秘密"),
    ];
    let response = send(
        &app,
        post("/login/method/password", &jar, &fields, Some(ORIGIN)),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    jar.update(&response);
    for consent_ready in [false, true] {
        if consent_ready {
            consent_page(&app, &jar).await;
        }
        let response = get(&app, "/login", &jar).await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(response.headers()[header::LOCATION], "/oauth/continue");
        assert!(!response.headers().contains_key(header::SET_COOKIE));
    }
    // A process restart loses development-memory state. Recovery is an explicit
    // GET page, while the original credential POST still fails closed.
    let (restarted, _) = startup::build_app(config).await.unwrap();
    let response = get(&restarted, "/login", &jar).await;
    assert_eq!(response.status(), StatusCode::OK);
    let mut cleared = jar.clone();
    cleared.update(&response);
    assert!(!cleared.0.contains_key("__Host-authotron_oauth"));
    assert!(!cleared.0.contains_key("__Host-authotron_oauth_browser"));
    assert!(text(response).await.contains("Restart authorization"));
    let response = send(
        &restarted,
        post("/login/method/password", &cleared, &fields, Some(ORIGIN)),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(
        !response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .any(|value| value
                .to_str()
                .unwrap()
                .starts_with("__Host-authotron_session="))
    );
    assert_eq!(
        get(&restarted, "/login/method/password", &cleared)
            .await
            .status(),
        StatusCode::OK
    );
}
async fn complete(a: &Router, b: &Router, api: bool) {
    let mut jar = Jar::default();
    let path = if api {
        "/login/method/ecmwf-api-key"
    } else {
        "/login/method/password"
    };
    let (csrf, tx) = login_form(a, &mut jar, path).await;
    let mut fields = vec![("csrf", csrf.as_str()), ("oauth_transaction", tx.as_str())];
    if api {
        fields.push(("api_key", "public-key"));
    } else {
        fields.extend([("username", "alice"), ("password", "päss:秘密")]);
    }
    let response = send(a, post(path, &jar, &fields, Some(ORIGIN))).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers()[header::LOCATION], "/oauth/continue");
    jar.update(&response);
    assert!(!jar.0.contains_key("__Host-authotron_session"));
    let (csrf, tx) = consent_page(b, &jar).await;
    let response = send(
        b,
        post(
            "/oauth/consent",
            &jar,
            &[
                ("csrf", &csrf),
                ("oauth_transaction", &tx),
                ("decision", "approve"),
            ],
            Some(ORIGIN),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    jar.update(&response);
    assert!(!jar.0.contains_key("__Host-authotron_oauth"));
    let callback = url::Url::parse(response.headers()[header::LOCATION].to_str().unwrap()).unwrap();
    let params: HashMap<_, _> = callback.query_pairs().into_owned().collect();
    assert_eq!(params["state"], "opaque+client");
    assert_eq!(params["iss"], ISSUER);
    assert_eq!(params["installation"], "test");
    let mut fields = vec![
        ("grant_type", "authorization_code"),
        ("client_id", "desktop"),
        ("code", params["code"].as_str()),
        ("redirect_uri", CALLBACK),
        ("resource", RESOURCE),
        (
            "code_verifier",
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        ),
    ];
    let response = send(a, post("/oauth/token", &Jar::default(), &fields, None)).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        serde_json::from_str::<Value>(&text(response).await).unwrap()["error"],
        "invalid_grant"
    );
    fields[5].1 = VERIFIER;
    fields.extend([("scope", "admin"), ("expires_in", "86400")]);
    let response = send(b, post("/oauth/token", &Jar::default(), &fields, None)).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let token: Value = serde_json::from_str(&text(response).await).unwrap();
    assert_eq!(token["token_type"], "Bearer");
    assert_eq!(token["scope"], "read");
    assert_eq!(token["expires_in"], 300);
    assert!(token.get("refresh_token").is_none());
    let jwt = token["access_token"].as_str().unwrap();
    let header = decode_header(jwt).unwrap();
    assert_eq!(header.alg, Algorithm::RS256);
    assert_eq!(header.typ.as_deref(), Some("at+jwt"));
    assert_eq!(header.kid.as_deref(), Some("http-test"));
    let jwks: Value =
        serde_json::from_str(&text(get(b, "/oauth/jwks", &Jar::default()).await).await).unwrap();
    let key = &jwks["keys"][0];
    assert!(key.get("d").is_none());
    let decoding =
        DecodingKey::from_rsa_components(key["n"].as_str().unwrap(), key["e"].as_str().unwrap())
            .unwrap();
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[ISSUER]);
    validation.set_audience(&[RESOURCE]);
    let claims = decode::<Value>(jwt, &decoding, &validation).unwrap().claims;
    assert_eq!(claims["scope"], "read");
    assert_eq!(claims["roles"], json!(["reader"]));
    assert!(claims.get("username").is_none());
    let response = send(a, post("/oauth/token", &Jar::default(), &fields, None)).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
#[tokio::test]
async fn basic_and_api_key_http_flows_issue_verified_one_use_tokens() {
    let mut mock = mockito::Server::new_async().await;
    let request = mock
        .mock("GET", "/who-am-i")
        .match_query(mockito::Matcher::UrlEncoded(
            "token".into(),
            "public-key".into(),
        ))
        .with_status(200)
        .with_body(json!({"uid": "public-user"}).to_string())
        .expect(1)
        .create_async()
        .await;
    let (_key, config) = fixture(&mock.url());
    let (app, state) = startup::build_app(Arc::new(config)).await.unwrap();
    let metadata: Value = serde_json::from_str(
        &text(
            get(
                &app,
                "/.well-known/oauth-authorization-server",
                &Jar::default(),
            )
            .await,
        )
        .await,
    )
    .unwrap();
    assert_eq!(metadata["issuer"], ISSUER);
    assert_eq!(
        metadata["token_endpoint_auth_methods_supported"],
        json!(["none"])
    );
    assert!(metadata.get("registration_endpoint").is_none());
    assert_eq!(metadata["scopes_supported"], json!(["read"]));
    complete(&app, &app, false).await;
    complete(&app, &app, true).await;
    request.assert_async().await;
    let metrics = authotron::routes::create_metrics_router(state);
    for path in [
        "/oauth/authorize",
        "/oauth/token",
        "/oauth/continue",
        "/oauth/jwks",
        "/.well-known/oauth-authorization-server",
    ] {
        assert_eq!(
            get(&metrics, path, &Jar::default()).await.status(),
            StatusCode::NOT_FOUND
        );
    }
}
#[tokio::test]
async fn metadata_scopes_supported_is_sorted_unique_union_of_resource_scopes() {
    let (_key, mut config) = fixture("http://127.0.0.1:9");
    let mut second = config.oauth.resources[0].clone();
    second.resource = "https://mcp.example.test/other".into();
    for name in ["write", "admin"] {
        let mut scope = second.scopes[0].clone();
        scope.name = name.into();
        second.scopes.push(scope);
    }
    config.oauth.resources.push(second);
    let (app, _) = startup::build_app(Arc::new(config)).await.unwrap();
    let response = get(
        &app,
        "/.well-known/oauth-authorization-server",
        &Jar::default(),
    )
    .await;
    let metadata: Value = serde_json::from_str(&text(response).await).unwrap();
    assert_eq!(
        metadata["scopes_supported"],
        json!(["admin", "read", "write"])
    );
}
#[tokio::test]
async fn invalid_authorization_and_stale_login_forms_never_verify_or_redirect() {
    let mut mock = mockito::Server::new_async().await;
    let request = mock.mock("GET", "/who-am-i").expect(0).create_async().await;
    let (_key, config) = fixture(&mock.url());
    let (app, _) = startup::build_app(Arc::new(config)).await.unwrap();
    for (field, value) in [
        ("client_id", "other"),
        ("redirect_uri", "https://evil.example/"),
        ("resource", "https://other.example/mcp"),
        ("scope", "admin"),
        ("code_challenge_method", "plain"),
    ] {
        let mut pairs: Vec<_> = url::form_urlencoded::parse(authorize_query().as_bytes())
            .into_owned()
            .collect();
        pairs.iter_mut().find(|(name, _)| name == field).unwrap().1 = value.into();
        let query = encoded(
            &pairs
                .iter()
                .map(|(a, b)| (a.as_str(), b.as_str()))
                .collect::<Vec<_>>(),
        );
        let response = get(&app, &format!("/oauth/authorize?{query}"), &Jar::default()).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(response.headers().get(header::LOCATION).is_none());
    }
    let mut jar = Jar::default();
    let (csrf, old_tx) = login_form(&app, &mut jar, "/login/method/ecmwf-api-key").await;
    // A distinct browser starts a different flow; posting the old form with the
    // new flow's cookie pair must still fail before credential verification.
    let response = get(
        &app,
        &format!("/oauth/authorize?{}", authorize_query()),
        &Jar::default(),
    )
    .await;
    jar.update(&response);
    for tx in [Some(old_tx.as_str()), None] {
        let mut fields = vec![("csrf", csrf.as_str()), ("api_key", "public-key")];
        if let Some(tx) = tx {
            fields.push(("oauth_transaction", tx));
        }
        assert_eq!(
            send(
                &app,
                post("/login/method/ecmwf-api-key", &jar, &fields, Some(ORIGIN))
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
    }
    let form = get(&app, "/login/method/ecmwf-api-key", &jar).await;
    jar.update(&form);
    let html = text(form).await;
    let csrf = hidden(&html, "csrf");
    let tx = hidden(&html, "oauth_transaction");
    let fields = [
        ("csrf", csrf.as_str()),
        ("oauth_transaction", tx.as_str()),
        ("api_key", "public-key"),
    ];
    assert_eq!(
        send(
            &app,
            post("/login/method/ecmwf-api-key", &jar, &fields, None)
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    let mut duplicate = post("/login/method/ecmwf-api-key", &jar, &fields, Some(ORIGIN));
    duplicate.headers_mut().append(
        header::COOKIE,
        format!("__Host-authotron_oauth={tx}").parse().unwrap(),
    );
    assert_eq!(send(&app, duplicate).await.status(), StatusCode::FORBIDDEN);
    request.assert_async().await;
}
#[tokio::test]
async fn consent_requires_origin_nonce_and_exact_decision_and_denial_has_no_code() {
    let (_key, config) = fixture("http://127.0.0.1:9");
    let (app, _) = startup::build_app(Arc::new(config)).await.unwrap();
    let mut jar = Jar::default();
    let (csrf, tx) = login_form(&app, &mut jar, "/login/method/password").await;
    let failed = send(
        &app,
        post(
            "/login/method/password",
            &jar,
            &[
                ("csrf", &csrf),
                ("oauth_transaction", &tx),
                ("username", "alice"),
                ("password", "public-wrong-password"),
            ],
            Some(ORIGIN),
        ),
    )
    .await;
    assert_eq!(failed.status(), StatusCode::UNAUTHORIZED);
    jar.update(&failed);
    let failed_html = text(failed).await;
    assert_eq!(hidden(&failed_html, "oauth_transaction"), tx);
    assert!(!failed_html.contains("public-wrong-password"));
    let csrf = hidden(&failed_html, "csrf");
    let response = send(
        &app,
        post(
            "/login/method/password",
            &jar,
            &[
                ("csrf", &csrf),
                ("oauth_transaction", &tx),
                ("username", "alice"),
                ("password", "päss:秘密"),
            ],
            Some(ORIGIN),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    jar.update(&response);
    let (csrf, tx) = consent_page(&app, &jar).await;
    let mut duplicate_origin = post(
        "/oauth/consent",
        &jar,
        &[
            ("csrf", &csrf),
            ("oauth_transaction", &tx),
            ("decision", "approve"),
        ],
        Some(ORIGIN),
    );
    duplicate_origin
        .headers_mut()
        .append(header::ORIGIN, ORIGIN.parse().unwrap());
    assert_eq!(
        send(&app, duplicate_origin).await.status(),
        StatusCode::FORBIDDEN
    );
    for fields in [
        vec![("csrf", csrf.as_str()), ("oauth_transaction", tx.as_str())],
        vec![
            ("csrf", csrf.as_str()),
            ("csrf", csrf.as_str()),
            ("oauth_transaction", tx.as_str()),
            ("decision", "approve"),
        ],
    ] {
        assert_eq!(
            send(&app, post("/oauth/consent", &jar, &fields, Some(ORIGIN)))
                .await
                .status(),
            StatusCode::BAD_REQUEST
        );
    }
    for (nonce, decision, origin, expected) in [
        (csrf.as_str(), "approve", None, StatusCode::FORBIDDEN),
        ("bad", "approve", Some(ORIGIN), StatusCode::BAD_REQUEST),
        (
            csrf.as_str(),
            "other",
            Some(ORIGIN),
            StatusCode::BAD_REQUEST,
        ),
    ] {
        assert_eq!(
            send(
                &app,
                post(
                    "/oauth/consent",
                    &jar,
                    &[
                        ("csrf", nonce),
                        ("oauth_transaction", &tx),
                        ("decision", decision)
                    ],
                    origin
                )
            )
            .await
            .status(),
            expected
        );
    }
    let response = send(
        &app,
        post(
            "/oauth/consent",
            &jar,
            &[
                ("csrf", &csrf),
                ("oauth_transaction", &tx),
                ("decision", "deny"),
            ],
            Some(ORIGIN),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let url = url::Url::parse(response.headers()[header::LOCATION].to_str().unwrap()).unwrap();
    let query: HashMap<_, _> = url.query_pairs().into_owned().collect();
    assert_eq!(query["error"], "access_denied");
    assert!(!query.contains_key("code"));
    assert_eq!(query["state"], "opaque+client");
}
/// Valid credentials for an identity that fails scope policy end the authorization with
/// an RFC 6749 `access_denied` redirect; wrong credentials still re-render the form.
#[tokio::test]
async fn policy_denied_identity_redirects_access_denied_and_consumes_transaction() {
    for case in ["role", "realm"] {
        let (_key, mut config) = fixture("http://127.0.0.1:9");
        match case {
            "role" => config.oauth.resources[0].scopes[0]
                .required_roles
                .push("public-admin".into()),
            _ => config.oauth.resources[0].allowed_realms = vec!["ecmwf".into()],
        }
        let (app, state) = startup::build_app(Arc::new(config)).await.unwrap();
        let mut jar = Jar::default();
        let (csrf, tx) = login_form(&app, &mut jar, "/login/method/password").await;
        let wrong = send(
            &app,
            post(
                "/login/method/password",
                &jar,
                &[
                    ("csrf", &csrf),
                    ("oauth_transaction", &tx),
                    ("username", "alice"),
                    ("password", "public-wrong-password"),
                ],
                Some(ORIGIN),
            ),
        )
        .await;
        assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED, "{case}");
        assert!(wrong.headers().get(header::LOCATION).is_none());
        jar.update(&wrong);
        let csrf = hidden(&text(wrong).await, "csrf");
        let stale = jar.clone();
        let fields = [
            ("csrf", csrf.as_str()),
            ("oauth_transaction", tx.as_str()),
            ("username", "alice"),
            ("password", "päss:秘密"),
        ];
        let response = send(
            &app,
            post("/login/method/password", &jar, &fields, Some(ORIGIN)),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER, "{case}");
        let location = response.headers()[header::LOCATION].to_str().unwrap();
        let url = url::Url::parse(location).unwrap();
        assert_eq!(
            format!("{}://{}{}", url.scheme(), url.authority(), url.path()),
            "http://127.0.0.1:49152/callback"
        );
        let query: HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(query["installation"], "test");
        assert_eq!(query["error"], "access_denied");
        assert_eq!(query["state"], "opaque+client");
        assert_eq!(query["iss"], ISSUER);
        assert!(!query.contains_key("code"));
        let cleared: Vec<_> = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|value| Cookie::parse(value.to_str().unwrap()).unwrap())
            .filter(|cookie| cookie.name().starts_with("__Host-authotron_oauth"))
            .collect();
        assert_eq!(cleared.len(), 2);
        let metrics = state.metrics.render().unwrap();
        for (outcome, count) in [("denied", 1), ("rejected", 1)] {
            assert!(
                metrics.contains(&format!(
                    "authotron_browser_login_attempts_total{{flow=\"basic\",method=\"password\",outcome=\"{outcome}\"}} {count}"
                )),
                "{case} {outcome}"
            );
        }
        assert!(cleared.iter().all(|cookie| cookie.value().is_empty()));
        jar.update(&response);
        assert!(!jar.header().contains("authotron_oauth"));
        // Replaying with the old cookies stays local: the transaction is gone.
        let replay = send(
            &app,
            post("/login/method/password", &stale, &fields, Some(ORIGIN)),
        )
        .await;
        assert!(replay.headers().get(header::LOCATION).is_none());
        assert!(replay.status().is_client_error(), "{case}");
        let resumed = get(&app, "/oauth/continue", &stale).await;
        assert!(resumed.headers().get(header::LOCATION).is_none());
        assert!(resumed.status().is_client_error(), "{case}");
    }
}
#[tokio::test]
async fn token_protocol_errors_are_bounded_fixed_json_without_origin_or_cors() {
    let (_key, config) = fixture("http://127.0.0.1:9");
    let (app, _) = startup::build_app(Arc::new(config)).await.unwrap();
    let fields = [
        ("grant_type", "authorization_code"),
        ("client_id", "desktop"),
        ("code", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        ("redirect_uri", CALLBACK),
        ("resource", RESOURCE),
        ("code_verifier", VERIFIER),
    ];
    for case in 0..6 {
        let mut body = fields.to_vec();
        let expected = match case {
            0 => {
                body.remove(4);
                "invalid_request"
            }
            1 => {
                body.push(("code", "duplicate"));
                "invalid_request"
            }
            2 => {
                body[0].1 = "refresh_token";
                "unsupported_grant_type"
            }
            3 => {
                body[1].1 = "unknown";
                "invalid_client"
            }
            4 => {
                body[2].1 = "malformed";
                "invalid_grant"
            }
            _ => "invalid_client",
        };
        let mut request = post("/oauth/token", &Jar::default(), &body, None);
        if case == 5 {
            request.headers_mut().insert(
                header::AUTHORIZATION,
                "Basic public-fixture".parse().unwrap(),
            );
        }
        let response = send(&app, request).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(response.headers()[header::PRAGMA], "no-cache");
        assert_eq!(
            response.headers()[header::X_CONTENT_TYPE_OPTIONS],
            "nosniff"
        );
        assert!(
            response
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .is_none()
        );
        assert_eq!(
            serde_json::from_str::<Value>(&text(response).await).unwrap(),
            json!({"error": expected})
        );
    }
    let request = Request::post("/oauth/token")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from("x".repeat(8193)))
        .unwrap();
    let response = send(&app, request).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        serde_json::from_str::<Value>(&text(response).await).unwrap()["error"],
        "invalid_request"
    );
}
#[tokio::test]
async fn enabled_readiness_and_disabled_no_key_io_are_enforced() {
    let (_key, config) = fixture("http://127.0.0.1:9");
    for case in 0..4 {
        let (_case_key, mut bad) = fixture("http://127.0.0.1:9");
        match case {
            0 => bad.ui.enabled = false,
            1 => bad.oauth.signing = None,
            2 => bad.oauth.clients.clear(),
            _ => {
                bad.ui.browser_session.as_mut().unwrap().public_origin =
                    serde_json::from_value(json!("https://different.example.test")).unwrap()
            }
        };
        assert!(startup::build_app(Arc::new(bad)).await.is_err());
    }
    let mut off = config;
    off.oauth.enabled = false;
    off.oauth.signing.as_mut().unwrap().keys[0].private_key_file =
        Some("/nonexistent/test-key.pem".into());
    let (app, _) = startup::build_app(Arc::new(off)).await.unwrap();
    for path in [
        "/oauth/authorize",
        "/oauth/token",
        "/oauth/continue",
        "/oauth/consent",
        "/oauth/jwks",
        "/.well-known/oauth-authorization-server",
    ] {
        assert_eq!(
            get(&app, path, &Jar::default()).await.status(),
            StatusCode::NOT_FOUND
        );
    }
}

struct Container(String);
impl Drop for Container {
    fn drop(&mut self) {
        let _ = Command::new("docker").args(["rm", "-f", &self.0]).output();
    }
}
fn docker(args: &[&str]) -> String {
    let output = Command::new("docker").args(args).output().unwrap();
    assert!(output.status.success());
    String::from_utf8(output.stdout).unwrap().trim().into()
}
#[tokio::test]
#[ignore = "requires Docker; creates and removes its own Valkey fixture"]
async fn disposable_valkey_http_oauth_cross_replica_flow() {
    let mut mock = mockito::Server::new_async().await;
    let upstream = mock
        .mock("GET", "/who-am-i")
        .match_query(mockito::Matcher::UrlEncoded(
            "token".into(),
            "public-key".into(),
        ))
        .with_status(200)
        .with_body(json!({"uid": "public-user"}).to_string())
        .expect(1)
        .create_async()
        .await;
    let container = Container(docker(&[
        "run",
        "--rm",
        "-d",
        "-p",
        "127.0.0.1::6379",
        "valkey/valkey:8",
        "sleep",
        "infinity",
    ]));
    let password = uuid::Uuid::new_v4().simple().to_string();
    let mut configure = Command::new("docker")
        .args([
            "exec",
            "-i",
            &container.0,
            "sh",
            "-c",
            "umask 077; cat > /tmp/http-fixture.conf",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    write!(
        configure.stdin.take().unwrap(),
        "requirepass {password}\nsave \"\"\nappendonly no\n"
    )
    .unwrap();
    assert!(configure.wait().unwrap().success());
    docker(&[
        "exec",
        "-d",
        &container.0,
        "valkey-server",
        "/tmp/http-fixture.conf",
    ]);
    let (_key, mut config) = fixture(&mock.url());
    config.ui.browser_session.as_mut().unwrap().backend = BrowserBackendConfig::Valkey {
        url: format!("redis://{}/0", docker(&["port", &container.0, "6379/tcp"])),
        key_prefix: format!("authotron:http:{}", uuid::Uuid::new_v4().simple()),
        password,
        connect_timeout_ms: 2000,
        operation_timeout_ms: 1000,
    };
    let config = Arc::new(config);
    let mut ready = None;
    for _ in 0..50 {
        if let Ok((app, _)) = startup::build_app(config.clone()).await {
            ready = Some(app);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let a = ready.unwrap();
    let (b, _) = startup::build_app(config.clone()).await.unwrap();
    complete(&a, &b, false).await;
    complete(&a, &b, true).await;
    consent_binding_recovery(&b).await;
    // An ACL failure is storage unavailability, not a missing browser flow.
    // Use an authenticated administrative fixture connection to restore access
    // before assertions; application requests must retain both binding cookies.
    let mut jar = Jar::default();
    let (csrf, tx) = login_form(&a, &mut jar, "/login/method/password").await;
    let response = send(
        &a,
        post(
            "/login/method/password",
            &jar,
            &[
                ("csrf", &csrf),
                ("oauth_transaction", &tx),
                ("username", "alice"),
                ("password", "päss:秘密"),
            ],
            Some(ORIGIN),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    jar.update(&response);
    let (csrf, tx) = consent_page(&b, &jar).await;
    let BrowserBackendConfig::Valkey { url, password, .. } =
        &config.ui.browser_session.as_ref().unwrap().backend
    else {
        unreachable!()
    };
    let mut connection = redis::IntoConnectionInfo::into_connection_info(url.as_str()).unwrap();
    connection.redis.password = Some(password.clone());
    let client = redis::Client::open(connection).unwrap();
    let mut admin = client.get_multiplexed_async_connection().await.unwrap();
    let _: () = redis::cmd("ACL")
        .arg(&["SETUSER", "default", "-eval"])
        .query_async(&mut admin)
        .await
        .unwrap();
    let mut responses = Vec::new();
    for path in [
        "/login",
        "/login/method/password",
        "/login/method/ecmwf-api-key",
    ] {
        responses.push(get(&b, path, &jar).await);
    }
    let _: () = redis::cmd("ACL")
        .arg(&["SETUSER", "default", "+eval"])
        .query_async(&mut admin)
        .await
        .unwrap();
    for response in responses {
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(!response.headers().contains_key(header::SET_COOKIE));
        assert!(!response.headers().contains_key(header::LOCATION));
    }
    let response = send(
        &a,
        post(
            "/oauth/consent",
            &jar,
            &[
                ("csrf", &csrf),
                ("oauth_transaction", &tx),
                ("decision", "deny"),
            ],
            Some(ORIGIN),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let (_isolated_key, mut isolated) = fixture(&mock.url());
    isolated.ui.browser_session.as_mut().unwrap().backend =
        config.ui.browser_session.as_ref().unwrap().backend.clone();
    isolate_clients(&mut isolated);
    let isolated = Arc::new(isolated);
    let (a, _) = startup::build_app(isolated.clone()).await.unwrap();
    let (b, _) = startup::build_app(isolated).await.unwrap();
    admission_isolation(&a, &b).await;
    upstream.assert_async().await;
}

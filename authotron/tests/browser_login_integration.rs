use authotron::{config::ConfigV2, startup};
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use cookie::Cookie;
use mockito::{Matcher, Server};
use serde_json::json;
use std::sync::Arc;
use tower::ServiceExt;
use tracing::instrument::WithSubscriber;

#[derive(Clone)]
struct CapturedLogs(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for CapturedLogs {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

const ORIGIN: &str = "https://login.example.test";
const KEY: &str = "public&+#=?fixture";
const PATH: &str = "/login/ecmwf-api-key";

// Public synthetic credentials and explicit loopback upstream; no local config reads.
fn config(uri: &str, enabled: bool) -> ConfigV2 {
    serde_json::from_value(json!({
        "store": {"enabled": false}, "services": [], "augmenters": [],
        "providers": [{"type": "ecmwf-api", "name": "ECMWF API Provider", "realm": "ecmwf", "uri": uri}],
        "server": {"host": "127.0.0.1", "port": 0}, "metrics": {"enabled": false},
        "jwt": {"iss": "public-test", "exp": 300, "secret": "public-test-only-secret"},
        "logging": {"level": "warn", "format": "console"},
        "ui": {"enabled": enabled, "branding": {"application_name": "Public <Application>"},
            "sign_in_actions": [{"label": "Continue with SSO", "start_url": "/sso/start"}],
            "ecmwf_api_key": {"provider_name": "ECMWF API Provider"}, "browser_session": {"public_origin": ORIGIN, "backend": {"type": "memory"}}}
    })).unwrap()
}

async fn request(app: Router, request: Request<Body>) -> Response {
    app.oneshot(request).await.unwrap()
}

async fn get(app: Router, path: &str) -> Response {
    request(app, Request::get(path).body(Body::empty()).unwrap()).await
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

fn response_cookie(response: &Response, name: &str) -> Option<Cookie<'static>> {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|h| Cookie::parse(h.to_str().unwrap().to_owned()).ok())
        .find(|cookie| cookie.name() == name)
}

async fn transaction(app: Router) -> (String, String) {
    transaction_for(app, PATH).await
}

async fn transaction_for(app: Router, path: &str) -> (String, String) {
    let response = get(app, path).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert!(
        response.headers()[header::CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap()
            .contains("form-action 'self'")
    );
    let cookie = response_cookie(&response, "__Host-authotron_form").unwrap();
    assert_eq!(cookie.secure(), Some(true));
    assert_eq!(cookie.http_only(), Some(true));
    assert!(cookie.domain().is_none());
    let html = text(response).await;
    assert!(html.contains("type=\"password\""));
    if path == PATH {
        assert!(html.contains("autocomplete=\"off\""));
        assert!(html.contains("maxlength=\"512\""));
    }
    assert!(html.contains("Public &lt;Application&gt;"));
    assert!(html.contains("Powered by "));
    let csrf = html
        .split("name=\"csrf\" value=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .to_owned();
    (
        cookie.to_string().split(';').next().unwrap().to_owned(),
        csrf,
    )
}

fn post(
    cookie: Option<&str>,
    csrf: Option<&str>,
    origin: Option<&str>,
    key: &str,
) -> Request<Body> {
    let mut request =
        Request::post(PATH).header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, cookie);
    }
    if let Some(origin) = origin {
        request = request.header(header::ORIGIN, origin);
    }
    let mut form = url::form_urlencoded::Serializer::new(String::new());
    form.append_pair("api_key", key);
    if let Some(csrf) = csrf {
        form.append_pair("csrf", csrf);
    }
    request.body(Body::from(form.finish())).unwrap()
}

#[tokio::test]
async fn verified_login_uses_uncached_query_rotated_secure_cookie_and_safe_identity() {
    let mut server = Server::new_async().await;
    let mock = server
        .mock("GET", "/who-am-i")
        .match_query(Matcher::UrlEncoded("token".into(), KEY.into()))
        .with_status(200)
        .with_body(
            json!({"uid": "public-user", "email": "public@example.test", "token": KEY}).to_string(),
        )
        .expect(2)
        .create_async()
        .await;
    let (app, _) = startup::build_app(Arc::new(config(&server.url(), true)))
        .await
        .unwrap();
    let login = text(get(app.clone(), "/login").await).await;
    assert!(login.contains("href=\"/login/ecmwf-api-key\""));
    assert!(login.contains("href=\"/sso/start\""));
    let mut previous = None;
    for _ in 0..2 {
        let (form_cookie, csrf) = transaction(app.clone()).await;
        let cookie = previous.as_ref().map_or(form_cookie.clone(), |sid| {
            format!("{form_cookie}; __Host-authotron_session={sid}")
        });
        let response = request(
            app.clone(),
            post(
                Some(&cookie),
                Some(&csrf),
                Some(ORIGIN),
                &format!(" {KEY} "),
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(response.headers()[header::LOCATION], "/login/account");
        assert!(!response.headers().contains_key(header::AUTHORIZATION));
        let session = response_cookie(&response, "__Host-authotron_session").unwrap();
        assert_eq!(session.secure(), Some(true));
        assert_eq!(session.http_only(), Some(true));
        assert_eq!(session.same_site(), Some(cookie::SameSite::Lax));
        assert_eq!(session.path(), Some("/"));
        assert!(session.domain().is_none());
        assert_eq!(session.max_age().unwrap().whole_seconds(), 300);
        assert!(!session.to_string().contains(KEY));
        if let Some(old) = previous {
            let response = request(
                app.clone(),
                Request::get("/login/account")
                    .header(header::COOKIE, format!("__Host-authotron_session={old}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
            assert_eq!(response.status(), StatusCode::SEE_OTHER);
        }
        let session_cookie = format!("__Host-authotron_session={}", session.value());
        let response = request(
            app.clone(),
            Request::get("/login/account")
                .header(header::COOKIE, &session_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let html = text(response).await;
        for expected in [
            "public-user",
            "ecmwf",
            "public@example.test",
            "Session expires at",
            "key re-entry",
            "handoff is separate",
        ] {
            assert!(html.contains(expected));
        }
        assert!(!html.contains(KEY));
        let response = request(
            app.clone(),
            Request::get("/login")
                .header(header::COOKIE, session_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let chooser = text(response).await;
        assert!(chooser.contains("href=\"/login/ecmwf-api-key\""));
        assert!(chooser.contains("href=\"/sso/start\""));
        let mut api_request = Request::get("/authenticate")
            .header(
                header::COOKIE,
                format!("__Host-authotron_session={}", session.value()),
            )
            .body(Body::empty())
            .unwrap();
        api_request
            .extensions_mut()
            .insert(axum::extract::ConnectInfo(
                "127.0.0.1:12345".parse::<std::net::SocketAddr>().unwrap(),
            ));
        let api_response = request(app.clone(), api_request).await;
        assert_eq!(api_response.status(), StatusCode::UNAUTHORIZED);
        assert!(!api_response.headers().contains_key(header::AUTHORIZATION));
        previous = Some(session.value().to_owned());
    }
    mock.assert_async().await;
}

#[tokio::test]
async fn credential_and_account_pages_suppress_external_branding_requests() {
    let mut server = Server::new_async().await;
    let mock = server
        .mock("GET", "/who-am-i")
        .match_query(Matcher::Any)
        .with_status(200)
        .with_body(r#"{"uid":"public-user"}"#)
        .create_async()
        .await;
    let mut settings = config(&server.url(), true);
    settings.ui.branding.logo_url = Some(
        "https://external.example.org/logo.png"
            .to_owned()
            .try_into()
            .unwrap(),
    );
    let (app, _) = startup::build_app(Arc::new(settings)).await.unwrap();
    let chooser = get(app.clone(), "/login").await;
    assert_eq!(chooser.headers()[header::REFERRER_POLICY], "strict-origin");
    let html = text(chooser).await;
    assert!(!html.contains("external.example.org"));
    assert!(html.contains("class=\"application-wordmark\""));
    let form = get(app.clone(), PATH).await;
    assert_eq!(form.headers()[header::REFERRER_POLICY], "strict-origin");
    let policy = form.headers()[header::CONTENT_SECURITY_POLICY]
        .to_str()
        .unwrap();
    assert!(policy.contains("img-src 'self';"));
    assert!(!policy.contains("https:"));
    let html = text(form).await;
    assert!(!html.contains("external.example.org"));
    assert!(html.contains("class=\"application-wordmark\""));
    let (cookie, csrf) = transaction(app.clone()).await;
    let response = request(
        app.clone(),
        post(Some(&cookie), Some(&csrf), Some(ORIGIN), "public-fixture"),
    )
    .await;
    let session = response_cookie(&response, "__Host-authotron_session").unwrap();
    let response = request(
        app,
        Request::get("/login/account")
            .header(
                header::COOKIE,
                format!("__Host-authotron_session={}", session.value()),
            )
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    let html = text(response).await;
    assert!(!html.contains("external.example.org"));
    mock.assert_async().await;
}

#[tokio::test]
async fn duplicate_key_fields_do_not_verify_and_forwarded_hosts_do_not_set_authority() {
    let mut server = Server::new_async().await;
    let mock = server
        .mock("GET", "/who-am-i")
        .match_query(Matcher::Any)
        .with_status(200)
        .with_body(r#"{"uid":"public-user"}"#)
        .expect(1)
        .create_async()
        .await;
    let (app, _) = startup::build_app(Arc::new(config(&server.url(), true)))
        .await
        .unwrap();
    let (cookie, csrf) = transaction(app.clone()).await;
    let duplicate = Request::post(PATH)
        .header(header::ORIGIN, ORIGIN)
        .header(header::COOKIE, &cookie)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(format!(
            "api_key=public-one&api_key=public-two&csrf={csrf}"
        )))
        .unwrap();
    let response = request(app.clone(), duplicate).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(response_cookie(&response, "__Host-authotron_session").is_none());
    let (cookie, csrf) = transaction(app.clone()).await;
    let mut spoofed = post(Some(&cookie), Some(&csrf), Some(ORIGIN), "public-key");
    spoofed
        .headers_mut()
        .insert(header::HOST, "untrusted.example".parse().unwrap());
    spoofed
        .headers_mut()
        .insert("x-forwarded-host", "untrusted.example".parse().unwrap());
    spoofed
        .headers_mut()
        .insert("x-forwarded-proto", "http".parse().unwrap());
    let response = request(app, spoofed).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers()[header::LOCATION], "/login/account");
    mock.assert_async().await;
}

#[tokio::test]
async fn csrf_cookie_and_origin_fail_closed_without_verification_or_session() {
    let mut server = Server::new_async().await;
    let mock = server
        .mock("GET", "/who-am-i")
        .match_query(Matcher::Any)
        .expect(0)
        .create_async()
        .await;
    let (app, _) = startup::build_app(Arc::new(config(&server.url(), true)))
        .await
        .unwrap();
    for failure in [
        "missing-origin",
        "foreign-origin",
        "missing-cookie",
        "wrong-cookie",
        "missing-csrf",
        "wrong-csrf",
    ] {
        let (cookie, csrf) = transaction(app.clone()).await;
        let origin = match failure {
            "missing-origin" => None,
            "foreign-origin" => Some("https://foreign.example.test"),
            _ => Some(ORIGIN),
        };
        let bound = match failure {
            "missing-cookie" => None,
            "wrong-cookie" => Some("__Host-authotron_form=wrong"),
            _ => Some(cookie.as_str()),
        };
        let csrf = match failure {
            "missing-csrf" => None,
            "wrong-csrf" => Some("wrong"),
            _ => Some(csrf.as_str()),
        };
        let response = request(app.clone(), post(bound, csrf, origin, KEY)).await;
        assert!(response.status().is_client_error(), "{failure}");
        assert!(response_cookie(&response, "__Host-authotron_session").is_none());
        if origin != Some(ORIGIN) {
            assert!(!response.headers().contains_key(header::SET_COOKIE));
        }
        let html = text(response).await;
        assert!(html.contains("Key invalid or could not be verified"));
        assert!(!html.contains(KEY));
    }
    mock.assert_async().await;
}

#[tokio::test]
async fn concurrent_double_submit_verifies_once_and_replay_fails() {
    let mut server = Server::new_async().await;
    let mock = server
        .mock("GET", "/who-am-i")
        .match_query(Matcher::UrlEncoded("token".into(), KEY.into()))
        .with_status(200)
        .with_body(r#"{"uid":"public-user"}"#)
        .expect(1)
        .create_async()
        .await;
    let (app, _) = startup::build_app(Arc::new(config(&server.url(), true)))
        .await
        .unwrap();
    let (cookie, csrf) = transaction(app.clone()).await;
    let (a, b) = tokio::join!(
        request(
            app.clone(),
            post(Some(&cookie), Some(&csrf), Some(ORIGIN), KEY)
        ),
        request(
            app.clone(),
            post(Some(&cookie), Some(&csrf), Some(ORIGIN), KEY)
        )
    );
    assert!(
        (a.status() == StatusCode::SEE_OTHER && b.status() == StatusCode::FORBIDDEN)
            || (b.status() == StatusCode::SEE_OTHER && a.status() == StatusCode::FORBIDDEN)
    );
    let response = request(app, post(Some(&cookie), Some(&csrf), Some(ORIGIN), KEY)).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(response_cookie(&response, "__Host-authotron_session").is_none());
    mock.assert_async().await;
}

#[tokio::test]
async fn invalid_identity_outage_and_redirect_do_not_issue_sessions_or_echo_keys() {
    for (status, body) in [
        (403, KEY.to_owned()),
        (200, "{}".into()),
        (200, KEY.into()),
        (500, KEY.into()),
        (302, KEY.into()),
        (200, json!({"uid": KEY}).to_string()),
        (200, json!({"uid": "public-user", "email": KEY}).to_string()),
    ] {
        let mut server = Server::new_async().await;
        let mock = server
            .mock("GET", "/who-am-i")
            .match_query(Matcher::UrlEncoded("token".into(), KEY.into()))
            .with_status(status)
            .with_header("location", "/redirected")
            .with_body(body)
            .expect(1)
            .create_async()
            .await;
        let redirect = server
            .mock("GET", "/redirected")
            .expect(0)
            .create_async()
            .await;
        let (app, _) = startup::build_app(Arc::new(config(&server.url(), true)))
            .await
            .unwrap();
        let (cookie, csrf) = transaction(app.clone()).await;
        let response = request(app, post(Some(&cookie), Some(&csrf), Some(ORIGIN), KEY)).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(response_cookie(&response, "__Host-authotron_session").is_none());
        assert!(response_cookie(&response, "__Host-authotron_form").is_some());
        assert!(!response.headers().contains_key(header::LOCATION));
        let html = text(response).await;
        assert!(html.contains("Key invalid or could not be verified"));
        assert!(!html.contains(KEY));
        mock.assert_async().await;
        redirect.assert_async().await;
    }
}

#[tokio::test]
async fn oversized_and_malformed_forms_are_sanitized_and_do_not_verify() {
    let mut server = Server::new_async().await;
    let mock = server
        .mock("GET", "/who-am-i")
        .match_query(Matcher::Any)
        .expect(0)
        .create_async()
        .await;
    let (app, _) = startup::build_app(Arc::new(config(&server.url(), true)))
        .await
        .unwrap();
    for (key, expected) in [
        ("x".repeat(9000), StatusCode::PAYLOAD_TOO_LARGE),
        ("x".repeat(513), StatusCode::UNAUTHORIZED),
        ("public fixture".into(), StatusCode::UNAUTHORIZED),
    ] {
        let (cookie, csrf) = transaction(app.clone()).await;
        let response = request(
            app.clone(),
            post(Some(&cookie), Some(&csrf), Some(ORIGIN), &key),
        )
        .await;
        assert_eq!(response.status(), expected);
        assert!(response_cookie(&response, "__Host-authotron_session").is_none());
        assert!(!text(response).await.contains(&key));
    }
    let (cookie, csrf) = transaction(app.clone()).await;
    let response = request(
        app.clone(),
        Request::post(PATH)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::ORIGIN, ORIGIN)
            .header(header::COOKIE, &cookie)
            .body(Body::from(format!("api_key={KEY}&csrf={csrf}&csrf={KEY}")))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(!text(response).await.contains(KEY));
    let replay = request(app, post(Some(&cookie), Some(&csrf), Some(ORIGIN), KEY)).await;
    assert_eq!(replay.status(), StatusCode::FORBIDDEN);
    mock.assert_async().await;
}

#[tokio::test]
async fn disabled_routes_and_missing_session_fail_closed() {
    for enabled in [false, true] {
        let mut cfg = config("http://127.0.0.1:1", enabled);
        if enabled {
            cfg.ui.ecmwf_api_key = None;
        }
        let (app, _) = startup::build_app(Arc::new(cfg)).await.unwrap();
        for path in [PATH, "/login/account"] {
            assert_eq!(get(app.clone(), path).await.status(), StatusCode::NOT_FOUND);
        }
        assert_eq!(
            request(app, post(None, None, None, KEY)).await.status(),
            StatusCode::NOT_FOUND
        );
    }
    let (app, _) = startup::build_app(Arc::new(config("http://127.0.0.1:1", true)))
        .await
        .unwrap();
    let response = get(app, "/login/account").await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers()[header::LOCATION], "/login");
}

#[tokio::test]
async fn invalid_browser_configuration_fails_startup_before_store_creation() {
    let mut cfg = config("http://127.0.0.1:1", true);
    cfg.providers.clear();
    assert!(startup::build_app(Arc::new(cfg)).await.is_err());
    let mut cfg = config("http://127.0.0.1:1", true);
    cfg.ui.browser_session.as_mut().unwrap().public_origin =
        "/not-an-origin".to_owned().try_into().unwrap();
    assert!(startup::build_app(Arc::new(cfg)).await.is_err());
}

#[tokio::test]
async fn transport_failure_is_generic_and_key_never_enters_url_response() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let (app, _) = startup::build_app(Arc::new(config(&format!("http://{address}"), true)))
        .await
        .unwrap();
    let (cookie, csrf) = transaction(app.clone()).await;
    let logs = CapturedLogs(Arc::new(std::sync::Mutex::new(Vec::new())));
    let writer = logs.clone();
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(move || writer.clone())
        .finish();
    let response = request(app, post(Some(&cookie), Some(&csrf), Some(ORIGIN), KEY))
        .with_subscriber(subscriber)
        .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(response_cookie(&response, "__Host-authotron_session").is_none());
    let html = text(response).await;
    assert!(!html.contains(KEY));
    assert!(!html.contains("who-am-i"));
    assert!(!html.contains("token="));
    let logs = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    assert!(logs.contains("providers.ecmwf_api.query.started"));
    assert!(!logs.contains(KEY));
    assert!(!logs.contains("token="));
    assert!(!logs.contains("public%26%2B%23%3D%3Ffixture"));
}

const BASIC: &str = "/login/basic";
const PASSWORD: &str = " 密码: public&+fixture ";

fn combined_config(uri: &str) -> ConfigV2 {
    let mut value = serde_json::to_value(config(uri, true)).unwrap();
    value["ui"]["basic"] = json!({"provider_name": "Local"});
    value["providers"].as_array_mut().unwrap().extend([
        json!({"type": "plain", "name": "Local", "realm": "local", "users": [
            {"username": "alice", "password": PASSWORD, "roles": ["configured"]},
            {"username": "bob", "password": "public-bob", "roles": []}
        ]}),
        // Same realm, different name: direct Basic must never fall through to it.
        json!({"type": "plain", "name": "Other", "realm": "local", "users": [
            {"username": "alice", "password": "other-password", "roles": ["wrong-provider"]}
        ]}),
    ]);
    let mut augmenters = Vec::new();
    for (realm, username) in [("local", "alice"), ("ecmwf", "public-user")] {
        augmenters.extend([
            json!({"type": "plain", "name": "base", "realm": realm, "roles": {"base": [username]}}),
            json!({"type": "plain_advanced", "name": "derived", "realm": realm,
                "match": {"role": ["base"]}, "augment": {"roles": ["<derived>"],
                    "attributes": {"display_name": "<Display & name>", "email": "public@example.test",
                        "password": "hidden-password", "api_key": "hidden-key", "arbitrary": "hidden-attribute"}}}),
            json!({"type": "plain_advanced", "name": "sequence", "realm": realm,
                "match": {"role": ["<derived>"]}, "augment": {"roles": ["final"]}}),
        ]);
    }
    value["augmenters"] = json!(augmenters);
    serde_json::from_value(value).unwrap()
}

fn basic_post(cookie: &str, csrf: &str, username: &str, password: &str) -> Request<Body> {
    let body = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("username", username)
        .append_pair("password", password)
        .append_pair("csrf", csrf)
        .finish();
    Request::post(BASIC)
        .header(header::ORIGIN, ORIGIN)
        .header(header::COOKIE, cookie)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap()
}

#[tokio::test]
async fn both_direct_flows_store_augmented_identities_and_render_only_safe_escaped_fields() {
    let mut server = Server::new_async().await;
    let mock = server
        .mock("GET", "/who-am-i")
        .match_query(Matcher::Any)
        .with_body(r#"{"uid":"public-user"}"#)
        .expect(2)
        .create_async()
        .await;
    let (app, state) = startup::build_app(Arc::new(combined_config(&server.url())))
        .await
        .unwrap();
    let chooser = text(get(app.clone(), "/login").await).await;
    for link in [BASIC, PATH, "/sso/start"] {
        assert!(chooser.contains(link));
    }
    let mut sessions = Vec::new();
    for path in [BASIC, PATH, BASIC, PATH] {
        let (cookie, csrf) = transaction_for(app.clone(), path).await;
        let response = request(
            app.clone(),
            if path == BASIC {
                basic_post(&cookie, &csrf, "alice", PASSWORD)
            } else {
                post(Some(&cookie), Some(&csrf), Some(ORIGIN), KEY)
            },
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert!(!response.headers().contains_key(header::WWW_AUTHENTICATE));
        assert!(!response.headers().contains_key(header::AUTHORIZATION));
        let sid = response_cookie(&response, "__Host-authotron_session")
            .unwrap()
            .value()
            .to_owned();
        let user = state.browser.lookup(&sid).await.unwrap().unwrap().user;
        for role in ["base", "<derived>", "final"] {
            assert!(user.roles.contains(&role.to_owned()));
        }
        assert_eq!(user.realm, if path == BASIC { "local" } else { "ecmwf" });
        assert_eq!(user.attributes["display_name"], "<Display & name>");
        assert_eq!(user.attributes.len(), 2);
        assert!(user.scopes.is_empty());
        let response = request(
            app.clone(),
            Request::get("/login/account")
                .header(header::COOKIE, format!("__Host-authotron_session={sid}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        let html = text(response).await;
        for expected in [
            "&lt;derived&gt;",
            "&lt;Display &amp; name&gt;",
            "public@example.test",
            "final",
        ] {
            assert!(html.contains(expected));
        }
        for secret in [
            PASSWORD,
            KEY,
            "hidden-password",
            "hidden-key",
            "hidden-attribute",
            "<derived>",
        ] {
            assert!(!html.contains(secret));
        }
        sessions.push(sid);
    }
    for sid in &sessions {
        assert!(state.browser.lookup(sid).await.unwrap().is_some());
    }
    assert_ne!(sessions[0], sessions[2]);
    mock.assert_async().await;
}

#[tokio::test]
async fn invalid_basic_is_generic_bounded_and_never_uses_another_provider_or_logs_password() {
    let (app, _) = startup::build_app(Arc::new(combined_config("http://127.0.0.1:1")))
        .await
        .unwrap();
    let logs = CapturedLogs(Arc::new(std::sync::Mutex::new(Vec::new())));
    let writer = logs.clone();
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(move || writer.clone())
        .finish();
    let response = async {
        let (cookie, csrf) = transaction_for(app.clone(), BASIC).await;
        request(
            app.clone(),
            basic_post(&cookie, &csrf, "alice", PASSWORD.trim()),
        )
        .await
    }
    .with_subscriber(subscriber)
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(!text(response).await.contains(PASSWORD.trim()));
    assert!(
        !String::from_utf8(logs.0.lock().unwrap().clone())
            .unwrap()
            .contains(PASSWORD.trim())
    );
    for (username, password, status) in [
        (
            "alice",
            "other-password".to_owned(),
            StatusCode::UNAUTHORIZED,
        ),
        ("unknown", PASSWORD.to_owned(), StatusCode::UNAUTHORIZED),
        ("alice", "x".repeat(1025), StatusCode::UNAUTHORIZED),
        ("alice", "x".repeat(9000), StatusCode::PAYLOAD_TOO_LARGE),
        ("alice:other", PASSWORD.to_owned(), StatusCode::UNAUTHORIZED),
        ("alice", String::new(), StatusCode::UNAUTHORIZED),
    ] {
        let (cookie, csrf) = transaction_for(app.clone(), BASIC).await;
        let response = request(app.clone(), basic_post(&cookie, &csrf, username, &password)).await;
        assert_eq!(response.status(), status);
        assert!(!response.headers().contains_key(header::WWW_AUTHENTICATE));
        assert!(response_cookie(&response, "__Host-authotron_session").is_none());
        assert!(
            text(response)
                .await
                .contains("Credentials invalid or could not be verified")
        );
    }
    // Query credentials are not consumed by the GET form.
    let html = text(get(app, "/login/basic?username=alice&password=query-secret").await).await;
    assert!(!html.contains("query-secret"));
}

#[tokio::test]
async fn basic_rejects_forged_duplicate_and_cross_flow_fields_and_enforces_exact_origin() {
    let (app, _) = startup::build_app(Arc::new(combined_config("http://127.0.0.1:1")))
        .await
        .unwrap();
    for extra in [
        "roles=admin",
        "realm=ecmwf",
        "provider_name=Other",
        "attributes=secret",
        "username=bob",
        "password=other",
        "csrf=forged",
        "api_key=public",
    ] {
        let (cookie, csrf) = transaction_for(app.clone(), BASIC).await;
        let mut req = basic_post(&cookie, &csrf, "alice", PASSWORD);
        let body = to_bytes(std::mem::replace(req.body_mut(), Body::empty()), 8192)
            .await
            .unwrap();
        *req.body_mut() = Body::from(format!(
            "{}&{extra}",
            String::from_utf8(body.to_vec()).unwrap()
        ));
        let response = request(app.clone(), req).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{extra}");
        assert!(response_cookie(&response, "__Host-authotron_session").is_none());
        assert_eq!(
            request(app.clone(), basic_post(&cookie, &csrf, "alice", PASSWORD))
                .await
                .status(),
            StatusCode::FORBIDDEN
        );
    }
    for source in [BASIC, PATH] {
        let (cookie, csrf) = transaction_for(app.clone(), source).await;
        let cross = if source == PATH {
            basic_post(&cookie, &csrf, "alice", PASSWORD)
        } else {
            post(Some(&cookie), Some(&csrf), Some(ORIGIN), KEY)
        };
        assert_eq!(
            request(app.clone(), cross).await.status(),
            StatusCode::FORBIDDEN
        );
    }
    for origin in [
        None,
        Some("null"),
        Some("https://foreign.example.test"),
        Some("https://login.example.test/"),
    ] {
        let (cookie, csrf) = transaction_for(app.clone(), BASIC).await;
        let mut req = basic_post(&cookie, &csrf, "alice", PASSWORD);
        req.headers_mut().remove(header::ORIGIN);
        if let Some(origin) = origin {
            req.headers_mut()
                .insert(header::ORIGIN, origin.parse().unwrap());
        }
        let response = request(app.clone(), req).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(!response.headers().contains_key(header::SET_COOKIE));
    }
    let (cookie, csrf) = transaction_for(app.clone(), BASIC).await;
    let mut req = basic_post(&cookie, &csrf, "alice", PASSWORD);
    req.headers_mut()
        .append(header::ORIGIN, ORIGIN.parse().unwrap());
    assert_eq!(
        request(app.clone(), req).await.status(),
        StatusCode::FORBIDDEN
    );
    for failure in ["missing-cookie", "duplicate-cookie", "wrong-csrf"] {
        let (cookie, csrf) = transaction_for(app.clone(), BASIC).await;
        let mut req = basic_post(
            &cookie,
            if failure == "wrong-csrf" {
                "wrong"
            } else {
                &csrf
            },
            "alice",
            PASSWORD,
        );
        if failure == "missing-cookie" {
            req.headers_mut().remove(header::COOKIE);
        }
        if failure == "duplicate-cookie" {
            req.headers_mut()
                .append(header::COOKIE, cookie.parse().unwrap());
        }
        assert_eq!(
            request(app.clone(), req).await.status(),
            StatusCode::FORBIDDEN
        );
    }
}

#[tokio::test]
async fn basic_one_use_rotation_and_independent_users_preserve_session_isolation() {
    let (app, state) = startup::build_app(Arc::new(combined_config("http://127.0.0.1:1")))
        .await
        .unwrap();
    let (cookie, csrf) = transaction_for(app.clone(), BASIC).await;
    let (a, b) = tokio::join!(
        request(app.clone(), basic_post(&cookie, &csrf, "alice", PASSWORD)),
        request(app.clone(), basic_post(&cookie, &csrf, "alice", PASSWORD))
    );
    let success = if a.status() == StatusCode::SEE_OTHER {
        assert_eq!(b.status(), StatusCode::FORBIDDEN);
        a
    } else {
        assert_eq!(a.status(), StatusCode::FORBIDDEN);
        b
    };
    assert_eq!(success.status(), StatusCode::SEE_OTHER);
    let alice = response_cookie(&success, "__Host-authotron_session")
        .unwrap()
        .value()
        .to_owned();
    let (cookie, csrf) = transaction_for(app.clone(), BASIC).await;
    let response = request(app.clone(), basic_post(&cookie, &csrf, "bob", "public-bob")).await;
    let bob = response_cookie(&response, "__Host-authotron_session")
        .unwrap()
        .value()
        .to_owned();
    assert!(
        state
            .browser
            .lookup(&bob)
            .await
            .unwrap()
            .unwrap()
            .user
            .roles
            .is_empty()
    );
    assert!(
        state
            .browser
            .lookup(&alice)
            .await
            .unwrap()
            .unwrap()
            .user
            .roles
            .contains(&"final".to_owned())
    );
    let (cookie, csrf) = transaction_for(app.clone(), BASIC).await;
    let response = request(
        app.clone(),
        basic_post(
            &format!("{cookie}; __Host-authotron_session={alice}"),
            &csrf,
            "alice",
            PASSWORD,
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(state.browser.lookup(&alice).await.unwrap().is_none());
    assert!(state.browser.lookup(&bob).await.unwrap().is_some());
    let mut req = Request::get("/whoami")
        .header(header::COOKIE, format!("__Host-authotron_session={bob}"))
        .body(Body::empty())
        .unwrap();
    req.extensions_mut().insert(axum::extract::ConnectInfo(
        "127.0.0.1:12345".parse::<std::net::SocketAddr>().unwrap(),
    ));
    assert_eq!(request(app, req).await.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn basic_configuration_requires_shared_session_unique_correct_provider_and_is_opt_in() {
    for change in [
        "missing-session",
        "missing-provider",
        "wrong-type",
        "duplicate-name",
        "blank-name",
        "bad-ttl",
    ] {
        let mut cfg = combined_config("http://127.0.0.1:1");
        match change {
            "missing-session" => cfg.ui.browser_session = None,
            "missing-provider" => cfg.ui.basic.as_mut().unwrap().provider_name = "missing".into(),
            "wrong-type" => {
                cfg.ui.basic.as_mut().unwrap().provider_name = "ECMWF API Provider".into()
            }
            "duplicate-name" => cfg.providers.push(
                serde_json::from_value(
                    json!({"type": "plain", "name": "Local", "realm": "other", "users": []}),
                )
                .unwrap(),
            ),
            "blank-name" => cfg.ui.basic.as_mut().unwrap().provider_name = " ".into(),
            "bad-ttl" => cfg.ui.browser_session.as_mut().unwrap().session_ttl_seconds = 86401,
            _ => unreachable!(),
        }
        assert!(startup::build_app(Arc::new(cfg)).await.is_err(), "{change}");
    }
    let mut cfg = combined_config("http://127.0.0.1:1");
    cfg.ui.ecmwf_api_key = None;
    let (app, _) = startup::build_app(Arc::new(cfg)).await.unwrap();
    assert_eq!(get(app.clone(), PATH).await.status(), StatusCode::NOT_FOUND);
    let (cookie, csrf) = transaction_for(app.clone(), BASIC).await;
    assert_eq!(
        request(app, basic_post(&cookie, &csrf, "alice", PASSWORD))
            .await
            .status(),
        StatusCode::SEE_OTHER
    );
    for enabled in [true, false] {
        let mut cfg = combined_config("http://127.0.0.1:1");
        cfg.ui.enabled = enabled;
        if enabled {
            cfg.ui.basic = None;
        }
        let (app, _) = startup::build_app(Arc::new(cfg)).await.unwrap();
        assert_eq!(get(app, BASIC).await.status(), StatusCode::NOT_FOUND);
    }
    // Legacy per-flow session settings cannot silently become a second source of truth.
    assert!(
        serde_json::from_value::<ConfigV2>(
            json!({"ui": {"basic": {"provider_name": "Local", "public_origin": ORIGIN}}})
        )
        .is_err()
    );
}

struct BlockingAugmenter {
    entered: Arc<std::sync::atomic::AtomicUsize>,
    release: Arc<tokio::sync::Semaphore>,
}

#[async_trait::async_trait]
impl authotron::augmenters::Augmenter for BlockingAugmenter {
    fn get_name(&self) -> &str {
        "blocking-test"
    }
    fn get_type(&self) -> &str {
        "plain"
    }
    fn get_realm(&self) -> &str {
        "local"
    }
    async fn augment(
        &self,
        user: Arc<futures::lock::Mutex<authotron::models::user::User>>,
    ) -> Result<(), String> {
        self.entered
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let permit = self.release.acquire().await.unwrap();
        permit.forget();
        user.lock().await.roles.push("after-wait".into());
        Ok(())
    }
}

async fn blocking_app() -> (
    Router,
    authotron::state::AppState,
    Arc<std::sync::atomic::AtomicUsize>,
    Arc<tokio::sync::Semaphore>,
) {
    let (app, mut state) = startup::build_app(Arc::new(combined_config("http://127.0.0.1:1")))
        .await
        .unwrap();
    drop(app);
    let entered = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let release = Arc::new(tokio::sync::Semaphore::new(0));
    Arc::get_mut(&mut state.auth)
        .unwrap()
        .augmenters
        .push(Box::new(BlockingAugmenter {
            entered: entered.clone(),
            release: release.clone(),
        }));
    (
        authotron::routes::create_app_router(state.clone()),
        state,
        entered,
        release,
    )
}

#[tokio::test]
async fn shared_admission_covers_augmentation_without_queueing_either_flow() {
    let (app, _, entered, release) = blocking_app().await;
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let (cookie, csrf) = transaction_for(app.clone(), BASIC).await;
        let app = app.clone();
        tasks.push(tokio::spawn(async move {
            request(app, basic_post(&cookie, &csrf, "alice", PASSWORD)).await
        }));
    }
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while entered.load(std::sync::atomic::Ordering::SeqCst) != 8 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    for path in [BASIC, PATH] {
        let (cookie, csrf) = transaction_for(app.clone(), path).await;
        let req = if path == BASIC {
            basic_post(&cookie, &csrf, "alice", PASSWORD)
        } else {
            post(Some(&cookie), Some(&csrf), Some(ORIGIN), KEY)
        };
        let response = request(app.clone(), req).await;
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(response_cookie(&response, "__Host-authotron_session").is_none());
    }
    release.add_permits(8);
    for task in tasks {
        assert_eq!(task.await.unwrap().status(), StatusCode::SEE_OTHER);
    }
    let (cookie, csrf) = transaction_for(app.clone(), BASIC).await;
    release.add_permits(1);
    assert_eq!(
        request(app, basic_post(&cookie, &csrf, "bob", "public-bob"))
            .await
            .status(),
        StatusCode::SEE_OTHER
    );
}

#[tokio::test]
async fn augmentation_timeout_creates_no_session_and_releases_admission() {
    let (app, state, _, release) = blocking_app().await;
    let (cookie, csrf) = transaction_for(app.clone(), BASIC).await;
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(12),
        request(app.clone(), basic_post(&cookie, &csrf, "alice", PASSWORD)),
    )
    .await
    .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(response_cookie(&response, "__Host-authotron_session").is_none());
    assert_eq!(
        request(app.clone(), basic_post(&cookie, &csrf, "alice", PASSWORD))
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    release.add_permits(1);
    let (cookie, csrf) = transaction_for(app.clone(), BASIC).await;
    let response = request(app, basic_post(&cookie, &csrf, "bob", "public-bob")).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let sid = response_cookie(&response, "__Host-authotron_session")
        .unwrap()
        .value()
        .to_owned();
    let user = state.browser.lookup(&sid).await.unwrap().unwrap().user;
    assert_eq!(user.username, "bob");
    assert_eq!(user.roles, ["after-wait"]);
    let metrics = state.metrics.render().unwrap();
    assert!(
        metrics.contains(
            "authotron_browser_login_attempts_total{flow=\"basic\",outcome=\"timeout\"} 1"
        )
    );
    assert!(metrics.contains("authotron_browser_logins_inflight 0"));
}

#[tokio::test]
async fn browser_metrics_record_final_post_outcomes_for_both_flows_without_secrets() {
    let mut server = Server::new_async().await;
    let mock = server
        .mock("GET", "/who-am-i")
        .match_query(Matcher::Any)
        .with_body(r#"{"uid":"public-user"}"#)
        .expect(2)
        .create_async()
        .await;
    for (path, flow) in [(BASIC, "basic"), (PATH, "ecmwf-api-key")] {
        let mut cfg = combined_config(&server.url());
        let settings = cfg.ui.browser_session.as_mut().unwrap();
        settings.max_sessions = 1;
        settings.max_logins_per_window = 3;
        let (app, state) = startup::build_app(Arc::new(cfg)).await.unwrap();
        assert!(
            state
                .metrics
                .render()
                .unwrap()
                .contains("authotron_browser_logins_inflight 0")
        );
        for (valid, status) in [
            (true, StatusCode::SEE_OTHER),
            (true, StatusCode::SERVICE_UNAVAILABLE),
            (false, StatusCode::UNAUTHORIZED),
            (true, StatusCode::TOO_MANY_REQUESTS),
        ] {
            let (cookie, csrf) = transaction_for(app.clone(), path).await;
            let response = request(
                app.clone(),
                if path == BASIC {
                    basic_post(
                        &cookie,
                        &csrf,
                        "alice",
                        if valid {
                            PASSWORD
                        } else {
                            "wrong-secret-fixture"
                        },
                    )
                } else {
                    post(
                        Some(&cookie),
                        Some(&csrf),
                        Some(ORIGIN),
                        if valid { KEY } else { "invalid key" },
                    )
                },
            )
            .await;
            assert_eq!(response.status(), status);
            if status != StatusCode::SEE_OTHER {
                assert!(response_cookie(&response, "__Host-authotron_session").is_none());
            }
        }
        let (cookie, _) = transaction_for(app.clone(), path).await;
        let response = request(
            app.clone(),
            if path == BASIC {
                basic_post(&cookie, "wrong", "alice", PASSWORD)
            } else {
                post(Some(&cookie), Some("wrong"), Some(ORIGIN), KEY)
            },
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        for (origin, status) in [
            (None, StatusCode::FORBIDDEN),
            (Some(ORIGIN), StatusCode::BAD_REQUEST),
        ] {
            let mut builder =
                Request::post(path).header("content-type", "application/x-www-form-urlencoded");
            if let Some(origin) = origin {
                builder = builder.header("origin", origin);
            }
            assert_eq!(
                request(
                    app.clone(),
                    builder
                        .body(Body::from("unexpected=secret-fixture"))
                        .unwrap()
                )
                .await
                .status(),
                status
            );
        }
        let metrics = state.metrics.render().unwrap();
        for outcome in [
            "success",
            "capacity",
            "rejected",
            "limited",
            "csrf",
            "origin",
            "malformed",
        ] {
            assert!(metrics.contains(&format!("authotron_browser_login_attempts_total{{flow=\"{flow}\",outcome=\"{outcome}\"}} 1")), "{flow} {outcome}");
            assert!(metrics.contains(&format!("authotron_browser_login_duration_seconds_count{{flow=\"{flow}\",outcome=\"{outcome}\"}} 1")));
        }
        assert!(metrics.contains("authotron_browser_logins_inflight 0"));
        for secret in [
            KEY,
            PASSWORD,
            "wrong-secret-fixture",
            "public-user",
            "alice",
            &cookie,
            &server.url(),
        ] {
            assert!(!metrics.contains(secret));
        }
        assert!(
            metrics
                .lines()
                .filter(|line| line.starts_with("auth_requests_total{"))
                .all(|line| line.ends_with(" 0")),
            "browser POSTs do not redefine API auth attempts"
        );
    }
    mock.assert_async().await;
}

struct IdentityFixture {
    realm: &'static str,
    identity: authotron::models::user::User,
}

#[async_trait::async_trait]
impl authotron::augmenters::Augmenter for IdentityFixture {
    fn get_name(&self) -> &str {
        "identity-fixture"
    }
    fn get_type(&self) -> &str {
        "plain_advanced"
    }
    fn get_realm(&self) -> &str {
        self.realm
    }
    async fn augment(
        &self,
        user: Arc<futures::lock::Mutex<authotron::models::user::User>>,
    ) -> Result<(), String> {
        *user.lock().await = self.identity.clone();
        Ok(())
    }
}

fn maximum_browser_identity() -> authotron::models::user::User {
    authotron::models::user::User::new(
        "r".repeat(256),
        "u".repeat(256),
        Some(
            (0..64)
                .map(|n| format!("{n:03}{}", "r".repeat(125)))
                .collect(),
        ),
        Some(std::collections::HashMap::from([
            ("ecmwf-email".into(), "e".repeat(320)),
            ("email".into(), "e".repeat(320)),
            ("display_name".into(), "名".repeat(85) + "x"),
            ("hidden".into(), "h".repeat(128 * 1024)),
        ])),
        Some(std::collections::HashMap::from([(
            "hidden".into(),
            vec!["s".repeat(128 * 1024)],
        )])),
        None,
    )
}

#[tokio::test]
async fn both_flows_enforce_post_augmentation_limits_and_retain_only_browser_projection() {
    let mut server = Server::new_async().await;
    let mock = server
        .mock("GET", "/who-am-i")
        .match_query(Matcher::Any)
        .with_body(r#"{"uid":"public-user"}"#)
        .expect(10)
        .create_async()
        .await;
    for path in [BASIC, PATH] {
        for excess in [
            None,
            Some("username"),
            Some("blank-username"),
            Some("control-username"),
            Some("realm"),
            Some("role-count"),
            Some("role-bytes"),
            Some("ecmwf-email"),
            Some("email"),
            Some("display_name"),
        ] {
            let mut identity = maximum_browser_identity();
            if let Some(field) = excess {
                match field {
                    "username" => identity.username.push('x'),
                    "blank-username" => identity.username = " ".into(),
                    "control-username" => identity.username = "alice\n".into(),
                    "realm" => identity.realm.push('x'),
                    "role-count" => identity.roles.push("extra".into()),
                    "role-bytes" => identity.roles[0].push('x'),
                    key => {
                        identity.attributes.get_mut(key).unwrap().push('x');
                    }
                }
            }
            let (app, mut state) = startup::build_app(Arc::new(combined_config(&server.url())))
                .await
                .unwrap();
            drop(app);
            Arc::get_mut(&mut state.auth)
                .unwrap()
                .augmenters
                .push(Box::new(IdentityFixture {
                    realm: if path == BASIC { "local" } else { "ecmwf" },
                    identity,
                }));
            let app = authotron::routes::create_app_router(state.clone());
            let (cookie, csrf) = transaction_for(app.clone(), path).await;
            let response = request(
                app.clone(),
                if path == BASIC {
                    basic_post(&cookie, &csrf, "alice", PASSWORD)
                } else {
                    post(Some(&cookie), Some(&csrf), Some(ORIGIN), KEY)
                },
            )
            .await;
            if excess.is_some() {
                assert_eq!(
                    response.status(),
                    StatusCode::UNAUTHORIZED,
                    "{path} {excess:?}"
                );
                assert!(response_cookie(&response, "__Host-authotron_session").is_none());
                assert!(!response.headers().contains_key(header::WWW_AUTHENTICATE));
                let body = text(response).await;
                assert!(!body.contains("hhhh"));
                assert!(!body.contains(PASSWORD));
                assert!(!body.contains(KEY));
                assert!(body.contains("invalid or could not be verified"));
            } else {
                assert_eq!(response.status(), StatusCode::SEE_OTHER);
                let sid = response_cookie(&response, "__Host-authotron_session")
                    .unwrap()
                    .value()
                    .to_owned();
                let user = state.browser.lookup(&sid).await.unwrap().unwrap().user;
                assert_eq!(user.roles.len(), 64);
                assert_eq!(user.username.len(), 256);
                assert_eq!(user.realm.len(), 256);
                assert_eq!(user.attributes.len(), 3);
                assert!(!user.attributes.contains_key("hidden"));
                assert!(user.scopes.is_empty());
                let html = text(
                    request(
                        app,
                        Request::get("/login/account")
                            .header(header::COOKIE, format!("__Host-authotron_session={sid}"))
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await,
                )
                .await;
                assert!(html.contains(&format!("063{}", "r".repeat(125))));
                assert!(!html.contains("hhhh"));
                assert!(html.len() < 24 * 1024);
            }
        }
    }
    mock.assert_async().await;
}

#[tokio::test]
async fn cancelled_augmentation_releases_all_admission_permits_without_sessions() {
    let (app, state, entered, release) = blocking_app().await;
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let (cookie, csrf) = transaction_for(app.clone(), BASIC).await;
        let app = app.clone();
        tasks.push(tokio::spawn(async move {
            request(app, basic_post(&cookie, &csrf, "alice", PASSWORD)).await
        }));
    }
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while entered.load(std::sync::atomic::Ordering::SeqCst) != 8 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(
        state
            .metrics
            .render()
            .unwrap()
            .contains("authotron_browser_logins_inflight 8")
    );
    for task in tasks {
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
    }
    let metrics = state.metrics.render().unwrap();
    assert!(metrics.contains("authotron_browser_logins_inflight 0"));
    assert!(metrics.contains(
        "authotron_browser_login_attempts_total{flow=\"basic\",outcome=\"cancelled\"} 8"
    ));
    let mut replacements = Vec::new();
    for _ in 0..8 {
        let (cookie, csrf) = transaction_for(app.clone(), BASIC).await;
        let app = app.clone();
        replacements.push(tokio::spawn(async move {
            request(app, basic_post(&cookie, &csrf, "bob", "public-bob")).await
        }));
    }
    // All eight slots must be reusable concurrently, not just one repeatedly.
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while entered.load(std::sync::atomic::Ordering::SeqCst) != 16 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    release.add_permits(8);
    for task in replacements {
        assert_eq!(task.await.unwrap().status(), StatusCode::SEE_OTHER);
    }
    assert!(
        state
            .metrics
            .render()
            .unwrap()
            .contains("authotron_browser_logins_inflight 0")
    );
}

#[tokio::test]
async fn basic_exhausts_shared_verification_quota_and_both_direct_chooser_stays_visible_without_sso()
 {
    let mut cfg = combined_config("http://127.0.0.1:1");
    cfg.ui.sign_in_actions.clear();
    let (app, _) = startup::build_app(Arc::new(cfg)).await.unwrap();
    let mut sid = String::new();
    for _ in 0..60 {
        let (cookie, csrf) = transaction_for(app.clone(), BASIC).await;
        let response = request(app.clone(), basic_post(&cookie, &csrf, "bob", "public-bob")).await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        sid = response_cookie(&response, "__Host-authotron_session")
            .unwrap()
            .value()
            .to_owned();
    }
    for path in [BASIC, PATH] {
        let (cookie, csrf) = transaction_for(app.clone(), path).await;
        let response = request(
            app.clone(),
            if path == BASIC {
                basic_post(&cookie, &csrf, "bob", "public-bob")
            } else {
                post(Some(&cookie), Some(&csrf), Some(ORIGIN), KEY)
            },
        )
        .await;
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(response_cookie(&response, "__Host-authotron_session").is_none());
    }
    let response = request(
        app,
        Request::get("/login")
            .header(header::COOKIE, format!("__Host-authotron_session={sid}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let html = text(response).await;
    assert!(html.contains(&format!("href=\"{BASIC}\"")));
    assert!(html.contains(&format!("href=\"{PATH}\"")));
}

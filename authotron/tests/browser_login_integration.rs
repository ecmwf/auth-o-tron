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
const PATH: &str = "/login/method/ecmwf-api-key";

// Public synthetic credentials and explicit loopback upstream; no local config reads.
fn config(uri: &str, enabled: bool) -> ConfigV2 {
    serde_json::from_value(json!({
        "store": {"enabled": false}, "services": [], "augmenters": [],
        "providers": [{"type": "ecmwf-api", "name": "ECMWF API Provider", "realm": "ecmwf", "uri": uri,
            "browser": {"id": "ecmwf-api-key", "label": "ECMWF API key"}}],
        "server": {"host": "127.0.0.1", "port": 0}, "metrics": {"enabled": false},
        "jwt": {"iss": "public-test", "exp": 300, "secret": "public-test-only-secret"},
        "logging": {"level": "warn", "format": "console"},
        "ui": {"enabled": enabled, "branding": {"application_name": "Public <Application>"},
            "sso": [{"label": "Continue with SSO", "start_url": "/sso/start"}],
            "browser_session": {"public_origin": ORIGIN, "backend": {"type": "memory"}}}
    })).unwrap()
}

/// Sets or removes the `browser` block of the provider named `name`; the method
/// id is the lowercased name with spaces replaced by hyphens.
fn set_browser(cfg: ConfigV2, name: &str, label: Option<&str>) -> ConfigV2 {
    let mut value = serde_json::to_value(cfg).unwrap();
    for provider in value["providers"].as_array_mut().unwrap() {
        if provider["name"] == name {
            match label {
                Some(label) => {
                    provider["browser"] =
                        json!({"id": name.to_lowercase().replace(' ', "-"), "label": label})
                }
                None => {
                    provider.as_object_mut().unwrap().remove("browser");
                }
            }
        }
    }
    serde_json::from_value(value).unwrap()
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
    if html.contains("name=\"api_key\"") {
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

#[tokio::test]
async fn shared_cookie_jar_preserves_tabs_and_rejects_cross_browser_without_burning() {
    let (app, _) = startup::build_app(Arc::new(combined_config("http://127.0.0.1:1")))
        .await
        .unwrap();
    let (mut jar, first) = transaction_for(app.clone(), BASIC).await;
    let response = request(
        app.clone(),
        Request::get(BASIC)
            .header(header::COOKIE, &jar)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    let cookie = response_cookie(&response, "__Host-authotron_form").unwrap();
    let next = cookie.to_string().split(';').next().unwrap().to_owned();
    assert_eq!(jar, next);
    jar = next;
    let html = text(response).await;
    let second = html
        .split("name=\"csrf\" value=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap();
    let (other, _) = transaction_for(app.clone(), BASIC).await;
    assert_eq!(
        request(app.clone(), basic_post(&other, &first, "alice", PASSWORD))
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    let (first_id, _) = first.split_once('.').unwrap();
    let (_, second_challenge) = second.split_once('.').unwrap();
    let mixed = format!("{first_id}.{second_challenge}");
    assert_eq!(
        request(app.clone(), basic_post(&jar, &mixed, "alice", PASSWORD))
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    for partial in [
        first_id.to_owned(),
        format!("{first_id}."),
        format!(".{second_challenge}"),
        format!("{first}.extra"),
    ] {
        assert_eq!(
            request(app.clone(), basic_post(&jar, &partial, "alice", PASSWORD))
                .await
                .status(),
            StatusCode::FORBIDDEN
        );
    }
    let duplicate = format!("{jar}; {jar}");
    assert_eq!(
        request(
            app.clone(),
            basic_post(&duplicate, &first, "alice", PASSWORD)
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        request(
            app.clone(),
            post(Some(&jar), Some(&first), Some(ORIGIN), KEY)
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
    for token in [&first, second] {
        let response = request(app.clone(), basic_post(&jar, token, "alice", PASSWORD)).await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert!(response_cookie(&response, "__Host-authotron_form").is_none());
        let session = response_cookie(&response, "__Host-authotron_session").unwrap();
        jar = format!(
            "{}; {}",
            jar.split(';').next().unwrap(),
            session.to_string().split(';').next().unwrap()
        );
        assert_eq!(
            request(app.clone(), basic_post(&jar, token, "alice", PASSWORD))
                .await
                .status(),
            StatusCode::FORBIDDEN
        );
    }
}

#[tokio::test]
async fn concurrent_first_forms_without_form_nonce_fail_closed_and_allow_retry() {
    let (app, _) = startup::build_app(Arc::new(combined_config("http://127.0.0.1:1")))
        .await
        .unwrap();
    // Both requests leave before either response can establish a browser cookie.
    let ((first_cookie, first), (jar, second)) = tokio::join!(
        transaction_for(app.clone(), BASIC),
        transaction_for(app.clone(), BASIC)
    );
    assert_ne!(first_cookie, jar);
    // The second response wins the browser cookie race. The first form cannot use it.
    let response = request(app.clone(), basic_post(&jar, &first, "alice", PASSWORD)).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let retry_cookie = response_cookie(&response, "__Host-authotron_form").unwrap();
    assert_eq!(retry_cookie.to_string().split(';').next().unwrap(), jar);
    let html = text(response).await;
    let retry = html
        .split("name=\"csrf\" value=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap();
    for token in [second.as_str(), retry] {
        assert_eq!(
            request(app.clone(), basic_post(&jar, token, "alice", PASSWORD))
                .await
                .status(),
            StatusCode::SEE_OTHER
        );
    }
    // The mismatch did not consume the first form either.
    assert_eq!(
        request(app, basic_post(&first_cookie, &first, "alice", PASSWORD))
            .await
            .status(),
        StatusCode::SEE_OTHER
    );
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
    assert!(login.contains("href=\"/login/method/ecmwf-api-key\""));
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
        assert!(chooser.contains("href=\"/login/method/ecmwf-api-key\""));
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
    let replay = request(
        app,
        post(Some(&cookie), Some(&csrf), Some(ORIGIN), "invalid key"),
    )
    .await;
    assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);
    mock.assert_async().await;
}

#[tokio::test]
async fn disabled_routes_and_missing_session_fail_closed() {
    for enabled in [false, true] {
        let mut cfg = config("http://127.0.0.1:1", enabled);
        if enabled {
            cfg = set_browser(cfg, "ECMWF API Provider", None);
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
    cfg.ui.browser_session = None;
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

const BASIC: &str = "/login/method/local";
const OTHER: &str = "/login/method/other";
const PASSWORD: &str = " 密码: public&+fixture ";

fn combined_config(uri: &str) -> ConfigV2 {
    let mut value = serde_json::to_value(config(uri, true)).unwrap();
    value["providers"].as_array_mut().unwrap().extend([
        json!({"type": "plain", "name": "Local", "realm": "local", "users": [
            {"username": "alice", "password": PASSWORD, "roles": ["configured"]},
            {"username": "bob", "password": "public-bob", "roles": []}
        ], "browser": {"id": "local", "label": "Local account"}}),
        // Same realm, not browser-enabled: direct Basic must never fall through to it.
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
    let html = text(
        get(
            app,
            "/login/method/local?username=alice&password=query-secret",
        )
        .await,
    )
    .await;
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
            StatusCode::SEE_OTHER
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

fn basic_post_to(
    path: &str,
    cookie: &str,
    csrf: &str,
    username: &str,
    password: &str,
) -> Request<Body> {
    let mut request = basic_post(cookie, csrf, username, password);
    *request.uri_mut() = path.parse().unwrap();
    request
}

#[tokio::test]
async fn same_username_in_different_realms_is_verified_only_by_its_own_method() {
    let mut value = serde_json::to_value(config("http://127.0.0.1:1", true)).unwrap();
    value["providers"] = json!([
        {"type": "plain", "name": "Staff", "realm": "staff-realm", "users": [
            {"username": "shared", "password": "staff-password", "roles": []}
        ], "browser": {"id": "staff", "label": "Staff"}},
        {"type": "plain", "name": "Guests", "realm": "guest-realm", "users": [
            {"username": "shared", "password": "guest-password", "roles": []}
        ], "browser": {"id": "guests", "label": "Guests"}},
    ]);
    let (app, state) = startup::build_app(Arc::new(serde_json::from_value(value).unwrap()))
        .await
        .unwrap();
    let methods = [
        ("/login/method/staff", "staff-password", "staff-realm"),
        ("/login/method/guests", "guest-password", "guest-realm"),
    ];
    for (path, password, realm) in methods {
        for (_, other_password, _) in methods.iter().filter(|m| m.0 != path) {
            let (cookie, csrf) = transaction_for(app.clone(), path).await;
            let response = request(
                app.clone(),
                basic_post_to(path, &cookie, &csrf, "shared", other_password),
            )
            .await;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{path}");
            assert!(response_cookie(&response, "__Host-authotron_session").is_none());
        }
        let (cookie, csrf) = transaction_for(app.clone(), path).await;
        let response = request(
            app.clone(),
            basic_post_to(path, &cookie, &csrf, "shared", password),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER, "{path}");
        let sid = response_cookie(&response, "__Host-authotron_session")
            .unwrap()
            .value()
            .to_owned();
        let user = state.browser.lookup(&sid).await.unwrap().unwrap().user;
        assert_eq!(user.realm, realm);
        let html = text(
            request(
                app.clone(),
                Request::get("/login/account")
                    .header(header::COOKIE, format!("__Host-authotron_session={sid}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await,
        )
        .await;
        assert!(html.contains(&format!("<dd>{realm}</dd>")), "{html}");
    }

    // A form issued for `staff` is bound to that id and survives a cross-method post.
    let (cookie, csrf) = transaction_for(app.clone(), "/login/method/staff").await;
    let response = request(
        app.clone(),
        basic_post_to(
            "/login/method/guests",
            &cookie,
            &csrf,
            "shared",
            "guest-password",
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(response_cookie(&response, "__Host-authotron_session").is_none());
    let response = request(
        app.clone(),
        basic_post_to(
            "/login/method/staff",
            &cookie,
            &csrf,
            "shared",
            "staff-password",
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let sid = response_cookie(&response, "__Host-authotron_session")
        .unwrap()
        .value()
        .to_owned();
    let user = state.browser.lookup(&sid).await.unwrap().unwrap().user;
    assert_eq!(user.realm, "staff-realm");
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
async fn browser_configuration_requires_session_unique_labels_and_is_opt_in() {
    for change in [
        "missing-session",
        "duplicate-label",
        "duplicate-id",
        "reserved-id",
        "too-many",
        "bad-ttl",
    ] {
        let mut cfg = combined_config("http://127.0.0.1:1");
        match change {
            "missing-session" => cfg.ui.browser_session = None,
            "duplicate-label" => cfg = set_browser(cfg, "Other", Some("ecmwf API KEY")),
            "duplicate-id" => {
                let mut value = serde_json::to_value(cfg).unwrap();
                value["providers"][2]["browser"] = json!({"id": "local", "label": "Other"});
                cfg = serde_json::from_value(value).unwrap();
            }
            "reserved-id" => {
                let mut value = serde_json::to_value(cfg).unwrap();
                value["providers"][2]["browser"] = json!({"id": "account", "label": "Other"});
                assert!(serde_json::from_value::<ConfigV2>(value).is_err());
                continue;
            }
            "too-many" => {
                for n in 0..15 {
                    cfg.providers.push(
                        serde_json::from_value(json!({"type": "plain", "name": format!("extra-{n}"),
                            "realm": "local", "users": [], "browser": {"id": format!("extra-{n}"), "label": format!("Extra {n}")}}))
                        .unwrap(),
                    );
                }
            }
            "bad-ttl" => cfg.ui.browser_session.as_mut().unwrap().session_ttl_seconds = 86401,
            _ => unreachable!(),
        }
        assert!(startup::build_app(Arc::new(cfg)).await.is_err(), "{change}");
    }
    let mut cfg = combined_config("http://127.0.0.1:1");
    for n in 0..14 {
        cfg.providers.push(
            serde_json::from_value(json!({"type": "plain", "name": format!("extra-{n}"),
                "realm": "local", "users": [], "browser": {"id": format!("extra-{n}"), "label": format!("Extra {n}")}}))
            .unwrap(),
        );
    }
    assert_eq!(
        startup::build_app(Arc::new(cfg))
            .await
            .unwrap()
            .1
            .browser
            .methods()
            .len(),
        16
    );
    // An API-key provider without a browser block is API-only: not offered, no route.
    let cfg = set_browser(
        combined_config("http://127.0.0.1:1"),
        "ECMWF API Provider",
        None,
    );
    let (app, _) = startup::build_app(Arc::new(cfg)).await.unwrap();
    let chooser = text(get(app.clone(), "/login").await).await;
    assert!(
        chooser.contains(
            "href=\"/login/method/local\" data-login-dialog=\"method\">Local account</a>"
        )
    );
    assert!(!chooser.contains("ECMWF API key"));
    assert_eq!(chooser.matches("data-login-dialog=").count(), 1);
    assert_eq!(get(app.clone(), PATH).await.status(), StatusCode::NOT_FOUND);
    let (cookie, csrf) = transaction_for(app.clone(), BASIC).await;
    let login = submit_to(BASIC, &cookie, &csrf, PASSWORD);
    assert_eq!(request(app, login).await.status(), StatusCode::SEE_OTHER);
    for enabled in [true, false] {
        let mut cfg = combined_config("http://127.0.0.1:1");
        cfg.ui.enabled = enabled;
        if enabled {
            cfg = set_browser(cfg, "Local", None);
            cfg = set_browser(cfg, "ECMWF API Provider", None);
        }
        let (app, _) = startup::build_app(Arc::new(cfg)).await.unwrap();
        for path in [PATH, BASIC, "/login/account"] {
            assert_eq!(get(app.clone(), path).await.status(), StatusCode::NOT_FOUND);
        }
    }
    // Removed per-flow UI keys fail loudly instead of silently disabling direct login.
    for legacy in [
        json!({"basic": {"provider_name": "Local"}}),
        json!({"ecmwf_api_key": {"provider_name": "ECMWF API Provider"}}),
        json!({"sign_in_actions": []}),
    ] {
        assert!(serde_json::from_value::<authotron::config::UiConfig>(legacy).is_err());
    }
    let mut jwt = serde_json::to_value(combined_config("http://127.0.0.1:1")).unwrap();
    jwt["providers"].as_array_mut().unwrap().push(json!({
        "type": "jwt", "name": "sso", "cert_uri": "https://idp.example.test/certs",
        "realm": "local", "iam_realm": "local", "browser": {"id": "sso", "label": "SSO"}
    }));
    let error = serde_json::from_value::<ConfigV2>(jwt)
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("plain and ecmwf-api"), "{error}");
}

#[tokio::test]
async fn multiple_plain_methods_verify_only_their_own_users_and_bind_forms() {
    let cfg = set_browser(
        combined_config("http://127.0.0.1:1"),
        "Other",
        Some("Other accounts"),
    );
    let (app, state) = startup::build_app(Arc::new(cfg)).await.unwrap();
    let chooser = text(get(app.clone(), "/login").await).await;
    let order: Vec<usize> = [
        "ECMWF API key",
        "Local account",
        "Other accounts",
        "Continue with SSO",
    ]
    .iter()
    .map(|label| chooser.find(&format!(">{label}</a>")).unwrap())
    .collect();
    assert!(order.windows(2).all(|pair| pair[0] < pair[1]));
    assert!(chooser.contains(&format!("href=\"{OTHER}\" data-login-dialog=\"method\"")));
    for (path, password, accepted) in [
        (BASIC, PASSWORD, true),
        (BASIC, "other-password", false),
        (OTHER, "other-password", true),
        (OTHER, PASSWORD, false),
    ] {
        let (cookie, csrf) = transaction_for(app.clone(), path).await;
        let response = request(app.clone(), submit_to(path, &cookie, &csrf, password)).await;
        if !accepted {
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{path}");
            continue;
        }
        assert_eq!(response.status(), StatusCode::SEE_OTHER, "{path}");
        let sid = response_cookie(&response, "__Host-authotron_session")
            .unwrap()
            .value()
            .to_owned();
        let user = state.browser.lookup(&sid).await.unwrap().unwrap().user;
        assert_eq!(
            user.roles.contains(&"wrong-provider".to_owned()),
            path == OTHER
        );
        assert_eq!(user.roles.contains(&"configured".to_owned()), path == BASIC);
    }
    // A form issued for one method is rejected by another without being consumed.
    let (cookie, csrf) = transaction_for(app.clone(), BASIC).await;
    let response = request(
        app.clone(),
        submit_to(OTHER, &cookie, &csrf, "other-password"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(response_cookie(&response, "__Host-authotron_session").is_none());
    assert_eq!(
        request(app.clone(), submit_to(BASIC, &cookie, &csrf, PASSWORD))
            .await
            .status(),
        StatusCode::SEE_OTHER
    );
    // Field sets must match the method type; mismatches are malformed, not credentials.
    let (cookie, csrf) = transaction_for(app.clone(), BASIC).await;
    let response = request(
        app.clone(),
        Request::post(BASIC)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::ORIGIN, ORIGIN)
            .header(header::COOKIE, &cookie)
            .body(Body::from(format!("api_key={KEY}&csrf={csrf}")))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(!text(response).await.contains(KEY));
    for path in [
        "/login/method/0",
        "/login/method/1",
        "/login/method/Local",
        "/login/method/LOCAL",
        "/login/method/local%20",
        "/login/method/-local",
        "/login/method/new",
        "/login/method/callback",
        "/login/method/",
        "/login/method",
        "/login/basic",
        "/login/ecmwf-api-key",
    ] {
        assert_eq!(
            get(app.clone(), path).await.status(),
            StatusCode::NOT_FOUND,
            "{path}"
        );
        let (cookie, csrf) = transaction_for(app.clone(), BASIC).await;
        let response = request(app.clone(), submit_to(path, &cookie, &csrf, PASSWORD)).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
    }
}

#[tokio::test]
async fn method_urls_follow_ids_across_relabel_and_reorder() {
    let relabelled = set_browser(
        combined_config("http://127.0.0.1:1"),
        "Local",
        Some("Staff sign-in"),
    );
    let mut reordered = serde_json::to_value(combined_config("http://127.0.0.1:1")).unwrap();
    reordered["providers"].as_array_mut().unwrap().reverse();
    for (cfg, label) in [
        (combined_config("http://127.0.0.1:1"), "Local account"),
        (relabelled, "Staff sign-in"),
        (serde_json::from_value(reordered).unwrap(), "Local account"),
    ] {
        let (app, _) = startup::build_app(Arc::new(cfg)).await.unwrap();
        let chooser = text(get(app.clone(), "/login").await).await;
        assert!(
            chooser.contains(&format!(
                "href=\"{BASIC}\" data-login-dialog=\"method\">{label}</a>"
            )),
            "{chooser}"
        );
        assert!(chooser.contains(&format!("href=\"{PATH}\"")));
        let (cookie, csrf) = transaction_for(app.clone(), BASIC).await;
        let response = request(app, submit_to(BASIC, &cookie, &csrf, PASSWORD)).await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER, "{label}");
    }
}

fn submit_to(path: &str, cookie: &str, csrf: &str, password: &str) -> Request<Body> {
    let mut req = basic_post(cookie, csrf, "alice", password);
    *req.uri_mut() = path.parse().unwrap();
    req
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
            "authotron_browser_login_attempts_total{flow=\"basic\",method=\"local\",outcome=\"timeout\"} 1"
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
    // `flow` is the credential type; `method` is the configured `browser.id`.
    for (path, flow, method) in [
        (BASIC, "basic", "local"),
        (PATH, "ecmwf-api-key", "ecmwf-api-key"),
    ] {
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
            assert!(metrics.contains(&format!("authotron_browser_login_attempts_total{{flow=\"{flow}\",method=\"{method}\",outcome=\"{outcome}\"}} 1")), "{flow} {outcome}");
            assert!(metrics.contains(&format!("authotron_browser_login_duration_seconds_count{{flow=\"{flow}\",method=\"{method}\",outcome=\"{outcome}\"}} 1")));
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
        "authotron_browser_login_attempts_total{flow=\"basic\",method=\"local\",outcome=\"cancelled\"} 8"
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
    cfg.ui.sso.clear();
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

#[tokio::test]
async fn trailing_slash_subpages_redirect_to_canonical_paths() {
    let (app, _) = startup::build_app(Arc::new(config("http://127.0.0.1:1", true)))
        .await
        .unwrap();
    for (path, location) in [
        ("/login/method/ecmwf-api-key/", PATH),
        ("/login/method/ecmwf-api-key/?a=b", PATH),
        ("/login/account/", "/login/account"),
    ] {
        for method in ["GET", "HEAD"] {
            let response = request(
                app.clone(),
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header(header::HOST, "evil.example")
                    .header("x-forwarded-host", "evil.example")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
            assert_eq!(response.status(), StatusCode::PERMANENT_REDIRECT, "{path}");
            assert_eq!(response.headers()[header::LOCATION], location);
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            assert_eq!(response.headers()[header::REFERRER_POLICY], "strict-origin");
            assert_eq!(response.headers()[header::X_FRAME_OPTIONS], "DENY");
            assert!(!response.headers().contains_key(header::SET_COOKIE));
        }
    }
    for path in [
        "/login/method/0/",
        "/login/method/ECMWF-API-KEY/",
        "/login/method/x/",
    ] {
        assert_eq!(
            get(app.clone(), path).await.status(),
            StatusCode::NOT_FOUND,
            "{path}"
        );
    }
    for path in ["/login/method/ecmwf-api-key/", "/login/account/"] {
        let response = request(
            app.clone(),
            Request::post(path).body(Body::empty()).unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED, "{path}");
        assert!(!response.headers().contains_key(header::LOCATION));
    }
    for path in [
        "/login/method/",
        "/login/method/ecmwf-api-key//",
        "/login/accounts/",
    ] {
        assert!(
            !get(app.clone(), path).await.status().is_redirection(),
            "{path}"
        );
    }

    let mut cfg = config("http://127.0.0.1:1", true);
    cfg = set_browser(cfg, "ECMWF API Provider", None);
    for cfg in [config("http://127.0.0.1:1", false), cfg] {
        let (app, _) = startup::build_app(Arc::new(cfg)).await.unwrap();
        for path in ["/login/method/ecmwf-api-key/", "/login/account/"] {
            assert_eq!(get(app.clone(), path).await.status(), StatusCode::NOT_FOUND);
        }
    }
}

#[tokio::test]
async fn unknown_login_paths_render_branded_not_found_page() {
    let (app, _) = startup::build_app(Arc::new(config("http://127.0.0.1:1", true)))
        .await
        .unwrap();
    for path in [
        "/login/method/0",
        "/login/method/unknown",
        "/login/method/unknown/",
        "/login/method/Ecmwf-Api-Key",
        // Percent escapes are rejected even when they decode to a configured id.
        "/login/method/ecmwf-api-ke%79",
        "/login/method/ecmwf%2Dapi-key",
        "/login/method/ecmwf-api-ke%79/",
        "/login/basic",
        "/login/nope",
        "/login/nope/deeper",
    ] {
        for method in ["GET", "HEAD"] {
            let response = request(
                app.clone(),
                Request::builder()
                    .method(method)
                    .uri(path)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{method} {path}");
            let headers = response.headers();
            assert_eq!(headers[header::CACHE_CONTROL], "no-store", "{path}");
            assert_eq!(headers[header::REFERRER_POLICY], "strict-origin", "{path}");
            assert_eq!(headers[header::X_FRAME_OPTIONS], "DENY", "{path}");
            assert_eq!(
                headers[header::CONTENT_SECURITY_POLICY],
                "default-src 'none'; style-src 'self'; img-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
                "{path}"
            );
            assert!(!headers.contains_key(header::SET_COOKIE), "{path}");
            if method == "GET" {
                let html = text(response).await;
                assert!(html.contains("Page not found"), "{path}");
                assert!(html.contains("href=\"/login\""), "{path}");
                assert!(html.contains("Back to sign in"), "{path}");
                assert!(html.contains("Public &lt;Application&gt;"), "{path}");
            }
        }
    }

    // POST to unknown paths stays a plain 404; existing routes keep 405.
    for path in [
        "/login/nope",
        "/login/method/unknown",
        "/login/method/ecmwf-api-ke%79",
    ] {
        let response = request(
            app.clone(),
            Request::post(path).body(Body::empty()).unwrap(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        assert!(!text(response).await.contains("Page not found"), "{path}");
    }
    let response = request(
        app.clone(),
        Request::post("/login/").body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);

    for (path, location) in [
        ("/login/", "/login"),
        ("/login/account/", "/login/account"),
        ("/login/method/ecmwf-api-key/", PATH),
    ] {
        let response = get(app.clone(), path).await;
        assert_eq!(response.status(), StatusCode::PERMANENT_REDIRECT, "{path}");
        assert_eq!(response.headers()[header::LOCATION], location);
    }
    assert_eq!(get(app.clone(), PATH).await.status(), StatusCode::OK);

    // Outside /login the generic empty 404 is unchanged.
    let response = get(app, "/nope").await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(text(response).await.is_empty());

    // With the UI disabled, nothing under /login is registered.
    let (app, _) = startup::build_app(Arc::new(config("http://127.0.0.1:1", false)))
        .await
        .unwrap();
    for path in ["/login/nope", "/login/method/unknown"] {
        let response = get(app.clone(), path).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        assert!(
            !response
                .headers()
                .contains_key(header::CONTENT_SECURITY_POLICY)
        );
        assert!(text(response).await.is_empty(), "{path}");
    }
}

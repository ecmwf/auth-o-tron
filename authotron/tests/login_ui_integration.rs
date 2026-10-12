use authotron::config::{Config, ConfigV2};
use authotron::routes::create_metrics_router;
use authotron::startup;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use figment::{
    Figment,
    providers::{Format, Yaml},
};
use serde_json::json;
use std::sync::Arc;
use tower::ServiceExt;

const BASE_CONFIG: &str = r#"
version: "2.0.0"
store:
  enabled: false
providers:
  - type: plain
    name: local
    realm: aviso
    users:
      - username: alice
        password: example-password
services: []
server:
  host: "127.0.0.1"
  port: 0
metrics:
  enabled: false
jwt:
  iss: login-ui-test
  exp: 300
  secret: test-only-secret
logging:
  level: warn
  format: console
"#;

fn config(ui: serde_json::Value) -> ConfigV2 {
    let figment = Figment::new()
        .merge(Yaml::string(BASE_CONFIG))
        .merge(("ui", ui));
    let Config::ConfigV2(config) = figment.extract::<Config>().unwrap() else {
        panic!("expected config v2");
    };
    config
}

async fn get(app: Router, path: &str) -> axum::response::Response {
    app.oneshot(Request::get(path).body(Body::empty()).unwrap())
        .await
        .unwrap()
}

async fn body(response: axum::response::Response) -> String {
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

#[tokio::test]
async fn ui_routes_are_absent_by_default_and_when_disabled() {
    for ui in [json!({}), json!({"enabled": false})] {
        let (app, _) = startup::build_app(Arc::new(config(ui))).await.unwrap();
        for path in [
            "/login",
            "/static/login.css",
            "/static/login.js",
            "/static/aviso-logo.png",
        ] {
            assert_eq!(get(app.clone(), path).await.status(), StatusCode::NOT_FOUND);
        }
        assert_eq!(get(app, "/").await.status(), StatusCode::OK);
    }
}

#[tokio::test]
async fn ui_routes_are_absent_when_the_entire_ui_section_is_omitted() {
    let Config::ConfigV2(config) = Figment::new()
        .merge(Yaml::string(BASE_CONFIG))
        .extract::<Config>()
        .unwrap()
    else {
        panic!("expected config v2");
    };
    let (app, _) = startup::build_app(Arc::new(config)).await.unwrap();
    for path in [
        "/login",
        "/static/login.css",
        "/static/login.js",
        "/static/aviso-logo.png",
    ] {
        assert_eq!(get(app.clone(), path).await.status(), StatusCode::NOT_FOUND);
    }
}

#[tokio::test]
async fn enabled_ui_renders_default_branding_without_authentication() {
    let (app, _) = startup::build_app(Arc::new(config(json!({"enabled": true}))))
        .await
        .unwrap();
    let response = get(app, "/login").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()["content-type"],
        "text/html; charset=utf-8"
    );
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(response.headers()["referrer-policy"], "no-referrer");
    assert_eq!(response.headers()["x-content-type-options"], "nosniff");
    assert_eq!(response.headers()["x-frame-options"], "DENY");
    assert!(!response.headers().contains_key("set-cookie"));
    assert!(!response.headers().contains_key("authorization"));
    let policy = response.headers()["content-security-policy"]
        .to_str()
        .unwrap();
    for directive in [
        "default-src 'none'",
        "style-src 'self'",
        "img-src 'self' https:",
        "form-action 'none'",
        "frame-ancestors 'none'",
    ] {
        assert!(policy.contains(directive));
    }

    let html = body(response).await;
    assert!(html.contains("Sign in to Auth-O-Tron"));
    assert!(html.contains("UI preview"));
    assert!(html.contains("No credentials are collected."));
    assert!(html.contains("Sign-in unavailable"));
    assert!(html.contains("disabled"));
    assert!(html.contains("Powered by "));
    assert!(
        html.contains("class=\"product-mark\" src=\"/favicon.ico\" alt=\"\" aria-hidden=\"true\"")
    );
    assert!(html.contains("https://github.com/ecmwf/auth-o-tron"));
    assert!(html.contains("rel=\"noopener noreferrer\""));
    for forbidden in [
        "<form",
        "<input",
        "<script",
        "example-password",
        "test-only-secret",
    ] {
        assert!(!html.contains(forbidden), "unexpected {forbidden} in HTML");
    }
}

#[tokio::test]
async fn ui_renders_custom_application_logo_and_text() {
    let (app, _) = startup::build_app(Arc::new(config(json!({
        "enabled": true,
        "branding": {
            "application_name": "Aviso",
            "logo_url": "/static/aviso-logo.png",
            "title": "Welcome to Aviso",
            "description": "Notifications and subscriptions"
        }
    }))))
    .await
    .unwrap();
    let html = body(get(app, "/login").await).await;
    assert!(html.contains("<title>Welcome to Aviso</title>"));
    assert!(html.contains("Notifications and subscriptions"));
    assert!(html.contains("class=\"application-logo\" src=\"/static/aviso-logo.png\""));
    assert!(html.contains("alt=\"Aviso logo\""));
    assert!(!html.contains("https://aviso"));
    assert!(!html.contains("data:image"));
}

#[tokio::test]
async fn bundled_aviso_logo_is_a_cacheable_secure_png_without_authentication() {
    let (app, _) = startup::build_app(Arc::new(config(json!({"enabled": true}))))
        .await
        .unwrap();
    let response = get(app, "/static/aviso-logo.png").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["content-type"], "image/png");
    assert_eq!(response.headers()["cache-control"], "public, max-age=86400");
    assert_eq!(response.headers()["x-content-type-options"], "nosniff");
    assert_eq!(response.headers()["referrer-policy"], "no-referrer");
    assert_eq!(response.headers()["x-frame-options"], "DENY");
    assert!(
        response.headers()["content-security-policy"]
            .to_str()
            .unwrap()
            .contains("default-src 'none'")
    );
    for header in ["set-cookie", "authorization", "location"] {
        assert!(!response.headers().contains_key(header));
    }
    let png = axum::body::to_bytes(response.into_body(), 16 * 1024)
        .await
        .unwrap();
    assert_eq!(&png[..8], b"\x89PNG\r\n\x1a\n");
    assert_eq!(&png[8..16], b"\0\0\0\rIHDR");
    assert_eq!(u32::from_be_bytes(png[16..20].try_into().unwrap()), 192);
    assert_eq!(u32::from_be_bytes(png[20..24].try_into().unwrap()), 192);
    assert_eq!(png[24], 4, "16-colour palette uses four-bit pixels");
    assert_eq!(png[25], 3, "indexed-colour PNG");
    assert_eq!(&png[png.len() - 12..], b"\0\0\0\0IEND\xaeB`\x82");
}

#[tokio::test]
async fn absent_or_blank_title_uses_the_application_name_and_omits_empty_description() {
    for title in [serde_json::Value::Null, json!(" \t")] {
        let (app, _) = startup::build_app(Arc::new(config(json!({
            "enabled": true,
            "branding": {
                "application_name": "Polytope",
                "title": title,
                "description": ""
            }
        }))))
        .await
        .unwrap();
        let html = body(get(app, "/login").await).await;
        assert!(html.contains("Sign in to Polytope"));
        assert!(html.contains("class=\"application-wordmark\">Polytope"));
        assert!(!html.contains("class=\"application-description\""));
        assert!(!html.contains("class=\"application-logo\""));
    }
}

#[tokio::test]
async fn branding_is_escaped_in_text_and_attributes_without_template_substitution() {
    let (app, _) = startup::build_app(Arc::new(config(json!({
        "enabled": true,
        "branding": {
            "application_name": "Aviso\" onerror=\"alert(1)",
            "logo_url": "/static/logo.png?theme=light&size=large",
            "title": "<script>alert(1)</script>",
            "description": "{{title}} <img src=x onerror=alert(2)> & data"
        }
    }))))
    .await
    .unwrap();
    let html = body(get(app, "/login").await).await;
    assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    assert!(html.contains("{{title}} &lt;img"));
    assert!(html.contains("&amp; data"));
    assert!(html.contains("theme=light&amp;size=large"));
    assert!(html.contains("Aviso&quot; onerror=&quot;alert(1) logo"));
    assert!(!html.contains("<script>"));
    assert!(!html.contains("<img src=x"));
    assert!(!html.contains("alt=\"Aviso\" onerror="));
}

#[tokio::test]
async fn stylesheet_is_embedded_and_ui_stays_off_the_metrics_router() {
    let (app, state) = startup::build_app(Arc::new(config(json!({"enabled": true}))))
        .await
        .unwrap();
    let response = get(app, "/static/login.css").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()["content-type"],
        "text/css; charset=utf-8"
    );
    assert_eq!(response.headers()["x-content-type-options"], "nosniff");
    let css = body(response).await;
    assert!(css.contains(".login-card"));
    assert!(css.contains(":focus-visible"));
    assert!(css.contains(".product-mark"));
    assert!(css.contains(".application-logo"));
    assert!(css.contains("max-width: min(100%, 14rem)"));
    assert!(css.contains("@media (prefers-color-scheme: dark)"));
    assert!(css.contains("--logo-background: #ffffff"));
    assert!(!css.contains("@import"));

    let metrics_app = create_metrics_router(state);
    for path in [
        "/login",
        "/static/login.css",
        "/static/login.js",
        "/static/aviso-logo.png",
    ] {
        assert_eq!(
            get(metrics_app.clone(), path).await.status(),
            StatusCode::NOT_FOUND
        );
    }
}

#[tokio::test]
async fn preview_does_not_redirect_or_reflect_unregistered_callback_parameters() {
    let (app, _) = startup::build_app(Arc::new(config(json!({"enabled": true}))))
        .await
        .unwrap();
    let response = get(
        app,
        "/login?redirect_uri=https%3A%2F%2Funtrusted.example%2Fcallback&return_to=%2Fsubscriptions",
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(!response.headers().contains_key("location"));
    assert!(!response.headers().contains_key("set-cookie"));
    let html = body(response).await;
    assert!(!html.contains("untrusted.example"));
    assert!(!html.contains("/subscriptions"));
}

#[tokio::test]
async fn posting_to_the_preview_cannot_start_authentication() {
    let (app, _) = startup::build_app(Arc::new(config(json!({"enabled": true}))))
        .await
        .unwrap();
    let response = app
        .oneshot(Request::post("/login").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert!(!response.headers().contains_key("location"));
    assert!(!response.headers().contains_key("set-cookie"));
    assert!(!response.headers().contains_key("authorization"));
}

#[tokio::test]
async fn configured_sign_in_action_is_escaped_and_ignores_request_destinations() {
    let (app, _) = startup::build_app(Arc::new(config(json!({
        "enabled": true,
        "sso": [{
            "label": "Continue <with> SSO",
            "start_url": "https://app.example.org/oauth2/start?rd=%2Faccount&mode=demo"
        }]
    }))))
    .await
    .unwrap();
    let response = get(
        app,
        "/login?start_url=https://untrusted.example&redirect_uri=https://untrusted.example",
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(!response.headers().contains_key("location"));
    assert!(!response.headers().contains_key("set-cookie"));
    let html = body(response).await;
    assert!(html.contains("Continue &lt;with&gt; SSO"));
    assert!(
        html.contains("href=\"https://app.example.org/oauth2/start?rd=%2Faccount&amp;mode=demo\"")
    );
    assert!(html.contains("Browser sign-in"));
    assert!(!html.contains("UI preview"));
    assert!(!html.contains("Sign-in unavailable"));
    assert!(!html.contains("untrusted.example"));
    assert!(!html.contains("<form"));
    assert!(!html.contains("<input"));
    assert!(!html.contains("<script"));
    assert!(!html.contains("<dialog"));
    assert!(!html.contains("data-login-dialog"));
}

fn direct_config() -> ConfigV2 {
    let mut config = config(json!({
        "enabled": true,
        "branding": {"application_name": "Aviso", "logo_url": "/static/aviso-logo.png"},
        "browser_session": {"public_origin": "https://login.example.test", "backend": {"type": "memory"}},
        "sso": [
            {"label": "Continue with SSO", "start_url": "https://app.example.test/sso/start"},
            {"label": "Configured method link", "start_url": "/login/method/0"}
        ]
    }));
    config.providers = [
        json!({"type": "plain", "name": "local", "realm": "aviso",
            "users": [{"username": "alice", "password": "example-password"}],
            "browser": {"label": "Username & <password>"}}),
        json!({"type": "ecmwf-api", "name": "api-only", "realm": "ecmwf", "uri": "http://127.0.0.1:9"}),
        json!({"type": "ecmwf-api", "name": "key-provider", "realm": "ecmwf",
            "uri": "http://127.0.0.1:9", "browser": {"label": "ECMWF API key"}}),
    ]
    .into_iter()
    .map(|provider| serde_json::from_value(provider).unwrap())
    .collect();
    config
}

#[tokio::test]
async fn direct_chooser_marks_only_direct_links_and_does_not_create_form_transactions() {
    let (app, _) = startup::build_app(Arc::new(direct_config())).await.unwrap();
    let response = get(app, "/login?flow=basic&action=https://untrusted.example").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(!response.headers().contains_key("set-cookie"));
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(response.headers()["referrer-policy"], "strict-origin");
    assert_eq!(
        response.headers()["content-security-policy"],
        "default-src 'none'; style-src 'self'; img-src 'self'; script-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
    );
    let html = body(response).await;
    assert!(html.contains("<script src=\"/static/login.js\" defer></script>"));
    let first = "<a class=\"login-action\" href=\"/login/method/0\" data-login-dialog=\"method\">Username &amp; &lt;password&gt;</a>";
    let second = "<a class=\"login-action\" href=\"/login/method/1\" data-login-dialog=\"method\">ECMWF API key</a>";
    let sso = "<a class=\"login-action\" href=\"https://app.example.test/sso/start\">Continue with SSO</a>";
    let configured =
        "<a class=\"login-action\" href=\"/login/method/0\">Configured method link</a>";
    let positions: Vec<usize> = [first, second, sso, configured]
        .iter()
        .map(|link| html.find(link).unwrap_or_else(|| panic!("missing {link}")))
        .collect();
    assert!(positions.windows(2).all(|pair| pair[0] < pair[1]));
    assert_eq!(html.matches("data-login-dialog=").count(), 2);
    assert!(!html.contains("/login/method/2"));
    assert!(html.contains("<dialog id=\"login-dialog\""));
    assert!(html.contains("aria-labelledby=\"login-dialog-title\""));
    assert!(html.contains("aria-live=\"polite\""));
    let dialog = html.split("<dialog").nth(1).unwrap();
    assert!(dialog.contains("class=\"login-dialog-brand\""));
    assert!(dialog.contains("class=\"login-dialog-logo\" src=\"/static/aviso-logo.png\""));
    assert!(dialog.contains("<span>Aviso</span>"));
    assert_eq!(html.matches("id=\"login-card-title\"").count(), 1);
    assert_eq!(html.matches("id=\"login-dialog-title\"").count(), 1);
    for absent in [
        "<form",
        "<input",
        "untrusted.example",
        "onload=",
        "onclick=",
        "style=",
    ] {
        assert!(!html.contains(absent), "unexpected {absent}");
    }
}

#[tokio::test]
async fn standalone_forms_keep_native_post_fallback_and_no_dialog_script() {
    let (app, _) = startup::build_app(Arc::new(direct_config())).await.unwrap();
    for (path, fields) in [
        ("/login/method/0", vec!["username", "password"]),
        ("/login/method/1", vec!["api_key"]),
    ] {
        let response = get(app.clone(), path).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response.headers()["set-cookie"]
                .to_str()
                .unwrap()
                .starts_with("__Host-authotron_form=")
        );
        assert_eq!(response.headers()["referrer-policy"], "strict-origin");
        let policy = response.headers()["content-security-policy"]
            .to_str()
            .unwrap();
        assert!(policy.contains("img-src 'self';"));
        assert!(policy.contains("form-action 'self'"));
        assert!(!policy.contains("script-src"));
        let html = body(response).await;
        assert!(html.contains(&format!(
            "<form class=\"key-form\" method=\"post\" action=\"{path}\""
        )));
        assert!(html.contains("type=\"hidden\" name=\"csrf\""));
        for field in fields {
            assert!(html.contains(&format!("name=\"{field}\"")));
        }
        assert!(!html.contains("<script"));
        assert!(!html.contains("<dialog"));
    }
}

#[tokio::test]
async fn dialog_script_is_explicitly_served_and_absent_on_metrics_router() {
    let (app, state) = startup::build_app(Arc::new(direct_config())).await.unwrap();
    let response = get(app, "/static/login.js").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()["content-type"],
        "text/javascript; charset=utf-8"
    );
    assert_eq!(response.headers()["x-content-type-options"], "nosniff");
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert!(!body(response).await.is_empty());
    assert_eq!(
        get(create_metrics_router(state), "/static/login.js")
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn ui_does_not_change_the_homepage_or_credential_authentication() {
    let (app, _) = startup::build_app(Arc::new(config(json!({"enabled": true}))))
        .await
        .unwrap();
    assert_eq!(get(app.clone(), "/").await.status(), StatusCode::OK);
    let mut request = Request::get("/authenticate")
        .header("authorization", "Basic YWxpY2U6ZXhhbXBsZS1wYXNzd29yZA==")
        .body(Body::empty())
        .unwrap();
    request.extensions_mut().insert(axum::extract::ConnectInfo(
        "127.0.0.1:12345".parse::<std::net::SocketAddr>().unwrap(),
    ));
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response.headers()["authorization"]
            .to_str()
            .unwrap()
            .starts_with("Bearer ")
    );
}

#[tokio::test]
async fn login_trailing_slash_redirects_get_and_head_only_when_ui_enabled() {
    let (app, _) = startup::build_app(Arc::new(config(json!({"enabled": true}))))
        .await
        .unwrap();
    for method in ["GET", "HEAD"] {
        for path in ["/login/", "/login/?next=https://evil.example"] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(path)
                        .header("host", "evil.example")
                        .header("x-forwarded-host", "evil.example")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::PERMANENT_REDIRECT);
            assert_eq!(response.headers()["location"], "/login");
            assert_eq!(response.headers()["cache-control"], "no-store");
            assert_eq!(response.headers()["referrer-policy"], "no-referrer");
            assert_eq!(response.headers()["x-frame-options"], "DENY");
            assert_eq!(response.headers()["x-content-type-options"], "nosniff");
            assert!(response.headers().contains_key("content-security-policy"));
        }
    }
    let post = app
        .clone()
        .oneshot(Request::post("/login/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(post.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert!(!post.headers().contains_key("location"));
    for path in [
        "/login//",
        "/static/",
        "/static/login.css/",
        "/whoami/",
        "/loginx/",
    ] {
        let response = get(app.clone(), path).await;
        assert!(!response.status().is_redirection(), "{path}");
    }

    for ui in [json!({}), json!({"enabled": false})] {
        let (app, _) = startup::build_app(Arc::new(config(ui))).await.unwrap();
        assert_eq!(get(app, "/login/").await.status(), StatusCode::NOT_FOUND);
    }
}

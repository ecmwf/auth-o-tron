// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! Direct browser login with shared transaction and identity-session protections.

use super::login::{render_page, secure_response};
use crate::{
    browser::{
        BrowserCredentials, BrowserSession, BrowserVerifyError, DISPLAY_ATTRIBUTES, LoginFlow,
    },
    config::UiConfig,
    metrics::{BrowserAttemptGuard, BrowserOutcome},
    state::AppState,
};
use axum::{
    Form, Router,
    extract::{DefaultBodyLimit, State, rejection::FormRejection},
    http::{HeaderMap, StatusCode, header},
    response::{Html, IntoResponse, Redirect, Response},
    routing::get,
};
use cookie::{Cookie, SameSite, time::Duration};
use maud::{Markup, html};
use serde::Deserialize;

const FORM_COOKIE: &str = "__Host-authotron_form";
const SESSION_COOKIE: &str = "__Host-authotron_session";
const ERROR: &str = "Key invalid or could not be verified";

pub(super) fn private_ui(state: &AppState) -> UiConfig {
    let mut config = state.config.ui.clone();
    let same_origin = config.branding.logo_url.as_ref().is_none_or(|logo| {
        logo.as_str().starts_with('/')
            || url::Url::parse(logo.as_str()).is_ok_and(|url| {
                Some(url.origin().ascii_serialization()).as_deref()
                    == state.browser.origin.as_deref()
            })
    });
    if !same_origin {
        config.branding.logo_url = None;
    }
    config
}

fn private_page(state: &AppState, card: Markup) -> String {
    render_page(&private_ui(state), card)
}

fn private_response(response: Response) -> Response {
    let mut response = secure_response(response, true);
    response.headers_mut().insert(header::CONTENT_SECURITY_POLICY,
        "default-src 'none'; style-src 'self'; img-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'".parse().expect("static policy"));
    // no-referrer turns navigation POST Origin into null; retain only its origin instead.
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        "strict-origin".parse().expect("static policy"),
    );
    response
}

pub fn routes(config: &UiConfig) -> Router<AppState> {
    if !config.enabled || !config.has_direct_login() {
        return Router::new();
    }
    let mut router = Router::new();
    if config.ecmwf_api_key.is_some() {
        router = router.route("/login/ecmwf-api-key", get(key_form).post(submit_key));
    }
    if config.basic.is_some() {
        router = router.route("/login/basic", get(basic_form).post(submit_basic));
    }
    router
        .route("/login/account", get(account))
        .layer(DefaultBodyLimit::max(8 * 1024))
}

/// Valid: `__Host-authotron_session=opaque`. Invalid: duplicate session cookies.
fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let mut found = None;
    for header in headers.get_all(header::COOKIE) {
        for parsed in Cookie::split_parse(header.to_str().ok()?) {
            let cookie = parsed.ok()?;
            if cookie.name() == name {
                if found.is_some() {
                    return None;
                }
                found = Some(cookie.value().to_owned());
            }
        }
    }
    found
}

fn set_cookie(response: &mut Response, name: &'static str, value: String, ttl: u64) {
    let cookie = Cookie::build((name, value))
        .secure(true)
        .http_only(true)
        .same_site(SameSite::Lax)
        .path("/")
        .max_age(Duration::seconds(ttl as i64))
        .build();
    response.headers_mut().append(
        header::SET_COOKIE,
        cookie.to_string().parse().expect("generated cookie"),
    );
}

pub(super) async fn current_session(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<Option<BrowserSession>, BrowserVerifyError> {
    let Some(sid) = cookie_value(headers, SESSION_COOKIE) else {
        return Ok(None);
    };
    state.browser.lookup(&sid).await
}

pub(super) fn unavailable(error: BrowserVerifyError) -> Response {
    let outcome = error_outcome(&error);
    let mut response = private_response(
        (
            if error == BrowserVerifyError::Limited {
                StatusCode::TOO_MANY_REQUESTS
            } else {
                StatusCode::SERVICE_UNAVAILABLE
            },
            "Sign-in temporarily unavailable",
        )
            .into_response(),
    );
    response.extensions_mut().insert(outcome);
    response
}

async fn form_response(
    state: &AppState,
    flow: LoginFlow,
    status: StatusCode,
    error: bool,
) -> Response {
    let (sid, csrf) = match state.browser.form(flow).await {
        Ok(form) => form,
        Err(error) => return unavailable(error),
    };
    let page = private_page(
        state,
        html! {
            h2 id="login-card-title" { @if flow == LoginFlow::ApiKey { "ECMWF API key" } @else { "Username and password" } }
            @if error { p class="login-card-message" role="alert" { (flow_error(flow)) } }
            p class="login-card-detail" { "Verify your identity for a short-lived Auth-O-Tron browser session." }
            form class="key-form" method="post" action=(if flow == LoginFlow::ApiKey { "/login/ecmwf-api-key" } else { "/login/basic" }) {
                input type="hidden" name="csrf" value=(csrf);
                @if flow == LoginFlow::ApiKey {
                    label for="api-key" { "ECMWF API key" }
                    input class="login-input" id="api-key" type="password" name="api_key" autocomplete="off" maxlength="512" required;
                } @else {
                    label for="username" { "Username" }
                    input class="login-input" id="username" name="username" autocomplete="username" maxlength="256" required;
                    label for="password" { "Password" }
                    input class="login-input" id="password" type="password" name="password" autocomplete="current-password" maxlength="1024" required;
                }
                button class="login-action" type="submit" { "Sign in" }
            }
            p class="login-card-detail" { "This verifies your identity in Auth-O-Tron. Application sign-in handoff is separate." }
        },
    );
    let mut response = private_response((status, Html(page)).into_response());
    set_cookie(
        &mut response,
        FORM_COOKIE,
        sid,
        state.browser.transaction_ttl(),
    );
    response
}

fn flow_error(flow: LoginFlow) -> &'static str {
    if flow == LoginFlow::ApiKey {
        ERROR
    } else {
        "Credentials invalid or could not be verified"
    }
}

async fn key_form(State(state): State<AppState>) -> Response {
    form_response(&state, LoginFlow::ApiKey, StatusCode::OK, false).await
}

async fn basic_form(State(state): State<AppState>) -> Response {
    form_response(&state, LoginFlow::Basic, StatusCode::OK, false).await
}

// Valid: api_key=public-fixture&csrf=opaque. Invalid: a missing or duplicate csrf field.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyForm {
    api_key: String,
    csrf: String,
}

// Valid: username=alice&password=public-fixture&csrf=opaque. Invalid: submitted roles.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BasicForm {
    username: String,
    password: String,
    csrf: String,
}

struct Submission {
    csrf: String,
    username: String,
    secret: String,
}

async fn submit_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Form<KeyForm>, FormRejection>,
) -> Response {
    submit(
        state,
        headers,
        payload.map(|Form(p)| Submission {
            csrf: p.csrf,
            username: String::new(),
            secret: p.api_key,
        }),
        LoginFlow::ApiKey,
    )
    .await
}

async fn submit_basic(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Form<BasicForm>, FormRejection>,
) -> Response {
    submit(
        state,
        headers,
        payload.map(|Form(p)| Submission {
            csrf: p.csrf,
            username: p.username,
            secret: p.password,
        }),
        LoginFlow::Basic,
    )
    .await
}

async fn submit(
    state: AppState,
    headers: HeaderMap,
    payload: Result<Submission, FormRejection>,
    flow: LoginFlow,
) -> Response {
    let mut attempt = state.metrics.browser_attempt_guard(flow);
    let response = submit_inner(state, headers, payload, flow, &mut attempt).await;
    if let Some(outcome) = response.extensions().get::<BrowserOutcome>() {
        attempt.outcome = *outcome;
    }
    attempt.complete();
    response
}

fn error_outcome(error: &BrowserVerifyError) -> BrowserOutcome {
    match error {
        BrowserVerifyError::Limited => BrowserOutcome::Limited,
        BrowserVerifyError::Rejected => BrowserOutcome::Rejected,
        BrowserVerifyError::Unavailable => BrowserOutcome::BackendUnavailable,
        BrowserVerifyError::Capacity => BrowserOutcome::Capacity,
        BrowserVerifyError::Timeout => BrowserOutcome::Timeout,
    }
}

async fn submit_inner(
    state: AppState,
    headers: HeaderMap,
    payload: Result<Submission, FormRejection>,
    flow: LoginFlow,
    attempt: &mut BrowserAttemptGuard,
) -> Response {
    let mut origins = headers.get_all(header::ORIGIN).iter();
    let origin_valid = origins.next().and_then(|o| o.to_str().ok())
        == state.browser.origin.as_deref()
        && origins.next().is_none();
    if !origin_valid {
        attempt.outcome = BrowserOutcome::Origin;
        return private_response((StatusCode::FORBIDDEN, flow_error(flow)).into_response());
    }
    let payload = match payload {
        Ok(form) => form,
        Err(error) => {
            attempt.outcome = BrowserOutcome::Malformed;
            // The extractor diagnostic can contain submitted values; never render it.
            let status = if error.status() == StatusCode::PAYLOAD_TOO_LARGE {
                StatusCode::PAYLOAD_TOO_LARGE
            } else {
                StatusCode::BAD_REQUEST
            };
            if let Some(sid) = cookie_value(&headers, FORM_COOKIE)
                && let Err(error) = state.browser.discard(&sid).await
            {
                return unavailable(error);
            }
            return form_response(&state, flow, status, true).await;
        }
    };
    let valid_transaction = if let Some(sid) = cookie_value(&headers, FORM_COOKIE) {
        match state.browser.consume(&sid, &payload.csrf, flow).await {
            Ok(valid) => valid,
            Err(error) => return unavailable(error),
        }
    } else {
        false
    };
    if !valid_transaction {
        attempt.outcome = BrowserOutcome::Csrf;
        return form_response(&state, flow, StatusCode::FORBIDDEN, true).await;
    }
    let credentials = match flow {
        LoginFlow::ApiKey => BrowserCredentials::ApiKey(&payload.secret),
        LoginFlow::Basic => {
            // Preserve UTF-8 and password whitespace exactly; ':' cannot delimit a username.
            BrowserCredentials::Basic {
                username: &payload.username,
                password: &payload.secret,
            }
        }
    };
    let user = match state
        .browser
        .verify_identity(credentials, &state.auth, &state.metrics)
        .await
    {
        Ok(user) => user,
        Err(error @ (BrowserVerifyError::Rejected | BrowserVerifyError::Timeout)) => {
            attempt.outcome = error_outcome(&error);
            return form_response(&state, flow, StatusCode::UNAUTHORIZED, true).await;
        }
        Err(BrowserVerifyError::Limited) => {
            attempt.outcome = BrowserOutcome::Limited;
            return private_response(
                (
                    StatusCode::TOO_MANY_REQUESTS,
                    "Sign-in temporarily unavailable",
                )
                    .into_response(),
            );
        }
        Err(error) => {
            attempt.outcome = error_outcome(&error);
            return unavailable(error);
        }
    };
    drop(payload);
    let previous = cookie_value(&headers, SESSION_COOKIE);
    let sid = match state.browser.save_session(user, previous.as_deref()).await {
        Ok(sid) => sid,
        Err(error) => {
            attempt.outcome = error_outcome(&error);
            return unavailable(error);
        }
    };
    let mut response = private_response(Redirect::to("/login/account").into_response());
    set_cookie(&mut response, SESSION_COOKIE, sid, state.browser.ttl);
    set_cookie(&mut response, FORM_COOKIE, String::new(), 0);
    attempt.outcome = BrowserOutcome::Success;
    response
}

async fn account(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let session = match current_session(&state, &headers).await {
        Ok(Some(session)) => session,
        Ok(None) => return private_response(Redirect::to("/login").into_response()),
        Err(error) => return unavailable(error),
    };
    let expiry = session.expires_at_utc;
    let page = private_page(
        &state,
        html! {
            h2 id="login-card-title" { "Verified identity" }
            dl {
                dt { "Username" } dd { (&session.user.username) }
                dt { "Realm" } dd { (&session.user.realm) }
                dt { "Roles" } dd {
                    @if session.user.roles.is_empty() { "None" }
                    @else { ul { @for role in &session.user.roles { li { (role) } } } }
                }
                @for (key, label, _) in DISPLAY_ATTRIBUTES {
                    @if let Some(value) = session.user.attributes.get(key) {
                        dt { (label) } dd { (value) }
                    }
                }
            }
            p class="login-card-detail" { "Session expires at " (expiry.to_rfc3339()) ". Next sign-in requires password or API-key re-entry; there is no automatic refresh." }
            p class="login-card-detail" { "This session displays your Auth-O-Tron identity. Application sign-in handoff is separate." }
        },
    );
    private_response(Html(page).into_response())
}

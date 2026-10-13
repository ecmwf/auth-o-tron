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
        BrowserCredentials, BrowserMethod, BrowserSession, BrowserVerifyError, DISPLAY_ATTRIBUTES,
        LoginFlow,
    },
    config::{BrowserMethodKind, UiConfig},
    metrics::{BrowserAttemptGuard, BrowserOutcome},
    oauth::{
        authentication::VerifiedOAuthIdentity,
        context::{AuthenticatedAuthorization, ContextError},
        records::BoundAuthorizationTransaction,
        runtime::OAuthRuntime,
        store::{StoreError, TransactionId},
    },
    state::AppState,
};
use axum::{
    Form, Router,
    extract::{DefaultBodyLimit, OriginalUri, Path, State, rejection::FormRejection},
    http::{HeaderMap, StatusCode, header},
    response::{Html, IntoResponse, Redirect, Response},
    routing::get,
};
use cookie::{Cookie, SameSite, time::Duration};
use maud::{Markup, html};
use serde::Deserialize;

pub(super) const FORM_COOKIE: &str = "__Host-authotron_form";
pub(super) const SESSION_COOKIE: &str = "__Host-authotron_session";
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

pub(super) fn private_page(state: &AppState, card: Markup) -> String {
    render_page(&private_ui(state), card)
}

pub(super) fn private_response(response: Response) -> Response {
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

pub fn routes(state: &AppState) -> Router<AppState> {
    if !state.config.ui.enabled || state.browser.methods().is_empty() {
        return Router::new();
    }
    Router::new()
        .route("/login/method/{id}", get(method_form).post(submit))
        .route("/login/method/{id}/", get(method_slash))
        .route(
            "/login/method/{id}/callback",
            get(super::oidc_login::callback),
        )
        .route("/login/account", get(account))
        .route("/login/account/", get(account_slash))
        .layer(DefaultBodyLimit::max(8 * 1024))
}

pub(super) fn method_path(id: &str) -> String {
    format!("/login/method/{id}")
}

/// Resolves a `/login/method/{id}` segment by exact match against configured
/// `browser.id` values, which are validated at startup. Ids are canonical `[a-z0-9-]`
/// text, so a request whose raw path contains any `%` escape (even one decoding to a
/// configured id) is rejected rather than decoded: each method has one URL.
/// Valid: `password`, `ecmwf-api-key` when configured. Invalid: `Password`,
/// `pass%77ord`, `password%20`, `0`, or any id with no configured method.
pub(super) fn resolve_method<'a>(
    state: &'a AppState,
    uri: &OriginalUri,
    id: &str,
) -> Option<&'a BrowserMethod> {
    if uri.path().contains('%') {
        return None;
    }
    state.browser.method(id)
}

/// Bare private 404 for non-navigational requests (e.g. form POSTs).
fn not_found() -> Response {
    private_response(StatusCode::NOT_FOUND.into_response())
}

/// Branded private 404 for GET/HEAD navigation to unknown `/login/...` paths.
pub(super) fn not_found_page(state: &AppState) -> Response {
    let card = html! {
        h2 id="login-card-title" { "Page not found" }
        p class="login-card-detail" { "This sign-in page does not exist or is no longer available." }
        p { a href="/login" { "Back to sign in" } }
    };
    private_response((StatusCode::NOT_FOUND, Html(private_page(state, card))).into_response())
}

/// Fallback for unmatched paths below `/login/` while the UI is enabled.
/// GET/HEAD render the branded page; other methods get the bare 404.
pub(super) async fn login_fallback(State(state): State<AppState>) -> Response {
    not_found_page(&state)
}

/// Valid: `__Host-authotron_session=opaque`. Invalid: duplicate session cookies.
pub(super) fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
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

pub(super) fn set_cookie(response: &mut Response, name: &'static str, value: String, ttl: u64) {
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
    headers: &HeaderMap,
    method: &BrowserMethod,
    status: StatusCode,
    error: bool,
) -> Response {
    let flow = &method.flow;
    let oauth_transaction = match super::oauth::form_transaction(state, headers).await {
        Ok(transaction) => transaction,
        Err(status) => return super::oauth::local(status),
    };
    let form_nonce = cookie_value(headers, FORM_COOKIE)
        .filter(|value| crate::browser::valid_id(value))
        .unwrap_or_else(crate::browser::opaque_id);
    let csrf = match state.browser.form_with_nonce(flow, &form_nonce).await {
        Ok(form) => form,
        Err(error) => return unavailable(error),
    };
    let api_key = flow.kind == BrowserMethodKind::ApiKey;
    let label = method.label.as_str();
    let page = private_page(
        state,
        html! {
            h2 id="login-card-title" { (label) }
            @if error { p class="login-card-message" role="alert" { (flow_error(flow)) } }
            p class="login-card-detail" {
                @if oauth_transaction.is_some() { "Verify your identity to review this authorization request." }
                @else { "Verify your identity for a short-lived Auth-O-Tron browser session." }
            }
            form class="key-form" method="post" action=(method_path(&flow.method)) {
                input type="hidden" name="csrf" value=(csrf);
                @if let Some(id) = &oauth_transaction { input type="hidden" name="oauth_transaction" value=(id); }
                @if api_key {
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
            p class="login-card-detail" {
                @if oauth_transaction.is_some() { "Explicit approval is required before returning to the registered application." }
                @else { "This verifies your identity in Auth-O-Tron. Application sign-in handoff is separate." }
            }
        },
    );
    let mut response = private_response((status, Html(page)).into_response());
    set_cookie(
        &mut response,
        FORM_COOKIE,
        form_nonce,
        state.browser.transaction_ttl(),
    );
    response
}

fn flow_error(flow: &LoginFlow) -> &'static str {
    if flow.kind == BrowserMethodKind::ApiKey {
        ERROR
    } else {
        "Credentials invalid or could not be verified"
    }
}

/// Redirects `/login/method/{id}/` only for a configured method; the
/// Location is rebuilt from the configured id, never echoed from the request.
async fn method_slash(
    State(state): State<AppState>,
    uri: OriginalUri,
    Path(id): Path<String>,
) -> Response {
    match resolve_method(&state, &uri, &id) {
        Some(method) => private_response(super::login::canonical_redirect(
            &method_path(&method.flow.method),
            true,
        )),
        None => not_found_page(&state),
    }
}

async fn account_slash() -> Response {
    private_response(super::login::canonical_redirect("/login/account", true))
}

async fn method_form(
    State(state): State<AppState>,
    uri: OriginalUri,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Some(method) = resolve_method(&state, &uri, &id) else {
        return not_found_page(&state);
    };
    if let Some(response) = super::oauth::login_entry_recovery(&state, &headers).await {
        return response;
    }
    if let Some(oidc) = method.oidc() {
        return super::oidc_login::start(&state, &headers, method, oidc).await;
    }
    form_response(&state, &headers, method, StatusCode::OK, false).await
}

// `csrf` is the opaque token from `BrowserLoginState::form_with_nonce`; the
// credential fields must match the method type.
// Valid (ecmwf-api): api_key=public-fixture&csrf=<64hex>.<64hex>.
// Valid (plain): username=alice&password=public-fixture&csrf=<64hex>.<64hex>.
// Invalid: duplicate csrf, an unknown field such as roles, or api_key posted
// to a plain method.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MethodForm {
    #[serde(default)]
    oauth_transaction: Option<String>,
    #[serde(default)]
    api_key: Option<String>,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
    csrf: String,
}

struct Submission {
    oauth_transaction: Option<String>,
    csrf: String,
    username: String,
    secret: String,
}

impl MethodForm {
    fn submission(self, kind: BrowserMethodKind) -> Option<Submission> {
        let (username, secret) = match (kind, self.api_key, self.username, self.password) {
            (BrowserMethodKind::ApiKey, Some(key), None, None) => (String::new(), key),
            (BrowserMethodKind::Basic, None, Some(username), Some(password)) => {
                (username, password)
            }
            _ => return None,
        };
        Some(Submission {
            oauth_transaction: self.oauth_transaction,
            csrf: self.csrf,
            username,
            secret,
        })
    }
}

/// Body errors are reported without the extractor diagnostic, which can echo values.
enum PayloadError {
    TooLarge,
    Malformed,
}

async fn submit(
    State(state): State<AppState>,
    uri: OriginalUri,
    Path(id): Path<String>,
    headers: HeaderMap,
    payload: Result<Form<MethodForm>, FormRejection>,
) -> Response {
    let Some(method) = resolve_method(&state, &uri, &id) else {
        return not_found();
    };
    let flow = &method.flow;
    // Redirect methods have no credential form to submit.
    if flow.kind == BrowserMethodKind::Oidc {
        return not_found();
    }
    let payload = match payload {
        Ok(Form(form)) => form.submission(flow.kind).ok_or(PayloadError::Malformed),
        Err(error) if error.status() == StatusCode::PAYLOAD_TOO_LARGE => {
            Err(PayloadError::TooLarge)
        }
        Err(_) => Err(PayloadError::Malformed),
    };
    let mut attempt = state.metrics.browser_attempt_guard(flow);
    let response = submit_inner(&state, headers, payload, method, &mut attempt).await;
    if let Some(outcome) = response.extensions().get::<BrowserOutcome>() {
        attempt.outcome = *outcome;
    }
    attempt.complete();
    response
}

pub(super) fn error_outcome(error: &BrowserVerifyError) -> BrowserOutcome {
    match error {
        BrowserVerifyError::Limited => BrowserOutcome::Limited,
        BrowserVerifyError::Rejected => BrowserOutcome::Rejected,
        BrowserVerifyError::Unavailable => BrowserOutcome::BackendUnavailable,
        BrowserVerifyError::Capacity => BrowserOutcome::Capacity,
        BrowserVerifyError::Timeout => BrowserOutcome::Timeout,
    }
}

async fn submit_inner(
    state: &AppState,
    headers: HeaderMap,
    payload: Result<Submission, PayloadError>,
    method: &BrowserMethod,
    attempt: &mut BrowserAttemptGuard,
) -> Response {
    let flow = &method.flow;
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
            let status = match error {
                PayloadError::TooLarge => StatusCode::PAYLOAD_TOO_LARGE,
                PayloadError::Malformed => StatusCode::BAD_REQUEST,
            };
            // Unparseable input proves neither transaction ownership nor CSRF knowledge.
            return form_response(state, &headers, method, status, true).await;
        }
    };
    let oauth_context =
        match super::oauth::posted_context(&headers, payload.oauth_transaction.as_deref()) {
            Ok(context) => context,
            Err(status) => {
                attempt.outcome = BrowserOutcome::Csrf;
                return super::oauth::local(status);
            }
        };
    let valid_transaction = if let Some(form_nonce) = cookie_value(&headers, FORM_COOKIE) {
        match state
            .browser
            .consume_with_nonce(&payload.csrf, &form_nonce, flow)
            .await
        {
            Ok(valid) => valid,
            Err(error) => return unavailable(error),
        }
    } else {
        false
    };
    if !valid_transaction {
        attempt.outcome = BrowserOutcome::Csrf;
        return form_response(state, &headers, method, StatusCode::FORBIDDEN, true).await;
    }
    let credentials = match flow.kind {
        BrowserMethodKind::ApiKey => BrowserCredentials::ApiKey(&payload.secret),
        BrowserMethodKind::Basic => {
            // Preserve UTF-8 and password whitespace exactly; ':' cannot delimit a username.
            BrowserCredentials::Basic {
                username: &payload.username,
                password: &payload.secret,
            }
        }
        BrowserMethodKind::Oidc => return not_found(),
    };
    if let Some((id, binding)) = oauth_context {
        let Some(runtime) = &state.oauth else {
            attempt.outcome = BrowserOutcome::Csrf;
            return super::oauth::local(StatusCode::FORBIDDEN);
        };
        let witness = match runtime.bound(&id, &binding).await {
            Ok(witness) => witness,
            Err(error) => {
                let (response, outcome) = pending_failure(error);
                attempt.outcome = outcome;
                return response;
            }
        };
        let identity = match crate::oauth::authentication::verify_identity(
            &flow.method,
            credentials,
            &state.browser,
            &state.auth,
            &state.metrics,
        )
        .await
        {
            Ok(identity) => identity,
            Err(error) => {
                use crate::oauth::authentication::AuthenticationError::*;
                attempt.outcome = match error {
                    Rejected => BrowserOutcome::Rejected,
                    Timeout => BrowserOutcome::Timeout,
                    Limited => BrowserOutcome::Limited,
                    Unavailable => BrowserOutcome::BackendUnavailable,
                };
                return match error {
                    Rejected | Timeout => {
                        form_response(state, &headers, method, StatusCode::UNAUTHORIZED, true).await
                    }
                    Limited => super::oauth::local(StatusCode::TOO_MANY_REQUESTS),
                    Unavailable => super::oauth::local(StatusCode::SERVICE_UNAVAILABLE),
                };
            }
        };
        let (response, outcome) =
            finish_authorization_login(runtime, &id, &binding, witness, identity).await;
        attempt.outcome = outcome;
        return response;
    }
    let user = match state
        .browser
        .verify_identity(&flow.method, credentials, &state.auth, &state.metrics)
        .await
    {
        Ok(user) => user,
        Err(error @ (BrowserVerifyError::Rejected | BrowserVerifyError::Timeout)) => {
            attempt.outcome = error_outcome(&error);
            return form_response(state, &headers, method, StatusCode::UNAUTHORIZED, true).await;
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
    let sid = match state
        .browser
        .save_session(user, None, previous.as_deref())
        .await
    {
        Ok(sid) => sid,
        Err(error) => {
            attempt.outcome = error_outcome(&error);
            return unavailable(error);
        }
    };
    let mut response = private_response(Redirect::to("/login/account").into_response());
    set_cookie(&mut response, SESSION_COOKIE, sid, state.browser.ttl);
    attempt.outcome = BrowserOutcome::Success;
    response
}

/// Response for a failed lookup of the pending authorization bound to this browser: a
/// missing transaction is a 400 counted as `csrf`; backend failures are 503.
pub(super) fn pending_failure(error: StoreError) -> (Response, BrowserOutcome) {
    if error == StoreError::Missing {
        (
            super::oauth::local(StatusCode::BAD_REQUEST),
            BrowserOutcome::Csrf,
        )
    } else {
        (
            super::oauth::local(StatusCode::SERVICE_UNAVAILABLE),
            BrowserOutcome::BackendUnavailable,
        )
    }
}

/// Binds a freshly verified identity to its pending authorization and continues to
/// consent; an identity the scope policy denies ends the flow with `access_denied`.
pub(super) async fn finish_authorization_login(
    runtime: &OAuthRuntime,
    id: &TransactionId,
    binding: &[u8; 32],
    witness: BoundAuthorizationTransaction,
    identity: VerifiedOAuthIdentity,
) -> (Response, BrowserOutcome) {
    let now = match runtime.now().await {
        Ok(now) => now,
        Err(_) => {
            return (
                super::oauth::local(StatusCode::SERVICE_UNAVAILABLE),
                BrowserOutcome::BackendUnavailable,
            );
        }
    };
    let context = match AuthenticatedAuthorization::new_bound(
        witness,
        identity,
        binding,
        &runtime.config,
        now,
    ) {
        Ok(context) => context,
        Err(ContextError::AccessDenied) => {
            // A verified identity that fails scope policy. The request was validated at
            // /oauth/authorize, so per RFC 6749 §4.1.2.1 the transaction is consumed
            // atomically and the registered callback gets access_denied.
            let consumed = runtime.consume_pending(id, binding).await;
            let outcome = policy_denial_outcome(&consumed);
            let response = match consumed {
                Ok(transaction) => super::oauth::access_denied(runtime, transaction.request()),
                Err(StoreError::Missing) => super::oauth::local(StatusCode::BAD_REQUEST),
                Err(_) => super::oauth::local(StatusCode::SERVICE_UNAVAILABLE),
            };
            return (response, outcome);
        }
        Err(error) => {
            use ContextError::*;
            let status = match error {
                Configuration | InvalidTime => StatusCode::SERVICE_UNAVAILABLE,
                InvalidTransaction | Binding => StatusCode::BAD_REQUEST,
                _ => StatusCode::FORBIDDEN,
            };
            let outcome = if status == StatusCode::SERVICE_UNAVAILABLE {
                BrowserOutcome::BackendUnavailable
            } else {
                BrowserOutcome::Rejected
            };
            return (super::oauth::local(status), outcome);
        }
    };
    if runtime.promote(id, binding, context).await.is_err() {
        return (
            super::oauth::local(StatusCode::SERVICE_UNAVAILABLE),
            BrowserOutcome::BackendUnavailable,
        );
    }
    (
        private_response(Redirect::to("/oauth/continue").into_response()),
        BrowserOutcome::Success,
    )
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
                dt { "Signed in as" } dd { (session.shown_name()) }
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
            p class="login-card-detail" { "Session expires at " (expiry.to_rfc3339()) ". Next sign-in requires verifying your identity again; there is no automatic refresh." }
            p class="login-card-detail" { "This session displays your Auth-O-Tron identity. Application sign-in handoff is separate." }
        },
    );
    private_response(Html(page).into_response())
}

/// Classifies the policy-denial consume: `denied` only when the `access_denied`
/// redirect is issued. A concurrent consumer winning the race (`Missing`) yields a
/// plain 400 and is counted as `rejected`.
fn policy_denial_outcome<T>(
    consumed: &Result<T, crate::oauth::store::StoreError>,
) -> BrowserOutcome {
    match consumed {
        Ok(_) => BrowserOutcome::Denied,
        Err(crate::oauth::store::StoreError::Missing) => BrowserOutcome::Rejected,
        Err(_) => BrowserOutcome::BackendUnavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::store::StoreError;

    #[test]
    fn policy_denial_counts_denied_only_when_redirect_happens() {
        assert!(matches!(
            policy_denial_outcome(&Ok::<(), StoreError>(())),
            BrowserOutcome::Denied
        ));
        assert!(matches!(
            policy_denial_outcome::<()>(&Err(StoreError::Missing)),
            BrowserOutcome::Rejected
        ));
        assert!(matches!(
            policy_denial_outcome::<()>(&Err(StoreError::Unavailable)),
            BrowserOutcome::BackendUnavailable
        ));
    }
}

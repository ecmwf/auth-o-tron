// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! OpenID Connect sign-in: `GET /login/method/{id}` redirects to the provider with a
//! single-use state bound to this browser, and `GET /login/method/{id}/callback`
//! verifies the provider's answer and starts a browser session. Pages are generic;
//! provider error text, codes and tokens are never shown or logged.

use super::browser_login::{
    FORM_COOKIE, SESSION_COOKIE, cookie_value, error_outcome, not_found_page, private_page,
    private_response, resolve_method, set_cookie, unavailable,
};
use crate::{
    browser::{BrowserMethod, opaque_id, valid_id},
    metrics::{BrowserAttemptGuard, BrowserOutcome},
    models::user::User,
    oidc::{
        OidcError,
        flow::{self, CallbackResult, FlowSecrets},
        method::OidcMethod,
    },
    state::AppState,
};
use axum::{
    extract::{OriginalUri, Path, RawQuery, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
};
use maud::html;

type Notice = (&'static str, &'static str);
const EXPIRED: Notice = (
    "Sign-in expired",
    "This sign-in attempt is no longer valid. Start again from the sign-in page.",
);
const NOT_COMPLETED: Notice = (
    "Sign-in not completed",
    "The identity provider did not complete the sign-in. Start again or choose another method.",
);
const UNVERIFIED: Notice = (
    "Sign-in could not be verified",
    "The identity provider's answer could not be verified. Start again from the sign-in page.",
);
const NOT_PERMITTED: Notice = ("Sign-in not permitted", "This account cannot sign in here.");
const PROVIDER_UNAVAILABLE: Notice = (
    "Sign-in temporarily unavailable",
    "The identity provider cannot be reached. Try again later or choose another method.",
);

fn notice(state: &AppState, status: StatusCode, (title, detail): Notice) -> Response {
    let card = html! {
        h2 id="login-card-title" { (title) }
        p class="login-card-detail" { (detail) }
        p { a href="/login" { "Back to sign in" } }
    };
    private_response((status, Html(private_page(state, card))).into_response())
}

/// Redirects to the provider's authorization endpoint. The state record is created only
/// once provider metadata is available, so an unreachable provider spends no capacity.
pub(super) async fn start(
    state: &AppState,
    headers: &HeaderMap,
    method: &BrowserMethod,
    oidc: &OidcMethod,
) -> Response {
    // Pending authorization requests continue with credential methods.
    if !matches!(super::oauth::parse_browser_binding(headers), Ok(None)) {
        return super::oauth::local(StatusCode::CONFLICT);
    }
    let metadata = match oidc.metadata().await {
        Ok(metadata) => metadata,
        Err(error) => {
            tracing::warn!(
                event_name = "browser.oidc.start_unavailable",
                event_domain = "browser",
                method = %method.flow.method,
                reason = error.label(),
                "OIDC provider metadata unavailable"
            );
            return notice(state, StatusCode::SERVICE_UNAVAILABLE, PROVIDER_UNAVAILABLE);
        }
    };
    let form_nonce = cookie_value(headers, FORM_COOKIE)
        .filter(|value| valid_id(value))
        .unwrap_or_else(opaque_id);
    let binding = flow::binding(&form_nonce, None);
    let sign_in_state = match state.browser.form_with_nonce(&method.flow, &binding).await {
        Ok(token) => token,
        Err(error) => return unavailable(error),
    };
    let secrets = FlowSecrets::derive(&form_nonce, &sign_in_state);
    let location = oidc.authorization_url(&metadata, &sign_in_state, &secrets);
    let mut response = private_response(Redirect::to(location.as_str()).into_response());
    set_cookie(
        &mut response,
        FORM_COOKIE,
        form_nonce,
        state.browser.transaction_ttl(),
    );
    response
}

/// Why a callback produced no identity.
enum SignInError {
    Provider(OidcError),
    /// Augmentation did not accept the identity.
    Augmentation,
}

pub(super) async fn callback(
    State(state): State<AppState>,
    uri: OriginalUri,
    Path(id): Path<String>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Response {
    let Some((method, oidc)) = resolve_method(&state, &uri, &id)
        .and_then(|method| method.oidc().map(|oidc| (method, oidc.clone())))
    else {
        return not_found_page(&state);
    };
    let mut attempt = state.metrics.browser_attempt_guard(&method.flow);
    let response = complete(
        &state,
        &headers,
        method,
        &oidc,
        query.as_deref(),
        &mut attempt,
    )
    .await;
    attempt.complete();
    response
}

async fn complete(
    state: &AppState,
    headers: &HeaderMap,
    method: &BrowserMethod,
    oidc: &OidcMethod,
    query: Option<&str>,
    attempt: &mut BrowserAttemptGuard,
) -> Response {
    let Some(callback) = query.and_then(|query| flow::parse_callback(query.as_bytes())) else {
        attempt.outcome = BrowserOutcome::Malformed;
        return notice(state, StatusCode::BAD_REQUEST, EXPIRED);
    };
    let Some(form_nonce) = cookie_value(headers, FORM_COOKIE).filter(|value| valid_id(value))
    else {
        attempt.outcome = BrowserOutcome::Csrf;
        return notice(state, StatusCode::BAD_REQUEST, EXPIRED);
    };
    let binding = flow::binding(&form_nonce, None);
    match state
        .browser
        .consume_with_nonce(&callback.state, &binding, &method.flow)
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            attempt.outcome = BrowserOutcome::Csrf;
            return notice(state, StatusCode::BAD_REQUEST, EXPIRED);
        }
        Err(error) => {
            attempt.outcome = error_outcome(&error);
            return unavailable(error);
        }
    }
    let code = match callback.result {
        CallbackResult::Code(code) => code,
        CallbackResult::Error(error) => {
            tracing::info!(
                event_name = "browser.oidc.provider_error",
                event_domain = "browser",
                method = %method.flow.method,
                error = %error,
                "OIDC provider returned an authorization error"
            );
            attempt.outcome = BrowserOutcome::IdpError;
            return notice(state, StatusCode::BAD_REQUEST, NOT_COMPLETED);
        }
    };
    let secrets = FlowSecrets::derive(&form_nonce, &callback.state);
    let verified = state
        .browser
        .admitted_with_metrics(
            async { Ok(verify(state, oidc, callback.iss.as_deref(), &code, &secrets).await) },
            Some(&state.metrics),
        )
        .await;
    let user = match verified {
        Ok(Ok(user)) => user,
        Ok(Err(error)) => return sign_in_failure(state, method, error, attempt),
        Err(error) => {
            attempt.outcome = error_outcome(&error);
            return unavailable(error);
        }
    };
    let previous = cookie_value(headers, SESSION_COOKIE);
    let sid = match state.browser.save_session(user, previous.as_deref()).await {
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

/// Provider verification, then the same best-effort augmentation as credential methods.
async fn verify(
    state: &AppState,
    oidc: &OidcMethod,
    iss: Option<&str>,
    code: &str,
    secrets: &FlowSecrets,
) -> Result<User, SignInError> {
    let user = oidc
        .complete(iss, code, secrets)
        .await
        .map_err(SignInError::Provider)?;
    state
        .auth
        .check_augmenters(user, &state.metrics)
        .await
        .ok_or(SignInError::Augmentation)
}

fn sign_in_failure(
    state: &AppState,
    method: &BrowserMethod,
    error: SignInError,
    attempt: &mut BrowserAttemptGuard,
) -> Response {
    let (reason, outcome, status, page) = match error {
        SignInError::Provider(
            error @ (OidcError::Unavailable
            | OidcError::ClientRejected
            | OidcError::InvalidResponse),
        ) => (
            error.label(),
            BrowserOutcome::IdpUnavailable,
            StatusCode::SERVICE_UNAVAILABLE,
            PROVIDER_UNAVAILABLE,
        ),
        SignInError::Provider(error @ (OidcError::Rejected | OidcError::InvalidIdToken)) => (
            error.label(),
            BrowserOutcome::Rejected,
            StatusCode::BAD_REQUEST,
            UNVERIFIED,
        ),
        SignInError::Provider(error @ OidcError::InvalidIdentity) => (
            error.label(),
            BrowserOutcome::Rejected,
            StatusCode::FORBIDDEN,
            NOT_PERMITTED,
        ),
        SignInError::Augmentation => (
            "augmentation",
            BrowserOutcome::Rejected,
            StatusCode::FORBIDDEN,
            NOT_PERMITTED,
        ),
    };
    tracing::warn!(
        event_name = "browser.oidc.sign_in_failed",
        event_domain = "browser",
        method = %method.flow.method,
        reason,
        "OIDC sign-in failed"
    );
    attempt.outcome = outcome;
    notice(state, status, page)
}

#[cfg(test)]
mod tests;

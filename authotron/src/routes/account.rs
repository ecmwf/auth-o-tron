// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! The account page of a browser session and the forms it posts. All forms of one page
//! view share one form transaction, checked like a sign-in form: exact `Origin`, the
//! form-nonce cookie and a one-use CSRF token.

use super::browser_login::{
    FORM_COOKIE, SESSION_COOKIE, cookie_value, current_session, private_page, private_response,
    same_origin, set_cookie, unavailable,
};
use crate::{
    browser::{BrowserVerifyError, DISPLAY_ATTRIBUTES},
    state::AppState,
};
use axum::{
    Form, Router,
    extract::{State, rejection::FormRejection},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use maud::html;
use serde::Deserialize;

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route("/login/account", get(page))
        .route("/login/account/", get(page_slash))
        .route("/login/logout", post(sign_out))
}

async fn page_slash() -> Response {
    private_response(super::login::canonical_redirect("/login/account", true))
}

async fn page(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let session = match current_session(&state, &headers).await {
        Ok(Some(session)) => session,
        Ok(None) => return private_response(Redirect::to("/login").into_response()),
        Err(error) => return unavailable(error),
    };
    let form_nonce = cookie_value(&headers, FORM_COOKIE)
        .filter(|value| crate::browser::valid_id(value))
        .unwrap_or_else(crate::browser::opaque_id);
    let csrf = match state.browser.account_form(&form_nonce).await {
        Ok(csrf) => csrf,
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
            form class="key-form" method="post" action="/login/logout" {
                input type="hidden" name="csrf" value=(csrf);
                button class="login-action" type="submit" { "Sign out" }
            }
        },
    );
    let mut response = private_response(Html(page).into_response());
    set_cookie(
        &mut response,
        FORM_COOKIE,
        form_nonce,
        state.browser.transaction_ttl(),
    );
    response
}

/// A refused account form: nothing was changed. Origin, CSRF and body failures share
/// this page, so it tells an attacker nothing about which check failed.
fn refused(state: &AppState, status: StatusCode) -> Response {
    let card = html! {
        h2 id="login-card-title" { "Request not completed" }
        p class="login-card-detail" { "This form has expired or did not come from this page. Nothing was changed." }
        p { a href="/login/account" { "Back to your account" } }
    };
    private_response((status, Html(private_page(state, card))).into_response())
}

/// Whether the posted `csrf` consumes this browser's account form transaction.
async fn consumed(
    state: &AppState,
    headers: &HeaderMap,
    csrf: &str,
) -> Result<bool, BrowserVerifyError> {
    let Some(form_nonce) = cookie_value(headers, FORM_COOKIE) else {
        return Ok(false);
    };
    state.browser.consume_account_form(csrf, &form_nonce).await
}

// `csrf` is the token of `BrowserLoginState::account_form`.
// Valid: csrf=<64hex>.<64hex>. Invalid: no csrf, a duplicate csrf, or any other field.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignOutForm {
    csrf: String,
}

/// Ends the browser session and clears its cookie, then shows the sign-in page with a
/// notice. Without a session it only clears the cookie. Logins of applications, which
/// hold refresh tokens, are not affected.
async fn sign_out(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Form<SignOutForm>, FormRejection>,
) -> Response {
    if !same_origin(&state, &headers) {
        return refused(&state, StatusCode::FORBIDDEN);
    }
    let Ok(Form(form)) = payload else {
        return refused(&state, StatusCode::BAD_REQUEST);
    };
    match consumed(&state, &headers, &form.csrf).await {
        Ok(true) => {}
        Ok(false) => return refused(&state, StatusCode::FORBIDDEN),
        Err(error) => return unavailable(error),
    }
    if let Some(sid) = cookie_value(&headers, SESSION_COOKIE)
        && let Err(error) = state.browser.end_session(&sid).await
    {
        return unavailable(error);
    }
    let mut response =
        private_response(Redirect::to(super::login::SIGNED_OUT_LOCATION).into_response());
    set_cookie(&mut response, SESSION_COOKIE, String::new(), 0);
    response
}

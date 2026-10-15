// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! The account page of a browser session and the forms it posts: signing out and, with
//! refresh tokens, revoking the user's logins. All forms of one page view share one
//! form transaction, checked like a sign-in form: exact `Origin`, the form-nonce cookie
//! and a one-use CSRF token.

use super::browser_login::{
    FORM_COOKIE, SESSION_COOKIE, cookie_value, current_session, private_page, private_response,
    same_origin, set_cookie, unavailable,
};
use crate::{
    browser::{BrowserVerifyError, DISPLAY_ATTRIBUTES},
    oauth::{audit::family_ref, logins::Logins, refresh::FamilySummary, runtime::OAuthRuntime},
    state::AppState,
};
use axum::{
    Form, Router,
    extract::{State, rejection::FormRejection},
    http::{HeaderMap, StatusCode, Uri},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use chrono::{DateTime, SecondsFormat};
use maud::{Markup, html};
use serde::Deserialize;

const REVOKE_PATH: &str = "/login/account/logins/revoke";
/// Where revoking leads: the account page with its revoked notice.
const REVOKED_LOCATION: &str = "/login/account?revoked";

pub(super) fn routes(state: &AppState) -> Router<AppState> {
    let routes = Router::new()
        .route("/login/account", get(page))
        .route("/login/account/", get(page_slash))
        .route("/login/logout", post(sign_out));
    if state.oauth.as_ref().is_some_and(|oauth| oauth.has_logins()) {
        routes.route(REVOKE_PATH, post(revoke))
    } else {
        routes
    }
}

async fn page_slash() -> Response {
    private_response(super::login::canonical_redirect("/login/account", true))
}

/// Shows the revoked notice only for the exact query of [`REVOKED_LOCATION`]; the text
/// is fixed and the same whether anything was revoked. Valid: `/login/account?revoked`.
/// Invalid (no notice): `/login/account?revoked=1`, `/login/account?a&revoked`.
async fn page(State(state): State<AppState>, uri: Uri, headers: HeaderMap) -> Response {
    let session = match current_session(&state, &headers).await {
        Ok(Some(session)) => session,
        Ok(None) => return private_response(Redirect::to("/login").into_response()),
        Err(error) => return unavailable(error),
    };
    let form_nonce = cookie_value(&headers, FORM_COOKIE)
        .filter(|value| crate::browser::valid_id(value))
        .unwrap_or_else(crate::browser::opaque_id);
    // Without a form (forms limited or the store failing) the identity is still shown.
    let csrf = match state.browser.account_form(&form_nonce).await {
        Ok(csrf) => Some(csrf),
        Err(error) => {
            tracing::warn!(
                event_name = "browser.account.forms_unavailable",
                event_domain = "browser",
                ?error,
                "account page shows no forms: none could be issued"
            );
            None
        }
    };
    // A store failure hides only the logins, so that signing out still works.
    let logins = match state.oauth.as_deref().filter(|oauth| oauth.has_logins()) {
        Some(runtime) => {
            let user = &session.user;
            let logins = runtime.logins(&user.realm, &user.username).await;
            if let Err(error) = &logins {
                tracing::warn!(
                    event_name = "browser.account.logins_unavailable",
                    event_domain = "browser",
                    ?error,
                    "account page shows no logins: the refresh-token store failed"
                );
            }
            Some((runtime, logins.ok()))
        }
        None => None,
    };
    let expiry = session.expires_at_utc;
    let page = private_page(
        &state,
        html! {
            h2 id="login-card-title" { "Verified identity" }
            @if uri.query() == Some("revoked") {
                p class="login-card-message" role="status" {
                    "Revoked. An application whose login you revoked must sign in again once its current access token expires."
                }
            }
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
            @if let Some(csrf) = &csrf {
                (sign_out_form(csrf))
            } @else {
                p class="login-card-message" role="status" { "Signing out and revoking logins are unavailable right now; reload this page to try again." }
            }
            @if let Some((runtime, logins)) = &logins {
                (logins_section(&state, runtime, logins.as_deref(), csrf.as_deref()))
            }
        },
    );
    let mut response = private_response(Html(page).into_response());
    if csrf.is_some() {
        let ttl = state.browser.transaction_ttl();
        set_cookie(&mut response, FORM_COOKIE, form_nonce, ttl);
    }
    response
}

fn sign_out_form(csrf: &str) -> Markup {
    html! {
        form class="key-form" method="post" action="/login/logout" {
            input type="hidden" name="csrf" value=(csrf);
            button class="login-action" type="submit" { "Sign out" }
        }
    }
}

/// `ms` as an element `<time datetime="2026-10-15T13:12:42Z">2026-10-15 13:12 UTC</time>`.
fn time(ms: u64) -> Markup {
    match i64::try_from(ms)
        .ok()
        .and_then(DateTime::from_timestamp_millis)
    {
        Some(at) => html! {
            time datetime=(at.to_rfc3339_opts(SecondsFormat::Secs, true)) {
                (at.format("%Y-%m-%d %H:%M UTC"))
            }
        },
        None => html! { "unknown" },
    }
}

/// "Your logins": each login with its client's display name, the label of its sign-in
/// method (or the configured ids, if they were removed), its times and short reference,
/// and a revoke form; then one form revoking them all. `logins` is `None` when the store
/// failed; without `csrf` there are no forms.
fn logins_section(
    state: &AppState,
    runtime: &OAuthRuntime,
    logins: Option<&[FamilySummary]>,
    csrf: Option<&str>,
) -> Markup {
    let client = |id: &str| {
        let client = runtime.config.clients.iter().find(|c| c.client_id == id);
        client.map_or(id.to_owned(), |client| client.display_name.clone())
    };
    let method = |id: &str| {
        state
            .browser
            .method(id)
            .map_or(id, |m| m.label.as_str())
            .to_owned()
    };
    html! {
        section aria-labelledby="logins-title" {
            h3 id="logins-title" { "Your logins" }
            p class="login-card-detail" {
                "Applications signed in with this identity. A revoked login can no longer refresh: its application must sign in again once its current access token expires."
            }
            @if let Some(logins) = logins.filter(|logins| !logins.is_empty()) {
                ul class="account-logins" {
                    @for login in logins {
                        @let name = client(&login.grant.client_id);
                        @let reference = family_ref(&login.family_id);
                        li {
                            h4 { (name) }
                            dl {
                                dt { "Sign-in method" } dd { (method(&login.grant.method)) }
                                dt { "Signed in" } dd { (time(login.created_at_ms)) }
                                dt { "Last used" } dd { (time(login.last_used_at_ms)) }
                                dt { "Expires if unused" } dd { (time(login.idle_expires_at_ms)) }
                                dt { "Expires at the latest" } dd { (time(login.absolute_expires_at_ms)) }
                                dt { "Reference" } dd { code { (reference) } }
                            }
                            @if let Some(csrf) = csrf {
                                form class="key-form" method="post" action=(REVOKE_PATH) {
                                    input type="hidden" name="csrf" value=(csrf);
                                    input type="hidden" name="login" value=(reference);
                                    button class="login-action" type="submit"
                                        aria-label=(format!("Revoke the login of {name}, reference {reference}")) { "Revoke" }
                                }
                            }
                        }
                    }
                }
                @if let Some(csrf) = csrf {
                    form class="key-form" method="post" action=(REVOKE_PATH) {
                        input type="hidden" name="csrf" value=(csrf);
                        input type="hidden" name="login" value="all";
                        button class="login-action" type="submit" { "Revoke all logins" }
                    }
                }
            } @else if logins.is_some() {
                p class="login-card-detail" { "No application is signed in." }
            } @else {
                p class="login-card-detail" role="status" { "Your logins cannot be shown right now; try again later." }
            }
        }
    }
}

/// A refused account form: nothing was changed. Origin, CSRF and body failures share
/// this page's text and differ only in their status: 403 for Origin and CSRF, 400 for
/// a malformed body.
fn refused(state: &AppState, status: StatusCode) -> Response {
    let card = html! {
        h2 id="login-card-title" { "Request not completed" }
        p class="login-card-detail" { "This form has expired or did not come from this page. Nothing was changed." }
        p { a href="/login/account" { "Back to your account" } }
    };
    private_response((status, Html(private_page(state, card))).into_response())
}

/// An account form the backend could not complete: 429 when it limits forms, else 503,
/// with one neutral page; part of the request may have been applied.
fn not_completed(state: &AppState, error: BrowserVerifyError) -> Response {
    let status = if error == BrowserVerifyError::Limited {
        StatusCode::TOO_MANY_REQUESTS
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    let card = html! {
        h2 id="login-card-title" { "Request not completed" }
        p class="login-card-detail" { "This could not be completed right now. Reload your account page to see where things stand, and try again later." }
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
        Err(error) => return not_completed(&state, error),
    }
    if let Some(sid) = cookie_value(&headers, SESSION_COOKIE)
        && let Err(error) = state.browser.end_session(&sid).await
    {
        tracing::warn!(
            event_name = "browser.account.sign_out_failed",
            event_domain = "browser",
            ?error,
            "browser session not ended: the session store failed"
        );
        return not_completed(&state, error);
    }
    let mut response =
        private_response(Redirect::to(super::login::SIGNED_OUT_LOCATION).into_response());
    set_cookie(&mut response, SESSION_COOKIE, String::new(), 0);
    response
}

// `csrf` is the account page's token; `login` names the logins to revoke: one by its
// reference, or `all`.
// Valid: csrf=<64hex>.<64hex>&login=3f2a9c0b71de, csrf=<64hex>.<64hex>&login=all.
// Invalid: login=3F2A9C0B71DE, an 11-digit reference, no login, a second login, or any
// other field.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RevokeForm {
    csrf: String,
    login: String,
}

/// The logins a [`RevokeForm`] names.
fn selected(login: &str) -> Option<Logins<'_>> {
    if login == "all" {
        return Some(Logins::All);
    }
    let reference = login.len() == 12
        && login
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    reference.then_some(Logins::Named(login))
}

/// Revokes logins of the signed-in user, then shows the account page with a notice
/// that does not tell whether the reference named one of them.
async fn revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Form<RevokeForm>, FormRejection>,
) -> Response {
    if !same_origin(&state, &headers) {
        return refused(&state, StatusCode::FORBIDDEN);
    }
    let Ok(Form(form)) = payload else {
        return refused(&state, StatusCode::BAD_REQUEST);
    };
    let Some(which) = selected(&form.login) else {
        return refused(&state, StatusCode::BAD_REQUEST);
    };
    match consumed(&state, &headers, &form.csrf).await {
        Ok(true) => {}
        Ok(false) => return refused(&state, StatusCode::FORBIDDEN),
        Err(error) => return not_completed(&state, error),
    }
    let session = match current_session(&state, &headers).await {
        Ok(Some(session)) => session,
        Ok(None) => return private_response(Redirect::to("/login").into_response()),
        Err(error) => return not_completed(&state, error),
    };
    let Some(runtime) = &state.oauth else {
        return refused(&state, StatusCode::NOT_FOUND);
    };
    let user = &session.user;
    let revoked = runtime
        .revoke_logins(
            &user.realm,
            &user.username,
            which,
            &state.browser,
            &state.metrics,
        )
        .await;
    if let Err(error) = revoked {
        tracing::warn!(
            event_name = "browser.account.revoke_failed",
            event_domain = "browser",
            ?error,
            "logins not revoked, or not all: the refresh-token store failed"
        );
        return not_completed(&state, BrowserVerifyError::Unavailable);
    }
    private_response(Redirect::to(REVOKED_LOCATION).into_response())
}

#[cfg(test)]
mod tests;

// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! OpenID Connect sign-in: `GET /login/method/{id}` redirects to the provider with a
//! single-use state bound to this browser. Pages are generic; provider error text,
//! codes and tokens are never shown or logged.

use super::browser_login::{
    FORM_COOKIE, cookie_value, private_page, private_response, set_cookie, unavailable,
};
use crate::{
    browser::{BrowserMethod, opaque_id, valid_id},
    oidc::{
        flow::{self, FlowSecrets},
        method::OidcMethod,
    },
    state::AppState,
};
use axum::{
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
};
use maud::html;

type Notice = (&'static str, &'static str);
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

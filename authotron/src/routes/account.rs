// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! The account page of a browser session.

use super::browser_login::{current_session, private_page, private_response, unavailable};
use crate::{browser::DISPLAY_ATTRIBUTES, state::AppState};
use axum::{
    Router,
    extract::State,
    http::HeaderMap,
    response::{Html, IntoResponse, Redirect, Response},
    routing::get,
};
use maud::html;

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route("/login/account", get(page))
        .route("/login/account/", get(page_slash))
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

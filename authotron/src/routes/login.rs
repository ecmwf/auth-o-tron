// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! Shared escaped branding for browser sign-in pages.

use axum::{
    Router,
    extract::State,
    http::header,
    response::{Html, IntoResponse, Redirect, Response},
    routing::get,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use maud::{DOCTYPE, Markup, html};
use std::sync::LazyLock;

use super::homepage::FAVICON_PATH;
use crate::config::UiConfig;
use crate::state::AppState;

const STYLESHEET: &str = include_str!("../static/login.css");
const DIALOG_POLICY: &str = "default-src 'none'; style-src 'self'; img-src 'self'; script-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";
// Curated Aviso branding fixture from https://aviso-playground.ecmwf.int/static/logo.png.
// The official 650x650 RGBA artwork is resized to a 192x192, 16-colour PNG.
// Only the bundled asset is served; requests never fetch the upstream image.
static AVISO_LOGO: LazyLock<Vec<u8>> = LazyLock::new(|| {
    let encoded: String = include_str!("../static/aviso-logo.base64")
        .split_ascii_whitespace()
        .collect();
    STANDARD.decode(encoded).expect("bundled Aviso logo base64")
});
const CONTENT_SECURITY_POLICY: &str = "default-src 'none'; style-src 'self'; img-src 'self' https:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

pub fn routes(config: &UiConfig) -> Router<AppState> {
    if !config.enabled {
        return Router::new();
    }

    Router::new()
        .route("/login", get(login))
        .route("/static/login.css", get(stylesheet))
        .route("/static/aviso-logo.png", get(aviso_logo))
}

async fn login(State(state): State<AppState>, headers: axum::http::HeaderMap) -> Response {
    let session = if state.config.ui.has_direct_login() {
        match super::browser_login::current_session(&state, &headers).await {
            Ok(session) => session,
            Err(error) => return super::browser_login::unavailable(error),
        }
    } else {
        None
    };
    if state.config.ui.has_direct_login()
        && !(state.config.ui.basic.is_some() && state.config.ui.ecmwf_api_key.is_some())
        && state.config.ui.sign_in_actions.is_empty()
        && session.is_some()
    {
        return secure_response(Redirect::to("/login/account").into_response(), true);
    }
    let config = if state.config.ui.has_direct_login() {
        super::browser_login::private_ui(&state)
    } else {
        state.config.ui.clone()
    };
    let mut response = secure_response(Html(render_login(&config)).into_response(), false);
    if state.config.ui.has_direct_login() {
        response.headers_mut().insert(
            header::CONTENT_SECURITY_POLICY,
            DIALOG_POLICY.parse().expect("static dialog policy"),
        );
        response.headers_mut().insert(
            header::REFERRER_POLICY,
            "strict-origin".parse().expect("static referrer policy"),
        );
    }
    response
}

pub(super) fn secure_response(mut response: Response, form: bool) -> Response {
    for (name, value) in [
        (header::CACHE_CONTROL, "no-store"),
        (
            header::CONTENT_SECURITY_POLICY,
            if form {
                "default-src 'none'; style-src 'self'; img-src 'self' https:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
            } else {
                CONTENT_SECURITY_POLICY
            },
        ),
        (header::REFERRER_POLICY, "no-referrer"),
        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (header::X_FRAME_OPTIONS, "DENY"),
    ] {
        response
            .headers_mut()
            .insert(name, value.parse().expect("static security header"));
    }
    response
}

async fn stylesheet() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/css; charset=utf-8"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        STYLESHEET,
    )
}

async fn aviso_logo() -> Response {
    let mut response = secure_response(AVISO_LOGO.as_slice().into_response(), false);
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        "image/png".parse().expect("static PNG type"),
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        "public, max-age=86400"
            .parse()
            .expect("static cache policy"),
    );
    response
}

fn render_login(config: &UiConfig) -> String {
    let available = !config.sign_in_actions.is_empty() || config.has_direct_login();
    render_page_with_dialog(
        config,
        html! {
            div class="login-card-heading" {
                svg class="login-icon" xmlns="http://www.w3.org/2000/svg"
                    viewBox="0 0 24 24" fill="none" stroke="currentColor"
                    stroke-width="1.5" aria-hidden="true" {
                    rect x="5" y="10" width="14" height="11" rx="2" {}
                    path d="M8 10V7a4 4 0 0 1 8 0v3" {}
                }
                span class="login-status-badge" {
                    @if available { "Browser sign-in" } @else { "UI preview" }
                }
            }
            h2 id="login-card-title" { "Sign in" }
            @if !available {
                p id="login-status" class="login-card-message" {
                    "Interactive sign-in is not available on this page."
                }
                p class="login-card-detail" {
                    "No credentials are collected. Continue using your application's existing authentication flow."
                }
                button class="login-placeholder" type="button" disabled
                    aria-describedby="login-status" { "Sign-in unavailable" }
            } @else {
                p class="login-card-message" { "Choose how to sign in." }
                p class="login-card-detail" {
                "Use direct identity verification or a configured browser sign-in flow."
                }
                div class="login-actions" {
                    @if config.basic.is_some() {
                        a class="login-action" href="/login/basic" { "Username and password" }
                    }
                    @if config.ecmwf_api_key.is_some() {
                        a class="login-action" href="/login/ecmwf-api-key" { "ECMWF API key" }
                    }
                    @for action in &config.sign_in_actions {
                        a class="login-action" href=(action.start_url.as_str()) { (&action.label) }
                    }
                }
            }
        },
        false,
    )
}

pub(super) fn render_page(config: &UiConfig, content: Markup) -> String {
    render_page_with_dialog(config, content, false)
}

fn render_page_with_dialog(config: &UiConfig, content: Markup, dialog: bool) -> String {
    let branding = &config.branding;
    let title = branding
        .title
        .as_deref()
        .filter(|title| !title.trim().is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| format!("Sign in to {}", branding.application_name));

    // Configuration is inserted through Maud's escaped expressions, never raw markup.
    html! {
        (DOCTYPE)
        html lang="en" {
            head {
                meta charset="UTF-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { (&title) }
                link rel="icon" type="image/x-icon" href=(FAVICON_PATH);
                link rel="stylesheet" href="/static/login.css";
                @if dialog {
                    script src="/static/login.js" defer {}
                }
            }
            body class="login-page" {
                main class="login-layout" aria-labelledby="login-title" {
                    header class="application-brand" {
                        @if let Some(logo) = &branding.logo_url {
                            img class="application-logo" src=(logo.as_str())
                                alt=(format!("{} logo", branding.application_name));
                        } @else {
                            p class="application-wordmark" { (&branding.application_name) }
                        }
                        h1 id="login-title" class="application-title" { (&title) }
                        @if let Some(description) = branding.description.as_deref()
                            .filter(|description| !description.trim().is_empty()) {
                            p class="application-description" { (description) }
                        }
                    }
                    section class="login-card" aria-labelledby="login-card-title" {
                        (content)
                    }
                }
                @if dialog {
                    dialog id="login-dialog" class="login-dialog" aria-labelledby="login-dialog-title" hidden {
                        div class="login-dialog-toolbar" {
                            div class="login-dialog-brand" {
                                @if let Some(logo) = &branding.logo_url {
                                    img class="login-dialog-logo" src=(logo.as_str())
                                        alt="" aria-hidden="true";
                                }
                                span { (&branding.application_name) }
                            }
                            button type="button" class="login-dialog-close" aria-label="Close sign-in dialog" { "Close" }
                        }
                        div id="login-dialog-content" {
                            h2 id="login-dialog-title" { "Sign in" }
                        }
                        p id="login-dialog-status" class="login-card-message" role="status" aria-live="polite" aria-atomic="true" {}
                    }
                }
                footer class="login-footer" {
                    a class="product-link" href="https://github.com/ecmwf/auth-o-tron"
                        rel="noopener noreferrer" {
                        img class="product-mark" src=(FAVICON_PATH) alt="" aria-hidden="true";
                        span {
                            "Powered by "
                            span class="product-name" { "Auth-O-Tron" }
                        }
                    }
                }
            }
        }
    }
    .into_string()
}

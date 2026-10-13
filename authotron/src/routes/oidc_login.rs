// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! OpenID Connect sign-in: `GET /login/method/{id}` redirects to the provider with a
//! single-use state bound to this browser (and to its pending authorization request,
//! if any), and `GET /login/method/{id}/callback` verifies the provider's answer. The
//! verified identity then either starts a browser session or continues the pending
//! authorization to consent. Pages are generic; provider error text, codes and tokens
//! are never shown or logged.

use super::browser_login::{
    FORM_COOKIE, SESSION_COOKIE, cookie_value, error_outcome, finish_authorization_login,
    not_found_page, pending_failure, private_page, private_response, resolve_method, set_cookie,
    unavailable,
};
use crate::{
    browser::{BrowserMethod, opaque_id, valid_id},
    metrics::{BrowserAttemptGuard, BrowserOutcome},
    models::user::User,
    oauth::{
        authentication::{VerifiedOAuthIdentity, oidc_identity},
        store::TransactionId,
        upstream::RevocationAudit,
    },
    oidc::{
        OidcError,
        flow::{self, CallbackResult, FlowSecrets},
        method::{OidcMethod, SignIn},
        upstream::{UpstreamBinding, UpstreamGrant},
    },
    state::AppState,
};
use axum::{
    extract::{OriginalUri, Path, RawQuery, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
};
use maud::html;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use zeroize::Zeroizing;

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

/// Binds a sign-in state to the pending authorization identified by the transaction and
/// browser cookies, so its callback can only complete that authorization.
fn authorization_binding(id: &TransactionId, browser: &[u8; 32]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"authotron-oidc-authorization\0");
    digest.update(id.as_secret_str().as_bytes());
    digest.update(browser);
    digest.finalize().into()
}

/// Redirects to the provider's authorization endpoint. The state record is created only
/// once provider metadata is available, so an unreachable provider spends no capacity.
pub(super) async fn start(
    state: &AppState,
    headers: &HeaderMap,
    method: &BrowserMethod,
    oidc: &OidcMethod,
) -> Response {
    // The caller has already recovered ended or advanced flows; remaining transaction
    // cookies name a pending authorization, confirmed here.
    let authorization = match super::oauth::parse_browser_binding(headers) {
        Ok(None) => None,
        Ok(Some((id, browser))) => {
            let Some(runtime) = &state.oauth else {
                return super::oauth::local(StatusCode::FORBIDDEN);
            };
            let bound = match runtime.bound(&id, &browser).await {
                Ok(bound) => bound,
                Err(error) => return pending_failure(error).0,
            };
            let client_id = bound.transaction().request().client_id();
            Some((
                authorization_binding(&id, &browser),
                runtime.offline_access(client_id, oidc),
            ))
        }
        Err(status) => return super::oauth::local(status),
    };
    let offline = authorization.is_some_and(|(_, offline)| offline);
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
    let binding = flow::binding(
        &form_nonce,
        authorization.as_ref().map(|(binding, _)| binding),
    );
    let sign_in_state = match state.browser.form_with_nonce(&method.flow, &binding).await {
        Ok(token) => token,
        Err(error) => return unavailable(error),
    };
    let secrets = FlowSecrets::derive(&form_nonce, &sign_in_state);
    let location = oidc.authorization_url(&metadata, &sign_in_state, &secrets, offline);
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
    /// Augmentation or identity bounds did not accept the identity.
    Augmentation,
    /// Offline access was requested, but no refresh token arrived or it could not be sealed.
    OfflineAccess,
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
    oidc: &Arc<OidcMethod>,
    query: Option<&str>,
    attempt: &mut BrowserAttemptGuard,
) -> Response {
    let Some(callback) = query.and_then(|query| flow::parse_callback(query.as_bytes())) else {
        attempt.outcome = BrowserOutcome::Malformed;
        return notice(state, StatusCode::BAD_REQUEST, EXPIRED);
    };
    let (Some(form_nonce), Ok(authorization)) = (
        cookie_value(headers, FORM_COOKIE).filter(|value| valid_id(value)),
        super::oauth::parse_browser_binding(headers),
    ) else {
        attempt.outcome = BrowserOutcome::Csrf;
        return notice(state, StatusCode::BAD_REQUEST, EXPIRED);
    };
    // The state was bound to the same cookies at the start: a sign-in begun for a
    // browser session cannot complete an authorization request, and vice versa.
    let binding = flow::binding(
        &form_nonce,
        authorization
            .as_ref()
            .map(|(id, browser)| authorization_binding(id, browser))
            .as_ref(),
    );
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
    if let Some((id, browser)) = authorization {
        return authorize(
            state,
            method,
            oidc,
            (&id, &browser),
            (callback.iss.as_deref(), &code, &secrets),
            attempt,
        )
        .await;
    }
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

/// Continues a pending authorization: the transaction is confirmed before the code is
/// exchanged, and the identity is strictly augmented, as for credential sign-in. With
/// offline access the provider's refresh token is sealed into the identity; it is revoked
/// at the provider if the authorization does not reach consent.
async fn authorize(
    state: &AppState,
    method: &BrowserMethod,
    oidc: &Arc<OidcMethod>,
    (id, browser): (&TransactionId, &[u8; 32]),
    (iss, code, secrets): (Option<&str>, &str, &FlowSecrets),
    attempt: &mut BrowserAttemptGuard,
) -> Response {
    let Some(runtime) = &state.oauth else {
        attempt.outcome = BrowserOutcome::Csrf;
        return super::oauth::local(StatusCode::FORBIDDEN);
    };
    let witness = match runtime.bound(id, browser).await {
        Ok(witness) => witness,
        Err(error) => {
            let (response, outcome) = pending_failure(error);
            attempt.outcome = outcome;
            return response;
        }
    };
    let client_id = witness.transaction().request().client_id().to_owned();
    let offline = runtime.offline_access(&client_id, oidc);
    let verified = state
        .browser
        .admitted_with_metrics(
            async {
                let SignIn {
                    user,
                    subject,
                    refresh_token,
                    ..
                } = match oidc.complete(iss, code, secrets).await {
                    Ok(signed_in) => signed_in,
                    Err(error) => return Ok((None, Err(SignInError::Provider(error)))),
                };
                // Without offline access a refresh token is dropped unused.
                let Some(token) = refresh_token.filter(|_| offline) else {
                    if offline {
                        tracing::error!(
                            event_name = "browser.oidc.offline_token_missing",
                            event_domain = "browser",
                            method = %method.flow.method,
                            "the provider issued no refresh token although offline_access was requested"
                        );
                        return Ok((None, Err(SignInError::OfflineAccess)));
                    }
                    return Ok((None, oidc_verified(state, method, user, None).await));
                };
                let binding = UpstreamBinding {
                    method: &method.flow.method,
                    issuer: &oidc.config().issuer,
                    client_id: &client_id,
                    realm: &user.realm,
                    username: &user.username,
                };
                let grant = UpstreamGrant::new(&subject, token.clone());
                let audit = RevocationAudit::sign_in(
                    &client_id,
                    &method.flow.method,
                    &user.realm,
                    &user.username,
                );
                let unheld = Some((token, audit));
                let Some(sealed) = runtime.seal_upstream(&binding, &grant) else {
                    return Ok((unheld, Err(SignInError::OfflineAccess)));
                };
                let identity = oidc_verified(state, method, user, Some(sealed)).await;
                Ok((unheld, identity))
            },
            Some(&state.metrics),
        )
        .await;
    let (token, identity) = match verified {
        Ok(verified) => verified,
        Err(error) => {
            attempt.outcome = error_outcome(&error);
            return unavailable(error);
        }
    };
    let unheld = |token: Option<(Zeroizing<String>, RevocationAudit)>| {
        if let Some((token, audit)) = token {
            runtime.revoke_upstream_token(oidc, token, audit, &state.metrics);
        }
    };
    let identity = match identity {
        Ok(identity) => identity,
        Err(error) => {
            unheld(token);
            return sign_in_failure(state, method, error, attempt);
        }
    };
    let (response, outcome) =
        finish_authorization_login(runtime, id, browser, witness, identity).await;
    if !matches!(outcome, BrowserOutcome::Success) {
        unheld(token);
    }
    attempt.outcome = outcome;
    response
}

/// Strict augmentation of a provider identity carrying an optional sealed upstream grant.
async fn oidc_verified(
    state: &AppState,
    method: &BrowserMethod,
    user: User,
    upstream: Option<String>,
) -> Result<VerifiedOAuthIdentity, SignInError> {
    oidc_identity(
        &method.flow.method,
        user,
        upstream,
        &state.auth,
        &state.metrics,
    )
    .await
    .map_err(|_| SignInError::Augmentation)
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
        .map_err(SignInError::Provider)?
        .user;
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
        SignInError::OfflineAccess => (
            "offline_access",
            BrowserOutcome::IdpUnavailable,
            StatusCode::SERVICE_UNAVAILABLE,
            NOT_COMPLETED,
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
mod authorization_tests;
#[cfg(all(test, unix))]
mod keycloak_tests;
#[cfg(test)]
mod offline_tests;
#[cfg(test)]
mod tests;

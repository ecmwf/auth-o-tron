// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! Opt-in public-client code/S256 endpoints and server-bound direct-login continuation.

use crate::{
    oauth::{
        authorization::{decode_component, validate_authorization_request},
        codes::{AuthorizationCode, CodeIssueOutcome, CodeStoreError},
        rate_limit::Endpoint,
        refresh_grant::{RefreshGrantError, RefreshRequest},
        runtime::{ActiveFlow, OAuthRuntime},
        store::{StoreError, TransactionId},
    },
    state::AppState,
};
use axum::{
    Extension, Json, Router,
    body::Bytes,
    extract::{ConnectInfo, DefaultBodyLimit, RawQuery, State, rejection::BytesRejection},
    http::{HeaderMap, StatusCode, header},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use cookie::{Cookie, SameSite, time::Duration};
use maud::html;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{collections::HashMap, net::SocketAddr, sync::Arc};

const TX: &str = "__Host-authotron_oauth";
const BROWSER: &str = "__Host-authotron_oauth_browser";
pub(super) fn routes(enabled: bool) -> Router<AppState> {
    if !enabled {
        return Router::new();
    }
    Router::new()
        .route("/.well-known/oauth-authorization-server", get(metadata))
        .route("/oauth/jwks", get(jwks))
        .route("/oauth/authorize", get(authorize))
        .route("/oauth/continue", get(continue_consent))
        .route("/oauth/consent", post(consent))
        .route("/oauth/token", post(token))
        .route("/oauth/revoke", post(revoke))
        .layer(DefaultBodyLimit::max(8192))
}
fn secure_oauth_response(response: Response) -> Response {
    let mut response = super::login::secure_response(response, true);
    response.headers_mut().insert(header::CONTENT_SECURITY_POLICY, "default-src 'none'; style-src 'self'; img-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'".parse().unwrap());
    response
        .headers_mut()
        .insert(header::REFERRER_POLICY, "strict-origin".parse().unwrap());
    response
        .headers_mut()
        .insert(header::PRAGMA, "no-cache".parse().unwrap());
    response
}
pub(super) fn local(status: StatusCode) -> Response {
    secure_oauth_response((status, "Authorization request could not be completed").into_response())
}
fn store_status(error: StoreError) -> StatusCode {
    match error {
        StoreError::Missing => StatusCode::BAD_REQUEST,
        StoreError::Limited => StatusCode::TOO_MANY_REQUESTS,
        StoreError::AccessDenied => StatusCode::FORBIDDEN,
        _ => StatusCode::SERVICE_UNAVAILABLE,
    }
}
fn cookie(response: &mut Response, name: &'static str, value: &str, ttl: u64) {
    let cookie = Cookie::build((name, value.to_owned()))
        .path("/")
        .secure(true)
        .http_only(true)
        .same_site(SameSite::Lax)
        .max_age(Duration::seconds(ttl as i64))
        .build();
    response
        .headers_mut()
        .append(header::SET_COOKIE, cookie.to_string().parse().unwrap());
}
/// Valid: one canonical transaction and browser cookie. Invalid: duplicate or partial pairs.
pub(super) fn parse_browser_binding(
    headers: &HeaderMap,
) -> Result<Option<(TransactionId, [u8; 32])>, StatusCode> {
    let mut tx = None;
    let mut browser = None;
    for header in headers.get_all(header::COOKIE) {
        for item in Cookie::split_parse(header.to_str().map_err(|_| StatusCode::FORBIDDEN)?) {
            let item = item.map_err(|_| StatusCode::FORBIDDEN)?;
            let target = match item.name() {
                TX => &mut tx,
                BROWSER => &mut browser,
                _ => continue,
            };
            if item.value().len() != 43 {
                return Err(StatusCode::FORBIDDEN);
            }
            if target.replace(item.value().to_owned()).is_some() {
                return Err(StatusCode::FORBIDDEN);
            }
        }
    }
    match (tx, browser) {
        (None, None) => Ok(None),
        (Some(tx), Some(browser)) => {
            let tx = TransactionId::parse(&tx).map_err(|_| StatusCode::FORBIDDEN)?;
            let browser = TransactionId::parse(&browser).map_err(|_| StatusCode::FORBIDDEN)?;
            Ok(Some((
                tx,
                Sha256::digest(browser.as_secret_str().as_bytes()).into(),
            )))
        }
        _ => Err(StatusCode::FORBIDDEN),
    }
}
pub(super) async fn form_transaction(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<Option<String>, StatusCode> {
    let Some((id, hash)) = parse_browser_binding(headers)? else {
        return Ok(None);
    };
    let runtime = state.oauth.as_ref().ok_or(StatusCode::FORBIDDEN)?;
    runtime.bound(&id, &hash).await.map_err(store_status)?;
    Ok(Some(id.as_secret_str().into()))
}
/// GET-only recovery. Credential POSTs continue to require the exact posted context.
/// A stale flow requires an explicit retry; it never silently becomes direct login.
pub(super) async fn login_entry_recovery(
    state: &AppState,
    headers: &HeaderMap,
) -> Option<Response> {
    let flow = match parse_browser_binding(headers) {
        Ok(None) => return None,
        Ok(Some((id, hash))) => active_flow(state, &id, &hash).await,
        Err(_) => Ok(ActiveFlow::Missing),
    };
    recovery_for_flow(state, flow)
}
/// Without an OAuth runtime any cookie pair is treated as an ended flow.
async fn active_flow(
    state: &AppState,
    id: &TransactionId,
    hash: &[u8; 32],
) -> Result<ActiveFlow, StoreError> {
    match &state.oauth {
        Some(runtime) => runtime.active_flow(id, hash).await,
        None => Ok(ActiveFlow::Missing),
    }
}
/// Pending flows need no recovery; post-login flows resume at consent; ended or
/// malformed flows clear the cookies. Backend errors keep the cookies.
fn recovery_for_flow(state: &AppState, flow: Result<ActiveFlow, StoreError>) -> Option<Response> {
    match flow {
        Ok(ActiveFlow::Pending(_)) => None,
        Ok(ActiveFlow::PastPending(_)) => Some(secure_oauth_response(
            Redirect::to("/oauth/continue").into_response(),
        )),
        Ok(ActiveFlow::Missing) => Some(session_ended(state)),
        // `/oauth/continue` performs the atomic removal and `access_denied` redirect.
        Err(StoreError::AccessDenied) => Some(secure_oauth_response(
            Redirect::to("/oauth/continue").into_response(),
        )),
        Err(error) => Some(local(store_status(error))),
    }
}
fn notice_page(
    state: &AppState,
    status: StatusCode,
    title: &str,
    body: &str,
    link_text: &str,
) -> Response {
    let page = super::login::render_page(
        &super::browser_login::private_ui(state),
        html! {
            h2 id="login-card-title" { (title) }
            p { (body) }
            a href="/login" { (link_text) }
        },
    );
    secure_oauth_response((status, Html(page)).into_response())
}
fn session_ended(state: &AppState) -> Response {
    let mut response = notice_page(
        state,
        StatusCode::OK,
        "Authorization session ended",
        "Restart authorization from your application, or continue to sign in directly.",
        "Continue to sign in",
    );
    cookie(&mut response, TX, "", 0);
    cookie(&mut response, BROWSER, "", 0);
    response
}
pub(super) fn posted_context(
    headers: &HeaderMap,
    submitted: Option<&str>,
) -> Result<Option<(TransactionId, [u8; 32])>, StatusCode> {
    let context = parse_browser_binding(headers)?;
    match (&context, submitted) {
        (None, None) => Ok(None),
        (Some((id, _)), Some(value)) if id.as_secret_str() == value => Ok(context),
        _ => Err(StatusCode::FORBIDDEN),
    }
}
fn origin(headers: &HeaderMap, runtime: &OAuthRuntime) -> bool {
    let mut values = headers.get_all(header::ORIGIN).iter();
    values.next().and_then(|value| value.to_str().ok()) == Some(runtime.origin.as_str())
        && values.next().is_none()
}
async fn metadata(State(state): State<AppState>) -> Response {
    let runtime = state.oauth.as_ref().unwrap();
    let issuer = runtime.config.issuer.as_deref().unwrap();
    let base = issuer.trim_end_matches('/');
    let scopes: std::collections::BTreeSet<&str> = runtime
        .config
        .resources
        .iter()
        .flat_map(|resource| resource.scopes.iter().map(|scope| scope.name.as_str()))
        .collect();
    let mut metadata = json!({"issuer": issuer, "scopes_supported": scopes, "authorization_endpoint": format!("{base}/oauth/authorize"), "token_endpoint": format!("{base}/oauth/token"), "jwks_uri": format!("{base}/oauth/jwks"), "response_types_supported": ["code"], "grant_types_supported": ["authorization_code"], "token_endpoint_auth_methods_supported": ["none"], "code_challenge_methods_supported": ["S256"], "authorization_response_iss_parameter_supported": true});
    if runtime.refresh_supported() {
        metadata["grant_types_supported"] = json!(["authorization_code", "refresh_token"]);
        metadata["revocation_endpoint"] = json!(format!("{base}/oauth/revoke"));
        metadata["revocation_endpoint_auth_methods_supported"] = json!(["none"]);
    }
    secure_oauth_response(Json(metadata).into_response())
}
async fn jwks(State(state): State<AppState>) -> Response {
    secure_oauth_response(Json(state.oauth.as_ref().unwrap().keys.jwks()).into_response())
}
async fn authorize(
    State(state): State<AppState>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Response {
    let runtime = state.oauth.as_ref().unwrap();
    let request = match validate_authorization_request(
        &runtime.config,
        query.as_deref().unwrap_or("").as_bytes(),
    ) {
        Ok(request) => request,
        Err(_) => return local(StatusCode::BAD_REQUEST),
    };
    // One active flow per browser cookie pair. Dropping cookies can bypass this
    // browser convenience guard, but cannot borrow another client's reserved share.
    let flow = match parse_browser_binding(&headers) {
        Ok(None) => None,
        Ok(Some((id, hash))) => Some(runtime.active_flow(&id, &hash).await),
        Err(_) => Some(Ok(ActiveFlow::Missing)),
    };
    if let Some(flow) = flow {
        if let Ok(active) = &flow
            && active.same_request(&request) == Some(false)
        {
            return notice_page(
                &state,
                StatusCode::CONFLICT,
                "Another authorization is in progress",
                "This request differs from the current authorization. Finish or deny the current authorization before restarting from your application.",
                "Continue current authorization",
            );
        }
        return recovery_for_flow(&state, flow)
            .unwrap_or_else(|| secure_oauth_response(Redirect::to("/login").into_response()));
    }
    let nonce = match OAuthRuntime::nonce() {
        Ok(nonce) => nonce,
        Err(_) => return local(StatusCode::SERVICE_UNAVAILABLE),
    };
    let hash = Sha256::digest(nonce.as_secret_str().as_bytes()).into();
    let created = match runtime.create(request, hash).await {
        Ok(created) => created,
        Err(error) => return local(store_status(error)),
    };
    let mut response = secure_oauth_response(Redirect::to("/login").into_response());
    let ttl = runtime.config.authorization_transaction_ttl_seconds;
    cookie(&mut response, TX, created.id.as_secret_str(), ttl);
    cookie(&mut response, BROWSER, nonce.as_secret_str(), ttl);
    response
}
async fn continue_consent(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let runtime = state.oauth.as_ref().unwrap();
    let (id, hash) = match parse_browser_binding(&headers) {
        Ok(Some(context)) => context,
        _ => return local(StatusCode::FORBIDDEN),
    };
    let csrf = match runtime.prepare(&id, &hash).await {
        Ok(csrf) => csrf,
        Err(error) => return store_failure(runtime, &id, &hash, error).await,
    };
    let context = match runtime.consent_context(&id, &hash).await {
        Ok(context) => context,
        Err(error) => return store_failure(runtime, &id, &hash, error).await,
    };
    let request = context.transaction().request();
    let client = runtime
        .config
        .clients
        .iter()
        .find(|client| client.client_id == request.client_id())
        .unwrap();
    let page = super::login::render_page(
        &super::browser_login::private_ui(&state),
        html! {
            h2 id="login-card-title" { "Authorize " (&client.display_name) }
            p { "Resource: " (request.resource()) }
            p { "Signed in as " (&context.as_user().username) }
            ul { @for scope in context.authorized_scopes() { li { (scope) } } }
            form class="key-form" method="post" action="/oauth/consent" {
                input type="hidden" name="csrf" value=(csrf.as_secret_str());
                input type="hidden" name="oauth_transaction" value=(id.as_secret_str());
                button class="login-action" type="submit" name="decision" value="approve" { "Approve" }
                button class="login-action" type="submit" name="decision" value="deny" { "Deny" }
            }
        },
    );
    let mut response = secure_oauth_response(Html(page).into_response());
    // Browsers enforce form-action on POST redirects too: allow only the registered
    // callback origin in addition to self, while the actual form action stays local.
    let callback_origin = url::Url::parse(request.redirect_uri())
        .unwrap()
        .origin()
        .ascii_serialization();
    response.headers_mut().insert(header::CONTENT_SECURITY_POLICY, format!("default-src 'none'; style-src 'self'; img-src 'self'; base-uri 'none'; form-action 'self' {callback_origin}; frame-ancestors 'none'").parse().unwrap());
    response
}
/// Valid: `code=a%2Bb`; invalid: duplicate known fields or malformed `%ZZ` escapes.
/// Every `required` field must be present; `optional` fields may be absent.
fn parse_urlencoded_form(
    headers: &HeaderMap,
    bytes: &[u8],
    required: &[&str],
    optional: &[&str],
    ignore_unknown: bool,
) -> Result<HashMap<String, String>, ()> {
    let mut types = headers.get_all(header::CONTENT_TYPE).iter();
    if types
        .next()
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        != Some("application/x-www-form-urlencoded")
        || types.next().is_some()
        || bytes.len() > 8192
        || bytes.split(|b| *b == b'&').count() > 32
    {
        return Err(());
    }
    let mut result = HashMap::new();
    for pair in bytes.split(|b| *b == b'&') {
        let split = pair.iter().position(|b| *b == b'=').ok_or(())?;
        let name = decode_component(&pair[..split]).map_err(|_| ())?;
        let value = decode_component(&pair[split + 1..]).map_err(|_| ())?;
        if !required.contains(&name.as_str()) && !optional.contains(&name.as_str()) {
            if ignore_unknown {
                continue;
            }
            return Err(());
        }
        if result.insert(name, value).is_some() {
            return Err(());
        }
    }
    if required.iter().any(|name| !result.contains_key(*name)) {
        return Err(());
    }
    Ok(result)
}
async fn consent(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let runtime = state.oauth.as_ref().unwrap();
    if !origin(&headers, runtime) {
        return local(StatusCode::FORBIDDEN);
    }
    let fields = match body.ok().and_then(|body| {
        parse_urlencoded_form(
            &headers,
            &body,
            &["csrf", "oauth_transaction", "decision"],
            &[],
            false,
        )
        .ok()
    }) {
        Some(fields) => fields,
        None => return local(StatusCode::BAD_REQUEST),
    };
    let (id, hash) = match posted_context(&headers, Some(&fields["oauth_transaction"])) {
        Ok(Some(context)) => context,
        _ => return local(StatusCode::FORBIDDEN),
    };
    let context = match runtime.consent_context(&id, &hash).await {
        Ok(context) => context,
        Err(error) => return store_failure(runtime, &id, &hash, error).await,
    };
    let outcome = match runtime
        .issue(&id, &hash, &fields["csrf"], &fields["decision"])
        .await
    {
        Ok(outcome) => outcome,
        Err(error) => {
            return local(match error {
                CodeStoreError::Limited => StatusCode::TOO_MANY_REQUESTS,
                CodeStoreError::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
                _ => StatusCode::BAD_REQUEST,
            });
        }
    };
    match &outcome {
        CodeIssueOutcome::Issued(code) => callback_response(
            runtime,
            code.redirect_uri(),
            code.state(),
            ("code", code.code().as_secret_str()),
        ),
        CodeIssueOutcome::Denied => {
            runtime.end_authorization_upstream(&context, &state.browser, &state.metrics);
            access_denied(runtime, context.transaction().request())
        }
    }
}
/// Builds the 303 to a callback already validated against the registered client,
/// appending one result parameter, the original `state`, and `iss` (RFC 9207), and
/// clearing the OAuth cookies. Example: `https://app.example.org/cb?error=access_denied&state=s&iss=...`.
fn callback_response(
    runtime: &OAuthRuntime,
    callback: &str,
    state_value: Option<&str>,
    (parameter, value): (&str, &str),
) -> Response {
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query.append_pair(parameter, value);
    if let Some(state_value) = state_value {
        query.append_pair("state", state_value);
    }
    query.append_pair("iss", runtime.config.issuer.as_deref().unwrap());
    let destination = format!(
        "{callback}{}{}",
        if callback.contains('?') { '&' } else { '?' },
        query.finish()
    );
    let mut response = secure_oauth_response(Redirect::to(&destination).into_response());
    cookie(&mut response, TX, "", 0);
    cookie(&mut response, BROWSER, "", 0);
    response
}
/// RFC 6749 §4.1.2.1 `access_denied` for a validated request whose stored transaction
/// has already been atomically consumed by the caller.
pub(super) fn access_denied(
    runtime: &OAuthRuntime,
    request: &crate::oauth::authorization::ValidatedAuthorizationRequest,
) -> Response {
    callback_response(
        runtime,
        request.redirect_uri(),
        request.state(),
        ("error", "access_denied"),
    )
}
/// Store failures stay local, except a confirmed policy denial: that record is removed
/// atomically and the client receives `access_denied`. Removal failures stay local.
async fn store_failure(
    runtime: &OAuthRuntime,
    id: &TransactionId,
    hash: &[u8; 32],
    error: StoreError,
) -> Response {
    if error != StoreError::AccessDenied {
        return local(store_status(error));
    }
    match runtime.reject_ineligible(id, hash).await {
        Ok(transaction) => access_denied(runtime, transaction.request()),
        Err(error) => local(store_status(error)),
    }
}
fn token_error(status: StatusCode, error: &'static str) -> Response {
    secure_oauth_response((status, Json(json!({"error": error}))).into_response())
}
type Peer = Option<Extension<ConnectInfo<SocketAddr>>>;
/// 429 with `Retry-After` and the RFC 6749 §4.1.2.1 `temporarily_unavailable` code,
/// the closest registered OAuth error for an overloaded endpoint.
fn rate_limited(
    runtime: &OAuthRuntime,
    endpoint: Endpoint,
    peer: Peer,
    headers: &HeaderMap,
) -> Option<Response> {
    let peer = peer.map(|Extension(ConnectInfo(addr))| addr.ip());
    let ip = runtime.rate_limit.client_ip(peer, headers);
    let retry_after = runtime.rate_limit.admit(endpoint, ip).err()?;
    tracing::debug!(
        event_name = "oauth.endpoint.rate_limited",
        endpoint = ?endpoint,
        retry_after_seconds = retry_after,
    );
    let mut response = token_error(StatusCode::TOO_MANY_REQUESTS, "temporarily_unavailable");
    response
        .headers_mut()
        .insert(header::RETRY_AFTER, retry_after.into());
    Some(response)
}
async fn token(
    State(state): State<AppState>,
    peer: Peer,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let runtime = state.oauth.as_ref().unwrap();
    if let Some(response) = rate_limited(runtime, Endpoint::Token, peer, &headers) {
        return response;
    }
    if headers.contains_key(header::AUTHORIZATION) {
        return token_error(StatusCode::BAD_REQUEST, "invalid_client");
    }
    let fields = match body.ok().and_then(|body| {
        parse_urlencoded_form(
            &headers,
            &body,
            &["grant_type", "client_id"],
            &[
                "code",
                "redirect_uri",
                "resource",
                "code_verifier",
                "refresh_token",
                "scope",
            ],
            true,
        )
        .ok()
    }) {
        Some(fields) => fields,
        None => return token_error(StatusCode::BAD_REQUEST, "invalid_request"),
    };
    let refresh = match fields["grant_type"].as_str() {
        "authorization_code" => false,
        "refresh_token" if runtime.refresh_supported() => true,
        _ => return token_error(StatusCode::BAD_REQUEST, "unsupported_grant_type"),
    };
    if !runtime
        .config
        .clients
        .iter()
        .any(|client| client.client_id == fields["client_id"])
    {
        return token_error(StatusCode::BAD_REQUEST, "invalid_client");
    }
    if refresh {
        return refresh_token(&state, runtime, &fields).await;
    }
    let (Some(code), Some(redirect_uri), Some(resource), Some(verifier)) = (
        fields.get("code"),
        fields.get("redirect_uri"),
        fields.get("resource"),
        fields.get("code_verifier"),
    ) else {
        return token_error(StatusCode::BAD_REQUEST, "invalid_request");
    };
    let code = match AuthorizationCode::parse(code) {
        Ok(code) => code,
        Err(_) => return token_error(StatusCode::BAD_REQUEST, "invalid_grant"),
    };
    let proof = match runtime
        .redeem(
            &code,
            &fields["client_id"],
            redirect_uri,
            resource,
            verifier,
        )
        .await
    {
        Ok(proof) => proof,
        Err(CodeStoreError::Unavailable) => {
            return token_error(StatusCode::SERVICE_UNAVAILABLE, "server_error");
        }
        Err(_) => return token_error(StatusCode::BAD_REQUEST, "invalid_grant"),
    };
    match runtime
        .exchange(proof, &state.browser, &state.metrics)
        .await
    {
        Ok(token) => secure_oauth_response(Json(token).into_response()),
        Err(_) => token_error(StatusCode::SERVICE_UNAVAILABLE, "server_error"),
    }
}
async fn refresh_token(
    state: &AppState,
    runtime: &Arc<OAuthRuntime>,
    fields: &HashMap<String, String>,
) -> Response {
    let Some(token) = fields.get("refresh_token") else {
        return token_error(StatusCode::BAD_REQUEST, "invalid_request");
    };
    let request = RefreshRequest {
        token,
        client_id: &fields["client_id"],
        scope: fields.get("scope").map(String::as_str),
        resource: fields.get("resource").map(String::as_str),
    };
    match runtime
        .refresh(request, &state.auth, &state.browser, &state.metrics)
        .await
    {
        Ok(token) => secure_oauth_response(Json(token).into_response()),
        Err(RefreshGrantError::InvalidGrant) => {
            token_error(StatusCode::BAD_REQUEST, "invalid_grant")
        }
        Err(RefreshGrantError::InvalidScope) => {
            token_error(StatusCode::BAD_REQUEST, "invalid_scope")
        }
        Err(RefreshGrantError::InvalidTarget) => {
            token_error(StatusCode::BAD_REQUEST, "invalid_target")
        }
        Err(RefreshGrantError::Unavailable) => {
            token_error(StatusCode::SERVICE_UNAVAILABLE, "server_error")
        }
    }
}
/// RFC 7009 revocation for public clients: `client_id` identifies the caller and
/// unknown, malformed or foreign tokens still yield 200.
async fn revoke(
    State(state): State<AppState>,
    peer: Peer,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let runtime = state.oauth.as_ref().unwrap();
    if let Some(response) = rate_limited(runtime, Endpoint::Revoke, peer, &headers) {
        return response;
    }
    if headers.contains_key(header::AUTHORIZATION) {
        return token_error(StatusCode::BAD_REQUEST, "invalid_client");
    }
    let fields = match body.ok().and_then(|body| {
        parse_urlencoded_form(
            &headers,
            &body,
            &["token", "client_id"],
            &["token_type_hint"],
            true,
        )
        .ok()
    }) {
        Some(fields) => fields,
        None => return token_error(StatusCode::BAD_REQUEST, "invalid_request"),
    };
    if !runtime
        .config
        .clients
        .iter()
        .any(|client| client.client_id == fields["client_id"])
    {
        return token_error(StatusCode::BAD_REQUEST, "invalid_client");
    }
    match runtime
        .revoke(
            &fields["token"],
            &fields["client_id"],
            &state.browser,
            &state.metrics,
        )
        .await
    {
        Ok(()) => secure_oauth_response(StatusCode::OK.into_response()),
        Err(_) => token_error(StatusCode::SERVICE_UNAVAILABLE, "server_error"),
    }
}

// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! Token-endpoint requests with the configured client authentication: the
//! authorization-code exchange with the PKCE verifier (RFC 6749 §4.1.3), refreshing an
//! upstream grant (§6) and revoking it (RFC 7009). Access tokens in responses are
//! dropped unread.

use super::{
    OidcError,
    http::{IdpHttp, IdpResponse, basic_authorization},
    id_token::MAX_ID_TOKEN_BYTES,
};
use serde::Deserialize;
use url::Url;
use zeroize::Zeroizing;

pub const TOKEN_RESPONSE_BYTES: usize = 64 * 1024;
pub const MAX_REFRESH_TOKEN_BYTES: usize = 8 * 1024;

/// Client authentication at the token endpoint. Deliberately not Debug.
pub enum ClientCredentials<'a> {
    /// `client_secret_basic`: form-urlencoded id and secret in an `Authorization` header.
    Basic { client_id: &'a str, secret: &'a str },
    /// `client_secret_post`: id and secret as form fields.
    Post { client_id: &'a str, secret: &'a str },
    /// Public client: `client_id` only; PKCE protects the code.
    Public { client_id: &'a str },
}

/// Tokens kept from a token response; both are wiped when dropped. Deliberately not Debug.
pub struct Tokens {
    pub id_token: Option<Zeroizing<String>>,
    pub refresh_token: Option<Zeroizing<String>>,
}

/// Adds the client authentication to `form`, returning an `Authorization` value for
/// `client_secret_basic`.
fn authenticate<'a>(
    credentials: &ClientCredentials<'a>,
    form: &mut Vec<(&'static str, &'a str)>,
) -> Option<Zeroizing<String>> {
    match credentials {
        ClientCredentials::Basic { client_id, secret } => {
            Some(basic_authorization(client_id, secret))
        }
        ClientCredentials::Post { client_id, secret } => {
            form.extend([("client_id", *client_id), ("client_secret", *secret)]);
            None
        }
        ClientCredentials::Public { client_id } => {
            form.push(("client_id", client_id));
            None
        }
    }
}

async fn post(
    http: &IdpHttp,
    endpoint: &Url,
    credentials: &ClientCredentials<'_>,
    mut form: Vec<(&'static str, &str)>,
) -> Result<IdpResponse, OidcError> {
    let authorization = authenticate(credentials, &mut form);
    http.post_form(
        endpoint,
        &form,
        authorization.as_deref().map(String::as_str),
        TOKEN_RESPONSE_BYTES,
    )
    .await
}

/// Exchanges `code`; the returned ID token is always present.
pub async fn exchange_code(
    http: &IdpHttp,
    endpoint: &Url,
    credentials: &ClientCredentials<'_>,
    code: &str,
    redirect_uri: &str,
    verifier: &str,
) -> Result<Tokens, OidcError> {
    let form = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("code_verifier", verifier),
    ];
    let tokens = tokens(post(http, endpoint, credentials, form).await?)?;
    if tokens.id_token.is_none() {
        return Err(OidcError::InvalidResponse);
    }
    Ok(tokens)
}

/// Refreshes an upstream grant. A rotated refresh token and a new ID token are returned
/// when the provider sends them.
pub async fn refresh(
    http: &IdpHttp,
    endpoint: &Url,
    credentials: &ClientCredentials<'_>,
    refresh_token: &str,
) -> Result<Tokens, OidcError> {
    let form = vec![
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
    ];
    tokens(post(http, endpoint, credentials, form).await?)
}

/// RFC 7009 revocation of a refresh token: 200 succeeds, 5xx is unavailability and
/// other answers mean the provider refused the request.
pub async fn revoke(
    http: &IdpHttp,
    endpoint: &Url,
    credentials: &ClientCredentials<'_>,
    token: &str,
) -> Result<(), OidcError> {
    let form = vec![("token", token), ("token_type_hint", "refresh_token")];
    match post(http, endpoint, credentials, form).await?.status {
        200 => Ok(()),
        status if status >= 500 => Err(OidcError::Unavailable),
        400 | 401 => Err(OidcError::ClientRejected),
        _ => Err(OidcError::InvalidResponse),
    }
}

/// Fields read from a token response.
#[derive(Deserialize)]
struct Body {
    id_token: Option<String>,
    refresh_token: Option<String>,
}

#[derive(Deserialize)]
struct ErrorBody {
    error: String,
}

/// Token text as issued: non-empty, within `limit` bytes, without whitespace or controls.
/// Valid: `eyJhbGciOi.payload.signature`. Invalid: an empty string or `a b`.
fn token_text(value: Option<String>, limit: usize) -> Result<Option<Zeroizing<String>>, OidcError> {
    let Some(value) = value.map(Zeroizing::new) else {
        return Ok(None);
    };
    if value.is_empty()
        || value.len() > limit
        || value.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(OidcError::InvalidResponse);
    }
    Ok(Some(value))
}

/// 200 yields the tokens; `invalid_grant` means the code or grant was rejected; any other
/// 400/401 means the provider refused this client or request, which is a configuration
/// problem; 5xx is unavailability.
fn tokens(response: IdpResponse) -> Result<Tokens, OidcError> {
    // The body holds every issued token; it is wiped when dropped.
    let body = Zeroizing::new(response.body);
    match response.status {
        200 => {
            let parsed: Body =
                serde_json::from_slice(&body).map_err(|_| OidcError::InvalidResponse)?;
            Ok(Tokens {
                id_token: token_text(parsed.id_token, MAX_ID_TOKEN_BYTES)?,
                refresh_token: token_text(parsed.refresh_token, MAX_REFRESH_TOKEN_BYTES)?,
            })
        }
        400 | 401 => match serde_json::from_slice::<ErrorBody>(&body) {
            Ok(body) if body.error == "invalid_grant" => Err(OidcError::Rejected),
            _ => Err(OidcError::ClientRejected),
        },
        status if status >= 500 => Err(OidcError::Unavailable),
        _ => Err(OidcError::InvalidResponse),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oidc::mock::serve;
    use axum::{
        Json, Router,
        extract::State,
        http::{HeaderMap, StatusCode, header},
        routing::post,
    };
    use serde_json::{Value, json};
    use std::{
        sync::{Arc, Mutex},
        time::Duration,
    };

    #[derive(Clone, Default)]
    struct Endpoint {
        answer: Arc<Mutex<(u16, Value)>>,
        seen: Arc<Mutex<Vec<(String, String)>>>,
    }

    async fn endpoint() -> (Url, Endpoint) {
        async fn token(
            State(endpoint): State<Endpoint>,
            headers: HeaderMap,
            body: String,
        ) -> (StatusCode, Json<Value>) {
            let authorization = headers
                .get(header::AUTHORIZATION)
                .map(|value| value.to_str().unwrap().to_owned())
                .unwrap_or_default();
            endpoint.seen.lock().unwrap().push((authorization, body));
            let (status, body) = endpoint.answer.lock().unwrap().clone();
            (StatusCode::from_u16(status).unwrap(), Json(body))
        }
        let endpoint = Endpoint::default();
        *endpoint.answer.lock().unwrap() = (
            200,
            json!({"access_token": "at", "refresh_token": "rt", "id_token": "header.claims.sig", "token_type": "Bearer"}),
        );
        let base = serve(
            Router::new()
                .route("/token", post(token))
                .with_state(endpoint.clone()),
        )
        .await;
        (Url::parse(&format!("{base}/token")).unwrap(), endpoint)
    }

    async fn exchange(url: &Url, credentials: &ClientCredentials<'_>) -> Result<Tokens, OidcError> {
        let http = IdpHttp::new(Duration::from_secs(2)).unwrap();
        exchange_code(
            &http,
            url,
            credentials,
            "code+1",
            "https://login.example.org/login/method/sso/callback",
            "verifier",
        )
        .await
    }

    #[tokio::test]
    async fn each_client_authentication_sends_the_code_verifier_and_redirect_uri() {
        let (url, endpoint) = endpoint().await;
        let common = "grant_type=authorization_code&code=code%2B1&redirect_uri=https%3A%2F%2Flogin.example.org%2Flogin%2Fmethod%2Fsso%2Fcallback&code_verifier=verifier";
        for (credentials, authorization, extra) in [
            (
                ClientCredentials::Basic {
                    client_id: "authotron",
                    secret: "s3cret:x",
                },
                "Basic YXV0aG90cm9uOnMzY3JldCUzQXg=",
                "",
            ),
            (
                ClientCredentials::Post {
                    client_id: "authotron",
                    secret: "s3cret:x",
                },
                "",
                "&client_id=authotron&client_secret=s3cret%3Ax",
            ),
            (
                ClientCredentials::Public {
                    client_id: "authotron",
                },
                "",
                "&client_id=authotron",
            ),
        ] {
            let tokens = exchange(&url, &credentials).await.unwrap();
            assert_eq!(tokens.id_token.unwrap().as_str(), "header.claims.sig");
            assert_eq!(tokens.refresh_token.unwrap().as_str(), "rt");
            let (seen_authorization, body) = endpoint.seen.lock().unwrap().pop().unwrap();
            assert_eq!(seen_authorization, authorization);
            assert_eq!(body, format!("{common}{extra}"));
        }
    }

    #[tokio::test]
    async fn token_endpoint_answers_are_classified() {
        let (url, endpoint) = endpoint().await;
        let credentials = ClientCredentials::Public {
            client_id: "authotron",
        };
        for (status, body, expected) in [
            (
                200,
                json!({"access_token": "at"}),
                OidcError::InvalidResponse,
            ),
            (200, json!({"id_token": 7}), OidcError::InvalidResponse),
            (200, json!({"id_token": ""}), OidcError::InvalidResponse),
            (
                200,
                json!({"id_token": "t", "refresh_token": "a b"}),
                OidcError::InvalidResponse,
            ),
            (
                200,
                json!({"id_token": "x".repeat(MAX_ID_TOKEN_BYTES + 1)}),
                OidcError::InvalidResponse,
            ),
            (
                400,
                json!({"error": "invalid_grant", "error_description": "Code not valid"}),
                OidcError::Rejected,
            ),
            (
                400,
                json!({"error": "invalid_request"}),
                OidcError::ClientRejected,
            ),
            (
                401,
                json!({"error": "invalid_client"}),
                OidcError::ClientRejected,
            ),
            (400, json!("not an error object"), OidcError::ClientRejected),
            (403, json!({}), OidcError::InvalidResponse),
            (302, json!({}), OidcError::InvalidResponse),
            (500, json!({}), OidcError::Unavailable),
            (
                503,
                json!({"error": "temporarily_unavailable"}),
                OidcError::Unavailable,
            ),
        ] {
            *endpoint.answer.lock().unwrap() = (status, body.clone());
            assert_eq!(
                exchange(&url, &credentials).await.err(),
                Some(expected),
                "{status} {body}"
            );
        }
    }

    #[tokio::test]
    async fn refresh_keeps_rotated_tokens_and_classifies_rejections() {
        let (url, endpoint) = endpoint().await;
        let http = IdpHttp::new(Duration::from_secs(2)).unwrap();
        let credentials = ClientCredentials::Basic {
            client_id: "authotron",
            secret: "s3cret",
        };
        let tokens = refresh(&http, &url, &credentials, "offline+1")
            .await
            .unwrap();
        assert_eq!(tokens.refresh_token.unwrap().as_str(), "rt");
        assert_eq!(tokens.id_token.unwrap().as_str(), "header.claims.sig");
        let (_, body) = endpoint.seen.lock().unwrap().pop().unwrap();
        assert_eq!(body, "grant_type=refresh_token&refresh_token=offline%2B1");
        // A provider may keep the refresh token and omit the ID token.
        *endpoint.answer.lock().unwrap() = (200, json!({"access_token": "at"}));
        let tokens = refresh(&http, &url, &credentials, "offline").await.unwrap();
        assert!(tokens.refresh_token.is_none() && tokens.id_token.is_none());
        for (status, body, expected) in [
            (400, json!({"error": "invalid_grant"}), OidcError::Rejected),
            (
                401,
                json!({"error": "invalid_client"}),
                OidcError::ClientRejected,
            ),
            (502, json!({}), OidcError::Unavailable),
            (
                200,
                json!({"refresh_token": "r".repeat(MAX_REFRESH_TOKEN_BYTES + 1)}),
                OidcError::InvalidResponse,
            ),
        ] {
            *endpoint.answer.lock().unwrap() = (status, body);
            assert_eq!(
                refresh(&http, &url, &credentials, "offline").await.err(),
                Some(expected)
            );
        }
    }

    #[tokio::test]
    async fn revocation_sends_the_token_and_hint_and_classifies_answers() {
        let (url, endpoint) = endpoint().await;
        let http = IdpHttp::new(Duration::from_secs(2)).unwrap();
        let credentials = ClientCredentials::Post {
            client_id: "authotron",
            secret: "s3cret",
        };
        revoke(&http, &url, &credentials, "offline+1")
            .await
            .unwrap();
        let (authorization, body) = endpoint.seen.lock().unwrap().pop().unwrap();
        assert!(authorization.is_empty());
        assert_eq!(
            body,
            "token=offline%2B1&token_type_hint=refresh_token&client_id=authotron&client_secret=s3cret"
        );
        for (status, expected) in [
            (503, OidcError::Unavailable),
            (400, OidcError::ClientRejected),
            (401, OidcError::ClientRejected),
            (404, OidcError::InvalidResponse),
        ] {
            *endpoint.answer.lock().unwrap() = (status, json!({"error": "x"}));
            assert_eq!(
                revoke(&http, &url, &credentials, "offline").await.err(),
                Some(expected)
            );
        }
    }
}

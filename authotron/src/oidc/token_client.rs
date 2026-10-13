// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! Authorization-code exchange at the token endpoint (RFC 6749 §4.1.3) with the PKCE
//! verifier and the configured client authentication. Only the ID token is kept;
//! access and refresh tokens in the response are dropped unread.

use super::{
    OidcError,
    http::{IdpHttp, IdpResponse, basic_authorization},
    id_token::MAX_ID_TOKEN_BYTES,
};
use serde::Deserialize;
use url::Url;
use zeroize::Zeroizing;

pub const TOKEN_RESPONSE_BYTES: usize = 64 * 1024;

/// Client authentication at the token endpoint. Deliberately not Debug.
pub enum ClientCredentials<'a> {
    /// `client_secret_basic`: form-urlencoded id and secret in an `Authorization` header.
    Basic { client_id: &'a str, secret: &'a str },
    /// `client_secret_post`: id and secret as form fields.
    Post { client_id: &'a str, secret: &'a str },
    /// Public client: `client_id` only; PKCE protects the code.
    Public { client_id: &'a str },
}

/// Exchanges `code` and returns the ID token.
pub async fn exchange_code(
    http: &IdpHttp,
    endpoint: &Url,
    credentials: &ClientCredentials<'_>,
    code: &str,
    redirect_uri: &str,
    verifier: &str,
) -> Result<Zeroizing<String>, OidcError> {
    let mut form = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("code_verifier", verifier),
    ];
    let authorization = match credentials {
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
    };
    let response = http
        .post_form(
            endpoint,
            &form,
            authorization.as_deref().map(String::as_str),
            TOKEN_RESPONSE_BYTES,
        )
        .await?;
    id_token(response)
}

/// The only field read from a token response.
#[derive(Deserialize)]
struct Tokens {
    id_token: Option<String>,
}

#[derive(Deserialize)]
struct ErrorBody {
    error: String,
}

/// 200 with an ID token succeeds; `invalid_grant` means the code was rejected; any other
/// 400/401 means the provider refused this client or request, which is a configuration
/// problem; 5xx is unavailability.
fn id_token(response: IdpResponse) -> Result<Zeroizing<String>, OidcError> {
    // The body holds every issued token; it is wiped when dropped.
    let body = Zeroizing::new(response.body);
    match response.status {
        200 => serde_json::from_slice::<Tokens>(&body)
            .ok()
            .and_then(|tokens| tokens.id_token)
            .map(Zeroizing::new)
            .filter(|token| !token.is_empty() && token.len() <= MAX_ID_TOKEN_BYTES)
            .ok_or(OidcError::InvalidResponse),
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

    async fn exchange(
        url: &Url,
        credentials: &ClientCredentials<'_>,
    ) -> Result<Zeroizing<String>, OidcError> {
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
            let token = exchange(&url, &credentials).await.unwrap();
            assert_eq!(token.as_str(), "header.claims.sig");
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
}

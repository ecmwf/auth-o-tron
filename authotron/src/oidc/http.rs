// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! Bounded HTTP for identity-provider requests: HTTPS destinations only, no redirects,
//! one deadline per request including the body, and capped response sizes.

use super::OidcError;
use crate::config::idp_url_allowed;
use base64::{Engine, engine::general_purpose::STANDARD};
use reqwest::header::{ACCEPT, AUTHORIZATION};
use std::time::Duration;
use url::Url;
use zeroize::Zeroizing;

/// Status and complete body of a provider answer; callers interpret both.
pub struct IdpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

/// One client per sign-in method so each method keeps its own deadline.
#[derive(Clone)]
pub struct IdpHttp {
    client: reqwest::Client,
}

impl IdpHttp {
    pub fn new(timeout: Duration) -> Result<Self, OidcError> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .https_only(!cfg!(test))
            .connect_timeout(timeout)
            .timeout(timeout)
            .user_agent(concat!("auth-o-tron/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|_| OidcError::Unavailable)?;
        Ok(Self { client })
    }

    pub async fn get(&self, url: &Url, limit: usize) -> Result<IdpResponse, OidcError> {
        self.send(self.client.get(url.as_str()), url, limit).await
    }

    /// Posts `application/x-www-form-urlencoded` fields, optionally with an
    /// `Authorization` header value such as [`basic_authorization`] returns.
    pub async fn post_form(
        &self,
        url: &Url,
        form: &[(&str, &str)],
        authorization: Option<&str>,
        limit: usize,
    ) -> Result<IdpResponse, OidcError> {
        let mut request = self.client.post(url.as_str()).form(form);
        if let Some(value) = authorization {
            request = request.header(AUTHORIZATION, value);
        }
        self.send(request, url, limit).await
    }

    async fn send(
        &self,
        request: reqwest::RequestBuilder,
        url: &Url,
        limit: usize,
    ) -> Result<IdpResponse, OidcError> {
        if !idp_url_allowed(url) || !url.username().is_empty() || url.password().is_some() {
            return Err(OidcError::InvalidResponse);
        }
        let mut response = request
            .header(ACCEPT, "application/json")
            .send()
            .await
            .map_err(|_| OidcError::Unavailable)?;
        let status = response.status().as_u16();
        if response
            .content_length()
            .is_some_and(|length| length > limit as u64)
        {
            return Err(OidcError::InvalidResponse);
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| OidcError::Unavailable)? {
            if body.len() + chunk.len() > limit {
                return Err(OidcError::InvalidResponse);
            }
            body.extend_from_slice(&chunk);
        }
        Ok(IdpResponse { status, body })
    }
}

/// `client_secret_basic` header value. RFC 6749 §2.3.1 form-urlencodes both parts
/// before Base64. Valid: `("a b", "p:w")` encodes `a+b:p%3Aw` as `Basic YStiOnAlM0F3`;
/// sending `a b:p:w` unencoded would be invalid, as the secret's `:` splits wrongly.
pub fn basic_authorization(client_id: &str, secret: &str) -> Zeroizing<String> {
    let encode = |value: &str| url::form_urlencoded::byte_serialize(value.as_bytes()).collect();
    let id: Zeroizing<String> = Zeroizing::new(encode(client_id));
    let secret: Zeroizing<String> = Zeroizing::new(encode(secret));
    let joined = Zeroizing::new(format!("{}:{}", *id, *secret));
    Zeroizing::new(format!("Basic {}", STANDARD.encode(joined.as_bytes())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oidc::mock::serve;
    use axum::{
        Router,
        body::{Body, Bytes},
        http::{HeaderMap, StatusCode, header},
        response::IntoResponse,
        routing::{get, post},
    };

    fn http(timeout_ms: u64) -> IdpHttp {
        IdpHttp::new(Duration::from_millis(timeout_ms)).unwrap()
    }
    fn url(base: &str, path: &str) -> Url {
        Url::parse(&format!("{base}{path}")).unwrap()
    }

    async fn provider() -> String {
        serve(
            Router::new()
                .route("/json", get(|| async { r#"{"ok":true}"# }))
                .route("/large", get(|| async { "x".repeat(2048) }))
                .route(
                    "/streamed",
                    get(|| async {
                        let chunks =
                            (0..4).map(|_| Ok::<_, std::io::Error>(Bytes::from(vec![b'x'; 512])));
                        Body::from_stream(futures::stream::iter(chunks))
                    }),
                )
                .route(
                    "/redirect",
                    get(|| async {
                        (StatusCode::FOUND, [(header::LOCATION, "/json")]).into_response()
                    }),
                )
                .route(
                    "/slow",
                    get(|| async {
                        tokio::time::sleep(Duration::from_secs(5)).await;
                        "late"
                    }),
                )
                .route(
                    "/echo",
                    post(|headers: HeaderMap, body: String| async move {
                        let authorization = headers
                            .get(header::AUTHORIZATION)
                            .map(|value| value.to_str().unwrap().to_owned())
                            .unwrap_or_default();
                        format!("{authorization}|{body}")
                    }),
                ),
        )
        .await
    }

    #[tokio::test]
    async fn bodies_are_returned_with_status_and_capped() {
        let base = provider().await;
        let client = http(2000);
        let response = client.get(&url(&base, "/json"), 64).await.unwrap();
        assert_eq!(
            (response.status, response.body.as_slice()),
            (200, &br#"{"ok":true}"#[..])
        );
        assert_eq!(
            client.get(&url(&base, "/large"), 2047).await.err(),
            Some(OidcError::InvalidResponse)
        );
        assert_eq!(
            client
                .get(&url(&base, "/large"), 2048)
                .await
                .unwrap()
                .body
                .len(),
            2048
        );
        // Without Content-Length the cap applies while streaming.
        assert_eq!(
            client.get(&url(&base, "/streamed"), 1500).await.err(),
            Some(OidcError::InvalidResponse)
        );
        let missing = client.get(&url(&base, "/missing"), 64).await.unwrap();
        assert_eq!(missing.status, 404);
    }

    #[tokio::test]
    async fn redirects_are_not_followed_and_deadlines_apply() {
        let base = provider().await;
        let client = http(300);
        let redirect = client.get(&url(&base, "/redirect"), 64).await.unwrap();
        assert_eq!(redirect.status, 302);
        assert!(redirect.body.is_empty());
        let started = std::time::Instant::now();
        assert_eq!(
            client.get(&url(&base, "/slow"), 64).await.err(),
            Some(OidcError::Unavailable)
        );
        assert!(started.elapsed() < Duration::from_secs(3));
        let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = closed.local_addr().unwrap();
        drop(closed);
        assert_eq!(
            client
                .get(&url(&format!("http://{address}"), "/json"), 64)
                .await
                .err(),
            Some(OidcError::Unavailable)
        );
    }

    #[tokio::test]
    async fn only_provider_urls_are_contacted() {
        let client = http(300);
        for value in [
            "http://example.org/json",
            "ftp://127.0.0.1/json",
            "http://user:pw@127.0.0.1:9/json",
        ] {
            assert_eq!(
                client.get(&Url::parse(value).unwrap(), 64).await.err(),
                Some(OidcError::InvalidResponse),
                "{value}"
            );
        }
    }

    #[tokio::test]
    async fn forms_carry_fields_and_authorization() {
        let base = provider().await;
        let authorization = basic_authorization("a b", "p:w");
        assert_eq!(authorization.as_str(), "Basic YStiOnAlM0F3");
        let response = http(2000)
            .post_form(
                &url(&base, "/echo"),
                &[("grant_type", "authorization_code"), ("code", "a&b=c")],
                Some(&authorization),
                256,
            )
            .await
            .unwrap();
        assert_eq!(
            String::from_utf8(response.body).unwrap(),
            "Basic YStiOnAlM0F3|grant_type=authorization_code&code=a%26b%3Dc"
        );
        let anonymous = http(2000)
            .post_form(&url(&base, "/echo"), &[("client_id", "public")], None, 256)
            .await
            .unwrap();
        assert_eq!(anonymous.body, b"|client_id=public");
    }
}

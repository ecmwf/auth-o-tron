// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! Provider metadata from OpenID Connect Discovery, fetched lazily and cached per
//! method. The document must name the configured issuer exactly, and every endpoint
//! must be on the issuer's origin or an explicitly allowed one.

use super::{
    OidcError,
    http::{IdpHttp, IdpResponse},
};
use crate::config::idp_url_allowed;
use serde::Deserialize;
use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use url::Url;

pub const DISCOVERY_BYTES: usize = 64 * 1024;
const REFRESH_AFTER: Duration = Duration::from_secs(3600);
const RETRY_AFTER: Duration = Duration::from_secs(10);
const SERVE_STALE_FOR: Duration = Duration::from_secs(86_400);

/// Validated endpoints of one provider.
#[derive(Debug, PartialEq, Eq)]
pub struct ProviderMetadata {
    pub authorization_endpoint: Url,
    pub token_endpoint: Url,
    pub jwks_uri: Url,
    /// RFC 7009 endpoint for revoking upstream refresh tokens, when the provider has one.
    pub revocation_endpoint: Option<Url>,
    /// RFC 9207: when advertised, authorization responses must carry a matching `iss`.
    pub authorization_response_iss_parameter_supported: bool,
}

/// Fields read from the discovery document; others are ignored.
#[derive(Deserialize)]
struct Document {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    #[serde(default)]
    revocation_endpoint: Option<String>,
    #[serde(default)]
    response_types_supported: Option<Vec<String>>,
    #[serde(default)]
    code_challenge_methods_supported: Option<Vec<String>>,
    #[serde(default)]
    authorization_response_iss_parameter_supported: bool,
}

/// Issuer with any trailing `/` removed, then `/.well-known/openid-configuration`.
/// Valid: `https://idp.example.org/realms/demo` gives
/// `https://idp.example.org/realms/demo/.well-known/openid-configuration`;
/// `https://idp.example.org/` gives `https://idp.example.org/.well-known/openid-configuration`.
pub fn discovery_url(issuer: &str) -> Result<Url, OidcError> {
    Url::parse(&format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    ))
    .map_err(|_| OidcError::InvalidResponse)
}

/// The issuer's origin followed by the configured additional origins.
pub fn allowed_origins(issuer: &str, additional: &[String]) -> Result<Vec<String>, OidcError> {
    let issuer = Url::parse(issuer).map_err(|_| OidcError::InvalidResponse)?;
    let mut origins = vec![issuer.origin().ascii_serialization()];
    origins.extend(additional.iter().cloned());
    Ok(origins)
}

/// Valid with origin `https://idp.example.org`: `https://idp.example.org/token`.
/// Invalid: `https://other.example.org/token`, `http://idp.example.org/token`,
/// `https://user@idp.example.org/token`, `https://idp.example.org/token#f`, `/token`.
fn endpoint(value: &str, origins: &[String]) -> Result<Url, OidcError> {
    let url = Url::parse(value).map_err(|_| OidcError::InvalidResponse)?;
    let allowed = idp_url_allowed(&url)
        && url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none()
        && origins.contains(&url.origin().ascii_serialization());
    allowed.then_some(url).ok_or(OidcError::InvalidResponse)
}

/// Checks a discovery document against the configured issuer and allowed origins.
pub fn parse_metadata(
    body: &[u8],
    issuer: &str,
    origins: &[String],
) -> Result<ProviderMetadata, OidcError> {
    let document: Document =
        serde_json::from_slice(body).map_err(|_| OidcError::InvalidResponse)?;
    let offers = |list: &Option<Vec<String>>, value: &str| {
        list.as_ref()
            .is_none_or(|values| values.iter().any(|item| item == value))
    };
    if document.issuer != issuer
        || !offers(&document.response_types_supported, "code")
        || !offers(&document.code_challenge_methods_supported, "S256")
    {
        return Err(OidcError::InvalidResponse);
    }
    Ok(ProviderMetadata {
        authorization_endpoint: endpoint(&document.authorization_endpoint, origins)?,
        token_endpoint: endpoint(&document.token_endpoint, origins)?,
        jwks_uri: endpoint(&document.jwks_uri, origins)?,
        revocation_endpoint: document
            .revocation_endpoint
            .as_deref()
            .map(|value| endpoint(value, origins))
            .transpose()?,
        authorization_response_iss_parameter_supported: document
            .authorization_response_iss_parameter_supported,
    })
}

/// Whether the chooser can offer the method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Availability {
    /// No fetch has completed yet.
    Unknown,
    Available,
    /// The last fetch failed and no usable metadata is cached.
    Unavailable,
}

#[derive(Default)]
struct Cached {
    metadata: Option<(Arc<ProviderMetadata>, Instant)>,
    failed_at: Option<Instant>,
}

#[derive(Clone, Copy)]
struct Timing {
    refresh_after: Duration,
    retry_after: Duration,
    serve_stale_for: Duration,
}

/// Refreshes metadata after an hour; after a failure, waits ten seconds before the
/// next fetch and keeps serving the last good metadata for up to a day.
pub struct Discovery {
    issuer: String,
    url: Url,
    origins: Vec<String>,
    cached: Mutex<Cached>,
    fetching: tokio::sync::Mutex<()>,
    timing: Timing,
}

impl Discovery {
    pub fn new(issuer: &str, additional_origins: &[String]) -> Result<Self, OidcError> {
        Ok(Self {
            issuer: issuer.to_owned(),
            url: discovery_url(issuer)?,
            origins: allowed_origins(issuer, additional_origins)?,
            cached: Mutex::default(),
            fetching: tokio::sync::Mutex::new(()),
            timing: Timing {
                refresh_after: REFRESH_AFTER,
                retry_after: RETRY_AFTER,
                serve_stale_for: SERVE_STALE_FOR,
            },
        })
    }

    pub fn availability(&self) -> Availability {
        let Ok(cached) = self.cached.lock() else {
            return Availability::Unavailable;
        };
        let usable = cached
            .metadata
            .as_ref()
            .is_some_and(|(_, at)| at.elapsed() < self.timing.serve_stale_for);
        match (usable, cached.failed_at) {
            (true, _) => Availability::Available,
            (false, Some(_)) => Availability::Unavailable,
            (false, None) => Availability::Unknown,
        }
    }

    /// Returns cached metadata, fetching it when stale; concurrent callers share one fetch.
    pub async fn metadata(&self, http: &IdpHttp) -> Result<Arc<ProviderMetadata>, OidcError> {
        if let Some(metadata) = self.cached_within(self.timing.refresh_after) {
            return Ok(metadata);
        }
        if self.retry_blocked() {
            return self.stale();
        }
        let _fetching = self.fetching.lock().await;
        if let Some(metadata) = self.cached_within(self.timing.refresh_after) {
            return Ok(metadata);
        }
        if self.retry_blocked() {
            return self.stale();
        }
        let result = self.fetch(http).await;
        let mut cached = self.cached.lock().map_err(|_| OidcError::Unavailable)?;
        match result {
            Ok(metadata) => {
                let metadata = Arc::new(metadata);
                cached.metadata = Some((metadata.clone(), Instant::now()));
                cached.failed_at = None;
                Ok(metadata)
            }
            Err(error) => {
                cached.failed_at = Some(Instant::now());
                drop(cached);
                self.cached_within(self.timing.serve_stale_for).ok_or(error)
            }
        }
    }

    fn cached_within(&self, limit: Duration) -> Option<Arc<ProviderMetadata>> {
        let cached = self.cached.lock().ok()?;
        cached
            .metadata
            .as_ref()
            .filter(|(_, at)| at.elapsed() < limit)
            .map(|(metadata, _)| metadata.clone())
    }

    fn retry_blocked(&self) -> bool {
        self.cached.lock().map_or(true, |cached| {
            cached
                .failed_at
                .is_some_and(|at| at.elapsed() < self.timing.retry_after)
        })
    }

    fn stale(&self) -> Result<Arc<ProviderMetadata>, OidcError> {
        self.cached_within(self.timing.serve_stale_for)
            .ok_or(OidcError::Unavailable)
    }

    async fn fetch(&self, http: &IdpHttp) -> Result<ProviderMetadata, OidcError> {
        match http.get(&self.url, DISCOVERY_BYTES).await? {
            IdpResponse { status: 200, body } => parse_metadata(&body, &self.issuer, &self.origins),
            IdpResponse { status, .. } if status >= 500 => Err(OidcError::Unavailable),
            _ => Err(OidcError::InvalidResponse),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::oidc::mock::serve;
    use axum::{Json, Router, extract::State, http::StatusCode, routing::get};
    use serde_json::{Value, json};
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A Keycloak-like discovery document for `issuer`.
    pub(crate) fn document(issuer: &str) -> Value {
        json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/protocol/openid-connect/auth"),
            "token_endpoint": format!("{issuer}/protocol/openid-connect/token"),
            "jwks_uri": format!("{issuer}/protocol/openid-connect/certs"),
            "revocation_endpoint": format!("{issuer}/protocol/openid-connect/revoke"),
            "response_types_supported": ["code", "none", "id_token"],
            "code_challenge_methods_supported": ["plain", "S256"],
            "authorization_response_iss_parameter_supported": true,
            "grant_types_supported": ["authorization_code", "refresh_token"]
        })
    }

    #[test]
    fn documents_must_name_the_issuer_and_keep_endpoints_on_allowed_origins() {
        let issuer = "https://idp.example.org/realms/demo";
        let origins = allowed_origins(issuer, &["https://keys.example.org".into()]).unwrap();
        assert_eq!(
            origins,
            ["https://idp.example.org", "https://keys.example.org"]
        );
        let metadata =
            parse_metadata(document(issuer).to_string().as_bytes(), issuer, &origins).unwrap();
        assert!(metadata.authorization_response_iss_parameter_supported);
        assert_eq!(
            metadata.revocation_endpoint.unwrap().as_str(),
            "https://idp.example.org/realms/demo/protocol/openid-connect/revoke"
        );
        assert_eq!(
            metadata.token_endpoint.as_str(),
            "https://idp.example.org/realms/demo/protocol/openid-connect/token"
        );
        let mut separate_keys = document(issuer);
        separate_keys["jwks_uri"] = json!("https://keys.example.org/certs");
        assert!(parse_metadata(separate_keys.to_string().as_bytes(), issuer, &origins).is_ok());
        let mut minimal = document(issuer);
        for field in [
            "revocation_endpoint",
            "response_types_supported",
            "code_challenge_methods_supported",
            "authorization_response_iss_parameter_supported",
        ] {
            minimal.as_object_mut().unwrap().remove(field);
        }
        let minimal = parse_metadata(minimal.to_string().as_bytes(), issuer, &origins).unwrap();
        assert!(!minimal.authorization_response_iss_parameter_supported);
        assert!(minimal.revocation_endpoint.is_none());
        for (field, value) in [
            ("issuer", json!("https://idp.example.org/realms/demo/")),
            ("issuer", json!("https://IDP.example.org/realms/demo")),
            ("issuer", json!("https://idp.example.org/realms/other")),
            ("token_endpoint", json!("https://other.example.org/token")),
            ("token_endpoint", json!("http://idp.example.org/token")),
            (
                "token_endpoint",
                json!("https://user@idp.example.org/token"),
            ),
            (
                "authorization_endpoint",
                json!("https://idp.example.org/auth#f"),
            ),
            ("authorization_endpoint", json!("/auth")),
            ("jwks_uri", json!("https://idp.example.org:8443/certs")),
            ("jwks_uri", json!(42)),
            (
                "revocation_endpoint",
                json!("https://other.example.org/revoke"),
            ),
            ("response_types_supported", json!(["id_token"])),
            ("code_challenge_methods_supported", json!(["plain"])),
        ] {
            let mut changed = document(issuer);
            changed[field] = value.clone();
            assert_eq!(
                parse_metadata(changed.to_string().as_bytes(), issuer, &origins),
                Err(OidcError::InvalidResponse),
                "{field}={value}"
            );
        }
        let mut missing = document(issuer);
        missing.as_object_mut().unwrap().remove("token_endpoint");
        assert!(parse_metadata(missing.to_string().as_bytes(), issuer, &origins).is_err());
        assert!(parse_metadata(b"not json", issuer, &origins).is_err());
    }

    #[test]
    fn discovery_url_follows_the_issuer_path() {
        for (issuer, url) in [
            (
                "https://idp.example.org/realms/demo",
                "https://idp.example.org/realms/demo/.well-known/openid-configuration",
            ),
            (
                "https://idp.example.org/",
                "https://idp.example.org/.well-known/openid-configuration",
            ),
            (
                "https://idp.example.org",
                "https://idp.example.org/.well-known/openid-configuration",
            ),
        ] {
            assert_eq!(discovery_url(issuer).unwrap().as_str(), url);
        }
    }

    #[derive(Clone)]
    struct Provider {
        status: Arc<AtomicUsize>,
        fetches: Arc<AtomicUsize>,
        issuer: Arc<Mutex<String>>,
    }

    async fn provider() -> (String, Provider) {
        async fn configuration(State(provider): State<Provider>) -> (StatusCode, Json<Value>) {
            provider.fetches.fetch_add(1, Ordering::SeqCst);
            let status = provider.status.load(Ordering::SeqCst) as u16;
            let issuer = provider.issuer.lock().unwrap().clone();
            (
                StatusCode::from_u16(status).unwrap(),
                Json(document(&issuer)),
            )
        }
        let provider = Provider {
            status: Arc::new(AtomicUsize::new(200)),
            fetches: Arc::default(),
            issuer: Arc::default(),
        };
        let base = serve(
            Router::new()
                .route(
                    "/realms/demo/.well-known/openid-configuration",
                    get(configuration),
                )
                .with_state(provider.clone()),
        )
        .await;
        *provider.issuer.lock().unwrap() = format!("{base}/realms/demo");
        (format!("{base}/realms/demo"), provider)
    }

    fn timed(issuer: &str, refresh_after: Duration, retry_after: Duration) -> Discovery {
        let mut discovery = Discovery::new(issuer, &[]).unwrap();
        discovery.timing.refresh_after = refresh_after;
        discovery.timing.retry_after = retry_after;
        discovery
    }

    #[tokio::test]
    async fn metadata_is_cached_and_shared() {
        let (issuer, provider) = provider().await;
        let http = IdpHttp::new(Duration::from_secs(2)).unwrap();
        let discovery = Discovery::new(&issuer, &[]).unwrap();
        assert_eq!(discovery.availability(), Availability::Unknown);
        let (a, b) = tokio::join!(discovery.metadata(&http), discovery.metadata(&http));
        assert!(Arc::ptr_eq(&a.unwrap(), &b.unwrap()));
        discovery.metadata(&http).await.unwrap();
        assert_eq!(provider.fetches.load(Ordering::SeqCst), 1);
        assert_eq!(discovery.availability(), Availability::Available);
    }

    #[tokio::test]
    async fn failures_back_off_and_stale_metadata_is_served() {
        let (issuer, provider) = provider().await;
        let http = IdpHttp::new(Duration::from_secs(2)).unwrap();
        provider.status.store(503, Ordering::SeqCst);
        let discovery = timed(&issuer, Duration::ZERO, Duration::from_secs(60));
        assert_eq!(
            discovery.metadata(&http).await.err(),
            Some(OidcError::Unavailable)
        );
        assert_eq!(discovery.availability(), Availability::Unavailable);
        // Within the retry delay no request is made.
        assert_eq!(
            discovery.metadata(&http).await.err(),
            Some(OidcError::Unavailable)
        );
        assert_eq!(provider.fetches.load(Ordering::SeqCst), 1);

        provider.status.store(200, Ordering::SeqCst);
        let discovery = timed(&issuer, Duration::ZERO, Duration::ZERO);
        let first = discovery.metadata(&http).await.unwrap();
        provider.status.store(500, Ordering::SeqCst);
        // Every call refreshes (refresh_after is zero); a failed refresh serves the last
        // good metadata and the method stays available.
        let stale = discovery.metadata(&http).await.unwrap();
        assert!(Arc::ptr_eq(&first, &stale));
        assert_eq!(discovery.availability(), Availability::Available);
        provider.status.store(404, Ordering::SeqCst);
        assert!(discovery.metadata(&http).await.is_ok());
        assert_eq!(provider.fetches.load(Ordering::SeqCst), 4);
    }

    #[tokio::test]
    async fn unexpected_answers_are_invalid_responses() {
        let (issuer, provider) = provider().await;
        let http = IdpHttp::new(Duration::from_secs(2)).unwrap();
        provider.status.store(404, Ordering::SeqCst);
        let discovery = timed(&issuer, Duration::ZERO, Duration::ZERO);
        assert_eq!(
            discovery.metadata(&http).await.err(),
            Some(OidcError::InvalidResponse)
        );
        provider.status.store(200, Ordering::SeqCst);
        *provider.issuer.lock().unwrap() = "https://mix-up.example.org/realms/demo".into();
        assert_eq!(
            discovery.metadata(&http).await.err(),
            Some(OidcError::InvalidResponse)
        );
        assert_eq!(discovery.availability(), Availability::Unavailable);
    }
}

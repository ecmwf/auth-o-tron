// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! Provider signing keys (JWKS): fetched lazily, cached for fifteen minutes, and
//! refetched for an unknown `kid` at most once every thirty seconds.

use super::{
    OidcError,
    http::{IdpHttp, IdpResponse},
};
use jsonwebtoken::{
    Algorithm, DecodingKey,
    jwk::{AlgorithmParameters, EllipticCurve, Jwk, KeyAlgorithm, PublicKeyUse},
};
use serde::Deserialize;
use std::{
    sync::Mutex,
    time::{Duration, Instant},
};
use url::Url;

pub const JWKS_BYTES: usize = 64 * 1024;
const MAX_KEYS: usize = 32;
const KEYS_TTL: Duration = Duration::from_secs(900);
const REFETCH_AFTER: Duration = Duration::from_secs(30);
const SERVE_STALE_FOR: Duration = Duration::from_secs(86_400);

/// Signature keys of a JWKS document. Keys for encryption or of unsupported types are
/// skipped rather than failing the set; more than 32 entries is an invalid document.
pub fn parse_jwks(body: &[u8]) -> Result<Vec<Jwk>, OidcError> {
    #[derive(Deserialize)]
    struct Document {
        keys: Vec<serde_json::Value>,
    }
    let document: Document =
        serde_json::from_slice(body).map_err(|_| OidcError::InvalidResponse)?;
    if document.keys.len() > MAX_KEYS {
        return Err(OidcError::InvalidResponse);
    }
    Ok(document
        .keys
        .into_iter()
        .filter_map(|key| serde_json::from_value::<Jwk>(key).ok())
        .filter(|key| {
            matches!(
                key.common.public_key_use,
                None | Some(PublicKeyUse::Signature)
            )
        })
        .collect())
}

fn declared(alg: Algorithm) -> KeyAlgorithm {
    match alg {
        Algorithm::RS256 => KeyAlgorithm::RS256,
        Algorithm::RS384 => KeyAlgorithm::RS384,
        Algorithm::RS512 => KeyAlgorithm::RS512,
        Algorithm::PS256 => KeyAlgorithm::PS256,
        Algorithm::PS384 => KeyAlgorithm::PS384,
        Algorithm::PS512 => KeyAlgorithm::PS512,
        Algorithm::ES256 => KeyAlgorithm::ES256,
        Algorithm::ES384 => KeyAlgorithm::ES384,
        Algorithm::EdDSA => KeyAlgorithm::EdDSA,
        Algorithm::HS256 => KeyAlgorithm::HS256,
        Algorithm::HS384 => KeyAlgorithm::HS384,
        Algorithm::HS512 => KeyAlgorithm::HS512,
    }
}

/// Key type and curve fit `alg`, and a declared `alg` matches it; symmetric keys never fit.
fn compatible(key: &Jwk, alg: Algorithm) -> bool {
    use Algorithm::*;
    let family = match (&key.algorithm, alg) {
        (AlgorithmParameters::RSA(_), RS256 | RS384 | RS512 | PS256 | PS384 | PS512) => true,
        (AlgorithmParameters::EllipticCurve(params), ES256) => params.curve == EllipticCurve::P256,
        (AlgorithmParameters::EllipticCurve(params), ES384) => params.curve == EllipticCurve::P384,
        (AlgorithmParameters::OctetKeyPair(params), EdDSA) => {
            params.curve == EllipticCurve::Ed25519
        }
        _ => false,
    };
    family
        && key
            .common
            .key_algorithm
            .is_none_or(|value| value == declared(alg))
}

/// The key named by `kid`, or without a `kid` the only key fitting `alg`.
pub fn select<'a>(keys: &'a [Jwk], kid: Option<&str>, alg: Algorithm) -> Option<&'a Jwk> {
    let mut candidates = keys.iter().filter(|key| compatible(key, alg));
    match kid {
        Some(kid) => candidates.find(|key| key.common.key_id.as_deref() == Some(kid)),
        None => {
            let only = candidates.next();
            candidates.next().is_none().then_some(only).flatten()
        }
    }
}

#[derive(Default)]
struct Cached {
    uri: Option<Url>,
    keys: Vec<Jwk>,
    fetched_at: Option<Instant>,
    failed_at: Option<Instant>,
}

#[derive(Clone, Copy)]
struct Timing {
    ttl: Duration,
    refetch_after: Duration,
}

pub struct Jwks {
    cached: Mutex<Cached>,
    fetching: tokio::sync::Mutex<()>,
    timing: Timing,
}

impl Default for Jwks {
    fn default() -> Self {
        Self {
            cached: Mutex::default(),
            fetching: tokio::sync::Mutex::new(()),
            timing: Timing {
                ttl: KEYS_TTL,
                refetch_after: REFETCH_AFTER,
            },
        }
    }
}

enum Lookup {
    Found(DecodingKey),
    /// Fetch, unless one was attempted too recently.
    Fetch,
    Missing(OidcError),
}

impl Jwks {
    /// Verification key for an ID token header. An unknown `kid` is `InvalidIdToken`.
    pub async fn key(
        &self,
        http: &IdpHttp,
        uri: &Url,
        kid: Option<&str>,
        alg: Algorithm,
    ) -> Result<DecodingKey, OidcError> {
        match self.lookup(uri, kid, alg)? {
            Lookup::Found(key) => return Ok(key),
            Lookup::Missing(error) => return Err(error),
            Lookup::Fetch => {}
        }
        let _fetching = self.fetching.lock().await;
        match self.lookup(uri, kid, alg)? {
            Lookup::Found(key) => return Ok(key),
            Lookup::Missing(error) => return Err(error),
            Lookup::Fetch => {}
        }
        let result = self.fetch(http, uri).await;
        let mut cached = self.cached.lock().map_err(|_| OidcError::Unavailable)?;
        match result {
            Ok(keys) => {
                *cached = Cached {
                    uri: Some(uri.clone()),
                    keys,
                    fetched_at: Some(Instant::now()),
                    failed_at: None,
                };
                decoding(select(&cached.keys, kid, alg))
            }
            Err(error) => {
                cached.failed_at = Some(Instant::now());
                drop(cached);
                match self.lookup(uri, kid, alg)? {
                    Lookup::Found(key) => Ok(key),
                    _ => Err(error),
                }
            }
        }
    }

    fn lookup(&self, uri: &Url, kid: Option<&str>, alg: Algorithm) -> Result<Lookup, OidcError> {
        let cached = self.cached.lock().map_err(|_| OidcError::Unavailable)?;
        let age = cached.fetched_at.map(|at| at.elapsed());
        let same_uri = cached.uri.as_ref() == Some(uri);
        let found = same_uri.then(|| select(&cached.keys, kid, alg)).flatten();
        let recent =
            |at: Option<Instant>| at.is_some_and(|at| at.elapsed() < self.timing.refetch_after);
        if let Some(key) = found
            && age.is_some_and(|age| age < self.timing.ttl)
        {
            return decoding(Some(key)).map(Lookup::Found);
        }
        if recent(cached.failed_at) {
            return Ok(
                match found.filter(|_| age.is_some_and(|age| age < SERVE_STALE_FOR)) {
                    Some(key) => Lookup::Found(decoding(Some(key))?),
                    None => Lookup::Missing(OidcError::Unavailable),
                },
            );
        }
        if same_uri && found.is_none() && recent(cached.fetched_at) {
            return Ok(Lookup::Missing(OidcError::InvalidIdToken));
        }
        Ok(Lookup::Fetch)
    }

    async fn fetch(&self, http: &IdpHttp, uri: &Url) -> Result<Vec<Jwk>, OidcError> {
        match http.get(uri, JWKS_BYTES).await? {
            IdpResponse { status: 200, body } => parse_jwks(&body),
            IdpResponse { status, .. } if status >= 500 => Err(OidcError::Unavailable),
            _ => Err(OidcError::InvalidResponse),
        }
    }
}

fn decoding(key: Option<&Jwk>) -> Result<DecodingKey, OidcError> {
    key.and_then(|key| DecodingKey::from_jwk(key).ok())
        .ok_or(OidcError::InvalidIdToken)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oidc::mock::{ec_jwk, rsa_jwk, serve};
    use axum::{Json, Router, extract::State, http::StatusCode, routing::get};
    use serde_json::{Value, json};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    fn keys(value: Value) -> Vec<Jwk> {
        parse_jwks(value.to_string().as_bytes()).unwrap()
    }

    #[test]
    fn only_signature_keys_are_kept_and_sets_are_bounded() {
        let parsed = keys(json!({"keys": [
            rsa_jwk(0, "sig", Some("RS256")),
            {"kty": "RSA", "use": "enc", "kid": "enc", "alg": "RSA-OAEP", "n": "AQAB", "e": "AQAB"},
            {"kty": "unknown", "kid": "odd"},
            ec_jwk("ec"),
            {"kty": "oct", "kid": "hmac", "k": "c2VjcmV0"}
        ]}));
        let kids: Vec<_> = parsed
            .iter()
            .map(|key| key.common.key_id.as_deref().unwrap())
            .collect();
        assert_eq!(kids, ["sig", "ec", "hmac"]);
        let many = json!({"keys": vec![rsa_jwk(0, "k", None); MAX_KEYS + 1]});
        assert_eq!(
            parse_jwks(many.to_string().as_bytes()),
            Err(OidcError::InvalidResponse)
        );
        assert!(parse_jwks(b"{\"keys\": {}}").is_err());
    }

    #[test]
    fn keys_are_selected_by_kid_type_curve_and_declared_algorithm() {
        let set = keys(json!({"keys": [
            rsa_jwk(0, "rsa", Some("RS256")),
            rsa_jwk(1, "any", None),
            ec_jwk("ec"),
            {"kty": "oct", "kid": "hmac", "k": "c2VjcmV0"}
        ]}));
        let kid = |kid, alg| select(&set, kid, alg).and_then(|key| key.common.key_id.clone());
        assert_eq!(kid(Some("rsa"), Algorithm::RS256).as_deref(), Some("rsa"));
        // The declared `alg` restricts the key to that algorithm.
        assert_eq!(kid(Some("rsa"), Algorithm::PS256), None);
        assert_eq!(kid(Some("any"), Algorithm::PS512).as_deref(), Some("any"));
        assert_eq!(kid(Some("ec"), Algorithm::ES256).as_deref(), Some("ec"));
        assert_eq!(kid(Some("ec"), Algorithm::ES384), None);
        assert_eq!(kid(Some("ec"), Algorithm::RS256), None);
        assert_eq!(kid(Some("hmac"), Algorithm::HS256), None);
        assert_eq!(kid(Some("missing"), Algorithm::RS256), None);
        // Without a kid only an unambiguous key is chosen.
        assert_eq!(kid(None, Algorithm::ES256).as_deref(), Some("ec"));
        assert_eq!(kid(None, Algorithm::RS256), None);
    }

    #[derive(Clone)]
    struct Provider {
        keys: Arc<Mutex<Value>>,
        status: Arc<AtomicUsize>,
        fetches: Arc<AtomicUsize>,
    }

    async fn provider(initial: Value) -> (Url, Provider) {
        async fn certs(State(provider): State<Provider>) -> (StatusCode, Json<Value>) {
            provider.fetches.fetch_add(1, Ordering::SeqCst);
            let status = StatusCode::from_u16(provider.status.load(Ordering::SeqCst) as u16);
            (status.unwrap(), Json(provider.keys.lock().unwrap().clone()))
        }
        let provider = Provider {
            keys: Arc::new(Mutex::new(initial)),
            status: Arc::new(AtomicUsize::new(200)),
            fetches: Arc::default(),
        };
        let base = serve(
            Router::new()
                .route("/certs", get(certs))
                .with_state(provider.clone()),
        )
        .await;
        (Url::parse(&format!("{base}/certs")).unwrap(), provider)
    }

    fn jwks(ttl: Duration, refetch_after: Duration) -> Jwks {
        Jwks {
            timing: Timing { ttl, refetch_after },
            ..Jwks::default()
        }
    }

    #[tokio::test]
    async fn keys_are_cached_and_unknown_kids_refetch_at_a_bounded_rate() {
        let (uri, provider) = provider(json!({"keys": [rsa_jwk(0, "old", None)]})).await;
        let http = IdpHttp::new(Duration::from_secs(2)).unwrap();
        let cache = jwks(KEYS_TTL, Duration::from_secs(60));
        for _ in 0..3 {
            cache
                .key(&http, &uri, Some("old"), Algorithm::RS256)
                .await
                .unwrap();
        }
        assert_eq!(provider.fetches.load(Ordering::SeqCst), 1);
        *provider.keys.lock().unwrap() = json!({"keys": [rsa_jwk(1, "new", None)]});
        // Fetched moments ago: the unknown kid is rejected without another request.
        assert_eq!(
            cache
                .key(&http, &uri, Some("new"), Algorithm::RS256)
                .await
                .err(),
            Some(OidcError::InvalidIdToken)
        );
        assert_eq!(provider.fetches.load(Ordering::SeqCst), 1);
        let cache = jwks(KEYS_TTL, Duration::ZERO);
        cache
            .key(&http, &uri, Some("new"), Algorithm::RS256)
            .await
            .unwrap();
        *provider.keys.lock().unwrap() = json!({"keys": [rsa_jwk(0, "rotated", None)]});
        cache
            .key(&http, &uri, Some("rotated"), Algorithm::RS256)
            .await
            .unwrap();
        assert_eq!(
            cache
                .key(&http, &uri, Some("gone"), Algorithm::RS256)
                .await
                .err(),
            Some(OidcError::InvalidIdToken)
        );
        assert_eq!(provider.fetches.load(Ordering::SeqCst), 4);
    }

    #[tokio::test]
    async fn failed_fetches_back_off_and_keep_serving_known_keys() {
        let (uri, provider) = provider(json!({"keys": [rsa_jwk(0, "k", None)]})).await;
        let http = IdpHttp::new(Duration::from_secs(2)).unwrap();
        provider.status.store(503, Ordering::SeqCst);
        let cache = jwks(Duration::ZERO, Duration::from_secs(60));
        assert_eq!(
            cache
                .key(&http, &uri, Some("k"), Algorithm::RS256)
                .await
                .err(),
            Some(OidcError::Unavailable)
        );
        assert_eq!(
            cache
                .key(&http, &uri, Some("k"), Algorithm::RS256)
                .await
                .err(),
            Some(OidcError::Unavailable)
        );
        assert_eq!(provider.fetches.load(Ordering::SeqCst), 1);

        provider.status.store(200, Ordering::SeqCst);
        let cache = jwks(Duration::ZERO, Duration::from_secs(60));
        cache
            .key(&http, &uri, Some("k"), Algorithm::RS256)
            .await
            .unwrap();
        provider.status.store(404, Ordering::SeqCst);
        // Expired keys trigger a refresh; its failure keeps the known key usable.
        cache
            .key(&http, &uri, Some("k"), Algorithm::RS256)
            .await
            .unwrap();
        cache
            .key(&http, &uri, Some("k"), Algorithm::RS256)
            .await
            .unwrap();
        assert_eq!(provider.fetches.load(Ordering::SeqCst), 3);
        assert_eq!(
            cache
                .key(&http, &uri, Some("other"), Algorithm::RS256)
                .await
                .err(),
            Some(OidcError::Unavailable)
        );
    }
}

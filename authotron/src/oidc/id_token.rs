// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! ID token validation (OpenID Connect Core §3.1.3.7): an allowed asymmetric algorithm
//! and its signature, then issuer, audience, authorized party, lifetime, nonce and,
//! when a maximum authentication age applies, `auth_time`. Claims are checked here
//! against the caller's clock rather than inside the JWT library.

use super::OidcError;
use crate::config::IdTokenAlgorithm;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde_json::{Map, Value};
use subtle::ConstantTimeEq;

pub const MAX_ID_TOKEN_BYTES: usize = 16 * 1024;
const MAX_SUBJECT_BYTES: usize = 255;
const MAX_AUDIENCES: usize = 16;

pub fn algorithm(value: IdTokenAlgorithm) -> Algorithm {
    match value {
        IdTokenAlgorithm::RS256 => Algorithm::RS256,
        IdTokenAlgorithm::RS384 => Algorithm::RS384,
        IdTokenAlgorithm::RS512 => Algorithm::RS512,
        IdTokenAlgorithm::PS256 => Algorithm::PS256,
        IdTokenAlgorithm::PS384 => Algorithm::PS384,
        IdTokenAlgorithm::PS512 => Algorithm::PS512,
        IdTokenAlgorithm::ES256 => Algorithm::ES256,
        IdTokenAlgorithm::ES384 => Algorithm::ES384,
        IdTokenAlgorithm::EdDSA => Algorithm::EdDSA,
    }
}

/// Header algorithm and key id, accepted only for a configured algorithm.
/// Valid: an RS256 header when `RS256` is allowed. Invalid: `HS256`, `none`, a
/// malformed header, or a token over 16 KiB.
pub fn inspect(
    token: &str,
    allowed: &[IdTokenAlgorithm],
) -> Result<(Algorithm, Option<String>), OidcError> {
    if token.len() > MAX_ID_TOKEN_BYTES {
        return Err(OidcError::InvalidIdToken);
    }
    let header = jsonwebtoken::decode_header(token).map_err(|_| OidcError::InvalidIdToken)?;
    if !allowed.iter().any(|value| algorithm(*value) == header.alg) {
        return Err(OidcError::InvalidIdToken);
    }
    Ok((header.alg, header.kid))
}

/// What the validated token must state, with the caller's current time.
pub struct Expected<'a> {
    pub issuer: &'a str,
    pub client_id: &'a str,
    /// Required and compared when set. Refreshed ID tokens are checked without it: the
    /// nonce belongs to the original authorization request.
    pub nonce: Option<&'a str>,
    pub now_seconds: u64,
    pub skew_seconds: u64,
    /// `iat` may be at most this much older than now (plus skew).
    pub max_issued_age_seconds: u64,
    /// When set, `auth_time` is required and may be at most this old (plus skew).
    pub max_authentication_age_seconds: Option<u64>,
}

/// Claims of a validated ID token; `sub` is 1-255 bytes without control characters.
/// Deliberately not Debug: claims carry personal data.
pub struct IdTokenClaims {
    pub sub: String,
    pub claims: Map<String, Value>,
}

/// Verifies the signature with `key` and every claim rule in [`Expected`].
pub fn verify(
    token: &str,
    alg: Algorithm,
    key: &DecodingKey,
    expected: &Expected<'_>,
) -> Result<IdTokenClaims, OidcError> {
    if token.len() > MAX_ID_TOKEN_BYTES {
        return Err(OidcError::InvalidIdToken);
    }
    let mut validation = Validation::new(alg);
    validation.validate_exp = false;
    validation.validate_nbf = false;
    validation.validate_aud = false;
    validation.required_spec_claims.clear();
    let claims = jsonwebtoken::decode::<Map<String, Value>>(token, key, &validation)
        .map_err(|_| OidcError::InvalidIdToken)?
        .claims;
    let sub = check_claims(&claims, expected).ok_or(OidcError::InvalidIdToken)?;
    Ok(IdTokenClaims { sub, claims })
}

/// Returns `sub` when every rule holds.
fn check_claims(claims: &Map<String, Value>, expected: &Expected<'_>) -> Option<String> {
    let text = |name: &str| claims.get(name).and_then(Value::as_str);
    let seconds = |name: &str| claims.get(name).and_then(Value::as_u64);
    let now = expected.now_seconds;
    let skew = expected.skew_seconds;

    if text("iss")? != expected.issuer {
        return None;
    }
    let sub = text("sub")?;
    if sub.is_empty() || sub.len() > MAX_SUBJECT_BYTES || sub.chars().any(char::is_control) {
        return None;
    }
    let audiences: Vec<&str> = match claims.get("aud")? {
        Value::String(audience) => vec![audience.as_str()],
        Value::Array(values) => values.iter().map(Value::as_str).collect::<Option<_>>()?,
        _ => return None,
    };
    if audiences.is_empty()
        || audiences.len() > MAX_AUDIENCES
        || !audiences.contains(&expected.client_id)
    {
        return None;
    }
    match claims.get("azp") {
        Some(azp) if azp.as_str() != Some(expected.client_id) => return None,
        None if audiences.len() > 1 => return None,
        _ => {}
    }
    if seconds("exp")?.saturating_add(skew) <= now {
        return None;
    }
    let issued = seconds("iat")?;
    if issued > now.saturating_add(skew)
        || issued
            .saturating_add(expected.max_issued_age_seconds)
            .saturating_add(skew)
            < now
    {
        return None;
    }
    if claims.contains_key("nbf") && seconds("nbf")? > now.saturating_add(skew) {
        return None;
    }
    if let Some(nonce) = expected.nonce
        && !bool::from(text("nonce")?.as_bytes().ct_eq(nonce.as_bytes()))
    {
        return None;
    }
    if let Some(max_age) = expected.max_authentication_age_seconds {
        let authenticated = seconds("auth_time")?;
        if authenticated > now.saturating_add(skew)
            || authenticated.saturating_add(max_age).saturating_add(skew) < now
        {
            return None;
        }
    }
    Some(sub.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oidc::mock::{ec_jwk, rsa_jwk, sign};
    use jsonwebtoken::{EncodingKey, Header, jwk::Jwk};
    use serde_json::json;

    const NOW: u64 = 1_700_000_000;
    const ISSUER: &str = "https://idp.example.org/realms/demo";
    const ALLOWED: [IdTokenAlgorithm; 3] = [
        IdTokenAlgorithm::RS256,
        IdTokenAlgorithm::PS256,
        IdTokenAlgorithm::ES256,
    ];

    fn expected(max_age: Option<u64>) -> Expected<'static> {
        Expected {
            issuer: ISSUER,
            client_id: "authotron",
            nonce: Some("nonce-value"),
            now_seconds: NOW,
            skew_seconds: 60,
            max_issued_age_seconds: 300,
            max_authentication_age_seconds: max_age,
        }
    }
    fn claims() -> Value {
        json!({
            "iss": ISSUER, "sub": "f81d4fae-7dec-11d0-a765-00a0c91e6bf6", "aud": "authotron",
            "exp": NOW + 60, "iat": NOW - 5, "auth_time": NOW - 100, "nonce": "nonce-value",
            "azp": "authotron", "preferred_username": "alice"
        })
    }
    fn key(jwk: Value) -> DecodingKey {
        DecodingKey::from_jwk(&serde_json::from_value::<Jwk>(jwk).unwrap()).unwrap()
    }
    fn check(claims: &Value, max_age: Option<u64>) -> Result<IdTokenClaims, OidcError> {
        let token = sign(claims, Algorithm::RS256, Some("k"), 0);
        let (alg, kid) = inspect(&token, &ALLOWED)?;
        assert_eq!(kid.as_deref(), Some("k"));
        verify(&token, alg, &key(rsa_jwk(0, "k", None)), &expected(max_age))
    }

    #[test]
    fn valid_tokens_verify_with_each_allowed_family() {
        let verified = check(&claims(), Some(3600)).unwrap();
        assert_eq!(verified.sub, "f81d4fae-7dec-11d0-a765-00a0c91e6bf6");
        assert_eq!(verified.claims["preferred_username"], "alice");
        for (alg, jwk) in [
            (Algorithm::PS256, rsa_jwk(0, "k", Some("PS256"))),
            (Algorithm::ES256, ec_jwk("k")),
        ] {
            let token = sign(&claims(), alg, Some("k"), 0);
            assert_eq!(inspect(&token, &ALLOWED).unwrap().0, alg);
            verify(&token, alg, &key(jwk), &expected(None)).unwrap();
        }
        let mut multiple = claims();
        multiple["aud"] = json!(["authotron", "account"]);
        check(&multiple, None).unwrap();
        // Lifetimes within the clock skew are accepted.
        let mut skewed = claims();
        skewed["exp"] = json!(NOW - 59);
        skewed["iat"] = json!(NOW + 60);
        skewed["nbf"] = json!(NOW + 60);
        check(&skewed, None).unwrap();
    }

    #[test]
    fn disallowed_algorithms_bad_signatures_and_oversized_tokens_are_rejected() {
        let hmac = jsonwebtoken::encode(
            &Header::new(Algorithm::HS256),
            &claims(),
            &EncodingKey::from_secret(b"client-secret-is-not-a-key"),
        )
        .unwrap();
        assert_eq!(inspect(&hmac, &ALLOWED), Err(OidcError::InvalidIdToken));
        let unsigned = format!(
            "eyJhbGciOiJub25lIn0.{}.",
            base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                claims().to_string()
            )
        );
        assert_eq!(inspect(&unsigned, &ALLOWED), Err(OidcError::InvalidIdToken));
        assert_eq!(
            inspect("not.a-jwt", &ALLOWED),
            Err(OidcError::InvalidIdToken)
        );
        let es = sign(&claims(), Algorithm::ES256, None, 0);
        assert_eq!(
            inspect(&es, &[IdTokenAlgorithm::RS256]),
            Err(OidcError::InvalidIdToken)
        );
        // Signed by another key than the one published for its kid.
        let forged = sign(&claims(), Algorithm::RS256, Some("k"), 1);
        assert_eq!(
            verify(
                &forged,
                Algorithm::RS256,
                &key(rsa_jwk(0, "k", None)),
                &expected(None)
            )
            .err(),
            Some(OidcError::InvalidIdToken)
        );
        let mut large = claims();
        large["padding"] = json!("x".repeat(MAX_ID_TOKEN_BYTES));
        let large = sign(&large, Algorithm::RS256, Some("k"), 0);
        assert_eq!(inspect(&large, &ALLOWED), Err(OidcError::InvalidIdToken));
        assert_eq!(
            verify(
                &large,
                Algorithm::RS256,
                &key(rsa_jwk(0, "k", None)),
                &expected(None)
            )
            .err(),
            Some(OidcError::InvalidIdToken)
        );
    }

    #[test]
    fn every_claim_rule_is_enforced() {
        for (claim, value) in [
            ("iss", json!("https://idp.example.org/realms/other")),
            ("iss", json!(null)),
            ("sub", json!("")),
            ("sub", json!(42)),
            ("sub", json!("a\nb")),
            ("sub", json!("s".repeat(256))),
            ("aud", json!("other-client")),
            ("aud", json!([])),
            ("aud", json!(["authotron", 7])),
            ("aud", json!(vec!["authotron"; MAX_AUDIENCES + 1])),
            ("azp", json!("other-client")),
            ("exp", json!(NOW - 60)),
            ("exp", json!(NOW as f64 + 0.5)),
            ("exp", json!(null)),
            ("iat", json!(NOW + 61)),
            ("iat", json!(NOW - 361)),
            ("iat", json!("now")),
            ("nbf", json!(NOW + 61)),
            ("nbf", json!("later")),
            ("nonce", json!("other-nonce")),
            ("nonce", json!(null)),
        ] {
            let mut changed = claims();
            changed[claim] = value.clone();
            assert_eq!(
                check(&changed, None).err(),
                Some(OidcError::InvalidIdToken),
                "{claim}={value}"
            );
        }
        for missing in ["iss", "sub", "aud", "exp", "iat", "nonce"] {
            let mut changed = claims();
            changed.as_object_mut().unwrap().remove(missing);
            assert!(check(&changed, None).is_err(), "{missing}");
        }
        // Several audiences require the authorized party to name this client.
        let mut multiple = claims();
        multiple["aud"] = json!(["authotron", "account"]);
        multiple.as_object_mut().unwrap().remove("azp");
        assert!(check(&multiple, None).is_err());
    }

    #[test]
    fn refreshed_tokens_are_checked_without_a_nonce() {
        let refreshed = Expected {
            nonce: None,
            ..expected(None)
        };
        let verify_claims = |claims: &Value| {
            let token = sign(claims, Algorithm::RS256, Some("k"), 0);
            verify(
                &token,
                Algorithm::RS256,
                &key(rsa_jwk(0, "k", None)),
                &refreshed,
            )
        };
        let mut without = claims();
        without.as_object_mut().unwrap().remove("nonce");
        assert!(verify_claims(&without).is_ok());
        assert!(verify_claims(&claims()).is_ok());
        assert!(check(&without, None).is_err());
        let mut foreign = claims();
        foreign["aud"] = json!("other-client");
        assert!(verify_claims(&foreign).is_err());
    }

    #[test]
    fn authentication_age_is_enforced_only_when_configured() {
        let mut old = claims();
        old["auth_time"] = json!(NOW - 3600 - 61);
        assert!(check(&old, None).is_ok());
        assert!(check(&old, Some(3600)).is_err());
        old["auth_time"] = json!(NOW - 3600 - 60);
        assert!(check(&old, Some(3600)).is_ok());
        let mut future = claims();
        future["auth_time"] = json!(NOW + 61);
        assert!(check(&future, Some(3600)).is_err());
        let mut missing = claims();
        missing.as_object_mut().unwrap().remove("auth_time");
        assert!(check(&missing, None).is_ok());
        assert!(check(&missing, Some(3600)).is_err());
    }
}

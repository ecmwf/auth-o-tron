// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! Provider signing keys (JWKS): parsing and selection of the key for an ID token.

use super::OidcError;
use jsonwebtoken::{
    Algorithm,
    jwk::{AlgorithmParameters, EllipticCurve, Jwk, KeyAlgorithm, PublicKeyUse},
};
use serde::Deserialize;

const MAX_KEYS: usize = 32;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oidc::mock::{ec_jwk, rsa_jwk};
    use serde_json::{Value, json};

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
}

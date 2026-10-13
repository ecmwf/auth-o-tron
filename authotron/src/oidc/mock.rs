// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! In-process identity-provider endpoints and signing keys for unit tests, served over
//! plain HTTP on a loopback port (accepted only in this crate's tests).

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rsa::{RsaPrivateKey, rand_core::OsRng, traits::PublicKeyParts};
use serde_json::{Value, json};
use std::sync::OnceLock;

/// Serves `router` on an ephemeral loopback port for the rest of the test runtime and
/// returns its base URL, e.g. `http://127.0.0.1:41234`.
pub(crate) async fn serve(router: axum::Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    base
}

/// Public half of a disposable P-256 test key; it protects nothing.
const EC_TEST_X: &str = "xXJVwcEjL2lizWBX5ztwIfd3uOIBGSbsheL34Tk8v3Y";
const EC_TEST_Y: &str = "YZLL8E9NgmVRE8y5qve-GOtcUhO8B2RW0W-EFbI0Vok";

/// Two RSA keys so tests can rotate signing keys.
pub(crate) fn rsa_key(index: usize) -> &'static RsaPrivateKey {
    static KEYS: OnceLock<[RsaPrivateKey; 2]> = OnceLock::new();
    &KEYS.get_or_init(|| [0, 1].map(|_| RsaPrivateKey::new(&mut OsRng, 2048).unwrap()))[index]
}

/// Public JWK of [`rsa_key`]; `alg` is omitted when `None`.
pub(crate) fn rsa_jwk(index: usize, kid: &str, alg: Option<&str>) -> Value {
    let key = rsa_key(index);
    let mut jwk = json!({
        "kty": "RSA", "use": "sig", "kid": kid,
        "n": URL_SAFE_NO_PAD.encode(key.n().to_bytes_be()),
        "e": URL_SAFE_NO_PAD.encode(key.e().to_bytes_be()),
    });
    if let Some(alg) = alg {
        jwk["alg"] = json!(alg);
    }
    jwk
}

pub(crate) fn ec_jwk(kid: &str) -> Value {
    json!({"kty": "EC", "use": "sig", "crv": "P-256", "kid": kid, "x": EC_TEST_X, "y": EC_TEST_Y})
}

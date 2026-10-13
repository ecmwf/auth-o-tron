// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! Parsing, validation and schema bounds of OIDC sign-in method settings.

use super::*;
use serde_json::{Value, json};

fn base() -> Value {
    json!({
        "id": "demo-sso", "label": "Continue with demo SSO", "realm": "keycloak-demo",
        "issuer": "https://idp.example.org/realms/demo", "client_id": "authotron",
        "client_secret_file": "/run/secrets/oidc/client-secret"
    })
}
fn parse(value: Value) -> OidcMethodConfig {
    serde_json::from_value(value).unwrap()
}

#[test]
fn minimal_method_uses_documented_defaults() {
    let config = parse(base());
    assert_eq!(config.client_auth, OidcClientAuth::ClientSecretBasic);
    assert_eq!(config.username_claim, UsernameClaim::Sub);
    assert_eq!(
        config.id_token_algorithms,
        [
            IdTokenAlgorithm::RS256,
            IdTokenAlgorithm::PS256,
            IdTokenAlgorithm::ES256
        ]
    );
    assert_eq!(config.clock_skew_seconds, 60);
    assert_eq!(config.http_timeout_ms, 5000);
    assert!(config.scopes.is_empty() && config.role_map.is_empty());
    assert!(config.roles_claim.is_none() && config.prompt.is_none());
    let round_trip: OidcMethodConfig =
        serde_json::from_value(serde_json::to_value(&config).unwrap()).unwrap();
    assert_eq!(round_trip, config);
}

#[test]
fn unknown_fields_ids_and_algorithms_are_rejected_while_parsing() {
    for (field, setting) in [
        ("id", json!("callback")),
        ("id", json!("Demo")),
        ("label", json!(" ")),
        ("client_auth", json!("private_key_jwt")),
        ("username_claim", json!("name")),
        ("id_token_algorithms", json!(["HS256"])),
        ("id_token_algorithms", json!(["none"])),
        ("prompt", json!("none")),
        ("client_secret", json!("inline-secret-value")),
        ("offline_access", json!(true)),
    ] {
        let mut value = base();
        value[field] = setting;
        assert!(
            serde_json::from_value::<OidcMethodConfig>(value).is_err(),
            "{field}"
        );
    }
}

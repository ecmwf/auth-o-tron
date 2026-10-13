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
    config.validate().unwrap();
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
    assert!(config.roles_claim.is_none() && config.prompt.is_none() && !config.offline_access);
    assert_eq!(config.display_name_claim, "preferred_username");
    let round_trip: OidcMethodConfig =
        serde_json::from_value(serde_json::to_value(&config).unwrap()).unwrap();
    assert_eq!(round_trip, config);
}

#[test]
fn full_method_validates() {
    let mut value = base();
    for (field, setting) in [
        ("client_auth", json!("client_secret_post")),
        ("scopes", json!(["profile", "email", "api:read"])),
        ("id_token_algorithms", json!(["ES384", "EdDSA", "PS512"])),
        ("username_claim", json!("preferred_username")),
        ("display_name_claim", json!("profile.full_name")),
        ("roles_claim", json!("realm_access.roles")),
        (
            "role_map",
            json!({"mcp-demo": "mcp-demo", "admins": "admin"}),
        ),
        ("max_authentication_age_seconds", json!(3600)),
        ("prompt", json!("select_account")),
        (
            "additional_endpoint_origins",
            json!(["https://keys.example.org:8443"]),
        ),
        ("clock_skew_seconds", json!(0)),
        ("http_timeout_ms", json!(30000)),
        ("refresh_max_lifetime_seconds", json!(86400)),
        ("offline_access", json!(true)),
    ] {
        value[field] = setting;
    }
    let config = parse(value);
    config.validate().unwrap();
    assert!(config.offline_access);
    assert_eq!(
        config.prompt.map(OidcPrompt::as_str),
        Some("select_account")
    );
    let mut public = base();
    public["client_auth"] = json!("none");
    public.as_object_mut().unwrap().remove("client_secret_file");
    parse(public).validate().unwrap();
}

#[test]
fn invalid_fields_are_rejected_without_echoing_values() {
    for (field, setting) in [
        ("realm", json!(" ")),
        ("realm", json!("r".repeat(129))),
        ("realm", json!("a\nb")),
        ("issuer", json!("http://idp.example.org/realms/demo")),
        ("issuer", json!("https://user@idp.example.org/realms/demo")),
        ("issuer", json!("https://idp.example.org/realms/demo?x=1")),
        ("issuer", json!("https://idp.example.org/realms/demo#f")),
        ("issuer", json!("https://idp.example.org:0/realms/demo")),
        ("issuer", json!("https://idp.example.org/realms/a b")),
        ("issuer", json!("idp.example.org")),
        (
            "issuer",
            json!(format!("https://idp.example.org/{}", "x".repeat(2048))),
        ),
        ("client_id", json!("")),
        ("client_id", json!("a b")),
        ("client_id", json!("é")),
        ("client_id", json!("c".repeat(257))),
        ("client_secret_file", json!("relative/secret")),
        ("client_secret_file", Value::Null),
        ("scopes", json!(["openid"])),
        ("scopes", json!(["offline_access"])),
        ("scopes", json!(["a b"])),
        ("scopes", json!(["\"x\""])),
        ("scopes", json!(["a\\b"])),
        ("scopes", json!([""])),
        ("scopes", json!(["profile", "profile"])),
        (
            "scopes",
            json!((0..17).map(|n| format!("s{n}")).collect::<Vec<_>>()),
        ),
        ("id_token_algorithms", json!([])),
        ("id_token_algorithms", json!(["RS256", "RS256"])),
        ("roles_claim", json!("realm_access.roles")),
        ("role_map", json!({"upstream": "local"})),
        ("display_name_claim", json!("")),
        ("display_name_claim", json!("$.name")),
        ("display_name_claim", json!("a.b.c.d.e")),
        ("max_authentication_age_seconds", json!(59)),
        ("max_authentication_age_seconds", json!(86401)),
        (
            "additional_endpoint_origins",
            json!(["https://keys.example.org/"]),
        ),
        (
            "additional_endpoint_origins",
            json!(["https://keys.example.org/certs"]),
        ),
        (
            "additional_endpoint_origins",
            json!(["http://keys.example.org"]),
        ),
        ("clock_skew_seconds", json!(301)),
        ("http_timeout_ms", json!(499)),
        ("http_timeout_ms", json!(30001)),
        ("refresh_max_lifetime_seconds", json!(299)),
        ("refresh_max_lifetime_seconds", json!(34560001)),
    ] {
        let mut value = base();
        value[field] = setting.clone();
        let config = parse(value);
        let error = config.validate().unwrap_err();
        assert!(!error.contains("secret-value"), "{field}");
        assert!(error.starts_with("OIDC"), "{field}={setting}: {error}");
    }
    let mut with_secret = base();
    with_secret["client_auth"] = json!("none");
    assert!(parse(with_secret).validate().is_err());
}

#[test]
fn roles_claim_and_role_map_are_bounded_and_required_together() {
    for (claim, valid) in [
        ("roles", true),
        ("realm_access.roles", true),
        ("a.b.c.d", true),
        ("a.b.c.d.e", false),
        ("a..b", false),
        (".roles", false),
        ("roles.", false),
        ("$.roles", false),
        ("", false),
    ] {
        assert_eq!(valid_claim_path(claim), valid, "{claim}");
        let mut value = base();
        value["roles_claim"] = json!(claim);
        value["role_map"] = json!({"upstream": "local"});
        assert_eq!(parse(value).validate().is_ok(), valid, "{claim}");
    }
    for map in [
        json!({" ": "local"}),
        json!({"upstream": "a\tb"}),
        json!({"upstream": "r".repeat(129)}),
        Value::Object((0..65).map(|n| (format!("u{n}"), json!("local"))).collect()),
    ] {
        let mut value = base();
        value["roles_claim"] = json!("roles");
        value["role_map"] = map;
        assert!(parse(value).validate().is_err());
    }
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
    ] {
        let mut value = base();
        value[field] = setting;
        assert!(
            serde_json::from_value::<OidcMethodConfig>(value).is_err(),
            "{field}"
        );
    }
}

#[test]
fn schema_bounds_agree_with_validation() {
    let schema = serde_json::to_value(schemars::schema_for!(OidcMethodConfig)).unwrap();
    let properties = &schema["properties"];
    assert_eq!(properties["id"]["pattern"], BROWSER_ID_PATTERN);
    assert_eq!(properties["roles_claim"]["pattern"], CLAIM_PATH_PATTERN);
    assert_eq!(
        properties["display_name_claim"]["pattern"],
        CLAIM_PATH_PATTERN
    );
    assert_eq!(properties["role_map"]["maxProperties"], MAX_ROLE_MAP);
    assert_eq!(properties["scopes"]["maxItems"], MAX_SCOPES);
    assert_eq!(
        properties["additional_endpoint_origins"]["maxItems"],
        MAX_ENDPOINT_ORIGINS
    );
    for (field, default, min, max) in [
        ("clock_skew_seconds", Some(60), 0, 300),
        ("http_timeout_ms", Some(5000), 500, 30000),
        ("max_authentication_age_seconds", None, 60, 86400),
        ("refresh_max_lifetime_seconds", None, 300, 34560000),
    ] {
        let property = &properties[field];
        if let Some(default) = default {
            assert_eq!(property["default"], default, "{field}");
        }
        assert_eq!(property["minimum"], min, "{field}");
        assert_eq!(property["maximum"], max, "{field}");
        for (value, valid) in [(min, true), (max, true), (max + 1, false)] {
            let mut config = base();
            config[field] = json!(value);
            assert_eq!(parse(config).validate().is_ok(), valid, "{field}={value}");
        }
    }
    let required: Vec<&str> = schema["required"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(
        required,
        ["id", "label", "realm", "issuer", "client_id"],
        "only identity fields are required"
    );
}

// (C) Copyright 2025- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

use super::{
    ecmwf_token_generator_provider::{
        EcmwfTokenGeneratorProvider, EcmwfTokenGeneratorProviderConfig,
    },
    ecmwfapi_provider::{EcmwfApiProvider, EcmwfApiProviderConfig},
    efasapi_provider::{EFASApiProviderConfig, EfasApiProvider},
    jwt_provider::{JWTAuthConfig, JWTProvider},
    openid_offline_provider::{OpenIDOfflineProvider, OpenIDOfflineProviderConfig},
    plain_provider::{PlainAuthConfig, PlainAuthProvider},
};
use crate::{models::user::User, state::AppState};
use axum::{
    Json,
    extract::{ConnectInfo, State},
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::net::SocketAddr;
use tracing::debug;

/// Configuration options for each authentication provider.
#[derive(Deserialize, Serialize, JsonSchema, Debug)]
#[serde(tag = "type", remote = "Self")]
#[schemars(transform = restrict_browser_to_supported_providers)]
pub enum ProviderConfig {
    #[serde(rename = "ecmwf-api")]
    EcmwfApi(EcmwfApiProviderConfig),
    #[serde(rename = "ecmwf-token-generator")]
    EcmwfTokenGenerator(EcmwfTokenGeneratorProviderConfig),
    #[serde(rename = "efas-api")]
    EfasApiProvider(EFASApiProviderConfig),
    #[serde(rename = "jwt")]
    Jwt(JWTAuthConfig),
    #[serde(rename = "openid-offline")]
    OpenIDOffline(OpenIDOfflineProviderConfig),
    #[serde(rename = "plain")]
    Plain(PlainAuthConfig),
}

const BROWSER_PROVIDER_TYPES: [&str; 2] = ["plain", "ecmwf-api"];

/// Mirrors the runtime `browser` check in the generated schema.
///
/// Provider variants other than `plain` and `ecmwf-api` keep accepting unknown
/// fields, but their `browser` property is constrained to `null`.
/// Valid: `{type: jwt, ..., browser: null}`.
/// Invalid: `{type: jwt, ..., browser: {id: sso, label: SSO}}`.
fn restrict_browser_to_supported_providers(schema: &mut schemars::Schema) {
    let Some(variants) = schema.get_mut("oneOf").and_then(Value::as_array_mut) else {
        return;
    };
    for variant in variants {
        let provider_type = variant
            .pointer("/properties/type/const")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let Some(provider_type) = provider_type else {
            continue;
        };
        if BROWSER_PROVIDER_TYPES.contains(&provider_type.as_str()) {
            continue;
        }
        if let Some(properties) = variant.get_mut("properties").and_then(Value::as_object_mut) {
            properties.insert(
                "browser".to_owned(),
                json!({
                    "description": "Direct browser sign-in is not supported for this provider type; only `null` is accepted.",
                    "type": "null"
                }),
            );
        }
    }
}

impl<'de> Deserialize<'de> for ProviderConfig {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // Provider structs ignore unknown fields, so an unsupported `browser` block
        // is rejected here instead of being silently dropped.
        // Valid: `{type: plain, name: staff, realm: r, users: [], browser: {id: staff, label: Staff}}`.
        // Invalid: `{type: jwt, name: sso, ..., browser: {id: staff, label: Staff}}`.
        // `browser: null` is treated as absent for every provider type.
        let value = Value::deserialize(deserializer)?;
        if let Some(object) = value.as_object()
            && object
                .get("browser")
                .is_some_and(|browser| !browser.is_null())
            && !object
                .get("type")
                .and_then(Value::as_str)
                .is_some_and(|kind| BROWSER_PROVIDER_TYPES.contains(&kind))
        {
            return Err(serde::de::Error::custom(
                "provider browser block is supported only for plain and ecmwf-api providers",
            ));
        }
        ProviderConfig::deserialize(value).map_err(serde::de::Error::custom)
    }
}

impl Serialize for ProviderConfig {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        ProviderConfig::serialize(self, serializer)
    }
}

/// An authentication provider must be able to return a User or an error.
#[async_trait::async_trait]
pub trait Provider: Send + Sync {
    fn get_name(&self) -> &str;
    fn get_type(&self) -> &str;
    /// Providers that support realm-based filtering should override this.
    fn get_realm(&self) -> Option<&str> {
        None
    }
    async fn authenticate(&self, credentials: &str) -> Result<User, String>;
    /// Whether `username` is still a configured account, without credentials.
    /// `None` when the provider cannot tell (e.g. a remote API-key service).
    fn account_still_exists(&self, _username: &str) -> Option<bool> {
        None
    }
}

/// Create an authentication provider from a given config.
pub fn create_auth_provider(config: &ProviderConfig) -> Box<dyn Provider> {
    match config {
        ProviderConfig::EcmwfApi(cfg) => Box::new(EcmwfApiProvider::new(cfg)),
        ProviderConfig::EcmwfTokenGenerator(cfg) => Box::new(EcmwfTokenGeneratorProvider::new(cfg)),
        ProviderConfig::EfasApiProvider(cfg) => Box::new(EfasApiProvider::new(cfg)),
        ProviderConfig::Jwt(cfg) => Box::new(JWTProvider::new(cfg)),
        ProviderConfig::OpenIDOffline(cfg) => Box::new(OpenIDOfflineProvider::new(cfg)),
        ProviderConfig::Plain(cfg) => Box::new(PlainAuthProvider::new(cfg)),
    }
}

/// GET /providers endpoint: returns only the provider "name", "type" and "realm" fields
/// by converting each provider config into JSON and extracting the fields.
pub async fn list_providers(
    State(state): State<AppState>,
    ConnectInfo(client_addr): ConnectInfo<SocketAddr>,
) -> Json<Value> {
    let client_ip = client_addr.ip();
    debug!(
        event_name = "providers.list.started",
        event_domain = "providers",
        client_ip = client_ip.to_string(),
        "listing configured providers"
    );

    let providers: Vec<Value> = state
        .config
        .providers
        .iter()
        .map(|provider| {
            let provider_json =
                serde_json::to_value(provider).expect("Failed to serialize provider config");
            if let Value::Object(mut map) = provider_json {
                let name = map.remove("name").unwrap_or_default();
                let provider_type = map.remove("type").unwrap_or_default();
                // Extract realm: check for "realm" first, then fallback to "iam_realm"
                let realm = if let Some(r) = map.remove("realm") {
                    r
                } else if let Some(r) = map.remove("iam_realm") {
                    r
                } else {
                    Value::Null
                };
                json!({
                    "name": name,
                    "type": provider_type,
                    "realm": realm,
                })
            } else {
                debug!(
                    event_name = "providers.list.invalid_config_shape",
                    event_domain = "providers",
                    "provider configuration was not an object"
                );
                json!({})
            }
        })
        .collect();

    debug!(
        event_name = "providers.list.completed",
        event_domain = "providers",
        client_ip = client_ip.to_string(),
        provider_count = providers.len(),
        "provider listing completed"
    );
    Json(json!({ "providers": providers }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROVIDER_TYPES: [&str; 6] = [
        "ecmwf-api",
        "ecmwf-token-generator",
        "efas-api",
        "jwt",
        "openid-offline",
        "plain",
    ];

    fn minimal_provider(provider_type: &str) -> Value {
        match provider_type {
            "ecmwf-api" | "efas-api" => {
                json!({"type": provider_type, "name": "p", "realm": "r", "uri": "https://example.test"})
            }
            "ecmwf-token-generator" => json!({
                "type": provider_type, "name": "p", "realm": "r",
                "cert_uri": "https://example.test/certs", "client_id": "c",
                "client_secret": "s", "token_generator_url": "https://example.test/token"
            }),
            "jwt" => json!({
                "type": provider_type, "name": "p", "realm": "r",
                "cert_uri": "https://example.test/certs", "iam_realm": "i"
            }),
            "openid-offline" => json!({
                "type": provider_type, "name": "p", "realm": "r",
                "cert_uri": "https://example.test/certs", "public_client_id": "pub",
                "private_client_id": "priv", "private_client_secret": "s",
                "iam_url": "https://example.test/iam"
            }),
            "plain" => json!({"type": provider_type, "name": "p", "realm": "r", "users": []}),
            other => panic!("unknown provider type {other}"),
        }
    }

    /// Evaluates the generated schema's `browser` property for one provider type.
    /// Supports only the shapes the generator emits: `{type: null}` on the variant,
    /// or `anyOf: [$ref ProviderBrowserConfig, {type: null}]` on the referenced struct.
    fn schema_accepts_browser(schema: &Value, provider_type: &str, browser: &Value) -> bool {
        let defs = &schema["$defs"];
        let variant = defs["ProviderConfig"]["oneOf"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v.pointer("/properties/type/const") == Some(&json!(provider_type)))
            .unwrap_or_else(|| panic!("no schema variant for {provider_type}"));
        let def_name = variant["$ref"]
            .as_str()
            .unwrap()
            .trim_start_matches("#/$defs/");
        let mut constraints = Vec::new();
        if let Some(c) = variant.pointer("/properties/browser") {
            constraints.push(c.clone());
        }
        if let Some(c) = defs[def_name].pointer("/properties/browser") {
            constraints.push(c.clone());
        }
        let matches = |c: &Value| -> bool {
            if c.get("type") == Some(&json!("null")) {
                return browser.is_null();
            }
            if c.get("$ref") == Some(&json!("#/$defs/ProviderBrowserConfig")) {
                let required = defs["ProviderBrowserConfig"]["required"]
                    .as_array()
                    .unwrap();
                return browser.is_object()
                    && required
                        .iter()
                        .all(|k| browser.get(k.as_str().unwrap()).is_some());
            }
            panic!("unexpected browser schema shape: {c}");
        };
        constraints.iter().all(|c| match c.get("anyOf") {
            Some(options) => options.as_array().unwrap().iter().any(matches),
            None => matches(c),
        })
    }

    #[test]
    fn browser_schema_matches_runtime_acceptance() {
        let schema = serde_json::to_value(schemars::schema_for!(crate::config::Config)).unwrap();
        let browser_object = json!({"id": "staff", "label": "Staff"});
        for provider_type in PROVIDER_TYPES {
            for browser in [Value::Null, browser_object.clone()] {
                let mut config = minimal_provider(provider_type);
                config["browser"] = browser.clone();
                let runtime = serde_json::from_value::<ProviderConfig>(config).is_ok();
                let schema_ok = schema_accepts_browser(&schema, provider_type, &browser);
                let expected = browser.is_null() || BROWSER_PROVIDER_TYPES.contains(&provider_type);
                assert_eq!(
                    runtime, expected,
                    "runtime: {provider_type} browser={browser}"
                );
                assert_eq!(
                    schema_ok, expected,
                    "schema: {provider_type} browser={browser}"
                );
            }
        }
    }
}

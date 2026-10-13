// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! Provider metadata from OpenID Connect Discovery. The document must name the
//! configured issuer exactly, and every endpoint must be on the issuer's origin or an
//! explicitly allowed one.

use super::OidcError;
use crate::config::idp_url_allowed;
use serde::Deserialize;
use url::Url;

/// Validated endpoints of one provider.
#[derive(Debug, PartialEq, Eq)]
pub struct ProviderMetadata {
    pub authorization_endpoint: Url,
    pub token_endpoint: Url,
    pub jwks_uri: Url,
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
        authorization_response_iss_parameter_supported: document
            .authorization_response_iss_parameter_supported,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::{Value, json};

    /// A Keycloak-like discovery document for `issuer`.
    pub(crate) fn document(issuer: &str) -> Value {
        json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/protocol/openid-connect/auth"),
            "token_endpoint": format!("{issuer}/protocol/openid-connect/token"),
            "jwks_uri": format!("{issuer}/protocol/openid-connect/certs"),
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
            metadata.token_endpoint.as_str(),
            "https://idp.example.org/realms/demo/protocol/openid-connect/token"
        );
        let mut separate_keys = document(issuer);
        separate_keys["jwks_uri"] = json!("https://keys.example.org/certs");
        assert!(parse_metadata(separate_keys.to_string().as_bytes(), issuer, &origins).is_ok());
        let mut minimal = document(issuer);
        for field in [
            "response_types_supported",
            "code_challenge_methods_supported",
            "authorization_response_iss_parameter_supported",
        ] {
            minimal.as_object_mut().unwrap().remove(field);
        }
        let minimal = parse_metadata(minimal.to_string().as_bytes(), issuer, &origins).unwrap();
        assert!(!minimal.authorization_response_iss_parameter_supported);
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
}

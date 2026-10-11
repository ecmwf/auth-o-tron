// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! Configuration contract for future OAuth authorization-server support.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct OAuthConfig {
    pub enabled: bool,
    pub issuer: Option<String>,
    #[schemars(range(min = 30, max = 300))]
    pub authorization_code_ttl_seconds: u64,
    #[schemars(range(min = 60, max = 3600))]
    pub access_token_ttl_seconds: u64,
}

impl Default for OAuthConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            issuer: None,
            authorization_code_ttl_seconds: 60,
            access_token_ttl_seconds: 300,
        }
    }
}

impl OAuthConfig {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.enabled && self.issuer.is_none() {
            return Err("oauth.issuer is required when OAuth is enabled");
        }
        if let Some(issuer) = &self.issuer {
            validate_issuer(issuer)?;
        }
        if !(30..=300).contains(&self.authorization_code_ttl_seconds) {
            return Err("oauth.authorization_code_ttl_seconds must be between 30 and 300");
        }
        if !(60..=3600).contains(&self.access_token_ttl_seconds) {
            return Err("oauth.access_token_ttl_seconds must be between 60 and 3600");
        }
        Ok(())
    }
}

/// Valid: `https://login.example.org/`. Invalid: `https://login.example.org/oauth`.
fn validate_issuer(value: &str) -> Result<(), &'static str> {
    let error = "oauth.issuer must be an absolute HTTPS origin without userinfo, path, query or fragment; issuer paths are unsupported";
    let uri: http::Uri = value.parse().map_err(|_| error)?;
    let url = url::Url::parse(value).map_err(|_| error)?;
    let authority = uri.authority().ok_or(error)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || url.port() == Some(0)
        || authority.as_str().ends_with(':')
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || uri.path() != "/"
        || value.contains(['@', '\\'])
        || value.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(error);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn defaults_and_unknown_fields() {
        let config: OAuthConfig = serde_json::from_value(json!({})).unwrap();
        assert!(!config.enabled);
        assert!(config.issuer.is_none());
        assert_eq!(config.authorization_code_ttl_seconds, 60);
        assert_eq!(config.access_token_ttl_seconds, 300);
        assert!(config.validate().is_ok());
        assert!(serde_json::from_value::<OAuthConfig>(json!({"enable": true})).is_err());
    }

    #[test]
    fn enabled_requires_issuer() {
        let config = OAuthConfig {
            enabled: true,
            ..Default::default()
        };
        assert_eq!(
            config.validate(),
            Err("oauth.issuer is required when OAuth is enabled")
        );
    }

    #[test]
    fn issuer_is_https_origin_only_even_when_disabled() {
        for issuer in [
            "https://login.example.org",
            "https://login.example.org/",
            "https://login.example.org:8443",
            "https://[::1]:8443/",
        ] {
            assert!(validate_issuer(issuer).is_ok(), "{issuer}");
        }
        for issuer in [
            "",
            "/login",
            "http://login.example.org",
            "https://user@login.example.org",
            "https://user:password@login.example.org",
            "https://@login.example.org",
            "https://login.example.org/oauth",
            "https://login.example.org/../",
            "https://login.example.org?",
            "https://login.example.org#",
            "https://login.example.org/\n",
            " https://login.example.org",
            "https://login.example.org\\",
            "https://login.example.org:/",
            "https://login.example.org:0/",
            "https://login.example.org:65536/",
            "https://login.example.org:not-a-port/",
            "https://login%20example.org/",
        ] {
            let config = OAuthConfig {
                issuer: Some(issuer.into()),
                ..Default::default()
            };
            assert!(config.validate().is_err(), "{issuer:?}");
        }
    }

    #[test]
    fn ttl_bounds_match_schema() {
        let schema = serde_json::to_value(schemars::schema_for!(OAuthConfig)).unwrap();
        assert_eq!(schema["additionalProperties"], false);
        for (field, min, max, default) in [
            ("authorization_code_ttl_seconds", 30, 300, 60),
            ("access_token_ttl_seconds", 60, 3600, 300),
        ] {
            let property = &schema["properties"][field];
            assert_eq!(property["minimum"], min);
            assert_eq!(property["maximum"], max);
            assert_eq!(property["default"], default);
            for value in [min - 1, min, max, max + 1] {
                let config: OAuthConfig = serde_json::from_value(json!({field: value})).unwrap();
                assert_eq!(config.validate().is_ok(), (min..=max).contains(&value));
            }
        }
    }
}

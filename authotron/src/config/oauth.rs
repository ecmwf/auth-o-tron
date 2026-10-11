// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! Configuration contract for future OAuth authorization-server support.

use super::oauth_policy::{ClientResource, OAuthResource};
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
    #[schemars(length(max = 64))]
    pub clients: Vec<OAuthClient>,
    #[schemars(length(max = 64))]
    pub resources: Vec<OAuthResource>,
}

impl Default for OAuthConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            issuer: None,
            authorization_code_ttl_seconds: 60,
            access_token_ttl_seconds: 300,
            clients: Vec::new(),
            resources: Vec::new(),
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
        if self.clients.len() > 64 {
            return Err("oauth.clients must contain at most 64 clients");
        }
        let mut ids = std::collections::HashSet::new();
        for client in &self.clients {
            client.validate()?;
            if !ids.insert(&client.client_id) {
                return Err("oauth.clients contains duplicate client_id values");
            }
        }
        self.validate_resources()
    }
}

/// Locally preregistered public client; token endpoint authentication is `none`.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OAuthClient {
    #[schemars(length(min = 1, max = 128), regex(pattern = r"^[A-Za-z0-9._-]+$"))]
    pub client_id: String,
    pub display_name: String,
    #[serde(default)]
    pub application_type: ApplicationType,
    #[schemars(length(min = 1, max = 8))]
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    #[schemars(length(max = 64))]
    pub resources: Vec<ClientResource>,
}

/// Uses the OpenID Connect `application_type` terminology.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ApplicationType {
    #[default]
    Web,
    Native,
}

impl OAuthClient {
    fn validate(&self) -> Result<(), &'static str> {
        if self.client_id.is_empty()
            || self.client_id.len() > 128
            || !self
                .client_id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
        {
            return Err(
                "OAuth client_id must be 1..128 ASCII bytes using letters, digits, '.', '_' or '-'",
            );
        }
        if self.display_name.trim().is_empty()
            || self.display_name.len() > 128
            || self.display_name.chars().any(char::is_control)
        {
            return Err(
                "OAuth display_name must be nonblank, control-free and at most 128 UTF-8 bytes",
            );
        }
        if !(1..=8).contains(&self.redirect_uris.len()) {
            return Err("OAuth redirect_uris must contain 1..8 callbacks");
        }
        for value in &self.redirect_uris {
            validate_callback(value, self.application_type)?;
        }
        Ok(())
    }
}

/// Valid native callback: `http://127.0.0.1:49152/callback`. Invalid: `http://localhost/callback`.
fn validate_callback(value: &str, application_type: ApplicationType) -> Result<(), &'static str> {
    let error = "OAuth callback must be an absolute HTTPS URI, or a native HTTP IP-loopback URI with an explicit nonzero port; no userinfo, fragment, backslash, whitespace or controls";
    if value.len() > 2048
        || value.contains('\\')
        || value.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(error);
    }
    let uri: http::Uri = value.parse().map_err(|_| error)?;
    let url = url::Url::parse(value).map_err(|_| error)?;
    let authority = uri.authority().ok_or(error)?;
    if url.host_str().is_none()
        || authority.as_str().contains('@')
        || authority.as_str().ends_with(':')
        || url.port() == Some(0)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(error);
    }
    match uri.scheme_str() {
        Some("https") if url.scheme() == "https" => {}
        Some("http")
            if application_type == ApplicationType::Native
                && matches!(uri.host(), Some("127.0.0.1" | "[::1]"))
                && uri.port_u16().is_some_and(|port| port != 0) => {}
        _ => return Err(error),
    }
    if url.query_pairs().any(|(name, _)| {
        matches!(
            name.as_ref(),
            "code" | "state" | "iss" | "error" | "error_description" | "error_uri"
        )
    }) {
        return Err("OAuth callback query must not contain reserved response parameters");
    }
    // Retain the original string for future exact matching, including port, path and query.
    Ok(())
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
        assert!(config.clients.is_empty());
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

    fn client(callback: &str) -> OAuthClient {
        serde_json::from_value(json!({"client_id": "mcp.desktop-1", "display_name": "MCP Desktop", "redirect_uris": [callback]})).unwrap()
    }

    #[test]
    fn public_clients_default_to_web_and_preserve_callbacks() {
        let callback = "https://APP.example.org:443/a%2Fb?fixed=a%20b&next=%2Faccount";
        let client = client(callback);
        assert_eq!(client.application_type, ApplicationType::Web);
        let config = OAuthConfig {
            clients: vec![client],
            ..Default::default()
        };
        assert!(config.validate().is_ok());
        assert_eq!(
            serde_json::to_value(&config).unwrap()["clients"][0]["redirect_uris"][0],
            callback
        );
        for field in [
            "client_secret",
            "token_endpoint_auth_method",
            "redirect_uri",
        ] {
            let mut value = serde_json::to_value(&config.clients[0]).unwrap();
            value[field] = json!("unsupported");
            assert!(serde_json::from_value::<OAuthClient>(value).is_err());
        }
    }

    #[test]
    fn client_identity_and_collection_bounds() {
        let valid = client("https://app.example.org/callback");
        for id in [
            "".into(),
            " ".into(),
            "é".into(),
            "https://client.example.org".into(),
            "a".repeat(129),
        ] {
            let mut candidate = valid.clone();
            candidate.client_id = id;
            assert!(candidate.validate().is_err());
        }
        for name in [" ".into(), "name\n".into(), "é".repeat(65)] {
            let mut candidate = valid.clone();
            candidate.display_name = name;
            assert!(candidate.validate().is_err());
        }
        let mut boundary = valid.clone();
        boundary.client_id = "a".repeat(128);
        boundary.display_name = "é".repeat(64);
        boundary.redirect_uris = vec![valid.redirect_uris[0].clone(); 8];
        assert!(boundary.validate().is_ok());
        for count in [0, 9] {
            boundary.redirect_uris = vec![valid.redirect_uris[0].clone(); count];
            assert!(boundary.validate().is_err());
        }
        let mut config = OAuthConfig {
            clients: vec![valid.clone(), valid.clone()],
            ..Default::default()
        };
        assert_eq!(
            config.validate(),
            Err("oauth.clients contains duplicate client_id values")
        );
        config.clients = (0..64)
            .map(|id| OAuthClient {
                client_id: id.to_string(),
                ..valid.clone()
            })
            .collect();
        assert!(config.validate().is_ok());
        config.clients.push(valid);
        assert!(config.validate().is_err());
    }

    #[test]
    fn callbacks_reject_unsafe_uris_and_reserved_query_names() {
        for callback in [
            "/callback",
            "https:///callback",
            "https://user@app.example.org/cb",
            "https://@app.example.org/cb",
            "https://app.example.org/cb#",
            "https://app.example.org\\cb",
            "https://app.example.org/c b",
            "https://app.example.org/cb\n",
            "https://app%20.example.org/cb",
            "https://app.example.org:/cb",
            "https://app.example.org:0/cb",
            "https://app.example.org:65536/cb",
            "https://app.example.org:bad/cb",
        ] {
            assert!(client(callback).validate().is_err(), "{callback:?}");
        }
        for name in [
            "code",
            "state",
            "iss",
            "error",
            "error_description",
            "error_uri",
            "%63ode",
        ] {
            assert!(
                client(&format!("https://app.example.org/cb?{name}=fixed"))
                    .validate()
                    .is_err()
            );
        }
        let prefix = "https://app.example.org/";
        assert!(
            client(&format!("{prefix}{}", "a".repeat(2048 - prefix.len())))
                .validate()
                .is_ok()
        );
        assert!(
            client(&format!("{prefix}{}", "a".repeat(2049 - prefix.len())))
                .validate()
                .is_err()
        );
    }

    #[test]
    fn native_http_requires_literal_loopback_and_fixed_nonzero_port() {
        for callback in [
            "http://127.0.0.1:49152/cb?fixed=1",
            "http://[::1]:49152/cb",
            "http://127.0.0.1:80/cb",
        ] {
            let mut candidate = client(callback);
            assert!(candidate.validate().is_err());
            candidate.application_type = ApplicationType::Native;
            assert!(candidate.validate().is_ok(), "{callback}");
            assert_eq!(candidate.redirect_uris[0], callback);
        }
        for callback in [
            "http://localhost:49152/cb",
            "http://127.0.0.2:49152/cb",
            "http://127.1:49152/cb",
            "http://0177.0.0.1:49152/cb",
            "http://2130706433:49152/cb",
            "http://[::ffff:127.0.0.1]:49152/cb",
            "http://127.0.0.1/cb",
            "http://[::1]/cb",
            "http://127.0.0.1:0/cb",
            "http://127.0.0.1:/cb",
            "http://app.example.org:49152/cb",
            "myapp:/callback",
        ] {
            let mut candidate = client(callback);
            candidate.application_type = ApplicationType::Native;
            assert!(candidate.validate().is_err(), "{callback}");
        }
        let mut candidate = client("https://app.example.org/cb?fixed=1");
        candidate.application_type = ApplicationType::Native;
        assert!(candidate.validate().is_ok());
        let case_distinct = client("https://app.example.org/cb?Code=fixed");
        assert!(case_distinct.validate().is_ok());
    }
}

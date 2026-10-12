// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! Configuration contract for the opt-in OAuth authorization server.

use super::oauth_policy::{ClientResource, OAuthResource};
use super::oauth_signing::OAuthSigningConfig;
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
    #[schemars(range(min = 30, max = 900))]
    pub authorization_transaction_ttl_seconds: u64,
    #[schemars(range(min = 1, max = 100000))]
    pub max_authorization_transactions: usize,
    #[schemars(range(min = 1, max = 100000))]
    pub max_authorization_codes: usize,
    #[schemars(range(min = 1, max = 3600))]
    pub max_authentication_age_seconds: u64,
    #[schemars(range(min = 0, max = 60))]
    pub authentication_clock_skew_seconds: u64,
    #[schemars(length(max = 64))]
    pub clients: Vec<OAuthClient>,
    #[schemars(length(max = 64))]
    pub resources: Vec<OAuthResource>,
    pub signing: Option<OAuthSigningConfig>,
}

impl Default for OAuthConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            issuer: None,
            authorization_code_ttl_seconds: 60,
            access_token_ttl_seconds: 300,
            authorization_transaction_ttl_seconds: 300,
            max_authorization_transactions: 1024,
            max_authorization_codes: 1024,
            max_authentication_age_seconds: 300,
            authentication_clock_skew_seconds: 30,
            clients: Vec::new(),
            resources: Vec::new(),
            signing: None,
        }
    }
}

impl OAuthConfig {
    pub fn validate(&self) -> Result<(), &'static str> {
        if let Some(signing) = &self.signing {
            signing.validate()?;
        }
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
        if !(30..=900).contains(&self.authorization_transaction_ttl_seconds) {
            return Err("oauth.authorization_transaction_ttl_seconds must be between 30 and 900");
        }
        if !(1..=100000).contains(&self.max_authorization_transactions) {
            return Err("oauth.max_authorization_transactions must be between 1 and 100000");
        }
        if !(1..=100000).contains(&self.max_authorization_codes) {
            return Err("oauth.max_authorization_codes must be between 1 and 100000");
        }
        if !(1..=3600).contains(&self.max_authentication_age_seconds) {
            return Err("oauth.max_authentication_age_seconds must be between 1 and 3600");
        }
        if self.authentication_clock_skew_seconds > 60 {
            return Err("oauth.authentication_clock_skew_seconds must be between 0 and 60");
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

/// Valid native callbacks: `http://127.0.0.1:49152/callback`, `http://localhost/callback`.
/// Invalid: `http://localhost:0/callback`, `http://127.0.0.2:49152/callback`.
/// Loopback callbacks may omit the port because any request port matches them
/// (see [`redirect_uri_matches`]).
/// `localhost` is accepted as a deliberate interoperability deviation from RFC 8252 §8.3,
/// because common native MCP clients register `localhost` loopback callbacks.
fn validate_callback(value: &str, application_type: ApplicationType) -> Result<(), &'static str> {
    let error = "OAuth callback must be an absolute HTTPS URI, or a native HTTP loopback URI (127.0.0.1, [::1] or localhost) with an optional nonzero port; no userinfo, fragment, backslash, whitespace, controls or malformed percent escapes";
    if value.len() > 2048
        || !valid_percent_triplets(value)
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
            if application_type == ApplicationType::Native && is_loopback_host(uri.host()) => {}
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
    // Retain the original string for matching: exact, or port-agnostic for loopback.
    Ok(())
}

fn is_loopback_host(host: Option<&str>) -> bool {
    matches!(host, Some("127.0.0.1" | "[::1]" | "localhost"))
}

/// Splits a literal `http://` loopback URI into `(host, port, path_and_query)`.
/// Valid: `http://localhost:8080/cb?x=1` gives `("localhost", Some(8080), "/cb?x=1")`.
/// Invalid (`None`): `https://localhost/cb`, `HTTP://localhost/cb`, `http://localhost:/cb`.
fn split_loopback(value: &str) -> Option<(&str, Option<&str>, &str)> {
    let rest = value.strip_prefix("http://")?;
    let end = rest.find(['/', '?']).unwrap_or(rest.len());
    let (authority, path_and_query) = rest.split_at(end);
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && !authority.ends_with(']') => (host, Some(port)),
        _ => (authority, None),
    };
    is_loopback_host(Some(host)).then_some((host, port, path_and_query))
}

/// Matches a requested callback against a validated registered callback. HTTPS callbacks
/// match only by exact string. Loopback HTTP callbacks (RFC 8252 §7.3) match any
/// canonical request port 1-65535 when host, path and query are literally identical;
/// hosts are not interchangeable (`localhost` never matches `127.0.0.1`).
/// Registered `http://127.0.0.1/cb`: valid `http://127.0.0.1:65535/cb`;
/// invalid `http://127.0.0.1/cb`, `http://127.0.0.1:0/cb`, `http://127.0.0.1:080/cb`,
/// `http://localhost:8080/cb`, `http://127.0.0.1:8080/cb?x=1`.
pub(crate) fn redirect_uri_matches(registered: &str, requested: &str) -> bool {
    let Some((host, _, path)) = split_loopback(registered) else {
        return registered == requested;
    };
    let Some((requested_host, Some(port), requested_path)) = split_loopback(requested) else {
        return false;
    };
    host == requested_host
        && path == requested_path
        && port
            .parse::<u16>()
            .is_ok_and(|parsed| parsed != 0 && parsed.to_string() == port)
}

/// Checks spelling only: `%20` and `%25` are valid; `%`, `%2` and `%GG` are invalid.
/// Registered identifiers remain literal strings, without decoding or normalization.
pub(super) fn valid_percent_triplets(value: &str) -> bool {
    let mut bytes = value.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'%'
            && !(bytes.next().is_some_and(|c| c.is_ascii_hexdigit())
                && bytes.next().is_some_and(|c| c.is_ascii_hexdigit()))
        {
            return false;
        }
    }
    true
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
    fn numeric_bounds_match_schema() {
        let schema = serde_json::to_value(schemars::schema_for!(OAuthConfig)).unwrap();
        let checked: serde_json::Value =
            serde_json::from_str(include_str!("../../schema.json")).unwrap();
        assert_eq!(
            schema["properties"]["max_authorization_codes"],
            checked["$defs"]["OAuthConfig"]["properties"]["max_authorization_codes"]
        );
        assert_eq!(
            checked["$defs"]["ConfigV2"]["properties"]["oauth"]["default"]["max_authorization_codes"],
            1024
        );
        assert_eq!(schema["additionalProperties"], false);
        for (field, min, max, default) in [
            ("authorization_code_ttl_seconds", 30, 300, 60),
            ("access_token_ttl_seconds", 60, 3600, 300),
            ("authorization_transaction_ttl_seconds", 30, 900, 300),
            ("max_authorization_transactions", 1, 100000, 1024),
            ("max_authorization_codes", 1, 100000, 1024),
            ("max_authentication_age_seconds", 1, 3600, 300),
            ("authentication_clock_skew_seconds", 0, 60, 30),
        ] {
            let property = &schema["properties"][field];
            assert_eq!(property["minimum"], min);
            assert_eq!(property["maximum"], max);
            assert_eq!(property["default"], default);
            for value in [min - 1, min, max, max + 1] {
                let config = serde_json::from_value::<OAuthConfig>(json!({field: value}));
                if value < 0 {
                    assert!(config.is_err());
                } else {
                    assert_eq!(
                        config.unwrap().validate().is_ok(),
                        (min..=max).contains(&value)
                    );
                }
            }
        }
    }

    fn client(callback: &str) -> OAuthClient {
        serde_json::from_value(json!({"client_id": "mcp.desktop-1", "display_name": "MCP Desktop", "redirect_uris": [callback]})).unwrap()
    }

    #[test]
    fn registered_uri_percent_triplets_are_checked_without_normalization() {
        use crate::oauth::authorization::{AuthorizationError, validate_authorization_request};

        let config_for = |callback: &str, resource: &str| -> OAuthConfig {
            serde_json::from_value(json!({
                "issuer": "https://login.example.org",
                "clients": [{"client_id": "desktop", "display_name": "Desktop",
                    "redirect_uris": [callback],
                    "resources": [{"resource": resource, "scopes": ["read"]}]}],
                "resources": [{"resource": resource, "allowed_realms": ["local"],
                    "scopes": [{"name": "read", "required_roles": []}]}]
            }))
            .unwrap()
        };
        let query_for = |callback: &str, resource: &str| {
            // Outer form escaping preserves the registered URI's literal percent escapes.
            url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs([
                    ("client_id", "desktop"),
                    ("redirect_uri", callback),
                    ("resource", resource),
                    ("scope", "read"),
                    ("response_type", "code"),
                    ("code_challenge_method", "S256"),
                    (
                        "code_challenge",
                        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                    ),
                ])
                .finish()
        };
        for escape in ["%", "%2", "%GG", "%20", "%25", "%2f", "%2F"] {
            let valid = matches!(escape, "%20" | "%25" | "%2f" | "%2F");
            for (callback, resource) in [
                (
                    format!("https://app.example.org/cb{escape}"),
                    "https://mcp.example.org/mcp".to_owned(),
                ),
                (
                    format!("https://app.example.org/cb?fixed={escape}"),
                    "https://mcp.example.org/mcp".to_owned(),
                ),
                (
                    format!("https://app.example.org/cb?fixed{escape}=value"),
                    "https://mcp.example.org/mcp".to_owned(),
                ),
                (
                    "https://app.example.org/cb".to_owned(),
                    format!("https://mcp.example.org/mcp{escape}"),
                ),
            ] {
                let config = config_for(&callback, &resource);
                assert_eq!(config.validate().is_ok(), valid, "{callback} {resource}");
                let query = query_for(&callback, &resource);
                let result = validate_authorization_request(&config, query.as_bytes());
                if valid {
                    let request = result.unwrap();
                    assert_eq!(request.redirect_uri(), callback);
                    assert_eq!(request.resource(), resource);
                    // Decoding or changing hex case does not authorize another spelling.
                    let alternate_escape = match escape {
                        "%20" => " ",
                        "%25" => "%",
                        "%2f" => "%2F",
                        "%2F" => "%2f",
                        _ => unreachable!(),
                    };
                    let alternate_callback = callback.replace(escape, alternate_escape);
                    let alternate_resource = resource.replace(escape, alternate_escape);
                    let alternate = query_for(&alternate_callback, &alternate_resource);
                    let expected = if alternate_callback != callback {
                        AuthorizationError::InvalidRequest
                    } else {
                        AuthorizationError::InvalidTarget
                    };
                    assert_eq!(
                        validate_authorization_request(&config, alternate.as_bytes()).err(),
                        Some(expected)
                    );
                } else {
                    assert_eq!(result.err(), Some(AuthorizationError::ServerError));
                }
            }
        }
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
    fn native_http_requires_literal_loopback_and_optional_nonzero_port() {
        for callback in [
            "http://127.0.0.1:49152/cb?fixed=1",
            "http://[::1]:49152/cb",
            "http://127.0.0.1:80/cb",
            "http://localhost:49152/cb",
            "http://localhost/cb",
            "http://127.0.0.1/cb",
            "http://[::1]/cb",
            "http://localhost",
        ] {
            let mut candidate = client(callback);
            assert!(candidate.validate().is_err());
            candidate.application_type = ApplicationType::Native;
            assert!(candidate.validate().is_ok(), "{callback}");
            assert_eq!(candidate.redirect_uris[0], callback);
        }
        for callback in [
            "http://localhost:0/cb",
            "http://LOCALHOST:49152/cb",
            "http://localhost.:49152/cb",
            "http://app.localhost:49152/cb",
            "http://127.0.0.2:49152/cb",
            "http://127.1:49152/cb",
            "http://0177.0.0.1:49152/cb",
            "http://2130706433:49152/cb",
            "http://[::ffff:127.0.0.1]:49152/cb",
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

    #[test]
    fn loopback_redirects_match_any_port_with_identical_host_path_and_query() {
        for (registered, requested) in [
            ("http://127.0.0.1/cb?x=1", "http://127.0.0.1:1/cb?x=1"),
            ("http://127.0.0.1/cb?x=1", "http://127.0.0.1:65535/cb?x=1"),
            ("http://127.0.0.1:49152/cb", "http://127.0.0.1:51734/cb"),
            ("http://[::1]/cb", "http://[::1]:8080/cb"),
            ("http://localhost/cb", "http://localhost:33418/cb"),
            ("http://localhost", "http://localhost:33418"),
            ("http://localhost:49152/cb", "http://localhost:49152/cb"),
            ("https://app.example.org/cb", "https://app.example.org/cb"),
        ] {
            assert!(redirect_uri_matches(registered, requested), "{requested}");
        }
        for (registered, requested) in [
            ("http://127.0.0.1/cb", "http://127.0.0.1:8080/other"),
            ("http://127.0.0.1/cb", "http://127.0.0.1:8080/cb/"),
            ("http://127.0.0.1/cb?x=1", "http://127.0.0.1:8080/cb?x=2"),
            ("http://127.0.0.1/cb", "http://127.0.0.1:8080/cb?x=1"),
            ("http://127.0.0.1/cb", "http://127.0.0.1:8080/cb#f"),
            ("http://127.0.0.1/cb", "http://localhost:8080/cb"),
            ("http://localhost/cb", "http://127.0.0.1:8080/cb"),
            ("http://localhost/cb", "http://LOCALHOST:8080/cb"),
            ("http://[::1]/cb", "http://127.0.0.1:8080/cb"),
            ("http://127.0.0.1/cb", "https://127.0.0.1:8080/cb"),
            ("http://127.0.0.1/cb", "HTTP://127.0.0.1:8080/cb"),
            ("http://127.0.0.1/cb", "http://u@127.0.0.1:8080/cb"),
            ("http://127.0.0.1/cb", "http://127.0.0.1/cb?"),
            ("http://127.0.0.1/cb", "http://127.0.0.1:0/cb"),
            ("http://127.0.0.1/cb", "http://127.0.0.1:/cb"),
            ("http://127.0.0.1/cb", "http://127.0.0.1:080/cb"),
            ("http://127.0.0.1/cb", "http://127.0.0.1:+80/cb"),
            ("http://127.0.0.1/cb", "http://127.0.0.1:65536/cb"),
            ("http://127.0.0.1/cb", "http://127.0.0.1:http/cb"),
            (
                "https://app.example.org/cb",
                "https://app.example.org:443/cb",
            ),
            (
                "https://app.example.org/cb",
                "https://app.example.org:8443/cb",
            ),
        ] {
            assert!(!redirect_uri_matches(registered, requested), "{requested}");
        }
        // A portless registration is never requestable without an explicit port.
        assert!(!redirect_uri_matches(
            "http://127.0.0.1/cb",
            "http://127.0.0.1/cb"
        ));
    }
}

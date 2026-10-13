// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! Settings for OpenID Connect sign-in methods offered on the browser login page.
//! Validation performs no file or network I/O.

use super::oauth_signing::valid_path;
use super::ui::{
    BROWSER_ID_MAX_LEN, BROWSER_ID_PATTERN, RESERVED_BROWSER_IDS, browser_id, browser_label,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::PathBuf};

/// Regex form of the `roles_claim` rule implemented by [`valid_roles_claim`].
pub const ROLES_CLAIM_PATTERN: &str = r"^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+){0,3}$";
const MAX_SCOPES: usize = 16;
const MAX_ROLE_MAP: usize = 64;
const MAX_ENDPOINT_ORIGINS: usize = 8;
const IDENTITY_TEXT_BYTES: usize = 128;

/// One identity provider offered as a browser sign-in method. The redirect URI
/// registered at the provider is `<public_origin>/login/method/<id>/callback`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OidcMethodConfig {
    /// Stable method id shared with provider `browser` ids; used in routes and metrics.
    #[serde(deserialize_with = "browser_id")]
    #[schemars(
        length(min = 1, max = BROWSER_ID_MAX_LEN),
        regex(pattern = BROWSER_ID_PATTERN),
        extend("not" = {"enum": RESERVED_BROWSER_IDS})
    )]
    pub id: String,
    /// Chooser button text, trimmed, 1-64 characters, no control characters.
    #[serde(deserialize_with = "browser_label")]
    #[schemars(length(min = 1, max = 64))]
    pub label: String,
    /// Realm of identities signed in with this method; unique across providers.
    #[schemars(length(min = 1, max = 128))]
    pub realm: String,
    /// Issuer identifier, compared exactly with the discovery document.
    #[schemars(length(min = 1, max = 2048))]
    pub issuer: String,
    #[schemars(length(min = 1, max = 256))]
    pub client_id: String,
    #[serde(default)]
    pub client_auth: OidcClientAuth,
    /// Absolute path of a file holding the client secret; required unless `client_auth` is `none`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_secret_file: Option<PathBuf>,
    /// Scopes requested in addition to `openid`.
    #[serde(default)]
    #[schemars(length(max = 16))]
    pub scopes: Vec<String>,
    #[serde(default = "default_algorithms")]
    #[schemars(length(min = 1, max = 9))]
    pub id_token_algorithms: Vec<IdTokenAlgorithm>,
    #[serde(default)]
    pub username_claim: UsernameClaim,
    /// Dotted path to a string-array claim of upstream roles, e.g. `realm_access.roles`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(regex(pattern = ROLES_CLAIM_PATTERN))]
    pub roles_claim: Option<String>,
    /// Upstream role to local role; upstream roles without an entry are dropped.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    #[schemars(extend("maxProperties" = 64))]
    pub role_map: BTreeMap<String, String>,
    /// Sent as `max_age`; the ID token must then carry a recent enough `auth_time`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(range(min = 60, max = 86400))]
    pub max_authentication_age_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt: Option<OidcPrompt>,
    /// Origins besides the issuer's that may host provider endpoints, e.g. a separate key host.
    #[serde(default)]
    #[schemars(length(max = 8))]
    pub additional_endpoint_origins: Vec<String>,
    #[serde(default = "default_clock_skew")]
    #[schemars(range(min = 0, max = 300))]
    pub clock_skew_seconds: u64,
    /// Bound on each provider request, including connection setup.
    #[serde(default = "default_http_timeout")]
    #[schemars(range(min = 500, max = 30000))]
    pub http_timeout_ms: u64,
    /// Upper bound on the absolute lifetime of OAuth refresh-token families started
    /// by a login with this method; the client's `absolute_ttl_seconds` still applies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(range(min = 300, max = 34560000))]
    pub refresh_max_lifetime_seconds: Option<u64>,
    /// Request `offline_access` for OAuth clients that set
    /// `refresh_tokens.upstream_offline_access`, coupling their refresh families to the
    /// provider's offline session.
    #[serde(default)]
    pub offline_access: bool,
}

/// Token-endpoint client authentication.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OidcClientAuth {
    #[default]
    ClientSecretBasic,
    ClientSecretPost,
    /// Public client; the code is protected by PKCE only.
    None,
}

/// Claim that becomes the Auth-O-Tron username. `email` requires `email_verified: true`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum UsernameClaim {
    #[default]
    Sub,
    PreferredUsername,
    Email,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OidcPrompt {
    Login,
    Consent,
    SelectAccount,
}

impl OidcPrompt {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Login => "login",
            Self::Consent => "consent",
            Self::SelectAccount => "select_account",
        }
    }
}

/// Asymmetric JWS algorithms accepted for ID tokens; symmetric and `none` are never offered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
pub enum IdTokenAlgorithm {
    RS256,
    RS384,
    RS512,
    PS256,
    PS384,
    PS512,
    ES256,
    ES384,
    EdDSA,
}

fn default_algorithms() -> Vec<IdTokenAlgorithm> {
    vec![
        IdTokenAlgorithm::RS256,
        IdTokenAlgorithm::PS256,
        IdTokenAlgorithm::ES256,
    ]
}
fn default_clock_skew() -> u64 {
    60
}
fn default_http_timeout() -> u64 {
    5000
}

/// Identity-provider URLs must be HTTPS. Plain-HTTP loopback URLs are accepted only
/// in this crate's unit tests, whose identity providers run in-process.
/// Valid: `https://idp.example.org/token`. Invalid: `http://idp.example.org/token`.
pub(crate) fn idp_url_allowed(url: &url::Url) -> bool {
    match url.scheme() {
        "https" => true,
        "http" => cfg!(test) && matches!(url.host_str(), Some("127.0.0.1" | "localhost")),
        _ => false,
    }
}

fn plain_text(value: &str) -> bool {
    !value.contains('\\') && !value.chars().any(|c| c.is_whitespace() || c.is_control())
}

/// Valid: `https://idp.example.org/realms/demo`, `https://accounts.example.org`.
/// Invalid: `http://idp.example.org`, `https://user@idp.example.org`,
/// `https://idp.example.org/r?x=1`, `https://idp.example.org/r#f`, `https://idp.example.org:0`.
fn valid_issuer(value: &str) -> bool {
    value.len() <= 2048
        && plain_text(value)
        && !value.contains('@')
        && url::Url::parse(value).is_ok_and(|url| {
            idp_url_allowed(&url)
                && url.host_str().is_some()
                && url.port() != Some(0)
                && url.query().is_none()
                && url.fragment().is_none()
        })
}

/// Canonical origin only. Valid: `https://keys.example.org`, `https://keys.example.org:8443`.
/// Invalid: `https://keys.example.org/`, `https://keys.example.org/certs`, `http://keys.example.org`.
fn valid_origin(value: &str) -> bool {
    plain_text(value)
        && url::Url::parse(value).is_ok_and(|url| {
            idp_url_allowed(&url)
                && url.host_str().is_some()
                && url.port() != Some(0)
                && url.origin().ascii_serialization() == value
        })
}

/// RFC 6749 scope-token characters. Valid: `profile`, `api:read`. Invalid: `a b`, `"x"`, `a\b`.
fn valid_scope(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|c| c == 0x21 || (0x23..=0x5B).contains(&c) || (0x5D..=0x7E).contains(&c))
}

/// Matches [`ROLES_CLAIM_PATTERN`]. Valid: `roles`, `realm_access.roles`.
/// Invalid: `a..b`, `.roles`, `roles.`, `$.roles`, five segments.
pub fn valid_roles_claim(value: &str) -> bool {
    let segments: Vec<&str> = value.split('.').collect();
    segments.len() <= 4
        && segments.iter().all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
        })
}

/// Same bounds as verified identity fields: non-blank, at most 128 bytes, no controls.
fn bounded_text(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= IDENTITY_TEXT_BYTES
        && !value.chars().any(char::is_control)
}

impl OidcMethodConfig {
    /// Checks each field without I/O; cross-method uniqueness is checked with the other
    /// browser methods.
    pub fn validate(&self) -> Result<(), &'static str> {
        if !bounded_text(&self.realm) {
            return Err("OIDC realm must be 1-128 bytes without control characters");
        }
        if !valid_issuer(&self.issuer) {
            return Err(
                "OIDC issuer must be an absolute HTTPS URL without userinfo, query, fragment or whitespace, at most 2048 bytes",
            );
        }
        if self.client_id.is_empty()
            || self.client_id.len() > 256
            || !self.client_id.bytes().all(|c| (0x21..=0x7E).contains(&c))
        {
            return Err("OIDC client_id must be 1-256 visible ASCII characters");
        }
        match (self.client_auth, &self.client_secret_file) {
            (OidcClientAuth::None, None) => {}
            (OidcClientAuth::None, Some(_)) => {
                return Err("OIDC client_auth none must not reference a client_secret_file");
            }
            (_, None) => {
                return Err(
                    "OIDC client_secret_basic and client_secret_post require client_secret_file",
                );
            }
            (_, Some(path)) if !valid_path(path) => {
                return Err(
                    "OIDC client_secret_file must be an absolute path of at most 4096 UTF-8 bytes without controls",
                );
            }
            _ => {}
        }
        if self.scopes.len() > MAX_SCOPES
            || !self.scopes.iter().all(|scope| valid_scope(scope))
            || self
                .scopes
                .iter()
                .any(|scope| scope == "openid" || scope == "offline_access")
            || has_duplicates(&self.scopes)
        {
            return Err(
                "OIDC scopes must be at most 16 unique scope tokens, excluding openid and offline_access",
            );
        }
        if self.id_token_algorithms.is_empty() || has_duplicates(&self.id_token_algorithms) {
            return Err("OIDC id_token_algorithms must list at least one algorithm, once each");
        }
        match &self.roles_claim {
            Some(claim) if !valid_roles_claim(claim) => {
                return Err(
                    "OIDC roles_claim must be a dotted path of 1-4 segments of letters, digits, '_' or '-'",
                );
            }
            Some(_) if self.role_map.is_empty() => {
                return Err("OIDC roles_claim requires a non-empty role_map");
            }
            None if !self.role_map.is_empty() => {
                return Err("OIDC role_map requires roles_claim");
            }
            _ => {}
        }
        if self.role_map.len() > MAX_ROLE_MAP
            || !self
                .role_map
                .iter()
                .all(|(upstream, local)| bounded_text(upstream) && bounded_text(local))
        {
            return Err(
                "OIDC role_map must hold at most 64 roles of 1-128 bytes without control characters",
            );
        }
        if self
            .max_authentication_age_seconds
            .is_some_and(|age| !(60..=86400).contains(&age))
        {
            return Err("OIDC max_authentication_age_seconds must be between 60 and 86400");
        }
        if self.additional_endpoint_origins.len() > MAX_ENDPOINT_ORIGINS
            || !self
                .additional_endpoint_origins
                .iter()
                .all(|origin| valid_origin(origin))
        {
            return Err(
                "OIDC additional_endpoint_origins must hold at most 8 canonical HTTPS origins such as https://keys.example.org",
            );
        }
        if self.clock_skew_seconds > 300 {
            return Err("OIDC clock_skew_seconds must be between 0 and 300");
        }
        if !(500..=30000).contains(&self.http_timeout_ms) {
            return Err("OIDC http_timeout_ms must be between 500 and 30000");
        }
        if self.refresh_max_lifetime_seconds.is_some_and(|seconds| {
            !(300..=super::MAX_REFRESH_TOKEN_ABSOLUTE_TTL_SECONDS).contains(&seconds)
        }) {
            return Err(
                "OIDC refresh_max_lifetime_seconds must be between 300 and 34560000 (400 days)",
            );
        }
        Ok(())
    }
}

fn has_duplicates<T: PartialEq>(values: &[T]) -> bool {
    values
        .iter()
        .enumerate()
        .any(|(index, value)| values[..index].contains(value))
}

#[cfg(test)]
mod tests;

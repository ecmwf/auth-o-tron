// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! Settings for OpenID Connect sign-in methods offered on the browser login page.

use super::ui::{
    BROWSER_ID_MAX_LEN, BROWSER_ID_PATTERN, RESERVED_BROWSER_IDS, browser_id, browser_label,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::PathBuf};

/// Regex form of the `roles_claim` rule.
pub const ROLES_CLAIM_PATTERN: &str = r"^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+){0,3}$";

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

#[cfg(test)]
mod tests;

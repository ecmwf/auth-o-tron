// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! Configuration for the optional, application-branded login page.

use http::Uri;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Controls branding, trusted SSO links, and the shared direct-login session.
///
/// Direct browser login methods are declared by `browser` blocks on `plain`
/// and `ecmwf-api` providers.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct UiConfig {
    pub enabled: bool,
    pub branding: BrandingConfig,
    pub sso: Vec<BrowserSignInAction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub browser_session: Option<Box<BrowserSessionConfig>>,
}

/// Upper bound on direct browser methods so the chooser stays short and
/// metric label cardinality stays bounded.
pub const MAX_BROWSER_METHODS: usize = 16;
const BROWSER_LABEL_CHARS: usize = 64;
/// Upper bound on a browser method id; keeps routes, flow tags and metric labels short.
pub const BROWSER_ID_MAX_LEN: usize = 32;
/// Regex form of the browser id rule; `valid_browser_id` implements it byte-wise and
/// `src/static/login.js` embeds the same literal. Valid: `staff`; invalid: `-staff`.
pub const BROWSER_ID_PATTERN: &str = r"^[a-z0-9][a-z0-9-]{0,31}$";
/// Ids that would collide with fixed `/login/...` routes or reserved future paths.
pub const RESERVED_BROWSER_IDS: [&str; 3] = ["callback", "new", "account"];

/// Offers a `plain` or `ecmwf-api` provider as a direct browser sign-in method.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProviderBrowserConfig {
    /// Stable method id used in `/login/method/{id}`, form flow tags and the
    /// `method` metric label; unique across providers.
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
    /// Upper bound on the absolute lifetime of OAuth refresh-token families started
    /// by a login with this method; the client's `absolute_ttl_seconds` still applies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(range(min = 300, max = 34560000))]
    pub refresh_max_lifetime_seconds: Option<u64>,
}

/// Matches [`BROWSER_ID_PATTERN`] and is not a reserved id.
/// Valid: `staff`, `ecmwf-api-key`, `2fa`. Invalid: `Staff`, `-staff`, `""`,
/// `a_b`, a 33-character id, or `callback`.
pub fn valid_browser_id(id: &str) -> bool {
    let bytes = id.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= BROWSER_ID_MAX_LEN
        && bytes[0] != b'-'
        && bytes
            .iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
        && !RESERVED_BROWSER_IDS.contains(&id)
}

fn browser_id<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    let id = String::deserialize(deserializer)?;
    if !valid_browser_id(&id) {
        return Err(serde::de::Error::custom(format!(
            "provider browser id must match {BROWSER_ID_PATTERN} and not be {}",
            RESERVED_BROWSER_IDS.join(", ")
        )));
    }
    Ok(id)
}

/// Valid: `"  Staff login "` (stored as `Staff login`). Invalid: `"   "`,
/// `"Line\nbreak"`, or a label longer than 64 characters after trimming.
fn browser_label<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    let label = String::deserialize(deserializer)?;
    let label = label.trim();
    if label.is_empty()
        || label.chars().count() > BROWSER_LABEL_CHARS
        || label.chars().any(char::is_control)
    {
        return Err(serde::de::Error::custom(
            "provider browser label must be 1-64 characters after trimming, without control characters",
        ));
    }
    Ok(label.to_owned())
}

/// Credential form offered by a browser method; follows the provider type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserMethodKind {
    Basic,
    ApiKey,
}

impl BrowserMethodKind {
    /// Provider `type` value that offers this credential form.
    pub fn provider_type(self) -> &'static str {
        match self {
            Self::Basic => "plain",
            Self::ApiKey => "ecmwf-api",
        }
    }

    /// Lowercase prefix of the stored form flow tag `<prefix>:<id>`.
    pub fn tag_prefix(self) -> &'static str {
        match self {
            Self::Basic => "basic",
            Self::ApiKey => "key",
        }
    }

    /// Fixed `flow` metric label per credential type.
    pub fn metric_label(self) -> &'static str {
        match self {
            Self::Basic => "basic",
            Self::ApiKey => "ecmwf-api-key",
        }
    }
}

/// A provider offered for direct browser login, listed in `providers` order.
#[derive(Debug, Clone, Copy)]
pub enum BrowserMethodProvider<'a> {
    Plain(&'a crate::providers::plain_provider::PlainAuthConfig),
    EcmwfApi(&'a crate::providers::ecmwfapi_provider::EcmwfApiProviderConfig),
}

#[derive(Debug, Clone, Copy)]
pub struct BrowserMethodConfig<'a> {
    pub id: &'a str,
    pub label: &'a str,
    pub refresh_max_lifetime_seconds: Option<u64>,
    pub provider: BrowserMethodProvider<'a>,
}

impl BrowserMethodConfig<'_> {
    pub fn kind(&self) -> BrowserMethodKind {
        match self.provider {
            BrowserMethodProvider::Plain(_) => BrowserMethodKind::Basic,
            BrowserMethodProvider::EcmwfApi(_) => BrowserMethodKind::ApiKey,
        }
    }
}

/// Browser-enabled providers in configuration order, without validation.
pub fn browser_methods(
    providers: &[crate::providers::ProviderConfig],
) -> Vec<BrowserMethodConfig<'_>> {
    use crate::providers::ProviderConfig;
    providers
        .iter()
        .filter_map(|provider| match provider {
            ProviderConfig::Plain(config) => config.browser.as_ref().map(|b| BrowserMethodConfig {
                id: &b.id,
                label: &b.label,
                refresh_max_lifetime_seconds: b.refresh_max_lifetime_seconds,
                provider: BrowserMethodProvider::Plain(config),
            }),
            ProviderConfig::EcmwfApi(config) => {
                config.browser.as_ref().map(|b| BrowserMethodConfig {
                    id: &b.id,
                    label: &b.label,
                    refresh_max_lifetime_seconds: b.refresh_max_lifetime_seconds,
                    provider: BrowserMethodProvider::EcmwfApi(config),
                })
            }
            _ => None,
        })
        .collect()
}

/// One origin and absolute session lifetime shared by all direct login flows.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BrowserSessionConfig {
    pub public_origin: UiUrl,
    #[serde(default = "default_session_ttl")]
    #[schemars(range(min = 60, max = 86400))]
    pub session_ttl_seconds: u64,
    pub backend: BrowserBackendConfig,
    #[serde(default = "default_session_ttl")]
    #[schemars(range(min = 30, max = 900))]
    pub transaction_ttl_seconds: u64,
    #[serde(default = "default_capacity")]
    #[schemars(range(min = 1, max = 100000))]
    pub max_forms: usize,
    #[serde(default = "default_capacity")]
    #[schemars(range(min = 1, max = 100000))]
    pub max_sessions: usize,
    #[serde(default = "default_forms")]
    #[schemars(range(min = 1, max = 100000))]
    pub max_forms_per_window: usize,
    #[serde(default = "default_logins")]
    #[schemars(range(min = 1, max = 100000))]
    pub max_logins_per_window: usize,
    #[serde(default = "default_window")]
    #[schemars(range(min = 1, max = 3600))]
    pub rate_window_seconds: u64,
    #[serde(default = "default_inflight")]
    #[schemars(range(min = 1, max = 256))]
    pub max_inflight_logins: usize,
    #[serde(default)]
    #[schemars(range(min = 1, max = 65536))]
    pub max_shared_inflight_logins: Option<usize>,
    #[serde(default = "default_verification")]
    #[schemars(range(min = 1, max = 30))]
    pub verification_timeout_seconds: u64,
}

fn default_capacity() -> usize {
    1024
}
fn default_forms() -> usize {
    120
}
fn default_logins() -> usize {
    60
}
fn default_window() -> u64 {
    60
}
fn default_inflight() -> usize {
    8
}
fn default_verification() -> u64 {
    10
}
fn default_connect() -> u64 {
    2000
}
fn default_operation() -> u64 {
    1000
}

/// A single primary endpoint; Cluster and Sentinel discovery are not supported.
#[derive(Clone, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub enum BrowserBackendConfig {
    Memory {},
    Valkey {
        url: String,
        key_prefix: String,
        #[serde(skip_serializing)]
        password: String,
        #[serde(default = "default_connect")]
        #[schemars(range(min = 1, max = 30000))]
        connect_timeout_ms: u64,
        #[serde(default = "default_operation")]
        #[schemars(range(min = 1, max = 10000))]
        operation_timeout_ms: u64,
    },
}

impl std::fmt::Debug for BrowserBackendConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Memory {} => "Memory",
            Self::Valkey { .. } => "Valkey { configuration: [redacted] }",
        })
    }
}

impl BrowserSessionConfig {
    pub fn validate(&self) -> Result<(), &'static str> {
        self.origin()?;
        if self
            .max_shared_inflight_logins
            .is_some_and(|cap| !(1..=65536).contains(&cap))
        {
            return Err("invalid browser max_shared_inflight_logins");
        }
        for (value, min, max, error) in [
            (
                self.session_ttl_seconds,
                60,
                86400,
                "browser session TTL must be between 60 and 86400 seconds",
            ),
            (
                self.transaction_ttl_seconds,
                30,
                900,
                "browser transaction TTL must be between 30 and 900 seconds",
            ),
            (
                self.max_forms as u64,
                1,
                100000,
                "invalid browser max_forms",
            ),
            (
                self.max_sessions as u64,
                1,
                100000,
                "invalid browser max_sessions",
            ),
            (
                self.max_forms_per_window as u64,
                1,
                100000,
                "invalid browser max_forms_per_window",
            ),
            (
                self.max_logins_per_window as u64,
                1,
                100000,
                "invalid browser max_logins_per_window",
            ),
            (
                self.rate_window_seconds,
                1,
                3600,
                "invalid browser rate_window_seconds",
            ),
            (
                self.max_inflight_logins as u64,
                1,
                256,
                "invalid browser max_inflight_logins",
            ),
            (
                self.verification_timeout_seconds,
                1,
                30,
                "invalid browser verification_timeout_seconds",
            ),
        ] {
            if !(min..=max).contains(&value) {
                return Err(error);
            }
        }
        self.backend.validate()
    }
}

impl BrowserBackendConfig {
    /// Validate connection settings independently of browser-session policy, without I/O.
    pub(crate) fn validate(&self) -> Result<(), &'static str> {
        if let BrowserBackendConfig::Valkey {
            url,
            key_prefix,
            password,
            connect_timeout_ms,
            operation_timeout_ms,
        } = self
        {
            let parsed = url::Url::parse(url).map_err(|_| "invalid browser Valkey URL")?;
            if !matches!(parsed.scheme(), "redis" | "rediss")
                || parsed.host_str().is_none()
                || !parsed.username().is_empty()
                || parsed.password().is_some()
                || parsed.query().is_some()
                || parsed.fragment().is_some()
                || url.contains('@')
                || url.chars().any(char::is_whitespace)
                || parsed
                    .path()
                    .strip_prefix('/')
                    .is_none_or(|db| !db.is_empty() && db.parse::<u32>().is_err())
            {
                return Err(
                    "browser Valkey URL must be a redis/rediss endpoint without userinfo, query or fragment",
                );
            }
            // Valid: authotron:browser:release. Invalid: a prefix with spaces or braces.
            if key_prefix.is_empty()
                || key_prefix.len() > 128
                || !key_prefix
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b":_-".contains(&c))
            {
                return Err("invalid browser Valkey key_prefix");
            }
            if password.trim().is_empty() {
                return Err("browser Valkey password must not be empty");
            }
            if !(1..=30000).contains(connect_timeout_ms)
                || !(1..=10000).contains(operation_timeout_ms)
            {
                return Err("invalid browser Valkey timeout");
            }
        }
        Ok(())
    }
}

fn default_session_ttl() -> u64 {
    300
}

impl BrowserSessionConfig {
    /// Valid: `https://login.example.org/`. Invalid: `/login` or an HTTPS URL with a query.
    pub fn origin(&self) -> Result<String, &'static str> {
        let value = self.public_origin.as_str();
        let uri: Uri = value.parse().map_err(|_| "invalid browser public origin")?;
        let url = url::Url::parse(value).map_err(|_| "invalid browser public origin")?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || uri.path() != "/"
        {
            return Err("browser public origin must be an absolute HTTPS origin only");
        }
        Ok(url.origin().ascii_serialization())
    }
}

impl UiConfig {
    /// Validates browser methods against the session settings and returns them in
    /// chooser order. Ids must be unique so routes are unambiguous; labels must be
    /// unique ignoring case so buttons are unambiguous.
    pub fn validate_browser_login<'a>(
        &self,
        providers: &'a [crate::providers::ProviderConfig],
    ) -> Result<Vec<BrowserMethodConfig<'a>>, &'static str> {
        let methods = browser_methods(providers);
        if methods.len() > MAX_BROWSER_METHODS {
            return Err("at most 16 providers may declare a browser block");
        }
        let mut ids = std::collections::HashSet::new();
        if methods.iter().any(|method| !ids.insert(method.id)) {
            return Err("provider browser ids must be unique");
        }
        let mut labels = std::collections::HashSet::new();
        if methods
            .iter()
            .any(|method| !labels.insert(method.label.to_lowercase()))
        {
            return Err("provider browser labels must be unique (case-insensitive)");
        }
        if methods.iter().any(|method| {
            method.refresh_max_lifetime_seconds.is_some_and(|seconds| {
                !(300..=crate::config::MAX_REFRESH_TOKEN_ABSOLUTE_TTL_SECONDS).contains(&seconds)
            })
        }) {
            return Err(
                "provider browser refresh_max_lifetime_seconds must be between 300 and 34560000 (400 days)",
            );
        }
        if !methods.is_empty() && self.browser_session.is_none() {
            return Err("provider browser login requires ui.browser_session");
        }
        if let Some(settings) = &self.browser_session {
            settings.validate()?;
        }
        Ok(methods)
    }
}

/// An operator-configured entry into an application's browser login flow.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BrowserSignInAction {
    #[serde(deserialize_with = "nonempty_label")]
    pub label: String,
    pub start_url: UiUrl,
}

fn nonempty_label<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    let label = String::deserialize(deserializer)?;
    if label.trim().is_empty() {
        return Err(serde::de::Error::custom(
            "sign-in action label must not be blank",
        ));
    }
    Ok(label)
}

/// Application-owned branding; all text is rendered as escaped plain text.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(default)]
pub struct BrandingConfig {
    pub application_name: String,
    pub logo_url: Option<UiUrl>,
    pub title: Option<String>,
    pub description: Option<String>,
}

impl Default for BrandingConfig {
    fn default() -> Self {
        Self {
            application_name: "Auth-O-Tron".to_owned(),
            logo_url: None,
            title: None,
            description: None,
        }
    }
}

/// A URL for escaped UI image and navigation attributes.
///
/// HTTPS URLs and root-relative paths such as `/assets/aviso.png` are accepted.
/// Scheme-relative URLs such as `//other.example/logo.png`, script URLs such
/// as `javascript:alert(1)`, and URLs containing credentials are rejected.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(try_from = "String", into = "String")]
#[schemars(with = "String")]
pub struct UiUrl(String);

impl UiUrl {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for UiUrl {
    type Error = &'static str;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        const ERROR: &str = "UI URL must be an HTTPS URL without credentials or a root-relative path, with no whitespace or backslashes";

        if value.contains('\\') || value.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(ERROR);
        }

        let uri: Uri = value.parse().map_err(|_| ERROR)?;
        let root_relative = value.starts_with('/')
            && !value.starts_with("//")
            && uri.scheme().is_none()
            && uri.authority().is_none();
        let https = uri.scheme_str() == Some("https")
            && uri.authority().is_some_and(|authority| {
                !authority.host().is_empty() && !authority.as_str().contains('@')
            })
            // Browser URL parsing also rejects invalid ports and encoded host delimiters.
            && url::Url::parse(&value).is_ok_and(|url| {
                url.scheme() == "https"
                    && url.host_str().is_some()
                    && url.username().is_empty()
                    && url.password().is_none()
            });

        if root_relative || https {
            Ok(Self(value))
        } else {
            Err(ERROR)
        }
    }
}

impl From<UiUrl> for String {
    fn from(value: UiUrl) -> Self {
        value.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session_json() -> serde_json::Value {
        serde_json::json!({"public_origin": "https://login.example.test", "backend": {"type": "memory"}})
    }

    #[test]
    fn shared_concurrency_is_optional_and_has_explicit_bounds() {
        let parsed: BrowserSessionConfig = serde_json::from_value(session_json()).unwrap();
        assert_eq!(parsed.max_shared_inflight_logins, None);
        for (value, valid) in [
            (serde_json::Value::Null, true),
            (0.into(), false),
            (1.into(), true),
            (65536.into(), true),
            (65537.into(), false),
        ] {
            let mut json = session_json();
            json["max_shared_inflight_logins"] = value;
            assert_eq!(
                serde_json::from_value::<BrowserSessionConfig>(json)
                    .unwrap()
                    .validate()
                    .is_ok(),
                valid
            );
        }
    }

    #[test]
    fn all_browser_numeric_defaults_ranges_and_schema_agree() {
        let schema = serde_json::to_value(schemars::schema_for!(BrowserSessionConfig)).unwrap();
        let defaults = serde_json::to_value(
            serde_json::from_value::<BrowserSessionConfig>(session_json()).unwrap(),
        )
        .unwrap();
        for (field, default, min, max) in [
            ("session_ttl_seconds", 300, 60, 86400),
            ("transaction_ttl_seconds", 300, 30, 900),
            ("max_forms", 1024, 1, 100000),
            ("max_sessions", 1024, 1, 100000),
            ("max_forms_per_window", 120, 1, 100000),
            ("max_logins_per_window", 60, 1, 100000),
            ("rate_window_seconds", 60, 1, 3600),
            ("max_inflight_logins", 8, 1, 256),
            ("verification_timeout_seconds", 10, 1, 30),
        ] {
            assert_eq!(defaults[field], default);
            assert_eq!(schema["properties"][field]["default"], default);
            assert_eq!(schema["properties"][field]["minimum"], min);
            assert_eq!(schema["properties"][field]["maximum"], max);
            for (value, valid) in [(min - 1, false), (min, true), (max, true), (max + 1, false)] {
                let mut json = session_json();
                json[field] = value.into();
                let config: BrowserSessionConfig = serde_json::from_value(json).unwrap();
                assert_eq!(config.validate().is_ok(), valid, "{field}={value}");
            }
        }
        let mut missing = session_json();
        missing.as_object_mut().unwrap().remove("backend");
        assert!(serde_json::from_value::<BrowserSessionConfig>(missing).is_err());
        let mut extra = session_json();
        extra["backend"]["unexpected"] = true.into();
        assert!(serde_json::from_value::<BrowserSessionConfig>(extra).is_err());
    }

    #[test]
    fn valkey_settings_reject_unsafe_endpoints_and_redact_secrets() {
        let base = serde_json::json!({"type": "valkey", "url": "rediss://service:6379/0", "key_prefix": "authotron:browser:release", "password": "secret-fixture-no-logging"});
        let mut json = session_json();
        json["backend"] = base.clone();
        let config: BrowserSessionConfig = serde_json::from_value(json.clone()).unwrap();
        config.validate().unwrap();
        assert!(!format!("{config:?}").contains("secret-fixture"));
        assert!(
            !serde_json::to_string(&config)
                .unwrap()
                .contains("secret-fixture")
        );
        for (field, value) in [
            ("url", "redis://user:password@service/0"),
            ("url", "redis://@service/0"),
            ("url", "redis://service/0?password=secret"),
            ("url", "rediss://service/0#fragment"),
            ("url", "http://service/0"),
            ("url", "redis://service/not-a-db"),
            ("key_prefix", ""),
            ("key_prefix", "a b"),
            ("key_prefix", "a{tag}"),
            ("key_prefix", "名"),
            ("password", ""),
            ("password", "  "),
        ] {
            let mut bad = json.clone();
            bad["backend"][field] = value.into();
            assert!(
                serde_json::from_value::<BrowserSessionConfig>(bad)
                    .unwrap()
                    .validate()
                    .is_err(),
                "{field}"
            );
        }
        for (field, default, max) in [
            ("connect_timeout_ms", 2000, 30000),
            ("operation_timeout_ms", 1000, 10000),
        ] {
            let schema = serde_json::to_value(schemars::schema_for!(BrowserBackendConfig)).unwrap();
            assert_eq!(schema["oneOf"][1]["properties"][field]["default"], default);
            for (value, valid) in [(0, false), (1, true), (max, true), (max + 1, false)] {
                let mut changed = json.clone();
                changed["backend"][field] = value.into();
                assert_eq!(
                    serde_json::from_value::<BrowserSessionConfig>(changed)
                        .unwrap()
                        .validate()
                        .is_ok(),
                    valid
                );
            }
        }
        json["backend"]["key_prefix"] = "x".repeat(129).into();
        assert!(
            serde_json::from_value::<BrowserSessionConfig>(json)
                .unwrap()
                .validate()
                .is_err()
        );
    }

    fn direct_config(origin: &str, ttl: u64) -> UiConfig {
        serde_json::from_value(serde_json::json!({
            "enabled": true,
            "browser_session": { "public_origin": origin, "backend": {"type": "memory"},
                "session_ttl_seconds": ttl
            }
        }))
        .unwrap()
    }

    #[test]
    fn browser_origin_and_ttl_are_validated() {
        for origin in ["https://login.example.test", "https://login.example.test/"] {
            assert_eq!(
                direct_config(origin, 300)
                    .browser_session
                    .unwrap()
                    .origin()
                    .unwrap(),
                "https://login.example.test"
            );
        }
        for origin in [
            "/login",
            "https://login.example.test/path",
            "https://login.example.test/?q=x",
            "https://login.example.test/#fragment",
        ] {
            assert!(
                direct_config(origin, 300)
                    .browser_session
                    .unwrap()
                    .origin()
                    .is_err()
            );
        }
        for ttl in [0, 59, 86401] {
            assert!(
                direct_config("https://login.example.test", ttl)
                    .validate_browser_login(&[])
                    .unwrap_err()
                    .contains("TTL")
            );
        }
        let parsed: BrowserSessionConfig = serde_json::from_value(serde_json::json!({
            "public_origin": "https://login.example.test", "backend": {"type": "memory"}
        }))
        .unwrap();
        assert_eq!(parsed.session_ttl_seconds, 300);
    }

    fn provider(json: serde_json::Value) -> crate::providers::ProviderConfig {
        serde_json::from_value(json).unwrap()
    }

    fn plain(name: &str, label: Option<&str>) -> crate::providers::ProviderConfig {
        let mut json =
            serde_json::json!({"type": "plain", "name": name, "realm": "r", "users": []});
        if let Some(label) = label {
            json["browser"] = serde_json::json!({"id": name, "label": label});
        }
        provider(json)
    }

    #[test]
    fn browser_methods_follow_provider_order_and_require_unique_labels() {
        let ui = direct_config("https://login.example.test", 300);
        let api = provider(serde_json::json!({
            "type": "ecmwf-api", "name": "api", "realm": "ecmwf",
            "uri": "https://api.example.test/v1", "browser": {"id": "api", "label": "  API key  "}
        }));
        let api_only = provider(serde_json::json!({
            "type": "ecmwf-api", "name": "api-only", "realm": "ecmwf", "uri": "https://api.example.test/v1"
        }));
        let providers = [
            plain("a", Some("Staff")),
            api_only,
            api,
            plain("b", Some("Guests")),
        ];
        let methods = ui.validate_browser_login(&providers).unwrap();
        let summary: Vec<_> = methods.iter().map(|m| (m.id, m.label, m.kind())).collect();
        assert_eq!(
            summary,
            [
                ("a", "Staff", BrowserMethodKind::Basic),
                ("api", "API key", BrowserMethodKind::ApiKey),
                ("b", "Guests", BrowserMethodKind::Basic),
            ]
        );
        assert!(
            ui.validate_browser_login(&[plain("a", Some("Staff")), plain("a", Some("Guests"))])
                .unwrap_err()
                .contains("ids must be unique")
        );
        assert!(
            ui.validate_browser_login(&[plain("a", Some("Staff")), plain("b", Some("sTAFF"))])
                .unwrap_err()
                .contains("unique")
        );
        // Case folding is Unicode-aware, not ASCII-only.
        for (left, right) in [("Zugang Ärzte", "zugang ärzte"), ("ΣΥΝΔΕΣΗ", "Συνδεση")]
        {
            assert!(
                ui.validate_browser_login(&[plain("a", Some(left)), plain("b", Some(right))])
                    .unwrap_err()
                    .contains("unique"),
                "{left} / {right}"
            );
        }
        let many: Vec<_> = (0..=MAX_BROWSER_METHODS)
            .map(|n| plain(&n.to_string(), Some(&format!("Method {n}"))))
            .collect();
        assert!(
            ui.validate_browser_login(&many[..MAX_BROWSER_METHODS])
                .is_ok()
        );
        assert!(ui.validate_browser_login(&many).is_err());
        let mut no_session = ui.clone();
        no_session.browser_session = None;
        assert!(
            no_session
                .validate_browser_login(&[plain("a", None)])
                .unwrap()
                .is_empty()
        );
        assert!(
            no_session
                .validate_browser_login(&[plain("a", Some("Staff"))])
                .unwrap_err()
                .contains("browser_session")
        );
    }

    #[test]
    fn browser_refresh_lifetime_cap_is_optional_and_bounded() {
        let ui = direct_config("https://login.example.test", 300);
        let capped = |seconds: serde_json::Value| {
            provider(serde_json::json!({
                "type": "plain", "name": "a", "realm": "r", "users": [],
                "browser": {"id": "a", "label": "A", "refresh_max_lifetime_seconds": seconds}
            }))
        };
        let methods = [plain("a", Some("A"))];
        let methods = ui.validate_browser_login(&methods).unwrap();
        assert_eq!(methods[0].refresh_max_lifetime_seconds, None);
        for (seconds, valid) in [
            (299, false),
            (300, true),
            (2_592_000, true),
            (34_560_000, true),
            (34_560_001, false),
        ] {
            let providers = [capped(seconds.into())];
            let result = ui.validate_browser_login(&providers);
            assert_eq!(result.is_ok(), valid, "{seconds}");
            if valid {
                assert_eq!(
                    result.unwrap()[0].refresh_max_lifetime_seconds,
                    Some(seconds)
                );
            }
        }
        let schema = serde_json::to_value(schemars::schema_for!(ProviderBrowserConfig)).unwrap();
        let property = &schema["properties"]["refresh_max_lifetime_seconds"];
        assert_eq!(property["minimum"], 300);
        assert_eq!(property["maximum"], 34_560_000);
    }

    #[test]
    fn browser_labels_and_unsupported_provider_types_are_rejected() {
        for (label, valid) in [
            ("Staff".to_owned(), true),
            ("名".repeat(64), true),
            ("名".repeat(65), false),
            ("x".repeat(64), true),
            (format!("  {}  ", "x".repeat(64)), true),
            ("x".repeat(65), false),
            ("   ".to_owned(), false),
            ("Line\nbreak".to_owned(), false),
        ] {
            let json = serde_json::json!({"type": "plain", "name": "p", "realm": "r", "users": [], "browser": {"id": "p", "label": label}});
            assert_eq!(
                serde_json::from_value::<crate::providers::ProviderConfig>(json).is_ok(),
                valid,
                "{label:?}"
            );
        }
        let extra = serde_json::json!({"type": "plain", "name": "p", "realm": "r", "users": [], "browser": {"id": "p", "label": "Staff", "url": "/x"}});
        assert!(serde_json::from_value::<crate::providers::ProviderConfig>(extra).is_err());
        let missing_id = serde_json::json!({"type": "plain", "name": "p", "realm": "r", "users": [], "browser": {"label": "Staff"}});
        assert!(serde_json::from_value::<crate::providers::ProviderConfig>(missing_id).is_err());
        for (id, valid) in [
            ("staff".to_owned(), true),
            ("ecmwf-api-key".to_owned(), true),
            ("0".to_owned(), true),
            ("a".repeat(32), true),
            ("a".repeat(33), false),
            (String::new(), false),
            ("Staff".to_owned(), false),
            ("-staff".to_owned(), false),
            ("a_b".to_owned(), false),
            ("a b".to_owned(), false),
            ("callback".to_owned(), false),
            ("new".to_owned(), false),
            ("account".to_owned(), false),
        ] {
            let json = serde_json::json!({"type": "plain", "name": "p", "realm": "r", "users": [], "browser": {"id": id, "label": "Staff"}});
            assert_eq!(
                serde_json::from_value::<crate::providers::ProviderConfig>(json).is_ok(),
                valid,
                "{id:?}"
            );
        }
        let jwt = serde_json::json!({
            "type": "jwt", "name": "jwt", "cert_uri": "https://idp.example.test/certs",
            "realm": "r", "iam_realm": "r", "browser": {"id": "sso", "label": "SSO"}
        });
        let error = serde_json::from_value::<crate::providers::ProviderConfig>(jwt.clone())
            .unwrap_err()
            .to_string();
        assert!(error.contains("plain and ecmwf-api"), "{error}");
        let mut jwt_without = jwt;
        jwt_without.as_object_mut().unwrap().remove("browser");
        assert!(
            serde_json::from_value::<crate::providers::ProviderConfig>(jwt_without.clone()).is_ok()
        );
        let mut jwt_null = jwt_without;
        jwt_null["browser"] = serde_json::Value::Null;
        assert!(serde_json::from_value::<crate::providers::ProviderConfig>(jwt_null).is_ok());
        for json in [
            serde_json::json!({"type": "plain", "name": "p", "realm": "r", "users": [], "browser": null}),
            serde_json::json!({"type": "ecmwf-api", "name": "k", "realm": "r", "uri": "https://api.example.test/v1", "browser": null}),
        ] {
            let config = serde_json::from_value::<crate::providers::ProviderConfig>(json).unwrap();
            assert!(browser_methods(std::slice::from_ref(&config)).is_empty());
        }
    }

    #[test]
    fn omitted_settings_keep_ui_disabled_with_default_branding() {
        let config: UiConfig = serde_json::from_str("{}").unwrap();
        assert!(!config.enabled);
        assert_eq!(config.branding.application_name, "Auth-O-Tron");
        assert!(config.branding.logo_url.is_none());
        assert!(config.branding.title.is_none());
        assert!(config.branding.description.is_none());
        assert!(config.sso.is_empty());
    }

    #[test]
    fn partial_branding_retains_defaults() {
        let config: UiConfig = serde_json::from_str(
            r#"{"enabled": true, "branding": {"description": "Application access"}}"#,
        )
        .unwrap();
        assert!(config.enabled);
        assert_eq!(config.branding.application_name, "Auth-O-Tron");
        assert_eq!(
            config.branding.description.as_deref(),
            Some("Application access")
        );
    }

    #[test]
    fn custom_branding_round_trips_as_plain_strings() {
        let json = serde_json::json!({
            "enabled": true,
            "sso": [],
            "branding": {
                "application_name": "Aviso",
                "logo_url": "https://aviso.example.org/assets/logo.png",
                "title": "Sign in to Aviso",
                "description": "Notifications & subscriptions"
            }
        });
        let config: UiConfig = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(serde_json::to_value(config).unwrap(), json);
    }

    #[test]
    fn ui_url_accepts_https_and_root_relative_paths() {
        for value in [
            "https://aviso.example.org/assets/logo.png",
            "https://aviso.example.org:8443/logo.png",
            "https://[::1]:8443/logo.png",
            "/static/logo.png",
            "/assets/logo.png?version=2",
        ] {
            let url = UiUrl::try_from(value.to_owned()).unwrap();
            assert_eq!(url.as_str(), value);
        }
    }

    #[test]
    fn ui_url_rejects_unsafe_or_ambiguous_urls() {
        for value in [
            "",
            "logo.png",
            "//other.example/logo.png",
            "http://aviso.example.org/logo.png",
            "javascript:alert(1)",
            "data:image/svg+xml,<svg></svg>",
            "file:///etc/passwd",
            "https:/logo.png",
            "https://user:password@aviso.example.org/logo.png",
            "https://aviso.example.org:99999/logo.png",
            "https://aviso.example.org:not-a-port/logo.png",
            "https://%2faviso.example.org/logo.png",
            "https://%00aviso.example.org/logo.png",
            "/\\other.example/logo.png",
            "/assets/with space.png",
            "/assets/logo\n.png",
        ] {
            assert!(
                UiUrl::try_from(value.to_owned()).is_err(),
                "unexpectedly accepted {value:?}"
            );
        }
    }

    #[test]
    fn unsafe_logo_rejects_the_ui_configuration() {
        let result = serde_json::from_value::<UiConfig>(serde_json::json!({
            "branding": {"logo_url": "javascript:alert(1)"}
        }));
        assert!(result.is_err());
    }

    #[test]
    fn schema_browser_id_rules_match_server_validation() {
        let generated = serde_json::to_value(schemars::schema_for!(crate::config::Config)).unwrap();
        let id = &generated["$defs"]["ProviderBrowserConfig"]["properties"]["id"];
        assert_eq!(id["pattern"], BROWSER_ID_PATTERN);
        assert_eq!(id["minLength"], 1);
        assert_eq!(id["maxLength"], BROWSER_ID_MAX_LEN);
        assert_eq!(id["not"]["enum"], serde_json::json!(RESERVED_BROWSER_IDS));
        // The pattern's `{0,31}` repetition must agree with the length constant.
        assert!(BROWSER_ID_PATTERN.ends_with(&format!("{{0,{}}}$", BROWSER_ID_MAX_LEN - 1)));
        for (id, valid) in [
            ("staff", true),
            ("2fa", true),
            ("a".repeat(BROWSER_ID_MAX_LEN).as_str(), true),
            ("a".repeat(BROWSER_ID_MAX_LEN + 1).as_str(), false),
            ("-staff", false),
            ("Staff", false),
            ("a_b", false),
            ("", false),
        ] {
            assert_eq!(valid_browser_id(id), valid, "{id}");
        }
    }

    #[test]
    fn login_script_embeds_the_browser_id_pattern() {
        let script = include_str!("../static/login.js");
        // The script anchors the id after the route prefix: drop the leading `^`.
        let expected = format!("/^\\/login\\/method\\/{}/", &BROWSER_ID_PATTERN[1..]);
        assert!(script.contains(&expected), "login.js lacks {expected}");
    }

    #[test]
    fn valkey_script_bounds_browser_ids_like_the_server() {
        // Lua patterns have no `{m,n}` repetition, so the script matches the character
        // classes as `[%l%d][%l%d%-]*` (regex `[a-z0-9][a-z0-9-]*`) and enforces the
        // length separately; the longest flow tag is `basic:` plus a maximum-length id.
        let script = include_str!("../../src/browser/valkey.lua");
        assert!(script.contains("'^(%l+):([%l%d][%l%d%-]*)$'"));
        assert!(script.contains(&format!("string.len(id) > {BROWSER_ID_MAX_LEN}")));
        let flow_max = "basic:".len() + BROWSER_ID_MAX_LEN;
        assert!(script.contains(&format!("string.len(ARGV[4]) > {flow_max}")));
        assert!(script.contains(&format!("HSTRLEN', key, 'flow') > {flow_max}")));
        assert!(BROWSER_ID_PATTERN.starts_with("^[a-z0-9][a-z0-9-]{"));
    }

    #[test]
    fn checked_in_schema_matches_generated_ui_definitions() {
        let generated = serde_json::to_value(schemars::schema_for!(crate::config::Config)).unwrap();
        let checked_in: serde_json::Value =
            serde_json::from_str(include_str!("../../schema.json")).unwrap();
        for name in [
            "UiConfig",
            "BrandingConfig",
            "UiUrl",
            "BrowserSignInAction",
            "ProviderBrowserConfig",
            "BrowserSessionConfig",
            "BrowserBackendConfig",
        ] {
            assert_eq!(checked_in["$defs"][name], generated["$defs"][name]);
        }
        assert_eq!(
            checked_in["$defs"]["ConfigV2"]["properties"]["ui"],
            generated["$defs"]["ConfigV2"]["properties"]["ui"]
        );
    }

    #[test]
    fn browser_sign_in_actions_require_safe_urls_and_nonempty_labels() {
        let action = serde_json::json!({
            "label": "Continue with demo SSO",
            "start_url": "https://app.example.org/oauth2/start?rd=%2Faccount"
        });
        let parsed: BrowserSignInAction = serde_json::from_value(action.clone()).unwrap();
        assert_eq!(parsed.label, "Continue with demo SSO");
        for invalid in [
            serde_json::json!({"label": " ", "start_url": "/oauth2/start"}),
            serde_json::json!({"label": "SSO", "start_url": "javascript:alert(1)"}),
            serde_json::json!({"label": "SSO", "start_url": "//other.example"}),
            serde_json::json!({"label": "SSO", "start_url": "/oauth2/start", "redirect_uri": "https://other.example"}),
        ] {
            assert!(serde_json::from_value::<BrowserSignInAction>(invalid).is_err());
        }
    }
}

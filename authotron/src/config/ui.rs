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

/// Controls branding, trusted browser sign-in links, and optional direct login.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(default)]
pub struct UiConfig {
    pub enabled: bool,
    pub branding: BrandingConfig,
    pub sign_in_actions: Vec<BrowserSignInAction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ecmwf_api_key: Option<DirectLoginConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub basic: Option<DirectLoginConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub browser_session: Option<Box<BrowserSessionConfig>>,
}

/// Direct browser login selects one configured provider, never a submitted URL.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DirectLoginConfig {
    pub provider_name: String,
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
            // Valid: authotron:browser:v1:release. Invalid: a prefix with spaces or braces.
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
    pub fn has_direct_login(&self) -> bool {
        self.ecmwf_api_key.is_some() || self.basic.is_some()
    }

    pub fn validate_basic_login<'a>(
        &self,
        providers: &'a [crate::providers::ProviderConfig],
    ) -> Result<Option<&'a crate::providers::plain_provider::PlainAuthConfig>, &'static str> {
        let Some(settings) = &self.basic else {
            return Ok(None);
        };
        match selected_provider(providers, &settings.provider_name)? {
            crate::providers::ProviderConfig::Plain(config) => Ok(Some(config)),
            _ => Err("browser Basic provider must have type plain"),
        }
    }

    pub fn validate_browser_login<'a>(
        &self,
        providers: &'a [crate::providers::ProviderConfig],
    ) -> Result<Option<&'a crate::providers::ecmwfapi_provider::EcmwfApiProviderConfig>, &'static str>
    {
        use crate::providers::ProviderConfig;
        if self.has_direct_login() && self.browser_session.is_none() {
            return Err("direct browser login requires ui.browser_session");
        }
        if let Some(settings) = &self.browser_session {
            settings.validate()?;
        }
        self.validate_basic_login(providers)?;
        let Some(settings) = &self.ecmwf_api_key else {
            return Ok(None);
        };
        match selected_provider(providers, &settings.provider_name)? {
            ProviderConfig::EcmwfApi(config) => Ok(Some(config)),
            _ => Err("browser provider must have type ecmwf-api"),
        }
    }
}

fn selected_provider<'a>(
    providers: &'a [crate::providers::ProviderConfig],
    name: &str,
) -> Result<&'a crate::providers::ProviderConfig, &'static str> {
    use crate::providers::ProviderConfig;
    if name.trim().is_empty() {
        return Err("browser provider name must not be blank");
    }
    let mut matches = providers.iter().filter(|provider| {
        let provider_name = match provider {
            ProviderConfig::EcmwfApi(c) => &c.name,
            ProviderConfig::EcmwfTokenGenerator(c) => &c.name,
            ProviderConfig::EfasApiProvider(c) => &c.name,
            ProviderConfig::Jwt(c) => &c.name,
            ProviderConfig::OpenIDOffline(c) => &c.name,
            ProviderConfig::Plain(c) => &c.name,
        };
        provider_name == name
    });
    let selected = matches
        .next()
        .ok_or("browser provider name must match exactly one provider")?;
    if matches.next().is_some() {
        return Err("browser provider name must be unique");
    }
    Ok(selected)
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
        let base = serde_json::json!({"type": "valkey", "url": "rediss://service:6379/0", "key_prefix": "authotron:browser:v1:release", "password": "secret-fixture-no-logging"});
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
            "enabled": true, "ecmwf_api_key": {"provider_name": "ECMWF API Provider"},
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

    #[test]
    fn browser_provider_requires_unique_exact_name_and_ecmwf_type() {
        use crate::providers::ProviderConfig;
        let ui = direct_config("https://login.example.test", 300);
        let ecmwf = || {
            serde_json::from_value::<ProviderConfig>(serde_json::json!({
            "type": "ecmwf-api", "name": "ECMWF API Provider", "realm": "ecmwf", "uri": "https://api.ecmwf.int/v1"
        })).unwrap()
        };
        let plain = || {
            serde_json::from_value::<ProviderConfig>(serde_json::json!({
                "type": "plain", "name": "ECMWF API Provider", "realm": "ecmwf", "users": []
            }))
            .unwrap()
        };
        assert!(ui.validate_browser_login(&[]).is_err());
        assert!(ui.validate_browser_login(&[plain()]).is_err());
        assert!(ui.validate_browser_login(&[ecmwf(), ecmwf()]).is_err());
        assert!(ui.validate_browser_login(&[ecmwf(), plain()]).is_err());
        assert!(ui.validate_browser_login(&[ecmwf()]).unwrap().is_some());
    }

    #[test]
    fn omitted_settings_keep_ui_disabled_with_default_branding() {
        let config: UiConfig = serde_json::from_str("{}").unwrap();
        assert!(!config.enabled);
        assert_eq!(config.branding.application_name, "Auth-O-Tron");
        assert!(config.branding.logo_url.is_none());
        assert!(config.branding.title.is_none());
        assert!(config.branding.description.is_none());
        assert!(config.sign_in_actions.is_empty());
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
            "sign_in_actions": [],
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
    fn checked_in_schema_matches_generated_ui_definitions() {
        let generated = serde_json::to_value(schemars::schema_for!(crate::config::Config)).unwrap();
        let checked_in: serde_json::Value =
            serde_json::from_str(include_str!("../../schema.json")).unwrap();
        for name in [
            "UiConfig",
            "BrandingConfig",
            "UiUrl",
            "BrowserSignInAction",
            "DirectLoginConfig",
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

// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! Absolute-expiry browser state, separate from the AOT token store.
//!
//! A memory-backend restart signs users out. Key revocation is observed on the next verification;
//! an existing identity view can remain signed in until its absolute expiry.

use crate::config::{BrowserBackendConfig, BrowserSessionConfig};
use crate::{
    auth::Auth,
    metrics::Metrics,
    providers::{Provider, plain_provider::PlainAuthProvider},
};
use crate::{config::ConfigV2, models::user::User, providers::ecmwfapi_provider::EcmwfApiProvider};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime},
};
use subtle::ConstantTimeEq;
use tokio::sync::Semaphore;
use uuid::Uuid;

const CAPACITY: usize = 1024;
const FORM_LIMIT: usize = 120;
const VERIFY_LIMIT: usize = 60;
const MAX_INFLIGHT: usize = 8;
#[cfg(test)]
const RATE_WINDOW: Duration = Duration::from_secs(60);
const CLEANUP_INTERVAL: Duration = Duration::from_secs(30);
pub const FORM_TTL: u64 = 300;

const IDENTITY_TEXT_LIMIT: usize = 256;
const ROLE_COUNT_LIMIT: usize = 64;
const ROLE_BYTES_LIMIT: usize = 128;
const IDENTITY_BYTES_LIMIT: usize = 16 * 1024;
pub(crate) const DISPLAY_ATTRIBUTES: [(&str, &str, usize); 3] = [
    ("ecmwf-email", "ECMWF email", 320),
    ("email", "Email", 320),
    ("display_name", "Display name", 256),
];

/// Check borrowed data before copying only the bounded browser projection.
/// Role limits reject the whole identity, never truncate entitlements.
fn browser_identity(user: &User) -> Result<User, BrowserVerifyError> {
    if user.username.trim().is_empty()
        || user.username.chars().any(char::is_control)
        || user.username.len() > IDENTITY_TEXT_LIMIT
        || user.realm.len() > IDENTITY_TEXT_LIMIT
        || user.roles.len() > ROLE_COUNT_LIMIT
    {
        return Err(BrowserVerifyError::Rejected);
    }
    let mut bytes = user.username.len() + user.realm.len();
    for role in &user.roles {
        if role.len() > ROLE_BYTES_LIMIT {
            return Err(BrowserVerifyError::Rejected);
        }
        bytes += role.len();
    }
    for (key, _, limit) in DISPLAY_ATTRIBUTES {
        if let Some(value) = user.attributes.get(key) {
            if value.len() > limit {
                return Err(BrowserVerifyError::Rejected);
            }
            bytes += key.len() + value.len();
        }
    }
    if bytes > IDENTITY_BYTES_LIMIT {
        return Err(BrowserVerifyError::Rejected);
    }
    // New containers avoid retaining large source capacities, hidden attributes or scopes.
    Ok(User::new(
        user.realm.clone(),
        user.username.clone(),
        Some(user.roles.to_vec()),
        Some(
            DISPLAY_ATTRIBUTES
                .iter()
                .filter_map(|(key, _, _)| {
                    user.attributes
                        .get(*key)
                        .map(|value| ((*key).to_owned(), value.clone()))
                })
                .collect(),
        ),
        None,
        None,
    ))
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum LoginFlow {
    ApiKey,
    Basic,
}

impl LoginFlow {
    pub(crate) fn metric_label(self) -> &'static str {
        match self {
            Self::ApiKey => "ecmwf-api-key",
            Self::Basic => "basic",
        }
    }
}

fn valid_id(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|c| c.is_ascii_hexdigit())
}

pub enum BrowserCredentials<'a> {
    ApiKey(&'a str),
    Basic {
        username: &'a str,
        password: &'a str,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub enum BrowserVerifyError {
    Limited,
    Rejected,
    Unavailable,
    Capacity,
    Timeout,
}

// Fixed-window quotas belong to the selected backend: shared in Valkey, local in
// development memory. No credential, caller-header or per-client keys are used.
#[derive(Default)]
struct Quota {
    window: Option<Instant>,
    used: usize,
}

impl Quota {
    fn admit(&mut self, now: Instant, limit: usize, window: Duration) -> bool {
        if self
            .window
            .is_none_or(|start| now.duration_since(start) >= window)
        {
            self.window = Some(now);
            self.used = 0;
        }
        if self.used >= limit {
            return false;
        }
        self.used += 1;
        true
    }
}

struct FormTransaction {
    csrf: String,
    expires: Instant,
    flow: LoginFlow,
}

#[derive(Clone)]
pub struct BrowserSession {
    pub user: Arc<User>,
    pub expires_at: SystemTime,
    pub expires_at_utc: chrono::DateTime<chrono::Utc>,
    expires: Instant,
}

#[derive(Default)]
struct Entries {
    forms: HashMap<String, FormTransaction>,
    sessions: HashMap<String, BrowserSession>,
    forms_quota: Quota,
    verify_quota: Quota,
}

/// Only transaction metadata and verified users are retained; never credentials.
pub struct BrowserLoginState {
    entries: Mutex<Entries>,
    pub origin: Option<String>,
    pub ttl: u64,
    provider: Option<EcmwfApiProvider>,
    basic_provider: Option<PlainAuthProvider>,
    client: reqwest::Client,
    inflight: Semaphore,
    settings: Option<BrowserSessionConfig>,
}

fn opaque_id() -> String {
    // Two UUIDv4 values provide 244 random bits (version/variant bits are fixed).
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

impl Entries {
    fn cleanup(&mut self, now: Instant) {
        self.forms.retain(|_, form| form.expires > now);
        self.sessions.retain(|_, session| session.expires > now);
    }
}

impl BrowserLoginState {
    /// Validate before constructing clients or any application store.
    pub fn new(config: &ConfigV2) -> Result<Self, Box<dyn std::error::Error>> {
        let selected = config.ui.validate_browser_login(&config.providers)?;
        let basic = config.ui.validate_basic_login(&config.providers)?;
        let settings = config.ui.browser_session.as_ref();
        let origin = settings.map(|s| s.origin()).transpose()?;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(
                settings
                    .map_or(10, |s| s.verification_timeout_seconds)
                    .min(10),
            ))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self {
            entries: Mutex::new(Entries::default()),
            origin,
            ttl: settings.map_or(300, |s| s.session_ttl_seconds),
            provider: selected.map(EcmwfApiProvider::new),
            basic_provider: basic.map(PlainAuthProvider::new),
            client,
            inflight: Semaphore::new(settings.map_or(MAX_INFLIGHT, |s| {
                if matches!(s.backend, BrowserBackendConfig::Memory {}) {
                    s.max_inflight_logins.min(
                        s.max_shared_inflight_logins
                            .unwrap_or(s.max_inflight_logins),
                    )
                } else {
                    s.max_inflight_logins
                }
            })),
            settings: settings.map(|s| (**s).clone()),
        })
    }

    pub async fn initialize(&mut self, enabled: bool) -> Result<(), &'static str> {
        if enabled {
            self.require_memory()
                .map_err(|_| "browser backend is not available")?;
        }
        Ok(())
    }

    fn require_memory(&self) -> Result<(), BrowserVerifyError> {
        match self.settings.as_ref().map(|s| &s.backend) {
            Some(BrowserBackendConfig::Memory {}) => Ok(()),
            _ => Err(BrowserVerifyError::Unavailable),
        }
    }

    pub fn transaction_ttl(&self) -> u64 {
        self.settings
            .as_ref()
            .map_or(FORM_TTL, |s| s.transaction_ttl_seconds)
    }
    fn window(&self) -> Duration {
        Duration::from_secs(self.settings.as_ref().map_or(60, |s| s.rate_window_seconds))
    }

    pub async fn form(&self, flow: LoginFlow) -> Result<(String, String), BrowserVerifyError> {
        self.require_memory()?;
        {
            let mut entries = self
                .entries
                .lock()
                .map_err(|_| BrowserVerifyError::Unavailable)?;
            let now = Instant::now();
            entries.cleanup(now);
            if entries.forms.len() >= self.settings.as_ref().map_or(CAPACITY, |s| s.max_forms) {
                return Err(BrowserVerifyError::Capacity);
            }
            if !entries.forms_quota.admit(
                now,
                self.settings
                    .as_ref()
                    .map_or(FORM_LIMIT, |s| s.max_forms_per_window),
                self.window(),
            ) {
                return Err(BrowserVerifyError::Limited);
            }
            let sid = opaque_id();
            let csrf = opaque_id();
            entries.forms.insert(
                sid.clone(),
                FormTransaction {
                    csrf: csrf.clone(),
                    flow,
                    expires: now + Duration::from_secs(self.transaction_ttl()),
                },
            );
            Ok((sid, csrf))
        }
    }

    pub async fn consume(
        &self,
        sid: &str,
        csrf: &str,
        flow: LoginFlow,
    ) -> Result<bool, BrowserVerifyError> {
        if !valid_id(sid) || !valid_id(csrf) {
            return Ok(false);
        }
        self.require_memory()?;
        self.consume_form_for(sid, csrf, flow)
    }

    pub async fn discard(&self, sid: &str) -> Result<(), BrowserVerifyError> {
        if !valid_id(sid) {
            return Ok(());
        }
        self.require_memory()?;
        {
            self.discard_form(sid)?;
        }
        Ok(())
    }

    pub async fn save_session(
        &self,
        user: User,
        previous: Option<&str>,
    ) -> Result<String, BrowserVerifyError> {
        let user = browser_identity(&user)?;
        let previous = previous.filter(|id| valid_id(id));
        self.require_memory()?;
        self.memory_save_session(user, previous)
    }

    pub async fn lookup(&self, sid: &str) -> Result<Option<BrowserSession>, BrowserVerifyError> {
        if !valid_id(sid) {
            return Ok(None);
        }
        self.require_memory()?;
        self.memory_session(sid)
    }

    #[cfg(test)]
    fn create_form(&self) -> Option<(String, String)> {
        self.create_form_for(LoginFlow::ApiKey)
    }

    #[cfg(test)]
    fn create_form_for(&self, flow: LoginFlow) -> Option<(String, String)> {
        let mut entries = self.entries.lock().ok()?;
        let now = Instant::now();
        entries.cleanup(now);
        if entries.forms.len() >= self.settings.as_ref().map_or(CAPACITY, |s| s.max_forms)
            || !entries.forms_quota.admit(
                now,
                self.settings
                    .as_ref()
                    .map_or(FORM_LIMIT, |s| s.max_forms_per_window),
                self.window(),
            )
        {
            return None;
        }
        let sid = opaque_id();
        let csrf = opaque_id();
        entries.forms.insert(
            sid.clone(),
            FormTransaction {
                csrf: csrf.clone(),
                expires: now + Duration::from_secs(self.transaction_ttl()),
                flow,
            },
        );
        Some((sid, csrf))
    }

    /// Removal under one lock makes replay and concurrent submission one-use.
    #[cfg(test)]
    fn consume_form(&self, sid: &str, csrf: &str) -> bool {
        self.consume_form_for(sid, csrf, LoginFlow::ApiKey).unwrap()
    }

    fn consume_form_for(
        &self,
        sid: &str,
        csrf: &str,
        flow: LoginFlow,
    ) -> Result<bool, BrowserVerifyError> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| BrowserVerifyError::Unavailable)?;
        entries.cleanup(Instant::now());
        let matches = entries.forms.get(sid).is_some_and(|form| {
            form.flow == flow && bool::from(form.csrf.as_bytes().ct_eq(csrf.as_bytes()))
        });
        if matches {
            entries.forms.remove(sid);
        }
        Ok(matches)
    }

    /// Burn malformed same-origin submissions after the route has checked Origin.
    fn discard_form(&self, sid: &str) -> Result<(), BrowserVerifyError> {
        self.entries
            .lock()
            .map_err(|_| BrowserVerifyError::Unavailable)?
            .forms
            .remove(sid);
        Ok(())
    }

    #[cfg(test)]
    async fn admitted(
        &self,
        operation: impl std::future::Future<Output = Result<User, BrowserVerifyError>>,
    ) -> Result<User, BrowserVerifyError> {
        self.admitted_with_metrics(operation, None).await
    }

    /// Local-first, nonblocking admission bounds pending backend requests as well
    /// as provider work. Only locally admitted attempts spend backend quota.
    async fn admitted_with_metrics(
        &self,
        operation: impl std::future::Future<Output = Result<User, BrowserVerifyError>>,
        metrics: Option<&Metrics>,
    ) -> Result<User, BrowserVerifyError> {
        let _permit = self
            .inflight
            .try_acquire()
            .map_err(|_| BrowserVerifyError::Limited)?;
        let _active = metrics.map(Metrics::browser_inflight_guard);
        // Admission time is part of the deadline, so a delayed lease response cannot
        // start a fresh verification deadline after the shared lease has aged.
        let deadline = tokio::time::Instant::now()
            + Duration::from_secs(
                self.settings
                    .as_ref()
                    .map_or(10, |s| s.verification_timeout_seconds),
            );
        self.require_memory()?;
        {
            let mut entries = self
                .entries
                .lock()
                .map_err(|_| BrowserVerifyError::Unavailable)?;
            if !entries.verify_quota.admit(
                Instant::now(),
                self.settings
                    .as_ref()
                    .map_or(VERIFY_LIMIT, |s| s.max_logins_per_window),
                self.window(),
            ) {
                return Err(BrowserVerifyError::Limited);
            }
        }
        let result = tokio::time::timeout_at(deadline, operation)
            .await
            .unwrap_or(Err(BrowserVerifyError::Timeout));
        result
    }

    #[cfg(test)]
    async fn verify(&self, key: &str) -> Result<User, BrowserVerifyError> {
        self.admitted(self.verify_key(key)).await
    }

    pub async fn verify_identity(
        &self,
        credentials: BrowserCredentials<'_>,
        auth: &Auth,
        metrics: &Metrics,
    ) -> Result<User, BrowserVerifyError> {
        self.admitted_with_metrics(
            async {
                let user = match credentials {
                    BrowserCredentials::ApiKey(key) => {
                        let key = validated_key(key).ok_or(BrowserVerifyError::Rejected)?;
                        self.verify_key(key).await?
                    }
                    BrowserCredentials::Basic { username, password } => {
                        if username.is_empty()
                            || username.len() > 256
                            || username.contains(':')
                            || username.chars().any(char::is_control)
                            || password.is_empty()
                            || password.len() > 1024
                        {
                            return Err(BrowserVerifyError::Rejected);
                        }
                        let encoded = STANDARD.encode(format!("{username}:{password}"));
                        self.basic_provider
                            .as_ref()
                            .ok_or(BrowserVerifyError::Rejected)?
                            .authenticate(&encoded)
                            .await
                            .map_err(|_| BrowserVerifyError::Rejected)?
                    }
                };
                let user = auth
                    .check_augmenters(user, metrics)
                    .await
                    .ok_or(BrowserVerifyError::Rejected)?;
                browser_identity(&user)
            },
            Some(metrics),
        )
        .await
    }

    async fn verify_key(&self, key: &str) -> Result<User, BrowserVerifyError> {
        let user = self
            .provider
            .as_ref()
            .ok_or(BrowserVerifyError::Rejected)?
            .authenticate_uncached(&self.client, key)
            .await
            .map_err(|_| BrowserVerifyError::Rejected)?;
        // Treat an upstream credential echo as an invalid identity, not profile data.
        if user.username.contains(key) || user.attributes.values().any(|value| value.contains(key))
        {
            return Err(BrowserVerifyError::Rejected);
        }
        Ok(user)
    }

    pub(crate) fn cleanup(&self) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.cleanup(Instant::now());
        }
    }

    pub(crate) fn start_cleanup_task(self: &Arc<Self>) {
        self.cleanup_task(CLEANUP_INTERVAL);
    }

    fn cleanup_task(self: &Arc<Self>, period: Duration) -> tokio::task::JoinHandle<()> {
        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(period);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                let Some(state) = weak.upgrade() else {
                    break;
                };
                state.cleanup();
            }
        })
    }

    fn memory_save_session(
        &self,
        user: User,
        previous: Option<&str>,
    ) -> Result<String, BrowserVerifyError> {
        // Enforce the invariant even for internal callers bypassing direct verification.
        let user = Arc::new(browser_identity(&user)?);
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| BrowserVerifyError::Unavailable)?;
        let now = Instant::now();
        entries.cleanup(now);
        let replacing = previous.is_some_and(|id| entries.sessions.contains_key(id));
        if entries.sessions.len() - usize::from(replacing)
            >= self.settings.as_ref().map_or(CAPACITY, |s| s.max_sessions)
        {
            return Err(BrowserVerifyError::Capacity);
        }
        if let Some(previous) = previous {
            entries.sessions.remove(previous);
        }
        let sid = opaque_id();
        let duration = Duration::from_secs(self.ttl);
        entries.sessions.insert(
            sid.clone(),
            BrowserSession {
                user,
                expires: now + duration,
                expires_at: SystemTime::now() + duration,
                expires_at_utc: chrono::Utc::now() + chrono::Duration::seconds(self.ttl as i64),
            },
        );
        Ok(sid)
    }

    fn memory_session(&self, sid: &str) -> Result<Option<BrowserSession>, BrowserVerifyError> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| BrowserVerifyError::Unavailable)?;
        entries.cleanup(Instant::now());
        Ok(entries.sessions.get(sid).cloned())
    }

    #[cfg(test)]
    fn create_session(&self, user: User, previous: Option<&str>) -> Option<String> {
        self.memory_save_session(user, previous).ok()
    }

    #[cfg(test)]
    fn session(&self, sid: &str) -> Option<BrowserSession> {
        self.memory_session(sid).unwrap()
    }
}

/// Valid: ` public&fixture ` (outer whitespace removed). Invalid: `public fixture`.
pub fn validated_key(value: &str) -> Option<&str> {
    let key = value.trim();
    (!key.is_empty()
        && key.len() <= 512
        && !value.chars().any(char::is_control)
        && !key.chars().any(char::is_whitespace))
    .then_some(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn maximum_identity() -> User {
        User::new(
            "r".repeat(256),
            "u".repeat(256),
            Some(vec!["x".repeat(128); 64]),
            Some(HashMap::from([
                ("ecmwf-email".into(), "e".repeat(320)),
                ("email".into(), "e".repeat(320)),
                ("display_name".into(), "名".repeat(85) + "x"),
            ])),
            None,
            None,
        )
    }

    #[test]
    fn browser_projection_accepts_exact_byte_limits_and_discards_hidden_data() {
        let mut user = maximum_identity();
        user.attributes
            .insert("secret".into(), "s".repeat(128 * 1024));
        user.scopes
            .insert("hidden-service".into(), vec!["s".repeat(128 * 1024)]);
        let projection = browser_identity(&user).unwrap();
        assert_eq!(projection.username.len(), 256);
        assert_eq!(projection.realm.len(), 256);
        assert_eq!(projection.roles.len(), 64);
        assert_eq!(projection.attributes.len(), 3);
        assert_eq!(projection.attributes["display_name"].len(), 256);
        assert!(projection.scopes.is_empty());
        let bytes = projection.username.len()
            + projection.realm.len()
            + projection.roles.iter().map(String::len).sum::<usize>()
            + projection
                .attributes
                .iter()
                .map(|(k, v)| k.len() + v.len())
                .sum::<usize>();
        assert_eq!(bytes, 9628);
        assert!(bytes <= IDENTITY_BYTES_LIMIT);
        let mut text = maximum_identity();
        text.username = " alice 名 ".into();
        assert_eq!(browser_identity(&text).unwrap().username, " alice 名 ");
        for invalid in [" ", "alice\n"] {
            text.username = invalid.into();
            assert!(matches!(
                browser_identity(&text),
                Err(BrowserVerifyError::Rejected)
            ));
        }
    }

    #[test]
    fn session_constructor_rejects_oversize_without_rotating_previous_session() {
        let state = state();
        let previous = state.create_session(maximum_identity(), None).unwrap();
        for field in [
            "username",
            "realm",
            "role-count",
            "role-bytes",
            "ecmwf-email",
            "email",
            "display_name",
        ] {
            let mut user = maximum_identity();
            match field {
                "username" => user.username.push('x'),
                "realm" => user.realm.push('x'),
                "role-count" => user.roles.push("extra".into()),
                "role-bytes" => user.roles[0].push('x'),
                key => {
                    user.attributes.get_mut(key).unwrap().push('x');
                }
            }
            assert!(
                state.create_session(user, Some(&previous)).is_none(),
                "{field}"
            );
            assert!(state.session(&previous).is_some());
        }
        assert_eq!(state.entries.lock().unwrap().sessions.len(), 1);
    }

    #[test]
    fn session_constructor_projects_and_session_reads_share_identity() {
        let state = state();
        let mut user = maximum_identity();
        user.attributes.insert("secret".into(), "hidden".into());
        user.scopes.insert("service".into(), vec!["hidden".into()]);
        let sid = state.create_session(user, None).unwrap();
        let a = state.session(&sid).unwrap();
        let b = state.session(&sid).unwrap();
        assert!(Arc::ptr_eq(&a.user, &b.user));
        assert!(!a.user.attributes.contains_key("secret"));
        assert!(a.user.scopes.is_empty());
    }

    fn state() -> BrowserLoginState {
        BrowserLoginState {
            entries: Mutex::new(Entries::default()),
            origin: Some("https://login.example.test".into()),
            ttl: 300,
            provider: None,
            basic_provider: None,
            client: reqwest::Client::new(),
            inflight: Semaphore::new(MAX_INFLIGHT),
            settings: Some(serde_json::from_value(serde_json::json!({"public_origin": "https://login.example.test", "backend": {"type": "memory"}})).unwrap()),
        }
    }

    fn configured_state(uri: &str) -> BrowserLoginState {
        let config: ConfigV2 = serde_json::from_value(serde_json::json!({
            "store": {"enabled": false}, "services": [], "augmenters": [],
            "providers": [{"type": "ecmwf-api", "name": "public-provider", "realm": "ecmwf", "uri": uri}],
            "server": {"port": 0}, "jwt": {"iss": "public-test", "exp": 300, "secret": "public-test-only-secret"},
            "logging": {"level": "warn", "format": "console"},
            "ui": {"enabled": true, "ecmwf_api_key": {"provider_name": "public-provider"}, "browser_session": {"public_origin": "https://login.example.test", "backend": {"type": "memory"}}}
        })).unwrap();
        BrowserLoginState::new(&config).unwrap()
    }

    #[test]
    fn key_validation_trims_only_outer_spaces_and_accepts_query_metacharacters() {
        assert_eq!(
            validated_key(" public&+#=?fixture "),
            Some("public&+#=?fixture")
        );
        for key in [
            "",
            " ",
            "public fixture",
            "public\nfixture",
            "\tpublic",
            "public\u{7f}",
        ] {
            assert!(validated_key(key).is_none());
        }
        assert!(validated_key(&"x".repeat(513)).is_none());
    }

    #[test]
    fn transactions_are_bound_one_use_and_expire() {
        let state = state();
        let (sid, csrf) = state.create_form().unwrap();
        assert!(!state.consume_form("wrong-cookie", &csrf));
        assert!(state.consume_form(&sid, &csrf));
        assert!(!state.consume_form(&sid, &csrf));
        let (sid, csrf) = state.create_form().unwrap();
        assert!(!state.consume_form(&sid, "wrong-csrf"));
        assert!(!state.consume_form(&sid, ""));
        assert!(state.consume_form(&sid, &csrf));
        let (sid, csrf) = state.create_form().unwrap();
        state
            .entries
            .lock()
            .unwrap()
            .forms
            .get_mut(&sid)
            .unwrap()
            .expires = Instant::now();
        assert!(!state.consume_form(&sid, &csrf));
    }

    #[test]
    fn sessions_expire_rotate_and_do_not_refresh() {
        let state = state();
        let user = User::new("ecmwf".into(), "public-user".into(), None, None, None, None);
        let sid = state.create_session(user.clone(), None).unwrap();
        let expiry = state.session(&sid).unwrap().expires_at;
        assert_eq!(state.session(&sid).unwrap().expires_at, expiry);
        let rotated = state.create_session(user, Some(&sid)).unwrap();
        assert_ne!(sid, rotated);
        assert!(state.session(&sid).is_none());
        state
            .entries
            .lock()
            .unwrap()
            .sessions
            .get_mut(&rotated)
            .unwrap()
            .expires = Instant::now();
        assert!(state.session(&rotated).is_none());
    }

    #[test]
    fn bounded_forms_and_sessions_reclaim_expired_entries() {
        let state = state();
        for _ in 0..CAPACITY {
            state.entries.lock().unwrap().forms.insert(
                opaque_id(),
                FormTransaction {
                    csrf: opaque_id(),
                    expires: Instant::now() + Duration::from_secs(FORM_TTL),
                    flow: LoginFlow::ApiKey,
                },
            );
        }
        assert!(state.create_form().is_none());
        for form in state.entries.lock().unwrap().forms.values_mut() {
            form.expires = Instant::now();
        }
        assert!(state.create_form().is_some());
        let user = User::new("ecmwf".into(), "public-user".into(), None, None, None, None);
        for _ in 0..CAPACITY {
            assert!(state.create_session(user.clone(), None).is_some());
        }
        assert!(state.create_session(user.clone(), None).is_none());
        for session in state.entries.lock().unwrap().sessions.values_mut() {
            session.expires = Instant::now();
        }
        assert!(state.create_session(user, None).is_some());
    }

    #[test]
    fn form_flood_is_bounded_and_window_reclaims_admission() {
        let state = state();
        for _ in 0..FORM_LIMIT {
            let (sid, csrf) = state.create_form().unwrap();
            assert!(state.consume_form(&sid, &csrf));
        }
        for _ in 0..10_000 {
            assert!(state.create_form().is_none());
        }
        let mut entries = state.entries.lock().unwrap();
        assert!(entries.forms.is_empty());
        assert_eq!(entries.forms_quota.used, FORM_LIMIT);
        entries.forms_quota.window = Some(Instant::now() - RATE_WINDOW);
        drop(entries);
        assert!(state.create_form().is_some());
    }

    #[tokio::test]
    async fn verification_quota_and_concurrency_reject_before_upstream() {
        use crate::providers::ecmwfapi_provider::EcmwfApiProviderConfig;
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/who-am-i")
            .match_query(mockito::Matcher::Any)
            .with_body(r#"{"uid":"public-user"}"#)
            .expect(VERIFY_LIMIT + 1)
            .create_async()
            .await;
        let mut state = state();
        state.provider = Some(EcmwfApiProvider::new(&EcmwfApiProviderConfig {
            uri: server.url(),
            realm: "ecmwf".into(),
            name: "public-provider".into(),
        }));
        let permits = state
            .inflight
            .try_acquire_many(MAX_INFLIGHT as u32)
            .unwrap();
        assert!(state.verify("public-fixture-key").await.is_err());
        assert_eq!(state.entries.lock().unwrap().verify_quota.used, 0);
        drop(permits);
        state.entries.lock().unwrap().verify_quota = Quota::default();
        for _ in 0..VERIFY_LIMIT {
            assert!(state.verify("public-fixture-key").await.is_ok());
        }
        for n in 0..1000 {
            assert!(
                state
                    .verify(&format!("public-other-key-{n}"))
                    .await
                    .is_err()
            );
        }
        assert_eq!(
            state.entries.lock().unwrap().verify_quota.used,
            VERIFY_LIMIT
        );
        state.entries.lock().unwrap().verify_quota.window = Some(Instant::now() - RATE_WINDOW);
        assert!(state.verify("public-fixture-key").await.is_ok());
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn idle_cleanup_reclaims_identities_and_task_stops_after_drop() {
        let state = Arc::new(state());
        state.create_form().unwrap();
        state
            .create_session(
                User::new("ecmwf".into(), "public-user".into(), None, None, None, None),
                None,
            )
            .unwrap();
        {
            let mut entries = state.entries.lock().unwrap();
            for form in entries.forms.values_mut() {
                form.expires = Instant::now();
            }
            for session in entries.sessions.values_mut() {
                session.expires = Instant::now();
            }
        }
        let task = state.cleanup_task(Duration::from_millis(10));
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                {
                    let entries = state.entries.lock().unwrap();
                    if entries.forms.is_empty() && entries.sessions.is_empty() {
                        break;
                    }
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let weak = Arc::downgrade(&state);
        drop(state);
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();
        assert!(weak.upgrade().is_none());
    }

    #[tokio::test]
    async fn failed_verifications_also_spend_quota_without_retaining_keys() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/who-am-i")
            .match_query(mockito::Matcher::Any)
            .with_status(403)
            .expect(VERIFY_LIMIT)
            .create_async()
            .await;
        let state = configured_state(&server.url());
        for n in 0..VERIFY_LIMIT + 100 {
            assert!(
                state
                    .verify(&format!("public-rejected-key-{n}"))
                    .await
                    .is_err()
            );
        }
        {
            let entries = state.entries.lock().unwrap();
            assert_eq!(entries.verify_quota.used, VERIFY_LIMIT);
            assert!(entries.forms.is_empty());
            assert!(entries.sessions.is_empty());
        }
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn concurrent_verification_never_queues_excess_requests() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/who-am-i")
            .match_query(mockito::Matcher::Any)
            .with_chunked_body(|writer| {
                std::thread::sleep(Duration::from_millis(100));
                writer.write_all(br#"{"uid":"public-user"}"#)
            })
            .expect(MAX_INFLIGHT)
            .create_async()
            .await;
        let state = Arc::new(configured_state(&server.url()));
        let mut tasks = Vec::new();
        for _ in 0..MAX_INFLIGHT {
            let state = state.clone();
            tasks.push(tokio::spawn(async move {
                state.verify("public-fixture-key").await
            }));
        }
        tokio::time::timeout(Duration::from_secs(1), async {
            while state.inflight.available_permits() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(state.verify("public-rejected-key").await.is_err());
        for task in tasks {
            assert!(task.await.unwrap().is_ok());
        }
        assert_eq!(state.inflight.available_permits(), MAX_INFLIGHT);
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn browser_client_refuses_redirects() {
        let mut server = mockito::Server::new_async().await;
        let destination = server
            .mock("GET", "/redirected")
            .match_query(mockito::Matcher::Any)
            .expect(0)
            .create_async()
            .await;
        let redirect = server
            .mock("GET", "/who-am-i")
            .match_query(mockito::Matcher::Any)
            .with_status(302)
            .with_header("location", &format!("{}/redirected", server.url()))
            .create_async()
            .await;
        assert!(
            configured_state(&server.url())
                .verify("public-fixture-key")
                .await
                .is_err()
        );
        redirect.assert_async().await;
        destination.assert_async().await;
    }

    #[tokio::test]
    async fn browser_client_times_out_and_releases_admission() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/who-am-i")
            .match_query(mockito::Matcher::Any)
            .with_chunked_body(|writer| {
                std::thread::sleep(Duration::from_secs(11));
                writer.write_all(br#"{"uid":"public-user"}"#)
            })
            .create_async()
            .await;
        let state = configured_state(&server.url());
        let started = Instant::now();
        let result =
            tokio::time::timeout(Duration::from_secs(12), state.verify("public-fixture-key"))
                .await
                .unwrap();
        assert!(result.is_err());
        assert!(started.elapsed() >= Duration::from_secs(9));
        assert_eq!(state.inflight.available_permits(), MAX_INFLIGHT);
        mock.assert_async().await;
    }
}

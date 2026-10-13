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

use crate::{
    auth::Auth,
    metrics::Metrics,
    oidc::method::OidcMethod,
    providers::{Provider, plain_provider::PlainAuthProvider},
};
use crate::{config::ConfigV2, models::user::User, providers::ecmwfapi_provider::EcmwfApiProvider};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime},
};
use subtle::ConstantTimeEq;
use tokio::sync::Semaphore;
use uuid::Uuid;
mod valkey;
use crate::config::{
    BrowserBackendConfig, BrowserMethodKind, BrowserMethodProvider, BrowserSessionConfig,
};

const CAPACITY: usize = 1024;
const FORM_LIMIT: usize = 120;
const VERIFY_LIMIT: usize = 60;
const MAX_INFLIGHT: usize = 8;
#[cfg(test)]
const RATE_WINDOW: Duration = Duration::from_secs(60);
const CLEANUP_INTERVAL: Duration = Duration::from_secs(30);
const OIDC_DISCOVERY_INTERVAL: Duration = Duration::from_secs(60);
pub const FORM_TTL: u64 = 300;

const IDENTITY_TEXT_LIMIT: usize = 256;
const ROLE_COUNT_LIMIT: usize = 64;
const ROLE_BYTES_LIMIT: usize = 128;
const IDENTITY_BYTES_LIMIT: usize = 16 * 1024;
const SESSION_WIRE_BYTES_LIMIT: usize = 65536;
const SESSION_ENVELOPE_BYTES_RESERVE: usize = 36;
pub(crate) const DISPLAY_ATTRIBUTES: [(&str, &str, usize); 3] = [
    ("ecmwf-email", "ECMWF email", 320),
    ("email", "Email", 320),
    ("display_name", "Display name", 256),
];

/// The wire payload accepts only the browser projection, never arbitrary User fields.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredIdentity {
    version: u8,
    username: String,
    realm: String,
    roles: Vec<String>,
    attributes: HashMap<String, String>,
}

impl StoredIdentity {
    fn from_user(user: User) -> Self {
        Self {
            version: 1,
            username: user.username,
            realm: user.realm,
            roles: user.roles,
            attributes: user.attributes,
        }
    }
    fn into_user(self) -> Result<User, BrowserVerifyError> {
        if self.version != 1 {
            return Err(BrowserVerifyError::Unavailable);
        }
        Ok(User::new(
            self.realm,
            self.username,
            Some(self.roles),
            Some(self.attributes),
            None,
            None,
        ))
    }
}

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

/// A form transaction binds both the browser method id and its credential
/// type, so a form issued for one method cannot be consumed by another.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LoginFlow {
    /// Configured `browser.id`, stable across provider reordering and relabelling.
    pub method: Arc<str>,
    pub kind: BrowserMethodKind,
}

impl LoginFlow {
    #[cfg(test)]
    pub fn basic(method: &str) -> Self {
        Self {
            method: method.into(),
            kind: BrowserMethodKind::Basic,
        }
    }
    #[cfg(test)]
    pub fn api_key(method: &str) -> Self {
        Self {
            method: method.into(),
            kind: BrowserMethodKind::ApiKey,
        }
    }
    #[cfg(test)]
    pub fn oidc(method: &str) -> Self {
        Self {
            method: method.into(),
            kind: BrowserMethodKind::Oidc,
        }
    }
    /// Fixed `flow` metric label per credential type.
    pub(crate) fn metric_label(&self) -> &'static str {
        self.kind.metric_label()
    }
    /// Stored transaction tag `<kind>:<id>`, at most 38 bytes for a 32-byte id.
    /// Valid: `basic:password`, `key:ecmwf-api-key`, `oidc:demo-sso`. Invalid:
    /// `api-key:password`, `basic:Password`, `basic:-x`.
    fn tag(&self) -> String {
        format!("{}:{}", self.kind.tag_prefix(), self.method)
    }
}

enum MethodVerifier {
    Plain(PlainAuthProvider),
    EcmwfApi(EcmwfApiProvider),
    Oidc(Arc<OidcMethod>),
}

/// One direct browser method, verified only by its own provider instance.
pub struct BrowserMethod {
    pub label: String,
    pub flow: LoginFlow,
    pub refresh_max_lifetime_seconds: Option<u64>,
    verifier: MethodVerifier,
}

impl BrowserMethod {
    /// See [`Provider::account_still_exists`]; used where no credentials are presented.
    pub fn account_still_exists(&self, username: &str) -> Option<bool> {
        match &self.verifier {
            MethodVerifier::Plain(provider) => provider.account_still_exists(username),
            MethodVerifier::EcmwfApi(provider) => provider.account_still_exists(username),
            MethodVerifier::Oidc(_) => None,
        }
    }

    /// The provider client of an OpenID Connect method.
    pub fn oidc(&self) -> Option<&Arc<OidcMethod>> {
        match &self.verifier {
            MethodVerifier::Oidc(method) => Some(method),
            _ => None,
        }
    }
}

pub(crate) fn valid_id(value: &str) -> bool {
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
    methods: Vec<BrowserMethod>,
    client: reqwest::Client,
    inflight: Semaphore,
    settings: Option<BrowserSessionConfig>,
    valkey: Option<valkey::Valkey>,
}

pub(crate) fn opaque_id() -> String {
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
        let validated = config.ui.validate_browser_login(&config.providers)?;
        let settings = config.ui.browser_session.as_ref();
        let origin = settings.map(|s| s.origin()).transpose()?;
        let methods = validated
            .into_iter()
            .map(|method| {
                Ok(BrowserMethod {
                    label: method.label.to_owned(),
                    flow: LoginFlow {
                        method: method.id.into(),
                        kind: method.kind(),
                    },
                    refresh_max_lifetime_seconds: method.refresh_max_lifetime_seconds,
                    verifier: match method.provider {
                        BrowserMethodProvider::Plain(c) => {
                            MethodVerifier::Plain(PlainAuthProvider::new(c))
                        }
                        BrowserMethodProvider::EcmwfApi(c) => {
                            MethodVerifier::EcmwfApi(EcmwfApiProvider::new(c))
                        }
                        // Validation guarantees a browser session, hence an origin.
                        BrowserMethodProvider::Oidc(c) => MethodVerifier::Oidc(Arc::new(
                            OidcMethod::new(c, origin.as_deref().unwrap_or_default())?,
                        )),
                    },
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
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
            methods,
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
            valkey: None,
        })
    }

    /// Direct browser methods in chooser order.
    pub fn methods(&self) -> &[BrowserMethod] {
        &self.methods
    }

    /// Looks up a configured method by its exact `browser.id`.
    pub fn method(&self, id: &str) -> Option<&BrowserMethod> {
        self.methods
            .iter()
            .find(|method| &*method.flow.method == id)
    }

    pub async fn initialize(&mut self, enabled: bool) -> Result<(), &'static str> {
        if enabled
            && let Some(settings) = &self.settings
            && matches!(settings.backend, BrowserBackendConfig::Valkey { .. })
        {
            self.valkey = Some(
                valkey::Valkey::connect(&settings.backend)
                    .await
                    .map_err(|_| "browser Valkey startup failed (connection or authentication)")?,
            );
        }
        Ok(())
    }

    fn shared(&self) -> Result<Option<&valkey::Valkey>, BrowserVerifyError> {
        match self.settings.as_ref().map(|s| &s.backend) {
            Some(BrowserBackendConfig::Memory {}) => Ok(None),
            Some(BrowserBackendConfig::Valkey { .. }) => self
                .valkey
                .as_ref()
                .map(Some)
                .ok_or(BrowserVerifyError::Unavailable),
            None => Err(BrowserVerifyError::Unavailable),
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

    /// Unbound transaction for backend unit tests; production forms always carry a nonce.
    #[cfg(test)]
    pub async fn form(&self, flow: &LoginFlow) -> Result<(String, String), BrowserVerifyError> {
        self.create_transaction(flow, None).await
    }

    /// Creates a transaction tied to the form-nonce cookie and returns the combined
    /// CSRF token in the format parsed by [`split_form_token`].
    pub(crate) async fn form_with_nonce(
        &self,
        flow: &LoginFlow,
        form_nonce: &str,
    ) -> Result<String, BrowserVerifyError> {
        let (sid, challenge) = self.create_transaction(flow, Some(form_nonce)).await?;
        Ok(format!("{sid}.{challenge}"))
    }

    async fn create_transaction(
        &self,
        flow: &LoginFlow,
        form_nonce: Option<&str>,
    ) -> Result<(String, String), BrowserVerifyError> {
        let csrf = opaque_id();
        let stored_csrf =
            form_nonce.map_or_else(|| csrf.clone(), |form_nonce| nonce_csrf(form_nonce, &csrf));
        if let Some(backend) = self.shared()? {
            let s = self
                .settings
                .as_ref()
                .ok_or(BrowserVerifyError::Unavailable)?;
            let sid = opaque_id();
            let result = backend
                .call(&[
                    "form".into(),
                    sid.clone(),
                    stored_csrf,
                    flow.tag(),
                    (s.transaction_ttl_seconds * 1000).to_string(),
                    s.max_forms.to_string(),
                    s.max_forms_per_window.to_string(),
                    (s.rate_window_seconds * 1000).to_string(),
                ])
                .await?;
            match result.first().map(String::as_str) {
                Some("ok") => Ok((sid, csrf)),
                Some("limited") => Err(BrowserVerifyError::Limited),
                Some("capacity") => Err(BrowserVerifyError::Capacity),
                _ => Err(BrowserVerifyError::Unavailable),
            }
        } else {
            let mut entries = self
                .entries
                .lock()
                .map_err(|_| BrowserVerifyError::Unavailable)?;
            let now = Instant::now();
            if !entries.forms_quota.admit(
                now,
                self.settings
                    .as_ref()
                    .map_or(FORM_LIMIT, |s| s.max_forms_per_window),
                self.window(),
            ) {
                return Err(BrowserVerifyError::Limited);
            }
            let capacity = self.settings.as_ref().map_or(CAPACITY, |s| s.max_forms);
            if entries.forms.len() >= capacity {
                entries.forms.retain(|_, form| form.expires > now);
                if entries.forms.len() >= capacity {
                    return Err(BrowserVerifyError::Capacity);
                }
            }
            let sid = opaque_id();
            entries.forms.insert(
                sid.clone(),
                FormTransaction {
                    csrf: stored_csrf,
                    flow: flow.clone(),
                    expires: now + Duration::from_secs(self.transaction_ttl()),
                },
            );
            Ok((sid, csrf))
        }
    }

    /// Compares the stored challenge directly; production callers go through
    /// [`Self::consume_with_nonce`].
    async fn consume(
        &self,
        sid: &str,
        csrf: &str,
        flow: &LoginFlow,
    ) -> Result<bool, BrowserVerifyError> {
        if !valid_id(sid) || !valid_id(csrf) {
            return Ok(false);
        }
        if let Some(backend) = self.shared()? {
            Ok(backend
                .call(&["consume".into(), sid.into(), csrf.into(), flow.tag()])
                .await?
                .first()
                .map(String::as_str)
                == Some("ok"))
        } else {
            self.consume_form_for(sid, csrf, flow)
        }
    }

    pub(crate) async fn consume_with_nonce(
        &self,
        token: &str,
        form_nonce: &str,
        flow: &LoginFlow,
    ) -> Result<bool, BrowserVerifyError> {
        let Some((sid, csrf)) = split_form_token(token) else {
            return Ok(false);
        };
        if !valid_id(form_nonce) {
            return Ok(false);
        }
        self.consume(sid, &nonce_csrf(form_nonce, csrf), flow).await
    }

    #[cfg(test)]
    pub async fn discard(&self, sid: &str) -> Result<(), BrowserVerifyError> {
        if !valid_id(sid) {
            return Ok(());
        }
        if let Some(backend) = self.shared()? {
            backend.call(&["discard".into(), sid.into()]).await?;
        } else {
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
        if let Some(backend) = self.shared()? {
            let sid = opaque_id();
            let payload = serde_json::to_string(&StoredIdentity::from_user(user))
                .map_err(|_| BrowserVerifyError::Rejected)?;
            if payload.len() > SESSION_WIRE_BYTES_LIMIT - SESSION_ENVELOPE_BYTES_RESERVE {
                return Err(BrowserVerifyError::Rejected);
            }
            let result = backend
                .call(&[
                    "session".into(),
                    sid.clone(),
                    previous.unwrap_or("").into(),
                    payload,
                    (self.ttl * 1000).to_string(),
                    self.settings
                        .as_ref()
                        .ok_or(BrowserVerifyError::Unavailable)?
                        .max_sessions
                        .to_string(),
                ])
                .await?;
            match result.first().map(String::as_str) {
                Some("ok") => {}
                Some("capacity") => return Err(BrowserVerifyError::Capacity),
                _ => return Err(BrowserVerifyError::Unavailable),
            }
            Ok(sid)
        } else {
            self.memory_save_session(user, previous)
        }
    }

    pub async fn lookup(&self, sid: &str) -> Result<Option<BrowserSession>, BrowserVerifyError> {
        if !valid_id(sid) {
            return Ok(None);
        }
        if let Some(backend) = self.shared()? {
            let result = backend.call(&["read".into(), sid.into()]).await?;
            match result.first().map(String::as_str) {
                Some("missing") => return Ok(None),
                Some("ok") => {}
                _ => return Err(BrowserVerifyError::Unavailable),
            }
            let value = result
                .get(1)
                .filter(|v| v.len() <= SESSION_WIRE_BYTES_LIMIT)
                .ok_or(BrowserVerifyError::Unavailable)?;
            let mut parts = value.splitn(3, '\n');
            if parts.next() != Some("1") {
                return Err(BrowserVerifyError::Unavailable);
            }
            let expiry = parts
                .next()
                .and_then(|v| v.parse::<u64>().ok())
                .ok_or(BrowserVerifyError::Unavailable)?;
            let expires_at_utc = i64::try_from(expiry)
                .ok()
                .and_then(chrono::DateTime::from_timestamp_millis)
                .ok_or(BrowserVerifyError::Unavailable)?;
            let stored: StoredIdentity =
                serde_json::from_str(parts.next().ok_or(BrowserVerifyError::Unavailable)?)
                    .map_err(|_| BrowserVerifyError::Unavailable)?;
            let user = stored.into_user()?;
            let projection =
                browser_identity(&user).map_err(|_| BrowserVerifyError::Unavailable)?;
            if user.attributes.len() != projection.attributes.len() {
                return Err(BrowserVerifyError::Unavailable);
            }
            let expires_at = SystemTime::UNIX_EPOCH
                .checked_add(Duration::from_millis(expiry))
                .ok_or(BrowserVerifyError::Unavailable)?;
            Ok(Some(BrowserSession {
                user: Arc::new(projection),
                expires_at,
                expires_at_utc,
                expires: Instant::now(),
            }))
        } else {
            self.memory_session(sid)
        }
    }

    #[cfg(test)]
    fn create_form(&self) -> Option<(String, String)> {
        self.create_form_for(&LoginFlow::api_key("ecmwf-api-key"))
    }

    #[cfg(test)]
    fn create_form_for(&self, flow: &LoginFlow) -> Option<(String, String)> {
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
                flow: flow.clone(),
            },
        );
        Some((sid, csrf))
    }

    /// Removal under one lock makes replay and concurrent submission one-use.
    #[cfg(test)]
    fn consume_form(&self, sid: &str, csrf: &str) -> bool {
        self.consume_form_for(sid, csrf, &LoginFlow::api_key("ecmwf-api-key"))
            .unwrap()
    }

    fn consume_form_for(
        &self,
        sid: &str,
        csrf: &str,
        flow: &LoginFlow,
    ) -> Result<bool, BrowserVerifyError> {
        let mut entries = self
            .entries
            .lock()
            .map_err(|_| BrowserVerifyError::Unavailable)?;
        let now = Instant::now();
        if entries
            .forms
            .get(sid)
            .is_some_and(|form| form.expires <= now)
        {
            entries.forms.remove(sid);
        }
        let matches = entries.forms.get(sid).is_some_and(|form| {
            &form.flow == flow && bool::from(form.csrf.as_bytes().ct_eq(csrf.as_bytes()))
        });
        if matches {
            entries.forms.remove(sid);
        }
        Ok(matches)
    }

    #[cfg(test)]
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
    pub(crate) async fn admitted_with_metrics<T>(
        &self,
        operation: impl std::future::Future<Output = Result<T, BrowserVerifyError>>,
        metrics: Option<&Metrics>,
    ) -> Result<T, BrowserVerifyError> {
        let _permit = self
            .inflight
            .try_acquire()
            .map_err(|_| BrowserVerifyError::Limited)?;
        let _active = metrics.map(Metrics::browser_inflight_guard);
        // Admission time is part of the deadline, so a delayed lease response cannot
        // start a fresh verification deadline after the shared lease has aged.
        let deadline = tokio::time::Instant::now() + self.verification_timeout();
        let mut lease = if let Some(backend) = self.shared()? {
            let s = self
                .settings
                .as_ref()
                .ok_or(BrowserVerifyError::Unavailable)?;
            if let Some(cap) = s.max_shared_inflight_logins {
                Some(
                    within_deadline(
                        deadline,
                        backend.admit(
                            s.max_logins_per_window,
                            s.rate_window_seconds,
                            cap,
                            s.verification_timeout_seconds,
                        ),
                    )
                    .await?,
                )
            } else {
                within_deadline(
                    deadline,
                    backend.quota(s.max_logins_per_window, s.rate_window_seconds),
                )
                .await?;
                None
            }
        } else {
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
            None
        };
        complete_verification(deadline, operation, async {
            if let Some(lease) = &mut lease {
                lease.release().await?;
            }
            Ok(())
        })
        .await
    }

    #[cfg(test)]
    async fn verify(&self, key: &str) -> Result<User, BrowserVerifyError> {
        self.admitted(self.verify_key("ecmwf-api-key", key)).await
    }

    pub(crate) fn verification_timeout(&self) -> Duration {
        Duration::from_secs(
            self.settings
                .as_ref()
                .map_or(10, |s| s.verification_timeout_seconds),
        )
    }

    pub async fn verify_identity(
        &self,
        method: &str,
        credentials: BrowserCredentials<'_>,
        auth: &Auth,
        metrics: &Metrics,
    ) -> Result<User, BrowserVerifyError> {
        self.verify_identity_with(method, credentials, auth, metrics, false, browser_identity)
            .await
            .map(|(user, _)| user)
    }

    pub(crate) async fn verify_identity_strict(
        &self,
        method: &str,
        credentials: BrowserCredentials<'_>,
        auth: &Auth,
        metrics: &Metrics,
        projection: fn(&User) -> Result<User, BrowserVerifyError>,
    ) -> Result<(User, Vec<String>), BrowserVerifyError> {
        self.verify_identity_with(method, credentials, auth, metrics, true, projection)
            .await
    }

    async fn verify_identity_with(
        &self,
        method: &str,
        credentials: BrowserCredentials<'_>,
        auth: &Auth,
        metrics: &Metrics,
        strict: bool,
        projection: fn(&User) -> Result<User, BrowserVerifyError>,
    ) -> Result<(User, Vec<String>), BrowserVerifyError> {
        self.admitted_with_metrics(
            async {
                let user = match credentials {
                    BrowserCredentials::ApiKey(key) => {
                        let key = validated_key(key).ok_or(BrowserVerifyError::Rejected)?;
                        self.verify_key(method, key).await?
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
                        let Some(MethodVerifier::Plain(provider)) =
                            self.method(method).map(|m| &m.verifier)
                        else {
                            return Err(BrowserVerifyError::Rejected);
                        };
                        provider
                            .authenticate(&encoded)
                            .await
                            .map_err(|_| BrowserVerifyError::Rejected)?
                    }
                };
                let provider_roles = user.roles.clone();
                let user = if strict {
                    auth.check_augmenters_strict(user, metrics)
                        .await
                        .map_err(|_| BrowserVerifyError::Rejected)?
                } else {
                    auth.check_augmenters(user, metrics)
                        .await
                        .ok_or(BrowserVerifyError::Rejected)?
                };
                Ok((projection(&user)?, provider_roles))
            },
            Some(metrics),
        )
        .await
    }

    async fn verify_key(&self, method: &str, key: &str) -> Result<User, BrowserVerifyError> {
        let Some(MethodVerifier::EcmwfApi(provider)) = self.method(method).map(|m| &m.verifier)
        else {
            return Err(BrowserVerifyError::Rejected);
        };
        let user = provider
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

    /// Fetches OIDC provider metadata now and then periodically, so the chooser reflects
    /// provider availability and a recovered provider becomes usable without a click.
    pub(crate) fn start_oidc_discovery_task(self: &Arc<Self>) {
        if self.methods.iter().all(|method| method.oidc().is_none()) {
            return;
        }
        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(OIDC_DISCOVERY_INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                let Some(state) = weak.upgrade() else {
                    break;
                };
                for method in &state.methods {
                    let Some(oidc) = method.oidc() else {
                        continue;
                    };
                    if let Err(error) = oidc.metadata().await {
                        tracing::warn!(
                            event_name = "browser.oidc.discovery_failed",
                            event_domain = "browser",
                            method = %method.flow.method,
                            reason = error.label(),
                            "OIDC provider metadata unavailable"
                        );
                    }
                }
            }
        });
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
        if entries.sessions.len() >= self.settings.as_ref().map_or(CAPACITY, |s| s.max_sessions) {
            entries.sessions.retain(|_, session| session.expires > now);
        }
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
        if entries
            .sessions
            .get(sid)
            .is_some_and(|session| session.expires <= Instant::now())
        {
            entries.sessions.remove(sid);
        }
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

/// Splits a form CSRF token `<sid>.<challenge>`, both 64 lowercase hex digits.
/// Valid: `<64hex>.<64hex>`. Invalid: `<64hex>`, `<64hex>.`, `<64hex>.<64hex>.x`.
fn split_form_token(token: &str) -> Option<(&str, &str)> {
    let (sid, challenge) = token.split_once('.')?;
    (valid_id(sid) && valid_id(challenge)).then_some((sid, challenge))
}

fn nonce_csrf(form_nonce: &str, csrf: &str) -> String {
    // Both components are fixed-length opaque hex IDs; the domain separates this digest.
    format!(
        "{:x}",
        Sha256::digest(format!("browser-form:{form_nonce}:{csrf}"))
    )
}

async fn within_deadline<T>(
    deadline: tokio::time::Instant,
    operation: impl std::future::Future<Output = Result<T, BrowserVerifyError>>,
) -> Result<T, BrowserVerifyError> {
    if tokio::time::Instant::now() >= deadline {
        return Err(BrowserVerifyError::Timeout);
    }
    let result = tokio::time::timeout_at(deadline, operation)
        .await
        .unwrap_or(Err(BrowserVerifyError::Timeout));
    // A cooperatively polled future can return Ready after doing work past the deadline.
    if tokio::time::Instant::now() >= deadline {
        return Err(BrowserVerifyError::Timeout);
    }
    result
}

async fn complete_verification<T>(
    deadline: tokio::time::Instant,
    operation: impl std::future::Future<Output = Result<T, BrowserVerifyError>>,
    cleanup: impl std::future::Future<Output = Result<(), BrowserVerifyError>>,
) -> Result<T, BrowserVerifyError> {
    let result = within_deadline(deadline, operation).await;
    let released = within_deadline(deadline, cleanup).await;
    // An elapsed deadline overrides even a Rejected result.
    if tokio::time::Instant::now() >= deadline {
        return Err(BrowserVerifyError::Timeout);
    }
    // Cleanup cannot turn failed verification into another outcome. A verified identity
    // is usable only after successful release; failures otherwise remain fail-closed.
    match result {
        Err(error) => Err(error),
        Ok(user) => released
            .map(|()| user)
            .map_err(|_| BrowserVerifyError::Unavailable),
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

    #[tokio::test]
    async fn release_failure_preserves_rejection_and_timeout_but_rejects_verified_success() {
        for (verification, expected) in [
            (Ok(maximum_identity()), BrowserVerifyError::Unavailable),
            (
                Err(BrowserVerifyError::Rejected),
                BrowserVerifyError::Rejected,
            ),
            (
                Err(BrowserVerifyError::Timeout),
                BrowserVerifyError::Timeout,
            ),
        ] {
            let released = std::cell::Cell::new(false);
            let result = complete_verification(
                tokio::time::Instant::now() + Duration::from_secs(10),
                async { verification },
                async {
                    released.set(true);
                    Err(BrowserVerifyError::Unavailable)
                },
            )
            .await;
            assert_eq!(result.err(), Some(expected));
            assert!(released.get());
        }
    }

    #[tokio::test]
    async fn ready_verification_after_deadline_is_timeout_without_polling_cleanup() {
        for verification in [Ok(maximum_identity()), Err(BrowserVerifyError::Rejected)] {
            let deadline = tokio::time::Instant::now() + Duration::from_millis(10);
            let result = complete_verification(
                deadline,
                async {
                    // Deliberately return Ready late in one poll, which timeout_at alone can accept.
                    std::thread::sleep(Duration::from_millis(20));
                    verification
                },
                async { panic!("expired cleanup must be left to the lease drop guard") },
            )
            .await;
            assert_eq!(result.err(), Some(BrowserVerifyError::Timeout));
        }
    }

    #[tokio::test]
    async fn ready_cleanup_after_deadline_overrides_success_and_rejection_with_timeout() {
        for verified in [true, false] {
            for cleanup in [Ok(()), Err(BrowserVerifyError::Unavailable)] {
                let result = complete_verification(
                    tokio::time::Instant::now() + Duration::from_millis(10),
                    async {
                        if verified {
                            Ok(maximum_identity())
                        } else {
                            Err(BrowserVerifyError::Rejected)
                        }
                    },
                    async {
                        std::thread::sleep(Duration::from_millis(20));
                        cleanup
                    },
                )
                .await;
                assert_eq!(result.err(), Some(BrowserVerifyError::Timeout));
            }
        }
    }

    #[tokio::test]
    async fn memory_misses_and_rate_rejection_leave_unrelated_expired_entries_for_cleanup() {
        let state = state();
        let (form, _) = state.create_form().unwrap();
        let session = state.create_session(maximum_identity(), None).unwrap();
        {
            let mut entries = state.entries.lock().unwrap();
            entries.forms.get_mut(&form).unwrap().expires = Instant::now();
            entries.sessions.get_mut(&session).unwrap().expires = Instant::now();
            entries.forms_quota.used = usize::MAX;
        }
        for _ in 0..10 {
            assert!(state.memory_session(&opaque_id()).unwrap().is_none());
            assert!(matches!(
                state.form(&LoginFlow::basic("password")).await,
                Err(BrowserVerifyError::Limited)
            ));
        }
        {
            let entries = state.entries.lock().unwrap();
            assert!(entries.forms.contains_key(&form));
            assert!(entries.sessions.contains_key(&session));
        }
        assert!(state.memory_session(&session).unwrap().is_none());
        assert!(state.entries.lock().unwrap().forms.contains_key(&form));
        state.cleanup();
        assert!(state.entries.lock().unwrap().forms.is_empty());
    }

    #[tokio::test]
    async fn memory_capacity_reclaims_expired_forms_without_pruning_sessions() {
        let mut state = state();
        state.settings.as_mut().unwrap().max_forms = 1;
        let (expired, _) = state.form(&LoginFlow::basic("password")).await.unwrap();
        let session = state.create_session(maximum_identity(), None).unwrap();
        {
            let mut entries = state.entries.lock().unwrap();
            entries.forms.get_mut(&expired).unwrap().expires = Instant::now();
            entries.sessions.get_mut(&session).unwrap().expires = Instant::now();
        }
        let (fresh, csrf) = state.form(&LoginFlow::basic("password")).await.unwrap();
        assert!(
            state
                .entries
                .lock()
                .unwrap()
                .sessions
                .contains_key(&session)
        );
        assert!(!state.entries.lock().unwrap().forms.contains_key(&expired));
        assert!(
            state
                .consume(&fresh, &csrf, &LoginFlow::basic("password"))
                .await
                .unwrap()
        );
    }

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
            methods: Vec::new(),
            client: reqwest::Client::new(),
            inflight: Semaphore::new(MAX_INFLIGHT),
            settings: Some(serde_json::from_value(serde_json::json!({"public_origin": "https://login.example.test", "backend": {"type": "memory"}})).unwrap()),
            valkey: None,
        }
    }

    fn configured_state(uri: &str) -> BrowserLoginState {
        let config: ConfigV2 = serde_json::from_value(serde_json::json!({
            "store": {"enabled": false}, "services": [], "augmenters": [],
            "providers": [{"type": "ecmwf-api", "name": "public-provider", "realm": "ecmwf", "uri": uri, "browser": {"id": "ecmwf-api-key", "label": "ECMWF API key"}}],
            "server": {"port": 0}, "jwt": {"iss": "public-test", "exp": 300, "secret": "public-test-only-secret"},
            "logging": {"level": "warn", "format": "console"},
            "ui": {"enabled": true, "browser_session": {"public_origin": "https://login.example.test", "backend": {"type": "memory"}}}
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

    #[tokio::test]
    async fn transactions_bind_method_id_and_type_without_burning_on_mismatch() {
        let state = state();
        let (sid, csrf) = state.form(&LoginFlow::basic("guests")).await.unwrap();
        for other in [
            LoginFlow::basic("password"),
            LoginFlow::basic("staff"),
            LoginFlow::api_key("guests"),
            LoginFlow::oidc("guests"),
        ] {
            assert!(!state.consume(&sid, &csrf, &other).await.unwrap());
        }
        assert!(
            state
                .consume(&sid, &csrf, &LoginFlow::basic("guests"))
                .await
                .unwrap()
        );
        for (flow, tag) in [
            (LoginFlow::basic("password"), "basic:password".to_owned()),
            (LoginFlow::api_key("0"), "key:0".to_owned()),
            (
                LoginFlow::api_key(&"a".repeat(32)),
                format!("key:{}", "a".repeat(32)),
            ),
            (
                LoginFlow::basic(&"a".repeat(32)),
                format!("basic:{}", "a".repeat(32)),
            ),
            (LoginFlow::oidc("demo-sso"), "oidc:demo-sso".to_owned()),
            (
                LoginFlow::oidc(&"a".repeat(32)),
                format!("oidc:{}", "a".repeat(32)),
            ),
        ] {
            assert_eq!(flow.tag(), tag);
            assert!(flow.tag().len() <= 38);
        }
        let (sid, csrf) = state.form(&LoginFlow::oidc("guests")).await.unwrap();
        assert!(
            !state
                .consume(&sid, &csrf, &LoginFlow::basic("guests"))
                .await
                .unwrap()
        );
        assert!(
            state
                .consume(&sid, &csrf, &LoginFlow::oidc("guests"))
                .await
                .unwrap()
        );
        assert!(
            !state
                .consume(&sid, &csrf, &LoginFlow::oidc("guests"))
                .await
                .unwrap()
        );
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
                    flow: LoginFlow::api_key("ecmwf-api-key"),
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
        state.methods.push(BrowserMethod {
            label: "ECMWF API key".into(),
            flow: LoginFlow::api_key("ecmwf-api-key"),
            refresh_max_lifetime_seconds: None,
            verifier: MethodVerifier::EcmwfApi(EcmwfApiProvider::new(&EcmwfApiProviderConfig {
                uri: server.url(),
                realm: "ecmwf".into(),
                name: "public-provider".into(),
                browser: None,
            })),
        });
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

    #[tokio::test]
    async fn expired_transactions_and_sessions_fail_closed_through_routes() {
        use axum::{
            body::Body,
            http::{Request, StatusCode},
        };
        use std::sync::Arc;
        use tower::ServiceExt;
        let config: ConfigV2 = serde_json::from_value(serde_json::json!({
            "store": {"enabled": false}, "services": [], "augmenters": [],
            "providers": [{"type": "ecmwf-api", "name": "public-provider", "realm": "ecmwf", "uri": "http://127.0.0.1:1", "browser": {"id": "ecmwf-api-key", "label": "ECMWF API key"}}],
            "server": {"port": 0}, "jwt": {"iss": "public-test", "exp": 300, "secret": "public-test-only-secret"},
            "logging": {"level": "warn", "format": "console"},
            "ui": {"enabled": true, "browser_session": {"public_origin": "https://login.example.test", "backend": {"type": "memory"}}}
        })).unwrap();
        let (app, state) = crate::startup::build_app(Arc::new(config)).await.unwrap();
        let (sid, csrf) = state.browser.create_form().unwrap();
        state
            .browser
            .entries
            .lock()
            .unwrap()
            .forms
            .get_mut(&sid)
            .unwrap()
            .expires = Instant::now();
        let response = app
            .clone()
            .oneshot(
                Request::post("/login/method/ecmwf-api-key")
                    .header("origin", "https://login.example.test")
                    .header("cookie", format!("__Host-authotron_form={sid}"))
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(format!("api_key=public-fixture&csrf={csrf}")))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let user = User::new("ecmwf".into(), "public-user".into(), None, None, None, None);
        let sid = state.browser.create_session(user, None).unwrap();
        state
            .browser
            .entries
            .lock()
            .unwrap()
            .sessions
            .get_mut(&sid)
            .unwrap()
            .expires = Instant::now();
        for path in ["/login/account", "/login"] {
            let response = app
                .clone()
                .oneshot(
                    Request::get(path)
                        .header("cookie", format!("__Host-authotron_session={sid}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                if path == "/login" {
                    StatusCode::OK
                } else {
                    StatusCode::SEE_OTHER
                }
            );
        }
    }
}

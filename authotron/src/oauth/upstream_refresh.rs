// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! The upstream step of refreshing a coupled family. Under a per-family lock the
//! current sealed grant is re-read, refreshed at the provider, and any rotated upstream
//! token is stored before anything else can fail, so a later step never loses it. The
//! refreshed identity must keep its `sub` and username; its mapped roles replace the
//! family's provider roles for this refresh.

use super::{
    refresh::{Presented, RefreshFamily, UpstreamStored, random_id},
    refresh_grant::{RefreshBackend, RefreshGrantError, refresh_dispatch},
    runtime::OAuthRuntime,
    upstream::binding,
};
use crate::{
    browser::BrowserLoginState,
    config::UsernameClaim,
    metrics::{Metrics, RefreshTokenEvent, UpstreamTokenEvent},
    oidc::{OidcError, method::OidcMethod, upstream::UpstreamGrant},
};
use std::time::Duration;

/// How long a refresh waits for another replica's upstream refresh of the same family.
const LOCK_WAIT: Duration = Duration::from_secs(2);
const LOCK_POLL: Duration = Duration::from_millis(100);
/// Lock lifetime beyond the provider request timeout.
const LOCK_MARGIN_MS: u64 = 5_000;

/// What the provider's answer means for the family.
enum Outcome {
    /// The refreshed identity's mapped provider roles.
    Roles(Vec<String>),
    /// 503; the family is kept.
    Unavailable,
    /// The upstream grant is gone or cannot be opened: end the family only.
    Dead,
    /// The identity changed or failed validation: end the family and its upstream grant.
    Changed,
}

impl OAuthRuntime {
    /// Renews a coupled family's upstream grant for the presented token and returns the
    /// provider roles to augment. Families whose upstream grant is dead or whose identity
    /// changed are revoked.
    pub(super) async fn refresh_upstream(
        &self,
        backend: &RefreshBackend,
        family: &RefreshFamily,
        presented: &[u8; 32],
        oidc: &OidcMethod,
        browser: &BrowserLoginState,
        metrics: &Metrics,
    ) -> Result<Vec<String>, RefreshGrantError> {
        use RefreshGrantError::*;
        let id = &family.family_id;
        let holder = random_id()?;
        let lifetime = oidc.config().http_timeout_ms + LOCK_MARGIN_MS;
        let deadline = tokio::time::Instant::now() + LOCK_WAIT;
        loop {
            let now = self.now().await.map_err(|_| Unavailable)?;
            if refresh_dispatch!(backend, lock_upstream(id, &holder, now, now + lifetime))? {
                break;
            }
            if tokio::time::Instant::now() + LOCK_POLL > deadline {
                tracing::warn!(
                    event_name = "oauth.upstream.lock_busy",
                    event_domain = "oauth",
                    method = %family.grant.method,
                    "another refresh of this family is still renewing its upstream grant"
                );
                metrics.record_upstream_token(UpstreamTokenEvent::Unavailable);
                return Err(Unavailable);
            }
            tokio::time::sleep(LOCK_POLL).await;
        }
        let outcome = self
            .renew(backend, family, presented, oidc, browser, metrics)
            .await;
        refresh_dispatch!(backend, unlock_upstream(id, &holder))?;
        let event = match &outcome {
            Ok(Outcome::Roles(_)) => Some(UpstreamTokenEvent::Refreshed),
            Ok(Outcome::Unavailable) | Err(Unavailable) => Some(UpstreamTokenEvent::Unavailable),
            Ok(Outcome::Dead) => Some(UpstreamTokenEvent::InvalidGrant),
            Ok(Outcome::Changed) => Some(UpstreamTokenEvent::IdentityChanged),
            Err(_) => None,
        };
        if let Some(event) = event {
            metrics.record_upstream_token(event);
        }
        match outcome? {
            Outcome::Roles(roles) => Ok(roles),
            Outcome::Unavailable => Err(Unavailable),
            ended @ (Outcome::Dead | Outcome::Changed) => {
                let revoked = refresh_dispatch!(backend, revoke_family(id))?;
                metrics.record_refresh_token(RefreshTokenEvent::FamilyRevoked);
                if matches!(ended, Outcome::Changed) {
                    self.end_upstream(revoked, browser, metrics);
                }
                Err(InvalidGrant)
            }
        }
    }

    /// The locked section: re-read, refresh at the provider, store a rotated token.
    async fn renew(
        &self,
        backend: &RefreshBackend,
        family: &RefreshFamily,
        presented: &[u8; 32],
        oidc: &OidcMethod,
        browser: &BrowserLoginState,
        metrics: &Metrics,
    ) -> Result<Outcome, RefreshGrantError> {
        let now = self
            .now()
            .await
            .map_err(|_| RefreshGrantError::Unavailable)?;
        // Another holder may have refreshed meanwhile: use the newest sealed grant.
        let current = match refresh_dispatch!(backend, lookup(presented, now))? {
            Presented::Current(current) if current.family_id == family.family_id => current,
            Presented::Reused { ended, .. } => {
                metrics.record_refresh_token(RefreshTokenEvent::ReuseDetected);
                metrics.record_refresh_token(RefreshTokenEvent::FamilyRevoked);
                self.end_upstream(ended.map(|ended| *ended), browser, metrics);
                return Err(RefreshGrantError::InvalidGrant);
            }
            _ => return Err(RefreshGrantError::InvalidGrant),
        };
        let grant = &current.grant;
        let binding = binding(grant, oidc);
        let (Some(upstream), Some(state)) = (&self.upstream, &current.upstream) else {
            return Ok(Outcome::Dead);
        };
        let Ok(opened) = upstream.cipher.open(&binding, &state.sealed) else {
            tracing::warn!(
                event_name = "oauth.upstream.unopenable",
                event_domain = "oauth",
                method = %grant.method,
                "sealed upstream grant cannot be opened with the configured keys"
            );
            return Ok(Outcome::Dead);
        };
        let refreshed = match oidc.refresh(opened.refresh_token()).await {
            Ok(refreshed) => refreshed,
            Err(OidcError::Rejected) => return Ok(Outcome::Dead),
            Err(error) => {
                tracing::warn!(
                    event_name = "oauth.upstream.refresh_unavailable",
                    event_domain = "oauth",
                    method = %grant.method,
                    reason = error.label(),
                    "upstream grant not refreshed"
                );
                return Ok(Outcome::Unavailable);
            }
        };
        if let Some(rotated) = refreshed.refresh_token {
            let sealed = upstream
                .cipher
                .seal(&binding, &UpstreamGrant::new(opened.subject(), rotated));
            let stored = match sealed {
                Ok(sealed) => refresh_dispatch!(
                    backend,
                    set_upstream(&current.family_id, state.generation, &sealed, now)
                ),
                Err(_) => Ok(UpstreamStored::Stale),
            };
            if !matches!(stored, Ok(UpstreamStored::Stored)) {
                tracing::error!(
                    event_name = "oauth.upstream.rotation_lost",
                    event_domain = "oauth",
                    method = %grant.method,
                    "rotated upstream refresh token could not be stored"
                );
                metrics.record_upstream_token(UpstreamTokenEvent::RotationLost);
                return Ok(Outcome::Unavailable);
            }
            metrics.record_upstream_token(UpstreamTokenEvent::Rotated);
        }
        Ok(match refreshed.identity {
            Ok(Some((subject, user)))
                if subject == opened.subject()
                    && user.username == grant.username
                    && user.realm == grant.realm =>
            {
                Outcome::Roles(user.roles)
            }
            Ok(Some(_))
            | Err(OidcError::InvalidIdToken | OidcError::InvalidIdentity | OidcError::Rejected) => {
                tracing::warn!(
                    event_name = "oauth.upstream.identity_changed",
                    event_domain = "oauth",
                    method = %grant.method,
                    "refreshed identity does not match the family"
                );
                Outcome::Changed
            }
            Err(_) => Outcome::Unavailable,
            // Without an ID token only a `sub` username and no mapped roles stay valid.
            Ok(None)
                if oidc.config().username_claim == UsernameClaim::Sub
                    && oidc.config().roles_claim.is_none() =>
            {
                Outcome::Roles(grant.provider_roles.clone())
            }
            Ok(None) => {
                tracing::warn!(
                    event_name = "oauth.upstream.identity_missing",
                    event_domain = "oauth",
                    method = %grant.method,
                    "provider sent no ID token to re-check the mapped username or roles"
                );
                Outcome::Unavailable
            }
        })
    }
}

#[cfg(all(test, unix))]
mod tests;

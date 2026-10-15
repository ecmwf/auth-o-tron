// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! Logins as an operator finds and revokes them: the live refresh-token families of a
//! realm, optionally of one username and one client, in the shared Valkey store. The
//! memory backend keeps families inside each server process, out of reach.

use super::{
    audit::{FamilyEnd, family_ended},
    refresh::{FamilySummary, RefreshGrant, user_key},
    refresh_grant::RefreshBackend,
    runtime::OAuthRuntime,
    valkey_refresh::ValkeyRefreshStore,
};
use crate::{
    browser::BrowserLoginState,
    metrics::{Metrics, UpstreamTokenEvent},
};
use futures::StreamExt;
use std::time::Duration;

/// Upstream revocations one admin revocation sends at once.
const UPSTREAM_CONCURRENCY: usize = 8;
/// How long one upstream revocation may take, the provider's metadata included.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(10);
/// Consecutive failed upstream revocations after which the provider is taken to be
/// down and the rest are not attempted, so a large revocation ends in bounded time.
pub const MAX_CONSECUTIVE_UPSTREAM_FAILURES: usize = 16;
/// The largest per-user family cap, so a user's index never holds more live families.
const MAX_FAMILIES_PER_USER: usize = 1000;

/// The logins an admin command selects: one realm, and optionally one username and one
/// client id, each compared exactly as the families store them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginFilter {
    pub realm: String,
    pub username: Option<String>,
    pub client: Option<String>,
}

impl LoginFilter {
    fn selects(&self, grant: &RefreshGrant) -> bool {
        grant.realm == self.realm
            && self
                .username
                .as_ref()
                .is_none_or(|name| *name == grant.username)
            && self.client.as_ref().is_none_or(|id| *id == grant.client_id)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminError {
    /// No client has refresh tokens, so there are no logins.
    NoLogins,
    /// The memory backend keeps families inside each server process.
    PerProcess,
    /// The store did not answer.
    Unavailable,
}

/// What an admin revocation did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Revoked {
    /// Families revoked; one that ended meanwhile is not counted.
    pub families: usize,
    /// The store failed before every family was revoked.
    pub interrupted: bool,
    /// Upstream grants of coupled families: revoked at the provider, unsupported there,
    /// failed, timed out or not attempted, and skipped because no key or method opens
    /// them.
    pub upstream_sent: usize,
    pub upstream_unsupported: usize,
    pub upstream_failed: usize,
    pub upstream_skipped: usize,
    /// The failed and skipped upstream grants, which may still be live at the provider.
    pub upstream_left: Vec<UpstreamLeft>,
}

/// An upstream grant an admin revocation left at the provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamLeft {
    /// The reference of its family.
    pub family: String,
    pub username: String,
    pub reason: LeftReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeftReason {
    /// The provider refused it, failed or did not answer in time.
    Failed,
    /// Not attempted, or abandoned, after [`MAX_CONSECUTIVE_UPSTREAM_FAILURES`].
    NotAttempted,
    /// No configured key and method open the grant any more.
    Skipped,
}

impl OAuthRuntime {
    fn admin_store(&self) -> Result<&ValkeyRefreshStore, AdminError> {
        match &self.refresh {
            None => Err(AdminError::NoLogins),
            Some(RefreshBackend::Memory(_)) => Err(AdminError::PerProcess),
            Some(RefreshBackend::Valkey(store)) => Ok(store),
        }
    }

    /// The live logins `filter` selects, newest first. With a username they come from
    /// that user's index; without, a scan of every family of the namespace finds them,
    /// in bounded steps ([`ValkeyRefreshStore::scan`]).
    pub async fn find_logins(
        &self,
        filter: &LoginFilter,
    ) -> Result<Vec<FamilySummary>, AdminError> {
        let store = self.admin_store()?;
        let now = self.now().await.map_err(|_| AdminError::Unavailable)?;
        let mut found = Vec::new();
        if let Some(username) = &filter.username {
            let key = user_key(&filter.realm, username);
            found = store
                .families_of(&key, MAX_FAMILIES_PER_USER, now)
                .await
                .map_err(|_| AdminError::Unavailable)?;
        } else {
            let mut cursor = 0;
            loop {
                let (next, families) = store
                    .scan(cursor, now)
                    .await
                    .map_err(|_| AdminError::Unavailable)?;
                found.extend(families.into_iter().filter(|f| filter.selects(&f.grant)));
                if next == 0 {
                    break;
                }
                cursor = next;
            }
        }
        found.retain(|family| filter.selects(&family.grant));
        found.sort_by(|a, b| (b.created_at_ms, &b.family_id).cmp(&(a.created_at_ms, &a.family_id)));
        // A scan may visit a key twice.
        found.dedup_by(|a, b| a.family_id == b.family_id);
        Ok(found)
    }

    /// Revokes `logins` as `admin_revoke`, then the upstream grants of the coupled ones at
    /// the provider, waiting for each answer for at most ten seconds and attempting no
    /// more after [`MAX_CONSECUTIVE_UPSTREAM_FAILURES`] failed in a row.
    pub async fn revoke_found(
        &self,
        logins: &[FamilySummary],
        browser: &BrowserLoginState,
        metrics: &Metrics,
    ) -> Result<Revoked, AdminError> {
        let store = self.admin_store()?;
        let mut revoked = Revoked::default();
        let mut sealed = Vec::new();
        for login in logins {
            let Ok(ended) = store.revoke_family(&login.family_id).await else {
                revoked.interrupted = true;
                break;
            };
            let Some(ended) = ended else {
                continue;
            };
            revoked.families += 1;
            let reference = family_ended(&ended, FamilyEnd::AdminRevoke, metrics);
            if let Some(grant) = ended.sealed {
                sealed.push((ended.grant, grant, reference));
            }
        }
        let mut answered = vec![false; sealed.len()];
        let mut pending = futures::stream::iter(sealed.iter().enumerate().map(
            |(index, (grant, sealed, family))| async move {
                let timeout = UPSTREAM_TIMEOUT;
                let outcome = self
                    .revoke_sealed_now(grant, sealed, family, browser, metrics, timeout)
                    .await;
                (index, outcome)
            },
        ))
        .buffer_unordered(UPSTREAM_CONCURRENCY);
        let mut failed_in_a_row = 0;
        while let Some((index, outcome)) = pending.next().await {
            answered[index] = true;
            let left = match outcome {
                UpstreamTokenEvent::RevocationSent => {
                    revoked.upstream_sent += 1;
                    None
                }
                UpstreamTokenEvent::RevocationUnsupported => {
                    revoked.upstream_unsupported += 1;
                    None
                }
                UpstreamTokenEvent::RevocationSkipped => {
                    revoked.upstream_skipped += 1;
                    Some(LeftReason::Skipped)
                }
                _ => {
                    revoked.upstream_failed += 1;
                    Some(LeftReason::Failed)
                }
            };
            failed_in_a_row = match left {
                Some(LeftReason::Failed) => failed_in_a_row + 1,
                _ => 0,
            };
            if let Some(reason) = left {
                revoked.upstream_left.push(left_at(&sealed[index], reason));
            }
            if failed_in_a_row == MAX_CONSECUTIVE_UPSTREAM_FAILURES {
                break;
            }
        }
        // Dropping the stream abandons the revocations still waiting for an answer.
        drop(pending);
        for (login, _) in sealed
            .iter()
            .zip(&answered)
            .filter(|(_, answered)| !**answered)
        {
            revoked.upstream_failed += 1;
            let left = left_at(login, LeftReason::NotAttempted);
            revoked.upstream_left.push(left);
        }
        Ok(revoked)
    }
}

fn left_at(
    (grant, _, family): &(RefreshGrant, String, String),
    reason: LeftReason,
) -> UpstreamLeft {
    UpstreamLeft {
        family: family.clone(),
        username: grant.username.clone(),
        reason,
    }
}

#[cfg(all(test, unix))]
mod tests;

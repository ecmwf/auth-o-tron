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
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Revoked {
    /// Families revoked; one that ended meanwhile is not counted.
    pub families: usize,
    /// The store failed before every family was revoked.
    pub interrupted: bool,
    /// Upstream grants of coupled families: revoked at the provider, unsupported there,
    /// failed or timed out, and skipped because no key or method opens them.
    pub upstream_sent: usize,
    pub upstream_unsupported: usize,
    pub upstream_failed: usize,
    pub upstream_skipped: usize,
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
    /// the provider, waiting for each answer for at most ten seconds.
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
        let outcomes: Vec<_> =
            futures::stream::iter(sealed.iter().map(|(grant, sealed, family)| {
                self.revoke_sealed_now(grant, sealed, family, browser, metrics, UPSTREAM_TIMEOUT)
            }))
            .buffer_unordered(UPSTREAM_CONCURRENCY)
            .collect()
            .await;
        for outcome in outcomes {
            match outcome {
                UpstreamTokenEvent::RevocationSent => revoked.upstream_sent += 1,
                UpstreamTokenEvent::RevocationUnsupported => revoked.upstream_unsupported += 1,
                UpstreamTokenEvent::RevocationSkipped => revoked.upstream_skipped += 1,
                _ => revoked.upstream_failed += 1,
            }
        }
        Ok(revoked)
    }
}

#[cfg(all(test, unix))]
mod tests;

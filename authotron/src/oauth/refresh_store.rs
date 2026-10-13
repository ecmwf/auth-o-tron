// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! Process-local refresh-token families for single-replica deployments.

use super::refresh::{
    EndedUpstream, MAX_ROTATED_HASHES, Presented, REUSE_GRACE_MS, RefreshFamily, RefreshGrant,
    RefreshStoreError, Revocation, Rotated, UpstreamState, UpstreamStored, deadline,
    initial_expiry, random_id,
};
use crate::config::RefreshTokenPolicy;
use std::{
    collections::{HashMap, VecDeque},
    sync::Mutex,
};

struct Family {
    grant: RefreshGrant,
    user_key: String,
    created_at_ms: u64,
    absolute_ms: u64,
    idle_ms: u64,
    current: [u8; 32],
    previous: Option<([u8; 32], u64)>,
    /// Recently rotated hashes, oldest first, at most [`MAX_ROTATED_HASHES`].
    rotated: VecDeque<[u8; 32]>,
    upstream: Option<UpstreamState>,
}
impl Family {
    fn live(&self, now_ms: u64) -> bool {
        now_ms < self.idle_ms && now_ms < self.absolute_ms
    }
    fn ended(self) -> Option<EndedUpstream> {
        let grant = self.grant;
        self.upstream.map(|upstream| EndedUpstream {
            grant,
            sealed: upstream.sealed,
        })
    }
}

#[derive(Default)]
struct Inner {
    families: HashMap<String, Family>,
    /// Current and recently rotated hashes with the family they belong to. Each entry
    /// expires at the family's idle deadline when it was issued or rotated: a family
    /// unused for that long has expired, so older hashes need not be recognised.
    tokens: HashMap<[u8; 32], (String, u64)>,
    /// Upstream refresh locks: family id to holder token and expiry.
    upstream_locks: HashMap<String, (String, u64)>,
}
impl Inner {
    fn prune(&mut self, now_ms: u64) {
        self.families.retain(|_, family| family.live(now_ms));
        let families = &self.families;
        self.tokens
            .retain(|_, (id, expires)| now_ms < *expires && families.contains_key(id));
        self.upstream_locks
            .retain(|_, (_, expires)| now_ms < *expires);
    }
}

pub struct MemoryRefreshStore {
    max_per_user: usize,
    inner: Mutex<Inner>,
}
impl MemoryRefreshStore {
    pub fn new(max_per_user: usize) -> Self {
        Self {
            max_per_user,
            inner: Mutex::default(),
        }
    }
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Inner>, RefreshStoreError> {
        self.inner
            .lock()
            .map_err(|_| RefreshStoreError::Unavailable)
    }
    /// Starts a family, coupled when `upstream` holds a sealed upstream grant; at the
    /// per-user cap the user's oldest families are revoked and the coupled ones returned.
    pub async fn issue(
        &self,
        grant: &RefreshGrant,
        token_hash: [u8; 32],
        now_ms: u64,
        policy: &RefreshTokenPolicy,
        upstream: Option<&str>,
    ) -> Result<Vec<EndedUpstream>, RefreshStoreError> {
        let (absolute_ms, idle_ms) =
            initial_expiry(now_ms, policy).ok_or(RefreshStoreError::Unavailable)?;
        grant.encode()?;
        let family_id = random_id()?;
        let user_key = grant.user_key();
        let mut inner = self.lock()?;
        inner.prune(now_ms);
        if inner.tokens.contains_key(&token_hash) {
            return Err(RefreshStoreError::Unavailable);
        }
        let mut owned: Vec<(u64, String)> = inner
            .families
            .iter()
            .filter(|(_, family)| family.user_key == user_key)
            .map(|(id, family)| (family.created_at_ms, id.clone()))
            .collect();
        owned.sort_unstable();
        let excess = (owned.len() + 1).saturating_sub(self.max_per_user);
        let evicted = owned
            .into_iter()
            .take(excess)
            .filter_map(|(_, id)| inner.families.remove(&id)?.ended())
            .collect();
        inner
            .tokens
            .insert(token_hash, (family_id.clone(), idle_ms));
        inner.families.insert(
            family_id,
            Family {
                grant: grant.clone(),
                user_key,
                created_at_ms: now_ms,
                absolute_ms,
                idle_ms,
                current: token_hash,
                previous: None,
                rotated: VecDeque::new(),
                upstream: upstream.map(|sealed| UpstreamState {
                    sealed: sealed.to_owned(),
                    generation: 0,
                }),
            },
        );
        inner.prune(now_ms);
        Ok(evicted)
    }
    /// Classifies a presented hash; reuse outside the grace window revokes the family.
    pub async fn lookup(
        &self,
        token_hash: &[u8; 32],
        now_ms: u64,
    ) -> Result<Presented, RefreshStoreError> {
        let mut inner = self.lock()?;
        let Some((id, expires)) = inner.tokens.get(token_hash).cloned() else {
            return Ok(Presented::Missing);
        };
        if now_ms >= expires {
            inner.tokens.remove(token_hash);
            return Ok(Presented::Missing);
        }
        let Some(family) = inner.families.get(&id) else {
            return Ok(Presented::Missing);
        };
        if !family.live(now_ms) {
            inner.families.remove(&id);
            return Ok(Presented::Missing);
        }
        if family.current == *token_hash {
            return Ok(Presented::Current(Box::new(RefreshFamily {
                family_id: id,
                grant: family.grant.clone(),
                created_at_ms: family.created_at_ms,
                absolute_expires_at_ms: family.absolute_ms,
                upstream: family.upstream.clone(),
            })));
        }
        if family.previous.is_some_and(|(hash, rotated_at)| {
            hash == *token_hash && now_ms < rotated_at.saturating_add(REUSE_GRACE_MS)
        }) {
            return Ok(Presented::Grace);
        }
        let client_id = family.grant.client_id.clone();
        let ended = inner.families.remove(&id).and_then(Family::ended);
        Ok(Presented::Reused {
            client_id,
            ended: ended.map(Box::new),
        })
    }
    /// Compare-and-swap from `presented` to `next`; `ceiling` is the current absolute expiry.
    pub async fn rotate(
        &self,
        family_id: &str,
        presented: &[u8; 32],
        next: [u8; 32],
        now_ms: u64,
        idle_ttl_seconds: u64,
        ceiling: u64,
    ) -> Result<Rotated, RefreshStoreError> {
        let idle_ms = deadline(now_ms, idle_ttl_seconds, Some(ceiling))
            .ok_or(RefreshStoreError::Unavailable)?;
        let mut inner = self.lock()?;
        if inner.tokens.contains_key(&next) {
            return Err(RefreshStoreError::Unavailable);
        }
        let Some(family) = inner.families.get_mut(family_id) else {
            return Ok(Rotated::Stale);
        };
        if !family.live(now_ms) || family.current != *presented || now_ms >= ceiling {
            return Ok(Rotated::Stale);
        }
        family.previous = Some((*presented, now_ms));
        family.current = next;
        family.idle_ms = idle_ms;
        family.absolute_ms = family.absolute_ms.min(ceiling);
        family.rotated.push_back(*presented);
        let forgotten = (family.rotated.len() > MAX_ROTATED_HASHES)
            .then(|| family.rotated.pop_front())
            .flatten();
        if let Some(forgotten) = forgotten {
            inner.tokens.remove(&forgotten);
        }
        inner.tokens.insert(*presented, (family_id.into(), idle_ms));
        inner.tokens.insert(next, (family_id.into(), idle_ms));
        Ok(Rotated::Rotated)
    }
    /// Replaces the sealed upstream grant of a live family while `generation` is its
    /// upstream generation, whichever token is current: a client's rotation must not
    /// discard an upstream token the provider has already rotated. Repeating a stored
    /// replacement reports `Stored` again.
    pub async fn set_upstream(
        &self,
        family_id: &str,
        generation: u64,
        sealed: &str,
        now_ms: u64,
    ) -> Result<UpstreamStored, RefreshStoreError> {
        let mut inner = self.lock()?;
        let Some(family) = inner.families.get_mut(family_id) else {
            return Ok(UpstreamStored::Stale);
        };
        if !family.live(now_ms) {
            return Ok(UpstreamStored::Stale);
        }
        let Some(upstream) = &mut family.upstream else {
            return Ok(UpstreamStored::Stale);
        };
        if upstream.generation == generation + 1 && upstream.sealed == sealed {
            return Ok(UpstreamStored::Stored);
        }
        if upstream.generation != generation {
            return Ok(UpstreamStored::Stale);
        }
        *upstream = UpstreamState {
            sealed: sealed.to_owned(),
            generation: generation + 1,
        };
        Ok(UpstreamStored::Stored)
    }
    /// Takes the family's upstream refresh lock for `holder` until `expires_ms`. Another
    /// holder's unexpired lock refuses it; the same holder renews its own lock.
    pub async fn lock_upstream(
        &self,
        family_id: &str,
        holder: &str,
        now_ms: u64,
        expires_ms: u64,
    ) -> Result<bool, RefreshStoreError> {
        let mut inner = self.lock()?;
        if inner
            .upstream_locks
            .get(family_id)
            .is_some_and(|(current, expires)| current != holder && now_ms < *expires)
        {
            return Ok(false);
        }
        inner
            .upstream_locks
            .insert(family_id.to_owned(), (holder.to_owned(), expires_ms));
        Ok(true)
    }
    /// Releases the lock only if `holder` still holds it.
    pub async fn unlock_upstream(
        &self,
        family_id: &str,
        holder: &str,
    ) -> Result<(), RefreshStoreError> {
        let mut inner = self.lock()?;
        if inner
            .upstream_locks
            .get(family_id)
            .is_some_and(|(current, _)| current == holder)
        {
            inner.upstream_locks.remove(family_id);
        }
        Ok(())
    }
    pub async fn revoke_family(
        &self,
        family_id: &str,
    ) -> Result<Option<EndedUpstream>, RefreshStoreError> {
        Ok(self
            .lock()?
            .families
            .remove(family_id)
            .and_then(Family::ended))
    }
    /// RFC 7009: any token of a family revokes it, but only for the owning client.
    pub async fn revoke_token(
        &self,
        token_hash: &[u8; 32],
        client_id: &str,
    ) -> Result<Revocation, RefreshStoreError> {
        let mut inner = self.lock()?;
        let Some((id, _)) = inner.tokens.get(token_hash).cloned() else {
            return Ok(Revocation::NotFound);
        };
        if inner
            .families
            .get(&id)
            .is_some_and(|family| family.grant.client_id == client_id)
        {
            let ended = inner.families.remove(&id).and_then(Family::ended);
            return Ok(Revocation::Revoked(ended));
        }
        Ok(Revocation::NotFound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::refresh::tests::grant;

    const NOW: u64 = 1_700_000_000_000;

    fn policy() -> RefreshTokenPolicy {
        RefreshTokenPolicy {
            enabled: true,
            idle_ttl_seconds: 600,
            absolute_ttl_seconds: 3600,
        }
    }
    fn current(presented: Presented) -> RefreshFamily {
        match presented {
            Presented::Current(family) => *family,
            other => panic!("expected current family, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn rotation_grace_and_reuse_revokes_family() {
        let store = MemoryRefreshStore::new(50);
        store
            .issue(&grant(), [1; 32], NOW, &policy(), None)
            .await
            .unwrap();
        let family = current(store.lookup(&[1; 32], NOW).await.unwrap());
        assert_eq!(family.grant, grant());
        assert_eq!(family.absolute_expires_at_ms, NOW + 3_600_000);
        let rotate = |presented, next, at| {
            let id = family.family_id.clone();
            let store = &store;
            async move {
                store
                    .rotate(&id, &presented, next, at, 600, NOW + 3_600_000)
                    .await
                    .unwrap()
            }
        };
        assert_eq!(rotate([1; 32], [2; 32], NOW + 1).await, Rotated::Rotated);
        assert_eq!(rotate([1; 32], [3; 32], NOW + 2).await, Rotated::Stale);
        assert!(matches!(
            store.lookup(&[1; 32], NOW + REUSE_GRACE_MS).await.unwrap(),
            Presented::Grace
        ));
        current(store.lookup(&[2; 32], NOW + 2).await.unwrap());
        assert!(matches!(
            store.lookup(&[1; 32], NOW + 1 + REUSE_GRACE_MS).await.unwrap(),
            Presented::Reused { client_id, ended: None } if client_id == "desktop"
        ));
        assert!(matches!(
            store.lookup(&[2; 32], NOW + 3).await.unwrap(),
            Presented::Missing
        ));
        assert!(matches!(
            store.lookup(&[9; 32], NOW).await.unwrap(),
            Presented::Missing
        ));
    }

    #[tokio::test]
    async fn older_ancestors_are_reuse_even_within_grace() {
        let store = MemoryRefreshStore::new(50);
        store
            .issue(&grant(), [1; 32], NOW, &policy(), None)
            .await
            .unwrap();
        let id = current(store.lookup(&[1; 32], NOW).await.unwrap()).family_id;
        let ceiling = NOW + 3_600_000;
        for (from, to) in [([1; 32], [2; 32]), ([2; 32], [3; 32])] {
            assert_eq!(
                store
                    .rotate(&id, &from, to, NOW, 600, ceiling)
                    .await
                    .unwrap(),
                Rotated::Rotated
            );
        }
        assert!(matches!(
            store.lookup(&[1; 32], NOW).await.unwrap(),
            Presented::Reused { .. }
        ));
        assert!(matches!(
            store.lookup(&[3; 32], NOW).await.unwrap(),
            Presented::Missing
        ));
    }

    #[tokio::test]
    async fn rotated_hashes_are_bounded_and_expire_at_their_idle_deadline() {
        let store = MemoryRefreshStore::new(50);
        store
            .issue(&grant(), [0; 32], NOW, &policy(), None)
            .await
            .unwrap();
        let id = current(store.lookup(&[0; 32], NOW).await.unwrap()).family_id;
        let ceiling = NOW + 3_600_000;
        let hash = |step: usize| [step as u8; 32];
        let rotations = MAX_ROTATED_HASHES + 2;
        for step in 0..rotations {
            let at = NOW + step as u64 * 1_000;
            let rotated = store
                .rotate(&id, &hash(step), hash(step + 1), at, 600, ceiling)
                .await
                .unwrap();
            assert_eq!(rotated, Rotated::Rotated);
        }
        let last = NOW + (rotations as u64 - 1) * 1_000;
        {
            let inner = store.lock().unwrap();
            assert_eq!(inner.tokens.len(), MAX_ROTATED_HASHES + 1);
            assert!(!inner.tokens.contains_key(&hash(1)));
            assert_eq!(inner.tokens[&hash(2)].1, NOW + 2_000 + 600_000);
        }
        // Forgotten ancestors are unknown and leave the family alone.
        assert!(matches!(
            store.lookup(&hash(0), last).await.unwrap(),
            Presented::Missing
        ));
        current(store.lookup(&hash(rotations), last).await.unwrap());
        // A retained ancestor past its own idle deadline is unknown as well.
        assert!(matches!(
            store.lookup(&hash(2), NOW + 602_000).await.unwrap(),
            Presented::Missing
        ));
        current(store.lookup(&hash(rotations), NOW + 602_000).await.unwrap());
        assert!(matches!(
            store.lookup(&hash(3), last).await.unwrap(),
            Presented::Reused { .. }
        ));
        assert!(matches!(
            store.lookup(&hash(rotations), last).await.unwrap(),
            Presented::Missing
        ));
    }

    #[tokio::test]
    async fn idle_and_absolute_expiry_and_rotation_extends_idle_only() {
        let store = MemoryRefreshStore::new(50);
        store
            .issue(&grant(), [1; 32], NOW, &policy(), None)
            .await
            .unwrap();
        assert!(matches!(
            store.lookup(&[1; 32], NOW + 600_000).await.unwrap(),
            Presented::Missing
        ));
        store
            .issue(&grant(), [2; 32], NOW, &policy(), None)
            .await
            .unwrap();
        let id = current(store.lookup(&[2; 32], NOW).await.unwrap()).family_id;
        let mut token = [2; 32];
        let ceiling = NOW + 3_600_000;
        for step in 1..=6u8 {
            let at = NOW + u64::from(step) * 500_000;
            let next = [10 + step; 32];
            let expected = if at < ceiling {
                Rotated::Rotated
            } else {
                Rotated::Stale
            };
            assert_eq!(
                store
                    .rotate(&id, &token, next, at, 600, ceiling)
                    .await
                    .unwrap(),
                expected
            );
            token = next;
        }
        assert!(matches!(
            store.lookup(&token, ceiling).await.unwrap(),
            Presented::Missing
        ));
        store
            .issue(&grant(), [3; 32], NOW, &policy(), None)
            .await
            .unwrap();
        let id = current(store.lookup(&[3; 32], NOW).await.unwrap()).family_id;
        assert_eq!(
            store
                .rotate(&id, &[3; 32], [4; 32], NOW + 1, 600, NOW + 1)
                .await
                .unwrap(),
            Rotated::Stale
        );
    }

    #[tokio::test]
    async fn per_user_cap_evicts_oldest_family_only_for_that_user() {
        let store = MemoryRefreshStore::new(2);
        let mut other = grant();
        other.username = "bob".into();
        store
            .issue(&other, [9; 32], NOW, &policy(), None)
            .await
            .unwrap();
        for (index, token) in [[1; 32], [2; 32], [3; 32]].into_iter().enumerate() {
            store
                .issue(&grant(), token, NOW + index as u64, &policy(), None)
                .await
                .unwrap();
        }
        assert!(matches!(
            store.lookup(&[1; 32], NOW + 5).await.unwrap(),
            Presented::Missing
        ));
        for token in [[2; 32], [3; 32], [9; 32]] {
            current(store.lookup(&token, NOW + 5).await.unwrap());
        }
        assert!(
            store
                .issue(&grant(), [2; 32], NOW, &policy(), None)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn upstream_grants_are_replaced_only_for_the_current_token_and_generation() {
        let store = MemoryRefreshStore::new(50);
        let coupled = RefreshGrant {
            upstream_coupled: true,
            ..grant()
        };
        store
            .issue(&coupled, [1; 32], NOW, &policy(), Some("v1.k.first"))
            .await
            .unwrap();
        let family = current(store.lookup(&[1; 32], NOW).await.unwrap());
        assert!(family.grant.upstream_coupled);
        let state = family.upstream.unwrap();
        assert_eq!((state.sealed.as_str(), state.generation), ("v1.k.first", 0));
        let id = family.family_id;
        let set = |id: &str, generation, sealed: &'static str, now| {
            let (store, id) = (&store, id.to_owned());
            async move {
                store
                    .set_upstream(&id, generation, sealed, now)
                    .await
                    .unwrap()
            }
        };
        assert_eq!(
            set("other", 0, "v1.k.second", NOW).await,
            UpstreamStored::Stale
        );
        assert_eq!(set(&id, 1, "v1.k.second", NOW).await, UpstreamStored::Stale);
        assert_eq!(
            set(&id, 0, "v1.k.second", NOW).await,
            UpstreamStored::Stored
        );
        // A repeated request after a lost answer is recognised as stored.
        assert_eq!(
            set(&id, 0, "v1.k.second", NOW).await,
            UpstreamStored::Stored
        );
        assert_eq!(set(&id, 0, "v1.k.other", NOW).await, UpstreamStored::Stale);
        let state = current(store.lookup(&[1; 32], NOW).await.unwrap())
            .upstream
            .unwrap();
        assert_eq!(
            (state.sealed.as_str(), state.generation),
            ("v1.k.second", 1)
        );
        // The family's own rotation does not block a replacement for its generation.
        store
            .rotate(&id, &[1; 32], [2; 32], NOW, 600, NOW + 3_600_000)
            .await
            .unwrap();
        assert_eq!(set(&id, 1, "v1.k.third", NOW).await, UpstreamStored::Stored);
        assert_eq!(
            set(&id, 2, "v1.k.fourth", NOW + 600_000).await,
            UpstreamStored::Stale
        );
        store
            .issue(&grant(), [5; 32], NOW, &policy(), None)
            .await
            .unwrap();
        let plain = current(store.lookup(&[5; 32], NOW).await.unwrap());
        assert!(plain.upstream.is_none());
        assert_eq!(
            store
                .set_upstream(&plain.family_id, 0, "v1.k.x", NOW)
                .await
                .unwrap(),
            UpstreamStored::Stale
        );
    }

    #[tokio::test]
    async fn upstream_locks_exclude_other_holders_until_released_or_expired() {
        let store = MemoryRefreshStore::new(50);
        assert!(store.lock_upstream("f", "a", NOW, NOW + 10).await.unwrap());
        assert!(
            !store
                .lock_upstream("f", "b", NOW + 1, NOW + 20)
                .await
                .unwrap()
        );
        // Other families and a renewal by the holder are unaffected.
        assert!(
            store
                .lock_upstream("g", "b", NOW + 1, NOW + 20)
                .await
                .unwrap()
        );
        assert!(
            store
                .lock_upstream("f", "a", NOW + 2, NOW + 30)
                .await
                .unwrap()
        );
        store.unlock_upstream("f", "b").await.unwrap();
        assert!(
            !store
                .lock_upstream("f", "b", NOW + 3, NOW + 40)
                .await
                .unwrap()
        );
        store.unlock_upstream("f", "a").await.unwrap();
        assert!(
            store
                .lock_upstream("f", "b", NOW + 4, NOW + 40)
                .await
                .unwrap()
        );
        // An expired lock no longer excludes anyone.
        assert!(
            store
                .lock_upstream("f", "c", NOW + 40, NOW + 50)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn revocation_requires_owning_client_and_accepts_any_family_token() {
        let store = MemoryRefreshStore::new(50);
        store
            .issue(&grant(), [1; 32], NOW, &policy(), None)
            .await
            .unwrap();
        let id = current(store.lookup(&[1; 32], NOW).await.unwrap()).family_id;
        store
            .rotate(&id, &[1; 32], [2; 32], NOW, 600, NOW + 3_600_000)
            .await
            .unwrap();
        assert!(matches!(
            store.revoke_token(&[1; 32], "other").await.unwrap(),
            Revocation::NotFound
        ));
        assert!(matches!(
            store.revoke_token(&[7; 32], "desktop").await.unwrap(),
            Revocation::NotFound
        ));
        current(store.lookup(&[2; 32], NOW).await.unwrap());
        assert!(matches!(
            store.revoke_token(&[1; 32], "desktop").await.unwrap(),
            Revocation::Revoked(None)
        ));
        assert!(matches!(
            store.lookup(&[2; 32], NOW).await.unwrap(),
            Presented::Missing
        ));
        assert!(matches!(
            store.revoke_token(&[2; 32], "desktop").await.unwrap(),
            Revocation::NotFound
        ));
        store
            .issue(&grant(), [5; 32], NOW, &policy(), None)
            .await
            .unwrap();
        let id = current(store.lookup(&[5; 32], NOW).await.unwrap()).family_id;
        store.revoke_family(&id).await.unwrap();
        assert!(matches!(
            store.lookup(&[5; 32], NOW).await.unwrap(),
            Presented::Missing
        ));
    }

    #[tokio::test]
    async fn ending_coupled_families_returns_their_sealed_upstream_grants() {
        let store = MemoryRefreshStore::new(2);
        let coupled = |n: u8| RefreshGrant {
            upstream_coupled: true,
            method: format!("sso-{n}"),
            ..grant()
        };
        let issue = |n: u8| {
            let store = &store;
            async move {
                store
                    .issue(
                        &coupled(n),
                        [n; 32],
                        NOW + u64::from(n),
                        &policy(),
                        Some(&format!("v1.k.{n}")),
                    )
                    .await
                    .unwrap()
            }
        };
        let named = |ended: EndedUpstream| (ended.grant.method, ended.sealed);
        let expected = |n: u8| (format!("sso-{n}"), format!("v1.k.{n}"));
        assert!(issue(1).await.is_empty() && issue(2).await.is_empty());
        // The per-user cap evicts the oldest family, which is coupled.
        let evicted = store
            .issue(&grant(), [3; 32], NOW + 3, &policy(), None)
            .await
            .unwrap();
        assert_eq!(
            evicted.into_iter().map(named).collect::<Vec<_>>(),
            [expected(1)]
        );
        match store.revoke_token(&[2; 32], "desktop").await.unwrap() {
            Revocation::Revoked(Some(ended)) => assert_eq!(named(ended), expected(2)),
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            store.revoke_token(&[3; 32], "desktop").await.unwrap(),
            Revocation::Revoked(None)
        ));
        issue(4).await;
        let id = current(store.lookup(&[4; 32], NOW).await.unwrap()).family_id;
        store
            .rotate(&id, &[4; 32], [5; 32], NOW + 4, 600, NOW + 3_600_000)
            .await
            .unwrap();
        match store
            .lookup(&[4; 32], NOW + 4 + REUSE_GRACE_MS)
            .await
            .unwrap()
        {
            Presented::Reused {
                ended: Some(ended), ..
            } => assert_eq!(named(*ended), expected(4)),
            other => panic!("{other:?}"),
        }
        issue(6).await;
        let id = current(store.lookup(&[6; 32], NOW).await.unwrap()).family_id;
        let ended = store.revoke_family(&id).await.unwrap().map(named);
        assert_eq!(ended, Some(expected(6)));
        assert!(store.revoke_family(&id).await.unwrap().is_none());
    }
}

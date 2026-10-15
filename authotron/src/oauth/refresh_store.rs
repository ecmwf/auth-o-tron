// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! Process-local refresh-token families for single-replica deployments.

use super::refresh::{
    EndedFamily, FamilySummary, MAX_RETRIES_PER_ROTATION, MAX_RETRY_WINDOW_MS, MAX_ROTATED_HASHES,
    Presented, RefreshFamily, RefreshGrant, RefreshStoreError, Repetition, Revocation, Rotated,
    Rotation, UpstreamState, UpstreamStored, deadline, initial_expiry, random_id,
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
    previous: Option<Previous>,
    /// Consecutive rotations, up to the latest, that were answered again.
    streak: u32,
    /// Recently rotated hashes, oldest first, at most [`MAX_ROTATED_HASHES`].
    rotated: VecDeque<[u8; 32]>,
    upstream: Option<UpstreamState>,
}

/// The token the latest rotation replaced: when, the current token sealed by it, and
/// how often the rotation was answered again for it.
struct Previous {
    hash: [u8; 32],
    rotated_at_ms: u64,
    sealed: String,
    retries: u32,
}

impl Family {
    fn live(&self, now_ms: u64) -> bool {
        now_ms < self.idle_ms && now_ms < self.absolute_ms
    }
    fn view(&self, family_id: String) -> Box<RefreshFamily> {
        Box::new(RefreshFamily {
            family_id,
            grant: self.grant.clone(),
            created_at_ms: self.created_at_ms,
            absolute_expires_at_ms: self.absolute_ms,
            upstream: self.upstream.clone(),
        })
    }
    /// Answers the latest rotation again for its previous token `presented`, within
    /// `window_ms` of it and at most [`MAX_RETRIES_PER_ROTATION`] times.
    fn repeat(
        &mut self,
        presented: &[u8; 32],
        window_ms: u64,
        now_ms: u64,
    ) -> Option<Box<Repetition>> {
        let previous = self.previous.as_mut().filter(|previous| {
            previous.hash == *presented
                && now_ms < previous.rotated_at_ms.saturating_add(window_ms)
                && previous.retries < MAX_RETRIES_PER_ROTATION
        })?;
        if previous.retries == 0 {
            self.streak += 1;
        }
        previous.retries += 1;
        Some(Box::new(Repetition {
            current: self.current,
            sealed: previous.sealed.clone(),
            retries: previous.retries,
            streak: self.streak,
        }))
    }
    fn summary(&self, family_id: String) -> FamilySummary {
        FamilySummary {
            family_id,
            grant: self.grant.clone(),
            created_at_ms: self.created_at_ms,
            last_used_at_ms: self
                .previous
                .as_ref()
                .map_or(self.created_at_ms, |previous| previous.rotated_at_ms),
            idle_expires_at_ms: self.idle_ms,
            absolute_expires_at_ms: self.absolute_ms,
        }
    }
    fn ended(self, family_id: String) -> EndedFamily {
        EndedFamily {
            family_id,
            grant: self.grant,
            sealed: self.upstream.map(|upstream| upstream.sealed),
        }
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
    /// The live family a token belongs to.
    fn family_of(&mut self, token_hash: &[u8; 32], now_ms: u64) -> Option<&mut Family> {
        let (id, _) = self.tokens.get(token_hash)?;
        self.families
            .get_mut(id)
            .filter(|family| family.live(now_ms))
    }
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
    /// per-user cap the user's oldest families are revoked and returned.
    pub async fn issue(
        &self,
        grant: &RefreshGrant,
        token_hash: [u8; 32],
        now_ms: u64,
        policy: &RefreshTokenPolicy,
        upstream: Option<&str>,
    ) -> Result<Vec<EndedFamily>, RefreshStoreError> {
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
            .filter_map(|(_, id)| Some(inner.families.remove(&id)?.ended(id)))
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
                streak: 0,
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
    /// Classifies a presented hash; any rotated token but the previous one within
    /// [`MAX_RETRY_WINDOW_MS`] of its rotation is reuse and revokes the family.
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
            return Ok(Presented::Current(family.view(id)));
        }
        if let Some(previous) = family.previous.as_ref().filter(|previous| {
            previous.hash == *token_hash
                && now_ms < previous.rotated_at_ms.saturating_add(MAX_RETRY_WINDOW_MS)
        }) {
            return Ok(Presented::Previous(family.view(id), previous.rotated_at_ms));
        }
        let Some(family) = inner.families.remove(&id) else {
            return Ok(Presented::Missing);
        };
        Ok(Presented::Reused(Box::new(family.ended(id))))
    }
    /// Rotates the family of `presented` if that token is still its current one. If it
    /// is the previous one, the latest rotation is answered again as by
    /// [`Self::repeat`]: a concurrent refresh applied it.
    pub async fn rotate(
        &self,
        presented: &[u8; 32],
        rotation: &Rotation<'_>,
        now_ms: u64,
    ) -> Result<Rotated, RefreshStoreError> {
        let Rotation {
            next,
            sealed,
            grant,
            idle_ttl_seconds,
            ceiling,
            retry_window_ms,
        } = *rotation;
        let idle_ms = deadline(now_ms, idle_ttl_seconds, Some(ceiling))
            .ok_or(RefreshStoreError::Unavailable)?;
        grant.encode()?;
        let mut inner = self.lock()?;
        let collision = inner.tokens.contains_key(&next);
        let Some(family) = inner.family_of(presented, now_ms) else {
            return Ok(Rotated::Stale);
        };
        if family
            .previous
            .as_ref()
            .is_some_and(|previous| previous.hash == *presented)
        {
            // This very rotation, run again after a lost reply, is already applied.
            if family.current == next {
                return Ok(Rotated::Rotated);
            }
            return Ok(family
                .repeat(presented, retry_window_ms, now_ms)
                .map_or(Rotated::Stale, Rotated::Repeated));
        }
        if family.current != *presented || now_ms >= ceiling {
            return Ok(Rotated::Stale);
        }
        if collision {
            return Err(RefreshStoreError::Unavailable);
        }
        // The streak goes on only if the rotation that ends now was answered again.
        if !family
            .previous
            .as_ref()
            .is_some_and(|previous| previous.retries > 0)
        {
            family.streak = 0;
        }
        family.grant = grant.clone();
        family.previous = Some(Previous {
            hash: *presented,
            rotated_at_ms: now_ms,
            sealed: sealed.to_owned(),
            retries: 0,
        });
        family.current = next;
        family.idle_ms = idle_ms;
        family.absolute_ms = family.absolute_ms.min(ceiling);
        family.rotated.push_back(*presented);
        let forgotten = (family.rotated.len() > MAX_ROTATED_HASHES)
            .then(|| family.rotated.pop_front())
            .flatten();
        let family_id = inner.tokens[presented].0.clone();
        if let Some(forgotten) = forgotten {
            inner.tokens.remove(&forgotten);
        }
        inner
            .tokens
            .insert(*presented, (family_id.clone(), idle_ms));
        inner.tokens.insert(next, (family_id, idle_ms));
        Ok(Rotated::Rotated)
    }
    /// Answers the latest rotation of the family of `presented` again, if that is its
    /// previous token, within `window_ms` of the rotation and at most
    /// [`MAX_RETRIES_PER_ROTATION`] times; otherwise `None`.
    pub async fn repeat(
        &self,
        presented: &[u8; 32],
        window_ms: u64,
        now_ms: u64,
    ) -> Result<Option<Box<Repetition>>, RefreshStoreError> {
        let mut inner = self.lock()?;
        Ok(inner
            .family_of(presented, now_ms)
            .and_then(|family| family.repeat(presented, window_ms, now_ms)))
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
    ) -> Result<Option<EndedFamily>, RefreshStoreError> {
        Ok(self
            .lock()?
            .families
            .remove(family_id)
            .map(|family| family.ended(family_id.to_owned())))
    }
    /// The live families of the user with the key `user_key` (see
    /// [`super::refresh::user_key`]), newest first, at most `limit`.
    pub async fn families_of(
        &self,
        user_key: &str,
        limit: usize,
        now_ms: u64,
    ) -> Result<Vec<FamilySummary>, RefreshStoreError> {
        let inner = self.lock()?;
        let mut families: Vec<_> = inner
            .families
            .iter()
            .filter(|(_, family)| family.user_key == user_key && family.live(now_ms))
            .map(|(id, family)| family.summary(id.clone()))
            .collect();
        families
            .sort_by(|a, b| (b.created_at_ms, &b.family_id).cmp(&(a.created_at_ms, &a.family_id)));
        families.truncate(limit);
        Ok(families)
    }
    /// Revokes every live family of the user with the key `user_key` and returns them.
    pub async fn revoke_user(
        &self,
        user_key: &str,
        now_ms: u64,
    ) -> Result<Vec<EndedFamily>, RefreshStoreError> {
        let mut inner = self.lock()?;
        inner.prune(now_ms);
        let owned: Vec<String> = inner
            .families
            .iter()
            .filter(|(_, family)| family.user_key == user_key)
            .map(|(id, _)| id.clone())
            .collect();
        Ok(owned
            .into_iter()
            .filter_map(|id| Some(inner.families.remove(&id)?.ended(id)))
            .collect())
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
            && let Some(family) = inner.families.remove(&id)
        {
            return Ok(Revocation::Revoked(Box::new(family.ended(id))));
        }
        Ok(Revocation::NotFound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::refresh::tests::{grant, rotation};

    const NOW: u64 = 1_700_000_000_000;

    fn policy() -> RefreshTokenPolicy {
        RefreshTokenPolicy {
            enabled: true,
            idle_ttl_seconds: 600,
            absolute_ttl_seconds: 3600,
            upstream_offline_access: false,
            retry_window_seconds: 30,
        }
    }
    fn current(presented: Presented) -> RefreshFamily {
        match presented {
            Presented::Current(family) => *family,
            other => panic!("expected current family, got {other:?}"),
        }
    }

    fn repetition(current: u8, retries: u32, streak: u32) -> Option<Box<Repetition>> {
        Some(Box::new(Repetition {
            current: [current; 32],
            sealed: format!("sealed-{current}"),
            retries,
            streak,
        }))
    }

    #[tokio::test]
    async fn rotation_previous_token_and_reuse_revokes_family() {
        let store = MemoryRefreshStore::new(50);
        store
            .issue(&grant(), [1; 32], NOW, &policy(), None)
            .await
            .unwrap();
        let family = current(store.lookup(&[1; 32], NOW).await.unwrap());
        assert_eq!(family.grant, grant());
        assert_eq!(family.absolute_expires_at_ms, NOW + 3_600_000);
        let rotate = |presented, next, at| {
            let store = &store;
            async move {
                store
                    .rotate(&presented, &rotation(next, &grant(), NOW + 3_600_000), at)
                    .await
                    .unwrap()
            }
        };
        assert_eq!(rotate([1; 32], [2; 32], NOW + 1).await, Rotated::Rotated);
        // The same rotation run again, as after a lost reply, is reported applied, also
        // without a retry window, and is no repetition.
        let fixture = grant();
        let resent = Rotation {
            retry_window_ms: 0,
            ..rotation([2; 32], &fixture, NOW + 3_600_000)
        };
        assert_eq!(
            store.rotate(&[1; 32], &resent, NOW + 2).await.unwrap(),
            Rotated::Rotated
        );
        // The previous token answers the latest rotation again, with its sealed token,
        // within the retry window and at most MAX_RETRIES_PER_ROTATION times.
        let closed = Rotation {
            retry_window_ms: 1,
            ..rotation([3; 32], &fixture, NOW + 3_600_000)
        };
        assert_eq!(
            store.rotate(&[1; 32], &closed, NOW + 2).await.unwrap(),
            Rotated::Stale
        );
        for retries in 1..=MAX_RETRIES_PER_ROTATION {
            assert_eq!(
                rotate([1; 32], [3; 32], NOW + 2).await,
                Rotated::Repeated(repetition(2, retries, 1).unwrap())
            );
        }
        assert_eq!(rotate([1; 32], [3; 32], NOW + 2).await, Rotated::Stale);
        match store
            .lookup(&[1; 32], NOW + MAX_RETRY_WINDOW_MS)
            .await
            .unwrap()
        {
            Presented::Previous(previous, rotated_at) => {
                assert_eq!(
                    (previous.family_id, rotated_at),
                    (family.family_id, NOW + 1)
                );
                assert_eq!(previous.grant, grant());
            }
            other => panic!("expected the previous token, got {other:?}"),
        }
        current(store.lookup(&[2; 32], NOW + 2).await.unwrap());
        assert!(matches!(
            store.lookup(&[1; 32], NOW + 1 + MAX_RETRY_WINDOW_MS).await.unwrap(),
            Presented::Reused(ended) if ended.grant.client_id == "desktop" && ended.sealed.is_none()
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
    async fn previous_tokens_repeat_the_latest_rotation_within_window_and_cap() {
        let store = MemoryRefreshStore::new(50);
        store
            .issue(&grant(), [1; 32], NOW, &policy(), None)
            .await
            .unwrap();
        let ceiling = NOW + 3_600_000;
        let rotate = |from: u8, at| {
            let store = &store;
            async move {
                let grant = grant();
                let rotation = rotation([from + 1; 32], &grant, ceiling);
                store.rotate(&[from; 32], &rotation, at).await.unwrap()
            }
        };
        let repeat = |from: u8, window, at| {
            let store = &store;
            async move { store.repeat(&[from; 32], window, at).await.unwrap() }
        };
        assert_eq!(rotate(1, NOW).await, Rotated::Rotated);
        assert_eq!(repeat(1, 10, NOW + 10).await, None, "outside its window");
        for retries in 1..=MAX_RETRIES_PER_ROTATION {
            assert_eq!(repeat(1, 10, NOW + 9).await, repetition(2, retries, 1));
        }
        assert_eq!(repeat(1, 10, NOW + 9).await, None, "past the cap");
        assert_eq!(repeat(2, 10, NOW + 9).await, None, "the current token");
        // Rotations answered again in a row lengthen the streak; one that is not
        // breaks it.
        assert_eq!(rotate(2, NOW + 1).await, Rotated::Rotated);
        assert_eq!(repeat(2, 10, NOW + 2).await, repetition(3, 1, 2));
        assert_eq!(rotate(3, NOW + 3).await, Rotated::Rotated);
        assert_eq!(rotate(4, NOW + 4).await, Rotated::Rotated);
        assert_eq!(repeat(4, 10, NOW + 5).await, repetition(5, 1, 1));
        assert_eq!(repeat(2, 10, NOW + 5).await, None, "an older token");
        // A rotation of the previous token honours the window it is given.
        let grant = grant();
        let closed = Rotation {
            retry_window_ms: 0,
            ..rotation([9; 32], &grant, ceiling)
        };
        assert_eq!(
            store.rotate(&[4; 32], &closed, NOW + 5).await.unwrap(),
            Rotated::Stale
        );
    }

    #[tokio::test]
    async fn older_ancestors_are_reuse_even_within_the_retry_window() {
        let store = MemoryRefreshStore::new(50);
        store
            .issue(&grant(), [1; 32], NOW, &policy(), None)
            .await
            .unwrap();
        let ceiling = NOW + 3_600_000;
        for (from, to) in [([1; 32], [2; 32]), ([2; 32], [3; 32])] {
            assert_eq!(
                store
                    .rotate(&from, &rotation(to, &grant(), ceiling), NOW)
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
        let ceiling = NOW + 3_600_000;
        let hash = |step: usize| [step as u8; 32];
        let rotations = MAX_ROTATED_HASHES + 2;
        for step in 0..rotations {
            let at = NOW + step as u64 * 1_000;
            let rotated = store
                .rotate(
                    &hash(step),
                    &rotation(hash(step + 1), &grant(), ceiling),
                    at,
                )
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
                    .rotate(&token, &rotation(next, &grant(), ceiling), at)
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
        assert_eq!(
            store
                .rotate(&[3; 32], &rotation([4; 32], &grant(), NOW + 1), NOW + 1)
                .await
                .unwrap(),
            Rotated::Stale
        );
    }

    #[tokio::test]
    async fn rotation_stores_the_grant_its_successor_carries() {
        let store = MemoryRefreshStore::new(50);
        let coupled = RefreshGrant {
            upstream_coupled: true,
            ..grant()
        };
        store
            .issue(&coupled, [1; 32], NOW, &policy(), Some("v1.k.first"))
            .await
            .unwrap();
        let ceiling = NOW + 3_600_000;
        let rotate = |next, grant| {
            let store = &store;
            async move {
                store
                    .rotate(&[1; 32], &rotation(next, grant, ceiling), NOW)
                    .await
            }
        };
        let oversized = RefreshGrant {
            provider_roles: vec!["r".repeat(64); 1024],
            ..coupled.clone()
        };
        assert!(rotate([2; 32], &oversized).await.is_err());
        let refreshed = RefreshGrant {
            provider_roles: vec!["writer".into()],
            ..coupled.clone()
        };
        assert_eq!(rotate([2; 32], &refreshed).await, Ok(Rotated::Rotated));
        assert_eq!(
            current(store.lookup(&[2; 32], NOW).await.unwrap()).grant,
            refreshed
        );
        // Answering the rotation again leaves the stored grant alone.
        assert!(matches!(
            rotate([3; 32], &coupled).await,
            Ok(Rotated::Repeated(_))
        ));
        assert_eq!(
            current(store.lookup(&[2; 32], NOW).await.unwrap()).grant,
            refreshed
        );
    }

    #[tokio::test]
    async fn a_users_families_are_listed_newest_first_and_revoked_together() {
        let store = MemoryRefreshStore::new(50);
        let bob = RefreshGrant {
            username: "bob".into(),
            ..grant()
        };
        for (index, (grant, token)) in [(grant(), 1), (grant(), 2), (bob.clone(), 3), (grant(), 4)]
            .into_iter()
            .enumerate()
        {
            store
                .issue(&grant, [token; 32], NOW + index as u64, &policy(), None)
                .await
                .unwrap();
        }
        let ceiling = NOW + 3_600_000;
        let rotated = store
            .rotate(&[1; 32], &rotation([5; 32], &grant(), ceiling), NOW + 10)
            .await
            .unwrap();
        assert_eq!(rotated, Rotated::Rotated);
        let alice = grant().user_key();
        let listed = store.families_of(&alice, 50, NOW + 20).await.unwrap();
        let created: Vec<_> = listed.iter().map(|family| family.created_at_ms).collect();
        assert_eq!(created, [NOW + 3, NOW + 1, NOW]);
        assert!(listed.iter().all(|family| family.grant == grant()));
        let oldest = &listed[2];
        assert_eq!(oldest.last_used_at_ms, NOW + 10);
        assert_eq!(oldest.idle_expires_at_ms, NOW + 10 + 600_000);
        assert_eq!(oldest.absolute_expires_at_ms, ceiling);
        assert_eq!(listed[0].last_used_at_ms, NOW + 3);
        let newest = store.families_of(&alice, 2, NOW + 20).await.unwrap();
        assert_eq!(newest, listed[..2]);
        // Families past their idle deadline are not listed.
        let late = store.families_of(&alice, 50, NOW + 600_005).await.unwrap();
        assert_eq!(late, listed[2..]);

        let ended = store.revoke_user(&alice, NOW + 20).await.unwrap();
        let mut ids: Vec<_> = ended
            .iter()
            .map(|family| family.family_id.clone())
            .collect();
        ids.sort();
        let mut expected: Vec<_> = listed
            .iter()
            .map(|family| family.family_id.clone())
            .collect();
        expected.sort();
        assert_eq!(ids, expected);
        assert!(
            store
                .families_of(&alice, 50, NOW + 20)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            store
                .revoke_user(&alice, NOW + 20)
                .await
                .unwrap()
                .is_empty()
        );
        for token in [[2; 32], [4; 32], [5; 32]] {
            assert!(matches!(
                store.lookup(&token, NOW + 20).await.unwrap(),
                Presented::Missing
            ));
        }
        let bobs = store
            .families_of(&bob.user_key(), 50, NOW + 20)
            .await
            .unwrap();
        assert_eq!(bobs.len(), 1);
        current(store.lookup(&[3; 32], NOW + 20).await.unwrap());
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
            .rotate(&[1; 32], &rotation([2; 32], &coupled, NOW + 3_600_000), NOW)
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
        store
            .rotate(&[1; 32], &rotation([2; 32], &grant(), NOW + 3_600_000), NOW)
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
        let id = current(store.lookup(&[2; 32], NOW).await.unwrap()).family_id;
        assert!(matches!(
            store.revoke_token(&[1; 32], "desktop").await.unwrap(),
            Revocation::Revoked(ended) if ended.family_id == id && ended.sealed.is_none()
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
    async fn ended_families_carry_their_id_grant_and_sealed_upstream_grant() {
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
        let named = |ended: EndedFamily| (ended.grant.method, ended.sealed);
        let expected = |n: u8| (format!("sso-{n}"), Some(format!("v1.k.{n}")));
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
            Revocation::Revoked(ended) => assert_eq!(named(*ended), expected(2)),
            other => panic!("{other:?}"),
        }
        // An uncoupled family is reported without a sealed grant.
        let id = current(store.lookup(&[3; 32], NOW + 3).await.unwrap()).family_id;
        match store.revoke_token(&[3; 32], "desktop").await.unwrap() {
            Revocation::Revoked(ended) => {
                assert_eq!((ended.family_id, ended.sealed), (id, None));
            }
            other => panic!("{other:?}"),
        }
        issue(4).await;
        let coupled_4 = coupled(4);
        store
            .rotate(
                &[4; 32],
                &rotation([5; 32], &coupled_4, NOW + 3_600_000),
                NOW + 4,
            )
            .await
            .unwrap();
        match store
            .lookup(&[4; 32], NOW + 4 + MAX_RETRY_WINDOW_MS)
            .await
            .unwrap()
        {
            Presented::Reused(ended) => assert_eq!(named(*ended), expected(4)),
            other => panic!("{other:?}"),
        }
        issue(6).await;
        let id = current(store.lookup(&[6; 32], NOW).await.unwrap()).family_id;
        let ended = store.revoke_family(&id).await.unwrap().map(named);
        assert_eq!(ended, Some(expected(6)));
        assert!(store.revoke_family(&id).await.unwrap().is_none());
    }
}

// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! Process-local refresh-token families for single-replica deployments.

use super::refresh::{
    Presented, REUSE_GRACE_MS, RefreshFamily, RefreshGrant, RefreshStoreError, Rotated, deadline,
    initial_expiry, random_id,
};
use crate::config::RefreshTokenPolicy;
use std::{collections::HashMap, sync::Mutex};

struct Family {
    grant: RefreshGrant,
    user_key: String,
    created_at_ms: u64,
    absolute_ms: u64,
    idle_ms: u64,
    current: [u8; 32],
    previous: Option<([u8; 32], u64)>,
}
impl Family {
    fn live(&self, now_ms: u64) -> bool {
        now_ms < self.idle_ms && now_ms < self.absolute_ms
    }
}

#[derive(Default)]
struct Inner {
    families: HashMap<String, Family>,
    /// Every hash ever issued for a live family, kept until the family's absolute
    /// expiry so rotated tokens remain recognisable for reuse detection.
    tokens: HashMap<[u8; 32], String>,
}
impl Inner {
    fn prune(&mut self, now_ms: u64) {
        self.families.retain(|_, family| family.live(now_ms));
        let families = &self.families;
        self.tokens.retain(|_, id| families.contains_key(id));
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
    /// Starts a family; at the per-user cap the user's oldest families are revoked.
    pub async fn issue(
        &self,
        grant: &RefreshGrant,
        token_hash: [u8; 32],
        now_ms: u64,
        policy: &RefreshTokenPolicy,
    ) -> Result<(), RefreshStoreError> {
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
        for (_, id) in owned.into_iter().take(excess) {
            inner.families.remove(&id);
        }
        inner.tokens.insert(token_hash, family_id.clone());
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
            },
        );
        inner.prune(now_ms);
        Ok(())
    }
    /// Classifies a presented hash; reuse outside the grace window revokes the family.
    pub async fn lookup(
        &self,
        token_hash: &[u8; 32],
        now_ms: u64,
    ) -> Result<Presented, RefreshStoreError> {
        let mut inner = self.lock()?;
        let Some(id) = inner.tokens.get(token_hash).cloned() else {
            return Ok(Presented::Missing);
        };
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
            })));
        }
        if family.previous.is_some_and(|(hash, rotated_at)| {
            hash == *token_hash && now_ms < rotated_at.saturating_add(REUSE_GRACE_MS)
        }) {
            return Ok(Presented::Grace);
        }
        let client_id = family.grant.client_id.clone();
        inner.families.remove(&id);
        Ok(Presented::Reused { client_id })
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
        inner.tokens.insert(next, family_id.into());
        Ok(Rotated::Rotated)
    }
    pub async fn revoke_family(&self, family_id: &str) -> Result<(), RefreshStoreError> {
        self.lock()?.families.remove(family_id);
        Ok(())
    }
    /// RFC 7009: any token of a family revokes it, but only for the owning client.
    pub async fn revoke_token(
        &self,
        token_hash: &[u8; 32],
        client_id: &str,
    ) -> Result<bool, RefreshStoreError> {
        let mut inner = self.lock()?;
        let Some(id) = inner.tokens.get(token_hash).cloned() else {
            return Ok(false);
        };
        if inner
            .families
            .get(&id)
            .is_some_and(|family| family.grant.client_id == client_id)
        {
            inner.families.remove(&id);
            return Ok(true);
        }
        Ok(false)
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
            .issue(&grant(), [1; 32], NOW, &policy())
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
            Presented::Reused { client_id } if client_id == "desktop"
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
            .issue(&grant(), [1; 32], NOW, &policy())
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
    async fn idle_and_absolute_expiry_and_rotation_extends_idle_only() {
        let store = MemoryRefreshStore::new(50);
        store
            .issue(&grant(), [1; 32], NOW, &policy())
            .await
            .unwrap();
        assert!(matches!(
            store.lookup(&[1; 32], NOW + 600_000).await.unwrap(),
            Presented::Missing
        ));
        store
            .issue(&grant(), [2; 32], NOW, &policy())
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
            .issue(&grant(), [3; 32], NOW, &policy())
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
        store.issue(&other, [9; 32], NOW, &policy()).await.unwrap();
        for (index, token) in [[1; 32], [2; 32], [3; 32]].into_iter().enumerate() {
            store
                .issue(&grant(), token, NOW + index as u64, &policy())
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
                .issue(&grant(), [2; 32], NOW, &policy())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn revocation_requires_owning_client_and_accepts_any_family_token() {
        let store = MemoryRefreshStore::new(50);
        store
            .issue(&grant(), [1; 32], NOW, &policy())
            .await
            .unwrap();
        let id = current(store.lookup(&[1; 32], NOW).await.unwrap()).family_id;
        store
            .rotate(&id, &[1; 32], [2; 32], NOW, 600, NOW + 3_600_000)
            .await
            .unwrap();
        assert!(!store.revoke_token(&[1; 32], "other").await.unwrap());
        assert!(!store.revoke_token(&[7; 32], "desktop").await.unwrap());
        current(store.lookup(&[2; 32], NOW).await.unwrap());
        assert!(store.revoke_token(&[1; 32], "desktop").await.unwrap());
        assert!(matches!(
            store.lookup(&[2; 32], NOW).await.unwrap(),
            Presented::Missing
        ));
        assert!(!store.revoke_token(&[2; 32], "desktop").await.unwrap());
        store
            .issue(&grant(), [5; 32], NOW, &policy())
            .await
            .unwrap();
        let id = current(store.lookup(&[5; 32], NOW).await.unwrap()).family_id;
        store.revoke_family(&id).await.unwrap();
        assert!(matches!(
            store.lookup(&[5; 32], NOW).await.unwrap(),
            Presented::Missing
        ));
    }
}

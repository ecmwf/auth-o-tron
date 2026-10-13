// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! Shared refresh-token families in Valkey; every mutation is one atomic Lua script.

use super::refresh::{
    MAX_ROTATED_HASHES, Presented, REUSE_GRACE_MS, RefreshFamily, RefreshGrant, RefreshStoreError,
    Rotated, UpstreamState, UpstreamStored, deadline, initial_expiry, random_id,
};
use super::refresh_durability::{self, Durability};
use crate::{
    config::{RefreshTokenPolicy, ui::BrowserBackendConfig},
    utils::valkey::ValkeyConnection,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

const SCRIPT: &str = include_str!("valkey_refresh.lua");

pub struct ValkeyRefreshStore {
    connection: ValkeyConnection,
    prefix: String,
    max_per_user: usize,
}

fn number(bytes: &[u8]) -> Result<u64, RefreshStoreError> {
    std::str::from_utf8(bytes)
        .ok()
        .and_then(|value| value.parse().ok())
        .ok_or(RefreshStoreError::Unavailable)
}
fn text(bytes: &[u8]) -> Result<String, RefreshStoreError> {
    String::from_utf8(bytes.to_vec()).map_err(|_| RefreshStoreError::Unavailable)
}

impl ValkeyRefreshStore {
    pub async fn new(
        backend: &BrowserBackendConfig,
        max_per_user: usize,
    ) -> Result<Self, RefreshStoreError> {
        let BrowserBackendConfig::Valkey { key_prefix, .. } = backend else {
            return Err(RefreshStoreError::Unavailable);
        };
        let connection = ValkeyConnection::connect(backend)
            .await
            .map_err(|_| RefreshStoreError::Unavailable)?;
        Ok(Self {
            connection,
            prefix: format!("{key_prefix}:oauth:refresh-tokens:v2:"),
            max_per_user,
        })
    }
    /// Reads `INFO persistence`; any failure, including ACL denial, is `Unverified`.
    pub(crate) async fn durability(&self) -> Durability {
        match self
            .connection
            .query::<String>(redis::cmd("INFO").arg("persistence"))
            .await
        {
            Ok(info) => refresh_durability::from_info(&info),
            Err(_) => Durability::Unverified,
        }
    }
    fn token_key(&self, hash: &[u8; 32]) -> String {
        format!("{}token:{}", self.prefix, URL_SAFE_NO_PAD.encode(hash))
    }
    fn lock_key(&self, family_id: &str) -> String {
        format!("{}lock:{family_id}", self.prefix)
    }
    async fn run(
        &self,
        keys: &[String],
        op: &str,
        now_ms: u64,
        args: &[&[u8]],
    ) -> Result<Vec<Vec<u8>>, RefreshStoreError> {
        let mut cmd = redis::cmd("EVAL");
        cmd.arg(SCRIPT)
            .arg(keys.len())
            .arg(keys)
            .arg(op)
            .arg(&self.prefix)
            .arg(now_ms)
            .arg(REUSE_GRACE_MS);
        for arg in args {
            cmd.arg(*arg);
        }
        self.connection
            .query(&cmd)
            .await
            .map_err(|_| RefreshStoreError::Unavailable)
    }
    fn expect_ok(reply: &[Vec<u8>]) -> Result<(), RefreshStoreError> {
        match reply {
            [status] if status == b"ok" => Ok(()),
            _ => Err(RefreshStoreError::Unavailable),
        }
    }
    /// Starts a family, coupled when `upstream` holds a sealed upstream grant; at the
    /// per-user cap the user's oldest families are revoked.
    pub async fn issue(
        &self,
        grant: &RefreshGrant,
        token_hash: [u8; 32],
        now_ms: u64,
        policy: &RefreshTokenPolicy,
        upstream: Option<&str>,
    ) -> Result<(), RefreshStoreError> {
        let (absolute, idle) =
            initial_expiry(now_ms, policy).ok_or(RefreshStoreError::Unavailable)?;
        let payload = grant.encode()?;
        let id = random_id()?;
        let reply = self
            .run(
                &[self.token_key(&token_hash)],
                "issue",
                now_ms,
                &[
                    id.as_bytes(),
                    grant.user_key().as_bytes(),
                    URL_SAFE_NO_PAD.encode(token_hash).as_bytes(),
                    &payload,
                    absolute.to_string().as_bytes(),
                    idle.to_string().as_bytes(),
                    self.max_per_user.to_string().as_bytes(),
                    grant.client_id.as_bytes(),
                    upstream.unwrap_or_default().as_bytes(),
                ],
            )
            .await?;
        Self::expect_ok(&reply)
    }
    /// Classifies a presented hash; reuse outside the grace window revokes the family.
    pub async fn lookup(
        &self,
        token_hash: &[u8; 32],
        now_ms: u64,
    ) -> Result<Presented, RefreshStoreError> {
        let encoded = URL_SAFE_NO_PAD.encode(token_hash);
        let reply = self
            .run(
                &[self.token_key(token_hash)],
                "lookup",
                now_ms,
                &[encoded.as_bytes()],
            )
            .await?;
        Ok(match reply.as_slice() {
            [status, id, grant, created, absolute, upstream, generation]
                if status == b"current" =>
            {
                Presented::Current(Box::new(RefreshFamily {
                    family_id: text(id)?,
                    grant: RefreshGrant::decode(grant)?,
                    created_at_ms: number(created)?,
                    absolute_expires_at_ms: number(absolute)?,
                    upstream: (!upstream.is_empty())
                        .then(|| {
                            Ok::<_, RefreshStoreError>(UpstreamState {
                                sealed: text(upstream)?,
                                generation: number(generation)?,
                            })
                        })
                        .transpose()?,
                }))
            }
            [status] if status == b"grace" => Presented::Grace,
            [status, client] if status == b"reused" => Presented::Reused {
                client_id: text(client)?,
            },
            [status] if status == b"missing" => Presented::Missing,
            _ => return Err(RefreshStoreError::Unavailable),
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
        let idle = deadline(now_ms, idle_ttl_seconds, Some(ceiling))
            .ok_or(RefreshStoreError::Unavailable)?;
        let reply = self
            .run(
                &[self.token_key(presented), self.token_key(&next)],
                "rotate",
                now_ms,
                &[
                    URL_SAFE_NO_PAD.encode(presented).as_bytes(),
                    URL_SAFE_NO_PAD.encode(next).as_bytes(),
                    idle.to_string().as_bytes(),
                    ceiling.to_string().as_bytes(),
                    family_id.as_bytes(),
                    MAX_ROTATED_HASHES.to_string().as_bytes(),
                ],
            )
            .await?;
        match reply.as_slice() {
            [status] if status == b"rotated" => Ok(Rotated::Rotated),
            [status] if status == b"stale" || status == b"missing" => Ok(Rotated::Stale),
            _ => Err(RefreshStoreError::Unavailable),
        }
    }
    /// Replaces the sealed upstream grant while `presented` is the family's current token
    /// and `generation` its current upstream generation. Repeating a stored replacement
    /// reports `Stored` again.
    pub async fn set_upstream(
        &self,
        family_id: &str,
        presented: &[u8; 32],
        generation: u64,
        sealed: &str,
        now_ms: u64,
    ) -> Result<UpstreamStored, RefreshStoreError> {
        let reply = self
            .run(
                &[self.token_key(presented)],
                "set_upstream",
                now_ms,
                &[
                    URL_SAFE_NO_PAD.encode(presented).as_bytes(),
                    family_id.as_bytes(),
                    generation.to_string().as_bytes(),
                    sealed.as_bytes(),
                ],
            )
            .await?;
        match reply.as_slice() {
            [status] if status == b"stored" => Ok(UpstreamStored::Stored),
            [status] if status == b"stale" || status == b"missing" => Ok(UpstreamStored::Stale),
            _ => Err(RefreshStoreError::Unavailable),
        }
    }
    /// Takes the family's upstream refresh lock for `holder` until `expires_ms`. Another
    /// holder's unexpired lock refuses it; the same holder renews its own lock, so a
    /// resent request succeeds.
    pub async fn lock_upstream(
        &self,
        family_id: &str,
        holder: &str,
        now_ms: u64,
        expires_ms: u64,
    ) -> Result<bool, RefreshStoreError> {
        let reply = self
            .run(
                &[self.lock_key(family_id)],
                "lock",
                now_ms,
                &[holder.as_bytes(), expires_ms.to_string().as_bytes()],
            )
            .await?;
        match reply.as_slice() {
            [status] if status == b"ok" => Ok(true),
            [status] if status == b"busy" => Ok(false),
            _ => Err(RefreshStoreError::Unavailable),
        }
    }
    /// Releases the lock only if `holder` still holds it.
    pub async fn unlock_upstream(
        &self,
        family_id: &str,
        holder: &str,
    ) -> Result<(), RefreshStoreError> {
        let reply = self
            .run(
                &[self.lock_key(family_id)],
                "unlock",
                1,
                &[holder.as_bytes()],
            )
            .await?;
        Self::expect_ok(&reply)
    }
    pub async fn revoke_family(&self, family_id: &str) -> Result<(), RefreshStoreError> {
        // The token key is unused by this operation; any key in the namespace routes it.
        let reply = self
            .run(
                &[format!("{}token:-", self.prefix)],
                "revoke_family",
                1,
                &[family_id.as_bytes()],
            )
            .await?;
        Self::expect_ok(&reply)
    }
    /// RFC 7009: any token of a family revokes it, but only for the owning client.
    pub async fn revoke_token(
        &self,
        token_hash: &[u8; 32],
        client_id: &str,
    ) -> Result<bool, RefreshStoreError> {
        let reply = self
            .run(
                &[self.token_key(token_hash)],
                "revoke",
                1,
                &[client_id.as_bytes()],
            )
            .await?;
        match reply.as_slice() {
            [status] if status == b"ok" => Ok(true),
            [status] if status == b"missing" => Ok(false),
            _ => Err(RefreshStoreError::Unavailable),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::refresh::tests::grant;
    use std::{process::Command, time::Duration};

    struct Fixture(String);
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = Command::new("docker").args(["rm", "-f", &self.0]).output();
        }
    }
    fn docker(args: &[&str]) -> String {
        let output = Command::new("docker")
            .args(args)
            .output()
            .expect("Docker CLI required for disposable Valkey tests");
        assert!(output.status.success(), "Docker fixture command failed");
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }
    fn policy() -> RefreshTokenPolicy {
        RefreshTokenPolicy {
            enabled: true,
            idle_ttl_seconds: 600,
            absolute_ttl_seconds: 3600,
        }
    }
    fn family(presented: Presented) -> RefreshFamily {
        match presented {
            Presented::Current(family) => *family,
            other => panic!("expected current family, got {other:?}"),
        }
    }
    /// Closes every other client connection, as a Valkey restart does.
    async fn close_other_connections(store: &ValkeyRefreshStore) {
        let killed: usize = store
            .connection
            .query(redis::cmd("CLIENT").arg(&["KILL", "TYPE", "normal", "SKIPME", "yes"]))
            .await
            .unwrap();
        assert!(killed >= 1, "another connection is closed");
    }

    /// A disposable Valkey container and a connected store with `max_per_user`.
    async fn disposable(
        max_per_user: usize,
    ) -> (Fixture, BrowserBackendConfig, ValkeyRefreshStore) {
        let fixture = Fixture(docker(&[
            "run",
            "--rm",
            "-d",
            "-p",
            "127.0.0.1::6379",
            "valkey/valkey:8",
            "valkey-server",
            "--requirepass",
            "public-disposable-fixture",
            "--save",
            "",
            "--appendonly",
            "no",
        ]));
        let backend = BrowserBackendConfig::Valkey {
            url: format!("redis://{}/0", docker(&["port", &fixture.0, "6379/tcp"])),
            key_prefix: "authotron:refresh:test".into(),
            password: "public-disposable-fixture".into(),
            connect_timeout_ms: 2000,
            operation_timeout_ms: 1000,
        };
        for _ in 0..100 {
            if let Ok(store) = ValkeyRefreshStore::new(&backend, max_per_user).await {
                return (fixture, backend, store);
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("disposable Valkey did not become ready");
    }
    async fn server_now(store: &ValkeyRefreshStore) -> u64 {
        let (sec, micros): (u64, u64) = store.connection.query(&redis::cmd("TIME")).await.unwrap();
        sec * 1000 + micros / 1000
    }

    /// Run explicitly: cargo test -p authotron disposable -- --ignored --test-threads=1.
    #[tokio::test]
    #[ignore = "requires Docker; starts and removes its own isolated Valkey container"]
    async fn disposable_valkey_refresh_rotation_reuse_cap_and_revocation() {
        let (_fixture, backend, a) = disposable(2).await;
        let b = ValkeyRefreshStore::new(&backend, 2).await.unwrap();
        assert_eq!(a.durability().await, Durability::NotPersisted);
        let _: String = a
            .connection
            .query(redis::cmd("CONFIG").arg("SET").arg("appendonly").arg("yes"))
            .await
            .unwrap();
        assert_eq!(a.durability().await, Durability::AppendOnly);
        let now = server_now(&a).await;
        let ceiling = now + 3_600_000;

        a.issue(&grant(), [1; 32], now, &policy(), None)
            .await
            .unwrap();
        assert!(
            a.issue(&grant(), [1; 32], now, &policy(), None)
                .await
                .is_err()
        );
        // The first operation on a closed connection reconnects and succeeds.
        close_other_connections(&a).await;
        let current = family(b.lookup(&[1; 32], now).await.unwrap());
        assert_eq!(current.grant, grant());
        assert_eq!(current.created_at_ms, now);
        assert_eq!(current.absolute_expires_at_ms, ceiling);
        let id = current.family_id;
        let family_key = format!("{}family:{id}", a.prefix);
        let ttl: i64 = a
            .connection
            .query(redis::cmd("PEXPIRETIME").arg(&family_key))
            .await
            .unwrap();
        assert_eq!(ttl as u64, now + 600_000);
        // A rotation sent on a closed connection runs once: a second run would be stale.
        close_other_connections(&a).await;
        assert_eq!(
            b.rotate(&id, &[1; 32], [2; 32], now + 1, 600, ceiling)
                .await
                .unwrap(),
            Rotated::Rotated
        );
        let ttl: i64 = a
            .connection
            .query(redis::cmd("PEXPIRETIME").arg(&family_key))
            .await
            .unwrap();
        assert_eq!(ttl as u64, now + 600_001);
        for token in [[1; 32], [2; 32]] {
            let ttl: i64 = a
                .connection
                .query(redis::cmd("PEXPIRETIME").arg(a.token_key(&token)))
                .await
                .unwrap();
            assert_eq!(ttl as u64, now + 600_001);
        }
        assert_eq!(
            a.rotate(&id, &[1; 32], [3; 32], now + 2, 600, ceiling)
                .await
                .unwrap(),
            Rotated::Stale
        );
        assert!(matches!(
            a.lookup(&[1; 32], now + 2).await.unwrap(),
            Presented::Grace
        ));
        family(a.lookup(&[2; 32], now + 2).await.unwrap());
        assert!(matches!(
            a.lookup(&[1; 32], now + 1 + REUSE_GRACE_MS).await.unwrap(),
            Presented::Reused { client_id } if client_id == "desktop"
        ));
        assert!(matches!(
            a.lookup(&[2; 32], now + 3).await.unwrap(),
            Presented::Missing
        ));

        for (index, token) in [[4; 32], [5; 32], [6; 32]].into_iter().enumerate() {
            a.issue(&grant(), token, now + index as u64, &policy(), None)
                .await
                .unwrap();
        }
        assert!(matches!(
            b.lookup(&[4; 32], now + 5).await.unwrap(),
            Presented::Missing
        ));
        family(b.lookup(&[5; 32], now + 5).await.unwrap());
        assert!(!b.revoke_token(&[5; 32], "other").await.unwrap());
        assert!(b.revoke_token(&[5; 32], "desktop").await.unwrap());
        assert!(!b.revoke_token(&[5; 32], "desktop").await.unwrap());
        let id = family(a.lookup(&[6; 32], now + 5).await.unwrap()).family_id;
        a.revoke_family(&id).await.unwrap();
        assert!(matches!(
            a.lookup(&[6; 32], now + 5).await.unwrap(),
            Presented::Missing
        ));
        assert!(matches!(
            a.lookup(&[7; 32], now).await.unwrap(),
            Presented::Missing
        ));
        a.issue(&grant(), [8; 32], now, &policy(), None)
            .await
            .unwrap();
        assert!(matches!(
            a.lookup(&[8; 32], now + 600_000).await.unwrap(),
            Presented::Missing
        ));

        let mut bounded = grant();
        bounded.username = "bounded".into();
        let hash = |step: usize| [100 + step as u8; 32];
        a.issue(&bounded, hash(0), now, &policy(), None)
            .await
            .unwrap();
        let id = family(a.lookup(&hash(0), now).await.unwrap()).family_id;
        let rotations = MAX_ROTATED_HASHES + 2;
        for step in 0..rotations {
            let rotated = b
                .rotate(&id, &hash(step), hash(step + 1), now, 600, ceiling)
                .await
                .unwrap();
            assert_eq!(rotated, Rotated::Rotated);
        }
        for (step, exists) in [(0, false), (1, false), (2, true), (rotations, true)] {
            let found: bool = a
                .connection
                .query(redis::cmd("EXISTS").arg(a.token_key(&hash(step))))
                .await
                .unwrap();
            assert_eq!(found, exists, "token {step}");
        }
        let history: String = a
            .connection
            .query(
                redis::cmd("HGET")
                    .arg(format!("{}family:{id}", a.prefix))
                    .arg("history"),
            )
            .await
            .unwrap();
        assert_eq!(history.split(' ').count(), MAX_ROTATED_HASHES);
        assert!(matches!(
            a.lookup(&hash(0), now).await.unwrap(),
            Presented::Missing
        ));
        assert!(matches!(
            a.lookup(&hash(2), now).await.unwrap(),
            Presented::Reused { .. }
        ));
        for step in [2, rotations] {
            let found: bool = a
                .connection
                .query(redis::cmd("EXISTS").arg(a.token_key(&hash(step))))
                .await
                .unwrap();
            assert!(!found, "revocation removes token {step}");
        }
    }

    /// Run explicitly: cargo test -p authotron disposable -- --ignored --test-threads=1.
    #[tokio::test]
    #[ignore = "requires Docker; starts and removes its own isolated Valkey container"]
    async fn disposable_valkey_upstream_grants_follow_token_and_generation() {
        let (_fixture, backend, a) = disposable(50).await;
        let b = ValkeyRefreshStore::new(&backend, 50).await.unwrap();
        let now = server_now(&a).await;
        let coupled = RefreshGrant {
            upstream_coupled: true,
            ..grant()
        };
        a.issue(&coupled, [1; 32], now, &policy(), Some("v1.k.first"))
            .await
            .unwrap();
        let current = family(b.lookup(&[1; 32], now).await.unwrap());
        assert!(current.grant.upstream_coupled);
        assert_eq!(
            current.upstream,
            Some(UpstreamState {
                sealed: "v1.k.first".into(),
                generation: 0
            })
        );
        let id = current.family_id;
        for (store, presented, generation, sealed, expected) in [
            (&a, [9; 32], 0, "v1.k.second", UpstreamStored::Stale),
            (&b, [1; 32], 1, "v1.k.second", UpstreamStored::Stale),
            (&a, [1; 32], 0, "v1.k.second", UpstreamStored::Stored),
            // A run resent after a lost reply recognises its own replacement.
            (&b, [1; 32], 0, "v1.k.second", UpstreamStored::Stored),
            (&b, [1; 32], 0, "v1.k.other", UpstreamStored::Stale),
        ] {
            assert_eq!(
                store
                    .set_upstream(&id, &presented, generation, sealed, now)
                    .await
                    .unwrap(),
                expected
            );
        }
        let state = family(a.lookup(&[1; 32], now).await.unwrap())
            .upstream
            .unwrap();
        assert_eq!(
            (state.sealed.as_str(), state.generation),
            ("v1.k.second", 1)
        );
        assert_eq!(
            a.rotate(&id, &[1; 32], [2; 32], now, 600, now + 3_600_000)
                .await
                .unwrap(),
            Rotated::Rotated
        );
        assert_eq!(
            b.set_upstream(&id, &[1; 32], 1, "v1.k.third", now)
                .await
                .unwrap(),
            UpstreamStored::Stale
        );
        assert_eq!(
            b.set_upstream(&id, &[2; 32], 1, "v1.k.third", now)
                .await
                .unwrap(),
            UpstreamStored::Stored
        );
        a.issue(&grant(), [5; 32], now, &policy(), None)
            .await
            .unwrap();
        let plain = family(a.lookup(&[5; 32], now).await.unwrap());
        assert!(plain.upstream.is_none() && !plain.grant.upstream_coupled);
        assert_eq!(
            a.set_upstream(&plain.family_id, &[5; 32], 0, "v1.k.x", now)
                .await
                .unwrap(),
            UpstreamStored::Stale
        );
    }

    /// Run explicitly: cargo test -p authotron disposable -- --ignored --test-threads=1.
    #[tokio::test]
    #[ignore = "requires Docker; starts and removes its own isolated Valkey container"]
    async fn disposable_valkey_upstream_lock_excludes_other_replicas() {
        let (_fixture, backend, a) = disposable(50).await;
        let b = ValkeyRefreshStore::new(&backend, 50).await.unwrap();
        let now = server_now(&a).await;
        assert!(a.lock_upstream("f", "a", now, now + 60_000).await.unwrap());
        assert!(!b.lock_upstream("f", "b", now, now + 60_000).await.unwrap());
        assert!(b.lock_upstream("g", "b", now, now + 60_000).await.unwrap());
        // A resent lock request by the holder succeeds and renews it.
        assert!(a.lock_upstream("f", "a", now, now + 60_000).await.unwrap());
        b.unlock_upstream("f", "b").await.unwrap();
        assert!(!b.lock_upstream("f", "b", now, now + 60_000).await.unwrap());
        a.unlock_upstream("f", "a").await.unwrap();
        a.unlock_upstream("f", "a").await.unwrap();
        assert!(b.lock_upstream("f", "b", now, now + 50).await.unwrap());
        let ttl: i64 = a
            .connection
            .query(redis::cmd("PTTL").arg(a.lock_key("f")))
            .await
            .unwrap();
        assert!((0..=50).contains(&ttl), "{ttl}");
        tokio::time::sleep(Duration::from_millis(80)).await;
        let later = server_now(&a).await.max(now + 51);
        assert!(
            a.lock_upstream("f", "a", later, later + 60_000)
                .await
                .unwrap()
        );
        assert!(a.lock_upstream("f", "a", now, now).await.is_err());
    }
}

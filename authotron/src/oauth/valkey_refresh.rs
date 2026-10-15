// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! Shared refresh-token families in Valkey; every mutation is one atomic Lua script.

use super::refresh::{
    EndedFamily, FamilySummary, MAX_RETRIES_PER_ROTATION, MAX_RETRY_WINDOW_MS, MAX_ROTATED_HASHES,
    Presented, RefreshFamily, RefreshGrant, RefreshStoreError, Repetition, Revocation, Rotated,
    Rotation, UpstreamState, UpstreamStored, deadline, initial_expiry, random_id,
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
/// The `id, grant, sealed` triples a reply appends for each ended family; `sealed` is
/// empty for a family without an upstream grant.
fn ended(values: &[Vec<u8>]) -> Result<Vec<EndedFamily>, RefreshStoreError> {
    let (triples, rest) = values.as_chunks::<3>();
    if !rest.is_empty() {
        return Err(RefreshStoreError::Unavailable);
    }
    triples
        .iter()
        .map(|[id, grant, sealed]| {
            Ok(EndedFamily {
                family_id: text(id)?,
                grant: RefreshGrant::decode(grant)?,
                sealed: (!sealed.is_empty()).then(|| text(sealed)).transpose()?,
            })
        })
        .collect()
}
/// A family view: `id, grant, created, absolute, sealed, generation`, where `sealed` is
/// empty for a family without an upstream grant. Any other number of values is invalid.
fn view(values: &[Vec<u8>]) -> Result<Box<RefreshFamily>, RefreshStoreError> {
    let [id, grant, created, absolute, upstream, generation] = values else {
        return Err(RefreshStoreError::Unavailable);
    };
    Ok(Box::new(RefreshFamily {
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
/// A token hash as the store keeps it, 32 bytes in canonical unpadded base64url.
/// Valid: 43 `A`s (32 zero bytes). Invalid: the same with `=` padding, 42 characters,
/// or a final `B`, whose trailing bits are not zero.
fn stored_hash(value: &[u8]) -> Result<[u8; 32], RefreshStoreError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| RefreshStoreError::Unavailable)?;
    decoded
        .try_into()
        .map_err(|_| RefreshStoreError::Unavailable)
}
/// A `repeated` reply: `current, sealed, retries, streak`; anything else is `None`.
fn repetition(values: &[Vec<u8>]) -> Result<Option<Box<Repetition>>, RefreshStoreError> {
    let count = |bytes| u32::try_from(number(bytes)?).map_err(|_| RefreshStoreError::Unavailable);
    match values {
        [status, current, sealed, retries, streak] if status == b"repeated" => {
            Ok(Some(Box::new(Repetition {
                current: stored_hash(current)?,
                sealed: text(sealed)?,
                retries: count(retries)?,
                streak: count(streak)?,
            })))
        }
        [status] if status == b"stale" || status == b"missing" => Ok(None),
        _ => Err(RefreshStoreError::Unavailable),
    }
}
/// The `id, grant, created, last used, idle, absolute` sextuples of family summaries.
fn summaries(values: &[Vec<u8>]) -> Result<Vec<FamilySummary>, RefreshStoreError> {
    let (rows, rest) = values.as_chunks::<6>();
    if !rest.is_empty() {
        return Err(RefreshStoreError::Unavailable);
    }
    rows.iter()
        .map(|[id, grant, created, used, idle, absolute]| {
            Ok(FamilySummary {
                family_id: text(id)?,
                grant: RefreshGrant::decode(grant)?,
                created_at_ms: number(created)?,
                last_used_at_ms: number(used)?,
                idle_expires_at_ms: number(idle)?,
                absolute_expires_at_ms: number(absolute)?,
            })
        })
        .collect()
}
/// At most one ended family, for replies that end a single family.
fn ended_one(values: &[Vec<u8>]) -> Result<Option<EndedFamily>, RefreshStoreError> {
    let mut all = ended(values)?;
    if all.len() > 1 {
        return Err(RefreshStoreError::Unavailable);
    }
    Ok(all.pop())
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
            prefix: format!("{key_prefix}:oauth:refresh-tokens:v3:"),
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
    fn family_key(&self, family_id: &str) -> String {
        format!("{}family:{family_id}", self.prefix)
    }
    fn index_key(&self, user_key: &str) -> String {
        format!("{}user:{user_key}", self.prefix)
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
            .arg(MAX_RETRY_WINDOW_MS);
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
    /// per-user cap the user's oldest families are revoked and returned.
    pub async fn issue(
        &self,
        grant: &RefreshGrant,
        token_hash: [u8; 32],
        now_ms: u64,
        policy: &RefreshTokenPolicy,
        upstream: Option<&str>,
    ) -> Result<Vec<EndedFamily>, RefreshStoreError> {
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
        match reply.split_first() {
            Some((status, evicted)) if status == b"ok" => ended(evicted),
            _ => Err(RefreshStoreError::Unavailable),
        }
    }
    /// Classifies a presented hash; any rotated token but the previous one within
    /// [`MAX_RETRY_WINDOW_MS`] of its rotation is reuse and revokes the family.
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
            [status, family @ ..] if status == b"current" => Presented::Current(view(family)?),
            [status, family @ .., rotated] if status == b"previous" => {
                Presented::Previous(view(family)?, number(rotated)?)
            }
            [status, rest @ ..] if status == b"reused" => Presented::Reused(Box::new(
                ended_one(rest)?.ok_or(RefreshStoreError::Unavailable)?,
            )),
            [status] if status == b"missing" => Presented::Missing,
            _ => return Err(RefreshStoreError::Unavailable),
        })
    }
    /// Rotates the family of `presented` if that token is still its current one. If it
    /// is the previous one, the latest rotation is answered again as by
    /// [`Self::repeat`]: a concurrent refresh, or an earlier run of this one, applied it.
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
        let idle = deadline(now_ms, idle_ttl_seconds, Some(ceiling))
            .ok_or(RefreshStoreError::Unavailable)?;
        let payload = grant.encode()?;
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
                    &payload,
                    MAX_ROTATED_HASHES.to_string().as_bytes(),
                    sealed.as_bytes(),
                    retry_window_ms.to_string().as_bytes(),
                    MAX_RETRIES_PER_ROTATION.to_string().as_bytes(),
                ],
            )
            .await?;
        match reply.as_slice() {
            [status] if status == b"rotated" => Ok(Rotated::Rotated),
            reply => Ok(repetition(reply)?.map_or(Rotated::Stale, Rotated::Repeated)),
        }
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
        let reply = self
            .run(
                &[self.token_key(presented)],
                "repeat",
                now_ms,
                &[
                    URL_SAFE_NO_PAD.encode(presented).as_bytes(),
                    window_ms.to_string().as_bytes(),
                    MAX_RETRIES_PER_ROTATION.to_string().as_bytes(),
                ],
            )
            .await?;
        repetition(&reply)
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
        let reply = self
            .run(
                &[self.family_key(family_id)],
                "set_upstream",
                now_ms,
                &[generation.to_string().as_bytes(), sealed.as_bytes()],
            )
            .await?;
        match reply.as_slice() {
            [status] if status == b"stored" => Ok(UpstreamStored::Stored),
            [status] if status == b"stale" => Ok(UpstreamStored::Stale),
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
    pub async fn revoke_family(
        &self,
        family_id: &str,
    ) -> Result<Option<EndedFamily>, RefreshStoreError> {
        // The token key is unused by this operation; any key in the namespace routes it.
        let reply = self
            .run(
                &[format!("{}token:-", self.prefix)],
                "revoke_family",
                1,
                &[family_id.as_bytes()],
            )
            .await?;
        match reply.split_first() {
            Some((status, rest)) if status == b"ok" => ended_one(rest),
            _ => Err(RefreshStoreError::Unavailable),
        }
    }
    /// The live families of the user with the key `user_key` (see
    /// [`super::refresh::user_key`]), newest first, at most `limit`.
    pub async fn families_of(
        &self,
        user_key: &str,
        limit: usize,
        now_ms: u64,
    ) -> Result<Vec<FamilySummary>, RefreshStoreError> {
        let reply = self
            .run(
                &[self.index_key(user_key)],
                "list",
                now_ms,
                &[limit.to_string().as_bytes()],
            )
            .await?;
        match reply.split_first() {
            Some((status, rest)) if status == b"ok" => summaries(rest),
            _ => Err(RefreshStoreError::Unavailable),
        }
    }
    /// Revokes every live family of the user with the key `user_key` and returns them.
    pub async fn revoke_user(
        &self,
        user_key: &str,
        now_ms: u64,
    ) -> Result<Vec<EndedFamily>, RefreshStoreError> {
        let reply = self
            .run(&[self.index_key(user_key)], "revoke_user", now_ms, &[])
            .await?;
        match reply.split_first() {
            Some((status, rest)) if status == b"ok" => ended(rest),
            _ => Err(RefreshStoreError::Unavailable),
        }
    }
    /// RFC 7009: any token of a family revokes it, but only for the owning client.
    pub async fn revoke_token(
        &self,
        token_hash: &[u8; 32],
        client_id: &str,
    ) -> Result<Revocation, RefreshStoreError> {
        let reply = self
            .run(
                &[self.token_key(token_hash)],
                "revoke",
                1,
                &[client_id.as_bytes()],
            )
            .await?;
        match reply.as_slice() {
            [status, rest @ ..] if status == b"ok" => Ok(Revocation::Revoked(Box::new(
                ended_one(rest)?.ok_or(RefreshStoreError::Unavailable)?,
            ))),
            [status] if status == b"missing" => Ok(Revocation::NotFound),
            _ => Err(RefreshStoreError::Unavailable),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::refresh::tests::{grant, rotation};
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
            upstream_offline_access: false,
            retry_window_seconds: 30,
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
        let family_key = a.family_key(&id);
        let ttl: i64 = a
            .connection
            .query(redis::cmd("PEXPIRETIME").arg(&family_key))
            .await
            .unwrap();
        assert_eq!(ttl as u64, now + 600_000);
        // A rotation sent on a closed connection runs once; a second run would answer
        // it again as a repetition.
        close_other_connections(&a).await;
        assert_eq!(
            b.rotate(&[1; 32], &rotation([2; 32], &grant(), ceiling), now + 1)
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
        // The previous token answers the latest rotation again, with its sealed token,
        // within the retry window and at most MAX_RETRIES_PER_ROTATION times.
        let fixture = grant();
        let closed = Rotation {
            retry_window_ms: 1,
            ..rotation([3; 32], &fixture, ceiling)
        };
        assert_eq!(
            a.rotate(&[1; 32], &closed, now + 2).await.unwrap(),
            Rotated::Stale
        );
        for retries in 1..=MAX_RETRIES_PER_ROTATION {
            assert_eq!(
                a.rotate(&[1; 32], &rotation([3; 32], &fixture, ceiling), now + 2)
                    .await
                    .unwrap(),
                Rotated::Repeated(repetition(2, retries, 1).unwrap())
            );
        }
        assert_eq!(
            b.rotate(&[1; 32], &rotation([3; 32], &fixture, ceiling), now + 2)
                .await
                .unwrap(),
            Rotated::Stale
        );
        for at in [now + 2, now + MAX_RETRY_WINDOW_MS] {
            match b.lookup(&[1; 32], at).await.unwrap() {
                Presented::Previous(previous, rotated_at) => {
                    assert_eq!(
                        (previous.family_id.as_str(), rotated_at),
                        (id.as_str(), now + 1)
                    );
                    assert_eq!(previous.grant, grant());
                }
                other => panic!("expected the previous token, got {other:?}"),
            }
        }
        family(a.lookup(&[2; 32], now + 2).await.unwrap());
        assert!(matches!(
            a.lookup(&[1; 32], now + 1 + MAX_RETRY_WINDOW_MS).await.unwrap(),
            Presented::Reused(ended) if ended.grant.client_id == "desktop" && ended.sealed.is_none()
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
        let id = family(b.lookup(&[5; 32], now + 5).await.unwrap()).family_id;
        assert!(matches!(
            b.revoke_token(&[5; 32], "other").await.unwrap(),
            Revocation::NotFound
        ));
        assert!(matches!(
            b.revoke_token(&[5; 32], "desktop").await.unwrap(),
            Revocation::Revoked(ended) if ended.family_id == id && ended.sealed.is_none()
        ));
        assert!(matches!(
            b.revoke_token(&[5; 32], "desktop").await.unwrap(),
            Revocation::NotFound
        ));
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
                .rotate(
                    &hash(step),
                    &rotation(hash(step + 1), &bounded, ceiling),
                    now,
                )
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
    async fn disposable_valkey_expired_families_leave_the_per_user_index() {
        let (_fixture, _, store) = disposable(2).await;
        let now = server_now(&store).await;
        for (index, token) in [[1; 32], [2; 32]].into_iter().enumerate() {
            store
                .issue(&grant(), token, now + index as u64, &policy(), None)
                .await
                .unwrap();
        }
        // The newer family expires: Valkey removes its key, but not its index entry.
        let id = family(store.lookup(&[2; 32], now).await.unwrap()).family_id;
        let _: usize = store
            .connection
            .query(redis::cmd("DEL").arg(store.family_key(&id)))
            .await
            .unwrap();
        // It no longer counts against the cap of two, so the older family stays.
        let evicted = store
            .issue(&grant(), [3; 32], now + 2, &policy(), None)
            .await
            .unwrap();
        assert!(evicted.is_empty());
        family(store.lookup(&[1; 32], now + 2).await.unwrap());
        let index = store.index_key(&grant().user_key());
        let members: Vec<String> = store
            .connection
            .query(redis::cmd("ZRANGE").arg(&index).arg(0).arg(-1))
            .await
            .unwrap();
        assert_eq!(members.len(), 2);
        assert!(!members.contains(&id));
    }

    /// Run explicitly: cargo test -p authotron disposable -- --ignored --test-threads=1.
    #[tokio::test]
    #[ignore = "requires Docker; starts and removes its own isolated Valkey container"]
    async fn disposable_valkey_a_users_families_are_listed_and_revoked_together() {
        let (_fixture, backend, a) = disposable(50).await;
        let b = ValkeyRefreshStore::new(&backend, 50).await.unwrap();
        let now = server_now(&a).await;
        let mut bob = grant();
        bob.username = "bob".into();
        let issued = [(grant(), 1), (grant(), 2), (bob.clone(), 3), (grant(), 4)];
        for (index, (grant, token)) in issued.into_iter().enumerate() {
            a.issue(&grant, [token; 32], now + index as u64, &policy(), None)
                .await
                .unwrap();
        }
        let ceiling = now + 3_600_000;
        let fixture = grant();
        let rotation = rotation([5; 32], &fixture, ceiling);
        assert_eq!(
            a.rotate(&[1; 32], &rotation, now + 10).await.unwrap(),
            Rotated::Rotated
        );
        let alice = grant().user_key();
        let listed = b.families_of(&alice, 50, now + 20).await.unwrap();
        let created: Vec<_> = listed.iter().map(|family| family.created_at_ms).collect();
        assert_eq!(created, [now + 3, now + 1, now]);
        assert!(listed.iter().all(|family| family.grant == grant()));
        assert_eq!(
            (listed[2].last_used_at_ms, listed[2].idle_expires_at_ms),
            (now + 10, now + 10 + 600_000)
        );
        assert_eq!(listed[2].absolute_expires_at_ms, ceiling);
        assert_eq!(listed[0].last_used_at_ms, now + 3);
        assert_eq!(
            b.families_of(&alice, 2, now + 20).await.unwrap(),
            listed[..2]
        );
        let ended = b.revoke_user(&alice, now + 20).await.unwrap();
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
        assert!(ended.iter().all(|family| family.sealed.is_none()));
        assert!(
            a.families_of(&alice, 50, now + 20)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(a.revoke_user(&alice, now + 20).await.unwrap().is_empty());
        for token in [[2; 32], [4; 32], [5; 32]] {
            assert!(matches!(
                a.lookup(&token, now + 20).await.unwrap(),
                Presented::Missing
            ));
        }
        assert_eq!(
            a.families_of(&bob.user_key(), 50, now).await.unwrap().len(),
            1
        );
        family(a.lookup(&[3; 32], now + 20).await.unwrap());
    }

    /// Run explicitly: cargo test -p authotron disposable -- --ignored --test-threads=1.
    #[tokio::test]
    #[ignore = "requires Docker; starts and removes its own isolated Valkey container"]
    async fn disposable_valkey_previous_tokens_repeat_within_window_and_cap() {
        let (_fixture, backend, a) = disposable(50).await;
        let b = ValkeyRefreshStore::new(&backend, 50).await.unwrap();
        let now = server_now(&a).await;
        a.issue(&grant(), [1; 32], now, &policy(), None)
            .await
            .unwrap();
        let ceiling = now + 3_600_000;
        let rotate = |from: u8, at| {
            let a = &a;
            async move {
                let grant = grant();
                let rotation = rotation([from + 1; 32], &grant, ceiling);
                a.rotate(&[from; 32], &rotation, at).await.unwrap()
            }
        };
        let repeat = |from: u8, window, at| {
            let b = &b;
            async move { b.repeat(&[from; 32], window, at).await.unwrap() }
        };
        assert_eq!(rotate(1, now).await, Rotated::Rotated);
        assert_eq!(repeat(1, 10, now + 10).await, None, "outside its window");
        for retries in 1..=MAX_RETRIES_PER_ROTATION {
            assert_eq!(repeat(1, 10, now + 9).await, repetition(2, retries, 1));
        }
        assert_eq!(repeat(1, 10, now + 9).await, None, "past the cap");
        assert_eq!(repeat(2, 10, now + 9).await, None, "the current token");
        assert_eq!(rotate(2, now + 1).await, Rotated::Rotated);
        assert_eq!(repeat(2, 10, now + 2).await, repetition(3, 1, 2));
        assert_eq!(rotate(3, now + 3).await, Rotated::Rotated);
        assert_eq!(rotate(4, now + 4).await, Rotated::Rotated);
        assert_eq!(repeat(4, 10, now + 5).await, repetition(5, 1, 1));
        assert_eq!(repeat(2, 10, now + 5).await, None, "an older token");
        let grant = grant();
        let closed = Rotation {
            retry_window_ms: 0,
            ..rotation([9; 32], &grant, ceiling)
        };
        assert_eq!(
            b.rotate(&[4; 32], &closed, now + 5).await.unwrap(),
            Rotated::Stale
        );
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
        for (store, family, generation, sealed, expected) in [
            (&a, "other", 0, "v1.k.second", UpstreamStored::Stale),
            (&b, id.as_str(), 1, "v1.k.second", UpstreamStored::Stale),
            (&a, id.as_str(), 0, "v1.k.second", UpstreamStored::Stored),
            // A run resent after a lost reply recognises its own replacement.
            (&b, id.as_str(), 0, "v1.k.second", UpstreamStored::Stored),
            (&b, id.as_str(), 0, "v1.k.other", UpstreamStored::Stale),
        ] {
            assert_eq!(
                store
                    .set_upstream(family, generation, sealed, now)
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
        // The rotation stores the grant its successor carries.
        let mut refreshed = coupled.clone();
        refreshed.provider_roles = vec!["writer".into()];
        let mut oversized = coupled.clone();
        oversized.provider_roles = vec!["r".repeat(64); 1024];
        let ceiling = now + 3_600_000;
        assert!(
            a.rotate(&[1; 32], &rotation([2; 32], &oversized, ceiling), now)
                .await
                .is_err()
        );
        assert_eq!(
            a.rotate(&[1; 32], &rotation([2; 32], &refreshed, ceiling), now)
                .await
                .unwrap(),
            Rotated::Rotated
        );
        assert_eq!(
            family(b.lookup(&[2; 32], now).await.unwrap()).grant,
            refreshed
        );
        // The family's own rotation does not block a replacement for its generation.
        assert_eq!(
            b.set_upstream(&id, 1, "v1.k.third", now).await.unwrap(),
            UpstreamStored::Stored
        );
        assert_eq!(
            b.set_upstream(&id, 2, "v1.k.fourth", now + 600_000)
                .await
                .unwrap(),
            UpstreamStored::Stale
        );
        a.issue(&grant(), [5; 32], now, &policy(), None)
            .await
            .unwrap();
        let plain = family(a.lookup(&[5; 32], now).await.unwrap());
        assert!(plain.upstream.is_none() && !plain.grant.upstream_coupled);
        assert_eq!(
            a.set_upstream(&plain.family_id, 0, "v1.k.x", now)
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
    /// Run explicitly: cargo test -p authotron disposable -- --ignored --test-threads=1.
    #[tokio::test]
    #[ignore = "requires Docker; starts and removes its own isolated Valkey container"]
    async fn disposable_valkey_ended_families_carry_id_grant_and_sealed_grant() {
        let (_fixture, backend, a) = disposable(2).await;
        let b = ValkeyRefreshStore::new(&backend, 2).await.unwrap();
        let now = server_now(&a).await;
        let coupled = |n: u8| RefreshGrant {
            upstream_coupled: true,
            method: format!("sso-{n}"),
            ..grant()
        };
        let named = |ended: EndedFamily| (ended.grant.method, ended.sealed);
        let expected = |n: u8| (format!("sso-{n}"), Some(format!("v1.k.{n}")));
        for n in [1, 2, 4, 6] {
            if n == 4 {
                let id = family(a.lookup(&[3; 32], now + 3).await.unwrap()).family_id;
                assert!(matches!(
                    b.revoke_token(&[3; 32], "desktop").await.unwrap(),
                    Revocation::Revoked(ended) if ended.family_id == id && ended.sealed.is_none()
                ));
            }
            let evicted = a
                .issue(
                    &coupled(n),
                    [n; 32],
                    now + u64::from(n),
                    &policy(),
                    Some(&format!("v1.k.{n}")),
                )
                .await
                .unwrap();
            assert!(evicted.is_empty());
            if n == 2 {
                let evicted = b
                    .issue(&grant(), [3; 32], now + 3, &policy(), None)
                    .await
                    .unwrap();
                assert_eq!(
                    evicted.into_iter().map(named).collect::<Vec<_>>(),
                    [expected(1)]
                );
                match b.revoke_token(&[2; 32], "desktop").await.unwrap() {
                    Revocation::Revoked(ended) => assert_eq!(named(*ended), expected(2)),
                    other => panic!("{other:?}"),
                }
            }
        }
        let coupled_4 = coupled(4);
        a.rotate(
            &[4; 32],
            &rotation([5; 32], &coupled_4, now + 3_600_000),
            now + 4,
        )
        .await
        .unwrap();
        match b
            .lookup(&[4; 32], now + 4 + MAX_RETRY_WINDOW_MS)
            .await
            .unwrap()
        {
            Presented::Reused(ended) => assert_eq!(named(*ended), expected(4)),
            other => panic!("{other:?}"),
        }
        let id = family(a.lookup(&[6; 32], now).await.unwrap()).family_id;
        assert_eq!(
            b.revoke_family(&id).await.unwrap().map(named),
            Some(expected(6))
        );
        assert!(a.revoke_family(&id).await.unwrap().is_none());
    }
}

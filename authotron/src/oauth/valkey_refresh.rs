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
    Rotated, deadline, initial_expiry, random_id,
};
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
    fn token_key(&self, hash: &[u8; 32]) -> String {
        format!("{}token:{}", self.prefix, URL_SAFE_NO_PAD.encode(hash))
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
    /// Starts a family; at the per-user cap the user's oldest families are revoked.
    pub async fn issue(
        &self,
        grant: &RefreshGrant,
        token_hash: [u8; 32],
        now_ms: u64,
        policy: &RefreshTokenPolicy,
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
            [status, id, grant, created, absolute] if status == b"current" => {
                Presented::Current(Box::new(RefreshFamily {
                    family_id: text(id)?,
                    grant: RefreshGrant::decode(grant)?,
                    created_at_ms: number(created)?,
                    absolute_expires_at_ms: number(absolute)?,
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

    /// Run explicitly: cargo test -p authotron disposable -- --ignored --test-threads=1.
    #[tokio::test]
    #[ignore = "requires Docker; starts and removes its own isolated Valkey container"]
    async fn disposable_valkey_refresh_rotation_reuse_cap_and_revocation() {
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
        let mut ready = None;
        for _ in 0..100 {
            if let Ok(store) = ValkeyRefreshStore::new(&backend, 2).await {
                ready = Some(store);
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let a = ready.expect("disposable Valkey did not become ready");
        let b = ValkeyRefreshStore::new(&backend, 2).await.unwrap();
        let (sec, _): (u64, u64) = a.connection.query(&redis::cmd("TIME")).await.unwrap();
        let now = sec * 1000;
        let ceiling = now + 3_600_000;

        a.issue(&grant(), [1; 32], now, &policy()).await.unwrap();
        assert!(a.issue(&grant(), [1; 32], now, &policy()).await.is_err());
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
            a.issue(&grant(), token, now + index as u64, &policy())
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
        a.issue(&grant(), [8; 32], now, &policy()).await.unwrap();
        assert!(matches!(
            a.lookup(&[8; 32], now + 600_000).await.unwrap(),
            Presented::Missing
        ));

        let mut bounded = grant();
        bounded.username = "bounded".into();
        let hash = |step: usize| [100 + step as u8; 32];
        a.issue(&bounded, hash(0), now, &policy()).await.unwrap();
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
}

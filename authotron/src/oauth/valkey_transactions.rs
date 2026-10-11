// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! Explicit shared authorization-input transactions, not authorization codes or grants.

use super::{
    authorization::ValidatedAuthorizationRequest,
    records::{AuthorizationTransaction, MAX_TRANSACTION_BYTES, valid_time},
    store::{CreatedTransaction, StoreError, TransactionId},
};
use crate::{
    config::{OAuthConfig, ui::BrowserBackendConfig},
    utils::valkey::{ConnectionError, ValkeyConnection},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use std::sync::Arc;

pub struct ValkeyTransactionStore {
    config: Arc<OAuthConfig>,
    connection: ValkeyConnection,
    prefix: String,
}
fn number(bytes: &[u8]) -> Result<u64, StoreError> {
    std::str::from_utf8(bytes)
        .ok()
        .and_then(|value| value.parse().ok())
        .ok_or(StoreError::Unavailable)
}
impl ValkeyTransactionStore {
    pub async fn new(
        config: Arc<OAuthConfig>,
        backend: &BrowserBackendConfig,
    ) -> Result<Self, StoreError> {
        config.validate().map_err(|_| StoreError::Configuration)?;
        if config
            .issuer
            .as_ref()
            .is_none_or(|issuer| issuer.len() > 2048)
        {
            return Err(StoreError::Configuration);
        }
        let BrowserBackendConfig::Valkey { key_prefix, .. } = backend else {
            return Err(StoreError::Configuration);
        };
        let connection = ValkeyConnection::connect(backend)
            .await
            .map_err(|error| match error {
                ConnectionError::Configuration => StoreError::Configuration,
                ConnectionError::Unavailable => StoreError::Unavailable,
            })?;
        Ok(Self {
            config,
            connection,
            prefix: format!("{key_prefix}:oauth:authorization-transactions:v1:"),
        })
    }
    fn keys(&self, id: &TransactionId) -> [String; 2] {
        [
            format!("{}index", self.prefix),
            format!(
                "{}record:{}",
                self.prefix,
                URL_SAFE_NO_PAD.encode(id.hash())
            ),
        ]
    }
    async fn call(
        &self,
        op: &str,
        id: &TransactionId,
        expiry: u64,
        payload: &[u8],
    ) -> Result<Vec<Vec<u8>>, StoreError> {
        self.connection
            .query(
                redis::cmd("EVAL")
                    .arg(include_str!("valkey_transactions.lua"))
                    .arg(2)
                    .arg(&self.keys(id))
                    .arg(op)
                    .arg(MAX_TRANSACTION_BYTES)
                    .arg(self.config.authorization_transaction_ttl_seconds * 1000)
                    .arg(self.config.max_authorization_transactions)
                    .arg(expiry)
                    .arg(payload),
            )
            .await
            .map_err(|_| StoreError::Unavailable)
    }
    pub async fn create(
        &self,
        request: ValidatedAuthorizationRequest,
        browser_hash: [u8; 32],
    ) -> Result<CreatedTransaction, StoreError> {
        let (seconds, micros): (u64, u64) = self
            .connection
            .query(&redis::cmd("TIME"))
            .await
            .map_err(|_| StoreError::Unavailable)?;
        let now = seconds
            .checked_mul(1000)
            .and_then(|ms| ms.checked_add(micros / 1000))
            .filter(|now| micros < 1000000 && valid_time(*now))
            .ok_or(StoreError::Unavailable)?;
        let expiry = now
            .checked_add(self.config.authorization_transaction_ttl_seconds * 1000)
            .ok_or(StoreError::Unavailable)?;
        let bytes = AuthorizationTransaction::new(request, browser_hash, expiry)
            .and_then(|record| record.encode())
            .map_err(|_| StoreError::Unavailable)?;
        AuthorizationTransaction::decode(&bytes, &self.config, now)
            .map_err(|_| StoreError::Unavailable)?;
        for _ in 0..4 {
            let id = TransactionId::generate()?;
            match self.call("create", &id, expiry, &bytes).await?.as_slice() {
                [status] if status == b"ok" => {
                    return Ok(CreatedTransaction {
                        id,
                        expires_at_ms: expiry,
                    });
                }
                [status] if status == b"limited" => return Err(StoreError::Limited),
                [status] if status == b"collision" => continue,
                _ => return Err(StoreError::Unavailable),
            }
        }
        Err(StoreError::Unavailable)
    }
    async fn read(
        &self,
        id: &TransactionId,
        browser_hash: &[u8; 32],
    ) -> Result<(AuthorizationTransaction, Vec<u8>), StoreError> {
        let reply = self.call("read", id, 0, &[]).await?;
        match reply.as_slice() {
            [status, now, expiry, bytes] if status == b"ok" => {
                let record = AuthorizationTransaction::decode(bytes, &self.config, number(now)?)
                    .map_err(|_| StoreError::Unavailable)?;
                if record.expires_at_ms() != number(expiry)? {
                    return Err(StoreError::Unavailable);
                }
                if !record.matches_browser_binding(browser_hash) {
                    return Err(StoreError::Missing);
                }
                Ok((record, bytes.clone()))
            }
            [status] if status == b"missing" => Err(StoreError::Missing),
            _ => Err(StoreError::Unavailable),
        }
    }
    pub async fn lookup(
        &self,
        id: &TransactionId,
        browser_hash: &[u8; 32],
    ) -> Result<AuthorizationTransaction, StoreError> {
        self.read(id, browser_hash).await.map(|(record, _)| record)
    }
    pub async fn consume(
        &self,
        id: &TransactionId,
        browser_hash: &[u8; 32],
    ) -> Result<AuthorizationTransaction, StoreError> {
        let (record, bytes) = self.read(id, browser_hash).await?;
        match self
            .call("consume", id, record.expires_at_ms(), &bytes)
            .await?
            .as_slice()
        {
            [status] if status == b"ok" => Ok(record),
            [status] if status == b"missing" => Err(StoreError::Missing),
            _ => Err(StoreError::Unavailable),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::store::tests::{config, request};
    use super::*;
    use std::{
        io::Write,
        process::{Command, Stdio},
        time::Duration,
    };
    struct Container(String);
    impl Drop for Container {
        fn drop(&mut self) {
            let _ = Command::new("docker").args(["rm", "-f", &self.0]).output();
        }
    }
    fn docker(args: &[&str]) -> String {
        let output = Command::new("docker")
            .args(args)
            .output()
            .expect("Docker CLI required");
        assert!(
            output.status.success(),
            "disposable Valkey fixture {} command failed",
            args[0]
        );
        String::from_utf8(output.stdout).unwrap().trim().into()
    }
    async fn command<T: redis::FromRedisValue>(
        store: &ValkeyTransactionStore,
        command: &redis::Cmd,
    ) -> T {
        store.connection.query(command).await.unwrap()
    }

    #[tokio::test]
    #[ignore = "requires Docker; creates and removes its own isolated Valkey container"]
    async fn disposable_oauth_valkey_transactions() {
        let password = uuid::Uuid::new_v4().simple().to_string();
        let container = Container(docker(&[
            "run",
            "--rm",
            "-d",
            "-p",
            "127.0.0.1::6379",
            "valkey/valkey:8",
            "sleep",
            "infinity",
        ]));
        let mut configure = Command::new("docker")
            .args([
                "exec",
                "-i",
                &container.0,
                "sh",
                "-c",
                "umask 077; cat > /tmp/fixture.conf",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        write!(
            configure.stdin.take().unwrap(),
            "requirepass {password}\nsave \"\"\nappendonly no\n"
        )
        .unwrap();
        assert!(
            configure.wait().unwrap().success(),
            "disposable Valkey configuration failed"
        );
        docker(&[
            "exec",
            "-d",
            &container.0,
            "valkey-server",
            "/tmp/fixture.conf",
        ]);
        let backend = BrowserBackendConfig::Valkey {
            url: format!("redis://{}/0", docker(&["port", &container.0, "6379/tcp"])),
            key_prefix: format!("authotron:test:{}", uuid::Uuid::new_v4().simple()),
            password,
            connect_timeout_ms: 2000,
            operation_timeout_ms: 1000,
        };
        let cfg = config();
        let mut ready = None;
        for _ in 0..100 {
            if let Ok(store) = ValkeyTransactionStore::new(cfg.clone(), &backend).await {
                ready = Some(store);
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let a = ready.expect("disposable Valkey did not become ready");
        let b = ValkeyTransactionStore::new(cfg.clone(), &backend)
            .await
            .unwrap();
        let created = a.create(request(&cfg), [7; 32]).await.unwrap();
        let keys = a.keys(&created.id);
        assert_eq!(
            b.create(request(&cfg), [7; 32]).await.err(),
            Some(StoreError::Limited)
        );
        assert_eq!(
            b.consume(&created.id, &[8; 32]).await.err(),
            Some(StoreError::Missing)
        );
        let ttl1: i64 = command(&a, redis::cmd("PTTL").arg(&keys[1])).await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(
            b.lookup(&created.id, &[7; 32])
                .await
                .unwrap()
                .expires_at_ms(),
            created.expires_at_ms
        );
        let ttl2: i64 = command(&a, redis::cmd("PTTL").arg(&keys[1])).await;
        assert!(ttl2 < ttl1 && ttl2 > 0);
        let (left, right) = tokio::join!(
            a.consume(&created.id, &[7; 32]),
            b.consume(&created.id, &[7; 32])
        );
        assert_ne!(left.is_ok(), right.is_ok());
        assert!(matches!(
            left.err().or(right.err()),
            Some(StoreError::Missing)
        ));
        let (seconds, micros): (u64, u64) = command(&a, &redis::cmd("TIME")).await;
        let expiry = seconds * 1000 + micros / 1000 + 1000;
        let short = TransactionId::generate().unwrap();
        let bytes = AuthorizationTransaction::new(request(&cfg), [7; 32], expiry)
            .unwrap()
            .encode()
            .unwrap();
        let reply = a.call("create", &short, expiry, &bytes).await.unwrap();
        assert!(matches!(reply.as_slice(), [status] if status == b"ok"));
        let (_, expected) = b.read(&short, &[7; 32]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(1100)).await;
        let reply = a.call("consume", &short, expiry, &expected).await.unwrap();
        assert!(matches!(reply.as_slice(), [status] if status == b"missing"));
        let created = a.create(request(&cfg), [7; 32]).await.unwrap();
        let keys = a.keys(&created.id);
        let mut revoked = (*cfg).clone();
        revoked.clients[0].resources.clear();
        let revoked = ValkeyTransactionStore::new(Arc::new(revoked), &backend)
            .await
            .unwrap();
        assert_eq!(
            revoked.consume(&created.id, &[7; 32]).await.err(),
            Some(StoreError::Unavailable)
        );
        assert!(b.lookup(&created.id, &[7; 32]).await.is_ok());
        let (record, expected) = a.read(&created.id, &[7; 32]).await.unwrap();
        let _: String = command(
            &a,
            redis::cmd("SET")
                .arg(&keys[1])
                .arg("corrupt")
                .arg("KEEPTTL"),
        )
        .await;
        let reply = a
            .call("consume", &created.id, record.expires_at_ms(), &expected)
            .await
            .unwrap();
        assert!(matches!(reply.as_slice(), [status] if status == b"missing"));
        assert_eq!(
            b.consume(&created.id, &[7; 32]).await.err(),
            Some(StoreError::Unavailable)
        );
        let _: String = command(
            &a,
            redis::cmd("SET")
                .arg(&keys[1])
                .arg(vec![b'x'; MAX_TRANSACTION_BYTES + 1])
                .arg("KEEPTTL"),
        )
        .await;
        assert_eq!(
            b.lookup(&created.id, &[7; 32]).await.err(),
            Some(StoreError::Unavailable)
        );
        let _: usize = command(&a, redis::cmd("DEL").arg(&keys[1])).await;
        let _: usize = command(&a, redis::cmd("RPUSH").arg(&keys[1]).arg("wrong-type")).await;
        assert_eq!(
            b.consume(&created.id, &[7; 32]).await.err(),
            Some(StoreError::Unavailable)
        );
        let _: usize = command(&a, redis::cmd("DEL").arg(&keys)).await;
        let _: String = command(&a, redis::cmd("SET").arg(&keys[0]).arg("wrong-type")).await;
        assert_eq!(
            a.create(request(&cfg), [7; 32]).await.err(),
            Some(StoreError::Unavailable)
        );
        let count: usize = command(&a, &redis::cmd("DBSIZE")).await;
        assert_eq!(count, 1);
        let _: usize = command(&a, redis::cmd("DEL").arg(&keys[0])).await;
        let _: String = command(&a, redis::cmd("ACL").arg(&["SETUSER", "default", "-zadd"])).await;
        assert_eq!(
            a.create(request(&cfg), [7; 32]).await.err(),
            Some(StoreError::Unavailable)
        );
        let count: usize = command(&a, &redis::cmd("DBSIZE")).await;
        assert_eq!(count, 0);
        let _: String = command(&a, redis::cmd("ACL").arg(&["SETUSER", "default", "+zadd"])).await;
        docker(&["stop", &container.0]);
        assert_eq!(
            b.lookup(&created.id, &[7; 32]).await.err(),
            Some(StoreError::Unavailable)
        );
    }
}

// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! Shared explicit Valkey connector; policy and key namespaces belong to its callers.

use crate::{config::ui::BrowserBackendConfig, utils::log_throttle::should_emit};
use futures::{
    FutureExt,
    future::{BoxFuture, Shared},
};
use redis::aio::MultiplexedConnection;
use std::{
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};
use tokio::time::{Instant, timeout_at};
use tracing::Instrument;

/// Longest wait for a PING on a connection whose command timed out; the operation
/// timeout applies when it is shorter.
const CONFIRM_TIMEOUT: Duration = Duration::from_secs(1);
/// Failed connection attempts are logged at most once per interval.
const ATTEMPT_LOG_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConnectionError {
    Configuration,
    Unavailable,
}

/// One connection attempt, shared by every command that waits for it; `None` if it
/// failed.
type Attempt = Shared<BoxFuture<'static, Option<MultiplexedConnection>>>;

/// The connection in use and its generation, which each replacement increments.
struct Current {
    generation: u64,
    attempt: Attempt,
}

/// Deliberately not Debug: the client holds the connection credentials.
struct Connector {
    client: redis::Client,
    settings: redis::AsyncConnectionConfig,
    /// Throttles the failure log per key prefix, such as `authotron`.
    log_key: String,
    current: Mutex<Current>,
}

impl Connector {
    /// Starts connecting at once, so the attempt completes even if no command waits,
    /// within the span of the command that started it. A failure is logged by its
    /// error kind only, never the address or credentials.
    fn attempt(
        client: &redis::Client,
        settings: &redis::AsyncConnectionConfig,
        log_key: &str,
    ) -> Attempt {
        let (client, settings, log_key) = (client.clone(), settings.clone(), log_key.to_owned());
        let attempt = async move {
            let error = match client
                .get_multiplexed_async_connection_with_config(&settings)
                .await
            {
                Ok(connection) => return Some(connection),
                Err(error) => error,
            };
            if let Some(suppressed) = should_emit(&log_key, ATTEMPT_LOG_INTERVAL) {
                tracing::warn!(
                    event_name = "valkey.connection.attempt_failed",
                    event_domain = "valkey",
                    kind = ?error.kind(),
                    suppressed,
                    "Valkey connection attempt failed"
                );
            }
            None
        }
        .instrument(tracing::Span::current())
        .boxed()
        .shared();
        tokio::spawn(attempt.clone().map(drop));
        attempt
    }
    fn current(&self) -> (u64, Attempt) {
        let current = self.current.lock().unwrap_or_else(PoisonError::into_inner);
        (current.generation, current.attempt.clone())
    }
    /// Replaces the connection of `generation` with a new attempt, unless another
    /// command has replaced it already. The old connection closes once no command
    /// uses it any more.
    fn replace(&self, generation: u64) {
        let mut current = self.current.lock().unwrap_or_else(PoisonError::into_inner);
        if current.generation == generation {
            current.generation += 1;
            current.attempt = Self::attempt(&self.client, &self.settings, &self.log_key);
        }
    }
    /// Keeps the connection of `generation` if it answers a PING within
    /// [`CONFIRM_TIMEOUT`], or `timeout` if shorter: its command was merely slow. A
    /// connection that stays silent is dead without having been closed and is
    /// replaced. The caller does not wait for the outcome.
    fn confirm(
        self: &Arc<Self>,
        generation: u64,
        mut connection: MultiplexedConnection,
        timeout: Duration,
    ) {
        let connector = self.clone();
        tokio::spawn(async move {
            let ping = redis::cmd("PING");
            let answer = tokio::time::timeout(
                CONFIRM_TIMEOUT.min(timeout),
                ping.query_async::<String>(&mut connection),
            )
            .await;
            if !matches!(answer, Ok(Ok(_))) {
                connector.replace(generation);
            }
        });
    }
    /// The exchange behind [`ValkeyConnection::query`].
    async fn exchange(
        self: Arc<Self>,
        command: redis::Cmd,
        timeout: Duration,
    ) -> Result<redis::Value, ConnectionError> {
        use ConnectionError::Unavailable;
        let deadline = Instant::now() + timeout;
        for last in [false, true] {
            let (generation, attempt) = self.current();
            let connection = timeout_at(deadline, attempt)
                .await
                .map_err(|_| Unavailable)?;
            let Some(mut connection) = connection else {
                // After the last try, the next command starts the next attempt.
                if !last {
                    self.replace(generation);
                }
                continue;
            };
            let Ok(result) = timeout_at(deadline, command.query_async(&mut connection)).await
            else {
                self.confirm(generation, connection, timeout);
                return Err(Unavailable);
            };
            match result {
                Ok(value) => return Ok(value),
                Err(error) if closed(&error) && !last => self.replace(generation),
                Err(error) => {
                    if error.is_unrecoverable_error() && !closed(&error) {
                        self.replace(generation);
                    }
                    return Err(Unavailable);
                }
            }
        }
        Err(Unavailable)
    }
}

/// Clones share one multiplexed connection.
#[derive(Clone)]
pub(crate) struct ValkeyConnection {
    connector: Arc<Connector>,
    timeout: Duration,
}

impl ValkeyConnection {
    pub(crate) async fn connect(settings: &BrowserBackendConfig) -> Result<Self, ConnectionError> {
        use ConnectionError::*;
        settings.validate().map_err(|_| Configuration)?;
        let BrowserBackendConfig::Valkey {
            url,
            key_prefix,
            password,
            connect_timeout_ms,
            operation_timeout_ms,
        } = settings
        else {
            return Err(Configuration);
        };
        let mut info: redis::ConnectionInfo = url.parse().map_err(|_| Configuration)?;
        info.redis.password = Some(password.clone());
        let client = redis::Client::open(info).map_err(|_| Configuration)?;
        // Bounds the TCP connect, TLS handshake and authentication of every attempt.
        let settings = redis::AsyncConnectionConfig::new()
            .set_connection_timeout(Duration::from_millis(*connect_timeout_ms));
        let log_key = format!("valkey.connection.attempt_failed:{key_prefix}");
        let attempt = Connector::attempt(&client, &settings, &log_key);
        let backend = Self {
            connector: Arc::new(Connector {
                client,
                settings,
                log_key,
                current: Mutex::new(Current {
                    generation: 0,
                    attempt: attempt.clone(),
                }),
            }),
            timeout: Duration::from_millis(*operation_timeout_ms),
        };
        attempt.await.ok_or(Unavailable)?;
        backend.query::<String>(&redis::cmd("PING")).await?;
        Ok(backend)
    }

    /// Sends one command within the operation deadline.
    ///
    /// If the connection turns out to be closed (Valkey restart, `CLIENT KILL`, idle
    /// timeout) or its connection attempt failed, a new attempt starts at once and the
    /// command is sent once more on it, within the same deadline. The client reports a
    /// command that was never written and one whose reply was lost with the same
    /// error, so the resend can run a command twice. Every store tolerates that: reads
    /// and revocations are idempotent, and one-use transitions (code issue and
    /// redemption, transaction transitions, form consumption, refresh rotation) compare
    /// against the state they expect, so a second run finds it consumed and reports
    /// missing or stale. Effects happen at most once: a lost reply can turn a success
    /// into a definite failure, and quota or budget counters may count one extra
    /// attempt.
    ///
    /// A command that times out after it was sent has an unknown outcome and is never
    /// resent. Its connection may be dead without having been closed (a crashed node,
    /// dropped packets): unless it answers a PING shortly afterwards, it is replaced,
    /// so later commands use a new connection instead of waiting on the old one. A
    /// command still waiting for a connection attempt when the deadline passes leaves
    /// that attempt running. The exchange runs as its own task, so a command whose
    /// caller goes away still completes, and its connection is still checked after a
    /// timeout. Server error replies are never resent, and callers must not retry
    /// mutations themselves. There is no memory fallback.
    pub(crate) async fn query<T: redis::FromRedisValue>(
        &self,
        command: &redis::Cmd,
    ) -> Result<T, ConnectionError> {
        let exchange = self
            .connector
            .clone()
            .exchange(command.clone(), self.timeout);
        let value = tokio::spawn(exchange.instrument(tracing::Span::current()))
            .await
            .map_err(|_| ConnectionError::Unavailable)??;
        T::from_redis_value(&value).map_err(|_| ConnectionError::Unavailable)
    }
}

/// Reset, broken pipe or end of stream on an established connection: it is gone.
/// Refused attempts, timeouts and server replies do not match.
fn closed(error: &redis::RedisError) -> bool {
    error.is_connection_dropped()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> BrowserBackendConfig {
        BrowserBackendConfig::Valkey {
            url: "redis://127.0.0.1:1/0".into(),
            key_prefix: "authotron:test".into(),
            password: "fixture-only".into(),
            connect_timeout_ms: 2000,
            operation_timeout_ms: 1000,
        }
    }

    #[tokio::test]
    async fn invalid_settings_fail_as_configuration_before_network_initialization() {
        assert_eq!(
            ValkeyConnection::connect(&BrowserBackendConfig::Memory {})
                .await
                .err(),
            Some(ConnectionError::Configuration)
        );
        for field in [
            "url",
            "key_prefix",
            "password",
            "connect_timeout_ms",
            "operation_timeout_ms",
        ] {
            let mut config = settings();
            let BrowserBackendConfig::Valkey {
                url,
                key_prefix,
                password,
                connect_timeout_ms,
                operation_timeout_ms,
            } = &mut config
            else {
                unreachable!()
            };
            match field {
                "url" => *url = "redis://user:secret@127.0.0.1:1/0".into(),
                "key_prefix" => *key_prefix = "invalid prefix".into(),
                "password" => *password = " ".into(),
                "connect_timeout_ms" => *connect_timeout_ms = 0,
                _ => *operation_timeout_ms = 10001,
            }
            assert_eq!(
                ValkeyConnection::connect(&config).await.err(),
                Some(ConnectionError::Configuration),
                "{field}"
            );
        }
        let mut config = settings();
        let BrowserBackendConfig::Valkey { url, .. } = &mut config else {
            unreachable!()
        };
        *url = "rediss://valkey.example.org:6379/0".into();
        assert!(config.validate().is_ok());
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn failed_connection_attempts_are_logged_rarely_and_without_credentials() {
        let mut config = settings();
        let BrowserBackendConfig::Valkey { key_prefix, .. } = &mut config else {
            unreachable!()
        };
        *key_prefix = "authotron:attempt-log-test".into();
        for _ in 0..3 {
            assert_eq!(
                ValkeyConnection::connect(&config).await.err(),
                Some(ConnectionError::Unavailable)
            );
        }
        logs_assert(|lines: &[&str]| {
            let failed: Vec<_> = lines
                .iter()
                .filter(|line| line.contains("valkey.connection.attempt_failed"))
                .collect();
            match failed.as_slice() {
                [line] if line.contains(" WARN ") && line.contains("kind=IoError") => Ok(()),
                other => Err(format!("unexpected attempt logs: {other:?}")),
            }
        });
        assert!(!logs_contain("fixture-only"));
    }

    struct Fixture(String);
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::process::Command::new("docker")
                .args(["rm", "-f", &self.0])
                .output();
        }
    }
    fn docker(args: &[&str]) -> String {
        let output = std::process::Command::new("docker")
            .args(args)
            .output()
            .expect("Docker CLI required for disposable Valkey tests");
        assert!(output.status.success(), "Docker fixture command failed");
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }

    /// A disposable Valkey container and settings that reach it directly.
    fn disposable() -> (Fixture, BrowserBackendConfig) {
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
        let mut config = settings();
        let BrowserBackendConfig::Valkey { url, password, .. } = &mut config else {
            unreachable!()
        };
        *url = format!("redis://{}/0", docker(&["port", &fixture.0, "6379/tcp"]));
        *password = "public-disposable-fixture".into();
        (fixture, config)
    }
    async fn ready(config: &BrowserBackendConfig) -> ValkeyConnection {
        for _ in 0..100 {
            if let Ok(connection) = ValkeyConnection::connect(config).await {
                return connection;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("disposable Valkey did not become ready");
    }

    /// Run explicitly: cargo test -p authotron disposable -- --ignored --test-threads=1.
    #[tokio::test]
    #[ignore = "requires Docker; starts and removes its own isolated Valkey container"]
    async fn disposable_valkey_resends_a_command_once_after_its_connection_closed() {
        let (fixture, config) = disposable();
        let connection = ready(&config).await;
        let admin = ValkeyConnection::connect(&config).await.unwrap();
        let mut kill = redis::cmd("CLIENT");
        kill.arg(&["KILL", "TYPE", "normal", "SKIPME", "yes"]);

        // A command that finds its connection closed runs exactly once on the new one.
        for expected in 1..=3_u64 {
            let killed: usize = admin.query(&kill).await.unwrap();
            assert!(killed >= 1, "the fixture connection is closed");
            let count: u64 = connection
                .query(redis::cmd("INCR").arg("fixture:resent"))
                .await
                .unwrap();
            assert_eq!(count, expected);
        }

        // Server error replies are returned without a second run.
        let mut failing = redis::cmd("EVAL");
        failing
            .arg("redis.call('INCR', KEYS[1]) return redis.error_reply('fixture')")
            .arg(1)
            .arg("fixture:failed");
        assert_eq!(
            connection.query::<()>(&failing).await.err(),
            Some(ConnectionError::Unavailable)
        );
        let count: u64 = admin
            .query(redis::cmd("GET").arg("fixture:failed"))
            .await
            .unwrap();
        assert_eq!(count, 1);

        docker(&["stop", &fixture.0]);
        assert_eq!(
            connection.query::<String>(&redis::cmd("PING")).await.err(),
            Some(ConnectionError::Unavailable)
        );
    }

    /// Relays TCP to `target` until [`Self::blackhole`] silently drops the replies of
    /// every connection open at that moment, as a crashed node or a network partition
    /// without FIN or RST does; later connections are relayed normally.
    struct Proxy {
        address: std::net::SocketAddr,
        accepted: Arc<std::sync::atomic::AtomicUsize>,
        open: Arc<Mutex<Vec<Arc<std::sync::atomic::AtomicBool>>>>,
    }
    impl Proxy {
        async fn start(target: &str) -> Self {
            use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let target: std::net::SocketAddr = target.parse().unwrap();
            let proxy = Self {
                address: listener.local_addr().unwrap(),
                accepted: Arc::new(AtomicUsize::new(0)),
                open: Arc::default(),
            };
            let (accepted, open) = (proxy.accepted.clone(), proxy.open.clone());
            tokio::spawn(async move {
                while let Ok((client, _)) = listener.accept().await {
                    let server = tokio::net::TcpStream::connect(target).await.unwrap();
                    let dropped = Arc::new(AtomicBool::new(false));
                    open.lock().unwrap().push(dropped.clone());
                    accepted.fetch_add(1, Ordering::SeqCst);
                    let (mut client_read, mut client_write) = client.into_split();
                    let (mut server_read, mut server_write) = server.into_split();
                    tokio::spawn(async move {
                        tokio::io::copy(&mut client_read, &mut server_write).await
                    });
                    tokio::spawn(async move {
                        let mut buffer = [0; 4096];
                        while let Ok(read @ 1..) = server_read.read(&mut buffer).await {
                            if !dropped.load(Ordering::SeqCst)
                                && client_write.write_all(&buffer[..read]).await.is_err()
                            {
                                break;
                            }
                        }
                    });
                }
            });
            proxy
        }
        fn blackhole(&self) {
            for dropped in self.open.lock().unwrap().iter() {
                dropped.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }
        fn accepted(&self) -> usize {
            self.accepted.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    /// A disposable Valkey, an admin connection to it, a relaying proxy and a connection
    /// through that proxy with a 400 ms operation timeout.
    async fn proxied() -> (Fixture, ValkeyConnection, Proxy, ValkeyConnection) {
        let (fixture, direct) = disposable();
        let admin = ready(&direct).await;
        let proxy = Proxy::start(&docker(&["port", &fixture.0, "6379/tcp"])).await;
        let mut config = direct;
        let BrowserBackendConfig::Valkey {
            url,
            operation_timeout_ms,
            ..
        } = &mut config
        else {
            unreachable!()
        };
        *url = format!("redis://{}/0", proxy.address);
        *operation_timeout_ms = 400;
        let connection = ValkeyConnection::connect(&config).await.unwrap();
        (fixture, admin, proxy, connection)
    }
    fn client_id() -> redis::Cmd {
        redis::cmd("CLIENT").arg("ID").to_owned()
    }
    async fn count(admin: &ValkeyConnection, key: &str) -> u64 {
        admin.query(redis::cmd("GET").arg(key)).await.unwrap()
    }
    /// Waits up to three seconds for the proxy to have accepted `count` connections.
    async fn accepted(proxy: &Proxy, count: usize) {
        for _ in 0..300 {
            if proxy.accepted() >= count {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(proxy.accepted(), count);
    }

    /// Run explicitly: cargo test -p authotron disposable -- --ignored --test-threads=1.
    #[tokio::test]
    #[ignore = "requires Docker; starts and removes its own isolated Valkey container"]
    async fn disposable_valkey_replaces_a_connection_after_a_command_on_it_timed_out() {
        let (_fixture, admin, proxy, connection) = proxied().await;
        let first: u64 = connection.query(&client_id()).await.unwrap();
        assert_eq!(proxy.accepted(), 1);

        // The command reaches Valkey, but its reply never returns: it times out, and
        // neither does the PING that follows, so the connection is replaced.
        proxy.blackhole();
        let started = std::time::Instant::now();
        assert_eq!(
            connection
                .query::<u64>(redis::cmd("INCR").arg("fixture:timed-out"))
                .await
                .err(),
            Some(ConnectionError::Unavailable)
        );
        let elapsed = started.elapsed();
        assert!((400..1_000).contains(&elapsed.as_millis()), "{elapsed:?}");
        accepted(&proxy, 2).await;
        let second: u64 = connection.query(&client_id()).await.unwrap();
        assert_ne!(second, first);
        // The timed-out command ran once and was not resent.
        assert_eq!(count(&admin, "fixture:timed-out").await, 1);
        // Clones share the replacement.
        let clone: u64 = connection.clone().query(&client_id()).await.unwrap();
        assert_eq!((clone, proxy.accepted()), (second, 2));
    }

    /// Run explicitly: cargo test -p authotron disposable -- --ignored --test-threads=1.
    #[tokio::test]
    #[ignore = "requires Docker; starts and removes its own isolated Valkey container"]
    async fn disposable_valkey_keeps_a_connection_whose_command_was_only_slow() {
        let (_fixture, admin, proxy, connection) = proxied().await;
        let first: u64 = connection.query(&client_id()).await.unwrap();
        // Writes wait 600 ms: the command times out, but the PING queued behind it
        // is answered within the confirmation window.
        let pause = redis::cmd("CLIENT")
            .arg(&["PAUSE", "600", "WRITE"])
            .to_owned();
        let _: String = admin.query(&pause).await.unwrap();
        assert_eq!(
            connection
                .query::<u64>(redis::cmd("INCR").arg("fixture:slow"))
                .await
                .err(),
            Some(ConnectionError::Unavailable)
        );
        tokio::time::sleep(Duration::from_millis(1_000)).await;
        let same: u64 = connection.query(&client_id()).await.unwrap();
        assert_eq!((same, proxy.accepted()), (first, 1));
        assert_eq!(count(&admin, "fixture:slow").await, 1);
    }

    /// Run explicitly: cargo test -p authotron disposable -- --ignored --test-threads=1.
    #[tokio::test]
    #[ignore = "requires Docker; starts and removes its own isolated Valkey container"]
    async fn disposable_valkey_replaces_a_silent_connection_once_for_concurrent_commands() {
        let (_fixture, admin, proxy, connection) = proxied().await;
        connection.query::<u64>(&client_id()).await.unwrap();
        proxy.blackhole();
        let commands = (0..8).map(|_| {
            let connection = connection.clone();
            async move {
                connection
                    .query::<u64>(redis::cmd("INCR").arg("fixture:concurrent"))
                    .await
            }
        });
        let results = futures::future::join_all(commands).await;
        assert!(results.iter().all(|result| result.is_err()));
        accepted(&proxy, 2).await;
        connection.query::<u64>(&client_id()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(proxy.accepted(), 2, "replaced once");
        assert_eq!(count(&admin, "fixture:concurrent").await, 8);
    }

    /// Run explicitly: cargo test -p authotron disposable -- --ignored --test-threads=1.
    #[tokio::test]
    #[ignore = "requires Docker; starts and removes its own isolated Valkey container"]
    async fn disposable_valkey_replaces_a_silent_connection_after_its_caller_gave_up() {
        let (_fixture, _admin, proxy, connection) = proxied().await;
        connection.query::<u64>(&client_id()).await.unwrap();
        proxy.blackhole();
        // The caller stops waiting long before the operation timeout; the command still
        // times out on its own and its connection is still replaced.
        let incr = redis::cmd("INCR").arg("fixture:abandoned").to_owned();
        let abandoned = connection.query::<u64>(&incr);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), abandoned)
                .await
                .is_err()
        );
        accepted(&proxy, 2).await;
        connection.query::<u64>(&client_id()).await.unwrap();
    }
}

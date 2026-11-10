// (C) Copyright 2025- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! Application startup and server initialization.
//!
//! Starts the application server and, when enabled, a dedicated metrics/health server
//! on a separate port.

use std::fmt::{self, Display, Formatter};
use std::io;
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::sync::watch;
use tracing::info;

use crate::auth::Auth;
use crate::config::ConfigV2;
use crate::metrics::Metrics;
use crate::routes;
use crate::state::AppState;
use crate::store::create_store;

/// Build the auth-o-tron application router and state from config.
///
/// Returns the app router ready to be served with `axum::serve()`.
/// The caller is responsible for binding a `TcpListener` and serving.
pub async fn build_app(
    config: Arc<ConfigV2>,
) -> Result<(axum::Router, AppState), Box<dyn std::error::Error>> {
    let store = create_store(&config.store).await;
    let auth_config = config.auth.clone();
    let auth = Arc::new(Auth::new(
        &config.providers,
        &config.augmenters,
        store.clone(),
        auth_config,
    ));

    let metrics = Metrics::new();

    // Pre-initialise per-provider/augmenter/realm series at zero from the
    // configured set so alert rules evaluate against existing series.
    let provider_desc: Vec<(String, String, String)> = auth
        .providers
        .iter()
        .map(|p| {
            (
                p.get_name().to_string(),
                p.get_type().to_string(),
                p.get_realm().unwrap_or("unknown").to_string(),
            )
        })
        .collect();
    let augmenter_desc: Vec<(String, String, String)> = auth
        .augmenters
        .iter()
        .map(|a| {
            (
                a.get_name().to_string(),
                a.get_type().to_string(),
                a.get_realm().to_string(),
            )
        })
        .collect();
    metrics.preinit_series(&provider_desc, &augmenter_desc);

    let state = AppState {
        config: config.clone(),
        auth,
        store,
        metrics,
    };

    let app = routes::create_app_router(state.clone());
    Ok((app, state))
}

/// Coordinates graceful shutdown across all running HTTP servers.
#[derive(Clone, Debug)]
pub struct ShutdownCoordinator {
    sender: watch::Sender<bool>,
}

/// A shutdown notification for one server.
#[derive(Debug)]
pub struct ShutdownSignal {
    receiver: watch::Receiver<bool>,
}

impl ShutdownCoordinator {
    /// Create a coordinator whose shutdown has not yet been requested.
    pub fn new() -> Self {
        let (sender, _) = watch::channel(false);
        Self { sender }
    }

    /// Subscribe one server to the shared shutdown notification.
    pub fn subscribe(&self) -> ShutdownSignal {
        ShutdownSignal {
            receiver: self.sender.subscribe(),
        }
    }

    /// Notify all current and future subscribers that shutdown was requested.
    pub fn shutdown(&self) {
        self.sender.send_replace(true);
    }
}

impl Default for ShutdownCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

impl ShutdownSignal {
    /// Wait until the coordinator requests shutdown.
    pub async fn wait(mut self) {
        while !*self.receiver.borrow() {
            if self.receiver.changed().await.is_err() {
                break;
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ShutdownReason {
    Interrupt,
    Terminate,
}

impl Display for ShutdownReason {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Interrupt => formatter.write_str("SIGINT"),
            Self::Terminate => formatter.write_str("SIGTERM"),
        }
    }
}

#[cfg(unix)]
async fn wait_for_shutdown_signal() -> io::Result<ShutdownReason> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut terminate = signal(SignalKind::terminate())?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => {
            result?;
            Ok(ShutdownReason::Interrupt)
        }
        signal = terminate.recv() => signal
            .map(|_| ShutdownReason::Terminate)
            .ok_or_else(|| io::Error::other("SIGTERM signal stream closed")),
    }
}

#[cfg(not(unix))]
async fn wait_for_shutdown_signal() -> io::Result<ShutdownReason> {
    tokio::signal::ctrl_c().await?;
    Ok(ShutdownReason::Interrupt)
}

fn server_shutdown_signals(
    coordinator: &ShutdownCoordinator,
    metrics_enabled: bool,
) -> (ShutdownSignal, Option<ShutdownSignal>) {
    let app = coordinator.subscribe();
    let metrics = metrics_enabled.then(|| coordinator.subscribe());
    (app, metrics)
}

#[derive(Clone, Copy)]
enum ServerKind {
    Application,
    Metrics,
}

impl Display for ServerKind {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Application => formatter.write_str("application"),
            Self::Metrics => formatter.write_str("metrics"),
        }
    }
}

#[cfg(all(unix, debug_assertions))]
impl ServerKind {
    fn test_listener_environment(self) -> &'static str {
        match self {
            Self::Application => "AUTHOTRON_TEST_APP_LISTENER_FD",
            Self::Metrics => "AUTHOTRON_TEST_METRICS_LISTENER_FD",
        }
    }
}

#[cfg(all(unix, debug_assertions))]
fn listener_from_test_environment(
    kind: ServerKind,
    host: &str,
    port: u16,
) -> io::Result<Option<TcpListener>> {
    use std::env;
    use std::net::IpAddr;
    use std::os::fd::{FromRawFd, OwnedFd};

    let environment = kind.test_listener_environment();
    let Some(value) = env::var_os(environment) else {
        return Ok(None);
    };
    let value = value
        .to_str()
        .ok_or_else(|| io::Error::other(format!("{environment} is not valid UTF-8")))?;
    let inherited_fd = value.parse::<libc::c_int>().map_err(|error| {
        io::Error::other(format!(
            "{environment} must contain a file descriptor: {error}"
        ))
    })?;

    // Duplicate first so an invalid environment value is reported by the OS rather than
    // being passed to `OwnedFd::from_raw_fd`, which requires a valid, owned descriptor.
    // SAFETY: `fcntl` does not dereference pointers, and a successful `F_DUPFD_CLOEXEC`
    // returns a new descriptor owned by this process.
    let listener_fd = unsafe { libc::fcntl(inherited_fd, libc::F_DUPFD_CLOEXEC, 0) };
    if listener_fd == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the successful `fcntl` call above returned a new descriptor that this
    // process owns and has not transferred elsewhere.
    let listener_fd = unsafe { OwnedFd::from_raw_fd(listener_fd) };
    let listener = std::net::TcpListener::from(listener_fd);
    listener.set_nonblocking(true)?;

    let actual_address = listener.local_addr()?;
    if actual_address.port() != port {
        return Err(io::Error::other(format!(
            "pre-bound {kind} listener uses port {}, but configuration uses {port}",
            actual_address.port()
        )));
    }
    if let Ok(expected_ip) = host.parse::<IpAddr>()
        && actual_address.ip() != expected_ip
    {
        return Err(io::Error::other(format!(
            "pre-bound {kind} listener uses address {}, but configuration uses {host}",
            actual_address.ip()
        )));
    }

    TcpListener::from_std(listener).map(Some)
}

async fn bind_listener(host: &str, port: u16, kind: ServerKind) -> io::Result<TcpListener> {
    #[cfg(all(unix, debug_assertions))]
    if let Some(listener) = listener_from_test_environment(kind, host, port)? {
        return Ok(listener);
    }

    #[cfg(not(all(unix, debug_assertions)))]
    let _ = kind;

    TcpListener::bind((host, port)).await
}

async fn run_servers(
    config: Arc<ConfigV2>,
    shutdown: ShutdownCoordinator,
) -> Result<(), Box<dyn std::error::Error>> {
    let (app, state) = build_app(config.clone()).await?;

    if config.metrics.enabled && config.server.port == config.metrics.port {
        return Err(format!(
            "application port and metrics port are both {}, they must be different",
            config.server.port
        )
        .into());
    }

    let host = config.server.host.as_str();
    let app_listener = bind_listener(host, config.server.port, ServerKind::Application)
        .await
        .map_err(|error| {
            format!(
                "could not bind application server on {}:{}: {error}",
                host, config.server.port
            )
        })?;

    let app_port = app_listener.local_addr()?.port();

    info!(
        event_name = "startup.server.listening",
        event_domain = "startup",
        host,
        port = app_port,
        "application server listening"
    );

    let (app_shutdown, metrics_shutdown) =
        server_shutdown_signals(&shutdown, config.metrics.enabled);
    let app_server = axum::serve(
        app_listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(app_shutdown.wait());

    if let Some(metrics_shutdown) = metrics_shutdown {
        let metrics_router = routes::create_metrics_router(state);
        let metrics_listener = bind_listener(host, config.metrics.port, ServerKind::Metrics)
            .await
            .map_err(|error| {
                format!(
                    "could not bind metrics server on {}:{}: {error}",
                    host, config.metrics.port
                )
            })?;

        let metrics_port = metrics_listener.local_addr()?.port();

        info!(
            event_name = "startup.metrics.listening",
            event_domain = "startup",
            host,
            port = metrics_port,
            "metrics server listening"
        );

        let metrics_server = axum::serve(metrics_listener, metrics_router)
            .with_graceful_shutdown(metrics_shutdown.wait());
        tokio::try_join!(app_server, metrics_server)?;
    } else {
        info!(
            event_name = "startup.metrics.disabled",
            event_domain = "startup",
            "metrics server disabled"
        );
        app_server.await?;
    }

    Ok(())
}

async fn coordinate_shutdown(
    coordinator: ShutdownCoordinator,
) -> Result<(), Box<dyn std::error::Error>> {
    let reason = wait_for_shutdown_signal().await?;
    info!(
        event_name = "startup.shutdown.requested",
        event_domain = "startup",
        signal = %reason,
        "shutdown requested; draining HTTP servers"
    );
    coordinator.shutdown();
    Ok(())
}

/// Start the application and metrics servers and stop them gracefully on SIGINT or SIGTERM.
pub async fn run(config: Arc<ConfigV2>) -> Result<(), Box<dyn std::error::Error>> {
    let coordinator = ShutdownCoordinator::new();
    tokio::try_join!(
        run_servers(config, coordinator.clone()),
        coordinate_shutdown(coordinator),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::time::timeout;

    use super::*;

    #[tokio::test]
    async fn coordinator_notifies_all_servers_and_late_subscribers() {
        let coordinator = ShutdownCoordinator::new();
        let (app_shutdown, metrics_shutdown) = server_shutdown_signals(&coordinator, true);
        let app = tokio::spawn(app_shutdown.wait());
        let metrics = tokio::spawn(metrics_shutdown.expect("metrics signal").wait());

        tokio::task::yield_now().await;
        assert!(!app.is_finished());
        assert!(!metrics.is_finished());

        coordinator.shutdown();
        timeout(Duration::from_secs(1), app)
            .await
            .expect("application server received shutdown")
            .expect("application shutdown task completed");
        timeout(Duration::from_secs(1), metrics)
            .await
            .expect("metrics server received shutdown")
            .expect("metrics shutdown task completed");
        timeout(Duration::from_secs(1), coordinator.subscribe().wait())
            .await
            .expect("late subscriber observed prior shutdown");
    }

    #[test]
    fn metrics_disabled_does_not_create_a_metrics_signal() {
        let coordinator = ShutdownCoordinator::new();
        let (_, metrics_shutdown) = server_shutdown_signals(&coordinator, false);

        assert!(metrics_shutdown.is_none());
    }
}

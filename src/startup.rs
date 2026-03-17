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

use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::info;

use crate::auth::Auth;
use crate::config::ConfigV2;
use crate::metrics::Metrics;
use crate::routes;
use crate::state::AppState;
use crate::store::create_store;

pub async fn run(config: Arc<ConfigV2>) -> Result<(), Box<dyn std::error::Error>> {
    let store = create_store(&config.store).await;
    let auth_config = config.auth.clone();
    let auth = Arc::new(Auth::new(
        &config.providers,
        &config.augmenters,
        store.clone(),
        auth_config,
    ));

    let metrics = Metrics::new();

    let state = AppState {
        config: config.clone(),
        auth,
        store,
        metrics,
    };

    if config.metrics.enabled && config.server.port == config.metrics.port {
        return Err(format!(
            "application port and metrics port are both {}, they must be different",
            config.server.port
        )
        .into());
    }

    let host = config.server.host.as_str();
    let app = routes::create_app_router(state.clone());
    let app_listener = TcpListener::bind((host, config.server.port))
        .await
        .map_err(|e| {
            format!(
                "could not bind application server on {}:{}: {e}",
                host, config.server.port
            )
        })?;

    info!(
        event_name = "startup.server.listening",
        event_domain = "startup",
        host,
        port = config.server.port,
        "application server listening"
    );

    if config.metrics.enabled {
        let metrics_router = routes::create_metrics_router(state);
        let metrics_listener = TcpListener::bind((host, config.metrics.port))
            .await
            .map_err(|e| {
                format!(
                    "could not bind metrics server on {}:{}: {e}",
                    host, config.metrics.port
                )
            })?;

        info!(
            event_name = "startup.metrics.listening",
            event_domain = "startup",
            host,
            port = config.metrics.port,
            "metrics server listening"
        );

        tokio::try_join!(
            async {
                axum::serve(
                    app_listener,
                    app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
                )
                .await
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
            },
            async {
                axum::serve(metrics_listener, metrics_router)
                    .await
                    .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
            }
        )?;
    } else {
        info!(
            event_name = "startup.metrics.disabled",
            event_domain = "startup",
            "metrics server disabled"
        );

        axum::serve(
            app_listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await?;
    }

    Ok(())
}

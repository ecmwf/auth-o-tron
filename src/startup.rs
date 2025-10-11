//! Application startup and server initialization.
//!
//! This module handles the creation and configuration of the HTTP server,
//! including initialization of the authentication system, token store, and route setup.

use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::info;

use crate::auth::Auth;
use crate::config::ConfigV1;
use crate::routes;
use crate::state::AppState;
use crate::store::create_store;

/// Initializes and runs the application server.
///
/// Sets up the authentication system, token store, and HTTP server
/// with configured routes. Binds to the address specified in the configuration
/// and starts serving requests.
///
/// # Errors
///
/// Returns an error if the server fails to bind to the specified address
/// or encounters a runtime error during execution.
pub async fn run(config: Arc<ConfigV1>) -> Result<(), Box<dyn std::error::Error>> {
    let store = create_store(&config.store).await;
    let auth_config = config.auth.clone();
    let auth = Arc::new(Auth::new(
        &config.providers,
        &config.augmenters,
        store.clone(),
        auth_config,
    ));

    info!("Starting server on {}", config.bind_address);

    let state = AppState {
        config: config.clone(),
        auth,
        store,
    };

    let app = routes::create_router(state);

    let listener = TcpListener::bind(&config.bind_address)
        .await
        .expect("Could not bind to specified address");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await
    .unwrap();

    Ok(())
}

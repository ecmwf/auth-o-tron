mod auth;
mod config;
mod models;
mod providers;
mod store;
mod utils;

use std::collections::HashMap;
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{self, IntoResponse};
use axum::routing::{delete, get};
use axum::{Json, Router};
use http::HeaderValue;
use serde::{Deserialize, Serialize};
use tracing::{error, info};
use uuid::Uuid;

use crate::auth::Auth;
use crate::config::ConfigV1;
use crate::models::{Token, User};
use crate::store::{create_store, Store};
use crate::utils::http_helpers::HTTPError;
use crate::utils::logger::init_logging;

/// Our application state, shared with Axum handlers.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<ConfigV1>,
    pub auth: Arc<Auth>,
    pub store: Arc<dyn Store>,
}

/// For returning errors in JSON.
#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

/// Helper that maps store errors into a (StatusCode, JSON) pair.
fn map_store_error(e: String) -> (StatusCode, Json<ErrorResponse>) {
    error!("Store error: {}", e);

    if e.to_lowercase().contains("disabled") {
        // If the store is "disabled", return 503
        let body = ErrorResponse {
            error: "Token store is disabled".to_string(),
        };
        (StatusCode::SERVICE_UNAVAILABLE, Json(body))
    } else {
        // Otherwise, something else is wrong => 500
        let body = ErrorResponse {
            error: format!("Store error: {}", e),
        };
        (StatusCode::INTERNAL_SERVER_ERROR, Json(body))
    }
}

/// GET /authenticate
///
/// If the user is successfully extracted, we respond with 200 and a new JWT in the "Authorization" header.
async fn authenticate(
    user: User,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, HTTPError> {
    let jwt = user.to_jwt(&state.config.jwt);

    let mut response_builder = axum::http::response::Response::builder()
        .status(StatusCode::OK)
        .header("Authorization", format!("Bearer {}", jwt))
        .body(Body::from("Authenticated successfully"))
        .map_err(|e| HTTPError::new(StatusCode::INTERNAL_SERVER_ERROR, e.to_string(), None))?;

    if state.config.include_legacy_headers.unwrap_or(false) {
        let headers = response_builder.headers_mut();
        headers.append(
            "X-Auth-Username",
            HeaderValue::from_str(&user.username).unwrap(),
        );
        headers.append("X-Auth-Realm", HeaderValue::from_str(&user.realm).unwrap());
        headers.append(
            "X-Auth-Roles",
            HeaderValue::from_str(&user.roles.join(",")).unwrap(),
        );
    }

    Ok(response_builder)
}

/// A small struct for returning a newly created token in JSON.
#[derive(Serialize, Deserialize)]
struct CreateTokenResponse {
    token: String,
}

/// GET /token
///
/// Issues a new token for the authenticated user and stores it in the datastore.
async fn create_token(
    user: User,
    State(state): State<AppState>,
) -> Result<(StatusCode, Json<CreateTokenResponse>), (StatusCode, Json<ErrorResponse>)> {
    let token_str = Uuid::new_v4().to_string();
    let token = Token::new(token_str.clone(), HashMap::new(), None);

    state
        .store
        .add_token(&token, &user, 3600)
        .await
        .map_err(map_store_error)?;

    Ok((
        StatusCode::OK,
        Json(CreateTokenResponse { token: token_str }),
    ))
}

/// A small struct for listing tokens in JSON.
#[derive(Serialize, Deserialize)]
struct GetTokensResponse {
    tokens: Vec<Token>,
}

/// GET /tokens
///
/// Fetches all tokens for the current user.
async fn get_tokens(
    user: User,
    State(state): State<AppState>,
) -> Result<(StatusCode, Json<GetTokensResponse>), (StatusCode, Json<ErrorResponse>)> {
    let tokens = state
        .store
        .get_tokens(&user)
        .await
        .map_err(map_store_error)?;
    Ok((StatusCode::OK, Json(GetTokensResponse { tokens })))
}

/// DELETE /token/<token>
///
/// Removes a specific token from the datastore.
async fn delete_token(
    _user: User,
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    state
        .store
        .delete_token(&token)
        .await
        .map_err(map_store_error)?;
    Ok(StatusCode::NO_CONTENT)
}

/// GET /health
///
/// Returns a simple "OK".
async fn health_check() -> impl IntoResponse {
    response::Response::new(Body::from("OK"))
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();

    // If we pass --schema, just print the JSON schema for the config and exit
    if args.contains(&"--schema".to_string()) {
        config::print_schema();
        return;
    }

    // Load the main config from config.yaml
    let config = Arc::new(config::load_config());
    // Initialize logging from config
    init_logging(&config.logging);

    // Create the store (could be NoStore or MongoDBStore, etc.)
    let store = create_store(&config.store).await;

    // Create the Auth object including all configured providers and augmenters
    let auth_config = config.auth.clone();
    let auth = Arc::new(Auth::new(
        &config.providers,
        &config.augmenters,
        store.clone(),
        auth_config,
    ));

    info!("Starting server on {}", &config.bind_address);

    // Build the Axum router with state
    let state = AppState {
        config: config.clone(),
        auth,
        store,
    };

    let app = Router::new()
        .route("/authenticate", get(authenticate))
        .route("/token", get(create_token))
        .route("/tokens", get(get_tokens))
        .route("/token/:token", delete(delete_token))
        .route("/providers", get(providers::list_providers))
        .route("/health", get(health_check))
        .with_state(state);

    // Start listening
    let listener = tokio::net::TcpListener::bind(&config.bind_address)
        .await
        .expect("Could not bind to specified address");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
}

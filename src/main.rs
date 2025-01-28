mod auth;
mod config;
mod http_helpers;
mod logger;
mod models;
mod store;

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
use logger::init_logging;
use serde::{Deserialize, Serialize};
use tracing::{error, info};
use uuid::Uuid;

use crate::auth::Auth;
use crate::http_helpers::HTTPError;
use crate::models::{Token, User};
use crate::store::Store;

// -- API Routes

// GET /authenticate
async fn authenticate(
    user: User,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, HTTPError> {
    let jwt = user.to_jwt(&state.config.jwt);

    let mut response_builder = axum::http::response::Response::builder()
        .status(StatusCode::OK)
        .header("Authorization", format!("Bearer {}", jwt))
        .body(Body::from("Authenticated successfully"))
        .map_err(|e| HTTPError::new(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

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
        // If needed, you can append more legacy headers here.
    }

    Ok(response_builder)
}

// GET /token
#[derive(Serialize, Deserialize)]
struct CreateUserRequest {
    user: User,
}

#[derive(Serialize, Deserialize)]
struct CreateTokenResponse {
    token: String,
}

async fn create_token(
    user: User,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, StatusCode> {
    let token_str = Uuid::new_v4().to_string();
    let token = Token::new(token_str.clone(), HashMap::new(), None);

    state
        .store
        .add_token(&token, &user, 3600)
        .await
        .map_err(|e| {
            error!("Failed to add token to store: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok((
        StatusCode::OK,
        Json(CreateTokenResponse { token: token_str }),
    ))
}

// GET /tokens
#[derive(Serialize, Deserialize)]
struct GetTokensResponse {
    tokens: Vec<Token>,
}

async fn get_tokens(
    user: User,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, StatusCode> {
    let tokens = state.store.get_tokens(&user).await.map_err(|e| {
        error!("Failed to retrieve tokens: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    Ok((StatusCode::OK, Json(GetTokensResponse { tokens })))
}

// DELETE /token/<token>
#[derive(Serialize, Deserialize)]
struct DeleteTokenRequest {
    token: String,
}

async fn delete_token(
    _user: User,
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    state.store.delete_token(&token).await.map_err(|e| {
        error!("Failed to delete token: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    Ok(StatusCode::NO_CONTENT)
}

// GET /health
async fn health_check() -> impl IntoResponse {
    response::Response::new(Body::from("OK"))
}

// -- Entrypoint

#[derive(Clone)]
struct AppState {
    config: Arc<config::ConfigV1>,
    auth: Arc<Auth>,
    store: Arc<dyn Store>,
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();

    if args.contains(&"--schema".to_string()) {
        config::print_schema();
        return;
    }

    let config = Arc::new(config::load_config());

    // Initialize logging from config
    init_logging(&config.logging);

    let store = store::create_store(&config.store).await;
    let auth = Arc::new(Auth::new(
        &config.providers,
        &config.augmenters,
        store.clone(),
    ));

    info!("Starting server on {}", &config.bind_address);

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
        .route("/health", get(health_check))
        .with_state(state);

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

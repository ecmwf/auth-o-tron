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


#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}


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

/// If successful, returns 200 + JSON with the new token.
/// If store is disabled or there's an error, returns JSON error with 503 or 500.
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

// GET /tokens
#[derive(Serialize, Deserialize)]
struct GetTokensResponse {
    tokens: Vec<Token>,
}

/// Lists all tokens associated with the authenticated user.
async fn get_tokens(
    user: User,
    State(state): State<AppState>,
) -> Result<(StatusCode, Json<GetTokensResponse>), (StatusCode, Json<ErrorResponse>)> {
    let tokens = state.store.get_tokens(&user).await.map_err(map_store_error)?;

    Ok((StatusCode::OK, Json(GetTokensResponse { tokens })))
}

// DELETE /token/<token>
#[derive(Serialize, Deserialize)]
struct DeleteTokenRequest {
    token: String,
}

/// Deletes the given token if found. Returns 204 or an error JSON.
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

// GET /health
async fn health_check() -> impl IntoResponse {
    response::Response::new(Body::from("OK"))
}


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

    // Potentially returns a NoStore if store.enabled = false
    let store = store::create_store(&config.store).await;

    // Build the Auth object
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

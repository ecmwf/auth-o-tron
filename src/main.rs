mod auth;
mod config;
mod http_helpers;
mod models;
mod store;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::response::{self};
use axum::routing::get;
use axum::Router;
use uuid::Uuid;

use crate::auth::Auth;
use crate::http_helpers::HTTPError;
use crate::models::User;
use crate::store::Store;

use inline_colorization::*;

// -- API Routes

// GET /authenticate

async fn authenticate(user: User) -> Result<impl IntoResponse, HTTPError> {
    let jwt = user.to_jwt();

    let response = response::Response::builder()
        .status(StatusCode::OK)
        .header("Authorization", format!("Bearer {}", jwt))
        .body(Body::from("Authenticated successfully"))
        .unwrap();

    Ok(response)
}

// GET /token

async fn create_token(
    user: User,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, HTTPError> {
    let token = Uuid::new_v4().to_string();
    state.store.add_token(&token, &user, 3600).await.unwrap();
    Ok((StatusCode::OK, token))
}

// GET /health

async fn health_check() -> impl IntoResponse {
    response::Response::new(Body::from("OK"))
}

// -- Entrypoint

#[derive(Clone)]
struct AppState {
    auth: Arc<Auth>,
    store: Arc<dyn Store>,
}

#[tokio::main]
async fn main() {
    let config = config::load_config();

    let store = store::create_store(&config.store);

    let auth = Arc::new(Auth::new(config.providers, config.augmenters));

    let state = AppState { auth, store };

    println!(
        "{color_magenta}{style_bold}Starting server on {}...{color_reset}{style_reset}",
        config.bind_address
    );

    let app = Router::new()
        .route("/authenticate", get(authenticate))
        .route("/token", get(create_token))
        .route("/health", get(health_check))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(config.bind_address)
        .await
        .unwrap();
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
}

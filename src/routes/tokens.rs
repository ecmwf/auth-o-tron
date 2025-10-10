//! Token management endpoint handlers.

use axum::extract::Path;
use axum::http::StatusCode;
use axum::{
    Json, Router,
    routing::{delete, get},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use crate::models::token::Token;
use crate::models::user::User;
use crate::state::AppState;

/// Registers token management routes.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/token", get(create_token))
        .route("/tokens", get(get_tokens))
        .route("/token/{token}", delete(delete_token))
}

#[derive(Serialize, Deserialize)]
struct CreateTokenResponse {
    token: String,
}

#[derive(Serialize, Deserialize)]
struct GetTokensResponse {
    tokens: Vec<Token>,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

/// Maps store errors to appropriate HTTP responses.
fn map_store_error(e: String) -> (StatusCode, Json<ErrorResponse>) {
    tracing::error!("Store error: {}", e);
    if e.to_lowercase().contains("disabled") {
        let body = ErrorResponse {
            error: "Token store is disabled".to_string(),
        };
        (StatusCode::SERVICE_UNAVAILABLE, Json(body))
    } else {
        let body = ErrorResponse {
            error: format!("Store error: {}", e),
        };
        (StatusCode::INTERNAL_SERVER_ERROR, Json(body))
    }
}

/// Creates a new authentication token for the authenticated user.
async fn create_token(
    user: User,
    axum::extract::State(state): axum::extract::State<AppState>,
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

/// Retrieves all tokens belonging to the authenticated user.
async fn get_tokens(
    user: User,
    axum::extract::State(state): axum::extract::State<AppState>,
) -> Result<(StatusCode, Json<GetTokensResponse>), (StatusCode, Json<ErrorResponse>)> {
    let tokens = state
        .store
        .get_tokens(&user)
        .await
        .map_err(map_store_error)?;
    Ok((StatusCode::OK, Json(GetTokensResponse { tokens })))
}

/// Deletes a specific authentication token.
async fn delete_token(
    _user: User,
    axum::extract::State(state): axum::extract::State<AppState>,
    Path(token): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    state
        .store
        .delete_token(&token)
        .await
        .map_err(map_store_error)?;
    Ok(StatusCode::NO_CONTENT)
}

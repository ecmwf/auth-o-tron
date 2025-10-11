//! Authentication endpoint handlers.

use axum::body::Body;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{Router, routing::get};
use http::HeaderValue;

use crate::models::user::User;
use crate::state::AppState;
use crate::utils::http_helpers::HTTPError;

/// Registers authentication routes.
pub fn routes() -> Router<AppState> {
    Router::new().route("/authenticate", get(authenticate))
}

/// Authenticates a user and returns a JWT token.
///
/// The user is extracted from the request via configured authentication providers.
/// Returns a JWT in the `Authorization` header and optionally includes legacy headers
/// for backwards compatibility.
async fn authenticate(
    user: User,
    axum::extract::State(state): axum::extract::State<AppState>,
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

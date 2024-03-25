mod auth;

use auth::User;

use axum::{
    body::Body,
    http::{header::HeaderMap, StatusCode},
    response::{self, IntoResponse, Response},
    routing::get,
    Extension, Router,
};

use crate::auth::Auth;
use std::sync::Arc;

// -- Error Handling

pub struct HTTPError {
    status: StatusCode,
    message: String,
}

impl HTTPError {
    pub fn new(status: StatusCode, message: impl Into<String>) -> Self {
        HTTPError {
            status,
            message: message.into(),
        }
    }
}

impl IntoResponse for HTTPError {
    fn into_response(self) -> Response {
        let body = format!("{{\"error\": \"{}\"}}", self.message);
        Response::builder()
            .status(self.status)
            .header("Content-Type", "application/json")
            .body(body.into())
            .unwrap()
    }
}

// -- Authenticate Method

async fn extract_user_from_header(headers: &HeaderMap, auth: Arc<Auth>) -> Result<User, HTTPError> {
    let auth_header = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");

    match auth.authenticate(auth_header).await {
        Some(user) => Ok(user),
        None => Err(HTTPError::new(
            StatusCode::UNAUTHORIZED,
            "Unauthorized access",
        )),
    }
}

// -- API Routes

async fn authenticate(
    headers: HeaderMap,
    Extension(auth): Extension<Arc<Auth>>,
) -> Result<impl IntoResponse, HTTPError> {
    let user = extract_user_from_header(&headers, auth).await?;
    println!("Authenticated user: {:?}", user.username);
    let body = format!("User {} authenticated successfully", user.username);
    Ok((StatusCode::OK, body))
}

async fn create_token(
    headers: HeaderMap,
    Extension(auth): Extension<Arc<Auth>>,
) -> Result<impl IntoResponse, HTTPError> {
    let user = extract_user_from_header(&headers, auth).await?;
    println!("Authenticated user: {:?}", user.username);
    // Proceed with token creation logic...
    Ok((StatusCode::OK, "some_token"))
}

async fn health_check() -> impl IntoResponse {
    response::Response::new(Body::from("OK"))
}

// -- Entrypoint

#[tokio::main]
async fn main() {
    let auth = Arc::new(Auth::new());

    let app = Router::new()
        .route("/authenticate", get(authenticate))
        .route("/create_token", get(create_token))
        .layer(Extension(auth))
        .route("/health_check", get(health_check));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

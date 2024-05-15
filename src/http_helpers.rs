use std::net::SocketAddr;

use crate::models::User;
use crate::AppState;
use axum::async_trait;
use axum::extract::ConnectInfo;
use axum::extract::FromRequestParts;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::response::Response;
use http::request::Parts;

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

// -- User Authentication

#[async_trait]
impl FromRequestParts<AppState> for User {
    type Rejection = HTTPError;

    async fn from_request_parts<'a, 'b>(
        parts: &'a mut Parts,
        state: &'b AppState,
    ) -> Result<User, HTTPError> {
        let auth_header = parts
            .headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");

        let client_ip = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ConnectInfo(addr)| addr.ip())
            .unwrap_or_else(|| {
                println!("Failed to get client IP address.");
                "unknown".parse().unwrap()
            });

        match state
            .auth
            .authenticate(auth_header, &client_ip.to_string())
            .await
        {
            Some(user) => Ok(user),
            None => Err(HTTPError::new(
                StatusCode::UNAUTHORIZED,
                "Unauthorized access",
            )),
        }
    }
}

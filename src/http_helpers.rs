use std::net::SocketAddr;

use axum::async_trait;
use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use http::request::Parts;
use tracing::warn;

use crate::models::User;
use crate::AppState;

/// A general purpose HTTP error type that can be converted into an `IntoResponse`.
pub struct HTTPError {
    status: StatusCode,
    message: String,
}

impl HTTPError {
    /// Creates a new HTTP error with the given status code and message.
    pub fn new(status: StatusCode, message: impl Into<String>) -> Self {
        HTTPError {
            status,
            message: message.into(),
        }
    }
}

/// Converts our `HTTPError` into an HTTP response.
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

/// Extractor implementation: tries to convert the request parts into a `User`.
/// This uses the `authorization` header and calls `Auth::authenticate`.
#[async_trait]
impl FromRequestParts<AppState> for User {
    type Rejection = HTTPError;

    async fn from_request_parts<'a, 'b>(
        parts: &'a mut Parts,
        state: &'b AppState,
    ) -> Result<User, HTTPError> {
        // Retrieve the authorization header
        let auth_header = parts
            .headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");

        // Try to read the client IP from the connection info
        let client_ip = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ConnectInfo(addr)| addr.ip())
            .unwrap_or_else(|| {
                // Log a warning if we cannot get the IP address
                warn!("Unable to determine client IP address.");
                "unknown".parse().unwrap()
            });

        // Ask our Auth object to handle the authentication
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

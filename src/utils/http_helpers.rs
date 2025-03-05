use std::net::SocketAddr;

use axum::async_trait;
use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

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
        parts: &'a mut http::request::Parts,
        state: &'b AppState,
    ) -> Result<User, HTTPError> {
        // Retrieve the Authorization header
        let auth_header = parts
            .headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .to_string();

        // Retrieve the optional X-Auth-Realm header
        let realm_filter = parts
            .headers
            .get("x-auth-realm")
            .and_then(|value| value.to_str().ok());

        // Get the client IP for logging purposes
        let client_ip = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ConnectInfo(addr)| addr.ip())
            .unwrap_or_else(|| {
                tracing::warn!("Unable to determine client IP address.");
                "unknown".parse().unwrap()
            });

        // Call the new authenticate function with the optional realm filter
        match state
            .auth
            .authenticate(&auth_header, &client_ip.to_string(), realm_filter)
            .await
        {
            Some(user) => Ok(user),
            None => Err(HTTPError::new(
                http::StatusCode::UNAUTHORIZED,
                "Unauthorized access",
            )),
        }
    }
}

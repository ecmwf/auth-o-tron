use crate::models::user::User;
use crate::AppState;
use axum::async_trait;
use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use http::request::Parts;
use std::net::SocketAddr;
use tracing::warn;

/// HTTPError is our custom error type returned by our request extractor.
/// It now carries an optional challenge string that is used to dynamically
/// populate the WWW-Authenticate header for unauthorized responses.
pub struct HTTPError {
    status: StatusCode,
    message: String,
    challenge: Option<String>,
}

impl HTTPError {
    /// Create a new HTTPError with a status, message, and optional challenge.
    pub fn new(status: StatusCode, message: impl Into<String>, challenge: Option<String>) -> Self {
        HTTPError {
            status,
            message: message.into(),
            challenge,
        }
    }
}

/// Convert the HTTPError into an HTTP response.
/// If the status is 401 Unauthorized and a challenge is provided,
/// we include it as the WWW-Authenticate header.
impl IntoResponse for HTTPError {
    fn into_response(self) -> Response {
        let body = format!("{{\"error\": \"{}\"}}", self.message);
        let mut builder = Response::builder()
            .status(self.status)
            .header("Content-Type", "application/json");

        if self.status == StatusCode::UNAUTHORIZED {
            // If a challenge is provided, use it.
            if let Some(challenge) = self.challenge {
                builder = builder.header("WWW-Authenticate", challenge);
            }
        }

        builder.body(body.into()).unwrap()
    }
}

/// Implementation of the request extractor for User.
/// When authentication fails, we return an HTTPError that includes a
/// dynamic WWW-Authenticate challenge generated from the available providers.
#[async_trait]
impl FromRequestParts<AppState> for User {
    type Rejection = HTTPError;
    async fn from_request_parts<'a, 'b>(
        parts: &'a mut Parts,
        state: &'b AppState,
    ) -> Result<User, HTTPError> {
        // Extract the Authorization header.
        let auth_header = parts
            .headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .to_string();

        // Extract the optional X-Auth-Realm header.
        let realm_filter = parts
            .headers
            .get("x-auth-realm")
            .and_then(|value| value.to_str().ok());

        // Retrieve the client IP (for logging purposes).
        let client_ip = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ConnectInfo(addr)| addr.ip())
            .unwrap_or_else(|| {
                warn!("Unable to determine client IP address.");
                "unknown".parse().unwrap()
            });

        // Attempt to authenticate using our Auth implementation.
        match state
            .auth
            .authenticate(&auth_header, &client_ip.to_string(), realm_filter)
            .await
        {
            Some(user) => Ok(user),
            None => {
                // Generate a dynamic challenge header from the available providers.
                let challenge = state.auth.generate_challenge_header();
                Err(HTTPError::new(
                    StatusCode::UNAUTHORIZED,
                    "Unauthorized access",
                    Some(challenge),
                ))
            }
        }
    }
}

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

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

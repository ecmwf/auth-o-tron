// (C) Copyright 2024- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

use axum::Json;
use axum::http::{HeaderValue, StatusCode, header::WWW_AUTHENTICATE};
use axum::response::{IntoResponse, Response};
use serde::Serialize;

/// HTTPError is our custom error type returned by our request extractor.
/// It now carries an optional challenge string that is used to dynamically
/// populate the WWW-Authenticate header for unauthorized responses.
#[derive(Debug)]
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

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

/// Convert the HTTPError into an HTTP response.
/// If the status is 401 Unauthorized and a valid challenge is provided,
/// we include it as the WWW-Authenticate header.
impl IntoResponse for HTTPError {
    fn into_response(self) -> Response {
        let mut response = (
            self.status,
            Json(ErrorBody {
                error: self.message,
            }),
        )
            .into_response();

        if self.status == StatusCode::UNAUTHORIZED
            && let Some(challenge) = self.challenge
            && let Ok(value) = HeaderValue::from_str(&challenge)
        {
            response.headers_mut().insert(WWW_AUTHENTICATE, value);
        }

        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    #[tokio::test]
    async fn error_message_is_serialized_as_json() {
        let message = "quote: \"; slash: /; backslash: \\; newline:\n; controls: \u{0000}\u{0007}";
        let response = HTTPError::new(StatusCode::BAD_REQUEST, message, None).into_response();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(response.headers()["Content-Type"], "application/json");

        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("error body should be readable");
        let json: serde_json::Value =
            serde_json::from_slice(&body).expect("error body should be valid JSON");
        assert_eq!(json["error"], message);
    }

    #[tokio::test]
    async fn malformed_www_authenticate_header_is_omitted() {
        let response = HTTPError::new(
            StatusCode::UNAUTHORIZED,
            "Unauthorized access",
            Some("Bearer realm=\"bad\nrealm\"".to_string()),
        )
        .into_response();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(!response.headers().contains_key(WWW_AUTHENTICATE));

        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("error body should be readable");
        let json: serde_json::Value =
            serde_json::from_slice(&body).expect("error body should be valid JSON");
        assert_eq!(json["error"], "Unauthorized access");
    }

    #[test]
    fn valid_www_authenticate_header_is_preserved() {
        let challenge = "Basic realm=\"operations\", Bearer";
        let response = HTTPError::new(
            StatusCode::UNAUTHORIZED,
            "Unauthorized access",
            Some(challenge.to_string()),
        )
        .into_response();

        assert_eq!(response.headers()[WWW_AUTHENTICATE], challenge);
    }

    #[test]
    fn challenge_is_only_added_to_unauthorized_responses() {
        let response = HTTPError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal server error",
            Some("Bearer".to_string()),
        )
        .into_response();

        assert!(!response.headers().contains_key(WWW_AUTHENTICATE));
    }
}

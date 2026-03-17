// (C) Copyright 2024- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

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

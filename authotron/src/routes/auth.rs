// (C) Copyright 2025- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! Authentication endpoint handlers.

use axum::body::Body;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Router, routing::get};
use http::HeaderValue;

use crate::models::user::{User, UserJwtExt};
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
    let jwt = user
        .to_jwt(&state.config.jwt, &state.jwt_signer)
        .map_err(|error| {
            HTTPError::new(StatusCode::INTERNAL_SERVER_ERROR, error.to_string(), None)
        })?;

    authentication_response(
        &user,
        jwt,
        state.config.include_legacy_headers.unwrap_or(false),
    )
}

fn authentication_response(
    user: &User,
    jwt: String,
    include_legacy_headers: bool,
) -> Result<Response<Body>, HTTPError> {
    let mut response = axum::http::response::Response::builder()
        .status(StatusCode::OK)
        .header("Authorization", format!("Bearer {}", jwt))
        .body(Body::from("Authenticated successfully"))
        .map_err(|_| internal_server_error())?;

    if include_legacy_headers {
        add_legacy_headers(response.headers_mut(), user)?;
    }

    Ok(response)
}

fn add_legacy_headers(headers: &mut HeaderMap, user: &User) -> Result<(), HTTPError> {
    // Convert every value before mutating the response so an invalid value cannot
    // leave a partially populated legacy-header set.
    let username = legacy_header_value(&user.username)?;
    let realm = legacy_header_value(&user.realm)?;
    let roles = legacy_header_value(&user.roles.join(","))?;

    headers.append("X-Auth-Username", username);
    headers.append("X-Auth-Realm", realm);
    headers.append("X-Auth-Roles", roles);

    Ok(())
}

fn legacy_header_value(value: &str) -> Result<HeaderValue, HTTPError> {
    HeaderValue::from_str(value).map_err(|_| internal_server_error())
}

fn internal_server_error() -> HTTPError {
    HTTPError::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Internal server error",
        None,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    fn user(username: &str, realm: &str, roles: &[&str]) -> User {
        User::new(
            realm.to_string(),
            username.to_string(),
            Some(roles.iter().map(|role| (*role).to_string()).collect()),
            None,
            None,
            None,
        )
    }

    #[tokio::test]
    async fn successful_response_remains_compatible() {
        let response = authentication_response(
            &user("alice", "operations", &["reader", "writer"]),
            "signed.jwt".to_string(),
            true,
        )
        .expect("valid legacy headers should produce a response");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["Authorization"], "Bearer signed.jwt");
        assert_eq!(response.headers()["X-Auth-Username"], "alice");
        assert_eq!(response.headers()["X-Auth-Realm"], "operations");
        assert_eq!(response.headers()["X-Auth-Roles"], "reader,writer");

        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("success body should be readable");
        assert_eq!(body.as_ref(), b"Authenticated successfully");
    }

    #[test]
    fn unicode_legacy_header_values_are_preserved() {
        let response = authentication_response(
            &user("álîçé", "météo", &["données", "观测"]),
            "signed.jwt".to_string(),
            true,
        )
        .expect("unicode legacy headers should produce a response");

        assert_eq!(
            response.headers()["X-Auth-Username"].as_bytes(),
            "álîçé".as_bytes()
        );
        assert_eq!(
            response.headers()["X-Auth-Realm"].as_bytes(),
            "météo".as_bytes()
        );
        assert_eq!(
            response.headers()["X-Auth-Roles"].as_bytes(),
            "données,观测".as_bytes()
        );
    }

    #[tokio::test]
    async fn control_bearing_legacy_values_return_a_generic_error() {
        let users = [
            user("ali\nce", "operations", &["reader"]),
            user("alice", "oper\rations", &["reader"]),
            user("alice", "operations", &["read\u{0000}er"]),
        ];

        for user in users {
            let result = authentication_response(&user, "signed.jwt".to_string(), true);
            let Err(error) = result else {
                panic!("control-bearing legacy header should be rejected");
            };

            let response = error.into_response();
            assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

            let body = to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("error body should be readable");
            let json: serde_json::Value =
                serde_json::from_slice(&body).expect("error body should be valid JSON");
            assert_eq!(json["error"], "Internal server error");
        }
    }

    #[test]
    fn invalid_values_do_not_matter_when_legacy_headers_are_disabled() {
        let response = authentication_response(
            &user("ali\nce", "oper\rations", &["read\u{0000}er"]),
            "signed.jwt".to_string(),
            false,
        )
        .expect("legacy values should not be inspected when headers are disabled");

        assert_eq!(response.status(), StatusCode::OK);
        assert!(!response.headers().contains_key("X-Auth-Username"));
        assert!(!response.headers().contains_key("X-Auth-Realm"));
        assert!(!response.headers().contains_key("X-Auth-Roles"));
    }
}

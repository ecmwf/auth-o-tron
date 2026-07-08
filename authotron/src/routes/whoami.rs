// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! Authenticated identity introspection endpoint.

use axum::{Json, Router, routing::get};

use crate::models::user::User;
use crate::state::AppState;

/// Registers identity introspection routes.
pub fn routes() -> Router<AppState> {
    Router::new().route("/whoami", get(whoami))
}

/// Returns the authenticated user's identity as JSON.
///
/// The user is extracted from the request via configured authentication
/// providers and augmenters, so the response reflects the same identity
/// (username, realm, roles, attributes, scopes) that would be embedded in
/// a JWT issued by `/authenticate`. This lets callers inspect their
/// effective identity without decoding a JWT.
async fn whoami(user: User) -> Json<User> {
    Json(user)
}

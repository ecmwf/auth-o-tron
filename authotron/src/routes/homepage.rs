// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

use crate::state::AppState;
use axum::{Router, http::header, response::IntoResponse, routing::get};

const TEMPLATE: &str = include_str!("../static/index.html");
const LOGO: &[u8] = include_bytes!("../static/logo.png");
const FAVICON: &[u8] = include_bytes!("../static/favicon.ico");

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(index))
        .route("/static/logo.png", get(logo))
        .route("/favicon.ico", get(favicon))
}

async fn index() -> impl IntoResponse {
    let html = TEMPLATE.replace("{{version}}", env!("CARGO_PKG_VERSION"));
    ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], html)
}

async fn logo() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "image/png")], LOGO)
}

async fn favicon() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "image/x-icon")], FAVICON)
}

use crate::state::AppState;
use axum::{Router, http::header, response::IntoResponse, routing::get};

const TEMPLATE: &str = include_str!("../static/index.html");
const LOGO: &[u8] = include_bytes!("../../docs/logo.png");

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(index))
        .route("/static/logo.png", get(logo))
}

async fn index() -> impl IntoResponse {
    let html = TEMPLATE.replace("{{version}}", env!("CARGO_PKG_VERSION"));
    ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], html)
}

async fn logo() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "image/png")], LOGO)
}

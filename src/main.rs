mod auth;

use axum::{
    body::Body,
    response::{self, IntoResponse, Response},
    routing::get,
    Router,
    http::{StatusCode, header::HeaderMap},
    Extension
};

use crate::auth::Auth;
use std::sync::Arc;

async fn authenticate(headers: HeaderMap, Extension(auth): Extension<Arc<Auth>>) -> impl IntoResponse {
    
    
    let auth_header = headers
    .get("authorization")
    .and_then(|value| value.to_str().ok())
    .unwrap_or("");
    
    match auth.authenticate(auth_header).await {
        Some(user) => {
            // Authentication successful
            println!("Authenticated user: {:?}", user.username);
            let body = Body::from(format!("User {} authenticated successfully", user.username));
            Response::builder()
            .status(StatusCode::OK)
            .body(body)
            .unwrap()
        }
        None => {
            // Authentication failed
            let body = Body::from("Authentication failed");
            response::Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .body(body)
            .unwrap()
        }
    }
    
}

#[tokio::main]
async fn main() {

    let auth = Arc::new(Auth::new());
    
    // build our application with a single route
    let app = Router::new().route("/authenticate", get(authenticate)).layer(Extension(auth));

    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
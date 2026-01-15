use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use authotron::auth::Auth;
use authotron::config::{AuthConfig, ConfigV1};
use authotron::metrics::Metrics;
use authotron::routes::create_router;
use authotron::state::AppState;
use authotron::store::create_store;
use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Method, Request};
use base64::{Engine as _, engine::general_purpose};
use jsonwebtoken::{DecodingKey, TokenData, Validation, decode};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: Option<String>,
    pub username: Option<String>,
    pub exp: Option<i64>,
    pub iss: Option<String>,
    pub roles: Vec<String>,
    pub realm: Option<String>,
}

pub async fn build_app(config: ConfigV1) -> (Router, Arc<ConfigV1>) {
    let config = Arc::new(config);
    let store = create_store(&config.store).await;
    let auth = Arc::new(Auth::new(
        &config.providers,
        &config.augmenters,
        store.clone(),
        AuthConfig {
            timeout_in_ms: config.auth.timeout_in_ms,
        },
    ));
    let metrics = Metrics::new();

    let state = AppState {
        config: config.clone(),
        auth,
        store,
        metrics,
    };

    (create_router(state), config)
}

pub fn request_with_bearer(path: &str, token: &str, method: Method) -> Request<Body> {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("Authorization", format!("Bearer {}", token))
        .body(Body::empty())
        .expect("failed to build request");

    request.extensions_mut().insert(ConnectInfo(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        0,
    )));

    request
}

pub fn request_with_basic(path: &str, credentials: &str, method: Method) -> Request<Body> {
    let encoded = general_purpose::STANDARD.encode(credentials);
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("Authorization", format!("Basic {}", encoded))
        .body(Body::empty())
        .expect("failed to build request");

    request.extensions_mut().insert(ConnectInfo(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        0,
    )));

    request
}

pub fn decode_claims(token: &str, secret: &str) -> TokenData<Claims> {
    let mut validation = Validation::default();
    validation.validate_aud = false;

    decode(
        token,
        &DecodingKey::from_secret(secret.as_ref()),
        &validation,
    )
    .expect("JWT should decode")
}

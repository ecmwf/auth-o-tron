use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use authotron::config::{ConfigV2, JWTConfig};
use authotron::startup;
use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Method, Request};
use base64::{Engine as _, engine::general_purpose};
use jsonwebtoken::{Algorithm, DecodingKey, TokenData, Validation, decode};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: Option<String>,
    pub username: Option<String>,
    pub exp: Option<i64>,
    pub iss: Option<String>,
    pub aud: Option<String>,
    pub roles: Vec<String>,
    pub realm: Option<String>,
}

pub async fn build_app(config: ConfigV2) -> (Router, Arc<ConfigV2>) {
    let (app, config, _state) = build_app_with_state(config).await;
    (app, config)
}

#[allow(dead_code)]
pub async fn build_app_with_state(
    config: ConfigV2,
) -> (Router, Arc<ConfigV2>, authotron::state::AppState) {
    let config = Arc::new(config);
    let (app, state) = startup::build_app(config.clone())
        .await
        .expect("test application should build");
    (app, config, state)
}

#[allow(dead_code)]
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

#[allow(dead_code)]
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

pub fn decode_claims(token: &str, jwt_config: &JWTConfig) -> TokenData<Claims> {
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[&jwt_config.iss]);
    validation.set_audience(&[&jwt_config.aud]);

    decode(
        token,
        &DecodingKey::from_rsa_pem(include_bytes!("fixtures/test-rsa-public.pem"))
            .expect("valid test public key"),
        &validation,
    )
    .expect("JWT should decode")
}

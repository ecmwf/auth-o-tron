// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! In-process identity-provider endpoints and signing keys for unit tests, served over
//! plain HTTP on a loopback port (accepted only in this crate's tests).

use axum::{
    Json, Router,
    http::{HeaderMap, StatusCode, header},
    routing::{get, post},
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use rsa::{RsaPrivateKey, pkcs1::EncodeRsaPrivateKey, rand_core::OsRng, traits::PublicKeyParts};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};
use url::Url;

/// Serves `router` on an ephemeral loopback port for the rest of the test runtime and
/// returns its base URL, e.g. `http://127.0.0.1:41234`.
pub(crate) async fn serve(router: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    base
}

/// Disposable P-256 key generated for these tests only; it protects nothing.
const EC_TEST_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgN0Nz+OaqMJoJZFbE
VxKJ/ZQUmVe9JuldC6pImgBXAJGhRANCAATFclXBwSMvaWLNYFfnO3Ah93e44gEZ
JuyF4vfhOTy/dmGSy/BPTYJlURPMuar3vhjrXFITvAdkVtFvhBWyNFaJ
-----END PRIVATE KEY-----
";
const EC_TEST_X: &str = "xXJVwcEjL2lizWBX5ztwIfd3uOIBGSbsheL34Tk8v3Y";
const EC_TEST_Y: &str = "YZLL8E9NgmVRE8y5qve-GOtcUhO8B2RW0W-EFbI0Vok";

/// Two RSA keys so tests can rotate signing keys.
pub(crate) fn rsa_key(index: usize) -> &'static RsaPrivateKey {
    static KEYS: OnceLock<[RsaPrivateKey; 2]> = OnceLock::new();
    &KEYS.get_or_init(|| [0, 1].map(|_| RsaPrivateKey::new(&mut OsRng, 2048).unwrap()))[index]
}

/// Public JWK of [`rsa_key`]; `alg` is omitted when `None`.
pub(crate) fn rsa_jwk(index: usize, kid: &str, alg: Option<&str>) -> Value {
    let key = rsa_key(index);
    let mut jwk = json!({
        "kty": "RSA", "use": "sig", "kid": kid,
        "n": URL_SAFE_NO_PAD.encode(key.n().to_bytes_be()),
        "e": URL_SAFE_NO_PAD.encode(key.e().to_bytes_be()),
    });
    if let Some(alg) = alg {
        jwk["alg"] = json!(alg);
    }
    jwk
}

pub(crate) fn ec_jwk(kid: &str) -> Value {
    json!({"kty": "EC", "use": "sig", "crv": "P-256", "kid": kid, "x": EC_TEST_X, "y": EC_TEST_Y})
}

/// Signs `claims` with RSA key `index` (RS*/PS*) or the P-256 key (ES256).
pub(crate) fn sign(claims: &Value, alg: Algorithm, kid: Option<&str>, index: usize) -> String {
    let key = match alg {
        Algorithm::ES256 => EncodingKey::from_ec_pem(EC_TEST_KEY.as_bytes()).unwrap(),
        _ => EncodingKey::from_rsa_der(rsa_key(index).to_pkcs1_der().unwrap().as_bytes()),
    };
    let mut header = Header::new(alg);
    header.kid = kid.map(str::to_owned);
    jsonwebtoken::encode(&header, claims, &key).unwrap()
}

/// Client registered at [`MockIdp`].
pub(crate) const CLIENT_ID: &str = "authotron";
/// Disposable client secret of [`MockIdp`]; it protects nothing.
pub(crate) const CLIENT_SECRET: &str = "fixture-client-secret";
pub(crate) const SUBJECT: &str = "0f1d4c2e-0000-4000-8000-000000000001";

/// Pending authorization recorded by [`MockIdp::authorize`].
struct Grant {
    nonce: String,
    challenge: String,
    redirect_uri: String,
    subject: String,
    /// The request asked for `offline_access`, so the code exchange issues a refresh token.
    offline: bool,
}

/// A live refresh token: the user it was issued for and the original nonce, which
/// refreshed ID tokens repeat as Keycloak's do.
#[derive(Clone)]
struct Offline {
    subject: String,
    nonce: String,
}

/// Mutable behaviour and records of a [`MockIdp`].
#[derive(Default)]
pub(crate) struct MockState {
    /// Advertise and send the RFC 9207 `iss` authorization response parameter.
    pub iss_parameter: AtomicBool,
    pub subject: Mutex<String>,
    /// Claims merged into every issued ID token, overriding the defaults.
    pub claims: Mutex<Value>,
    /// Replaces the token endpoint's answer when set.
    pub token_answer: Mutex<Option<(u16, Value)>>,
    /// RSA key index and kid used to sign ID tokens.
    pub signer: Mutex<(usize, String)>,
    pub token_requests: AtomicUsize,
    pub discovery_requests: AtomicUsize,
    /// Answer `offline_access` requests with a refresh token.
    pub issue_offline_tokens: AtomicBool,
    /// Advertise the RFC 7009 revocation endpoint.
    pub revocation: AtomicBool,
    /// Refresh responses carry a new refresh token, invalidating the presented one.
    pub rotate_refresh_tokens: AtomicBool,
    /// Refresh responses carry a new ID token.
    pub refresh_id_tokens: AtomicBool,
    /// Subjects whose refresh tokens are refused, like disabled accounts.
    pub disabled: Mutex<HashSet<String>>,
    pub refresh_requests: AtomicUsize,
    /// Tokens received at the revocation endpoint, in order.
    pub revoked: Mutex<Vec<String>>,
    grants: Mutex<HashMap<String, Grant>>,
    offline: Mutex<HashMap<String, Offline>>,
}

/// An identity provider with discovery, JWKS and a token endpoint, plus an in-process
/// authorization step standing in for the user's sign-in at the provider.
pub(crate) struct MockIdp {
    pub issuer: String,
    pub state: Arc<MockState>,
}

impl MockIdp {
    pub(crate) async fn start() -> Self {
        // Key generation is slow in debug builds; finish it before requests have deadlines.
        let _ = (rsa_key(0), rsa_key(1));
        let state = Arc::new(MockState::default());
        for flag in [
            &state.iss_parameter,
            &state.issue_offline_tokens,
            &state.revocation,
            &state.rotate_refresh_tokens,
            &state.refresh_id_tokens,
        ] {
            flag.store(true, Ordering::SeqCst);
        }
        *state.subject.lock().unwrap() = SUBJECT.into();
        *state.claims.lock().unwrap() = json!({});
        *state.signer.lock().unwrap() = (0, "k0".into());
        let issuer_cell = Arc::new(OnceLock::<String>::new());
        let router = Router::new()
            .route(
                "/realms/test/.well-known/openid-configuration",
                get({
                    let (state, issuer) = (state.clone(), issuer_cell.clone());
                    move || async move {
                        state.discovery_requests.fetch_add(1, Ordering::SeqCst);
                        let issuer = issuer.get().unwrap();
                        let mut document = json!({
                            "issuer": issuer,
                            "authorization_endpoint": format!("{issuer}/auth"),
                            "token_endpoint": format!("{issuer}/token"),
                            "jwks_uri": format!("{issuer}/certs"),
                            "response_types_supported": ["code"],
                            "code_challenge_methods_supported": ["S256"],
                            "authorization_response_iss_parameter_supported":
                                state.iss_parameter.load(Ordering::SeqCst),
                        });
                        if state.revocation.load(Ordering::SeqCst) {
                            document["revocation_endpoint"] = json!(format!("{issuer}/revoke"));
                        }
                        Json(document)
                    }
                }),
            )
            .route(
                "/realms/test/certs",
                get(|| async {
                    Json(json!({"keys": [rsa_jwk(0, "k0", Some("RS256")), rsa_jwk(1, "k1", None)]}))
                }),
            )
            .route(
                "/realms/test/token",
                post({
                    let (state, issuer) = (state.clone(), issuer_cell.clone());
                    move |headers: HeaderMap, body: String| async move {
                        token(&state, issuer.get().unwrap(), &headers, &body)
                    }
                }),
            )
            .route(
                "/realms/test/revoke",
                post({
                    let state = state.clone();
                    move |headers: HeaderMap, body: String| async move {
                        revoke(&state, &headers, &body)
                    }
                }),
            );
        let issuer = format!("{}/realms/test", serve(router).await);
        issuer_cell.set(issuer.clone()).unwrap();
        Self { issuer, state }
    }

    /// Validates an authorization request as the provider would and returns the callback
    /// URL it redirects the browser to, carrying a fresh one-use code.
    pub(crate) fn authorize(&self, request: &Url) -> String {
        let query: HashMap<String, String> = request.query_pairs().into_owned().collect();
        assert_eq!(
            request.as_str().split('?').next(),
            Some(format!("{}/auth", self.issuer).as_str())
        );
        assert_eq!(query["response_type"], "code");
        assert_eq!(query["client_id"], CLIENT_ID);
        assert_eq!(query["code_challenge_method"], "S256");
        assert!(query["scope"].split(' ').any(|scope| scope == "openid"));
        let code = uuid::Uuid::new_v4().simple().to_string();
        self.state.grants.lock().unwrap().insert(
            code.clone(),
            Grant {
                nonce: query["nonce"].clone(),
                challenge: query["code_challenge"].clone(),
                redirect_uri: query["redirect_uri"].clone(),
                subject: self.state.subject.lock().unwrap().clone(),
                offline: query["scope"]
                    .split(' ')
                    .any(|scope| scope == "offline_access"),
            },
        );
        self.callback(&query, &[("code", &code)])
    }

    /// The callback URL for a user who declined at the provider.
    pub(crate) fn deny(&self, request: &Url) -> String {
        let query: HashMap<String, String> = request.query_pairs().into_owned().collect();
        self.callback(
            &query,
            &[
                ("error", "access_denied"),
                ("error_description", "Declined"),
            ],
        )
    }

    fn callback(&self, query: &HashMap<String, String>, result: &[(&str, &str)]) -> String {
        let mut response = url::form_urlencoded::Serializer::new(String::new());
        response.append_pair("state", &query["state"]);
        response.append_pair("session_state", "mock-session");
        if self.state.iss_parameter.load(Ordering::SeqCst) {
            response.append_pair("iss", &self.issuer);
        }
        for (name, value) in result {
            response.append_pair(name, value);
        }
        format!("{}?{}", query["redirect_uri"], response.finish())
    }
}

fn form(body: &str) -> HashMap<String, String> {
    url::form_urlencoded::parse(body.as_bytes())
        .into_owned()
        .collect()
}

/// The registered client, authenticated with either secret method.
fn authenticated(headers: &HeaderMap, form: &HashMap<String, String>) -> bool {
    let basic = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok()?.strip_prefix("Basic "))
        .and_then(|value| String::from_utf8(STANDARD.decode(value).ok()?).ok());
    basic
        .map(|pair| pair == format!("{CLIENT_ID}:{CLIENT_SECRET}"))
        .unwrap_or_else(|| {
            form.get("client_id").map(String::as_str) == Some(CLIENT_ID)
                && form.get("client_secret").map(String::as_str) == Some(CLIENT_SECRET)
        })
}

fn error(status: StatusCode, code: &str) -> (StatusCode, Json<Value>) {
    (status, Json(json!({"error": code})))
}

/// Token endpoint: one-use codes, exact redirect URI, S256 verifier and client secret;
/// refresh tokens for live, enabled users.
fn token(
    state: &MockState,
    issuer: &str,
    headers: &HeaderMap,
    body: &str,
) -> (StatusCode, Json<Value>) {
    state.token_requests.fetch_add(1, Ordering::SeqCst);
    if let Some((status, answer)) = state.token_answer.lock().unwrap().clone() {
        return (StatusCode::from_u16(status).unwrap(), Json(answer));
    }
    let form = form(body);
    if !authenticated(headers, &form) {
        return error(StatusCode::UNAUTHORIZED, "invalid_client");
    }
    match form.get("grant_type").map(String::as_str) {
        Some("authorization_code") => exchange(state, issuer, &form),
        Some("refresh_token") => refresh(state, issuer, &form),
        _ => error(StatusCode::BAD_REQUEST, "unsupported_grant_type"),
    }
}

fn exchange(
    state: &MockState,
    issuer: &str,
    form: &HashMap<String, String>,
) -> (StatusCode, Json<Value>) {
    let grant = form
        .get("code")
        .and_then(|code| state.grants.lock().unwrap().remove(code));
    let valid = grant.as_ref().filter(|grant| {
        form.get("redirect_uri") == Some(&grant.redirect_uri)
            && form.get("code_verifier").is_some_and(|verifier| {
                URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())) == grant.challenge
            })
    });
    let Some(grant) = valid else {
        return error(StatusCode::BAD_REQUEST, "invalid_grant");
    };
    let mut answer = json!({
        "access_token": "mock-access-token", "token_type": "Bearer", "expires_in": 60,
        "id_token": id_token(state, issuer, &grant.subject, &grant.nonce)
    });
    if grant.offline && state.issue_offline_tokens.load(Ordering::SeqCst) {
        answer["refresh_token"] = json!(state.issue_refresh_token(Offline {
            subject: grant.subject.clone(),
            nonce: grant.nonce.clone(),
        }));
    }
    (StatusCode::OK, Json(answer))
}

fn refresh(
    state: &MockState,
    issuer: &str,
    form: &HashMap<String, String>,
) -> (StatusCode, Json<Value>) {
    state.refresh_requests.fetch_add(1, Ordering::SeqCst);
    let presented = form.get("refresh_token").cloned().unwrap_or_default();
    let record = state.offline.lock().unwrap().get(&presented).cloned();
    let Some(record) =
        record.filter(|record| !state.disabled.lock().unwrap().contains(&record.subject))
    else {
        return error(StatusCode::BAD_REQUEST, "invalid_grant");
    };
    let mut answer =
        json!({"access_token": "mock-access-token", "token_type": "Bearer", "expires_in": 60});
    if state.rotate_refresh_tokens.load(Ordering::SeqCst) {
        state.offline.lock().unwrap().remove(&presented);
        answer["refresh_token"] = json!(state.issue_refresh_token(record.clone()));
    }
    if state.refresh_id_tokens.load(Ordering::SeqCst) {
        answer["id_token"] = json!(id_token(state, issuer, &record.subject, &record.nonce));
    }
    (StatusCode::OK, Json(answer))
}

/// RFC 7009 endpoint: records the token and ends it.
fn revoke(state: &MockState, headers: &HeaderMap, body: &str) -> StatusCode {
    let form = form(body);
    if !authenticated(headers, &form) {
        return StatusCode::UNAUTHORIZED;
    }
    if let Some(token) = form.get("token") {
        state.offline.lock().unwrap().remove(token);
        state.revoked.lock().unwrap().push(token.clone());
    }
    StatusCode::OK
}

impl MockState {
    fn issue_refresh_token(&self, record: Offline) -> String {
        let token = format!("offline-{}", uuid::Uuid::new_v4().simple());
        self.offline.lock().unwrap().insert(token.clone(), record);
        token
    }
    /// Whether `token` is a live refresh token.
    pub(crate) fn refresh_token_live(&self, token: &str) -> bool {
        self.offline.lock().unwrap().contains_key(token)
    }
    /// A live refresh token for `subject`, as an earlier offline sign-in would leave.
    pub(crate) fn offline_token(&self, subject: &str) -> String {
        self.issue_refresh_token(Offline {
            subject: subject.into(),
            nonce: "earlier-sign-in".into(),
        })
    }
}

/// An ID token for `subject` with the default claims and [`MockState::claims`] merged in.
fn id_token(state: &MockState, issuer: &str, subject: &str, nonce: &str) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut claims = json!({
        "iss": issuer, "sub": subject, "aud": CLIENT_ID, "azp": CLIENT_ID,
        "exp": now + 300, "iat": now, "auth_time": now, "nonce": nonce,
        "preferred_username": "alice", "email": "alice@example.org", "email_verified": true,
        "name": "Alice Demo", "realm_access": {"roles": ["mcp-demo", "offline_access"]}
    });
    for (name, value) in state.claims.lock().unwrap().as_object().unwrap() {
        claims[name] = value.clone();
    }
    let (index, kid) = state.signer.lock().unwrap().clone();
    sign(&claims, Algorithm::RS256, Some(&kid), index)
}

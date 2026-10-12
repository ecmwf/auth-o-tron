// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! Pure authorization-request gate; errors never authorize a redirect.

use crate::config::OAuthConfig;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use subtle::ConstantTimeEq;

pub(super) const MAX_AUTHORIZATION_QUERY_BYTES: usize = 8 * 1024;

const KNOWN: [&str; 8] = [
    "client_id",
    "redirect_uri",
    "response_type",
    "resource",
    "scope",
    "state",
    "code_challenge",
    "code_challenge_method",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationError {
    InvalidRequest,
    UnauthorizedClient,
    UnsupportedResponseType,
    InvalidTarget,
    InvalidScope,
    ServerError,
}

/// Constructed only after strict S256 challenge validation; no Deserialize or mutation API.
pub struct PkceChallenge {
    digest: [u8; 32],
}
impl PkceChallenge {
    pub(super) fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
    pub fn verify(&self, verifier: &str) -> bool {
        if !(43..=128).contains(&verifier.len())
            || !verifier
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"-._~".contains(&c))
        {
            return false;
        }
        let actual: [u8; 32] = Sha256::digest(verifier.as_bytes()).into();
        bool::from(self.digest.ct_eq(&actual))
    }
}

/// This proves input validation, not login, consent, role eligibility or grant issuance.
pub struct ValidatedAuthorizationRequest {
    client_id: String,
    redirect_uri: String,
    resource: String,
    scopes: Vec<String>,
    state: Option<String>,
    challenge: PkceChallenge,
}
impl ValidatedAuthorizationRequest {
    /// True when both requests carry identical authorization parameters.
    /// The destructure is exhaustive so adding a field forces this comparison to be revisited.
    pub fn same_request(&self, other: &Self) -> bool {
        let Self {
            client_id,
            redirect_uri,
            resource,
            scopes,
            state,
            challenge,
        } = self;
        *client_id == other.client_id
            && *redirect_uri == other.redirect_uri
            && *resource == other.resource
            && *scopes == other.scopes
            && *state == other.state
            && challenge.digest() == other.challenge.digest()
    }
    pub fn client_id(&self) -> &str {
        &self.client_id
    }
    pub fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }
    pub fn resource(&self) -> &str {
        &self.resource
    }
    pub fn scopes(&self) -> &[String] {
        &self.scopes
    }
    pub fn state(&self) -> Option<&str> {
        self.state.as_deref()
    }
    pub fn challenge(&self) -> &PkceChallenge {
        &self.challenge
    }
}

/// Valid: `state=a%2Bb` decodes to `a+b`; invalid: `state=%ZZ` or `%FF`.
pub(crate) fn decode_component(raw: &[u8]) -> Result<String, AuthorizationError> {
    let mut bytes = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        match raw[i] {
            b'+' => bytes.push(b' '),
            b'%' => {
                let hex = raw
                    .get(i + 1..i + 3)
                    .ok_or(AuthorizationError::InvalidRequest)?;
                let digit = |c: u8| (c as char).to_digit(16).map(|n| n as u8);
                let a = digit(hex[0]).ok_or(AuthorizationError::InvalidRequest)?;
                let b = digit(hex[1]).ok_or(AuthorizationError::InvalidRequest)?;
                bytes.push(a * 16 + b);
                i += 2;
            }
            byte => bytes.push(byte),
        }
        i += 1;
    }
    String::from_utf8(bytes).map_err(|_| AuthorizationError::InvalidRequest)
}

/// Takes raw form-urlencoded query bytes, without a leading `?`. All errors are local;
/// callers must never redirect to a submitted URI on failure.
pub fn validate_authorization_request(
    config: &OAuthConfig,
    raw: &[u8],
) -> Result<ValidatedAuthorizationRequest, AuthorizationError> {
    use AuthorizationError::*;
    if raw.len() > MAX_AUTHORIZATION_QUERY_BYTES || raw.split(|c| *c == b'&').count() > 32 {
        return Err(InvalidRequest);
    }
    config.validate().map_err(|_| ServerError)?;
    if config
        .issuer
        .as_ref()
        .is_none_or(|issuer| issuer.len() > 2048)
    {
        return Err(ServerError);
    }
    let mut parameters = HashMap::new();
    for pair in raw.split(|c| *c == b'&') {
        let split = pair.iter().position(|c| *c == b'=');
        let (name, value) = split.map_or((pair, &b""[..]), |i| (&pair[..i], &pair[i + 1..]));
        let name = decode_component(name)?;
        let value = decode_component(value)?;
        if let Some(known) = KNOWN.iter().find(|known| **known == name)
            && parameters.insert(*known, value).is_some()
        {
            return Err(InvalidRequest);
        }
    }
    let required = |name| {
        parameters
            .get(name)
            .map(String::as_str)
            .ok_or(InvalidRequest)
    };
    let client_id = required("client_id")?;
    let client = config
        .clients
        .iter()
        .find(|c| c.client_id == client_id)
        .ok_or(UnauthorizedClient)?;
    let redirect_uri = required("redirect_uri")?;
    if !client
        .redirect_uris
        .iter()
        .any(|uri| crate::config::oauth::redirect_uri_matches(uri, redirect_uri))
    {
        return Err(InvalidRequest);
    }
    if required("response_type")? != "code" {
        return Err(UnsupportedResponseType);
    }
    let resource = required("resource")?;
    if !config.resources.iter().any(|r| r.resource == resource) {
        return Err(InvalidTarget);
    }
    let binding = client
        .resources
        .iter()
        .find(|r| r.resource == resource)
        .ok_or(InvalidTarget)?;
    // RFC 6749 §3.3: an absent `scope` defaults to every scope the client is bound to for
    // this resource. A present but empty or malformed `scope` remains `invalid_scope`.
    // Example: no `scope` with binding `["read", "write"]` yields `read write`;
    // `scope=` (empty) is rejected.
    let scopes = match parameters.get("scope") {
        Some(scope) => scope.split(' ').map(String::from).collect::<Vec<_>>(),
        None => binding.scopes.clone(),
    };
    let mut seen = HashSet::new();
    if !(1..=32).contains(&scopes.len())
        || scopes.iter().any(|s| {
            s.is_empty()
                || s.len() > 64
                || !s
                    .bytes()
                    .all(|c| matches!(c, 0x21 | 0x23..=0x5b | 0x5d..=0x7e))
                || !seen.insert(s)
                || !binding.scopes.contains(s)
        })
    {
        return Err(InvalidScope);
    }
    let state = parameters.get("state");
    if state.is_some_and(|s| s.len() > 1024 || s.chars().any(char::is_control)) {
        return Err(InvalidRequest);
    }
    if required("code_challenge_method")? != "S256" {
        return Err(InvalidRequest);
    }
    let challenge = required("code_challenge")?;
    if challenge.len() != 43 {
        return Err(InvalidRequest);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(challenge)
        .map_err(|_| InvalidRequest)?;
    if URL_SAFE_NO_PAD.encode(&decoded) != challenge {
        return Err(InvalidRequest);
    }
    let digest = decoded.try_into().map_err(|_| InvalidRequest)?;
    Ok(ValidatedAuthorizationRequest {
        client_id: client_id.into(),
        redirect_uri: redirect_uri.into(),
        resource: resource.into(),
        scopes,
        state: state.cloned(),
        challenge: PkceChallenge { digest },
    })
}

#[cfg(test)]
mod tests {
    use super::validate_authorization_request as parse;
    use super::*;
    use AuthorizationError::*;
    use serde_json::json;
    const RESOURCE: &str = "https://mcp.example.org/mcp";
    const CALLBACK: &str = "https://app.test/cb?fixed=a%20b";
    const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    const NON_CANONICAL: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cN";
    const ALIAS: &str = "https://app.test/a/../cb?fixed=a%20b";

    fn config() -> OAuthConfig {
        serde_json::from_value(json!({"issuer": "https://login.example.org", "clients": [
            {"client_id": "desktop", "display_name": "Desktop", "redirect_uris": [CALLBACK], "resources": [{"resource": RESOURCE, "scopes": ["read"]}]}],
            "resources": [{"resource": RESOURCE, "allowed_realms": ["local"], "scopes": [{"name": "read", "required_roles": ["reader"]}, {"name": "write", "required_roles": []}]}]})).unwrap()
    }
    fn parameters() -> Vec<(&'static str, String)> {
        [
            ("client_id", "desktop"),
            ("redirect_uri", CALLBACK),
            ("response_type", "code"),
            ("resource", RESOURCE),
            ("scope", "read"),
            ("code_challenge", CHALLENGE),
            ("code_challenge_method", "S256"),
        ]
        .into_iter()
        .map(|(key, value)| (key, value.into()))
        .collect()
    }
    fn query(parameters: &[(&str, String)]) -> String {
        url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(parameters.iter().map(|(key, value)| (*key, value)))
            .finish()
    }
    fn set(params: &mut Vec<(&'static str, String)>, key: &'static str, value: String) {
        if let Some(pair) = params.iter_mut().find(|(name, _)| *name == key) {
            pair.1 = value;
        } else {
            params.push((key, value));
        }
    }
    #[test]
    fn exact_fields_optional_opaque_state_unknown_parameters_and_rfc_pkce_vector() {
        let cfg = config();
        let mut params = parameters();
        let request = parse(&cfg, query(&params).as_bytes()).unwrap();
        assert_eq!(request.client_id(), "desktop");
        assert_eq!(request.redirect_uri(), CALLBACK);
        assert_eq!(request.resource(), RESOURCE);
        assert_eq!(request.scopes(), &["read"]);
        assert!(request.state().is_none());
        assert!(request.challenge().verify(VERIFIER));
        assert!(!request.challenge().verify(&"x".repeat(43)));
        for verifier in [
            "x".repeat(42),
            "x".repeat(129),
            format!("{}!", "x".repeat(42)),
            format!("{}é", "x".repeat(42)),
        ] {
            assert!(!request.challenge().verify(&verifier));
        }
        params.extend([
            ("state", "opaque + café<&>".into()),
            ("username", "ignored".into()),
            ("roles", "admin".into()),
            ("password", "not-retained".into()),
            ("scope_hint", "write".into()),
            ("unknown", "one".into()),
            ("unknown", "two".into()),
        ]);
        let request = parse(&cfg, query(&params).as_bytes()).unwrap();
        assert_eq!(request.state(), Some("opaque + café<&>"));
        assert_eq!(request.scopes(), &["read"]);
        assert_eq!(request.redirect_uri(), CALLBACK);
        for verifier in ["-".repeat(43), "~".repeat(128), "a".repeat(64)] {
            let mut params = parameters();
            set(
                &mut params,
                "code_challenge",
                URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())),
            );
            assert!(
                parse(&cfg, query(&params).as_bytes())
                    .unwrap()
                    .challenge()
                    .verify(&verifier)
            );
        }
    }
    #[test]
    fn duplicates_missing_fields_and_malformed_form_fail_locally() {
        let cfg = config();
        for key in KNOWN {
            let mut params = parameters();
            params.extend([(key, "x".into()), (key, "y".into())]);
            assert_eq!(
                parse(&cfg, query(&params).as_bytes()).err(),
                Some(InvalidRequest)
            );
        }
        for (index, (key, _)) in parameters().into_iter().enumerate() {
            let mut params = parameters();
            params.remove(index);
            // An absent `scope` selects the server default instead of failing.
            assert_eq!(
                parse(&cfg, query(&params).as_bytes()).is_err(),
                key != "scope",
                "{key}"
            );
        }
        for raw in [
            b"state=%ZZ".as_slice(),
            b"state=%",
            b"state=%FF",
            b"state=\xff",
            &[b'x'; 8193],
        ] {
            assert_eq!(parse(&cfg, raw).err(), Some(InvalidRequest));
        }
        let raw = format!("{}&{}", query(&parameters()), "unknown=x&".repeat(32));
        assert_eq!(parse(&cfg, raw.as_bytes()).err(), Some(InvalidRequest));
        assert!(parse(&OAuthConfig::default(), query(&parameters()).as_bytes()).is_err());
    }
    #[test]
    fn absent_scope_defaults_to_client_binding_but_empty_or_unknown_scope_fails() {
        let mut cfg = config();
        cfg.clients[0].resources[0].scopes = vec!["write".into(), "read".into()];
        let mut params = parameters();
        params.retain(|(key, _)| *key != "scope");
        let request = parse(&cfg, query(&params).as_bytes()).unwrap();
        assert_eq!(request.scopes(), &["write", "read"]);
        for value in ["", " ", "admin", "read admin"] {
            let mut params = parameters();
            set(&mut params, "scope", value.into());
            assert_eq!(
                parse(&cfg, query(&params).as_bytes()).err(),
                Some(InvalidScope),
                "{value:?}"
            );
        }
        // `scope` without `=` decodes to an empty value and is not treated as absent.
        let raw = format!("{}&scope", query(&params));
        assert_eq!(parse(&cfg, raw.as_bytes()).err(), Some(InvalidScope));
    }
    #[test]
    fn registry_scope_and_s256_restrictions() {
        for (key, value, error) in [
            ("client_id", "unknown", UnauthorizedClient),
            (
                "redirect_uri",
                "https://app.test/cb?fixed=a+b",
                InvalidRequest,
            ),
            ("redirect_uri", ALIAS, InvalidRequest),
            ("response_type", "token", UnsupportedResponseType),
            ("resource", "https://mcp.example.org/mcp/", InvalidTarget),
            ("scope", "write", InvalidScope),
            ("scope", "read read", InvalidScope),
            ("scope", "read  read", InvalidScope),
            ("scope", "read\twrite", InvalidScope),
            ("code_challenge_method", "plain", InvalidRequest),
            ("code_challenge", "short", InvalidRequest),
            ("code_challenge", NON_CANONICAL, InvalidRequest),
            ("state", "line\n", InvalidRequest),
        ] {
            let mut params = parameters();
            set(&mut params, key, value.into());
            assert_eq!(
                parse(&config(), query(&params).as_bytes()).err(),
                Some(error),
                "{key}"
            );
        }
        let mut cfg = config();
        cfg.clients[0].resources.clear();
        assert_eq!(
            parse(&cfg, query(&parameters()).as_bytes()).err(),
            Some(InvalidTarget)
        );
        let mut params = parameters();
        params.push(("state", "x".repeat(1025)));
        assert_eq!(
            parse(&config(), query(&params).as_bytes()).err(),
            Some(InvalidRequest)
        );
    }

    #[test]
    fn strict_decoding_and_boundaries_use_otherwise_valid_requests() {
        let cfg = config();
        let valid = query(&parameters());
        for suffix in [
            "state=%ZZ",
            "state=%",
            "state=%FF",
            "unknown=%ZZ",
            "unknown=%FF",
        ] {
            assert_eq!(
                parse(&cfg, format!("{valid}&{suffix}").as_bytes()).err(),
                Some(InvalidRequest)
            );
        }
        let mut invalid_utf8 = format!("{valid}&state=").into_bytes();
        invalid_utf8.push(0xff);
        assert_eq!(parse(&cfg, &invalid_utf8).err(), Some(InvalidRequest));
        for (encoded, decoded) in [("a+b", "a b"), ("a%2Bb", "a+b")] {
            let request = parse(&cfg, format!("{valid}&state={encoded}").as_bytes()).unwrap();
            assert_eq!(request.state(), Some(decoded));
        }
        for length in [1024, 1025] {
            let raw = format!("{valid}&state={}", "x".repeat(length));
            assert_eq!(parse(&cfg, raw.as_bytes()).is_ok(), length == 1024);
        }
        let prefix = format!("{valid}&ignored=");
        let exact = format!("{prefix}{}", "x".repeat(8192 - prefix.len()));
        assert!(parse(&cfg, exact.as_bytes()).is_ok());
        assert_eq!(
            parse(&cfg, format!("{exact}x").as_bytes()).err(),
            Some(InvalidRequest)
        );
        for count in [32, 33] {
            let raw = format!("{valid}{}", "&unknown=x".repeat(count - parameters().len()));
            assert_eq!(parse(&cfg, raw.as_bytes()).is_ok(), count == 32);
        }
    }

    #[test]
    fn same_request_compares_every_parameter() {
        let cfg = config();
        let base = parse(&cfg, query(&parameters()).as_bytes()).unwrap();
        assert!(base.same_request(&parse(&cfg, query(&parameters()).as_bytes()).unwrap()));
        let mut params = parameters();
        set(&mut params, "state", "other".into());
        assert!(!base.same_request(&parse(&cfg, query(&params).as_bytes()).unwrap()));
    }
    #[test]
    fn loopback_registration_accepts_any_port_and_retains_requested_callback() {
        let mut cfg = config();
        cfg.clients[0].application_type = crate::config::oauth::ApplicationType::Native;
        cfg.clients[0].redirect_uris = vec![
            "http://127.0.0.1/cb?x=1".into(),
            "http://localhost/cb".into(),
            CALLBACK.into(),
        ];
        for callback in [
            "http://127.0.0.1:1/cb?x=1",
            "http://127.0.0.1:65535/cb?x=1",
            "http://127.0.0.1:51734/cb?x=1",
            "http://localhost:33418/cb",
            CALLBACK,
        ] {
            let mut params = parameters();
            set(&mut params, "redirect_uri", callback.into());
            let request = parse(&cfg, query(&params).as_bytes()).unwrap();
            assert_eq!(request.redirect_uri(), callback);
        }
        for callback in [
            "http://127.0.0.1/cb?x=1",
            "http://127.0.0.1:0/cb?x=1",
            "http://127.0.0.1:abc/cb?x=1",
            "http://127.0.0.1:8080/cb?x=2",
            "http://127.0.0.1:8080/other?x=1",
            "http://localhost:8080/cb?x=1",
            "http://127.0.0.1:8080/cb",
            "https://127.0.0.1:8080/cb?x=1",
            "https://app.test:8443/cb?fixed=a%20b",
        ] {
            let mut params = parameters();
            set(&mut params, "redirect_uri", callback.into());
            assert_eq!(
                parse(&cfg, query(&params).as_bytes()).err(),
                Some(InvalidRequest),
                "{callback}"
            );
        }
    }
}

// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! Browser leg of the authorization code flow: the binding stored with the sign-in
//! state, the nonce and PKCE verifier derived from it, the authorization request URL,
//! and the callback query.
//!
//! The `state` sent to the provider is the browser form token `<sid>.<challenge>`. Only
//! a hash bound to the browser's form cookie is stored; the nonce and verifier are
//! recomputed from that cookie and `state` at the callback, so neither is kept at rest.

use crate::{config::OidcMethodConfig, oauth::authorization::decode_component};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use url::Url;
use zeroize::Zeroizing;

const MAX_CALLBACK_QUERY_BYTES: usize = 8 * 1024;
const MAX_CALLBACK_FIELDS: usize = 32;
const MAX_STATE_BYTES: usize = 256;
const MAX_CODE_BYTES: usize = 4096;
const CALLBACK_FIELDS: [&str; 7] = [
    "code",
    "state",
    "iss",
    "error",
    "error_description",
    "error_uri",
    "session_state",
];

/// Route of a method's callback, e.g. `/login/method/demo-sso/callback`.
pub fn callback_path(id: &str) -> String {
    format!("/login/method/{id}/callback")
}

/// Redirect URI registered at the provider: the browser origin (no trailing slash, as
/// `BrowserSessionConfig::origin` returns it) followed by [`callback_path`].
pub fn redirect_uri(origin: &str, id: &str) -> String {
    format!("{origin}{}", callback_path(id))
}

/// 64 lowercase hex digits binding a sign-in state to the browser's form cookie and, for
/// an authorization request, to its transaction cookies. Stored as the form nonce, so a
/// callback with other cookies cannot consume the state.
pub fn binding(form_nonce: &str, authorization: Option<&[u8; 32]>) -> String {
    let mut digest = Sha256::new();
    digest.update(b"authotron-oidc-binding\0");
    digest.update(form_nonce.as_bytes());
    match authorization {
        Some(hash) => {
            digest.update(b"\0authorization\0");
            digest.update(hash);
        }
        None => digest.update(b"\0browser"),
    }
    format!("{:x}", digest.finalize())
}

fn derive(domain: &[u8], form_nonce: &str, state: &str) -> String {
    let mut digest = Sha256::new();
    for part in [domain, form_nonce.as_bytes(), state.as_bytes()] {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part);
    }
    URL_SAFE_NO_PAD.encode(digest.finalize())
}

/// Per-state nonce and PKCE verifier (43 base64url characters, RFC 7636 §4.1).
/// Deliberately not Debug.
pub struct FlowSecrets {
    nonce: String,
    verifier: Zeroizing<String>,
}

impl FlowSecrets {
    pub fn derive(form_nonce: &str, state: &str) -> Self {
        Self {
            nonce: derive(b"authotron-oidc-nonce", form_nonce, state),
            verifier: Zeroizing::new(derive(b"authotron-oidc-pkce", form_nonce, state)),
        }
    }
    pub fn nonce(&self) -> &str {
        &self.nonce
    }
    pub fn verifier(&self) -> &str {
        &self.verifier
    }
    /// S256 challenge: base64url SHA-256 of the verifier.
    pub fn challenge(&self) -> String {
        URL_SAFE_NO_PAD.encode(Sha256::digest(self.verifier.as_bytes()))
    }
}

/// Authorization request for the code flow, appended to any query the endpoint has.
/// `offline` adds the `offline_access` scope, asking for a refresh token.
pub fn authorization_url(
    endpoint: &Url,
    config: &OidcMethodConfig,
    redirect_uri: &str,
    state: &str,
    secrets: &FlowSecrets,
    offline: bool,
) -> Url {
    let scope = std::iter::once("openid")
        .chain(config.scopes.iter().map(String::as_str))
        .chain(offline.then_some("offline_access"))
        .collect::<Vec<_>>()
        .join(" ");
    let mut url = endpoint.clone();
    {
        let mut query = url.query_pairs_mut();
        query
            .append_pair("response_type", "code")
            .append_pair("client_id", &config.client_id)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("scope", &scope)
            .append_pair("state", state)
            .append_pair("nonce", secrets.nonce())
            .append_pair("code_challenge", &secrets.challenge())
            .append_pair("code_challenge_method", "S256");
        if let Some(age) = config.max_authentication_age_seconds {
            query.append_pair("max_age", &age.to_string());
        }
        if let Some(prompt) = config.prompt {
            query.append_pair("prompt", prompt.as_str());
        }
    }
    url
}

/// What the provider returned for the authorization request.
pub enum CallbackResult {
    Code(Zeroizing<String>),
    /// The provider's `error` code when it is a short `[a-z_]` token, otherwise `invalid`.
    Error(String),
}

pub struct Callback {
    pub state: String,
    pub iss: Option<String>,
    pub result: CallbackResult,
}

/// Parses the callback query; unknown parameters are ignored.
/// Valid: `code=SplxlOBe&state=<s>&iss=https%3A%2F%2Fidp.example.org`,
/// `error=access_denied&state=<s>`, either with `session_state=…`.
/// Invalid: a repeated known parameter, both or neither of `code` and `error`, a missing
/// or empty `state`, a `%ZZ` escape, more than 32 fields, or more than 8 KiB.
pub fn parse_callback(query: &[u8]) -> Option<Callback> {
    if query.len() > MAX_CALLBACK_QUERY_BYTES
        || query.split(|byte| *byte == b'&').count() > MAX_CALLBACK_FIELDS
    {
        return None;
    }
    let mut fields: HashMap<String, String> = HashMap::new();
    for pair in query.split(|byte| *byte == b'&') {
        let split = pair
            .iter()
            .position(|byte| *byte == b'=')
            .unwrap_or(pair.len());
        let name = decode_component(&pair[..split]).ok()?;
        if !CALLBACK_FIELDS.contains(&name.as_str()) {
            continue;
        }
        let value = decode_component(pair.get(split + 1..).unwrap_or_default()).ok()?;
        if fields.insert(name, value).is_some() {
            return None;
        }
    }
    let state = fields.remove("state")?;
    if state.is_empty() || state.len() > MAX_STATE_BYTES {
        return None;
    }
    let result = match (fields.remove("code"), fields.remove("error")) {
        (Some(code), None)
            if !code.is_empty()
                && code.len() <= MAX_CODE_BYTES
                && !code.chars().any(|c| c.is_whitespace() || c.is_control()) =>
        {
            CallbackResult::Code(Zeroizing::new(code))
        }
        (None, Some(error)) => CallbackResult::Error(
            if !error.is_empty()
                && error.len() <= 64
                && error.bytes().all(|c| c.is_ascii_lowercase() || c == b'_')
            {
                error
            } else {
                "invalid".to_owned()
            },
        ),
        _ => return None,
    };
    Some(Callback {
        state,
        iss: fields.remove("iss"),
        result,
    })
}

/// RFC 9207: a present `iss` must equal the issuer; it is required when advertised.
pub fn issuer_parameter_valid(iss: Option<&str>, issuer: &str, advertised: bool) -> bool {
    match iss {
        Some(value) => value == issuer,
        None => !advertised,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const NONCE: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const STATE: &str = "aaaa.bbbb";

    #[test]
    fn bindings_and_secrets_are_distinct_per_browser_state_and_context() {
        let browser = binding(NONCE, None);
        assert_eq!(browser.len(), 64);
        assert!(
            browser
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        );
        assert_eq!(browser, binding(NONCE, None));
        let authorization = binding(NONCE, Some(&[7; 32]));
        assert_ne!(browser, authorization);
        assert_ne!(authorization, binding(NONCE, Some(&[8; 32])));
        assert_ne!(browser, binding(&NONCE.replace('0', "1"), None));

        let secrets = FlowSecrets::derive(NONCE, STATE);
        assert_eq!(secrets.verifier().len(), 43);
        assert!(
            secrets
                .verifier()
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        );
        assert_ne!(secrets.nonce(), secrets.verifier());
        let again = FlowSecrets::derive(NONCE, STATE);
        assert_eq!(
            (again.nonce(), again.verifier()),
            (secrets.nonce(), secrets.verifier())
        );
        let other = FlowSecrets::derive(NONCE, "aaaa.bbbc");
        assert_ne!(other.nonce(), secrets.nonce());
        assert_ne!(other.verifier(), secrets.verifier());
        // RFC 7636 appendix B example.
        let example = FlowSecrets {
            nonce: String::new(),
            verifier: Zeroizing::new("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".into()),
        };
        assert_eq!(
            example.challenge(),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn authorization_requests_carry_every_protection_parameter() {
        let mut config: OidcMethodConfig = serde_json::from_value(json!({
            "id": "demo-sso", "label": "SSO", "realm": "idp", "issuer": "https://idp.example.org",
            "client_id": "authotron playground", "client_auth": "none", "scopes": ["profile", "email"]
        }))
        .unwrap();
        let endpoint = Url::parse("https://idp.example.org/auth?tenant=a%20b").unwrap();
        let redirect = redirect_uri("https://login.example.org", "demo-sso");
        assert_eq!(
            redirect,
            "https://login.example.org/login/method/demo-sso/callback"
        );
        let secrets = FlowSecrets::derive(NONCE, STATE);
        let url = authorization_url(&endpoint, &config, &redirect, STATE, &secrets, false);
        let query: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        let challenge = secrets.challenge();
        let expected = [
            ("tenant", "a b"),
            ("response_type", "code"),
            ("client_id", "authotron playground"),
            ("redirect_uri", redirect.as_str()),
            ("scope", "openid profile email"),
            ("state", STATE),
            ("nonce", secrets.nonce()),
            ("code_challenge", challenge.as_str()),
            ("code_challenge_method", "S256"),
        ];
        assert_eq!(
            query,
            expected.map(|(name, value)| (name.to_owned(), value.to_owned()))
        );
        assert!(!url.as_str().contains(secrets.verifier()));
        config.max_authentication_age_seconds = Some(600);
        config.prompt = Some(crate::config::OidcPrompt::Login);
        let url = authorization_url(&endpoint, &config, &redirect, STATE, &secrets, true);
        let scope = url
            .query_pairs()
            .find(|(name, _)| name == "scope")
            .unwrap()
            .1;
        assert_eq!(scope, "openid profile email offline_access");
        let tail: Vec<(String, String)> = url.query_pairs().into_owned().skip(9).collect();
        assert_eq!(
            tail,
            [
                ("max_age".to_owned(), "600".to_owned()),
                ("prompt".to_owned(), "login".to_owned())
            ]
        );
    }

    fn code(callback: &Callback) -> Option<&str> {
        match &callback.result {
            CallbackResult::Code(code) => Some(code.as_str()),
            CallbackResult::Error(_) => None,
        }
    }
    fn error(callback: &Callback) -> Option<&str> {
        match &callback.result {
            CallbackResult::Error(error) => Some(error),
            CallbackResult::Code(_) => None,
        }
    }

    #[test]
    fn callback_queries_are_parsed_strictly() {
        let callback = parse_callback(
            b"state=aaaa.bbbb&session_state=x&iss=https%3A%2F%2Fidp.example.org&code=c.1-x_y&extra=1",
        )
        .unwrap();
        assert_eq!(callback.state, STATE);
        assert_eq!(callback.iss.as_deref(), Some("https://idp.example.org"));
        assert_eq!(code(&callback), Some("c.1-x_y"));
        let denied =
            parse_callback(b"error=access_denied&error_description=No%20thanks&state=s").unwrap();
        assert_eq!(error(&denied), Some("access_denied"));
        assert!(denied.iss.is_none());
        let odd = parse_callback(b"error=%3Cscript%3E&state=s").unwrap();
        assert_eq!(error(&odd), Some("invalid"));
        for invalid in [
            &b"code=a&code=b&state=s"[..],
            b"code=a&state=s&state=t",
            b"code=a&error=access_denied&state=s",
            b"state=s",
            b"code=a",
            b"code=a&state=",
            b"code=&state=s",
            b"code=a%20b&state=s",
            b"code=a&state=%ZZ",
            b"code=a&state=s&iss=a&iss=b",
        ] {
            assert!(
                parse_callback(invalid).is_none(),
                "{}",
                String::from_utf8_lossy(invalid)
            );
        }
        let long_state = format!("code=a&state={}", "s".repeat(MAX_STATE_BYTES + 1));
        assert!(parse_callback(long_state.as_bytes()).is_none());
        let many = format!("code=a&state=s{}", "&x=1".repeat(MAX_CALLBACK_FIELDS));
        assert!(parse_callback(many.as_bytes()).is_none());
        let large = format!("code={}&state=s", "c".repeat(MAX_CALLBACK_QUERY_BYTES));
        assert!(parse_callback(large.as_bytes()).is_none());
    }

    #[test]
    fn issuer_parameter_must_match_and_is_required_when_advertised() {
        let issuer = "https://idp.example.org/realms/demo";
        assert!(issuer_parameter_valid(Some(issuer), issuer, true));
        assert!(issuer_parameter_valid(Some(issuer), issuer, false));
        assert!(issuer_parameter_valid(None, issuer, false));
        assert!(!issuer_parameter_valid(None, issuer, true));
        assert!(!issuer_parameter_valid(
            Some("https://attacker.example.org"),
            issuer,
            false
        ));
    }
}

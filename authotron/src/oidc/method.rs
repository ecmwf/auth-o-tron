// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! One configured OIDC sign-in method: its client secret, provider metadata and keys,
//! and the two steps the browser routes need, building the authorization request and
//! turning a callback code into a verified identity.

use super::{
    OidcError,
    claims::map_identity,
    discovery::{Availability, Discovery, ProviderMetadata},
    flow::{FlowSecrets, authorization_url, issuer_parameter_valid, redirect_uri},
    http::IdpHttp,
    id_token::{Expected, inspect, verify},
    jwks::Jwks,
    token_client::{ClientCredentials, exchange_code},
};
use crate::{
    config::{OidcClientAuth, OidcMethodConfig},
    models::user::User,
    utils::secret_file::read_secret_text,
};
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use url::Url;
use zeroize::Zeroizing;

const MAX_SECRET_BYTES: usize = 4096;
/// An ID token is issued during the code exchange, so it is at most this old (plus skew).
const MAX_ISSUED_AGE_SECONDS: u64 = 600;

/// A completed sign-in: the mapped identity (not yet augmented), the provider's `sub`
/// and the refresh token, when the provider issued one. Deliberately not Debug.
pub struct SignIn {
    pub user: User,
    pub subject: String,
    pub refresh_token: Option<Zeroizing<String>>,
}

pub struct OidcMethod {
    config: OidcMethodConfig,
    secret: Option<Zeroizing<String>>,
    redirect_uri: String,
    http: IdpHttp,
    discovery: Discovery,
    jwks: Jwks,
}

impl OidcMethod {
    /// Validates the method and reads its client secret; `origin` is the browser public
    /// origin that prefixes the redirect URI.
    pub fn new(config: &OidcMethodConfig, origin: &str) -> Result<Self, String> {
        config.validate().map_err(str::to_owned)?;
        let secret = match &config.client_secret_file {
            Some(path) => Some(read_secret_text(path, MAX_SECRET_BYTES).ok_or_else(|| {
                format!(
                    "OIDC method {}: client_secret_file is unreadable, empty, larger than 4 KiB or not plain text",
                    config.id
                )
            })?),
            None => None,
        };
        let invalid = |_| format!("OIDC method {}: invalid issuer", config.id);
        Ok(Self {
            config: config.clone(),
            secret,
            redirect_uri: redirect_uri(origin, &config.id),
            http: IdpHttp::new(Duration::from_millis(config.http_timeout_ms)).map_err(invalid)?,
            discovery: Discovery::new(&config.issuer, &config.additional_endpoint_origins)
                .map_err(invalid)?,
            jwks: Jwks::default(),
        })
    }

    pub fn config(&self) -> &OidcMethodConfig {
        &self.config
    }

    pub fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }

    pub fn availability(&self) -> Availability {
        self.discovery.availability()
    }

    /// Cached provider metadata, fetched when missing or stale.
    pub async fn metadata(&self) -> Result<Arc<ProviderMetadata>, OidcError> {
        self.discovery.metadata(&self.http).await
    }

    /// `offline` requests the `offline_access` scope.
    pub fn authorization_url(
        &self,
        metadata: &ProviderMetadata,
        state: &str,
        secrets: &FlowSecrets,
        offline: bool,
    ) -> Url {
        authorization_url(
            &metadata.authorization_endpoint,
            &self.config,
            &self.redirect_uri,
            state,
            secrets,
            offline,
        )
    }

    fn credentials(&self) -> ClientCredentials<'_> {
        let client_id = &self.config.client_id;
        match (self.config.client_auth, &self.secret) {
            (OidcClientAuth::ClientSecretBasic, Some(secret)) => {
                ClientCredentials::Basic { client_id, secret }
            }
            (OidcClientAuth::ClientSecretPost, Some(secret)) => {
                ClientCredentials::Post { client_id, secret }
            }
            _ => ClientCredentials::Public { client_id },
        }
    }

    /// Checks the callback's `iss`, exchanges `code`, validates the ID token against the
    /// state's `secrets` and maps its claims.
    pub async fn complete(
        &self,
        iss: Option<&str>,
        code: &str,
        secrets: &FlowSecrets,
    ) -> Result<SignIn, OidcError> {
        let metadata = self.metadata().await?;
        if !issuer_parameter_valid(
            iss,
            &self.config.issuer,
            metadata.authorization_response_iss_parameter_supported,
        ) {
            return Err(OidcError::Rejected);
        }
        let tokens = exchange_code(
            &self.http,
            &metadata.token_endpoint,
            &self.credentials(),
            code,
            &self.redirect_uri,
            secrets.verifier(),
        )
        .await?;
        let id_token = tokens.id_token.ok_or(OidcError::InvalidResponse)?;
        let (alg, kid) = inspect(&id_token, &self.config.id_token_algorithms)?;
        let key = self
            .jwks
            .key(&self.http, &metadata.jwks_uri, kid.as_deref(), alg)
            .await?;
        let now_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| OidcError::Unavailable)?
            .as_secs();
        let claims = verify(
            &id_token,
            alg,
            &key,
            &Expected {
                issuer: &self.config.issuer,
                client_id: &self.config.client_id,
                nonce: secrets.nonce(),
                now_seconds,
                skew_seconds: self.config.clock_skew_seconds,
                max_issued_age_seconds: MAX_ISSUED_AGE_SECONDS,
                max_authentication_age_seconds: self.config.max_authentication_age_seconds,
            },
        )?;
        let user = map_identity(&self.config, &claims)?;
        Ok(SignIn {
            user,
            subject: claims.sub,
            refresh_token: tokens.refresh_token,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oidc::mock::{CLIENT_ID, CLIENT_SECRET, MockIdp, SUBJECT};
    use serde_json::json;
    use std::{io::Write, sync::atomic::Ordering};

    const ORIGIN: &str = "https://login.example.org";
    const FORM_NONCE: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn method(idp: &MockIdp, changes: serde_json::Value) -> (tempfile::NamedTempFile, OidcMethod) {
        let mut secret = tempfile::NamedTempFile::new().unwrap();
        writeln!(secret, "  {CLIENT_SECRET}  ").unwrap();
        let mut value = json!({
            "id": "demo-sso", "label": "SSO", "realm": "idp", "issuer": idp.issuer,
            "client_id": CLIENT_ID, "client_secret_file": secret.path(),
        });
        value
            .as_object_mut()
            .unwrap()
            .extend(changes.as_object().unwrap().clone());
        let config: OidcMethodConfig = serde_json::from_value(value).unwrap();
        (secret, OidcMethod::new(&config, ORIGIN).unwrap())
    }

    /// Runs the browser leg: authorization URL, provider sign-in, callback parameters.
    async fn sign_in(
        idp: &MockIdp,
        method: &OidcMethod,
        state: &str,
        offline: bool,
    ) -> Result<SignIn, OidcError> {
        let secrets = FlowSecrets::derive(FORM_NONCE, state);
        let metadata = method.metadata().await?;
        let request = method.authorization_url(&metadata, state, &secrets, offline);
        let callback = idp.authorize(&request);
        let query = url::Url::parse(&callback).unwrap();
        let callback =
            crate::oidc::flow::parse_callback(query.query().unwrap().as_bytes()).unwrap();
        assert_eq!(callback.state, state);
        let crate::oidc::flow::CallbackResult::Code(code) = callback.result else {
            panic!("expected a code");
        };
        method
            .complete(callback.iss.as_deref(), &code, &secrets)
            .await
    }

    #[tokio::test]
    async fn a_complete_sign_in_yields_the_mapped_identity() {
        let idp = MockIdp::start().await;
        for auth in ["client_secret_basic", "client_secret_post"] {
            let (_secret, method) = method(&idp, json!({"client_auth": auth}));
            assert_eq!(
                method.redirect_uri(),
                "https://login.example.org/login/method/demo-sso/callback"
            );
            assert_eq!(method.availability(), Availability::Unknown);
            let signed_in = sign_in(&idp, &method, "state-1", false).await.unwrap();
            assert_eq!(signed_in.subject, SUBJECT);
            assert!(signed_in.refresh_token.is_none());
            let user = signed_in.user;
            assert_eq!(
                (user.realm.as_str(), user.username.as_str()),
                ("idp", SUBJECT)
            );
            assert!(user.roles.is_empty());
            assert_eq!(user.attributes["email"], "alice@example.org");
            assert_eq!(method.availability(), Availability::Available);
        }
        let (_secret, mapped) = method(
            &idp,
            json!({"username_claim": "preferred_username", "roles_claim": "realm_access.roles",
                "role_map": {"mcp-demo": "mcp-demo"}}),
        );
        let user = sign_in(&idp, &mapped, "state-2", false).await.unwrap().user;
        // Requesting offline access yields the provider's refresh token.
        let offline = sign_in(&idp, &mapped, "state-3", true).await.unwrap();
        assert!(offline.refresh_token.unwrap().starts_with("offline-"));
        assert_eq!(user.username, "alice");
        assert_eq!(user.roles, ["mcp-demo"]);
    }

    #[tokio::test]
    async fn codes_issuers_nonces_and_keys_are_checked() {
        let idp = MockIdp::start().await;
        let (_secret, method) = method(&idp, json!({}));
        let secrets = FlowSecrets::derive(FORM_NONCE, "state");
        let metadata = method.metadata().await.unwrap();
        let callback =
            idp.authorize(&method.authorization_url(&metadata, "state", &secrets, false));
        let code = url::Url::parse(&callback)
            .unwrap()
            .query_pairs()
            .find(|(name, _)| name == "code")
            .unwrap()
            .1
            .into_owned();
        // RFC 9207: the provider advertises `iss`, so it is required and must match.
        for iss in [None, Some("https://attacker.example.org")] {
            assert_eq!(
                method.complete(iss, &code, &secrets).await.err(),
                Some(OidcError::Rejected)
            );
        }
        assert_eq!(idp.state.token_requests.load(Ordering::SeqCst), 0);
        // A verifier or nonce from another state fails at the provider or locally.
        let other = FlowSecrets::derive(FORM_NONCE, "other-state");
        assert_eq!(
            method
                .complete(Some(&idp.issuer), &code, &other)
                .await
                .err(),
            Some(OidcError::Rejected)
        );
        // The code is single-use at the provider.
        assert_eq!(
            method
                .complete(Some(&idp.issuer), &code, &secrets)
                .await
                .err(),
            Some(OidcError::Rejected)
        );
        *idp.state.claims.lock().unwrap() = json!({"nonce": "replayed"});
        assert_eq!(
            sign_in(&idp, &method, "state-3", false).await.err(),
            Some(OidcError::InvalidIdToken)
        );
        *idp.state.claims.lock().unwrap() = json!({"aud": "other-client"});
        assert_eq!(
            sign_in(&idp, &method, "state-4", false).await.err(),
            Some(OidcError::InvalidIdToken)
        );
        *idp.state.claims.lock().unwrap() = json!({});
        // Rotated signing key published under a new kid.
        *idp.state.signer.lock().unwrap() = (1, "k1".into());
        assert!(sign_in(&idp, &method, "state-5", false).await.is_ok());
        *idp.state.signer.lock().unwrap() = (1, "k0".into());
        assert_eq!(
            sign_in(&idp, &method, "state-6", false).await.err(),
            Some(OidcError::InvalidIdToken)
        );
    }

    #[tokio::test]
    async fn providers_without_the_iss_parameter_and_failing_endpoints() {
        let idp = MockIdp::start().await;
        idp.state.iss_parameter.store(false, Ordering::SeqCst);
        let (_secret, method) = method(&idp, json!({}));
        assert!(sign_in(&idp, &method, "state", false).await.is_ok());
        for (status, answer, expected) in [
            (500, json!({}), OidcError::Unavailable),
            (
                401,
                json!({"error": "invalid_client"}),
                OidcError::ClientRejected,
            ),
            (
                200,
                json!({"access_token": "only"}),
                OidcError::InvalidResponse,
            ),
        ] {
            *idp.state.token_answer.lock().unwrap() = Some((status, answer));
            assert_eq!(
                sign_in(&idp, &method, "state", false).await.err(),
                Some(expected)
            );
        }
        // A wrong client secret is refused by the provider.
        *idp.state.token_answer.lock().unwrap() = None;
        let mut secret = tempfile::NamedTempFile::new().unwrap();
        writeln!(secret, "wrong-secret").unwrap();
        let mut config = method.config().clone();
        config.client_secret_file = Some(secret.path().to_owned());
        let wrong = OidcMethod::new(&config, ORIGIN).unwrap();
        assert_eq!(
            sign_in(&idp, &wrong, "state", false).await.err(),
            Some(OidcError::ClientRejected)
        );
    }

    #[test]
    fn secret_files_must_be_small_plain_text() {
        let config = |path: &std::path::Path| -> OidcMethodConfig {
            serde_json::from_value(json!({
                "id": "sso", "label": "SSO", "realm": "idp", "issuer": "https://idp.example.org",
                "client_id": CLIENT_ID, "client_secret_file": path
            }))
            .unwrap()
        };
        for content in [
            "".to_owned(),
            " \n".to_owned(),
            "a\u{7}b".to_owned(),
            "s".repeat(MAX_SECRET_BYTES + 1),
        ] {
            let mut file = tempfile::NamedTempFile::new().unwrap();
            file.write_all(content.as_bytes()).unwrap();
            let error = OidcMethod::new(&config(file.path()), ORIGIN).err().unwrap();
            assert!(error.contains("client_secret_file"));
            assert!(!error.contains(file.path().to_str().unwrap()));
        }
        let missing = std::path::Path::new("/nonexistent-authotron-test/secret");
        assert!(OidcMethod::new(&config(missing), ORIGIN).is_err());
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(&[0xff, 0xfe]).unwrap();
        assert!(OidcMethod::new(&config(file.path()), ORIGIN).is_err());
    }
}

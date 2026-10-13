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
};
use std::{
    io::Read,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use url::Url;
use zeroize::Zeroizing;

const MAX_SECRET_BYTES: usize = 4096;
/// An ID token is issued during the code exchange, so it is at most this old (plus skew).
const MAX_ISSUED_AGE_SECONDS: u64 = 600;

pub struct OidcMethod {
    config: OidcMethodConfig,
    secret: Option<Zeroizing<String>>,
    redirect_uri: String,
    http: IdpHttp,
    discovery: Discovery,
    jwks: Jwks,
}

/// Reads a secret file: at most 4 KiB of UTF-8, surrounding whitespace trimmed, and
/// non-empty without control characters. Errors never include the content or path.
fn read_secret(path: &std::path::Path) -> Option<Zeroizing<String>> {
    let file = std::fs::File::open(path).ok()?;
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(MAX_SECRET_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    let text = std::str::from_utf8(&bytes).ok()?.trim();
    (bytes.len() <= MAX_SECRET_BYTES && !text.is_empty() && !text.chars().any(char::is_control))
        .then(|| Zeroizing::new(text.to_owned()))
}

impl OidcMethod {
    /// Validates the method and reads its client secret; `origin` is the browser public
    /// origin that prefixes the redirect URI.
    pub fn new(config: &OidcMethodConfig, origin: &str) -> Result<Self, String> {
        config.validate().map_err(str::to_owned)?;
        let secret = match &config.client_secret_file {
            Some(path) => Some(read_secret(path).ok_or_else(|| {
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

    pub fn authorization_url(
        &self,
        metadata: &ProviderMetadata,
        state: &str,
        secrets: &FlowSecrets,
    ) -> Url {
        authorization_url(
            &metadata.authorization_endpoint,
            &self.config,
            &self.redirect_uri,
            state,
            secrets,
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
    /// state's `secrets` and maps its claims. The returned identity is not yet augmented.
    pub async fn complete(
        &self,
        iss: Option<&str>,
        code: &str,
        secrets: &FlowSecrets,
    ) -> Result<User, OidcError> {
        let metadata = self.metadata().await?;
        if !issuer_parameter_valid(
            iss,
            &self.config.issuer,
            metadata.authorization_response_iss_parameter_supported,
        ) {
            return Err(OidcError::Rejected);
        }
        let token = exchange_code(
            &self.http,
            &metadata.token_endpoint,
            &self.credentials(),
            code,
            &self.redirect_uri,
            secrets.verifier(),
        )
        .await?;
        let (alg, kid) = inspect(&token, &self.config.id_token_algorithms)?;
        let key = self
            .jwks
            .key(&self.http, &metadata.jwks_uri, kid.as_deref(), alg)
            .await?;
        let now_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| OidcError::Unavailable)?
            .as_secs();
        let claims = verify(
            &token,
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
        map_identity(&self.config, &claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::Write;

    const ORIGIN: &str = "https://login.example.org";

    #[test]
    fn secret_files_must_be_small_plain_text() {
        let config = |path: &std::path::Path| -> OidcMethodConfig {
            serde_json::from_value(json!({
                "id": "sso", "label": "SSO", "realm": "idp", "issuer": "https://idp.example.org",
                "client_id": "authotron", "client_secret_file": path
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

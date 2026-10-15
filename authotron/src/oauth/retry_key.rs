// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! The retry key: a secret every replica holds and the store never does, mixed into
//! the key that seals each rotation's successor for retries. A family record keeps only
//! its latest sealed successor, but Valkey's append-only file, its replicas and command
//! logs (`MONITOR`, `SLOWLOG`) keep earlier ones too. Without the retry key none of them
//! opens, even with an old refresh token, so they cannot be walked to the current token.

use super::refresh::RefreshStoreError;
use crate::{
    config::{ConfigV2, ui::BrowserBackendConfig},
    oidc::upstream::read_key_file,
};
use ring::{
    aead::{AES_256_GCM, LessSafeKey, UnboundKey},
    hkdf,
};
use rsa::rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

/// HKDF info label of successor keys, ahead of the family id.
const SUCCESSOR_LABEL: &[u8] = b"authotron-refresh-successor-v2";

/// Deliberately not Debug.
pub struct RetryKey(Zeroizing<[u8; 32]>);

impl RetryKey {
    /// `oauth.refresh_token_retry_key_file`, or else a random key for this process,
    /// which [`validate`] allows only without a Valkey store of refresh tokens: a memory
    /// store answers every retry in the process that rotated. A key that is also an
    /// upstream token encryption key is refused.
    pub(super) fn load(config: &ConfigV2) -> Result<Self, String> {
        let Some(path) = &config.oauth.refresh_token_retry_key_file else {
            let mut key = Zeroizing::new([0; 32]);
            OsRng
                .try_fill_bytes(&mut *key)
                .map_err(|_| "no randomness for the refresh-token retry key")?;
            return Ok(Self(key));
        };
        let key = read_key_file(path).ok_or(
            "oauth.refresh_token_retry_key_file is unreadable or not 32 bytes of standard Base64",
        )?;
        let upstream = config.oauth.upstream_token_encryption.iter();
        for other in upstream.flat_map(|encryption| &encryption.keys) {
            if read_key_file(&other.key_file).is_some_and(|bytes| *bytes == *key) {
                return Err(format!(
                    "oauth.refresh_token_retry_key_file holds upstream token key {}; give it a key of its own",
                    other.kid
                ));
            }
        }
        Ok(Self(key))
    }

    #[cfg(test)]
    pub(super) fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// The AES-256-GCM key with which `token` seals its successor in family `family_id`.
    /// HKDF-SHA256 extracts with the retry key as salt, which makes the pseudorandom key
    /// HMAC-SHA256(retry key, token): unpredictable without either of them (RFC 5869
    /// §3.1 allows a secret salt), so the token stays the input keying material it is.
    /// Expand binds the info `authotron-refresh-successor-v2 ‖ family id`, unambiguous
    /// since the label has a fixed length.
    pub(super) fn successor_key(
        &self,
        token: &str,
        family_id: &str,
    ) -> Result<LessSafeKey, RefreshStoreError> {
        let secret = hkdf::Salt::new(hkdf::HKDF_SHA256, &self.0[..]).extract(token.as_bytes());
        let info = [SUCCESSOR_LABEL, family_id.as_bytes()];
        let okm = secret
            .expand(&info, &AES_256_GCM)
            .map_err(|_| RefreshStoreError::Unavailable)?;
        Ok(LessSafeKey::new(UnboundKey::from(okm)))
    }
}

/// Checks that need neither files nor network, made before either is touched: refresh
/// tokens in Valkey require the retry key, and its file must not be another configured
/// key or secret file.
pub(super) fn validate(config: &ConfigV2) -> Result<(), &'static str> {
    let oauth = &config.oauth;
    let Some(path) = &oauth.refresh_token_retry_key_file else {
        let refresh = oauth.clients.iter().any(|c| c.refresh_tokens.enabled);
        let backend = config.ui.browser_session.as_ref().map(|s| &s.backend);
        return match backend {
            Some(BrowserBackendConfig::Valkey { .. }) if refresh => Err(
                "oauth.refresh_token_retry_key_file is required when refresh tokens are stored in Valkey",
            ),
            _ => Ok(()),
        };
    };
    let upstream = oauth.upstream_token_encryption.iter();
    let upstream = upstream.flat_map(|e| e.keys.iter().map(|key| key.key_file.as_path()));
    let signing = oauth.signing.iter().flat_map(|signing| {
        let keys = signing.keys.iter();
        keys.flat_map(|key| [&key.private_key_file, &key.public_key_file])
            .flatten()
            .map(|path| path.as_path())
    });
    let methods = config.ui.oidc.iter();
    let secrets = methods.filter_map(|method| method.client_secret_file.as_deref());
    if upstream
        .chain(signing)
        .chain(secrets)
        .any(|other| other == path)
    {
        return Err(
            "oauth.refresh_token_retry_key_file must be a file of its own, not another key or secret file",
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::STANDARD};
    use serde_json::{Value, json};
    use std::io::Write;

    fn key_file(bytes: [u8; 32]) -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(file, "{}", STANDARD.encode(bytes)).unwrap();
        file
    }

    /// Refresh tokens for `desktop`, upstream key `u1` and a Valkey browser backend; no
    /// file is read and no connection made.
    fn config(edit: impl FnOnce(&mut Value)) -> ConfigV2 {
        let mut value = json!({
            "store": {"enabled": false}, "services": [], "augmenters": [], "providers": [],
            "server": {"port": 0}, "jwt": {"iss": "fixture", "exp": 300, "secret": "fixture-only"},
            "logging": {"level": "warn", "format": "console"},
            "ui": {"enabled": true, "browser_session": {"public_origin": "https://login.example.org",
                "backend": {"type": "valkey", "url": "redis://127.0.0.1:1/0", "key_prefix": "fixture",
                    "password": "public-fixture"}}},
            "oauth": {"enabled": true, "issuer": "https://login.example.org/",
                "signing": {"active_kid": "k", "keys": [{"kid": "k", "private_key_file": "/run/oauth/signing.pem"}]},
                "upstream_token_encryption": {"active_kid": "u1", "keys": [{"kid": "u1", "key_file": "/run/oauth/u1.key"}]},
                "clients": [{"client_id": "desktop", "display_name": "Desktop", "redirect_uris": ["https://app.example.org/cb"],
                    "resources": [{"resource": "https://mcp.example.org/mcp", "scopes": ["read"]}],
                    "refresh_tokens": {"enabled": true}}],
                "resources": [{"resource": "https://mcp.example.org/mcp", "allowed_realms": ["idp"], "scopes": [{"name": "read", "required_roles": []}]}]}
        });
        edit(&mut value);
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn valkey_stores_require_a_retry_key_of_its_own() {
        let required = config(|_| {});
        assert_eq!(
            validate(&required),
            Err(
                "oauth.refresh_token_retry_key_file is required when refresh tokens are stored in Valkey"
            )
        );
        for allowed in [
            config(|c| c["oauth"]["refresh_token_retry_key_file"] = json!("/run/oauth/retry.key")),
            config(|c| c["ui"]["browser_session"]["backend"] = json!({"type": "memory"})),
            config(|c| c["oauth"]["clients"][0]["refresh_tokens"] = json!({"enabled": false})),
        ] {
            assert_eq!(validate(&allowed), Ok(()));
        }
        for reused in ["/run/oauth/u1.key", "/run/oauth/signing.pem"] {
            let config = config(|c| c["oauth"]["refresh_token_retry_key_file"] = json!(reused));
            assert!(validate(&config).is_err(), "{reused}");
        }
        let relative = config(|c| c["oauth"]["refresh_token_retry_key_file"] = json!("retry.key"));
        assert!(relative.oauth.validate().is_err());
    }

    #[test]
    fn retry_keys_are_read_like_other_key_files_and_never_shared_with_upstream_keys() {
        let (retry, upstream) = (key_file([1; 32]), key_file([2; 32]));
        let with = |retry: &tempfile::NamedTempFile, upstream: &tempfile::NamedTempFile| {
            config(|c| {
                c["oauth"]["refresh_token_retry_key_file"] = json!(retry.path());
                c["oauth"]["upstream_token_encryption"]["keys"][0]["key_file"] =
                    json!(upstream.path());
            })
        };
        let loaded = RetryKey::load(&with(&retry, &upstream)).unwrap();
        assert_eq!(*loaded.0, [1; 32]);
        let copy = key_file([2; 32]);
        let error = RetryKey::load(&with(&copy, &upstream)).err().unwrap();
        assert!(error.contains("upstream token key u1"), "{error}");
        let mut short = tempfile::NamedTempFile::new().unwrap();
        writeln!(short, "{}", STANDARD.encode([1u8; 16])).unwrap();
        assert!(RetryKey::load(&with(&short, &upstream)).is_err());
        let random = config(|_| {});
        assert_ne!(
            *RetryKey::load(&random).unwrap().0,
            *RetryKey::load(&random).unwrap().0
        );
    }
}

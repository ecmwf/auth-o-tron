// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! File references for the keys that seal upstream refresh tokens at rest; validation
//! performs no file I/O.

use super::oauth_signing::{valid_kid, valid_path};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// AES-256 keys for upstream refresh tokens. New tokens are sealed with `active_kid`;
/// the other keys only open tokens sealed before a rotation.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UpstreamTokenEncryptionConfig {
    #[schemars(length(min = 1, max = 64), regex(pattern = r"^[A-Za-z0-9._-]+$"))]
    pub active_kid: String,
    #[schemars(length(min = 1, max = 4))]
    pub keys: Vec<UpstreamTokenKey>,
}

/// One key: a file holding 32 random bytes in standard Base64, such as
/// `openssl rand -base64 32` writes.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UpstreamTokenKey {
    #[schemars(length(min = 1, max = 64), regex(pattern = r"^[A-Za-z0-9._-]+$"))]
    pub kid: String,
    pub key_file: PathBuf,
}

impl UpstreamTokenEncryptionConfig {
    /// Checks structure only; reading and decoding the key files belongs to the loader.
    pub fn validate(&self) -> Result<(), &'static str> {
        if !valid_kid(&self.active_kid) || !(1..=4).contains(&self.keys.len()) {
            return Err(
                "oauth.upstream_token_encryption requires a valid active_kid and 1..4 keys",
            );
        }
        let mut kids = std::collections::HashSet::new();
        for key in &self.keys {
            if !valid_kid(&key.kid) || !kids.insert(&key.kid) {
                return Err(
                    "oauth.upstream_token_encryption key ids must be unique 1..64 ASCII letters, digits, '.', '_' or '-'",
                );
            }
            if !valid_path(&key.key_file) {
                return Err(
                    "oauth.upstream_token_encryption key_file must be an absolute path of at most 4096 UTF-8 bytes without controls",
                );
            }
        }
        if !kids.contains(&self.active_kid) {
            return Err(
                "oauth.upstream_token_encryption active_kid must reference a configured key",
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn fixture() -> Value {
        json!({"active_kid": "upstream-2", "keys": [
            {"kid": "upstream-2", "key_file": "/run/secrets/oidc/upstream-2.key"},
            {"kid": "upstream.1", "key_file": "/run/secrets/oidc/upstream-1.key"}
        ]})
    }
    fn parse(value: Value) -> UpstreamTokenEncryptionConfig {
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn references_validate_without_reading_files() {
        let config = parse(fixture());
        config.validate().unwrap();
        assert_eq!(serde_json::to_value(&config).unwrap(), fixture());
    }

    #[test]
    fn invalid_references_are_rejected() {
        for (pointer, value) in [
            ("/active_kid", json!("missing")),
            ("/active_kid", json!("a/b")),
            ("/keys/1/kid", json!("upstream-2")),
            ("/keys/1/kid", json!("")),
            ("/keys/1/key_file", json!("relative.key")),
            ("/keys/1/key_file", json!("/a\nb.key")),
        ] {
            let mut input = fixture();
            *input.pointer_mut(pointer).unwrap() = value.clone();
            assert!(parse(input).validate().is_err(), "{pointer}={value}");
        }
        let mut many = fixture();
        many["keys"] = json!(
            (0..5)
                .map(|n| json!({"kid": format!("k{n}"), "key_file": format!("/k/{n}.key")}))
                .collect::<Vec<_>>()
        );
        many["active_kid"] = json!("k0");
        assert!(parse(many).validate().is_err());
        let mut none = fixture();
        none["keys"] = json!([]);
        assert!(parse(none).validate().is_err());
        for field in ["key", "secret"] {
            let mut inline = fixture();
            inline["keys"][0][field] = json!("not-key-material");
            assert!(serde_json::from_value::<UpstreamTokenEncryptionConfig>(inline).is_err());
        }
    }
}

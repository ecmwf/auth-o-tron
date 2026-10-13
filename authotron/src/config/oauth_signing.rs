// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! File references for RS256 signing; validation performs no file I/O.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OAuthSigningConfig {
    #[schemars(length(min = 1, max = 64), regex(pattern = r"^[A-Za-z0-9._-]+$"))]
    pub active_kid: String,
    #[schemars(length(min = 1, max = 8))]
    pub keys: Vec<OAuthSigningKey>,
}

/// Admin-selected paths only; key contents are never part of the config contract.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OAuthSigningKey {
    #[schemars(length(min = 1, max = 64), regex(pattern = r"^[A-Za-z0-9._-]+$"))]
    pub kid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key_file: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key_file: Option<PathBuf>,
}

pub(super) fn valid_kid(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
}

/// Valid: `/run/secrets/oauth/active.pem`. Invalid: `keys/active.pem` or a control character.
pub(super) fn valid_path(path: &Path) -> bool {
    path.is_absolute()
        && path.file_name().is_some()
        && path
            .to_str()
            .is_some_and(|value| value.len() <= 4096 && !value.chars().any(char::is_control))
}

impl OAuthSigningConfig {
    /// Checks structure only; existence, PEM parsing and cryptographic checks belong to the loader.
    pub fn validate(&self) -> Result<(), &'static str> {
        if !valid_kid(&self.active_kid) || !(1..=8).contains(&self.keys.len()) {
            return Err("OAuth signing requires a valid active_kid and 1..8 keys");
        }
        let mut kids = std::collections::HashSet::new();
        for key in &self.keys {
            if !valid_kid(&key.kid) || !kids.insert(&key.kid) {
                return Err(
                    "OAuth signing key IDs must be unique 1..64 ASCII letters, digits, '.', '_' or '-'",
                );
            }
            if key.private_key_file.is_none() && key.public_key_file.is_none() {
                return Err("OAuth signing keys require a private or public key file reference");
            }
            if [
                key.private_key_file.as_deref(),
                key.public_key_file.as_deref(),
            ]
            .into_iter()
            .flatten()
            .any(|path| !valid_path(path))
            {
                return Err(
                    "OAuth signing file references must be absolute paths of at most 4096 UTF-8 bytes without controls",
                );
            }
        }
        let active = self
            .keys
            .iter()
            .find(|key| key.kid == self.active_kid)
            .ok_or("OAuth signing active_kid must reference a configured key")?;
        if active.private_key_file.is_none() {
            return Err("OAuth signing active key requires a private key file reference");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::OAuthConfig;
    use serde_json::{Value, json};

    fn fixture() -> Value {
        json!({"active_kid": "active-1", "keys": [
            {"kid": "active-1", "private_key_file": "/nonexistent-authotron-test/active.pem"},
            {"kid": "old.1", "public_key_file": "/nonexistent-authotron-test/old.pem"}
        ]})
    }

    #[test]
    fn references_validate_without_reading_files_and_round_trip_without_key_contents() {
        let mut config: OAuthConfig = serde_json::from_value(json!({})).unwrap();
        assert!(config.signing.is_none());
        config.signing = Some(serde_json::from_value(fixture()).unwrap());
        assert!(config.validate().is_ok());
        assert_eq!(serde_json::to_value(&config.signing).unwrap(), fixture());
        let signing = config.signing.as_mut().unwrap();
        signing.keys[0].public_key_file =
            Some("/nonexistent-authotron-test/active-public.pem".into());
        signing.keys[1].private_key_file =
            Some("/nonexistent-authotron-test/old-private.pem".into());
        assert!(signing.validate().is_ok());
    }

    #[test]
    fn active_key_and_reference_errors_are_fixed_and_do_not_echo_paths() {
        for (pointer, value) in [
            ("/active_kid", json!("unknown")),
            ("/keys/0/kid", json!("old.1")),
            ("/keys/0/private_key_file", Value::Null),
            ("/keys/1/public_key_file", Value::Null),
            (
                "/keys/0/private_key_file",
                json!("relative-sensitive-name.pem"),
            ),
            ("/keys/0/private_key_file", json!("/sensitive-name\n.pem")),
            ("/keys/0/private_key_file", json!("/")),
            (
                "/keys/0/private_key_file",
                json!(format!("/{}", "x".repeat(4096))),
            ),
        ] {
            let mut input = fixture();
            *input.pointer_mut(pointer).unwrap() = value;
            let signing: OAuthSigningConfig = serde_json::from_value(input).unwrap();
            let error = signing.validate().unwrap_err();
            assert!(!error.contains("sensitive-name"));
            let config = OAuthConfig {
                signing: Some(signing),
                ..Default::default()
            };
            assert!(config.validate().is_err());
        }
        let mut signing: OAuthSigningConfig = serde_json::from_value(fixture()).unwrap();
        signing.keys[0].private_key_file = None;
        signing.keys[0].public_key_file = Some("/nonexistent-authotron-test/public.pem".into());
        assert_eq!(
            signing.validate(),
            Err("OAuth signing active key requires a private key file reference")
        );
    }

    #[test]
    fn key_ids_and_count_are_bounded() {
        for kid in [
            "".into(),
            " ".into(),
            "é".into(),
            "kid/1".into(),
            "k".repeat(65),
        ] {
            let mut signing: OAuthSigningConfig = serde_json::from_value(fixture()).unwrap();
            signing.active_kid = kid.clone();
            signing.keys[0].kid = kid;
            assert!(signing.validate().is_err());
        }
        let mut signing: OAuthSigningConfig = serde_json::from_value(fixture()).unwrap();
        signing.active_kid = "k".repeat(64);
        signing.keys[0].kid = signing.active_kid.clone();
        signing.keys = (0..8)
            .map(|i| OAuthSigningKey {
                kid: if i == 0 {
                    signing.active_kid.clone()
                } else {
                    format!("key_{i}")
                },
                ..signing.keys[0].clone()
            })
            .collect();
        assert!(signing.validate().is_ok());
        signing.keys.push(OAuthSigningKey {
            kid: "ninth".into(),
            ..signing.keys[0].clone()
        });
        assert!(signing.validate().is_err());
        signing.keys.clear();
        assert!(signing.validate().is_err());
    }

    #[test]
    fn unknown_fields_and_inline_key_material_are_rejected() {
        for field in ["private_key", "public_key", "algorithm", "secret"] {
            let mut input = fixture();
            input["keys"][0][field] = json!("not-key-material");
            assert!(serde_json::from_value::<OAuthSigningConfig>(input).is_err());
        }
        let mut input = fixture();
        input["reload"] = json!(true);
        assert!(serde_json::from_value::<OAuthSigningConfig>(input).is_err());
    }
}

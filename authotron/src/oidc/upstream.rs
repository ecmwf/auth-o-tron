// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! Upstream refresh tokens sealed with AES-256-GCM for storage with a refresh-token
//! family. The associated data binds a sealed token to its key id, sign-in method,
//! issuer, OAuth client and Auth-O-Tron identity, so it cannot be opened for another
//! family's user or client. Plaintext never leaves this module except to the provider.

use crate::{config::UpstreamTokenEncryptionConfig, utils::secret_file::read_secret_text};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use ring::{
    aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey},
    rand::{SecureRandom, SystemRandom},
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Upper bound on a sealed token; the plaintext is at most an 8 KiB refresh token.
pub const MAX_SEALED_BYTES: usize = 12 * 1024;
const FORMAT: &str = "v1";
const KEY_FILE_BYTES: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamError {
    /// Sealing failed: no randomness or an oversized token.
    Seal,
    /// Malformed, unknown key id, wrong binding, or tampered.
    Open,
}

/// The family context every sealed token is bound to.
pub struct UpstreamBinding<'a> {
    pub method: &'a str,
    pub issuer: &'a str,
    pub client_id: &'a str,
    pub realm: &'a str,
    pub username: &'a str,
}

/// An upstream grant in the clear. Deliberately not Debug, Clone or Serialize.
pub struct UpstreamGrant {
    subject: String,
    refresh_token: Zeroizing<String>,
}

impl UpstreamGrant {
    /// `subject` is the provider's `sub` for the signed-in user.
    pub fn new(subject: &str, refresh_token: Zeroizing<String>) -> Self {
        Self {
            subject: subject.to_owned(),
            refresh_token,
        }
    }
    pub fn subject(&self) -> &str {
        &self.subject
    }
    pub fn refresh_token(&self) -> &str {
        &self.refresh_token
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Plaintext<'a> {
    sub: &'a str,
    refresh_token: &'a str,
}

/// Seals with the active key; opens with any configured key. Deliberately not Debug.
pub struct UpstreamCipher {
    active: String,
    keys: Vec<(String, LessSafeKey)>,
    random: SystemRandom,
}

/// Shape of a sealed grant read from storage, checked without opening it: the `v1.`
/// prefix and at most [`MAX_SEALED_BYTES`] of printable ASCII without spaces.
/// Valid: `v1.k1.AAAA`. Invalid: `v2.k1.AAAA`, `v1.k1.A A`, an empty string.
pub fn well_formed(sealed: &str) -> bool {
    sealed.len() <= MAX_SEALED_BYTES
        && sealed
            .strip_prefix(FORMAT)
            .is_some_and(|rest| rest.starts_with('.'))
        && sealed.bytes().all(|byte| byte.is_ascii_graphic())
}

/// Exactly 32 bytes in standard Base64 with padding.
/// Valid: the 44 characters `openssl rand -base64 32` writes. Invalid: the same without
/// `=` padding, 64 hex digits, or a 16-byte key.
fn decode_key(text: &str) -> Option<Zeroizing<[u8; 32]>> {
    let bytes = Zeroizing::new(STANDARD.decode(text).ok()?);
    let mut key = Zeroizing::new([0u8; 32]);
    (bytes.len() == 32).then(|| {
        key.copy_from_slice(&bytes);
        key
    })
}

/// Length-prefixed fields, so `("ab", "c")` and `("a", "bc")` differ.
fn associated_data(kid: &str, binding: &UpstreamBinding<'_>) -> Vec<u8> {
    let mut aad = Vec::new();
    for field in [
        "authotron-upstream-v1",
        kid,
        binding.method,
        binding.issuer,
        binding.client_id,
        binding.realm,
        binding.username,
    ] {
        aad.extend_from_slice(&(field.len() as u64).to_be_bytes());
        aad.extend_from_slice(field.as_bytes());
    }
    aad
}

impl UpstreamCipher {
    /// Reads every configured key file; errors name the key id, never the content.
    pub fn load(config: &UpstreamTokenEncryptionConfig) -> Result<Self, String> {
        config.validate().map_err(str::to_owned)?;
        let keys = config
            .keys
            .iter()
            .map(|key| {
                read_secret_text(&key.key_file, KEY_FILE_BYTES)
                    .and_then(|text| decode_key(&text))
                    .map(|bytes| (key.kid.clone(), bytes))
                    .ok_or_else(|| {
                        format!(
                            "upstream token key {}: key_file is unreadable or not 32 bytes of standard Base64",
                            key.kid
                        )
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Self::from_keys(&config.active_kid, keys)
    }

    pub fn from_keys(
        active_kid: &str,
        keys: Vec<(String, Zeroizing<[u8; 32]>)>,
    ) -> Result<Self, String> {
        let keys = keys
            .into_iter()
            .map(|(kid, bytes)| {
                UnboundKey::new(&AES_256_GCM, bytes.as_slice())
                    .map(|key| (kid, LessSafeKey::new(key)))
                    .map_err(|_| "invalid upstream token key".to_owned())
            })
            .collect::<Result<Vec<_>, _>>()?;
        if !keys.iter().any(|(kid, _)| kid == active_kid) {
            return Err("upstream token active_kid has no key".into());
        }
        Ok(Self {
            active: active_kid.to_owned(),
            keys,
            random: SystemRandom::new(),
        })
    }

    fn key(&self, kid: &str) -> Option<&LessSafeKey> {
        self.keys
            .iter()
            .find(|(candidate, _)| candidate == kid)
            .map(|(_, key)| key)
    }

    /// `v1.<kid>.<base64url(nonce ‖ ciphertext ‖ tag)>` under the active key.
    pub fn seal(
        &self,
        binding: &UpstreamBinding<'_>,
        grant: &UpstreamGrant,
    ) -> Result<String, UpstreamError> {
        let key = self.key(&self.active).ok_or(UpstreamError::Seal)?;
        let mut nonce = [0u8; NONCE_LEN];
        self.random
            .fill(&mut nonce)
            .map_err(|_| UpstreamError::Seal)?;
        let mut data = Zeroizing::new(
            serde_json::to_vec(&Plaintext {
                sub: &grant.subject,
                refresh_token: &grant.refresh_token,
            })
            .map_err(|_| UpstreamError::Seal)?,
        );
        key.seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(associated_data(&self.active, binding)),
            &mut *data,
        )
        .map_err(|_| UpstreamError::Seal)?;
        let mut sealed = nonce.to_vec();
        sealed.extend_from_slice(&data);
        let text = format!(
            "{FORMAT}.{}.{}",
            self.active,
            URL_SAFE_NO_PAD.encode(sealed)
        );
        (text.len() <= MAX_SEALED_BYTES)
            .then_some(text)
            .ok_or(UpstreamError::Seal)
    }

    /// Opens a token sealed by [`Self::seal`] under any configured key.
    /// Valid: `v1.upstream.1.<base64url>` (key id `upstream.1`). Invalid: `v2.k.<…>`,
    /// a missing key id, padded or non-canonical Base64, or more than 12 KiB.
    pub fn open(
        &self,
        binding: &UpstreamBinding<'_>,
        sealed: &str,
    ) -> Result<UpstreamGrant, UpstreamError> {
        let error = UpstreamError::Open;
        if sealed.len() > MAX_SEALED_BYTES {
            return Err(error);
        }
        let (head, payload) = sealed.rsplit_once('.').ok_or(error)?;
        let kid = head
            .strip_prefix(FORMAT)
            .and_then(|rest| rest.strip_prefix('.'))
            .filter(|kid| !kid.is_empty())
            .ok_or(error)?;
        let key = self.key(kid).ok_or(error)?;
        let bytes = URL_SAFE_NO_PAD.decode(payload).map_err(|_| error)?;
        if bytes.len() <= NONCE_LEN || URL_SAFE_NO_PAD.encode(&bytes) != payload {
            return Err(error);
        }
        let (nonce, ciphertext) = bytes.split_at(NONCE_LEN);
        let nonce = Nonce::try_assume_unique_for_key(nonce).map_err(|_| error)?;
        let mut data = Zeroizing::new(ciphertext.to_vec());
        let plaintext = key
            .open_in_place(
                nonce,
                Aad::from(associated_data(kid, binding)),
                data.as_mut_slice(),
            )
            .map_err(|_| error)?;
        let parsed: Plaintext<'_> = serde_json::from_slice(plaintext).map_err(|_| error)?;
        Ok(UpstreamGrant::new(
            parsed.sub,
            Zeroizing::new(parsed.refresh_token.to_owned()),
        ))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::Write;

    pub(crate) fn cipher(active: &str, kids: &[&str]) -> UpstreamCipher {
        let keys = kids
            .iter()
            .enumerate()
            .map(|(index, kid)| (kid.to_string(), Zeroizing::new([index as u8 + 1; 32])))
            .collect();
        UpstreamCipher::from_keys(active, keys).unwrap()
    }
    fn binding() -> UpstreamBinding<'static> {
        UpstreamBinding {
            method: "demo-sso",
            issuer: "https://idp.example.org/realms/demo",
            client_id: "claude-code",
            realm: "idp",
            username: "0f1d4c2e-0000-4000-8000-000000000001",
        }
    }
    fn grant() -> UpstreamGrant {
        UpstreamGrant::new("subject-1", Zeroizing::new("offline.token.value".into()))
    }

    #[test]
    fn sealed_tokens_open_only_with_their_binding_and_key() {
        let cipher = cipher("k1", &["k1"]);
        let sealed = cipher.seal(&binding(), &grant()).unwrap();
        assert!(sealed.starts_with("v1.k1.") && well_formed(&sealed));
        for invalid in ["", "v1", "v2.k1.AAAA", "v1.k1.A A", "v1.k1.\u{e9}"] {
            assert!(!well_formed(invalid), "{invalid}");
        }
        assert!(!well_formed(&format!(
            "v1.{}",
            "A".repeat(MAX_SEALED_BYTES)
        )));
        assert!(!sealed.contains("offline.token.value"));
        assert_ne!(sealed, cipher.seal(&binding(), &grant()).unwrap());
        let opened = cipher.open(&binding(), &sealed).unwrap();
        assert_eq!(
            (opened.subject(), opened.refresh_token()),
            ("subject-1", "offline.token.value")
        );
        let fields: [fn(&mut UpstreamBinding<'static>); 5] = [
            |b| b.method = "other",
            |b| b.issuer = "https://idp.example.org/realms/other",
            |b| b.client_id = "codex",
            |b| b.realm = "local",
            |b| b.username = "alice",
        ];
        for change in fields {
            let mut other = binding();
            change(&mut other);
            assert_eq!(
                cipher.open(&other, &sealed).err(),
                Some(UpstreamError::Open)
            );
        }
        let (head, payload) = sealed.rsplit_once('.').unwrap();
        let mut bytes = URL_SAFE_NO_PAD.decode(payload).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        let tampered = format!("{head}.{}", URL_SAFE_NO_PAD.encode(bytes));
        for invalid in [
            tampered,
            sealed.replacen("v1.", "v2.", 1),
            format!("v1..{payload}"),
            format!("v1.k2.{payload}"),
            format!("{sealed}="),
            format!("v1.k1.{}", URL_SAFE_NO_PAD.encode([0u8; NONCE_LEN])),
            "v1.k1".into(),
            "x".repeat(MAX_SEALED_BYTES + 1),
        ] {
            assert_eq!(
                cipher.open(&binding(), &invalid).err(),
                Some(UpstreamError::Open),
                "{invalid}"
            );
        }
    }

    #[test]
    fn rotation_seals_with_the_active_key_and_opens_with_older_ones() {
        let old = cipher("upstream.1", &["upstream.1"]);
        let sealed = old.seal(&binding(), &grant()).unwrap();
        let rotated = cipher("upstream.2", &["upstream.1", "upstream.2"]);
        assert_eq!(
            rotated.open(&binding(), &sealed).unwrap().subject(),
            "subject-1"
        );
        assert!(
            rotated
                .seal(&binding(), &grant())
                .unwrap()
                .starts_with("v1.upstream.2.")
        );
        let removed = cipher("upstream.2", &["upstream.2"]);
        assert!(removed.open(&binding(), &sealed).is_err());
        let large = UpstreamGrant::new("s", Zeroizing::new("t".repeat(MAX_SEALED_BYTES)));
        assert_eq!(
            rotated.seal(&binding(), &large).err(),
            Some(UpstreamError::Seal)
        );
        assert!(UpstreamCipher::from_keys("missing", vec![]).is_err());
    }

    #[test]
    fn key_files_hold_32_bytes_of_padded_base64() {
        let valid = STANDARD.encode([7u8; 32]);
        assert_eq!(valid.len(), 44);
        assert!(decode_key(&valid).is_some());
        for invalid in [
            valid.trim_end_matches('=').to_owned(),
            "07".repeat(32),
            STANDARD.encode([7u8; 16]),
            STANDARD.encode([7u8; 33]),
        ] {
            assert!(decode_key(&invalid).is_none(), "{invalid}");
        }
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(file, "{valid}").unwrap();
        let config: UpstreamTokenEncryptionConfig = serde_json::from_value(serde_json::json!({
            "active_kid": "k1", "keys": [{"kid": "k1", "key_file": file.path()}]
        }))
        .unwrap();
        let loaded = UpstreamCipher::load(&config).unwrap();
        let sealed = loaded.seal(&binding(), &grant()).unwrap();
        assert!(loaded.open(&binding(), &sealed).is_ok());
        let mut short = tempfile::NamedTempFile::new().unwrap();
        writeln!(short, "{}", STANDARD.encode([7u8; 16])).unwrap();
        let mut config = config;
        config.keys[0].key_file = short.path().to_owned();
        let error = UpstreamCipher::load(&config).err().unwrap();
        assert!(error.contains("k1") && !error.contains(short.path().to_str().unwrap()));
    }
}

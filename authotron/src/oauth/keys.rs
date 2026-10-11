// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! Explicit, all-or-nothing loading of RS256 keys, separate from legacy HMAC JWTs.

use crate::config::OAuthSigningConfig;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, crypto};
use rsa::{
    RsaPrivateKey, RsaPublicKey,
    pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPrivateKey},
    pkcs8::{DecodePrivateKey, DecodePublicKey},
    traits::PublicKeyParts,
};
use serde::Serialize;
use std::path::Path;
use zeroize::Zeroizing;

const MAX_PEM: usize = 16 * 1024;
const PROBE: &[u8] = b"authotron RS256 key consistency check";

/// Fixed error classes never carry paths, PEM contents or underlying crypto errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyError {
    Configuration,
    File,
    TooLarge,
    InvalidPem,
    KeySize,
    KeyMismatch,
    Consistency,
}
impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Configuration => "invalid OAuth signing configuration",
            Self::File => "OAuth key requires a readable regular file on Unix",
            Self::TooLarge => "OAuth PEM exceeds 16 KiB",
            Self::InvalidPem => "invalid OAuth RSA PEM key",
            Self::KeySize => "OAuth RSA key must be 2048..4096 bits",
            Self::KeyMismatch => "OAuth private/public key pair does not match",
            Self::Consistency => "OAuth RS256 key consistency check failed",
        })
    }
}
impl std::error::Error for KeyError {}

#[derive(Clone, Serialize)]
pub struct PublicJwk {
    pub kty: &'static str,
    pub alg: &'static str,
    #[serde(rename = "use")]
    pub usage: &'static str,
    pub kid: String,
    pub n: String,
    pub e: String,
}
#[derive(Clone, Serialize)]
pub struct PublicJwks {
    pub keys: Vec<PublicJwk>,
}

/// Private state deliberately has no Debug/Serialize implementation or public signer API.
pub struct KeyManager {
    signing_config: OAuthSigningConfig,
    active_kid: String,
    encoding: EncodingKey,
    jwks: PublicJwks,
}

impl KeyManager {
    /// Loads once from trusted admin paths. No startup hook or automatic reload is installed.
    pub fn load(config: &OAuthSigningConfig) -> Result<Self, KeyError> {
        config.validate().map_err(|_| KeyError::Configuration)?;
        let mut keys = Vec::new();
        let mut active = None;
        for reference in &config.keys {
            let private = reference
                .private_key_file
                .as_deref()
                .map(|path| {
                    let bytes = read_pem(path)?;
                    let pem = std::str::from_utf8(&bytes).map_err(|_| KeyError::InvalidPem)?;
                    let key = RsaPrivateKey::from_pkcs8_pem(pem)
                        .or_else(|_| RsaPrivateKey::from_pkcs1_pem(pem))
                        .map_err(|_| KeyError::InvalidPem)?;
                    check_size(&key.to_public_key())?;
                    key.validate().map_err(|_| KeyError::InvalidPem)?;
                    Ok::<_, KeyError>(key)
                })
                .transpose()?;
            let public = reference
                .public_key_file
                .as_deref()
                .map(|path| {
                    let bytes = read_pem(path)?;
                    let pem = std::str::from_utf8(&bytes).map_err(|_| KeyError::InvalidPem)?;
                    RsaPublicKey::from_public_key_pem(pem)
                        .or_else(|_| RsaPublicKey::from_pkcs1_pem(pem))
                        .map_err(|_| KeyError::InvalidPem)
                })
                .transpose()?;
            let derived = private.as_ref().map(RsaPrivateKey::to_public_key);
            if let (Some(a), Some(b)) = (&derived, &public)
                && (a.n() != b.n() || a.e() != b.e())
            {
                return Err(KeyError::KeyMismatch);
            }
            let public = public.or(derived).ok_or(KeyError::Configuration)?;
            check_size(&public)?;
            if reference.kid == config.active_kid {
                let der = private
                    .as_ref()
                    .ok_or(KeyError::Configuration)?
                    .to_pkcs1_der()
                    .map_err(|_| KeyError::InvalidPem)?;
                active = Some(EncodingKey::from_rsa_der(der.as_bytes()));
            }
            keys.push(PublicJwk {
                kty: "RSA",
                alg: "RS256",
                usage: "sig",
                kid: reference.kid.clone(),
                n: URL_SAFE_NO_PAD.encode(public.n().to_bytes_be()),
                e: URL_SAFE_NO_PAD.encode(public.e().to_bytes_be()),
            });
        }
        let manager = Self {
            signing_config: config.clone(),
            active_kid: config.active_kid.clone(),
            encoding: active.ok_or(KeyError::Configuration)?,
            jwks: PublicJwks { keys },
        };
        let (kid, encoding) = manager.active_signer();
        let public = manager
            .jwks
            .keys
            .iter()
            .find(|key| key.kid == kid)
            .ok_or(KeyError::Consistency)?;
        let decoding = DecodingKey::from_rsa_components(&public.n, &public.e)
            .map_err(|_| KeyError::Consistency)?;
        let signature =
            crypto::sign(PROBE, encoding, Algorithm::RS256).map_err(|_| KeyError::Consistency)?;
        if !crypto::verify(&signature, PROBE, &decoding, Algorithm::RS256)
            .map_err(|_| KeyError::Consistency)?
        {
            return Err(KeyError::Consistency);
        }
        Ok(manager)
    }
    pub fn active_kid(&self) -> &str {
        &self.active_kid
    }
    pub fn jwks(&self) -> &PublicJwks {
        &self.jwks
    }
    pub(super) fn matches_config(&self, config: &OAuthSigningConfig) -> bool {
        self.signing_config == *config
    }
    /// Only sibling OAuth capabilities can borrow the validated signing key.
    pub(super) fn active_signer(&self) -> (&str, &EncodingKey) {
        (&self.active_kid, &self.encoding)
    }
}

fn check_size(key: &RsaPublicKey) -> Result<(), KeyError> {
    if (2048..=4096).contains(&key.n().bits()) {
        Ok(())
    } else {
        Err(KeyError::KeySize)
    }
}

#[cfg(unix)]
fn read_pem(path: &Path) -> Result<Zeroizing<Vec<u8>>, KeyError> {
    use std::{fs::OpenOptions, io::Read, os::unix::fs::OpenOptionsExt};
    // Follow projected Secret symlinks; O_NONBLOCK prevents a swapped-in FIFO from blocking.
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| KeyError::File)?;
    if !file.metadata().map_err(|_| KeyError::File)?.is_file() {
        return Err(KeyError::File);
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_PEM + 1));
    file.take((MAX_PEM + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| KeyError::File)?;
    if bytes.len() > MAX_PEM {
        return Err(KeyError::TooLarge);
    }
    Ok(bytes)
}
#[cfg(not(unix))]
fn read_pem(_: &Path) -> Result<Zeroizing<Vec<u8>>, KeyError> {
    Err(KeyError::File)
}

#[cfg(all(test, unix))]
pub(super) mod tests {
    use super::*;
    use rsa::{
        pkcs1::EncodeRsaPublicKey,
        pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding},
        rand_core::OsRng,
    };
    use std::{
        fs::OpenOptions,
        io::Write,
        os::unix::fs::{OpenOptionsExt, symlink},
        sync::OnceLock,
    };

    pub(in crate::oauth) fn keys() -> &'static [RsaPrivateKey; 3] {
        static KEYS: OnceLock<[RsaPrivateKey; 3]> = OnceLock::new();
        KEYS.get_or_init(|| {
            [2048, 2048, 1024].map(|bits| RsaPrivateKey::new(&mut OsRng, bits).unwrap())
        })
    }
    pub(in crate::oauth) fn break_signer(manager: &mut KeyManager) {
        manager.encoding = EncodingKey::from_rsa_der(b"invalid test signing key");
    }
    fn write(dir: &Path, name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let path = dir.join(name);
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap()
            .write_all(bytes)
            .unwrap();
        path
    }
    fn fixture(dir: &Path, pkcs1: bool) -> OAuthSigningConfig {
        let pem = if pkcs1 {
            keys()[0].to_pkcs1_pem(LineEnding::LF).unwrap()
        } else {
            keys()[0].to_pkcs8_pem(LineEnding::LF).unwrap()
        };
        let private = write(dir, "private.pem", pem.as_bytes());
        let public = if pkcs1 {
            keys()[1]
                .to_public_key()
                .to_pkcs1_pem(LineEnding::LF)
                .unwrap()
        } else {
            keys()[1]
                .to_public_key()
                .to_public_key_pem(LineEnding::LF)
                .unwrap()
        };
        let old = write(dir, "old.pem", public.as_bytes());
        serde_json::from_value(serde_json::json!({"active_kid": "active", "keys": [
            {"kid": "active", "private_key_file": private},
            {"kid": "old", "public_key_file": old}
        ]}))
        .unwrap()
    }
    #[test]
    fn pem_formats_rotation_symlinks_and_public_only_jwks() {
        for pkcs1 in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let mut config = fixture(dir.path(), pkcs1);
            let link = dir.path().join("projected.pem");
            symlink(config.keys[0].private_key_file.as_ref().unwrap(), &link).unwrap();
            config.keys[0].private_key_file = Some(link);
            let manager = KeyManager::load(&config).unwrap();
            assert_eq!(manager.active_kid(), "active");
            let value = serde_json::to_value(manager.jwks()).unwrap();
            assert_eq!(value.as_object().unwrap().len(), 1);
            for (index, key) in value["keys"].as_array().unwrap().iter().enumerate() {
                let mut names = key
                    .as_object()
                    .unwrap()
                    .keys()
                    .map(String::as_str)
                    .collect::<Vec<_>>();
                names.sort_unstable();
                assert_eq!(names, ["alg", "e", "kid", "kty", "n", "use"]);
                assert_eq!(key["alg"], "RS256");
                assert_eq!(key["use"], "sig");
                assert_eq!(key["kty"], "RSA");
                assert_eq!(
                    key["n"],
                    URL_SAFE_NO_PAD.encode(keys()[index].n().to_bytes_be())
                );
                assert!(!key["n"].as_str().unwrap().contains('='));
            }
            let (kid, encoding) = manager.active_signer();
            assert_eq!(kid, manager.jwks().keys[0].kid);
            let signature = crypto::sign(b"test-only proof", encoding, Algorithm::RS256).unwrap();
            for (index, public) in manager.jwks().keys.iter().enumerate() {
                let decoding = DecodingKey::from_rsa_components(&public.n, &public.e).unwrap();
                assert_eq!(
                    crypto::verify(&signature, b"test-only proof", &decoding, Algorithm::RS256)
                        .unwrap(),
                    index == 0
                );
            }
            let matching = keys()[0]
                .to_public_key()
                .to_public_key_pem(LineEnding::LF)
                .unwrap();
            config.keys[0].public_key_file =
                Some(write(dir.path(), "matching.pem", matching.as_bytes()));
            assert!(KeyManager::load(&config).is_ok());
            let inactive = keys()[1].to_pkcs8_pem(LineEnding::LF).unwrap();
            config.keys[1].private_key_file =
                Some(write(dir.path(), "inactive.pem", inactive.as_bytes()));
            config.keys[1].public_key_file = None;
            assert!(KeyManager::load(&config).is_ok());
            config.keys[0].public_key_file = Some(dir.path().join("old.pem"));
            assert!(matches!(
                KeyManager::load(&config),
                Err(KeyError::KeyMismatch)
            ));
        }
    }
    #[test]
    fn malformed_oversized_nonregular_and_small_keys_fail_without_leaking() {
        for bits in [2047, 2048, 4096, 4097] {
            let n = (rsa::BigUint::from(1u8) << (bits - 1)) + rsa::BigUint::from(1u8);
            let key = RsaPublicKey::new_with_max_size(n, 65537u32.into(), 4097).unwrap();
            assert_eq!(check_size(&key).is_ok(), (2048..=4096).contains(&bits));
        }
        let dir = tempfile::tempdir().unwrap();
        let mut config = fixture(dir.path(), false);
        let small = keys()[2].to_pkcs8_pem(LineEnding::LF).unwrap();
        let small = write(dir.path(), "small.pem", small.as_bytes());
        let bad = write(dir.path(), "secret-name.pem", b"sensitive malformed PEM");
        let big = write(dir.path(), "big.pem", &vec![b'x'; MAX_PEM + 1]);
        let boundary = write(dir.path(), "boundary.pem", &vec![b'x'; MAX_PEM]);
        let fifo = dir.path().join("fifo");
        let name = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        // The test owns this temporary pathname; no file descriptor is passed to libc.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        for (path, expected) in [
            (small, KeyError::KeySize),
            (bad, KeyError::InvalidPem),
            (big, KeyError::TooLarge),
            (boundary, KeyError::InvalidPem),
            (dir.path().to_owned(), KeyError::File),
            (fifo, KeyError::File),
            (dir.path().join("missing"), KeyError::File),
        ] {
            config.keys[0].private_key_file = Some(path);
            let error = KeyManager::load(&config).err().unwrap();
            assert_eq!(error, expected);
            assert!(!format!("{error} {error:?}").contains("secret-name"));
            assert!(!format!("{error} {error:?}").contains("sensitive"));
        }
        config.keys.push(config.keys[1].clone());
        assert!(matches!(
            KeyManager::load(&config),
            Err(KeyError::Configuration)
        ));
    }
}

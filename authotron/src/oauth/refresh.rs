// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! Opaque rotating refresh tokens, their family records and lifetime arithmetic.
//! Stores keep only SHA-256 token hashes; the plaintext token leaves only in a response.

use super::records::valid_time;
use crate::config::RefreshTokenPolicy;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::{
    aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey},
    hkdf,
};
use rsa::rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// A rotated token presented again within this window after its successor was issued
/// is rejected without revoking the family, tolerating concurrent or retried refreshes.
pub const REUSE_GRACE_MS: u64 = 30_000;
/// Rotated hashes a family keeps for reuse detection, newest first; older ones are
/// forgotten and, if replayed, are merely unknown (`invalid_grant`, family kept).
pub const MAX_ROTATED_HASHES: usize = 32;
pub(super) const MAX_REFRESH_GRANT_BYTES: usize = 32 * 1024;
/// HKDF salt separating successor keys from any other use of a token.
const SUCCESSOR_SALT: &[u8] = b"authotron-refresh-successor-v1";
/// A sealed successor: nonce, the 32 token bytes and the AES-GCM tag.
const SEALED_SUCCESSOR_BYTES: usize = NONCE_LEN + 32 + 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshStoreError {
    Unavailable,
    InvalidRecord,
}

/// 256 random bits, base64url without padding. Deliberately not Debug.
pub struct RefreshToken(String);
impl RefreshToken {
    pub fn generate() -> Result<Self, RefreshStoreError> {
        random_id().map(Self)
    }
    /// Valid: 43 canonical base64url characters such as `AAAA…AAA` (32 zero bytes).
    /// Invalid: padded `…=`, 42/44 characters, or non-canonical final characters.
    pub fn parse(value: &str) -> Option<Self> {
        if value.len() != 43 {
            return None;
        }
        let bytes = URL_SAFE_NO_PAD.decode(value).ok()?;
        (bytes.len() == 32 && URL_SAFE_NO_PAD.encode(&bytes) == value).then(|| Self(value.into()))
    }
    pub fn as_secret_str(&self) -> &str {
        &self.0
    }
    pub fn hash(&self) -> [u8; 32] {
        Sha256::digest(self.0.as_bytes()).into()
    }
    /// The key this token seals its successor in family `family_id` with: HKDF-SHA256
    /// of the token under a fixed salt, with the family id as info. The store keeps
    /// only token hashes, so only a holder of this token can derive it.
    fn successor_key(&self, family_id: &str) -> Result<LessSafeKey, RefreshStoreError> {
        let secret = hkdf::Salt::new(hkdf::HKDF_SHA256, SUCCESSOR_SALT).extract(self.0.as_bytes());
        let info = [family_id.as_bytes()];
        let okm = secret
            .expand(&info, &AES_256_GCM)
            .map_err(|_| RefreshStoreError::Unavailable)?;
        Ok(LessSafeKey::new(UnboundKey::from(okm)))
    }
    /// `next`, the token that replaces this one, sealed for the family record:
    /// base64url of a fresh nonce, the AES-256-GCM ciphertext of its 32 bytes and the
    /// tag, 80 characters.
    pub fn seal_successor(
        &self,
        family_id: &str,
        next: &RefreshToken,
    ) -> Result<String, RefreshStoreError> {
        let key = self.successor_key(family_id)?;
        let mut nonce = [0; NONCE_LEN];
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| RefreshStoreError::Unavailable)?;
        let mut data = Zeroizing::new(Vec::with_capacity(SEALED_SUCCESSOR_BYTES));
        URL_SAFE_NO_PAD
            .decode_vec(&next.0, &mut data)
            .map_err(|_| RefreshStoreError::Unavailable)?;
        key.seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::empty(),
            &mut *data,
        )
        .map_err(|_| RefreshStoreError::Unavailable)?;
        let mut sealed = nonce.to_vec();
        sealed.extend_from_slice(&data);
        Ok(URL_SAFE_NO_PAD.encode(sealed))
    }
    /// The successor that [`Self::seal_successor`] sealed with this token for
    /// `family_id`. Valid: the 80 base64url characters it returns. Invalid: another
    /// length, `=` padding, standard Base64 characters such as `+`, another family or
    /// token, or any altered character.
    pub fn open_successor(&self, family_id: &str, sealed: &str) -> Option<RefreshToken> {
        let bytes = URL_SAFE_NO_PAD.decode(sealed).ok()?;
        if bytes.len() != SEALED_SUCCESSOR_BYTES || URL_SAFE_NO_PAD.encode(&bytes) != sealed {
            return None;
        }
        let (nonce, ciphertext) = bytes.split_at(NONCE_LEN);
        let nonce = Nonce::try_assume_unique_for_key(nonce).ok()?;
        let mut data = Zeroizing::new(ciphertext.to_vec());
        let key = self.successor_key(family_id).ok()?;
        let token = key.open_in_place(nonce, Aad::empty(), &mut data).ok()?;
        Some(Self(URL_SAFE_NO_PAD.encode(token)))
    }
}

pub(super) fn random_id() -> Result<String, RefreshStoreError> {
    let mut random = [0; 32];
    OsRng
        .try_fill_bytes(&mut random)
        .map_err(|_| RefreshStoreError::Unavailable)?;
    Ok(URL_SAFE_NO_PAD.encode(random))
}

/// Authorization snapshot captured at login and re-evaluated on every refresh. Only the
/// provider roles of a coupled family change: each rotation stores those of its
/// upstream refresh, which the role map bounds (see the size test below).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefreshGrant {
    pub client_id: String,
    pub resource: String,
    pub scopes: Vec<String>,
    pub username: String,
    pub realm: String,
    pub provider_roles: Vec<String>,
    /// Browser method id of the login that started the family.
    pub method: String,
    /// The family holds a sealed upstream grant that each refresh renews at the
    /// provider. Serialized only when set, so uncoupled grants keep their encoding.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub upstream_coupled: bool,
}
impl RefreshGrant {
    pub(super) fn encode(&self) -> Result<Vec<u8>, RefreshStoreError> {
        let bytes = serde_json::to_vec(self).map_err(|_| RefreshStoreError::InvalidRecord)?;
        if bytes.len() > MAX_REFRESH_GRANT_BYTES {
            return Err(RefreshStoreError::InvalidRecord);
        }
        Ok(bytes)
    }
    pub(super) fn decode(bytes: &[u8]) -> Result<Self, RefreshStoreError> {
        if bytes.len() > MAX_REFRESH_GRANT_BYTES {
            return Err(RefreshStoreError::InvalidRecord);
        }
        serde_json::from_slice(bytes).map_err(|_| RefreshStoreError::InvalidRecord)
    }
    /// Length-prefixed digest so `("ab", "c")` and `("a", "bc")` index differently.
    pub(super) fn user_key(&self) -> String {
        let mut digest = Sha256::new();
        for value in [&self.realm, &self.username] {
            digest.update((value.len() as u64).to_be_bytes());
            digest.update(value.as_bytes());
        }
        URL_SAFE_NO_PAD.encode(digest.finalize())
    }
}

/// A family's live view, returned only for the current (latest) token.
#[derive(Debug)]
pub struct RefreshFamily {
    pub family_id: String,
    pub grant: RefreshGrant,
    pub created_at_ms: u64,
    pub absolute_expires_at_ms: u64,
    pub upstream: Option<UpstreamState>,
}

/// A coupled family's sealed upstream grant and its generation, which every stored
/// upstream rotation increments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamState {
    pub sealed: String,
    pub generation: u64,
}

/// Outcome of replacing a family's sealed upstream grant.
#[derive(Debug, PartialEq, Eq)]
pub enum UpstreamStored {
    Stored,
    /// The presented token or the generation is no longer current.
    Stale,
}

/// Classification of a presented refresh token.
#[derive(Debug)]
pub enum Presented {
    Current(Box<RefreshFamily>),
    /// The immediate predecessor within [`REUSE_GRACE_MS`]: rejected, family kept.
    Grace,
    /// Any other rotated token: the store has already revoked the family.
    Reused(Box<EndedFamily>),
    Missing,
}

/// A family that revocation, reuse detection or the per-user cap ended: its id and grant
/// for the audit log and, for a coupled family, the sealed upstream grant to revoke.
#[derive(Debug)]
pub struct EndedFamily {
    pub family_id: String,
    pub grant: RefreshGrant,
    pub sealed: Option<String>,
}

/// Outcome of revoking a presented token for its client (RFC 7009).
#[derive(Debug)]
pub enum Revocation {
    /// Unknown token, or a family of another client: nothing changed.
    NotFound,
    Revoked(Box<EndedFamily>),
}

/// A compare-and-swap of a family's current token from the presented one to `next`.
pub struct Rotation<'a> {
    pub next: [u8; 32],
    /// Becomes the family's grant: the same client, identity and method, with the
    /// provider roles this refresh started from.
    pub grant: &'a RefreshGrant,
    pub idle_ttl_seconds: u64,
    /// The current absolute expiry, which caps the new idle deadline.
    pub ceiling: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Rotated {
    Rotated,
    /// The presented token stopped being current since lookup (a concurrent refresh).
    Stale,
}

/// `now + ttl`, capped by `ceiling`; `None` on overflow or out-of-range time.
pub(super) fn deadline(now_ms: u64, ttl_seconds: u64, ceiling: Option<u64>) -> Option<u64> {
    let end = ttl_seconds
        .checked_mul(1000)
        .and_then(|ttl| now_ms.checked_add(ttl))
        .filter(|end| valid_time(*end))?;
    Some(ceiling.map_or(end, |ceiling| end.min(ceiling)))
}

/// Absolute and first idle expiry for a family created at `now_ms`.
pub(super) fn initial_expiry(now_ms: u64, policy: &RefreshTokenPolicy) -> Option<(u64, u64)> {
    let absolute = deadline(now_ms, policy.absolute_ttl_seconds, None)?;
    let idle = deadline(now_ms, policy.idle_ttl_seconds, Some(absolute))?;
    Some((absolute, idle))
}

/// Current policy also bounds older families: a shortened absolute lifetime applies at once.
pub(super) fn effective_absolute(
    created_at_ms: u64,
    stored_absolute_ms: u64,
    policy: &RefreshTokenPolicy,
) -> Option<u64> {
    deadline(
        created_at_ms,
        policy.absolute_ttl_seconds,
        Some(stored_absolute_ms),
    )
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    /// A rotation to `next` carrying `grant`, with a 600-second idle lifetime.
    pub(in crate::oauth) fn rotation(
        next: [u8; 32],
        grant: &RefreshGrant,
        ceiling: u64,
    ) -> Rotation<'_> {
        Rotation {
            next,
            grant,
            idle_ttl_seconds: 600,
            ceiling,
        }
    }

    pub(in crate::oauth) fn grant() -> RefreshGrant {
        RefreshGrant {
            client_id: "desktop".into(),
            resource: "https://mcp.example.org/mcp".into(),
            scopes: vec!["read".into()],
            username: "alice".into(),
            realm: "local".into(),
            provider_roles: vec!["reader".into()],
            method: "password".into(),
            upstream_coupled: false,
        }
    }

    #[test]
    fn tokens_are_canonical_256_bit_base64url() {
        let token = RefreshToken::generate().unwrap();
        assert_eq!(token.as_secret_str().len(), 43);
        assert!(RefreshToken::parse(token.as_secret_str()).is_some());
        assert_ne!(
            token.as_secret_str(),
            RefreshToken::generate().unwrap().as_secret_str()
        );
        let zero = "A".repeat(43);
        assert_eq!(
            RefreshToken::parse(&zero).unwrap().hash(),
            <[u8; 32]>::from(Sha256::digest(zero.as_bytes()))
        );
        for invalid in [
            String::new(),
            "A".repeat(42),
            "A".repeat(44),
            format!("{}=", "A".repeat(42)),
            format!("{}B", "A".repeat(42)),
            format!("{}+", "A".repeat(42)),
        ] {
            assert!(RefreshToken::parse(&invalid).is_none(), "{invalid}");
        }
    }

    #[test]
    fn successors_open_only_with_their_predecessor_and_family() {
        let previous = RefreshToken::generate().unwrap();
        let next = RefreshToken::generate().unwrap();
        let sealed = previous.seal_successor("family", &next).unwrap();
        assert_eq!(sealed.len(), 80);
        assert!(!sealed.contains(next.as_secret_str()));
        let opened = previous.open_successor("family", &sealed).unwrap();
        assert_eq!(opened.as_secret_str(), next.as_secret_str());
        // A fresh nonce each time; both open to the same token.
        let again = previous.seal_successor("family", &next).unwrap();
        assert_ne!(again, sealed);
        let reopened = previous.open_successor("family", &again).unwrap();
        assert_eq!(reopened.as_secret_str(), next.as_secret_str());
        let mut bytes = URL_SAFE_NO_PAD.decode(&sealed).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        let tampered = URL_SAFE_NO_PAD.encode(&bytes);
        assert!(previous.open_successor("familz", &sealed).is_none());
        assert!(next.open_successor("family", &sealed).is_none());
        for invalid in [
            tampered,
            format!("{sealed}="),
            sealed[..79].to_owned(),
            format!("{}+", &sealed[..79]),
            String::new(),
        ] {
            assert!(
                previous.open_successor("family", &invalid).is_none(),
                "{invalid}"
            );
        }
    }

    #[test]
    fn grant_codec_rejects_unknown_fields_and_user_key_is_unambiguous() {
        let grant = grant();
        assert_eq!(
            RefreshGrant::decode(&grant.encode().unwrap()),
            Ok(grant.clone())
        );
        let mut value = serde_json::to_value(&grant).unwrap();
        assert!(value.get("upstream_coupled").is_none());
        let coupled = RefreshGrant {
            upstream_coupled: true,
            ..grant.clone()
        };
        assert_eq!(
            RefreshGrant::decode(&coupled.encode().unwrap()),
            Ok(coupled)
        );
        value["roles"] = serde_json::json!(["admin"]);
        assert_eq!(
            RefreshGrant::decode(&serde_json::to_vec(&value).unwrap()),
            Err(RefreshStoreError::InvalidRecord)
        );
        let mut a = grant.clone();
        (a.realm, a.username) = ("ab".into(), "c".into());
        let mut b = grant;
        (b.realm, b.username) = ("a".into(), "bc".into());
        assert_ne!(a.user_key(), b.user_key());
    }

    /// The largest grant configuration allows: identifiers and resource at their
    /// bounds, every scope of a binding, and a coupled family's provider roles, which
    /// only an OIDC method's role map grants, all made of characters JSON escapes.
    #[test]
    fn the_largest_grant_a_refresh_can_store_fits() {
        use crate::config::oidc::{IDENTITY_TEXT_BYTES, MAX_ROLE_MAP};
        let text = |bytes: usize| "\"".repeat(bytes);
        let grant = RefreshGrant {
            client_id: "c".repeat(128),
            resource: format!("https://{}", "r".repeat(2040)),
            scopes: vec![text(64); 32],
            username: text(IDENTITY_TEXT_BYTES),
            realm: text(IDENTITY_TEXT_BYTES),
            provider_roles: vec![text(IDENTITY_TEXT_BYTES); MAX_ROLE_MAP],
            method: text(IDENTITY_TEXT_BYTES),
            upstream_coupled: true,
        };
        assert!(grant.encode().unwrap().len() < MAX_REFRESH_GRANT_BYTES);
    }

    #[test]
    fn lifetimes_cap_idle_by_absolute_and_reject_overflow() {
        let policy = RefreshTokenPolicy {
            enabled: true,
            idle_ttl_seconds: 300,
            absolute_ttl_seconds: 600,
            upstream_offline_access: false,
        };
        assert_eq!(initial_expiry(1_000, &policy), Some((601_000, 301_000)));
        assert_eq!(deadline(500_000, 300, Some(601_000)), Some(601_000));
        assert_eq!(initial_expiry(u64::MAX, &policy), None);
        assert_eq!(deadline(253402300799999, 1, None), None);
        assert_eq!(deadline(0, u64::MAX, None), None);
        let shorter = RefreshTokenPolicy {
            absolute_ttl_seconds: 300,
            ..policy.clone()
        };
        assert_eq!(effective_absolute(1_000, 601_000, &shorter), Some(301_000));
        let longer = RefreshTokenPolicy {
            absolute_ttl_seconds: 6000,
            ..policy
        };
        assert_eq!(effective_absolute(1_000, 601_000, &longer), Some(601_000));
    }
}

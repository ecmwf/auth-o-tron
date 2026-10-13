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
use rsa::rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A rotated token presented again within this window after its successor was issued
/// is rejected without revoking the family, tolerating concurrent or retried refreshes.
pub const REUSE_GRACE_MS: u64 = 30_000;
/// Rotated hashes a family keeps for reuse detection, newest first; older ones are
/// forgotten and, if replayed, are merely unknown (`invalid_grant`, family kept).
pub const MAX_ROTATED_HASHES: usize = 32;
pub(super) const MAX_REFRESH_GRANT_BYTES: usize = 32 * 1024;

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
}

pub(super) fn random_id() -> Result<String, RefreshStoreError> {
    let mut random = [0; 32];
    OsRng
        .try_fill_bytes(&mut random)
        .map_err(|_| RefreshStoreError::Unavailable)?;
    Ok(URL_SAFE_NO_PAD.encode(random))
}

/// Immutable authorization snapshot captured at login and re-evaluated on every refresh.
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
    Reused {
        client_id: String,
        ended: Option<Box<EndedUpstream>>,
    },
    Missing,
}

/// A coupled family that revocation, reuse detection or the per-user cap ended, with the
/// grant needed to open its sealed upstream grant for upstream revocation.
#[derive(Debug)]
pub struct EndedUpstream {
    pub grant: RefreshGrant,
    pub sealed: String,
}

/// Outcome of revoking a presented token for its client (RFC 7009).
#[derive(Debug)]
pub enum Revocation {
    /// Unknown token, or a family of another client: nothing changed.
    NotFound,
    Revoked(Option<EndedUpstream>),
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

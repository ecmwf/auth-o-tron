// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! Audit log lines of refresh-token families. Each names the client, login method,
//! realm and username, as `auth.request.authenticated` does, and a short non-reversible
//! family reference; never a token, code or sealed grant.

use super::{refresh::EndedFamily, runtime::OAuthRuntime};
use crate::{
    browser::BrowserLoginState,
    metrics::{Metrics, RefreshTokenEvent},
};
use sha2::{Digest, Sha256};
use std::fmt::Write;

/// Why a refresh-token family ended: the `reason` of `oauth.refresh_token.family_revoked`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FamilyEnd {
    /// The client revoked one of its tokens (RFC 7009).
    ClientRevoke,
    /// A rotated token was presented again.
    ReuseDetected,
    /// A newer sign-in of the same user exceeded the per-user family cap.
    PerUserCap,
    /// The client is no longer configured with refresh tokens.
    ClientDisabled,
    /// The login method is gone, or no longer an OIDC method for a coupled family.
    MethodRemoved,
    /// The family outlived its absolute lifetime, possibly shortened since sign-in.
    LifetimeExceeded,
    /// The provider no longer has the password account.
    AccountRemoved,
    /// The identity provider refused the upstream refresh (`invalid_grant`).
    UpstreamInvalidGrant,
    /// The sealed upstream grant is missing or cannot be opened.
    UpstreamUnusable,
    /// The refreshed identity no longer matches the family.
    IdentityChanged,
}

impl FamilyEnd {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::ClientRevoke => "client_revoke",
            Self::ReuseDetected => "reuse_detected",
            Self::PerUserCap => "per_user_cap",
            Self::ClientDisabled => "client_disabled",
            Self::MethodRemoved => "method_removed",
            Self::LifetimeExceeded => "lifetime_exceeded",
            Self::AccountRemoved => "account_removed",
            Self::UpstreamInvalidGrant => "upstream_invalid_grant",
            Self::UpstreamUnusable => "upstream_unusable",
            Self::IdentityChanged => "identity_changed",
        }
    }
    /// Possible token theft and upstream refusals are warnings; the other ends are
    /// ordinary lifecycle events.
    fn warns(self) -> bool {
        matches!(
            self,
            Self::ReuseDetected
                | Self::UpstreamInvalidGrant
                | Self::UpstreamUnusable
                | Self::IdentityChanged
        )
    }
}

/// The `family` of lines about an upstream grant that no family holds.
pub(crate) const NO_FAMILY: &str = "none";

/// Short reference to a family for correlating its log lines: the first 12 hex digits
/// of SHA-256 over the random family id, e.g. `3f2a9c0b71de`. The id cannot be
/// recovered from it.
pub(crate) fn family_ref(family_id: &str) -> String {
    Sha256::digest(family_id.as_bytes())[..6].iter().fold(
        String::with_capacity(12),
        |mut text, byte| {
            let _ = write!(text, "{byte:02x}");
            text
        },
    )
}

/// An `oauth` event naming the grant's client, method, realm and username and the
/// family reference `$family`; `$level` is a `tracing` macro such as `warn`.
macro_rules! family_event {
    ($level:ident, $grant:expr, $family:expr, $($fields:tt)*) => {
        tracing::$level!(
            event_domain = "oauth",
            client_id = %$grant.client_id,
            method = %$grant.method,
            realm = %$grant.realm,
            username = %$grant.username,
            family = %$family,
            $($fields)*
        )
    };
}
pub(super) use family_event;

impl OAuthRuntime {
    /// Logs and counts the end of each family and queues revocation of a coupled
    /// family's upstream grant.
    pub(super) fn families_ended(
        &self,
        ended: impl IntoIterator<Item = EndedFamily>,
        reason: FamilyEnd,
        browser: &BrowserLoginState,
        metrics: &Metrics,
    ) {
        for family in ended {
            let reference = family_ref(&family.family_id);
            let label = reason.label();
            if reason.warns() {
                family_event!(
                    warn,
                    family.grant,
                    reference,
                    event_name = "oauth.refresh_token.family_revoked",
                    reason = label,
                    "refresh token family revoked"
                );
            } else {
                family_event!(
                    info,
                    family.grant,
                    reference,
                    event_name = "oauth.refresh_token.family_revoked",
                    reason = label,
                    "refresh token family revoked"
                );
            }
            metrics.record_refresh_token(RefreshTokenEvent::FamilyRevoked);
            if let Some(sealed) = &family.sealed {
                self.revoke_sealed(&family.grant, sealed, &reference, browser, metrics);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reasons_have_distinct_labels_and_only_misuse_or_upstream_ends_warn() {
        use FamilyEnd::*;
        let all = [
            (ClientRevoke, "client_revoke", false),
            (ReuseDetected, "reuse_detected", true),
            (PerUserCap, "per_user_cap", false),
            (ClientDisabled, "client_disabled", false),
            (MethodRemoved, "method_removed", false),
            (LifetimeExceeded, "lifetime_exceeded", false),
            (AccountRemoved, "account_removed", false),
            (UpstreamInvalidGrant, "upstream_invalid_grant", true),
            (UpstreamUnusable, "upstream_unusable", true),
            (IdentityChanged, "identity_changed", true),
        ];
        for (reason, label, warns) in all {
            assert_eq!(
                (reason.label(), reason.warns()),
                (label, warns),
                "{reason:?}"
            );
        }
        let labels: std::collections::BTreeSet<_> = all.iter().map(|(r, ..)| r.label()).collect();
        assert_eq!(labels.len(), all.len());
    }

    #[test]
    fn family_references_are_short_stable_and_not_the_id() {
        let id = "aP3x-Qk9_family-id-from-random-bytes";
        let reference = family_ref(id);
        assert_eq!(reference.len(), 12);
        assert!(reference.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(reference, family_ref(id));
        assert_ne!(reference, family_ref("another-family"));
        assert!(!id.contains(&reference));
    }
}

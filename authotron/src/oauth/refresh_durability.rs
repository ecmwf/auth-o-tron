// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! Startup check that refresh-token state survives a backend restart; advisory only.
//!
//! Only the append-only file counts as durable. RDB snapshots are not inspected:
//! `CONFIG GET save` is commonly ACL-denied, and a snapshot loses every rotation since
//! the last save, so clients that rotated afterwards hold tokens a restore no longer knows.

/// Refresh-token store persistence as observed at startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Durability {
    /// In-process store; every refresh token is lost on restart.
    Memory,
    /// Valkey reports `aof_enabled:1`.
    AppendOnly,
    /// Valkey reports `aof_enabled:0`.
    NotPersisted,
    /// `INFO persistence` failed (for example ACL-denied) or lacked `aof_enabled`.
    Unverified,
}

/// Reads `aof_enabled` from an `INFO persistence` reply.
///
/// Valid: "# Persistence\r\naof_enabled:1\r\n" gives `AppendOnly`, "aof_enabled:0"
/// gives `NotPersisted`. Invalid: "aof_enabled:yes" or a reply without the field
/// gives `Unverified`.
pub(crate) fn from_info(info: &str) -> Durability {
    info.lines()
        .find_map(|line| line.trim_end_matches('\r').strip_prefix("aof_enabled:"))
        .map_or(Durability::Unverified, |value| match value {
            "1" => Durability::AppendOnly,
            "0" => Durability::NotPersisted,
            _ => Durability::Unverified,
        })
}

/// Logs one structured event; startup continues whatever the outcome.
pub(crate) fn report(durability: Durability) {
    match durability {
        Durability::AppendOnly => tracing::info!(
            event_name = "oauth.refresh_token.store_durable",
            backend = "valkey",
            "refresh-token store uses Valkey append-only persistence"
        ),
        Durability::NotPersisted => tracing::warn!(
            event_name = "oauth.refresh_token.store_not_durable",
            backend = "valkey",
            "refresh tokens are enabled but Valkey append-only persistence is off; \
             a Valkey restart ends every refresh-token sign-in"
        ),
        Durability::Memory => tracing::warn!(
            event_name = "oauth.refresh_token.store_not_durable",
            backend = "memory",
            "refresh tokens are enabled with the memory backend; \
             a restart ends every refresh-token sign-in"
        ),
        Durability::Unverified => tracing::warn!(
            event_name = "oauth.refresh_token.store_durability_unverified",
            backend = "valkey",
            "refresh tokens are enabled but Valkey persistence could not be verified \
             (INFO persistence failed or was denied); ensure append-only persistence"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn info_reply_maps_to_durability() {
        for (info, expected) in [
            (
                "# Persistence\r\nloading:0\r\naof_enabled:1\r\naof_rewrite_in_progress:0\r\n",
                Durability::AppendOnly,
            ),
            ("# Persistence\naof_enabled:0\n", Durability::NotPersisted),
            ("aof_enabled:yes\r\n", Durability::Unverified),
            ("aof_enabled:\r\n", Durability::Unverified),
            ("# Persistence\r\nloading:0\r\n", Durability::Unverified),
            ("", Durability::Unverified),
            ("x_aof_enabled:1\r\n", Durability::Unverified),
        ] {
            assert_eq!(from_info(info), expected, "{info:?}");
        }
    }
}

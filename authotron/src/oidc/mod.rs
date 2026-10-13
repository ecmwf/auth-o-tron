// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! OpenID Connect relying-party support for browser sign-in methods. These modules
//! talk to identity providers and validate their answers; they create no sessions,
//! consent records or authorization grants.

pub mod claims;
pub mod discovery;
pub mod flow;
pub mod http;
pub mod id_token;
pub mod jwks;
#[cfg(test)]
pub(crate) mod mock;

/// Bounded failure classes, safe for logs and metric labels; provider-supplied text is
/// never carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OidcError {
    /// Network failure, timeout or a server error at the provider.
    Unavailable,
    /// An answer outside the protocol: unexpected status, malformed or oversized body,
    /// or a destination that is not an allowed provider URL.
    InvalidResponse,
    /// The ID token's signature, key or claims failed validation.
    InvalidIdToken,
    /// Validated claims do not form an acceptable identity.
    InvalidIdentity,
}

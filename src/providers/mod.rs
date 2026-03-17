// (C) Copyright 2025- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! Credential validation backends (JWT, Basic auth, OIDC, API keys).

pub mod base;
pub mod ecmwf_token_generator_provider;
pub mod ecmwfapi_provider;
pub mod efasapi_provider;
pub mod jwt_provider;
pub mod openid_offline_provider;
pub mod plain_provider;

// Re-export from base so we can do "use crate::providers::*;"
pub use base::*;

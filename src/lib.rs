// (C) Copyright 2026- ECMWF and individual contributors.
//
// This software is licensed under the terms of the Apache Licence Version 2.0
// which can be obtained at http://www.apache.org/licenses/LICENSE-2.0.
// In applying this licence, ECMWF does not waive the privileges and immunities
// granted to it by virtue of its status as an intergovernmental organisation nor
// does it submit to any jurisdiction.

//! # Auth-O-Tron
//!
//! Authentication and authorization gateway for web APIs.
//!
//! Auth-O-Tron validates credentials from multiple providers simultaneously,
//! enriches users with roles and attributes via augmenters, and issues signed
//! JWTs. It is designed to work as an NGINX `auth_request` backend.

pub mod augmenters;
pub mod auth;
pub mod config;
pub mod metrics;
pub mod models;
pub mod providers;
pub mod routes;
pub mod startup;
pub mod state;
pub mod store;
pub mod utils;

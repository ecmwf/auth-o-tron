//! OAuth authorization-server runtime, initialized at startup only when OAuth is enabled.
//! HTTP routes enforce request parsing and browser-origin checks before domain transitions.

pub mod admin;
pub(crate) mod audit;
pub mod authentication;
pub mod authorization;
pub mod code_grant;
pub mod codes;
pub mod consent;
pub mod context;
#[cfg(all(test, unix))]
mod key_rotation_tests;
pub mod keys;
pub mod logins;
pub mod rate_limit;
pub mod records;
pub mod refresh;
mod refresh_durability;
pub mod refresh_grant;
pub mod refresh_store;
pub mod retry_key;
pub mod runtime;
pub mod store;
pub mod tokens;
pub mod upstream;
pub mod upstream_refresh;
pub mod valkey_refresh;
pub mod valkey_transactions;

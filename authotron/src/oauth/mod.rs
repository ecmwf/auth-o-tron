//! OAuth authorization-server runtime, initialized at startup only when OAuth is enabled.
//! HTTP routes enforce request parsing and browser-origin checks before domain transitions.

pub mod authentication;
pub mod authorization;
pub mod code_grant;
pub mod codes;
pub mod consent;
pub mod context;
pub mod keys;
pub mod records;
pub mod refresh;
pub mod refresh_grant;
pub mod refresh_store;
pub mod runtime;
pub mod store;
pub mod tokens;
pub mod valkey_refresh;
pub mod valkey_transactions;

//! Shared application state.
//!
//! Contains the state that is shared across all request handlers,
//! including configuration, authentication, and token storage.

use crate::auth::Auth;
use crate::config::ConfigV1;
use crate::store::Store;
use std::sync::Arc;

/// Application state shared across all HTTP handlers.
///
/// This state is cloned for each request handler and contains
/// references to the configuration, authentication system, and token store.
#[derive(Clone)]
pub struct AppState {
    /// Application configuration loaded at startup.
    pub config: Arc<ConfigV1>,
    /// Authentication system handling provider and augmenter chains.
    pub auth: Arc<Auth>,
    /// Token store for managing persistent authentication tokens.
    pub store: Arc<dyn Store>,
}

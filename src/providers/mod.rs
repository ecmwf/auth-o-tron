pub mod base;
pub mod ecmwf_token_generator_provider;
pub mod ecmwfapi_provider;
pub mod jwt_provider;
pub mod openid_offline_provider;
pub mod plain_provider;

// Re-export from base so we can do "use crate::providers::*;"
pub use base::*;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A token stored in a database for lookup/revocation.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Token {
    pub version: i32,
    pub token_string: String,
    /// A map from service -> scopes
    pub scopes: HashMap<String, Vec<String>>,
}

impl Token {
    /// Create a new Token with optional version.
    /// We automatically generate a new token_string (UUID).
    pub fn new(
        _suggested_token_str: String,
        scopes: HashMap<String, Vec<String>>,
        version: Option<i32>,
    ) -> Self {
        Token {
            version: version.unwrap_or(1),
            token_string: uuid::Uuid::new_v4().to_string(),
            scopes,
        }
    }
}

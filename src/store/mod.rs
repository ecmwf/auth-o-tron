pub mod base;
pub mod mongodb_store;
pub mod no_store;

// Re-export the primary Store items so code outside can do
// "use crate::store::{Store, create_store};"
pub use base::{Store, create_store};

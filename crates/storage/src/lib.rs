//! # rw-secstore-storage
//!
//! SQLite storage layer with strict permissions, schema migrations, and
//! integrity verification.
//!
//! ## Modules
//!
//! - [`connection`] — Per-command SQLite connection setup with secure
//!   defaults (WAL, foreign keys, 0o600 file mode)
//! - [`migrations`] — Schema migrations (additive only, transactional)
//! - [`permissions`] — File permission management (0o600 DB, 0o700 dirs)
//! - [`integrity`] — HMAC seal and per-row HMAC for tamper detection
//! - [`error`] — Storage-specific error types

#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![warn(missing_docs)]

pub mod connection;
pub mod error;
pub mod integrity;
pub mod migrations;
pub mod permissions;

pub use connection::open;
pub use error::{Result, StorageError};
pub use integrity::{compute_and_store_seal, verify_seal, SealHeader};
pub use migrations::{current_version, rollback_last, run_migrations, CURRENT_SCHEMA_VERSION};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lib_exports_resolve() {
        // Smoke test: ensure all exports are accessible
        let _open_fn: fn(&std::path::Path) -> Result<rusqlite::Connection> = open;
    }
}

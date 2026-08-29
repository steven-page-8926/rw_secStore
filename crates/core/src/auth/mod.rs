//! Authentication infrastructure.
//!
//! Provides master password input, OS keyring integration, backup codes,
//! rate limiting, password policy enforcement, password generation,
//! and master password file storage.

pub mod backup_codes;
pub mod generator;
pub mod password;
pub mod password_file;
pub mod policy;
pub mod rate_limit;

#[cfg(feature = "keyring")]
pub mod keyring;

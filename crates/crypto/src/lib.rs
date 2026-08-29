//! # rw-secstore-crypto
//!
//! Cryptographic primitives: password-based key derivation (Argon2id),
//! authenticated encryption (AES-256-GCM), key derivation (HKDF-SHA256),
//! and constant-time operations.
//!
//! ## Modules
//!
//! - [`argon2`] — Argon2id password-based key derivation
//! - [`aes_gcm`] — AES-256-GCM authenticated encryption
//! - [`hkdf`] — HKDF-SHA256 key derivation
//! - [`constant_time`] — Constant-time comparison operations
//! - [`random`] — Cryptographically-secure random number generation
//! - [`version`] — Crypto version header
//! - [`seal`] — Database HMAC seal
//! - [`verification_kek`] — Verification KEK for cheap master password check
//! - [`row_hmac`] — Per-row HMAC for tamper detection

#![deny(unsafe_code)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![warn(missing_docs)]

pub mod aes_gcm;
pub mod argon2;
pub mod constant_time;
pub mod error;
pub mod hkdf;
pub mod random;
pub mod row_hmac;
pub mod seal;
pub mod verification_kek;
pub mod version;

pub use error::{CryptoError, Result};
pub use version::{CURRENT_VERSION, EncryptedHeader, CRYPTO_VERSION};

/// Cryptographic version constant (re-exported for convenience).
pub const VERSION: u8 = CURRENT_VERSION;

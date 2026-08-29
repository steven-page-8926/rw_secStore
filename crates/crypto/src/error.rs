//! Error types for crypto operations.

use thiserror::Error;

/// Result type alias for crypto operations.
pub type Result<T> = std::result::Result<T, CryptoError>;

/// Errors that can occur during cryptographic operations.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// Invalid Argon2id parameters (below security minimum).
    #[error("Argon2id parameters below security minimum: {0}")]
    WeakArgon2Params(String),

    /// Key derivation failed.
    #[error("Key derivation failed: {0}")]
    KeyDerivation(String),

    /// Encryption failed.
    #[error("Encryption failed: {0}")]
    Encryption(String),

    /// Decryption failed (authentication tag mismatch or corrupted ciphertext).
    #[error("Decryption failed: {0}")]
    Decryption(String),

    /// HMAC verification failed.
    #[error("HMAC verification failed")]
    HmacMismatch,

    /// Invalid nonce (wrong length).
    #[error("Invalid nonce: expected 12 bytes, got {0}")]
    InvalidNonce(usize),

    /// Invalid key length.
    #[error("Invalid key length: expected {expected} bytes, got {actual}")]
    InvalidKeyLength {
        /// Expected length in bytes.
        expected: usize,
        /// Actual length in bytes.
        actual: usize,
    },

    /// OS RNG unavailable.
    #[error("OS CSPRNG unavailable")]
    RngUnavailable,

    /// Unsupported crypto version (forward-incompatibility).
    #[error("Unsupported crypto version: {0}")]
    UnsupportedVersion(u8),

    /// Constant-time comparison failed.
    #[error("Constant-time comparison failed")]
    ConstantTime,
}

//! Core domain errors.

use thiserror::Error;

/// Errors that can occur in the rw-secstore core domain.
#[derive(Debug, Error)]
pub enum CoreError {
    /// Cryptographic operation failed.
    #[error("Crypto error: {0}")]
    Crypto(#[from] rw_secstore_crypto::CryptoError),

    /// Storage layer error.
    #[error("Storage error: {0}")]
    Storage(#[from] rw_secstore_storage::StorageError),

    /// The requested resource has not been initialized.
    #[error("Not initialized: {0}")]
    NotInitialized(String),

    /// The resource has already been initialized.
    #[error("Already initialized: {0}")]
    AlreadyInitialized(String),

    /// The requested resource was not found.
    #[error("Not found: {0}")]
    NotFound(String),

    /// The provided input was invalid.
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Authentication failed.
    #[error("Authentication failed: {0}")]
    AuthFailed(String),

    /// Operation rate-limited; retry after the specified seconds.
    #[error("Rate limited: retry after {0} seconds")]
    RateLimited(u64),

    /// OS keyring operation failed.
    #[error("Keyring error: {0}")]
    Keyring(String),

    /// Password file operation failed.
    #[error("Password file error: {0}")]
    PasswordFile(String),

    /// Password does not meet policy requirements.
    #[error("Password policy violation: {0}")]
    PasswordPolicy(String),

    /// Configuration error.
    #[error("Configuration error: {0}")]
    Config(String),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON serialization/deserialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Internal error (should not normally occur).
    #[error("Internal: {0}")]
    Internal(String),
}

/// Result type for core operations.
pub type Result<T> = std::result::Result<T, CoreError>;

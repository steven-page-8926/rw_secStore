//! Core domain errors.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("Crypto error: {0}")]
    Crypto(#[from] rw_secstore_crypto::CryptoError),

    #[error("Storage error: {0}")]
    Storage(#[from] rw_secstore_storage::StorageError),

    #[error("Not initialized: {0}")]
    NotInitialized(String),

    #[error("Already initialized: {0}")]
    AlreadyInitialized(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Authentication failed: {0}")]
    AuthFailed(String),

    #[error("Rate limited: retry after {0} seconds")]
    RateLimited(u64),
}

pub type Result<T> = std::result::Result<T, CoreError>;

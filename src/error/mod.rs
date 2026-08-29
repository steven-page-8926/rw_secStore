//! Error types for rw_secstore

use thiserror::Error;

/// Result type alias
pub type Result<T> = std::result::Result<T, Error>;

/// Main error type
#[derive(Error, Debug)]
pub enum Error {
    #[error("Configuration error: {0}")]
    Config(#[from] config::ConfigError),

    #[error("Cryptographic error: {0}")]
    Crypto(#[from] crypto::CryptoError),

    #[error("Storage error: {0}")]
    Storage(#[from] storage::StorageError),

    #[error("API error: {0}")]
    Api(#[from] api::ApiError),

    #[error("Audit error: {0}")]
    Audit(#[from] audit::AuditError),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<Box<dyn std::error::Error + Send + Sync>> for Error {
    fn from(err: Box<dyn std::error::Error + Send + Sync>) -> Self {
        Error::Internal(err.to_string())
    }
}
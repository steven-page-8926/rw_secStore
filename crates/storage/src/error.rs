//! Error types for storage operations.

use thiserror::Error;

/// Result type alias for storage operations.
pub type Result<T> = std::result::Result<T, StorageError>;

/// Errors that can occur during storage operations.
#[derive(Debug, Error)]
pub enum StorageError {
    /// SQLite error.
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Migration error.
    #[error("Migration {version} failed: {message}")]
    Migration {
        /// The migration version that failed.
        version: i32,
        /// Error message.
        message: String,
    },

    /// Schema version mismatch.
    #[error("Schema version mismatch: expected {expected}, found {found}")]
    SchemaVersionMismatch {
        /// Expected version.
        expected: i32,
        /// Actual version found in DB.
        found: i32,
    },

    /// Permission denied.
    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    /// Database file does not exist.
    #[error("Database file does not exist: {0}")]
    DatabaseNotFound(String),

    /// Database is locked.
    #[error("Database is locked (another process is using it)")]
    DatabaseLocked,
}

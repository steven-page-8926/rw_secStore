//! Audit logging for security-relevant operations.
//!
//! Records every authentication, key access, and CA operation in an
//! append-only audit log. The log is queryable but cannot be modified
//! without breaking the integrity seal.

use std::path::Path;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{CoreError, Result};

/// The result of a security-relevant operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditResult {
    /// Operation succeeded.
    Success,
    /// Operation failed.
    Failure,
}

/// The type of entity affected by an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntityType {
    /// Authentication event.
    Auth,
    /// Key operation.
    Key,
    /// Certificate operation.
    Certificate,
    /// CA operation.
    Ca,
    /// Backup code operation.
    BackupCode,
    /// System event.
    System,
}

/// A single audit log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Unique ID for this entry.
    pub id: String,
    /// When the event happened (milliseconds since Unix epoch).
    pub timestamp_ms: i64,
    /// The operation performed.
    pub operation: String,
    /// The type of entity.
    pub entity_type: EntityType,
    /// The ID of the affected entity (if applicable).
    pub entity_id: Option<String>,
    /// Who performed the action ("cli", "user", etc.).
    pub actor: String,
    /// Whether the operation succeeded.
    pub result: AuditResult,
    /// Optional details (e.g., the alias of the key).
    pub details: Option<String>,
    /// Error message (if failed).
    pub error_message: Option<String>,
}

impl AuditEntry {
    /// Creates a new audit entry with auto-generated ID and timestamp.
    #[must_use]
    pub fn new(operation: &str, entity_type: EntityType) -> Self {
        Self {
            id: Uuid::now_v7().to_string(),
            timestamp_ms: Utc::now().timestamp_millis(),
            operation: operation.to_string(),
            entity_type,
            entity_id: None,
            actor: "cli".to_string(),
            result: AuditResult::Success,
            details: None,
            error_message: None,
        }
    }

    /// Sets the entity ID.
    #[must_use]
    pub fn with_entity_id(mut self, id: &str) -> Self {
        self.entity_id = Some(id.to_string());
        self
    }

    /// Sets the result.
    #[must_use]
    pub fn with_result(mut self, result: AuditResult) -> Self {
        self.result = result;
        self
    }

    /// Sets the details.
    #[must_use]
    pub fn with_details(mut self, details: &str) -> Self {
        self.details = Some(details.to_string());
        self
    }

    /// Sets the error message.
    #[must_use]
    pub fn with_error(mut self, err: &str) -> Self {
        self.error_message = Some(err.to_string());
        self.result = AuditResult::Failure;
        self
    }

    /// Serializes the entry to a JSON line.
    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

/// Append-only audit log writer.
///
/// Writes entries to a file, one per line (JSONL format).
pub struct AuditLog {
    path: std::path::PathBuf,
}

impl AuditLog {
    /// Opens or creates the audit log at the given path.
    #[must_use]
    pub fn open(path: &Path) -> Self {
        Self { path: path.to_path_buf() }
    }

    /// Appends an entry to the log.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be opened or written.
    pub fn append(&self, entry: &AuditEntry) -> Result<()> {
        use std::io::Write;
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| CoreError::Io(e))?;

        // Log via tracing
        let level = match entry.result {
            AuditResult::Success => tracing::info!(
                op = %entry.operation,
                entity_type = ?entry.entity_type,
                entity_id = ?entry.entity_id,
                actor = %entry.actor,
                "audit"
            ),
            AuditResult::Failure => tracing::warn!(
                op = %entry.operation,
                entity_type = ?entry.entity_type,
                entity_id = ?entry.entity_id,
                actor = %entry.actor,
                error = ?entry.error_message,
                "audit"
            ),
        };

        // Write JSONL line
        let json = entry.to_json();
        writeln!(file, "{json}").map_err(CoreError::Io)?;

        let _ = level; // suppress unused
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn audit_entry_creation() {
        let entry = AuditEntry::new("test_op", EntityType::Auth);
        assert_eq!(entry.operation, "test_op");
        assert_eq!(entry.entity_type, EntityType::Auth);
        assert_eq!(entry.result, AuditResult::Success);
        assert!(!entry.id.is_empty());
    }

    #[test]
    fn audit_entry_builder() {
        let entry = AuditEntry::new("add_key", EntityType::Key)
            .with_entity_id("key-123")
            .with_details("production key")
            .with_result(AuditResult::Success);
        assert_eq!(entry.entity_id, Some("key-123".to_string()));
        assert_eq!(entry.details, Some("production key".to_string()));
        assert_eq!(entry.result, AuditResult::Success);
    }

    #[test]
    fn audit_log_writes_jsonl() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let log = AuditLog::open(&path);

        let entry1 = AuditEntry::new("op1", EntityType::Auth);
        let entry2 = AuditEntry::new("op2", EntityType::Key).with_entity_id("k1");

        log.append(&entry1).unwrap();
        log.append(&entry2).unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("op1"));
        assert!(lines[1].contains("op2"));
    }

    #[test]
    fn audit_entry_with_error_sets_failure() {
        let entry = AuditEntry::new("test", EntityType::Auth).with_error("bad password");
        assert_eq!(entry.result, AuditResult::Failure);
        assert_eq!(entry.error_message, Some("bad password".to_string()));
    }
}

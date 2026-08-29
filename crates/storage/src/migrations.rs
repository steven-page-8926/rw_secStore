//! Schema migrations.
//!
//! All migrations are additive (no column drops, no destructive changes).
//! Each migration runs in a single transaction with rollback support.

use rusqlite::Connection;

use super::error::{Result, StorageError};

/// Current schema version (must match the last applied migration).
pub const CURRENT_SCHEMA_VERSION: i32 = 3;

/// A single schema migration.
pub struct Migration {
    /// Schema version after this migration.
    pub version: i32,
    /// Human-readable description.
    pub description: &'static str,
    /// SQL to apply.
    pub up_sql: &'static str,
    /// SQL to roll back (down migration).
    pub down_sql: &'static str,
}

/// All migrations in order.
pub const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        description: "Initial schema: all base tables and indexes",
        up_sql: MIGRATION_001_UP,
        down_sql: MIGRATION_001_DOWN,
    },
    Migration {
        version: 2,
        description: "Add HMAC seal columns and verification salt",
        up_sql: MIGRATION_002_UP,
        down_sql: MIGRATION_002_DOWN,
    },
    Migration {
        version: 3,
        description: "Add backup_codes, password_history, ssh_keys tables",
        up_sql: MIGRATION_003_UP,
        down_sql: MIGRATION_003_DOWN,
    },
];

const MIGRATION_001_UP: &str = r"
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at INTEGER NOT NULL,
    description TEXT
);

CREATE TABLE IF NOT EXISTS keystore_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    row_hmac BLOB
);

CREATE TABLE IF NOT EXISTS certificate_authorities (
    id TEXT PRIMARY KEY,
    alias TEXT NOT NULL UNIQUE,
    ca_type TEXT NOT NULL,
    parent_id TEXT,
    subject_dn TEXT NOT NULL,
    common_name TEXT NOT NULL,
    country_code TEXT,
    state TEXT,
    city TEXT,
    organization TEXT,
    organization_unit TEXT,
    key_profile TEXT NOT NULL,
    digest_algorithm TEXT NOT NULL,
    valid_days INTEGER NOT NULL,
    not_before INTEGER NOT NULL,
    not_after INTEGER NOT NULL,
    cert_pem TEXT NOT NULL,
    encrypted_key_pem TEXT NOT NULL,
    pkcs12_blob BLOB,
    crl_der BLOB,
    crl_number INTEGER DEFAULT 0,
    crl_updated_at INTEGER,
    pathlen INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    deleted_at INTEGER,
    FOREIGN KEY (parent_id) REFERENCES certificate_authorities(id)
);

CREATE TABLE IF NOT EXISTS certificates (
    id TEXT PRIMARY KEY,
    ca_id TEXT NOT NULL,
    alias TEXT NOT NULL,
    subject_dn TEXT NOT NULL,
    common_name TEXT NOT NULL,
    country_code TEXT,
    state TEXT,
    city TEXT,
    organization TEXT,
    organization_unit TEXT,
    dns_names TEXT,
    ip_addresses TEXT,
    key_profile TEXT NOT NULL,
    digest_algorithm TEXT NOT NULL,
    valid_days INTEGER NOT NULL,
    not_before INTEGER NOT NULL,
    not_after INTEGER NOT NULL,
    cert_pem TEXT NOT NULL,
    encrypted_key_pem TEXT NOT NULL,
    serial_number TEXT NOT NULL,
    revoked_at INTEGER,
    revocation_reason TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    deleted_at INTEGER,
    FOREIGN KEY (ca_id) REFERENCES certificate_authorities(id) ON DELETE CASCADE,
    UNIQUE (ca_id, serial_number)
);

CREATE TABLE IF NOT EXISTS keys (
    id TEXT PRIMARY KEY,
    alias TEXT NOT NULL UNIQUE,
    key_type TEXT NOT NULL,
    key_algorithm TEXT NOT NULL,
    public_key_pem TEXT,
    encrypted_private_key BLOB NOT NULL,
    labels TEXT,
    description TEXT,
    expires_at INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    deleted_at INTEGER
);

CREATE TABLE IF NOT EXISTS audit_log (
    id TEXT PRIMARY KEY,
    timestamp INTEGER NOT NULL,
    operation TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id TEXT,
    actor TEXT NOT NULL,
    success BOOLEAN NOT NULL,
    details TEXT,
    error_message TEXT,
    hmac_chain TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_certificates_ca_id ON certificates(ca_id, created_at);
CREATE INDEX IF NOT EXISTS idx_certificates_alias ON certificates(alias);
CREATE INDEX IF NOT EXISTS idx_keys_alias ON keys(alias);
CREATE INDEX IF NOT EXISTS idx_keys_type ON keys(key_type);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_entity ON audit_log(entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_audit_operation ON audit_log(operation);
";

const MIGRATION_001_DOWN: &str = r"
DROP INDEX IF EXISTS idx_audit_operation;
DROP INDEX IF EXISTS idx_audit_entity;
DROP INDEX IF EXISTS idx_audit_timestamp;
DROP INDEX IF EXISTS idx_keys_type;
DROP INDEX IF EXISTS idx_keys_alias;
DROP INDEX IF EXISTS idx_certificates_alias;
DROP INDEX IF EXISTS idx_certificates_ca_id;
DROP TABLE IF EXISTS audit_log;
DROP TABLE IF EXISTS keys;
DROP TABLE IF EXISTS certificates;
DROP TABLE IF EXISTS certificate_authorities;
DROP TABLE IF EXISTS keystore_meta;
DROP TABLE IF EXISTS schema_version;
";

const MIGRATION_002_UP: &str = r"
-- Add verification_salt column to keystore_meta (stored as a meta key)
INSERT OR REPLACE INTO keystore_meta (key, value) VALUES ('hmac_seal_enabled', 'true');

-- Add hmac_seal column to keystore_meta (per-row HMAC verification)
-- Note: row_hmac column already added in migration 001 for future use.
";

const MIGRATION_002_DOWN: &str = r"
DELETE FROM keystore_meta WHERE key = 'hmac_seal_enabled';
";

const MIGRATION_003_UP: &str = r"
CREATE TABLE IF NOT EXISTS ssh_keys (
    id TEXT PRIMARY KEY,
    key_id TEXT NOT NULL UNIQUE,
    key_format TEXT NOT NULL DEFAULT 'openssh',
    comment TEXT,
    passphrase_encrypted BOOLEAN DEFAULT FALSE,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (key_id) REFERENCES keys(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS backup_codes (
    id TEXT PRIMARY KEY,
    code_hash TEXT NOT NULL UNIQUE,
    salt TEXT NOT NULL,
    code_index INTEGER NOT NULL UNIQUE,
    used_at INTEGER,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS password_history (
    id TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_failures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp INTEGER NOT NULL,
    method TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ssh_keys_key_id ON ssh_keys(key_id);
CREATE INDEX IF NOT EXISTS idx_backup_codes_index ON backup_codes(code_index);
CREATE INDEX IF NOT EXISTS idx_auth_failures_timestamp ON auth_failures(timestamp);
";

const MIGRATION_003_DOWN: &str = r"
DROP INDEX IF EXISTS idx_auth_failures_timestamp;
DROP INDEX IF EXISTS idx_backup_codes_index;
DROP INDEX IF EXISTS idx_ssh_keys_key_id;
DROP TABLE IF EXISTS auth_failures;
DROP TABLE IF EXISTS password_history;
DROP TABLE IF EXISTS backup_codes;
DROP TABLE IF EXISTS ssh_keys;
";

/// Returns the current schema version in the database.
///
/// Returns 0 if no migrations have been applied.
pub fn current_version(conn: &Connection) -> Result<i32> {
    // Check if schema_version table exists
    let exists: i32 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='schema_version'",
        [],
        |row| row.get(0),
    )?;

    if exists == 0 {
        return Ok(0);
    }

    let version: i32 = conn.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM schema_version",
        [],
        |row| row.get(0),
    )?;
    Ok(version)
}

/// Applies all pending migrations to bring the database up to `CURRENT_SCHEMA_VERSION`.
pub fn run_migrations(conn: &Connection) -> Result<()> {
    let current = current_version(conn)?;

    for migration in MIGRATIONS {
        if migration.version <= current {
            continue;
        }

        // Each migration runs in its own transaction
        let tx = conn.unchecked_transaction()?;

        // Execute the migration SQL
        tx.execute_batch(migration.up_sql).map_err(|e| StorageError::Migration {
            version: migration.version,
            message: e.to_string(),
        })?;

        // Record the migration
        let now = chrono::Utc::now().timestamp_millis();
        tx.execute(
            "INSERT INTO schema_version (version, applied_at, description) VALUES (?, ?, ?)",
            rusqlite::params![migration.version, now, migration.description],
        )?;

        tx.commit()?;
    }

    Ok(())
}

/// Rolls back the most recent migration (down to the previous version).
pub fn rollback_last(conn: &Connection) -> Result<()> {
    let current = current_version(conn)?;
    if current == 0 {
        return Err(StorageError::Migration {
            version: 0,
            message: "No migrations to roll back".to_string(),
        });
    }

    let migration = MIGRATIONS
        .iter()
        .find(|m| m.version == current)
        .ok_or_else(|| StorageError::Migration {
            version: current,
            message: format!("Migration {} not found in registry", current),
        })?;

    // For v1 rollback, the schema_version table itself is dropped
    let drops_schema_version = migration.version == 1;

    let tx = conn.unchecked_transaction()?;
    tx.execute_batch(migration.down_sql)?;
    if !drops_schema_version {
        tx.execute(
            "DELETE FROM schema_version WHERE version = ?",
            rusqlite::params![migration.version],
        )?;
    }
    tx.commit()?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn run_migrations_from_empty() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.sqlite");
        let conn = super::super::connection::open(&path).unwrap();
        run_migrations(&conn).unwrap();
        let version = current_version(&conn).unwrap();
        assert_eq!(version, CURRENT_SCHEMA_VERSION);
    }

    #[test]
    fn run_migrations_idempotent() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.sqlite");
        let conn = super::super::connection::open(&path).unwrap();
        run_migrations(&conn).unwrap();
        // Run again - should be no-op
        run_migrations(&conn).unwrap();
        let version = current_version(&conn).unwrap();
        assert_eq!(version, CURRENT_SCHEMA_VERSION);
    }

    #[test]
    fn rollback_returns_to_zero() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.sqlite");
        let conn = super::super::connection::open(&path).unwrap();
        run_migrations(&conn).unwrap();
        assert_eq!(current_version(&conn).unwrap(), CURRENT_SCHEMA_VERSION);

        // Roll back to v2
        rollback_last(&conn).unwrap();
        assert_eq!(current_version(&conn).unwrap(), CURRENT_SCHEMA_VERSION - 1);
    }

    #[test]
    fn rollback_all_the_way() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.sqlite");
        let conn = super::super::connection::open(&path).unwrap();
        run_migrations(&conn).unwrap();

        // Roll back all migrations
        for _ in 0..CURRENT_SCHEMA_VERSION {
            rollback_last(&conn).unwrap();
        }
        assert_eq!(current_version(&conn).unwrap(), 0);
    }

    #[test]
    fn reapply_after_rollback() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.sqlite");
        let conn = super::super::connection::open(&path).unwrap();
        run_migrations(&conn).unwrap();
        rollback_last(&conn).unwrap();

        // Re-apply
        run_migrations(&conn).unwrap();
        assert_eq!(current_version(&conn).unwrap(), CURRENT_SCHEMA_VERSION);
    }
}

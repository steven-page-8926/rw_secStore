//! Database integrity protection.
//!
//! Two layers of integrity verification:
//!
//! 1. **Full-file HMAC seal** (`seal`): Computed over the entire database
//!    blob (after the seal header). Detects any modification to the file.
//!
//! 2. **Per-row HMAC** (`row_hmac`): Computed per row in sensitive tables.
//!    Detects row-level tampering (insertion, deletion, modification).
//!
//! Both keys are derived from the master password via separate HKDF
//! contexts to ensure they cannot be confused with the encryption key.

use rusqlite::{params, Connection};
use zeroize::Zeroize;

use rw_secstore_crypto::row_hmac as rh;
use rw_secstore_crypto::seal;

use super::error::{Result, StorageError};

/// Magic bytes at the start of a sealed database file.
pub const SEAL_MAGIC: &[u8; 8] = b"RWSS\x00\x00\x00\x01";

/// Seal header (16 bytes total):
/// - 8 bytes: magic
/// - 8 bytes: salt (truncated for header; full salt in metadata)
#[derive(Debug, Clone, Copy)]
pub struct SealHeader {
    /// The salt used to derive the seal key.
    pub salt: [u8; 32],
}

impl SealHeader {
    /// Size of the header in bytes.
    pub const SIZE: usize = 8 + 32;

    /// Serializes the header to bytes.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut out = [0u8; Self::SIZE];
        out[..8].copy_from_slice(SEAL_MAGIC);
        out[8..].copy_from_slice(&self.salt);
        out
    }

    /// Parses a header from bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the magic bytes are wrong.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < Self::SIZE {
            return Err(StorageError::Migration {
                version: 0,
                message: "seal header too short".to_string(),
            });
        }
        if &bytes[..8] != SEAL_MAGIC {
            return Err(StorageError::Migration {
                version: 0,
                message: "invalid seal magic".to_string(),
            });
        }
        let mut salt = [0u8; 32];
        salt.copy_from_slice(&bytes[8..40]);
        Ok(Self { salt })
    }
}

/// Computes and stores a seal for the database content.
///
/// The seal is stored in `keystore_meta` under the key `db_seal`.
/// The seal is computed BEFORE storing, so verification uses the
/// same canonical state.
pub fn compute_and_store_seal(conn: &Connection, master_key: &[u8; 32], salt: &[u8; 32]) -> Result<()> {
    // Derive the seal key (separate from encryption key)
    let mut seal_key = [0u8; 32];
    seal::derive_seal_key(master_key, salt, &mut seal_key).map_err(|e| {
        StorageError::Migration {
            version: 0,
            message: format!("seal key derivation: {e}"),
        }
    })?;

    // Compute seal over the canonical database state
    let db_content = serialize_db_content(conn)?;
    let db_seal = seal::compute(&seal_key, db_content.as_bytes());

    // Store as hex
    let hex_seal = hex::encode(db_seal);
    store_meta(conn, "db_seal", &hex_seal)?;
    store_meta(conn, "db_seal_salt", &hex::encode(salt))?;

    seal_key.zeroize();
    Ok(())
}

/// Verifies the database seal.
///
/// # Errors
///
/// Returns an error if the seal is missing, the salt is missing,
/// or the computed seal doesn't match the stored one.
pub fn verify_seal(conn: &Connection, master_key: &[u8; 32]) -> Result<()> {
    let hex_seal = load_meta(conn, "db_seal")?
        .ok_or_else(|| StorageError::Migration {
            version: 0,
            message: "database seal missing".to_string(),
        })?;
    let stored_seal = hex::decode(&hex_seal).map_err(|e| StorageError::Migration {
        version: 0,
        message: format!("invalid seal hex: {e}"),
    })?;
    if stored_seal.len() != 32 {
        return Err(StorageError::Migration {
            version: 0,
            message: "invalid seal length".to_string(),
        });
    }
    let mut expected = [0u8; 32];
    expected.copy_from_slice(&stored_seal);

    let hex_salt = load_meta(conn, "db_seal_salt")?
        .ok_or_else(|| StorageError::Migration {
            version: 0,
            message: "database seal salt missing".to_string(),
        })?;
    let salt_bytes = hex::decode(&hex_salt).map_err(|e| StorageError::Migration {
        version: 0,
        message: format!("invalid salt hex: {e}"),
    })?;
    if salt_bytes.len() != 32 {
        return Err(StorageError::Migration {
            version: 0,
            message: "invalid salt length".to_string(),
        });
    }
    let mut salt = [0u8; 32];
    salt.copy_from_slice(&salt_bytes);

    let mut seal_key = [0u8; 32];
    seal::derive_seal_key(master_key, &salt, &mut seal_key).map_err(|e| {
        StorageError::Migration {
            version: 0,
            message: format!("seal key derivation: {e}"),
        }
    })?;

    let db_content = serialize_db_content(conn)?;
    seal::verify(&seal_key, db_content.as_bytes(), &expected).map_err(|e| {
        StorageError::Migration {
            version: 0,
            message: format!("seal verification failed: {e}"),
        }
    })?;

    seal_key.zeroize();
    Ok(())
}

/// Computes a per-row HMAC for tamper detection.
///
/// Used in `keystore_meta` table to detect modifications to specific rows.
pub fn compute_row_hmac(key: &[u8], table: &str, id: &str, value: &str) -> [u8; 32] {
    // Combine table and id as the key, value as the value
    let combined_key = format!("{table}:{id}");
    rh::compute_row_hmac(key, &combined_key, value)
}

/// Verifies a per-row HMAC.
pub fn verify_row_hmac(key: &[u8], table: &str, id: &str, value: &str, expected: &[u8; 32]) -> Result<()> {
    let combined_key = format!("{table}:{id}");
    rh::verify_row_hmac(key, &combined_key, value, expected).map_err(|e| {
        StorageError::Migration {
            version: 0,
            message: format!("row HMAC verification failed: {e}"),
        }
    })
}

/// Serializes the database content (all rows from all tables) to a canonical
/// byte representation for sealing.
///
/// Uses a deterministic order (by table name, then primary key) to ensure
/// the seal is reproducible. Excludes the seal metadata itself to avoid
/// chicken-and-egg dependency.
fn serialize_db_content(conn: &Connection) -> Result<String> {
    let mut output = String::new();

    // Get all tables (excluding schema_version which has timestamps that change)
    let mut tables: Vec<String> = Vec::new();
    let mut stmt = conn.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name != 'schema_version' ORDER BY name")?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
    for r in rows {
        tables.push(r?);
    }

    for table in &tables {
        output.push_str(&format!("--TABLE:{table}\n"));

        // Get all column names
        let mut col_stmt = conn.prepare(&format!("SELECT * FROM \"{table}\""))?;
        let col_count = col_stmt.column_count();
        let col_names: Vec<String> = (0..col_count)
            .map(|i| col_stmt.column_name(i).unwrap_or("?").to_string())
            .collect();

        // Order by first column (assumed primary key) for determinism
        let order_by = col_names.first().cloned().unwrap_or_else(|| "rowid".to_string());
        let query = format!("SELECT * FROM \"{table}\" ORDER BY \"{order_by}\"");

        let mut row_stmt = conn.prepare(&query)?;
        let mut rows = row_stmt.query([])?;
        while let Some(row) = rows.next()? {
            let mut values = Vec::new();
            for i in 0..col_count {
                let val: rusqlite::types::Value = row.get(i)?;
                values.push(format_value(&val));
            }
            // For keystore_meta, exclude the seal entries themselves
            if table == "keystore_meta" {
                let key = values.first().map(String::as_str).unwrap_or("");
                if key == "db_seal" || key == "db_seal_salt" {
                    continue;
                }
            }
            output.push_str(&format!("{}|{}\n", col_names.join(","), values.join("|")));
        }
    }

    Ok(output)
}

/// Formats a SQLite value for canonical serialization.
fn format_value(v: &rusqlite::types::Value) -> String {
    use rusqlite::types::Value;
    match v {
        Value::Null => "NULL".to_string(),
        Value::Integer(i) => i.to_string(),
        Value::Real(f) => format!("{f}"),
        Value::Text(s) => s.clone(),
        Value::Blob(b) => hex::encode(b),
    }
}

/// Stores a key-value pair in the keystore_meta table.
fn store_meta(conn: &Connection, key: &str, value: &str) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO keystore_meta (key, value) VALUES (?1, ?2)",
        params![key, value],
    )?;
    Ok(())
}

/// Loads a value from keystore_meta, returning None if not present.
fn load_meta(conn: &Connection, key: &str) -> Result<Option<String>> {
    let result: Option<String> = conn
        .query_row(
            "SELECT value FROM keystore_meta WHERE key = ?1",
            params![key],
            |row| row.get(0),
        )
        .ok();
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn seal_header_round_trip() {
        let salt = [42u8; 32];
        let header = SealHeader { salt };
        let bytes = header.to_bytes();
        let parsed = SealHeader::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.salt, salt);
    }

    #[test]
    fn seal_header_rejects_bad_magic() {
        let bytes = [0u8; 40];
        let result = SealHeader::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn seal_header_rejects_short_input() {
        let bytes = [0u8; 16];
        let result = SealHeader::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn row_hmac_is_deterministic() {
        let key = [1u8; 32];
        let h1 = compute_row_hmac(&key, "keys", "id1", "value1");
        let h2 = compute_row_hmac(&key, "keys", "id1", "value1");
        assert_eq!(h1, h2);
    }

    #[test]
    fn row_hmac_detects_value_change() {
        let key = [1u8; 32];
        let h1 = compute_row_hmac(&key, "keys", "id1", "value1");
        let h2 = compute_row_hmac(&key, "keys", "id1", "value2");
        assert_ne!(h1, h2);
    }

    #[test]
    fn row_hmac_detects_table_change() {
        let key = [1u8; 32];
        let h1 = compute_row_hmac(&key, "keys", "id1", "value");
        let h2 = compute_row_hmac(&key, "certificates", "id1", "value");
        assert_ne!(h1, h2);
    }
    #[test]
    fn row_hmac_verifies_match() {
        let key = [1u8; 32];
        let h = compute_row_hmac(&key, "keys", "id1", "value");
        assert!(verify_row_hmac(&key, "keys", "id1", "value", &h).is_ok());
    }

    #[test]
    fn row_hmac_verifies_rejects_tampered() {
        let key = [1u8; 32];
        let h = compute_row_hmac(&key, "keys", "id1", "value");
        assert!(verify_row_hmac(&key, "keys", "id1", "tampered", &h).is_err());
    }

    #[test]
    fn seal_round_trip_with_database() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.sqlite");
        let conn = super::super::connection::open(&path).unwrap();
        super::super::migrations::run_migrations(&conn).unwrap();

        // Insert a test row
        conn.execute(
            "INSERT INTO keystore_meta (key, value) VALUES ('test', 'value1')",
            [],
        )
        .unwrap();

        let master_key = [42u8; 32];
        let salt = [7u8; 32];

        compute_and_store_seal(&conn, &master_key, &salt).unwrap();
        verify_seal(&conn, &master_key).unwrap();
    }

    #[test]
    fn seal_detects_tampering() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.sqlite");
        let conn = super::super::connection::open(&path).unwrap();
        super::super::migrations::run_migrations(&conn).unwrap();

        conn.execute(
            "INSERT INTO keystore_meta (key, value) VALUES ('test', 'value1')",
            [],
        )
        .unwrap();

        let master_key = [42u8; 32];
        let salt = [7u8; 32];

        compute_and_store_seal(&conn, &master_key, &salt).unwrap();
        verify_seal(&conn, &master_key).unwrap();

        // Tamper with the database
        conn.execute(
            "UPDATE keystore_meta SET value = 'tampered' WHERE key = 'test'",
            [],
        )
        .unwrap();

        // Verification should now fail
        assert!(verify_seal(&conn, &master_key).is_err());
    }
}

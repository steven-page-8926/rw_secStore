//! Per-command SQLite connection.
//!
//! Each CLI invocation opens a fresh connection. No pooling (CLI is
//! short-lived, sequential by nature).

use std::path::Path;
use std::time::Duration;

use rusqlite::{Connection, OpenFlags};

use super::error::Result;
use super::permissions;

/// Opens a SQLite connection with the required flags and pragmas.
///
/// Sets WAL mode, foreign keys, busy timeout, and runs migrations.
pub fn open(path: &Path) -> Result<Connection> {
    // Ensure parent dir exists with 0o700
    permissions::set_db_dir_mode(path)?;

    // Open with create-if-missing
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
    )?;

    // Set pragmas via raw SQL (avoid trait method conflicts)
    // Note: Some pragmas return result rows, so we must use `query_row`
    // for them; others can use `execute`.
    let _: String = conn.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
    conn.execute("PRAGMA foreign_keys = ON", [])?;
    // Use the rusqlite method for busy_timeout
    conn.busy_timeout(Duration::from_millis(5000))?;
    // synchronous is a special pragma that does NOT return a result row
    conn.pragma_update(None, "synchronous", "1")?; // 1 = NORMAL
    conn.execute("PRAGMA temp_store = MEMORY", [])?;

    // Set file mode to 0o600. SQLite doesn't always create with
    // restrictive permissions, so we always set explicitly.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = std::fs::metadata(path) {
            let mut perms = metadata.permissions();
            perms.set_mode(0o600);
            let _ = std::fs::set_permissions(path, perms);
        }
    }

    Ok(conn)
}

/// Sets a SQLite pragma via raw SQL.
fn set_pragma(conn: &Connection, name: &str, value: &str) -> Result<()> {
    // PRAGMA queries don't accept parameters in all cases;
    // use string interpolation after validating the name
    let safe_name = name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_');
    if !safe_name {
        return Err(super::error::StorageError::Migration {
            version: 0,
            message: format!("invalid pragma name: {name}"),
        });
    }
    conn.execute(&format!("PRAGMA {name} = {value}"), [])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn open_creates_db_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.sqlite");
        let _conn = open(&path).unwrap();
        assert!(path.exists());
    }

    #[test]
    fn open_enables_wal_mode() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.sqlite");
        let conn = open(&path).unwrap();
        let mode: String = conn.query_row("PRAGMA journal_mode", [], |row| row.get(0)).unwrap();
        assert_eq!(mode.to_lowercase(), "wal");
    }

    #[test]
    fn open_enables_foreign_keys() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.sqlite");
        let conn = open(&path).unwrap();
        let fk: i64 = conn.query_row("PRAGMA foreign_keys", [], |row| row.get(0)).unwrap();
        assert_eq!(fk, 1);
    }

    #[cfg(unix)]
    #[test]
    fn open_creates_db_with_0o600_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.sqlite");
        let _conn = open(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}

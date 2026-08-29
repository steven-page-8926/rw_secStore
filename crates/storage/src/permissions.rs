//! File permission helpers.
//!
//! Ensures the database file has 0o600 permissions (owner read/write only)
//! and the parent directory has 0o700 permissions.

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use super::error::{Result, StorageError};

/// Required file mode for the database (owner read/write only).
pub const DB_FILE_MODE: u32 = 0o600;
/// Required directory mode for the database parent (owner rwx only).
pub const DB_DIR_MODE: u32 = 0o700;

/// Sets the file mode to 0o600 (owner read/write only).
///
/// On non-Unix platforms, this is a no-op.
pub fn set_db_file_mode(path: &std::path::Path) -> Result<()> {
    #[cfg(unix)]
    {
        let metadata = std::fs::metadata(path)?;
        let mut permissions = metadata.permissions();
        permissions.set_mode(DB_FILE_MODE);
        std::fs::set_permissions(path, permissions)?;
    }
    #[cfg(not(unix))]
    {
        let _ = path; // unused
    }
    Ok(())
}

/// Sets the parent directory mode to 0o700 (owner rwx only).
///
/// On non-Unix platforms, this is a no-op.
pub fn set_db_dir_mode(path: &std::path::Path) -> Result<()> {
    #[cfg(unix)]
    {
        if let Some(parent) = path.parent() {
            if parent.as_os_str().is_empty() {
                return Ok(());
            }
            std::fs::create_dir_all(parent)?;
            let metadata = std::fs::metadata(parent)?;
            let mut permissions = metadata.permissions();
            permissions.set_mode(DB_DIR_MODE);
            std::fs::set_permissions(parent, permissions)?;
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path; // unused
    }
    Ok(())
}

/// Verifies the file has the expected mode (returns error if more permissive).
pub fn verify_file_mode(path: &std::path::Path, expected_mode: u32) -> Result<()> {
    #[cfg(unix)]
    {
        let metadata = std::fs::metadata(path)?;
        let actual_mode = metadata.permissions().mode() & 0o777;
        // Reject if actual mode has ANY bits set that expected_mode doesn't have
        // (i.e., file is MORE permissive than expected)
        if actual_mode & !expected_mode != 0 {
            return Err(StorageError::PermissionDenied(format!(
                "file {} has mode {:o}, expected {:o}",
                path.display(),
                actual_mode,
                expected_mode
            )));
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, expected_mode); // unused
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[cfg(unix)]
    #[test]
    fn set_db_file_mode_creates_0o600() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("db.sqlite");
        std::fs::write(&path, b"test").unwrap();

        // Set a permissive mode first
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o644);
        std::fs::set_permissions(&path, perms).unwrap();

        set_db_file_mode(&path).unwrap();

        let actual = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(actual, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn verify_rejects_world_readable() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("db.sqlite");
        std::fs::write(&path, b"test").unwrap();

        // Set world-readable
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o644);
        std::fs::set_permissions(&path, perms).unwrap();

        let result = verify_file_mode(&path, 0o600);
        assert!(result.is_err());
    }
}

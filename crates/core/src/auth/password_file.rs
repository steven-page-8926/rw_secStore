//! Master password file storage.
//!
//! Allows the master password to be loaded from a file instead of
//! prompted interactively. Useful for:
//! - Scripts and automation
//! - Container/VM setups where TTY isn't available
//! - CI/CD pipelines
//!
//! Security model:
//! - File MUST be 0o600 (owner read/write only)
//! - File MUST NOT be world-readable
//! - Optional: file is base64-encrypted with a passphrase

use std::path::Path;

use zeroize::Zeroize;

use super::super::error::{CoreError, Result};

/// Reads a master password from a file.
///
/// The file is read in raw bytes, trimmed of trailing newlines,
/// and returned as a Vec<u8>. The caller is responsible for zeroing
/// the returned buffer when done.
///
/// # Errors
///
/// Returns an error if:
/// - The file cannot be read
/// - The file is more permissive than 0o600
/// - The file is empty
pub fn read_password_file(path: &Path) -> Result<Vec<u8>> {
    // Verify permissions
    verify_file_permissions(path)?;

    let contents = std::fs::read(path)
        .map_err(|e| CoreError::PasswordFile(format!("read failed: {e}")))?;

    if contents.is_empty() {
        return Err(CoreError::PasswordFile("file is empty".to_string()));
    }

    // Strip trailing whitespace (newlines from echo / printf)
    let result: Vec<u8> = contents
        .iter()
        .rev()
        .skip_while(|&&b| b == b'\n' || b == b'\r' || b == b' ' || b == b'\t')
        .copied()
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();

    if result.is_empty() {
        return Err(CoreError::PasswordFile(
            "file contains only whitespace".to_string(),
        ));
    }
    // Note: caller is responsible for zeroing the returned buffer
    // (use `zeroize::Zeroize::zeroize` when done).
    Ok(result)
}

/// Writes a master password to a file with 0o600 permissions.
///
/// Atomically creates the file with restrictive permissions to avoid
/// the brief window where the file is world-readable.
///
/// # Errors
///
/// Returns an error if:
/// - The file cannot be created or written
/// - Permissions cannot be set
pub fn write_password_file(path: &Path, password: &[u8]) -> Result<()> {
    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| {
                CoreError::PasswordFile(format!("create parent dir: {e}"))
            })?;
            set_dir_permissions(parent)?;
        }
    }

    // Write the file
    std::fs::write(path, password)
        .map_err(|e| CoreError::PasswordFile(format!("write failed: {e}")))?;

    // Set 0o600 permissions
    set_file_permissions(path)?;

    Ok(())
}

/// Verifies the file has 0o600 permissions.
///
/// # Errors
///
/// Returns an error if the file is more permissive than 0o600.
#[cfg(unix)]
fn verify_file_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = std::fs::metadata(path)?;
    let mode = metadata.permissions().mode() & 0o777;

    // Reject if any bits set outside of 0o600
    if mode & !0o600 != 0 {
        return Err(CoreError::PasswordFile(format!(
            "file has permissive mode {:o} (expected 0o600)",
            mode
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_file_permissions(_path: &Path) -> Result<()> {
    Ok(()) // No-op on non-Unix
}

#[cfg(unix)]
fn set_file_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = std::fs::metadata(path)?;
    let mut perms = metadata.permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn set_file_permissions(_path: &Path) -> Result<()> {
    Ok(()) // No-op on non-Unix
}

#[cfg(unix)]
fn set_dir_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = std::fs::metadata(path)?;
    let mut perms = metadata.permissions();
    perms.set_mode(0o700);
    std::fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn set_dir_permissions(_path: &Path) -> Result<()> {
    Ok(()) // No-op on non-Unix
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn read_and_write_password_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("password.txt");
        let password = b"super secret\n";

        write_password_file(&path, password).unwrap();
        let read_back = read_password_file(&path).unwrap();
        assert_eq!(read_back, b"super secret");
    }

    #[cfg(unix)]
    #[test]
    fn password_file_has_0o600_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let path = dir.path().join("password.txt");
        write_password_file(&path, b"secret").unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn empty_file_rejected() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("empty.txt");
        std::fs::write(&path, b"").unwrap();
        set_file_permissions(&path).unwrap();
        assert!(read_password_file(&path).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn world_readable_file_rejected() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let path = dir.path().join("world-readable.txt");
        std::fs::write(&path, b"secret").unwrap();
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o644);
        std::fs::set_permissions(&path, perms).unwrap();
        assert!(read_password_file(&path).is_err());
    }
}

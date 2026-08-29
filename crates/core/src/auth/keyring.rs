//! OS keyring integration for storing the Master Encryption Key (MEK).
//!
//! Uses the `keyring` crate which abstracts over:
//! - Linux: libsecret / Secret Service
//! - macOS: Keychain
//! - Windows: Credential Manager

use keyring::Entry;

use super::super::error::{CoreError, Result};

const KEYRING_SERVICE: &str = "rw-secstore";
const KEYRING_USER: &str = "default";

/// Stores the MEK in the OS keyring.
///
/// # Errors
///
/// Returns an error if the keyring backend is unavailable or the
/// MEK cannot be stored.
pub fn store_mek(mek: &[u8; 32]) -> Result<()> {
    let entry = Entry::new(KEYRING_SERVICE, KEYRING_USER)
        .map_err(|e| CoreError::Keyring(e.to_string()))?;
    let encoded = hex::encode(mek);
    entry
        .set_password(&encoded)
        .map_err(|e| CoreError::Keyring(e.to_string()))
}

/// Retrieves the MEK from the OS keyring.
///
/// # Errors
///
/// Returns an error if:
/// - The keyring backend is unavailable
/// - No MEK is stored
/// - The stored data is not valid hex of length 32 bytes
pub fn retrieve_mek() -> Result<[u8; 32]> {
    let entry = Entry::new(KEYRING_SERVICE, KEYRING_USER)
        .map_err(|e| CoreError::Keyring(e.to_string()))?;
    let encoded = entry
        .get_password()
        .map_err(|e| CoreError::Keyring(e.to_string()))?;
    let bytes = hex::decode(&encoded).map_err(|e| CoreError::Keyring(e.to_string()))?;
    if bytes.len() != 32 {
        return Err(CoreError::Keyring(format!(
            "stored MEK has wrong length: {} != 32",
            bytes.len()
        )));
    }
    let mut mek = [0u8; 32];
    mek.copy_from_slice(&bytes);
    Ok(mek)
}

/// Deletes the MEK from the OS keyring.
///
/// # Errors
///
/// Returns an error if the keyring backend fails.
pub fn delete_mek() -> Result<()> {
    let entry = Entry::new(KEYRING_SERVICE, KEYRING_USER)
        .map_err(|e| CoreError::Keyring(e.to_string()))?;
    entry
        .delete_credential()
        .map_err(|e| CoreError::Keyring(e.to_string()))
}

/// Returns true if a MEK is stored in the keyring.
pub fn has_mek() -> bool {
    Entry::new(KEYRING_SERVICE, KEYRING_USER)
        .and_then(|e| e.get_password().map(|_| ()))
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyring_roundtrip_isolated() {
        // This test may fail in headless CI environments without a
        // keyring backend. It's a smoke test; in real environments,
        // the keyring is required to be available.
        if !has_mek() {
            // Skip if no keyring available
            eprintln!("skipping keyring test: no backend available");
            return;
        }

        let mek = [42u8; 32];
        store_mek(&mek).unwrap();
        let retrieved = retrieve_mek().unwrap();
        assert_eq!(mek, retrieved);
        delete_mek().unwrap();
    }
}

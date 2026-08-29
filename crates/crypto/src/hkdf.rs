//! HKDF-SHA256 key derivation (used for per-entry DEKs from the master KEK).
//!
//! Context separation via the `info` parameter prevents cross-entry key
//! derivation attacks.

use hkdf::Hkdf;
use sha2::Sha256;

use super::error::{CryptoError, Result};
use super::random::random_bytes;

/// Length of derived key in bytes.
pub const DEK_LEN: usize = 32;
/// Length of HKDF salt in bytes.
pub const SALT_LEN: usize = 32;

/// Derives a 256-bit DEK from a master KEK using HKDF-SHA256.
///
/// The `info` parameter binds the derivation to a specific context
/// (e.g., `"rw_secstore:v1:entry:{entry_id}:{created_at}"`).
/// Different `info` values produce different DEKs from the same KEK.
///
/// # Errors
///
/// Returns an error if the salt or input key is the wrong length.
pub fn derive_dek(
    master_kek: &[u8],
    info: &[u8],
    salt: &[u8; SALT_LEN],
    out_dek: &mut [u8; DEK_LEN],
) -> Result<()> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt.as_slice()), master_kek);
    hkdf.expand(info, out_dek.as_mut_slice())
        .map_err(|e| CryptoError::KeyDerivation(e.to_string()))
}

/// Generates a random HKDF salt.
#[must_use]
pub fn generate_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    random_bytes(&mut salt);
    salt
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_dek_deterministic() {
        let kek = b"master key encryption key - 32 bytes!";
        let info = b"entry:12345";
        let salt = [7u8; SALT_LEN];

        let mut dek1 = [0u8; DEK_LEN];
        let mut dek2 = [0u8; DEK_LEN];

        derive_dek(kek, info, &salt, &mut dek1).unwrap();
        derive_dek(kek, info, &salt, &mut dek2).unwrap();

        assert_eq!(dek1, dek2);
    }

    #[test]
    fn derive_dek_context_separation() {
        // Same KEK and salt, but different info -> different DEK
        let kek = b"master key encryption key - 32 bytes!";
        let salt = [7u8; SALT_LEN];

        let mut dek1 = [0u8; DEK_LEN];
        let mut dek2 = [0u8; DEK_LEN];

        derive_dek(kek, b"entry:1", &salt, &mut dek1).unwrap();
        derive_dek(kek, b"entry:2", &salt, &mut dek2).unwrap();

        assert_ne!(dek1, dek2, "Context separation failed!");
    }

    #[test]
    fn derive_dek_salt_changes_output() {
        let kek = b"master key encryption key - 32 bytes!";
        let info = b"entry:1";
        let salt1 = [1u8; SALT_LEN];
        let salt2 = [2u8; SALT_LEN];

        let mut dek1 = [0u8; DEK_LEN];
        let mut dek2 = [0u8; DEK_LEN];

        derive_dek(kek, info, &salt1, &mut dek1).unwrap();
        derive_dek(kek, info, &salt2, &mut dek2).unwrap();

        assert_ne!(dek1, dek2);
    }
}

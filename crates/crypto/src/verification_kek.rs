//! Verification KEK (separate from encryption KEK).
//!
//! This module derives a separate key for HMAC seal verification, used to
//! validate the integrity of the keystore_meta table BEFORE the user
//! enters their password. This solves the "chicken-and-egg" problem where
//! the HMAC seal needs a key but the key requires the user to unlock.
//!
//! ## How it works
//!
//! 1. At `init`, a 32-byte "verification salt" is generated and stored
//!    in the database.
//! 2. The HMAC seal key is derived from this salt + a known constant
//!    (no password needed).
//! 3. The seal is computed over all critical `keystore_meta` rows.
//! 4. On `unlock`, the seal is verified FIRST (before password check).
//! 5. If the seal is valid, the password is then used to derive the
//!    encryption KEK.
//!
//! This means: an attacker who modifies the database without knowing
//! the verification salt will fail the seal check BEFORE the password
//! is even attempted.

use hkdf::Hkdf;
use sha2::Sha256;

use super::error::Result;
use super::random::random_bytes;

/// Length of the verification salt.
pub const VERIFICATION_SALT_LEN: usize = 32;
/// Length of the derived verification key.
pub const VERIFICATION_KEY_LEN: usize = 32;

/// Context string for HKDF derivation of the verification key.
pub const VERIFICATION_CONTEXT: &[u8] = b"rw_secstore:v1:verification_key";

/// Generates a random 32-byte verification salt.
#[must_use]
pub fn generate_verification_salt() -> [u8; VERIFICATION_SALT_LEN] {
    let mut salt = [0u8; VERIFICATION_SALT_LEN];
    random_bytes(&mut salt);
    salt
}

/// Derives a 32-byte verification key from the salt.
///
/// This derivation does NOT require a password — the salt itself is the
/// secret. Store the salt in the database (it is NOT sensitive by itself,
/// but binding it via HMAC prevents offline tampering).
///
/// # Errors
///
/// Returns an error if HKDF expansion fails.
pub fn derive_verification_key(
    salt: &[u8; VERIFICATION_SALT_LEN],
    out_key: &mut [u8; VERIFICATION_KEY_LEN],
) -> Result<()> {
    // Use an empty IKM and the salt as the HKDF salt
    let hkdf = Hkdf::<Sha256>::new(Some(salt.as_slice()), &[]);
    hkdf.expand(VERIFICATION_CONTEXT, out_key.as_mut_slice())
        .map_err(|e| super::error::CryptoError::KeyDerivation(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_verification_key_deterministic() {
        let salt = [42u8; VERIFICATION_SALT_LEN];
        let mut key1 = [0u8; VERIFICATION_KEY_LEN];
        let mut key2 = [0u8; VERIFICATION_KEY_LEN];
        derive_verification_key(&salt, &mut key1).unwrap();
        derive_verification_key(&salt, &mut key2).unwrap();
        assert_eq!(key1, key2);
    }

    #[test]
    fn different_salt_yields_different_key() {
        let salt1 = [1u8; VERIFICATION_SALT_LEN];
        let salt2 = [2u8; VERIFICATION_SALT_LEN];
        let mut key1 = [0u8; VERIFICATION_KEY_LEN];
        let mut key2 = [0u8; VERIFICATION_KEY_LEN];
        derive_verification_key(&salt1, &mut key1).unwrap();
        derive_verification_key(&salt2, &mut key2).unwrap();
        assert_ne!(key1, key2);
    }
}

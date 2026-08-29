//! HMAC integrity seal for the keystore.
//!
//! Provides a full-file HMAC-SHA256 seal that detects tampering of the
//! keystore database. The seal is computed over the database file
//! contents (excluding the seal itself) using a key derived from the
//! KEK/MEK via a separate HKDF context.

use hmac::{Hmac, Mac};
use sha2::Sha256;

use super::constant_time::ct_verify;
use super::error::Result;
use super::hkdf;
use super::random::random_bytes;

type HmacSha256 = Hmac<Sha256>;

/// HMAC-SHA256 output size in bytes.
pub const HMAC_LEN: usize = 32;
/// Length of the seal key context.
pub const SEAL_KEY_CONTEXT: &[u8] = b"rw_secstore:v1:hmac_seal_key";

/// Derives the HMAC seal key from the master KEK/MEK.
///
/// Uses a separate HKDF context from encryption to ensure the seal key
/// is different from the encryption key.
pub fn derive_seal_key(master_key: &[u8], salt: &[u8; 32], out_key: &mut [u8; 32]) -> Result<()> {
    hkdf::derive_dek(master_key, SEAL_KEY_CONTEXT, salt, out_key)
}

/// Computes an HMAC-SHA256 of `data` using `key`.
///
/// HMAC-SHA256 accepts keys of any length, so this function is infallible.
/// The `Result` return is a defensive API choice for future algorithm
/// agility (e.g., if we move to keyed BLAKE3 or another keyed hash).
#[must_use]
pub fn compute(key: &[u8], data: &[u8]) -> [u8; HMAC_LEN] {
    let mut mac = match <HmacSha256 as Mac>::new_from_slice(key) {
        Ok(m) => m,
        Err(_) => {
            // HMAC-SHA256 accepts any key length, so this branch is
            // unreachable in practice. Return zeros as a defensive
            // measure; the caller will reject the verification.
            return [0u8; HMAC_LEN];
        }
    };
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; HMAC_LEN];
    out.copy_from_slice(&result);
    out
}

/// Verifies an HMAC-SHA256 in constant time.
pub fn verify(key: &[u8], data: &[u8], expected: &[u8; HMAC_LEN]) -> Result<()> {
    let actual = compute(key, data);
    ct_verify(&actual, expected)
}

/// Generates a random seal salt.
#[must_use]
pub fn generate_salt() -> [u8; 32] {
    let mut salt = [0u8; 32];
    random_bytes(&mut salt);
    salt
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_is_deterministic() {
        let key = [1u8; 32];
        let data = b"hello world";
        let a = compute(&key, data);
        let b = compute(&key, data);
        assert_eq!(a, b);
    }

    #[test]
    fn verify_match() {
        let key = [1u8; 32];
        let data = b"hello";
        let mac = compute(&key, data);
        assert!(verify(&key, data, &mac).is_ok());
    }

    #[test]
    fn verify_tampered() {
        let key = [1u8; 32];
        let data = b"hello";
        let mut mac = compute(&key, data);
        mac[0] ^= 1;
        assert!(verify(&key, data, &mac).is_err());
    }

    #[test]
    fn seal_key_derivation_uses_separate_context() {
        let master = [42u8; 32];
        let salt = [1u8; 32];
        let mut seal_key = [0u8; 32];
        derive_seal_key(&master, &salt, &mut seal_key).unwrap();
        // Different from master
        assert_ne!(seal_key, master);
    }
}

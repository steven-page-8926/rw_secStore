//! Per-row HMAC for sensitive metadata (tamper detection).
//!
//! Some metadata rows (e.g., `keystore_meta` values) are critical for
//! security. If an attacker with DB write access modifies these, they
//! could downgrade Argon2id parameters, disable password policy, etc.
//!
//! This module provides per-row HMAC computation and verification using
//! the verification key derived from `verification_kek`.

use super::constant_time::ct_verify;
use super::error::Result;
use super::seal;
use super::verification_kek;

/// Length of the per-row HMAC.
pub const ROW_HMAC_LEN: usize = seal::HMAC_LEN;

/// Computes the HMAC for a single row: `HMAC(verification_key, key || value)`.
#[must_use]
pub fn compute_row_hmac(verification_key: &[u8], key: &str, value: &str) -> [u8; ROW_HMAC_LEN] {
    let mut data = Vec::with_capacity(key.len() + 1 + value.len());
    data.extend_from_slice(key.as_bytes());
    data.push(0x00); // Separator (won't appear in keys)
    data.extend_from_slice(value.as_bytes());
    seal::compute(verification_key, &data)
}

/// Verifies a row's HMAC.
pub fn verify_row_hmac(
    verification_key: &[u8],
    key: &str,
    value: &str,
    expected: &[u8; ROW_HMAC_LEN],
) -> Result<()> {
    let actual = compute_row_hmac(verification_key, key, value);
    ct_verify(&actual, expected)
}

/// Convenience: derive the verification key from the salt and compute
/// the row HMAC in one call.
pub fn compute_with_salt(salt: &[u8; verification_kek::VERIFICATION_SALT_LEN], key: &str, value: &str) -> Result<[u8; ROW_HMAC_LEN]> {
    let mut vk = [0u8; verification_kek::VERIFICATION_KEY_LEN];
    verification_kek::derive_verification_key(salt, &mut vk)?;
    Ok(compute_row_hmac(&vk, key, value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_deterministic() {
        let key = [1u8; 32];
        let a = compute_row_hmac(&key, "salt", "value1");
        let b = compute_row_hmac(&key, "salt", "value1");
        assert_eq!(a, b);
    }

    #[test]
    fn different_value_different_hmac() {
        let key = [1u8; 32];
        let a = compute_row_hmac(&key, "salt", "value1");
        let b = compute_row_hmac(&key, "salt", "value2");
        assert_ne!(a, b);
    }

    #[test]
    fn different_key_different_hmac() {
        let vk = [1u8; 32];
        let a = compute_row_hmac(&vk, "key1", "value");
        let b = compute_row_hmac(&vk, "key2", "value");
        assert_ne!(a, b);
    }

    #[test]
    fn verify_match() {
        let key = [1u8; 32];
        let hmac = compute_row_hmac(&key, "salt", "value");
        assert!(verify_row_hmac(&key, "salt", "value", &hmac).is_ok());
    }

    #[test]
    fn verify_tampered() {
        let key = [1u8; 32];
        let mut hmac = compute_row_hmac(&key, "salt", "value");
        hmac[0] ^= 1;
        assert!(verify_row_hmac(&key, "salt", "value", &hmac).is_err());
    }

    #[test]
    fn separator_collision_resistance() {
        // Ensure that "ab" + "c" doesn't collide with "a" + "bc"
        let key = [1u8; 32];
        let h1 = compute_row_hmac(&key, "ab", "c");
        let h2 = compute_row_hmac(&key, "a", "bc");
        assert_ne!(h1, h2, "Separator collision detected");
    }
}

//! Argon2id key derivation function.
//!
//! Implements the password-based key derivation with hardcoded minimums
//! to prevent downgrade attacks.
//!
//! Production parameters: memory=64MB, iterations=3, parallelism=4
//! CI/test parameters: memory=8MB, iterations=1 (via `RW_SECSTORE_FAST_KDF=1`)

use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroize;

use super::error::{CryptoError, Result};

/// Production parameters: 64 MiB memory, 3 iterations, 4 parallelism.
pub const PROD_MEMORY_KIB: u32 = 64 * 1024;
/// Production iteration count.
pub const PROD_ITERATIONS: u32 = 3;
/// Production parallelism.
pub const PROD_PARALLELISM: u32 = 4;

/// CI/test parameters: 8 MiB memory, 1 iteration, 1 parallelism.
pub const CI_MEMORY_KIB: u32 = 8 * 1024;
/// CI/test iteration count.
pub const CI_ITERATIONS: u32 = 1;
/// CI/test parallelism.
pub const CI_PARALLELISM: u32 = 1;

/// Salt length in bytes (256-bit).
pub const SALT_LEN: usize = 32;

/// Derived key length in bytes (256-bit).
pub const DERIVED_KEY_LEN: usize = 32;

/// Argon2id parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Params {
    /// Memory cost in KiB.
    pub memory_kib: u32,
    /// Iteration count (time cost).
    pub iterations: u32,
    /// Parallelism (lanes).
    pub parallelism: u32,
}

impl Argon2Params {
    /// Returns the appropriate parameters based on the `RW_SECSTORE_FAST_KDF` env var.
    ///
    /// Production defaults unless `RW_SECSTORE_FAST_KDF=1` is set.
    #[must_use]
    pub fn from_env() -> Self {
        if std::env::var("RW_SECSTORE_FAST_KDF").is_ok() {
            Self::ci()
        } else {
            Self::production()
        }
    }

    /// Production parameters: 64 MiB memory, 3 iterations, 4 parallelism.
    #[must_use]
    pub const fn production() -> Self {
        Self {
            memory_kib: PROD_MEMORY_KIB,
            iterations: PROD_ITERATIONS,
            parallelism: PROD_PARALLELISM,
        }
    }

    /// CI/test parameters: 8 MiB memory, 1 iteration, 1 parallelism.
    #[must_use]
    pub const fn ci() -> Self {
        Self {
            memory_kib: CI_MEMORY_KIB,
            iterations: CI_ITERATIONS,
            parallelism: CI_PARALLELISM,
        }
    }

    /// Validates that parameters meet security minimums.
    ///
    /// Returns `Err` if any parameter is below the production minimum.
    pub fn validate(&self) -> Result<()> {
        if self.memory_kib < PROD_MEMORY_KIB {
            return Err(CryptoError::WeakArgon2Params(format!(
                "memory_kib {} < production minimum {}",
                self.memory_kib, PROD_MEMORY_KIB
            )));
        }
        if self.iterations < PROD_ITERATIONS {
            return Err(CryptoError::WeakArgon2Params(format!(
                "iterations {} < production minimum {}",
                self.iterations, PROD_ITERATIONS
            )));
        }
        Ok(())
    }

    /// Returns the `argon2::Params` representation.
    fn to_argon2_params(&self) -> Result<Params> {
        Params::new(self.memory_kib, self.iterations, self.parallelism, Some(DERIVED_KEY_LEN))
            .map_err(|e| CryptoError::KeyDerivation(e.to_string()))
    }
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self::production()
    }
}

/// Derives a 256-bit key from a password using Argon2id.
///
/// The salt MUST be 32 bytes of cryptographically random data.
/// The derived key is written to `out_key` and zeroized on drop.
///
/// Callers SHOULD validate params via `params.validate()` before
/// calling this function. This function does NOT validate params
/// to allow test/CI usage with reduced-cost parameters.
///
/// # Errors
///
/// Returns an error if the salt is the wrong length or the underlying
/// Argon2 derivation fails.
pub fn derive_key(
    password: &[u8],
    salt: &[u8],
    params: &Argon2Params,
    out_key: &mut [u8; DERIVED_KEY_LEN],
) -> Result<()> {
    if salt.len() != SALT_LEN {
        return Err(CryptoError::InvalidKeyLength {
            expected: SALT_LEN,
            actual: salt.len(),
        });
    }

    let argon2_params = params.to_argon2_params()?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);

    // Derive the key. Zeroize the output buffer on error too.
    let result = argon2.hash_password_into(password, salt, out_key);

    if result.is_err() {
        out_key.zeroize();
    }

    result.map_err(|e| CryptoError::KeyDerivation(e.to_string()))
}

/// Derives a key with strict production-only validation.
///
/// Use this in production code paths to enforce hardcoded minimums.
pub fn derive_key_production(
    password: &[u8],
    salt: &[u8],
    out_key: &mut [u8; DERIVED_KEY_LEN],
) -> Result<()> {
    let params = Argon2Params::production();
    params.validate()?;
    derive_key(password, salt, &params, out_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_params_meet_minimums() {
        assert!(Argon2Params::production().validate().is_ok());
    }

    #[test]
    fn ci_params_fail_validation() {
        // CI params are weaker than production, must fail
        assert!(Argon2Params::ci().validate().is_err());
    }

    #[test]
    #[allow(unsafe_code)]
    fn from_env_returns_ci_when_set() {
        // SAFETY: Test-only env var manipulation
        unsafe {
            std::env::set_var("RW_SECSTORE_FAST_KDF", "1");
        }
        let params = Argon2Params::from_env();
        assert_eq!(params.memory_kib, CI_MEMORY_KIB);
        unsafe {
            std::env::remove_var("RW_SECSTORE_FAST_KDF");
        }
    }

    #[test]
    fn derive_key_uses_salt_correctly() {
        let mut key1 = [0u8; DERIVED_KEY_LEN];
        let mut key2 = [0u8; DERIVED_KEY_LEN];
        let salt = [42u8; SALT_LEN];
        let password = b"correct horse battery staple";

        // Use CI params for fast tests
        let ci_params = Argon2Params::ci();
        derive_key(password, &salt, &ci_params, &mut key1).unwrap();
        derive_key(password, &salt, &ci_params, &mut key2).unwrap();

        // Same input -> same output
        assert_eq!(key1, key2);
    }

    #[test]
    fn derive_key_different_salt_different_output() {
        let mut key1 = [0u8; DERIVED_KEY_LEN];
        let mut key2 = [0u8; DERIVED_KEY_LEN];
        let salt1 = [1u8; SALT_LEN];
        let salt2 = [2u8; SALT_LEN];
        let password = b"hunter2";

        let ci_params = Argon2Params::ci();
        derive_key(password, &salt1, &ci_params, &mut key1).unwrap();
        derive_key(password, &salt2, &ci_params, &mut key2).unwrap();

        assert_ne!(key1, key2);
    }

    #[test]
    fn derive_key_wrong_salt_length_fails() {
        let mut key = [0u8; DERIVED_KEY_LEN];
        let short_salt = [0u8; 16]; // Wrong length
        let ci_params = Argon2Params::ci();

        let result = derive_key(b"password", &short_salt, &ci_params, &mut key);
        assert!(result.is_err());
    }
}

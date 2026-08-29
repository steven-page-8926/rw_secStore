//! Cryptographically secure random number generation.
//!
//! Uses `OsRng` (the operating system's CSPRNG) only. No fallback to
//! weaker RNGs — if `OsRng` fails, this module panics.

use rand::{CryptoRng, RngCore};
use zeroize::Zeroize;

use super::error::CryptoError;

/// Fills a buffer with cryptographically random bytes.
///
/// # Panics
///
/// Panics if the OS CSPRNG is unavailable. This is intentional per
/// security policy (no fallback to weaker RNGs).
pub fn random_bytes(buf: &mut [u8]) {
    use rand::Rng;
    let mut rng = OsRngPanic;
    rng.fill(buf);
}

/// Generates a random 32-byte value.
#[must_use]
pub fn random_32() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    random_bytes(&mut bytes);
    bytes
}

/// A CSPRNG wrapper that panics on failure (no fallback).
///
/// The `aes-gcm` and `argon2` crates require `CryptoRng + RngCore`.
/// `OsRng` satisfies both, but we wrap it to ensure the `try_fill_bytes`
/// failure mode is explicitly handled.
struct OsRngPanic;

impl RngCore for OsRngPanic {
    fn next_u32(&mut self) -> u32 {
        rand::rngs::OsRng.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        rand::rngs::OsRng.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        rand::rngs::OsRng.fill_bytes(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        rand::rngs::OsRng.try_fill_bytes(dest)
    }
}

impl CryptoRng for OsRngPanic {}

/// Securely zeros a buffer.
pub fn zeroize(buf: &mut [u8]) {
    buf.zeroize();
}

/// Convert `try_fill_bytes` errors to our error type.
pub fn try_random_bytes(buf: &mut [u8]) -> Result<(), CryptoError> {
    use rand::Rng;
    let mut rng = rand::rngs::OsRng;
    rng.try_fill(buf)
        .map_err(|_| CryptoError::RngUnavailable)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_bytes_fills_buffer() {
        let mut buf = [0u8; 32];
        random_bytes(&mut buf);
        // Extremely unlikely to be all zeros
        assert!(buf.iter().any(|&b| b != 0));
    }

    #[test]
    fn random_32_returns_unique_values() {
        let a = random_32();
        let b = random_32();
        assert_ne!(a, b);
    }

    #[test]
    fn zeroize_clears_buffer() {
        let mut buf = [0xFFu8; 32];
        zeroize(&mut buf);
        assert_eq!(buf, [0u8; 32]);
    }
}

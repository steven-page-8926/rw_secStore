//! Backup codes for account recovery.
//!
//! Generates 8 single-use base32 codes (80 bits each) at init time.
//! On use, the code is hashed and marked as used.

use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::error::CoreError;

/// Type alias for Result with CoreError.
type Result<T> = std::result::Result<T, CoreError>;

/// Number of backup codes generated at init.
pub const BACKUP_CODE_COUNT: usize = 8;

/// Length of each backup code in bytes (80 bits = 10 bytes).
pub const BACKUP_CODE_BYTES: usize = 10;

/// A single backup code.
#[derive(Debug, Clone)]
pub struct BackupCode {
    /// Index (0..BACKUP_CODE_COUNT).
    pub index: usize,
    /// The plaintext code (base32-encoded).
    pub code: String,
    /// SHA-256 hash of the code (for storage).
    pub hash: String,
    /// Salt used for the hash.
    pub salt: String,
}

impl BackupCode {
    /// Generates a new random backup code.
    #[must_use]
    pub fn generate(index: usize) -> Self {
        let mut rng = rand::thread_rng();
        let mut bytes = [0u8; BACKUP_CODE_BYTES];
        rng.fill_bytes(&mut bytes);
        let code = encode_base32(&bytes);
        let salt = generate_salt();
        let hash = hash_code(&code, &salt);
        bytes.zeroize();
        Self {
            index,
            code,
            hash,
            salt,
        }
    }

    /// Verifies a candidate code against this entry's hash.
    #[must_use]
    pub fn verify(&self, candidate: &str) -> bool {
        let candidate_hash = hash_code(candidate, &self.salt);
        // Constant-time comparison
        constant_time_eq(&candidate_hash, &self.hash)
    }
}

/// Generates `BACKUP_CODE_COUNT` random backup codes.
#[must_use]
pub fn generate_backup_codes() -> Vec<BackupCode> {
    (0..BACKUP_CODE_COUNT)
        .map(BackupCode::generate)
        .collect()
}

/// Hashes a backup code with the given salt using SHA-256.
#[must_use]
pub fn hash_code(code: &str, salt: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(salt.as_bytes());
    hasher.update(b":");
    hasher.update(code.as_bytes());
    hex::encode(hasher.finalize())
}

/// Generates a random salt for backup code hashing.
#[must_use]
pub fn generate_salt() -> String {
    let mut rng = rand::thread_rng();
    let mut bytes = [0u8; 16];
    rng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Constant-time string comparison.
fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        result |= x ^ y;
    }
    result == 0
}

/// Base32 encoding (RFC 4648, lowercase, no padding).
fn encode_base32(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut output = String::new();
    let mut buffer: u64 = 0;
    let mut bits_in_buffer: u32 = 0;

    for &byte in bytes {
        buffer = (buffer << 8) | u64::from(byte);
        bits_in_buffer += 8;

        while bits_in_buffer >= 5 {
            bits_in_buffer -= 5;
            let index = ((buffer >> bits_in_buffer) & 0x1F) as usize;
            output.push(ALPHABET[index] as char);
        }
    }

    if bits_in_buffer > 0 {
        let index = ((buffer << (5 - bits_in_buffer)) & 0x1F) as usize;
        output.push(ALPHABET[index] as char);
    }

    output
}

/// Result of a backup code attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupCodeResult {
    /// Code was valid and accepted.
    Valid,
    /// Code was valid but already used.
    AlreadyUsed,
    /// Code was invalid.
    Invalid,
}

impl BackupCodeResult {
    /// Returns true if the code was accepted.
    #[must_use]
    pub fn is_valid(self) -> bool {
        matches!(self, Self::Valid)
    }
}

/// Decodes a base32 string back to bytes (for testing).
#[cfg(test)]
fn decode_base32(s: &str) -> Result<Vec<u8>> {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut output = Vec::new();
    let mut buffer: u64 = 0;
    let mut bits_in_buffer: u32 = 0;

    for c in s.chars() {
        let pos = ALPHABET.iter().position(|&b| b == c as u8).ok_or_else(|| {
            CoreError::InvalidInput(format!("invalid base32 char: {c}"))
        })?;
        buffer = (buffer << 5) | u64::from(pos as u8);
        bits_in_buffer += 5;

        if bits_in_buffer >= 8 {
            bits_in_buffer -= 8;
            output.push(((buffer >> bits_in_buffer) & 0xFF) as u8);
        }
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backup_codes_are_unique() {
        let codes = generate_backup_codes();
        assert_eq!(codes.len(), BACKUP_CODE_COUNT);

        let unique: std::collections::HashSet<_> = codes.iter().map(|c| c.code.clone()).collect();
        assert_eq!(unique.len(), BACKUP_CODE_COUNT);
    }

    #[test]
    fn backup_code_format_is_lowercase_base32() {
        let codes = generate_backup_codes();
        for code in &codes {
            // Each code should be 16 chars (10 bytes * 8 / 5 = 16)
            assert_eq!(code.code.len(), 16);
            for c in code.code.chars() {
                assert!(c.is_ascii_lowercase() || c.is_ascii_digit());
            }
        }
    }

    #[test]
    fn backup_code_verifies_correctly() {
        let backup = BackupCode::generate(0);
        assert!(backup.verify(&backup.code));
    }

    #[test]
    fn backup_code_rejects_wrong() {
        let backup = BackupCode::generate(0);
        assert!(!backup.verify("wrongcode12345"));
    }

    #[test]
    fn base32_round_trip() {
        let bytes = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let encoded = encode_base32(&bytes);
        let decoded = decode_base32(&encoded).unwrap();
        assert_eq!(decoded, bytes);
    }
}

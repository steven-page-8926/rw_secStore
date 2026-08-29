//! AES-256-GCM authenticated encryption.
//!
//! Provides per-entry encryption with 96-bit random nonces and per-entry
//! data encryption keys (DEKs) derived via HKDF from the master KEK.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use rand::RngCore;
use zeroize::Zeroize;

use super::error::{CryptoError, Result};

/// AES-256 key length in bytes (256-bit).
pub const KEY_LEN: usize = 32;
/// AES-GCM nonce length in bytes (96-bit).
pub const NONCE_LEN: usize = 12;
/// AES-GCM authentication tag length in bytes (128-bit).
pub const TAG_LEN: usize = 16;

/// Generates a cryptographically random 12-byte nonce.
///
/// Panics if the OS CSPRNG is unavailable (no fallback per security policy).
#[must_use]
pub fn generate_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Encrypts plaintext with AES-256-GCM, producing (nonce || ciphertext || tag).
///
/// The `aad` (additional authenticated data) is bound to the ciphertext
/// but NOT encrypted. Use it to bind metadata (e.g., entry_id).
///
/// # Errors
///
/// Returns an error if the key is the wrong length or encryption fails.
pub fn encrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce_obj = Nonce::from_slice(nonce);

    cipher
        .encrypt(
            nonce_obj,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| CryptoError::Encryption(e.to_string()))
}

/// Decrypts ciphertext with AES-256-GCM, verifying the authentication tag.
///
/// The `aad` MUST match the value used during encryption.
///
/// # Errors
///
/// Returns `Decryption` error if the tag verification fails (tampered or
/// wrong key/nonce/AAD).
pub fn decrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce_obj = Nonce::from_slice(nonce);

    cipher
        .decrypt(
            nonce_obj,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|e| CryptoError::Decryption(e.to_string()))
}

/// Securely zeros a key in place.
pub fn zeroize_key(key: &mut [u8]) {
    key.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = [42u8; KEY_LEN];
        let nonce = generate_nonce();
        let plaintext = b"super secret data";
        let aad = b"entry-12345";

        let ciphertext = encrypt(&key, &nonce, plaintext, aad).unwrap();
        assert_ne!(ciphertext, plaintext);

        let decrypted = decrypt(&key, &nonce, &ciphertext, aad).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_aad_fails() {
        let key = [42u8; KEY_LEN];
        let nonce = generate_nonce();
        let plaintext = b"super secret data";

        let ciphertext = encrypt(&key, &nonce, plaintext, b"aad-1").unwrap();
        let result = decrypt(&key, &nonce, &ciphertext, b"aad-2");
        assert!(result.is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let key1 = [1u8; KEY_LEN];
        let key2 = [2u8; KEY_LEN];
        let nonce = generate_nonce();

        let ciphertext = encrypt(&key1, &nonce, b"data", b"").unwrap();
        let result = decrypt(&key2, &nonce, &ciphertext, b"");
        assert!(result.is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let key = [42u8; KEY_LEN];
        let nonce = generate_nonce();
        let mut ciphertext = encrypt(&key, &nonce, b"data", b"").unwrap();

        // Tamper with the ciphertext
        let last = ciphertext.len() - 1;
        ciphertext[last] ^= 0x01;

        let result = decrypt(&key, &nonce, &ciphertext, b"");
        assert!(result.is_err());
    }

    #[test]
    fn nonces_are_unique() {
        let mut nonces = std::collections::HashSet::new();
        for _ in 0..1000 {
            let nonce = generate_nonce();
            assert!(nonces.insert(nonce), "Duplicate nonce generated");
        }
    }
}

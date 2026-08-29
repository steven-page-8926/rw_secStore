//! Property-based tests for cryptographic primitives.
//!
//! Uses `proptest` to verify invariants across many random inputs.
//!
//! ## Properties tested
//!
//! P-CRYPTO-1: Argon2id derivation is deterministic (same input → same output)
//! P-CRYPTO-2: Argon2id produces different keys for different salts
//! P-CRYPTO-3: Argon2id produces different keys for different passwords
//! P-CRYPTO-4: AES-GCM encryption is reversible (round-trip)
//! P-CRYPTO-5: AES-GCM detects tampering (auth tag)
//! P-CRYPTO-6: HKDF is deterministic
//! P-CRYPTO-7: HKDF produces different keys for different salts
//! P-CRYPTO-8: Constant-time comparison works correctly

use proptest::prelude::*;

use rw_secstore_crypto::aes_gcm;
use rw_secstore_crypto::argon2;
use rw_secstore_crypto::constant_time;
use rw_secstore_crypto::hkdf;
use rw_secstore_crypto::version;

const SALT_LEN: usize = argon2::SALT_LEN;
const KEY_LEN: usize = argon2::DERIVED_KEY_LEN;

/// Strategy for generating random 32-byte salts.
fn salt_strategy() -> impl Strategy<Value = [u8; SALT_LEN]> {
    any::<[u8; SALT_LEN]>()
}

/// Strategy for generating random passwords (max 64 bytes).
fn password_strategy() -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(any::<u8>(), 8..=64)
}

/// Strategy for generating random DEK (key encryption key).
fn dek_strategy() -> impl Strategy<Value = [u8; KEY_LEN]> {
    any::<[u8; KEY_LEN]>()
}

/// Strategy for generating random additional data (for AES-GCM AAD).
fn aad_strategy() -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(any::<u8>(), 0..=128)
}

/// Strategy for generating random plaintext (for AES-GCM).
fn plaintext_strategy() -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(any::<u8>(), 0..=512)
}

proptest! {
    // P-CRYPTO-1: Argon2id derivation is deterministic
    #[test]
    fn p_crypto_1_argon2id_deterministic(
        password in password_strategy(),
        salt in salt_strategy(),
    ) {
        let params = argon2::Argon2Params::ci();
        let mut key1 = [0u8; KEY_LEN];
        let mut key2 = [0u8; KEY_LEN];
        argon2::derive_key(&password, &salt, &params, &mut key1).unwrap();
        argon2::derive_key(&password, &salt, &params, &mut key2).unwrap();
        prop_assert_eq!(key1, key2);
    }

    // P-CRYPTO-2: Different salts produce different keys
    #[test]
    fn p_crypto_2_argon2id_different_salt(
        password in password_strategy(),
        salt1 in salt_strategy(),
        salt2 in salt_strategy(),
    ) {
        prop_assume!(salt1 != salt2);
        let params = argon2::Argon2Params::ci();
        let mut key1 = [0u8; KEY_LEN];
        let mut key2 = [0u8; KEY_LEN];
        argon2::derive_key(&password, &salt1, &params, &mut key1).unwrap();
        argon2::derive_key(&password, &salt2, &params, &mut key2).unwrap();
        prop_assert_ne!(key1, key2);
    }

    // P-CRYPTO-3: Different passwords produce different keys
    #[test]
    fn p_crypto_3_argon2id_different_password(
        password1 in password_strategy(),
        password2 in password_strategy(),
        salt in salt_strategy(),
    ) {
        prop_assume!(password1 != password2);
        let params = argon2::Argon2Params::ci();
        let mut key1 = [0u8; KEY_LEN];
        let mut key2 = [0u8; KEY_LEN];
        argon2::derive_key(&password1, &salt, &params, &mut key1).unwrap();
        argon2::derive_key(&password2, &salt, &params, &mut key2).unwrap();
        prop_assert_ne!(key1, key2);
    }

    // P-CRYPTO-4: AES-GCM round-trip
    #[test]
    fn p_crypto_4_aes_gcm_round_trip(
        key in dek_strategy(),
        plaintext in plaintext_strategy(),
        aad in aad_strategy(),
    ) {
        let nonce = aes_gcm::generate_nonce();
        let ciphertext = aes_gcm::encrypt(&key, &nonce, &plaintext, &aad).unwrap();
        let decrypted = aes_gcm::decrypt(&key, &nonce, &ciphertext, &aad).unwrap();
        prop_assert_eq!(decrypted, plaintext);
    }

    // P-CRYPTO-5: AES-GCM detects tampering
    #[test]
    fn p_crypto_5_aes_gcm_detects_tampering(
        key in dek_strategy(),
        plaintext in plaintext_strategy(),
        aad in aad_strategy(),
    ) {
        let nonce = aes_gcm::generate_nonce();
        let mut ciphertext = aes_gcm::encrypt(&key, &nonce, &plaintext, &aad).unwrap();
        // Tamper with one byte
        if !ciphertext.is_empty() {
            ciphertext[0] ^= 0xFF;
        }
        let result = aes_gcm::decrypt(&key, &nonce, &ciphertext, &aad);
        prop_assert!(result.is_err());
    }

    // P-CRYPTO-6: HKDF is deterministic
    #[test]
    fn p_crypto_6_hkdf_deterministic(
        ikm in dek_strategy(),
        salt in salt_strategy(),
    ) {
        let info = b"test info";
        let mut key1 = [0u8; 32];
        let mut key2 = [0u8; 32];
        hkdf::derive_dek(&ikm, info, &salt, &mut key1).unwrap();
        hkdf::derive_dek(&ikm, info, &salt, &mut key2).unwrap();
        prop_assert_eq!(key1, key2);
    }

    // P-CRYPTO-7: HKDF different salt produces different key
    #[test]
    fn p_crypto_7_hkdf_different_salt(
        ikm in dek_strategy(),
        salt1 in salt_strategy(),
        salt2 in salt_strategy(),
    ) {
        prop_assume!(salt1 != salt2);
        let info = b"test info";
        let mut key1 = [0u8; 32];
        let mut key2 = [0u8; 32];
        hkdf::derive_dek(&ikm, info, &salt1, &mut key1).unwrap();
        hkdf::derive_dek(&ikm, info, &salt2, &mut key2).unwrap();
        prop_assert_ne!(key1, key2);
    }

    // P-CRYPTO-8: Versioned blob round-trip
    #[test]
    fn p_crypto_8_versioned_blob_round_trip(
        plaintext in plaintext_strategy(),
    ) {
        let key = [42u8; 32];
        let nonce = aes_gcm::generate_nonce();
        let ciphertext = aes_gcm::encrypt(&key, &nonce, &plaintext, b"").unwrap();

        // Build a versioned blob
        let blob = version::build_blob(version::EncryptedHeader::V1_AES_GCM, &nonce, &ciphertext);

        // Parse it back
        let (header, parsed_nonce, parsed_ct) = version::parse_blob(&blob).unwrap();
        prop_assert_eq!(header, version::EncryptedHeader::V1_AES_GCM);
        prop_assert_eq!(parsed_nonce, nonce);
        prop_assert_eq!(parsed_ct, ciphertext.as_slice());

        // And it decrypts back to the plaintext
        let decrypted = aes_gcm::decrypt(&key, &parsed_nonce, parsed_ct, b"").unwrap();
        prop_assert_eq!(decrypted, plaintext);
    }
}

#[cfg(test)]
mod const_time_tests {
    use super::*;

    // Test constant-time eq
    #[test]
    fn const_time_eq_matches_normal_eq() {
        proptest!(|(a in any::<[u8; 32]>(), b in any::<[u8; 32]>())| {
            let normal = a == b;
            let ct = constant_time::ct_eq_array(&a, &b);
            prop_assert_eq!(normal, ct);
        });
    }
}

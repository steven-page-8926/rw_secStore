//! Cryptographic operations

use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit};
use aes_gcm::aead::{Aead, OsRng};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, Algorithm, Version, Params};
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use rand::rngs::OsRng;
use ring::rand::SystemRandom;
use secrecy::{Secret, ExposeSecret};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Cryptographic errors
#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Encryption failed: {0}")]
    Encryption(String),

    #[error("Decryption failed: {0}")]
    Decryption(String),

    #[error("Key derivation failed: {0}")]
    KeyDerivation(String),

    #[error("Signing failed: {0}")]
    Signing(String),

    #[error("Verification failed: {0}")]
    Verification(String),

    #[error("Invalid key: {0}")]
    InvalidKey(String),

    #[error("Invalid nonce: {0}")]
    InvalidNonce(String),

    #[error("HSM error: {0}")]
    Hsm(String),
}

/// Encryption key with zeroize support
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct EncryptionKey(Secret<[u8; 32]>);

impl EncryptionKey {
    /// Generate a new random encryption key
    pub fn generate() -> Self {
        let mut key = [0u8; 32];
        SystemRandom::new().fill(&mut key).expect("RNG failure");
        Self(Secret::new(key))
    }

    /// Create from raw bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Secret::new(bytes))
    }

    /// Get the key bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.expose_secret()
    }
}

/// Initialize crypto provider
pub fn init() -> Result<(), CryptoError> {
    // Ring's SystemRandom is automatically initialized
    Ok(())
}

/// Encrypt data with AES-256-GCM
pub fn encrypt(key: &EncryptionKey, plaintext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_bytes()));
    let mut nonce_bytes = [0u8; 12];
    SystemRandom::new().fill(&mut nonce_bytes).map_err(|e| CryptoError::Encryption(e.to_string()))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let mut ciphertext = cipher.encrypt(nonce, aes_gcm::aead::Payload {
        msg: plaintext,
        aad: associated_data,
    }).map_err(|e| CryptoError::Encryption(e.to_string()))?;

    // Prepend nonce to ciphertext
    let mut result = nonce_bytes.to_vec();
    result.append(&mut ciphertext);
    Ok(result)
}

/// Decrypt data with AES-256-GCM
pub fn decrypt(key: &EncryptionKey, ciphertext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if ciphertext.len() < 12 {
        return Err(CryptoError::Decryption("Ciphertext too short".to_string()));
    }

    let (nonce_bytes, ciphertext) = ciphertext.split_at(12);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_bytes()));
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher.decrypt(nonce, aes_gcm::aead::Payload {
        msg: ciphertext,
        aad: associated_data,
    }).map_err(|e| CryptoError::Decryption(e.to_string()))
}

/// Derive key from password using Argon2id
pub fn derive_key(password: &[u8], salt: &[u8]) -> Result<EncryptionKey, CryptoError> {
    let params = Params::new(65536, 3, 1, Some(32)).map_err(|e| CryptoError::KeyDerivation(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; 32];
    argon2.hash_password_into(password, salt, &mut key)
        .map_err(|e| CryptoError::KeyDerivation(e.to_string()))?;

    Ok(EncryptionKey::from_bytes(key))
}

/// Hash password with Argon2id
pub fn hash_password(password: &[u8]) -> Result<String, CryptoError> {
    let salt = generate_salt()?;
    let params = Params::new(65536, 3, 1, Some(32)).map_err(|e| CryptoError::KeyDerivation(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let password_hash = argon2.hash_password(password, &salt)
        .map_err(|e| CryptoError::KeyDerivation(e.to_string()))?;

    Ok(password_hash.to_string())
}

/// Verify password against hash
pub fn verify_password(password: &[u8], hash: &str) -> Result<bool, CryptoError> {
    let parsed_hash = PasswordHash::new(hash).map_err(|e| CryptoError::Verification(e.to_string()))?;
    let argon2 = Argon2::default();
    Ok(argon2.verify_password(password, &parsed_hash).is_ok())
}

/// Generate random salt
fn generate_salt() -> Result<argon2::password_hash::SaltString, CryptoError> {
    let mut salt = [0u8; 16];
    SystemRandom::new().fill(&mut salt).map_err(|e| CryptoError::KeyDerivation(e.to_string()))?;
    Ok(argon2::password_hash::SaltString::encode_b64(&salt).map_err(|e| CryptoError::KeyDerivation(e.to_string()))?)
}

/// Ed25519 signing key pair
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SigningKeyPair {
    signing_key: SigningKey,
}

impl SigningKeyPair {
    /// Generate new key pair
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self { signing_key }
    }

    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, CryptoError> {
        let signing_key = SigningKey::from_bytes(bytes);
        Ok(Self { signing_key })
    }

    /// Get verifying key
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Sign data
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }

    /// Get raw signing key bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }
}

/// Verify Ed25519 signature
pub fn verify_signature(verifying_key: &VerifyingKey, message: &[u8], signature: &Signature) -> Result<bool, CryptoError> {
    verifying_key.verify(message, signature)
        .map(|_| true)
        .map_err(|e| CryptoError::Verification(e.to_string()))
}

/// Generate random bytes
pub fn random_bytes(len: usize) -> Result<Vec<u8>, CryptoError> {
    let mut bytes = vec![0u8; len];
    SystemRandom::new().fill(&mut bytes).map_err(|e| CryptoError::Encryption(e.to_string()))?;
    Ok(bytes)
}

/// Constant-time comparison
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}
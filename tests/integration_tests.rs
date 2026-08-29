//! Integration tests for rw_secstore

use rw_secstore::{init, config::Config, crypto::{encrypt, decrypt, EncryptionKey, hash_password, verify_password, random_bytes}};
use tempfile::TempDir;

#[tokio::test]
async fn test_config_load() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("config.toml");
    
    let config_content = r#"
[server]
bind_address = "127.0.0.1"
port = 8443
tls_enabled = false

[storage]
backend = "sled"
database_path = "./data/db"
pool_size = 10

[crypto]
encryption_algorithm = "aes-256-gcm"
kdf_algorithm = "argon2id"
key_rotation_days = 90

[audit]
enabled = true
format = "json"
retention_days = 365
"#;
    
    std::fs::write(&config_path, config_content).unwrap();
    let config = Config::load(Some(&config_path)).unwrap();
    
    assert_eq!(config.server.bind_address, "127.0.0.1");
    assert_eq!(config.server.port, 8443);
    assert_eq!(config.storage.backend, config::StorageBackend::Sled);
    assert_eq!(config.crypto.encryption_algorithm, config::EncryptionAlgorithm::Aes256Gcm);
}

#[test]
fn test_encryption_roundtrip() {
    init().unwrap();
    
    let key = EncryptionKey::generate();
    let plaintext = b"Hello, World! This is a secret message.";
    let aad = b"associated-data";
    
    let ciphertext = encrypt(&key, plaintext, aad).unwrap();
    let decrypted = decrypt(&key, &ciphertext, aad).unwrap();
    
    assert_eq!(plaintext, decrypted.as_slice());
}

#[test]
fn test_encryption_different_keys() {
    init().unwrap();
    
    let key1 = EncryptionKey::generate();
    let key2 = EncryptionKey::generate();
    let plaintext = b"Test message";
    let aad = b"aad";
    
    let ciphertext = encrypt(&key1, plaintext, aad).unwrap();
    
    // Decryption with wrong key should fail
    let result = decrypt(&key2, &ciphertext, aad);
    assert!(result.is_err());
}

#[test]
fn test_password_hashing() {
    init().unwrap();
    
    let password = b"secure-password-123";
    let hash = hash_password(password).unwrap();
    
    // Verify correct password
    assert!(verify_password(password, &hash).unwrap());
    
    // Verify wrong password fails
    assert!(!verify_password(b"wrong-password", &hash).unwrap());
}

#[test]
fn test_random_bytes() {
    init().unwrap();
    
    let bytes1 = random_bytes(32).unwrap();
    let bytes2 = random_bytes(32).unwrap();
    
    assert_eq!(bytes1.len(), 32);
    assert_eq!(bytes2.len(), 32);
    assert_ne!(bytes1, bytes2); // Should be different
}

#[test]
fn test_key_derivation() {
    init().unwrap();
    
    let password = b"my-password";
    let salt = b"unique-salt-1234"; // 16 bytes
    
    let key1 = rw_secstore::crypto::derive_key(password, salt).unwrap();
    let key2 = rw_secstore::crypto::derive_key(password, salt).unwrap();
    
    // Same password + salt should produce same key
    assert_eq!(key1.as_bytes(), key2.as_bytes());
    
    // Different salt should produce different key
    let salt2 = b"different-salt!!";
    let key3 = rw_secstore::crypto::derive_key(password, salt2).unwrap();
    assert_ne!(key1.as_bytes(), key3.as_bytes());
}
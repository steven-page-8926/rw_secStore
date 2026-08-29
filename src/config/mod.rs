//! Configuration management

use config::{Config, ConfigError, File, FileFormat};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Server bind address
    #[serde(default = "default_bind_address")]
    pub bind_address: String,

    /// Server port
    #[serde(default = "default_port")]
    pub port: u16,

    /// Enable TLS
    #[serde(default)]
    pub tls_enabled: bool,

    /// TLS certificate path
    pub tls_cert_path: Option<PathBuf>,

    /// TLS key path
    pub tls_key_path: Option<PathBuf>,
}

fn default_bind_address() -> String {
    "0.0.0.0".to_string()
}

fn default_port() -> u16 {
    8443
}

/// Storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Storage backend type
    #[serde(default = "default_storage_backend")]
    pub backend: StorageBackend,

    /// Database path (for SQLite)
    pub database_path: Option<PathBuf>,

    /// RocksDB path
    pub rocksdb_path: Option<PathBuf>,

    /// Connection pool size
    #[serde(default = "default_pool_size")]
    pub pool_size: u32,
}

fn default_storage_backend() -> StorageBackend {
    StorageBackend::Sled
}

fn default_pool_size() -> u32 {
    10
}

/// Storage backend types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum StorageBackend {
    Sled,
    RocksDb,
    Sqlite,
    Postgres,
}

/// Cryptography configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoConfig {
    /// Default encryption algorithm
    #[serde(default = "default_encryption_algorithm")]
    pub encryption_algorithm: EncryptionAlgorithm,

    /// Default key derivation algorithm
    #[serde(default = "default_kdf_algorithm")]
    pub kdf_algorithm: KdfAlgorithm,

    /// Key rotation interval (days)
    #[serde(default = "default_key_rotation_days")]
    pub key_rotation_days: u32,

    /// HSM configuration
    pub hsm: Option<HsmConfig>,
}

fn default_encryption_algorithm() -> EncryptionAlgorithm {
    EncryptionAlgorithm::Aes256Gcm
}

fn default_kdf_algorithm() -> KdfAlgorithm {
    KdfAlgorithm::Argon2id
}

fn default_key_rotation_days() -> u32 {
    90
}

/// Encryption algorithms
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum EncryptionAlgorithm {
    Aes256Gcm,
    ChaCha20Poly1305,
}

/// Key derivation algorithms
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum KdfAlgorithm {
    Argon2id,
    Pbkdf2,
    Scrypt,
}

/// HSM configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HsmConfig {
    /// PKCS#11 library path
    pub library_path: PathBuf,

    /// Slot ID
    #[serde(default)]
    pub slot_id: u64,

    /// Token label
    pub token_label: String,

    /// User PIN (should be from env in production)
    pub user_pin: Option<String>,
}

/// Audit configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    /// Enable audit logging
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Log file path
    pub log_path: Option<PathBuf>,

    /// Log format
    #[serde(default = "default_log_format")]
    pub format: AuditLogFormat,

    /// Retention days
    #[serde(default = "default_retention_days")]
    pub retention_days: u32,
}

fn default_true() -> bool {
    true
}

fn default_log_format() -> AuditLogFormat {
    AuditLogFormat::Json
}

fn default_retention_days() -> u32 {
    365
}

/// Audit log formats
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AuditLogFormat {
    Json,
    Text,
    Syslog,
}

/// Main configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub storage: StorageConfig,
    pub crypto: CryptoConfig,
    pub audit: AuditConfig,
}

impl Config {
    /// Load configuration from file
    pub fn load(path: Option<&PathBuf>) -> Result<Self, ConfigError> {
        let mut builder = Config::builder();

        // Default config file locations
        let default_paths = vec![
            PathBuf::from("/etc/rw_secstore/config.toml"),
            PathBuf::from("./config.toml"),
            PathBuf::from("config.toml"),
        ];

        // Add provided path first if given
        let paths = if let Some(p) = path {
            let mut v = vec![p.clone()];
            v.extend(default_paths);
            v
        } else {
            default_paths
        };

        // Try each path
        for p in paths {
            if p.exists() {
                builder = builder.add_source(File::from(p.clone()).format(FileFormat::Toml));
                break;
            }
        }

        // Environment variables override
        builder = builder.add_source(config::Environment::with_prefix("RW_SECSTORE").separator("__"));

        builder.build()?.try_deserialize()
    }
}
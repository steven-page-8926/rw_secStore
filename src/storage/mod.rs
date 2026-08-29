//! Storage abstraction layer

use async_trait::async_trait;
use rw_secstore::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use sled::Db;

/// Storage errors
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("Database error: {0}")]
    Database(String),

    #[error("Key not found: {0}")]
    NotFound(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Transaction error: {0}")]
    Transaction(String),

    #[error("Migration error: {0}")]
    Migration(String),
}

impl From<sled::Error> for StorageError {
    fn from(err: sled::Error) -> Self {
        StorageError::Database(err.to_string())
    }
}

impl From<serde_json::Error> for StorageError {
    fn from(err: serde_json::Error) -> Self {
        StorageError::Serialization(err.to_string())
    }
}

/// Stored secret entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretEntry {
    pub id: String,
    pub name: String,
    pub namespace: String,
    pub value: Vec<u8>, // Encrypted
    pub metadata: HashMap<String, String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub version: u64,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Stored key entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyEntry {
    pub id: String,
    pub name: String,
    pub namespace: String,
    pub key_type: KeyType,
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>, // Encrypted
    pub metadata: HashMap<String, String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Key types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum KeyType {
    Encryption,
    Signing,
    KeyExchange,
}

/// Storage trait for different backends
#[async_trait]
pub trait SecretStore: Send + Sync {
    async fn put_secret(&self, entry: &SecretEntry) -> Result<()>;
    async fn get_secret(&self, namespace: &str, name: &str) -> Result<Option<SecretEntry>>;
    async fn delete_secret(&self, namespace: &str, name: &str) -> Result<bool>;
    async fn list_secrets(&self, namespace: &str) -> Result<Vec<SecretEntry>>;
    async fn secret_exists(&self, namespace: &str, name: &str) -> Result<bool>;
}

#[async_trait]
pub trait KeyStore: Send + Sync {
    async fn put_key(&self, entry: &KeyEntry) -> Result<()>;
    async fn get_key(&self, namespace: &str, name: &str) -> Result<Option<KeyEntry>>;
    async fn delete_key(&self, namespace: &str, name: &str) -> Result<bool>;
    async fn list_keys(&self, namespace: &str) -> Result<Vec<KeyEntry>>;
}

/// Sled-based storage implementation
pub struct SledStore {
    db: Db,
    secrets_tree: sled::Tree,
    keys_tree: sled::Tree,
}

impl SledStore {
    /// Create new Sled store
    pub fn new(path: &PathBuf) -> Result<Self, StorageError> {
        let db = sled::open(path)?;
        let secrets_tree = db.open_tree("secrets")?;
        let keys_tree = db.open_tree("keys")?;
        Ok(Self { db, secrets_tree, keys_tree })
    }

    fn secret_key(namespace: &str, name: &str) -> Vec<u8> {
        format!("{}/{}", namespace, name).into_bytes()
    }

    fn key_key(namespace: &str, name: &str) -> Vec<u8> {
        format!("{}/{}", namespace, name).into_bytes()
    }
}

#[async_trait]
impl SecretStore for SledStore {
    async fn put_secret(&self, entry: &SecretEntry) -> Result<()> {
        let key = Self::secret_key(&entry.namespace, &entry.name);
        let value = serde_json::to_vec(entry)?;
        self.secrets_tree.insert(key, value)?;
        self.secrets_tree.flush_async().await?;
        Ok(())
    }

    async fn get_secret(&self, namespace: &str, name: &str) -> Result<Option<SecretEntry>> {
        let key = Self::secret_key(namespace, name);
        match self.secrets_tree.get(key)? {
            Some(value) => Ok(Some(serde_json::from_slice(&value)?)),
            None => Ok(None),
        }
    }

    async fn delete_secret(&self, namespace: &str, name: &str) -> Result<bool> {
        let key = Self::secret_key(namespace, name);
        Ok(self.secrets_tree.remove(key)?.is_some())
    }

    async fn list_secrets(&self, namespace: &str) -> Result<Vec<SecretEntry>> {
        let prefix = format!("{}/", namespace).into_bytes();
        let mut results = Vec::new();

        for item in self.secrets_tree.scan_prefix(&prefix) {
            let (_, value) = item?;
            let entry: SecretEntry = serde_json::from_slice(&value)?;
            results.push(entry);
        }

        Ok(results)
    }

    async fn secret_exists(&self, namespace: &str, name: &str) -> Result<bool> {
        let key = Self::secret_key(namespace, name);
        Ok(self.secrets_tree.contains_key(key)?)
    }
}

#[async_trait]
impl KeyStore for SledStore {
    async fn put_key(&self, entry: &KeyEntry) -> Result<()> {
        let key = Self::key_key(&entry.namespace, &entry.name);
        let value = serde_json::to_vec(entry)?;
        self.keys_tree.insert(key, value)?;
        self.keys_tree.flush_async().await?;
        Ok(())
    }

    async fn get_key(&self, namespace: &str, name: &str) -> Result<Option<KeyEntry>> {
        let key = Self::key_key(namespace, name);
        match self.keys_tree.get(key)? {
            Some(value) => Ok(Some(serde_json::from_slice(&value)?)),
            None => Ok(None),
        }
    }

    async fn delete_key(&self, namespace: &str, name: &str) -> Result<bool> {
        let key = Self::key_key(namespace, name);
        Ok(self.keys_tree.remove(key)?.is_some())
    }

    async fn list_keys(&self, namespace: &str) -> Result<Vec<KeyEntry>> {
        let prefix = format!("{}/", namespace).into_bytes();
        let mut results = Vec::new();

        for item in self.keys_tree.scan_prefix(&prefix) {
            let (_, value) = item?;
            let entry: KeyEntry = serde_json::from_slice(&value)?;
            results.push(entry);
        }

        Ok(results)
    }
}

/// Storage factory
pub struct StorageFactory;

impl StorageFactory {
    pub fn create_sled(path: &PathBuf) -> Result<Box<dyn SecretStore + KeyStore>, StorageError> {
        let store = SledStore::new(path)?;
        Ok(Box::new(store))
    }
}
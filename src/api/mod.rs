//! API layer (gRPC and REST)

use rw_secstore::{Error, Result};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// API errors
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("Authentication required")]
    Unauthorized,

    #[error("Permission denied: {0}")]
    Forbidden(String),

    #[error("Resource not found: {0}")]
    NotFound(String),

    #[error("Conflict: {0}")]
    Conflict(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

/// Secret API models
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSecretRequest {
    pub name: String,
    pub namespace: String,
    pub value: String, // Base64 encoded
    pub metadata: Option<std::collections::HashMap<String, String>>,
    pub ttl_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateSecretRequest {
    pub value: Option<String>, // Base64 encoded
    pub metadata: Option<std::collections::HashMap<String, String>>,
    pub ttl_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretResponse {
    pub id: String,
    pub name: String,
    pub namespace: String,
    pub metadata: std::collections::HashMap<String, String>,
    pub created_at: String,
    pub updated_at: String,
    pub version: u64,
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretValueResponse {
    pub value: String, // Base64 encoded
    pub version: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListSecretsResponse {
    pub secrets: Vec<SecretResponse>,
    pub total: usize,
}

/// Key API models
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateKeyRequest {
    pub name: String,
    pub namespace: String,
    pub key_type: String, // "encryption", "signing", "key_exchange"
    pub metadata: Option<std::collections::HashMap<String, String>>,
    pub ttl_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyResponse {
    pub id: String,
    pub name: String,
    pub namespace: String,
    pub key_type: String,
    pub public_key: String, // Base64 encoded
    pub metadata: std::collections::HashMap<String, String>,
    pub created_at: String,
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListKeysResponse {
    pub keys: Vec<KeyResponse>,
    pub total: usize,
}

/// Health check response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub uptime_seconds: u64,
}

/// Metrics response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsResponse {
    pub secrets_count: u64,
    pub keys_count: u64,
    pub namespaces_count: u64,
    pub requests_total: u64,
    pub errors_total: u64,
}

/// API server trait
#[async_trait::async_trait]
pub trait ApiServer: Send + Sync {
    async fn start(&self) -> Result<()>;
    async fn stop(&self) -> Result<()>;
}

/// REST API server
pub struct RestApiServer {
    config: Arc<crate::config::ServerConfig>,
    secret_store: Arc<dyn crate::storage::SecretStore>,
    key_store: Arc<dyn crate::storage::KeyStore>,
    audit_logger: Arc<crate::audit::AuditLogger>,
}

impl RestApiServer {
    pub fn new(
        config: Arc<crate::config::ServerConfig>,
        secret_store: Arc<dyn crate::storage::SecretStore>,
        key_store: Arc<dyn crate::storage::KeyStore>,
        audit_logger: Arc<crate::audit::AuditLogger>,
    ) -> Self {
        Self {
            config,
            secret_store,
            key_store,
            audit_logger,
        }
    }
}

#[async_trait::async_trait]
impl ApiServer for RestApiServer {
    async fn start(&self) -> Result<()> {
        // TODO: Implement REST server with axum or warp
        tracing::info!("Starting REST API server on {}:{}", self.config.bind_address, self.config.port);
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        tracing::info!("Stopping REST API server");
        Ok(())
    }
}

/// gRPC API server
pub struct GrpcApiServer {
    config: Arc<crate::config::ServerConfig>,
    secret_store: Arc<dyn crate::storage::SecretStore>,
    key_store: Arc<dyn crate::storage::KeyStore>,
    audit_logger: Arc<crate::audit::AuditLogger>,
}

impl GrpcApiServer {
    pub fn new(
        config: Arc<crate::config::ServerConfig>,
        secret_store: Arc<dyn crate::storage::SecretStore>,
        key_store: Arc<dyn crate::storage::KeyStore>,
        audit_logger: Arc<crate::audit::AuditLogger>,
    ) -> Self {
        Self {
            config,
            secret_store,
            key_store,
            audit_logger,
        }
    }
}

#[async_trait::async_trait]
impl ApiServer for GrpcApiServer {
    async fn start(&self) -> Result<()> {
        // TODO: Implement gRPC server with tonic
        tracing::info!("Starting gRPC API server on {}:{}", self.config.bind_address, self.config.port);
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        tracing::info!("Stopping gRPC API server");
        Ok(())
    }
}
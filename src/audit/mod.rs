//! Audit logging

use rw_secstore::{Error, Result};
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tracing::{error, info};

/// Audit event types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventType {
    SecretCreated,
    SecretRead,
    SecretUpdated,
    SecretDeleted,
    SecretListed,
    KeyCreated,
    KeyRead,
    KeyUpdated,
    KeyDeleted,
    KeyListed,
    KeyRotated,
    AuthenticationSuccess,
    AuthenticationFailure,
    AuthorizationFailure,
    ConfigurationChanged,
    BackupCreated,
    BackupRestored,
    SystemStart,
    SystemStop,
}

/// Audit event severity
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AuditSeverity {
    Info,
    Warning,
    Critical,
}

/// Audit event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: uuid::Uuid,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub event_type: AuditEventType,
    pub severity: AuditSeverity,
    pub user_id: Option<String>,
    pub client_ip: Option<String>,
    pub resource_type: String,
    pub resource_id: String,
    pub namespace: String,
    pub details: serde_json::Value,
    pub success: bool,
    pub error_message: Option<String>,
}

/// Audit logger
pub struct AuditLogger {
    writer: Arc<Mutex<Option<BufWriter<std::fs::File>>>>,
    config: crate::config::AuditConfig,
}

impl AuditLogger {
    /// Create new audit logger
    pub fn new(config: crate::config::AuditConfig) -> Result<Self> {
        let writer = if config.enabled {
            if let Some(path) = &config.log_path {
                let file = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)?;
                Some(Arc::new(Mutex::new(Some(BufWriter::new(file)))))
            } else {
                None
            }
        } else {
            None
        };

        Ok(Self { writer, config })
    }

    /// Log an audit event
    pub fn log(&self, event: AuditEvent) -> Result<()> {
        // Always log to tracing
        match event.severity {
            AuditSeverity::Info => info!(?event, "Audit event"),
            AuditSeverity::Warning => tracing::warn!(?event, "Audit event"),
            AuditSeverity::Critical => error!(?event, "Audit event"),
        }

        // Write to file if configured
        if let Some(writer) = &self.writer {
            let mut guard = writer.lock().unwrap();
            if let Some(w) = guard.as_mut() {
                let line = match self.config.format {
                    crate::config::AuditLogFormat::Json => serde_json::to_string(&event)?,
                    crate::config::AuditLogFormat::Text => format!(
                        "{} {} {} {} {}",
                        event.timestamp.to_rfc3339(),
                        event.event_type as u8,
                        event.resource_type,
                        event.resource_id,
                        event.success
                    ),
                    crate::config::AuditLogFormat::Syslog => format!(
                        "<{}>{} rw_secstore: {}",
                        event.severity as u8 + 1,
                        event.timestamp.to_rfc3339(),
                        serde_json::to_string(&event)?
                    ),
                };
                writeln!(w, "{}", line)?;
                w.flush()?;
            }
        }

        Ok(())
    }

    /// Create audit event builder
    pub fn event(&self, event_type: AuditEventType) -> AuditEventBuilder {
        AuditEventBuilder::new(event_type)
    }
}

/// Audit event builder
pub struct AuditEventBuilder {
    event_type: AuditEventType,
    severity: AuditSeverity,
    user_id: Option<String>,
    client_ip: Option<String>,
    resource_type: String,
    resource_id: String,
    namespace: String,
    details: serde_json::Value,
    success: bool,
    error_message: Option<String>,
}

impl AuditEventBuilder {
    fn new(event_type: AuditEventType) -> Self {
        Self {
            event_type,
            severity: AuditSeverity::Info,
            user_id: None,
            client_ip: None,
            resource_type: String::new(),
            resource_id: String::new(),
            namespace: String::new(),
            details: serde_json::Value::Null,
            success: true,
            error_message: None,
        }
    }

    pub fn severity(mut self, severity: AuditSeverity) -> Self {
        self.severity = severity;
        self
    }

    pub fn user_id(mut self, user_id: String) -> Self {
        self.user_id = Some(user_id);
        self
    }

    pub fn client_ip(mut self, client_ip: String) -> Self {
        self.client_ip = Some(client_ip);
        self
    }

    pub fn resource(mut self, resource_type: String, resource_id: String) -> Self {
        self.resource_type = resource_type;
        self.resource_id = resource_id;
        self
    }

    pub fn namespace(mut self, namespace: String) -> Self {
        self.namespace = namespace;
        self
    }

    pub fn details(mut self, details: serde_json::Value) -> Self {
        self.details = details;
        self
    }

    pub fn success(mut self, success: bool) -> Self {
        self.success = success;
        self
    }

    pub fn error(mut self, error: String) -> Self {
        self.success = false;
        self.error_message = Some(error);
        self.severity = AuditSeverity::Critical;
        self
    }

    pub fn log(self, logger: &AuditLogger) -> Result<()> {
        let event = AuditEvent {
            id: uuid::Uuid::new_v4(),
            timestamp: chrono::Utc::now(),
            event_type: self.event_type,
            severity: self.severity,
            user_id: self.user_id,
            client_ip: self.client_ip,
            resource_type: self.resource_type,
            resource_id: self.resource_id,
            namespace: self.namespace,
            details: self.details,
            success: self.success,
            error_message: self.error_message,
        };
        logger.log(event)
    }
}

/// Audit errors
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}
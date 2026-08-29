//! CLI definitions

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "rw_secstore")]
#[command(about = "RapidWebs Secure Store - Enterprise secrets management", long_about = None)]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Configuration file path
    #[arg(short, long, global = true)]
    pub config: Option<PathBuf>,

    /// Verbose output
    #[arg(short, long, global = true)]
    pub verbose: bool,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Initialize configuration and storage
    Init {
        /// Configuration file path
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Storage path
        #[arg(short, long)]
        storage_path: Option<PathBuf>,

        /// Force overwrite existing config
        #[arg(short, long)]
        force: bool,
    },

    /// Start the server
    Serve {
        /// Bind address
        #[arg(long, default_value = "0.0.0.0")]
        bind: String,

        /// Port
        #[arg(short, long, default_value = "8443")]
        port: u16,

        /// Enable TLS
        #[arg(long)]
        tls: bool,

        /// TLS certificate path
        #[arg(long)]
        tls_cert: Option<PathBuf>,

        /// TLS key path
        #[arg(long)]
        tls_key: Option<PathBuf>,
    },

    /// Secret management
    Secret {
        #[command(subcommand)]
        command: SecretCommands,
    },

    /// Key management
    Key {
        #[command(subcommand)]
        command: KeyCommands,
    },

    /// Namespace management
    Namespace {
        #[command(subcommand)]
        command: NamespaceCommands,
    },

    /// Audit log management
    Audit {
        #[command(subcommand)]
        command: AuditCommands,
    },

    /// Health check
    Health,

    /// Show version
    Version,
}

#[derive(Subcommand)]
pub enum SecretCommands {
    /// Create a new secret
    Create {
        /// Secret name
        #[arg(short, long)]
        name: String,

        /// Namespace
        #[arg(short, long, default_value = "default")]
        namespace: String,

        /// Secret value (or read from stdin if not provided)
        #[arg(short, long)]
        value: Option<String>,

        /// Value from file
        #[arg(long)]
        value_file: Option<PathBuf>,

        /// Metadata as JSON
        #[arg(long)]
        metadata: Option<String>,

        /// TTL in seconds
        #[arg(long)]
        ttl: Option<u64>,
    },

    /// Read a secret
    Get {
        /// Secret name
        #[arg(short, long)]
        name: String,

        /// Namespace
        #[arg(short, long, default_value = "default")]
        namespace: String,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Update a secret
    Update {
        /// Secret name
        #[arg(short, long)]
        name: String,

        /// Namespace
        #[arg(short, long, default_value = "default")]
        namespace: String,

        /// New value
        #[arg(short, long)]
        value: Option<String>,

        /// Value from file
        #[arg(long)]
        value_file: Option<PathBuf>,

        /// Metadata as JSON
        #[arg(long)]
        metadata: Option<String>,

        /// TTL in seconds
        #[arg(long)]
        ttl: Option<u64>,
    },

    /// Delete a secret
    Delete {
        /// Secret name
        #[arg(short, long)]
        name: String,

        /// Namespace
        #[arg(short, long, default_value = "default")]
        namespace: String,

        /// Force delete without confirmation
        #[arg(short, long)]
        force: bool,
    },

    /// List secrets
    List {
        /// Namespace
        #[arg(short, long, default_value = "default")]
        namespace: String,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
pub enum KeyCommands {
    /// Create a new key
    Create {
        /// Key name
        #[arg(short, long)]
        name: String,

        /// Namespace
        #[arg(short, long, default_value = "default")]
        namespace: String,

        /// Key type: encryption, signing, key_exchange
        #[arg(short, long, default_value = "encryption")]
        key_type: String,

        /// Metadata as JSON
        #[arg(long)]
        metadata: Option<String>,

        /// TTL in seconds
        #[arg(long)]
        ttl: Option<u64>,
    },

    /// Get a key (public only)
    Get {
        /// Key name
        #[arg(short, long)]
        name: String,

        /// Namespace
        #[arg(short, long, default_value = "default")]
        namespace: String,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Rotate a key
    Rotate {
        /// Key name
        #[arg(short, long)]
        name: String,

        /// Namespace
        #[arg(short, long, default_value = "default")]
        namespace: String,
    },

    /// Delete a key
    Delete {
        /// Key name
        #[arg(short, long)]
        name: String,

        /// Namespace
        #[arg(short, long, default_value = "default")]
        namespace: String,

        /// Force delete without confirmation
        #[arg(short, long)]
        force: bool,
    },

    /// List keys
    List {
        /// Namespace
        #[arg(short, long, default_value = "default")]
        namespace: String,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
pub enum NamespaceCommands {
    /// Create a namespace
    Create {
        /// Namespace name
        name: String,
    },

    /// Delete a namespace
    Delete {
        /// Namespace name
        name: String,

        /// Force delete without confirmation
        #[arg(short, long)]
        force: bool,
    },

    /// List namespaces
    List {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
pub enum AuditCommands {
    /// Show recent audit events
    Log {
        /// Number of events to show
        #[arg(short, long, default_value = "100")]
        limit: usize,

        /// Filter by event type
        #[arg(long)]
        event_type: Option<String>,

        /// Filter by namespace
        #[arg(long)]
        namespace: Option<String>,

        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Export audit log
    Export {
        /// Output file
        #[arg(short, long)]
        output: PathBuf,

        /// Start time (RFC3339)
        #[arg(long)]
        start: Option<String>,

        /// End time (RFC3339)
        #[arg(long)]
        end: Option<String>,

        /// Format: json, csv
        #[arg(long, default_value = "json")]
        format: String,
    },
}

impl Cli {
    pub async fn execute(&self) -> Result<(), crate::Error> {
        use crate::{init, config::Config};

        // Load configuration
        let config = Config::load(self.config.as_ref())?;

        // Initialize
        init()?;

        match &self.command {
            Commands::Init { config: config_path, storage_path, force } => {
                self.cmd_init(config_path, storage_path, *force).await
            }
            Commands::Serve { bind, port, tls, tls_cert, tls_key } => {
                self.cmd_serve(bind, *port, *tls, tls_cert, tls_key).await
            }
            Commands::Secret { command } => self.cmd_secret(command).await,
            Commands::Key { command } => self.cmd_key(command).await,
            Commands::Namespace { command } => self.cmd_namespace(command).await,
            Commands::Audit { command } => self.cmd_audit(command).await,
            Commands::Health => self.cmd_health().await,
            Commands::Version => self.cmd_version().await,
        }
    }

    async fn cmd_init(&self, config_path: &Option<PathBuf>, storage_path: &Option<PathBuf>, force: bool) -> Result<(), crate::Error> {
        println!("Initializing rw_secstore...");
        // TODO: Implement initialization
        Ok(())
    }

    async fn cmd_serve(&self, bind: &str, port: u16, tls: bool, tls_cert: &Option<PathBuf>, tls_key: &Option<PathBuf>) -> Result<(), crate::Error> {
        println!("Starting server on {}:{}", bind, port);
        // TODO: Implement server
        Ok(())
    }

    async fn cmd_secret(&self, _command: &SecretCommands) -> Result<(), crate::Error> {
        // TODO: Implement secret commands
        Ok(())
    }

    async fn cmd_key(&self, _command: &KeyCommands) -> Result<(), crate::Error> {
        // TODO: Implement key commands
        Ok(())
    }

    async fn cmd_namespace(&self, _command: &NamespaceCommands) -> Result<(), crate::Error> {
        // TODO: Implement namespace commands
        Ok(())
    }

    async fn cmd_audit(&self, _command: &AuditCommands) -> Result<(), crate::Error> {
        // TODO: Implement audit commands
        Ok(())
    }

    async fn cmd_health(&self) -> Result<(), crate::Error> {
        println!("OK");
        Ok(())
    }

    async fn cmd_version(&self) -> Result<(), crate::Error> {
        println!("rw_secstore {}", env!("CARGO_PKG_VERSION"));
        Ok(())
    }
}
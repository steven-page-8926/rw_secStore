//! Configuration management.
//!
//! Configuration is loaded from a TOML file at:
//! - `$XDG_CONFIG_HOME/rw-secstore/config.toml` (or `~/.config/rw-secstore/config.toml`)
//! - Or `$RW_SECSTORE_CONFIG_DIR/config.toml` (override)

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{CoreError, Result};

/// Default config file name.
pub const CONFIG_FILE_NAME: &str = "config.toml";

/// Default database file name.
pub const DB_FILE_NAME: &str = "keystore.sqlite";

/// Runtime configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Path to the keystore database file.
    pub database_path: PathBuf,
    /// Path to the master password file (optional).
    #[serde(default)]
    pub password_file: Option<PathBuf>,
    /// Use OS keyring for the Master Encryption Key (MEK).
    #[serde(default = "default_true")]
    pub use_keyring: bool,
    /// Generate backup codes at init.
    #[serde(default = "default_true")]
    pub generate_backup_codes: bool,
    /// Inactivity timeout in seconds (0 = no timeout).
    #[serde(default = "default_inactivity_timeout")]
    pub inactivity_timeout_secs: u64,
    /// Default key profile for new CAs.
    #[serde(default = "default_key_profile")]
    pub default_key_profile: String,
    /// Default validity in days for issued certificates.
    #[serde(default = "default_validity_days")]
    pub default_validity_days: u32,
    /// Logging level (error, warn, info, debug, trace).
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

fn default_true() -> bool {
    true
}

fn default_inactivity_timeout() -> u64 {
    3600 // 1 hour
}

fn default_key_profile() -> String {
    "ed25519".to_string()
}

fn default_validity_days() -> u32 {
    365
}

fn default_log_level() -> String {
    "info".to_string()
}

impl Default for Config {
    fn default() -> Self {
        Self {
            database_path: default_database_path(),
            password_file: None,
            use_keyring: true,
            generate_backup_codes: true,
            inactivity_timeout_secs: 3600,
            default_key_profile: "ed25519".to_string(),
            default_validity_days: 365,
            log_level: "info".to_string(),
        }
    }
}

/// Returns the default config directory using XDG standard.
#[must_use]
pub fn default_config_dir() -> PathBuf {
    // Allow override via env var
    if let Ok(path) = std::env::var("RW_SECSTORE_CONFIG_DIR") {
        return PathBuf::from(path);
    }

    // Use XDG via directories crate
    if let Some(proj) = directories::ProjectDirs::from("org", "rapidwebs", "rw-secstore") {
        return proj.config_dir().to_path_buf();
    }

    // Fallback to ~/.rw-secstore
    directories::UserDirs::new()
        .and_then(|u| Some(u.home_dir().join(".rw-secstore")))
        .unwrap_or_else(|| PathBuf::from(".rw-secstore"))
}

/// Returns the default data directory using XDG standard.
#[must_use]
pub fn default_data_dir() -> PathBuf {
    if let Some(proj) = directories::ProjectDirs::from("org", "rapidwebs", "rw-secstore") {
        return proj.data_local_dir().to_path_buf();
    }
    directories::UserDirs::new()
        .and_then(|u| Some(u.home_dir().join(".rw-secstore")))
        .unwrap_or_else(|| PathBuf::from(".rw-secstore"))
}

/// Returns the default database path.
#[must_use]
pub fn default_database_path() -> PathBuf {
    default_data_dir().join(DB_FILE_NAME)
}

/// Returns the default config file path.
#[must_use]
pub fn default_config_path() -> PathBuf {
    default_config_dir().join(CONFIG_FILE_NAME)
}

/// Loads the configuration from the default location.
///
/// Returns the default config if no config file exists.
pub fn load() -> Result<Config> {
    let path = default_config_path();
    if !path.exists() {
        return Ok(Config::default());
    }
    load_from(&path)
}

/// Loads the configuration from the specified file.
///
/// # Errors
///
/// Returns an error if the file cannot be read or parsed.
pub fn load_from(path: &Path) -> Result<Config> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| CoreError::Config(format!("read {}: {e}", path.display())))?;
    let config: Config = toml::from_str(&contents)
        .map_err(|e| CoreError::Config(format!("parse {}: {e}", path.display())))?;
    Ok(config)
}

/// Writes the configuration to the default location.
///
/// # Errors
///
/// Returns an error if the config cannot be serialized or written.
pub fn save(config: &Config) -> Result<()> {
    let path = default_config_path();
    save_to(config, &path)
}

/// Writes the configuration to the specified file.
///
/// # Errors
///
/// Returns an error if the config cannot be serialized or written.
pub fn save_to(config: &Config, path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| {
                CoreError::Config(format!("create dir {}: {e}", parent.display()))
            })?;
        }
    }
    let contents = toml::to_string_pretty(config)
        .map_err(|e| CoreError::Config(format!("serialize: {e}")))?;
    std::fs::write(path, contents)
        .map_err(|e| CoreError::Config(format!("write {}: {e}", path.display())))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn default_config_has_sane_values() {
        let config = Config::default();
        assert_eq!(config.inactivity_timeout_secs, 3600);
        assert_eq!(config.default_validity_days, 365);
        assert!(config.use_keyring);
        assert!(config.generate_backup_codes);
    }

    #[test]
    fn round_trip_config() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let original = Config::default();
        save_to(&original, &path).unwrap();
        let loaded = load_from(&path).unwrap();
        assert_eq!(
            original.inactivity_timeout_secs,
            loaded.inactivity_timeout_secs
        );
        assert_eq!(original.default_validity_days, loaded.default_validity_days);
    }

    #[test]
    fn load_from_missing_file_returns_default() {
        let config = load().unwrap();
        // Should not panic, just return default
        assert_eq!(config.inactivity_timeout_secs, 3600);
    }

    #[test]
    fn default_directories_are_valid() {
        let config_dir = default_config_dir();
        let data_dir = default_data_dir();
        assert!(!config_dir.as_os_str().is_empty());
        assert!(!data_dir.as_os_str().is_empty());
    }
}

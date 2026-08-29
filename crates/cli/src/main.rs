//! Command-line interface for rw-secstore.

#![allow(clippy::print_stderr)]
#![allow(clippy::print_stdout)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use rw_secstore_core::auth::{
    generator::{generate_passphrase, generate_strong_password},
    password::read_password_from_tty,
    policy::{check_password, PasswordStrength},
};
use rw_secstore_core::config;

/// `rw-secstore`: Secure keystore and certificate authority.
#[derive(Debug, Parser)]
#[command(name = "rw-secstore", version, about, long_about = None)]
pub struct Cli {
    /// Path to configuration file (overrides XDG default).
    #[arg(long, global = true, env = "RW_SECSTORE_CONFIG")]
    pub config: Option<PathBuf>,

    /// Increase verbosity (-v, -vv, -vvv).
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    pub verbose: u8,

    /// The subcommand to run.
    #[command(subcommand)]
    pub command: Command,
}

/// Available subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Initialize a new keystore.
    Init {
        /// Path to the keystore database (overrides config).
        #[arg(long)]
        db: Option<PathBuf>,
    },
    /// Show version information.
    Version,
    /// Generate a strong password.
    Pwgen {
        /// Length of the generated password.
        #[arg(long, default_value_t = 24)]
        length: usize,
    },
    /// Generate a passphrase (diceware-style).
    Passphrase {
        /// Number of words.
        #[arg(long, default_value_t = 6)]
        words: usize,
        /// Word separator.
        #[arg(long, default_value = "-")]
        separator: String,
    },
    /// Check the strength of a password.
    Check {
        /// Password to check (omit to read from TTY).
        password: Option<String>,
    },
    /// Show the resolved configuration.
    Config,
    /// Print man pages (roff format) to stdout.
    Manpages,
}

/// CLI error type.
#[derive(Debug)]
pub enum CliError {
    /// Domain/core error.
    Core(rw_secstore_core::CoreError),
    /// Configuration error.
    Config(String),
    /// I/O error.
    Io(std::io::Error),
    /// Other error.
    Other(String),
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CliError::Core(e) => write!(f, "{e}"),
            CliError::Config(s) => write!(f, "config error: {s}"),
            CliError::Io(e) => write!(f, "I/O error: {e}"),
            CliError::Other(s) => write!(f, "{s}"),
        }
    }
}

impl std::error::Error for CliError {}

impl From<rw_secstore_core::CoreError> for CliError {
    fn from(e: rw_secstore_core::CoreError) -> Self {
        Self::Core(e)
    }
}

impl From<std::io::Error> for CliError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<toml::de::Error> for CliError {
    fn from(e: toml::de::Error) -> Self {
        Self::Config(e.to_string())
    }
}

impl From<toml::ser::Error> for CliError {
    fn from(e: toml::ser::Error) -> Self {
        Self::Config(e.to_string())
    }
}

/// Runs a subcommand and returns the result.
fn run_command(cli: Cli) -> Result<Option<ExitCode>, CliError> {
    match cli.command {
        Command::Init { db } => {
            cmd_init(db, cli.config)?;
            Ok(None)
        }
        Command::Version => {
            eprintln!("rw-secstore {}", env!("CARGO_PKG_VERSION"));
            eprintln!("Secure keystore and certificate authority");
            Ok(None)
        }
        Command::Pwgen { length } => {
            cmd_pwgen(length)?;
            Ok(None)
        }
        Command::Passphrase { words, separator } => {
            cmd_passphrase(words, &separator)?;
            Ok(None)
        }
        Command::Check { password } => cmd_check(password),
        Command::Config => {
            cmd_config(cli.config)?;
            Ok(None)
        }
        Command::Manpages => {
            cmd_manpages()?;
            Ok(None)
        }
    }
}

/// Binary entry point for `rw-secstore`.
pub fn main() -> ExitCode {
    let cli = Cli::parse();
    init_logging(cli.verbose);

    match run_command(cli) {
        Ok(None) => ExitCode::from(0),
        Ok(Some(code)) => code,
        Err(e) => {
            eprintln!("Error: {e}");
            ExitCode::from(1)
        }
    }
}

/// Initialize a new keystore.
fn cmd_init(db_path: Option<PathBuf>, config_path: Option<PathBuf>) -> Result<(), CliError> {
    let cfg = match config_path {
        Some(p) => config::load_from(&p)?,
        None => config::load()?,
    };
    let db_path = db_path.unwrap_or(cfg.database_path);
    eprintln!("Would initialize keystore at: {}", db_path.display());
    eprintln!("(Full init implementation in Phase 2)");
    Ok(())
}

/// Generate a strong password.
fn cmd_pwgen(length: usize) -> Result<(), CliError> {
    let password = generate_strong_password(length)?;
    eprintln!("Generated password: {password}");
    eprintln!("Length: {} chars", password.chars().count());
    Ok(())
}

/// Generate a passphrase.
fn cmd_passphrase(words: usize, separator: &str) -> Result<(), CliError> {
    let phrase = generate_passphrase(words, separator)?;
    eprintln!("Generated passphrase: {phrase}");
    Ok(())
}

/// Check password strength. Returns Some(ExitCode) when the password is very weak.
fn cmd_check(password: Option<String>) -> Result<Option<ExitCode>, CliError> {
    let password = match password {
        Some(p) => p,
        None => read_password_from_tty("Password to check: ")
            .map_err(|e| CliError::Other(e.to_string()))?
            .as_str()
            .to_string(),
    };
    let check = check_password(&password);
    eprintln!("Strength: {:?}", check.strength);
    eprintln!("Entropy: {:.1} bits", check.entropy_bits);
    eprintln!("Valid: {}", check.is_valid);
    for fb in &check.feedback {
        eprintln!("  - {fb}");
    }
    if check.strength == PasswordStrength::VeryWeak {
        Ok(Some(ExitCode::from(1)))
    } else {
        Ok(None)
    }
}

/// Show the resolved configuration.
fn cmd_config(config_path: Option<PathBuf>) -> Result<(), CliError> {
    let cfg = match config_path {
        Some(p) => config::load_from(&p)?,
        None => config::load()?,
    };
    eprintln!("{cfg:#?}");
    Ok(())
}

/// Print man pages to stdout.
fn cmd_manpages() -> Result<(), CliError> {
    let cmd = <Cli as clap::CommandFactory>::command();
    let man = clap_mangen::Man::new(cmd);
    man.render(&mut std::io::stdout())?;
    Ok(())
}

/// Initialize logging based on verbosity.
fn init_logging(verbosity: u8) {
    use tracing_subscriber::{fmt, EnvFilter};
    let level = match verbosity {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    let _ = fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level)),
        )
        .with_writer(std::io::stderr)
        .try_init();
}

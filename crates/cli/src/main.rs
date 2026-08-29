//! Command-line interface for rw-secstore.

#![allow(clippy::print_stderr)]
#![allow(clippy::print_stdout)]

use clap::{Parser, Subcommand};

/// `rw-secstore`: Secure keystore and certificate authority.
#[derive(Debug, Parser)]
#[command(name = "rw-secstore", version, about)]
pub struct Cli {
    /// The subcommand to run.
    #[command(subcommand)]
    pub command: Command,
}

/// Available subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Initialize a new keystore.
    Init,
    /// Show version information.
    Version,
}

/// Binary entry point for `rw-secstore`.
pub fn main() {
    let cli = Cli::parse();
    match cli.command {
        Command::Init => eprintln!("init: not yet implemented (Phase 2)"),
        Command::Version => eprintln!("rw-secstore {}", env!("CARGO_PKG_VERSION")),
    }
}

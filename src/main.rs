//! rw_secstore - Main entry point

use clap::Parser;
use rw_secstore::{init, Error, Result};
use tracing::{error, info};

mod cli;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    // Initialize library
    init()?;

    // Parse CLI
    let cli = cli::Cli::parse();

    // Execute command
    if let Err(e) = cli.execute().await {
        error!("Command failed: {}", e);
        std::process::exit(1);
    }

    Ok(())
}
//! rw_secstore - RapidWebs Secure Store
//!
//! Enterprise-grade secrets management and key storage solution.

pub mod audit;
pub mod config;
pub mod crypto;
pub mod error;
pub mod storage;
pub mod api;

pub use error::{Error, Result};

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Initialize the library
pub fn init() -> Result<()> {
    // Initialize crypto provider
    crypto::init()?;
    Ok(())
}
//! # rw-secstore-core
//!
//! Core domain types, business logic, and operations.
//!
//! This crate is the authoritative implementation of the operations
//! defined in the SPEC. It depends on `rw-secstore-crypto` and
//! `rw-secstore-storage` and is consumed by `rw-secstore-cli`.
//!
//! ## Modules
//!
//! - [`error`] — Core error types
//! - [`auth`] — Authentication: password input, keyring, backup codes, rate limiting
//! - [`config`] — Configuration management (TOML, XDG)
//! - [`audit`] — Audit logging for security-relevant operations

pub mod audit;
pub mod auth;
pub mod config;
pub mod error;

pub use error::{CoreError, Result};

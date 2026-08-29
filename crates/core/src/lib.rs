//! # rw-secstore-core
//!
//! Core domain types, business logic, and operations.
//!
//! This crate is the authoritative implementation of the operations
//! defined in the SPEC. It depends on `rw-secstore-crypto` and
//! `rw-secstore-storage` and is consumed by `rw-secstore-cli`.
//!
//! ## Modules (Phase 1)
//!
//! - [`error`] — Core error types
//!
//! Future phases will add: keystore, ca, ssh, auth, audit, config.

pub mod error;

pub use error::{CoreError, Result};

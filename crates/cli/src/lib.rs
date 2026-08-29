//! # rw-secstore-cli
//!
//! Command-line interface for rw-secstore.
//!
//! Phase 1 delivers a minimal CLI that compiles; subsequent phases
//! add the keystore, CA, SSH, and auth commands.

#![allow(clippy::print_stderr)]
#![allow(clippy::print_stdout)]

/// Library entry point (re-exports the binary's main function for tests).
pub fn main() {
    eprintln!("rw-secstore: Phase 1 scaffold (no commands implemented yet)");
}

#[cfg(test)]
mod tests {
    #[test]
    fn cli_placeholder() {
        // Placeholder test
        assert_eq!(2 + 2, 4);
    }
}

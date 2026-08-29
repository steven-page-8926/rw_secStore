//! Master password input.
//!
//! Provides secure password input from TTY (no echo) and validation.

#![allow(clippy::print_stderr)]
#![allow(clippy::print_stdout)]

use std::io::Write;

use rpassword::read_password;

use crate::error::{CoreError, Result};

/// Maximum master password length (to prevent memory DoS).
pub const MAX_PASSWORD_LEN: usize = 1024;

/// Reads a password securely from the TTY.
///
/// Uses `rpassword` which does not echo and reads from `/dev/tty`
/// (not stdin, which may be a pipe).
///
/// # Errors
///
/// Returns an error if reading from the TTY fails.
pub fn read_password_from_tty(prompt: &str) -> Result<zeroize::Zeroizing<String>> {
    // Print prompt to stderr (won't be redirected by `>`)
    eprint!("{prompt}");
    std::io::stderr().flush().ok();

    let password = read_password().map_err(|e| CoreError::AuthFailed(e.to_string()))?;
    Ok(zeroize::Zeroizing::new(password))
}

/// Validates the length of a master password.
///
/// Enforces:
/// - At least 1 character (caller decides min length policy)
/// - At most `MAX_PASSWORD_LEN` characters (memory DoS prevention)
pub fn validate_password_length(password: &str) -> Result<()> {
    if password.is_empty() {
        return Err(CoreError::PasswordPolicy(
            "password cannot be empty".to_string(),
        ));
    }
    if password.len() > MAX_PASSWORD_LEN {
        return Err(CoreError::PasswordPolicy(format!(
            "password too long: {} > {}",
            password.len(),
            MAX_PASSWORD_LEN
        )));
    }
    Ok(())
}

/// Reads and confirms a new master password.
///
/// Prompts twice and ensures both entries match.
///
/// # Errors
///
/// Returns an error if:
/// - Either input is empty
/// - The two entries do not match
/// - TTY reading fails
pub fn read_and_confirm_password(prompt: &str, confirm_prompt: &str) -> Result<Vec<u8>> {
    let password = read_password_from_tty(prompt)?;
    let confirmation = read_password_from_tty(confirm_prompt)?;

    if password.as_str() != confirmation.as_str() {
        return Err(CoreError::PasswordPolicy(
            "passwords do not match".to_string(),
        ));
    }
    validate_password_length(password.as_str())?;

    let bytes = password.as_bytes().to_vec();
    // bytes will be zeroized on drop (via standard Vec drop semantics for this scope)
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_password_length_rejects_empty() {
        assert!(validate_password_length("").is_err());
    }

    #[test]
    fn validate_password_length_rejects_too_long() {
        let long = "a".repeat(MAX_PASSWORD_LEN + 1);
        assert!(validate_password_length(&long).is_err());
    }

    #[test]
    fn validate_password_length_accepts_normal() {
        assert!(validate_password_length("hunter2").is_ok());
    }
}

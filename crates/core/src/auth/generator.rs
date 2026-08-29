//! Password generator.
//!
//! Generates cryptographically strong passwords using:
//! - Custom charset (mixed case, digits, symbols)
//! - Diceware (EFF word list, English)

use rand::seq::SliceRandom;
use rand::Rng;

use super::super::error::Result;

/// Default password length for generated passwords.
pub const DEFAULT_PASSWORD_LENGTH: usize = 24;

/// Character sets for password generation.
pub struct Charset {
    /// Lowercase letters (a-z).
    pub lowercase: &'static str,
    /// Uppercase letters (A-Z).
    pub uppercase: &'static str,
    /// Digits (0-9).
    pub digits: &'static str,
    /// Symbols.
    pub symbols: &'static str,
}

impl Default for Charset {
    fn default() -> Self {
        Self {
            lowercase: "abcdefghijklmnopqrstuvwxyz",
            uppercase: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            digits: "0123456789",
            symbols: "!@#$%^&*()-_=+[]{};:,.<>?",
        }
    }
}

impl Charset {
    /// Returns the full character set.
    #[must_use]
    pub fn all(&self) -> Vec<char> {
        let mut chars: Vec<char> = Vec::new();
        chars.extend(self.lowercase.chars());
        chars.extend(self.uppercase.chars());
        chars.extend(self.digits.chars());
        chars.extend(self.symbols.chars());
        chars
    }
}

/// Generates a random password from the given charset.
///
/// # Errors
///
/// Returns an error if the charset is empty.
pub fn generate_password(length: usize, charset: &Charset) -> Result<String> {
    if length == 0 {
        return Err(super::super::error::CoreError::PasswordPolicy(
            "password length must be > 0".to_string(),
        ));
    }

    let all_chars = charset.all();
    if all_chars.is_empty() {
        return Err(super::super::error::CoreError::PasswordPolicy(
            "charset is empty".to_string(),
        ));
    }

    let mut rng = rand::thread_rng();
    let password: String = (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..all_chars.len());
            all_chars[idx]
        })
        .collect();

    Ok(password)
}

/// Generates a password guaranteed to include at least one character from
/// each of the four character classes (lowercase, uppercase, digit, symbol).
///
/// # Errors
///
/// Returns an error if length is less than 4 or the charset is incomplete.
pub fn generate_strong_password(length: usize) -> Result<String> {
    if length < 4 {
        return Err(super::super::error::CoreError::PasswordPolicy(
            "strong password must be at least 4 characters".to_string(),
        ));
    }

    let charset = Charset::default();
    let mut rng = rand::thread_rng();
    let mut password = String::with_capacity(length);

    // First 4 chars: one from each class
    let first_four = [
        charset.lowercase.chars().collect::<Vec<_>>(),
        charset.uppercase.chars().collect::<Vec<_>>(),
        charset.digits.chars().collect::<Vec<_>>(),
        charset.symbols.chars().collect::<Vec<_>>(),
    ];
    for class in &first_four {
        if class.is_empty() {
            return Err(super::super::error::CoreError::PasswordPolicy(
                "charset class is empty".to_string(),
            ));
        }
        let idx = rng.gen_range(0..class.len());
        password.push(class[idx]);
    }

    // Remaining chars: from the full set
    let all_chars = charset.all();
    for _ in 4..length {
        let idx = rng.gen_range(0..all_chars.len());
        password.push(all_chars[idx]);
    }

    // Shuffle to avoid predictable pattern
    let mut chars: Vec<char> = password.chars().collect();
    chars.shuffle(&mut rng);
    Ok(chars.into_iter().collect())
}

/// A small embedded word list for diceware generation (subset of EFF list).
///
/// This is a fallback for systems where the full EFF list is not available.
/// For production, the full 7776-word EFF list should be used.
const FALLBACK_WORDLIST: &[&str] = &[
    "abbey", "absurd", "abyss", "ace", "acid", "acorn", "actor", "adapt", "admit", "adobe",
    "adopt", "adore", "adult", "agent", "agile", "agree", "ahead", "alarm", "album", "alert",
    "alibi", "alien", "alike", "alive", "alley", "allow", "alloy", "alpha", "alter", "always",
    "amber", "amend", "amigo", "amino", "ample", "amuse", "angel", "anger", "angle", "ankle",
    "annex", "annoy", "annul", "apart", "apex", "apple", "apply", "april", "arbor", "arcade",
    "arena", "argue", "arise", "armor", "aroma", "arrow", "ashes", "aside", "asset", "atlas",
    "atomic", "attic", "audit", "avoid", "awake", "award", "aware", "awful", "axiom", "bacon",
    "badge", "baker", "balmy", "banjo", "barge", "basil", "basin", "basis", "batch", "baton",
];

/// Generates a diceware-style passphrase with `word_count` words separated by `separator`.
///
/// # Errors
///
/// Returns an error if `word_count` is 0.
pub fn generate_passphrase(word_count: usize, separator: &str) -> Result<String> {
    if word_count == 0 {
        return Err(super::super::error::CoreError::PasswordPolicy(
            "word count must be > 0".to_string(),
        ));
    }

    let mut rng = rand::thread_rng();
    let words: Vec<String> = (0..word_count)
        .map(|_| FALLBACK_WORDLIST.choose(&mut rng).unwrap_or(&"word").to_string())
        .collect();

    Ok(words.join(separator))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_password_has_requested_length() {
        let password = generate_password(24, &Charset::default()).unwrap();
        assert_eq!(password.len(), 24);
    }

    #[test]
    fn generated_strong_password_has_all_classes() {
        let password = generate_strong_password(20).unwrap();
        assert_eq!(password.len(), 20);

        assert!(password.chars().any(|c| c.is_ascii_lowercase()));
        assert!(password.chars().any(|c| c.is_ascii_uppercase()));
        assert!(password.chars().any(|c| c.is_ascii_digit()));
        assert!(password.chars().any(|c| !c.is_alphanumeric()));
    }

    #[test]
    fn generated_passwords_are_different() {
        let p1 = generate_password(24, &Charset::default()).unwrap();
        let p2 = generate_password(24, &Charset::default()).unwrap();
        assert_ne!(p1, p2);
    }

    #[test]
    fn generate_strong_rejects_too_short() {
        assert!(generate_strong_password(3).is_err());
    }

    #[test]
    fn generate_passphrase_has_requested_words() {
        let phrase = generate_passphrase(6, "-").unwrap();
        let words: Vec<&str> = phrase.split('-').collect();
        assert_eq!(words.len(), 6);
    }
}

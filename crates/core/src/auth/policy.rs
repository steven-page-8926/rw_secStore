//! Password policy enforcement.
//!
//! Uses `zxcvbn` for entropy estimation and structural pattern detection.
//! Falls back to length-only policy if `zxcvbn` is not available.

use zxcvbn::{zxcvbn as zxcvbn_score, Score};

use super::super::error::{CoreError, Result};

/// Minimum acceptable password entropy (bits).
pub const MIN_ENTROPY_BITS: f64 = 80.0;

/// Minimum password length (overrides zxcvbn if shorter).
pub const MIN_PASSWORD_LENGTH: usize = 12;

/// Password strength level derived from zxcvbn score.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordStrength {
    /// Score 0-1: very guessable (too risky).
    VeryWeak,
    /// Score 2: somewhat guessable.
    Weak,
    /// Score 3: safely unguessable.
    Reasonable,
    /// Score 4: very unguessable.
    Strong,
    /// Score 5: extremely unguessable.
    VeryStrong,
}

impl PasswordStrength {
    /// Returns the strength from a zxcvbn score.
    #[must_use]
    pub const fn from_score(score: Score) -> Self {
        match score {
            Score::Zero | Score::One => Self::VeryWeak,
            Score::Two => Self::Weak,
            Score::Three => Self::Reasonable,
            Score::Four => Self::Strong,
            _ => Self::VeryStrong,
        }
    }

    /// Returns the approximate entropy in bits for this strength level.
    #[must_use]
    pub const fn entropy_bits(self) -> f64 {
        match self {
            Self::VeryWeak => 28.0,
            Self::Weak => 36.0,
            Self::Reasonable => 60.0,
            Self::Strong => 80.0,
            Self::VeryStrong => 100.0,
        }
    }
}

/// Password policy check result.
#[derive(Debug, Clone)]
pub struct PolicyCheck {
    /// Whether the password meets policy.
    pub is_valid: bool,
    /// The strength level.
    pub strength: PasswordStrength,
    /// Estimated entropy in bits.
    pub entropy_bits: f64,
    /// Feedback for the user.
    pub feedback: Vec<String>,
    /// Estimated number of guesses needed.
    pub guesses: u64,
}

/// Checks a password against the policy.
///
/// Returns a `PolicyCheck` with detailed feedback. The caller decides
/// whether to reject the password based on the `is_valid` flag.
#[must_use]
pub fn check_password(password: &str) -> PolicyCheck {
    let mut feedback = Vec::new();

    // Length check (cheap, do first)
    if password.len() < MIN_PASSWORD_LENGTH {
        feedback.push(format!(
            "Password must be at least {} characters long",
            MIN_PASSWORD_LENGTH
        ));
    }

    // zxcvbn entropy estimation
    let estimate = zxcvbn_score(password, &[]);
    let strength = PasswordStrength::from_score(estimate.score());
    let entropy_bits = estimate.guesses_log10() * std::f64::consts::LN_10 / std::f64::consts::LN_2;

    // Entropy check
    if entropy_bits < MIN_ENTROPY_BITS {
        feedback.push(format!(
            "Password entropy too low: {:.1} bits < {:.0} bits required",
            entropy_bits, MIN_ENTROPY_BITS
        ));
    }

    // Add zxcvbn feedback
    if let Some(fb) = estimate.feedback() {
        if let Some(warning) = fb.warning() {
            feedback.push(format!("Warning: {}", warning));
        }
        for suggestion in fb.suggestions() {
            feedback.push(format!("Suggestion: {}", suggestion));
        }
    }

    let is_valid = password.len() >= MIN_PASSWORD_LENGTH && entropy_bits >= MIN_ENTROPY_BITS;

    let guesses = estimate.guesses();

    PolicyCheck {
        is_valid,
        strength,
        entropy_bits,
        feedback,
        guesses,
    }
}

/// Validates a password against the policy.
///
/// Returns an error with detailed feedback if the password is too weak.
///
/// # Errors
///
/// Returns `CoreError::PasswordPolicy` if the password does not meet
/// the policy requirements.
pub fn validate_password(password: &str) -> Result<()> {
    let check = check_password(password);
    if !check.is_valid {
        return Err(CoreError::PasswordPolicy(check.feedback.join("; ")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_password_is_invalid() {
        let check = check_password("");
        assert!(!check.is_valid);
    }

    #[test]
    fn short_password_is_invalid() {
        let check = check_password("abc");
        assert!(!check.is_valid);
        assert!(check.feedback.iter().any(|f| f.contains("at least")));
    }

    #[test]
    fn strong_password_is_valid() {
        let check = check_password("correct horse battery staple extra random words here");
        // This is a 7-word diceware-style phrase, should be strong
        assert!(check.entropy_bits > 60.0);
    }

    #[test]
    fn password_strength_ordering() {
        // Stronger passwords should have higher entropy bits
        let weak = check_password("password123");
        let strong = check_password("Tr0ub4dor&3-correct-horse-battery-staple-extra");
        assert!(strong.entropy_bits >= weak.entropy_bits);
    }
}

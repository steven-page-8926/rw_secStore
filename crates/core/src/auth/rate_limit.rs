//! Rate limiting for authentication attempts.
//!
//! Implements progressive delay after failed auth attempts to prevent
//! brute-force attacks.

use std::time::{Duration, Instant};

use super::super::error::{CoreError, Result};

/// Maximum number of consecutive failed attempts before lockout.
pub const MAX_FAILED_ATTEMPTS: u32 = 5;

/// Lockout duration after `MAX_FAILED_ATTEMPTS` failures.
pub const LOCKOUT_DURATION: Duration = Duration::from_secs(60);

/// Rate limiter state.
#[derive(Debug)]
pub struct RateLimiter {
    /// Number of consecutive failed attempts.
    failed_attempts: u32,
    /// When the lockout expires.
    locked_until: Option<Instant>,
}

impl RateLimiter {
    /// Creates a new rate limiter.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            failed_attempts: 0,
            locked_until: None,
        }
    }

    /// Returns true if the limiter is currently in a locked state.
    #[must_use]
    pub fn is_locked(&self) -> bool {
        match self.locked_until {
            Some(until) => Instant::now() < until,
            None => false,
        }
    }

    /// Returns the number of remaining seconds in the lockout, or 0 if not locked.
    #[must_use]
    pub fn lockout_remaining_secs(&self) -> u64 {
        match self.locked_until {
            Some(until) => until.saturating_duration_since(Instant::now()).as_secs(),
            None => 0,
        }
    }

    /// Records a successful authentication, resetting the failure count.
    pub fn record_success(&mut self) {
        self.failed_attempts = 0;
        self.locked_until = None;
    }

    /// Records a failed authentication, incrementing the failure count
    /// and starting a lockout if the threshold is reached.
    pub fn record_failure(&mut self) {
        self.failed_attempts = self.failed_attempts.saturating_add(1);
        if self.failed_attempts >= MAX_FAILED_ATTEMPTS {
            self.locked_until = Some(Instant::now() + LOCKOUT_DURATION);
        }
    }

    /// Checks if an auth attempt is allowed. Returns an error if locked.
    pub fn check(&self) -> Result<()> {
        if self.is_locked() {
            return Err(CoreError::RateLimited(self.lockout_remaining_secs()));
        }
        Ok(())
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limiter_starts_unlocked() {
        let limiter = RateLimiter::new();
        assert!(!limiter.is_locked());
        assert!(limiter.check().is_ok());
    }

    #[test]
    fn rate_limiter_locks_after_max_failures() {
        let mut limiter = RateLimiter::new();
        for _ in 0..MAX_FAILED_ATTEMPTS {
            limiter.record_failure();
        }
        assert!(limiter.is_locked());
        assert!(limiter.check().is_err());
    }

    #[test]
    fn rate_limiter_resets_on_success() {
        let mut limiter = RateLimiter::new();
        limiter.record_failure();
        limiter.record_failure();
        limiter.record_success();
        assert_eq!(limiter.failed_attempts, 0);
        assert!(!limiter.is_locked());
    }

    #[test]
    fn rate_limiter_remaining_secs_zero_when_unlocked() {
        let limiter = RateLimiter::new();
        assert_eq!(limiter.lockout_remaining_secs(), 0);
    }
}

//! Constant-time comparison operations.
//!
//! All comparisons of secret material (passwords, HMACs, MACs) MUST use
//! these functions to prevent timing attacks.

use subtle::ConstantTimeEq;

use super::error::{CryptoError, Result};

/// Compares two byte slices in constant time, returning `true` if equal.
///
/// Returns `false` if the slices are different lengths (still constant-time
/// over the input length).
#[must_use]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Compares two fixed-size arrays in constant time.
#[must_use]
pub fn ct_eq_array<const N: usize>(a: &[u8; N], b: &[u8; N]) -> bool {
    a.ct_eq(b).into()
}

/// Verifies an HMAC in constant time. Returns `Ok(())` on match, `Err` on mismatch.
///
/// Use this for password verification, MAC verification, and tag checking.
pub fn ct_verify(a: &[u8], b: &[u8]) -> Result<()> {
    if ct_eq(a, b) {
        Ok(())
    } else {
        Err(CryptoError::HmacMismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ct_eq_equal() {
        let a = [1u8, 2, 3, 4];
        let b = [1u8, 2, 3, 4];
        assert!(ct_eq(&a, &b));
        assert!(ct_eq_array(&a, &b));
    }

    #[test]
    fn ct_eq_not_equal() {
        let a = [1u8, 2, 3, 4];
        let b = [1u8, 2, 3, 5];
        assert!(!ct_eq(&a, &b));
        assert!(!ct_eq_array(&a, &b));
    }

    #[test]
    fn ct_eq_different_length() {
        let a = [1u8, 2, 3, 4];
        let b = [1u8, 2, 3];
        assert!(!ct_eq(&a, &b));
    }

    #[test]
    fn ct_verify_match() {
        let a = [1u8, 2, 3, 4];
        let b = [1u8, 2, 3, 4];
        assert!(ct_verify(&a, &b).is_ok());
    }

    #[test]
    fn ct_verify_mismatch() {
        let a = [1u8, 2, 3, 4];
        let b = [1u8, 2, 3, 5];
        assert!(ct_verify(&a, &b).is_err());
    }
}

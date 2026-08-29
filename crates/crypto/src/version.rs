//! Versioned encryption format (algorithm agility).
//!
//! Each encrypted blob starts with a 1-byte version tag, allowing
//! future migration to new algorithms without breaking existing data.

use super::error::{CryptoError, Result};

/// Current encryption version.
pub const CURRENT_VERSION: u8 = 1;

/// Crypto format version (alias of CURRENT_VERSION, semver-style).
pub const CRYPTO_VERSION: &str = "1.0.0";

/// Encrypted blob header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncryptedHeader {
    /// Format version.
    pub version: u8,
    /// Algorithm identifier (0 = AES-256-GCM).
    pub algorithm: u8,
}

impl EncryptedHeader {
    /// Current header (version 1, AES-256-GCM).
    pub const V1_AES_GCM: Self = Self {
        version: 1,
        algorithm: 0,
    };

    /// Serializes the header to bytes.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 2] {
        [self.version, self.algorithm]
    }

    /// Parses a header from bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the version is unsupported.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 2 {
            return Err(CryptoError::UnsupportedVersion(0));
        }
        let header = Self {
            version: bytes[0],
            algorithm: bytes[1],
        };
        if header.version > CURRENT_VERSION {
            return Err(CryptoError::UnsupportedVersion(header.version));
        }
        Ok(header)
    }
}

/// Builds the full encrypted blob: header || nonce || ciphertext.
pub fn build_blob(header: EncryptedHeader, nonce: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let mut blob = Vec::with_capacity(2 + nonce.len() + ciphertext.len());
    blob.extend_from_slice(&header.to_bytes());
    blob.extend_from_slice(nonce);
    blob.extend_from_slice(ciphertext);
    blob
}

/// Parses a full encrypted blob into (header, nonce, ciphertext).
///
/// # Errors
///
/// Returns an error if the blob is too short or the version is unsupported.
pub fn parse_blob(blob: &[u8]) -> Result<(EncryptedHeader, [u8; 12], &[u8])> {
    if blob.len() < 2 + 12 {
        return Err(CryptoError::UnsupportedVersion(0));
    }
    let header = EncryptedHeader::from_bytes(&blob[..2])?;
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&blob[2..14]);
    let ciphertext = &blob[14..];
    Ok((header, nonce, ciphertext))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_round_trip() {
        let original = EncryptedHeader::V1_AES_GCM;
        let bytes = original.to_bytes();
        let parsed = EncryptedHeader::from_bytes(&bytes).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn unsupported_version_rejected() {
        let bytes = [99, 0];
        let result = EncryptedHeader::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn blob_round_trip() {
        let nonce = [1u8; 12];
        let ciphertext = vec![2, 3, 4, 5];
        let blob = build_blob(EncryptedHeader::V1_AES_GCM, &nonce, &ciphertext);
        let (header, parsed_nonce, parsed_ct) = parse_blob(&blob).unwrap();
        assert_eq!(header, EncryptedHeader::V1_AES_GCM);
        assert_eq!(parsed_nonce, nonce);
        assert_eq!(parsed_ct, ciphertext.as_slice());
    }

    #[test]
    fn short_blob_rejected() {
        let short = vec![1, 0, 1]; // Only 3 bytes, need at least 14
        let result = parse_blob(&short);
        assert!(result.is_err());
    }
}

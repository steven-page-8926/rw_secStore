# ADR-005: SSH Key Management via `ssh-key` Crate

**Status**: Accepted
**Date**: 2026-08-29
**Deciders**: ForgeCode, RapidWebs Engineering
**Supersedes**: None
**Related**: SPEC-2026-001 v1.1.0 (REQ-SSH-001 through REQ-SSH-003)

## Context

rw_secstore v1.1.0 needs to store and export SSH key pairs for fleet management (VMs, servers, workstations, GitHub accounts). The SPEC requires OpenSSH private key format (`BEGIN OPENSSH PRIVATE KEY`) and authorized_keys public key format.

Options for SSH key handling in Rust:

1. **`ssh-key` crate (Pure Rust)**: Modern, pure Rust SSH key parser/generator. Supports Ed25519, RSA, ECDSA, DSA. Generates OpenSSH format directly. Maintained by RustCrypto/WireGuard.

2. **`thrussh` keys (Pure Rust)**: SSH protocol implementation, includes key types. More complex, more dependencies.

3. **Shell out to `ssh-keygen`**: Reliable but requires OpenSSH installed, harder to test, not pure Rust.

4. **Custom implementation**: Not viable, complex protocol.

## Decision

Use the **`ssh-key` crate** as the primary SSH key handling library.

**Rationale**:
- Pure Rust, no system dependencies (matches our no-OpenSSL requirement)
- Generates OpenSSH format directly (no conversion needed)
- Supports all required key types: Ed25519, RSA (2048/4096), ECDSA (P-256/P-384)
- Well-maintained, security-audited
- Allows passphrase-protected private keys (for SSH key passphrase feature)

**Deferred to v1.1**: SSH provisioning, SSH certificates, known_hosts, SSH agent (these require more network/system integration than pure crypto).

## Consequences

### Positive
- Single dependency for all SSH key operations
- Pure Rust = reproducible builds, no platform-specific bugs
- Easy to test (deterministic output)

### Negative
- `ssh-key` crate may not support latest OpenSSH extensions (acceptable for v1)
- Newer than OpenSSH, possible edge cases
- Version-locked to OpenSSH format version supported by crate

### Risks
- `ssh-key` v0.6+ stable, widely used in production
- We can fall back to PEM (PKCS#8) format for interop if OpenSSH format has issues

## Implementation Notes

```rust
// Storage
use ssh_key::{PrivateKey, PublicKey, Algorithm};

let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)?;
let openssh_pem = key.to_openssh(LineEnding::LF)?; // BEGIN OPENSSH PRIVATE KEY

// Export
let pkcs8_pem = key.to_pkcs8(LineEnding::LF)?; // For OpenSSL interop
let public_openssh = key.public_key().to_openssh()?; // authorized_keys format
```

## Alternatives Reconsidered

- **Shell out to ssh-keygen**: Rejected. Requires system OpenSSH, complicates testing, breaks single-binary deployment.
- **`rsa` + custom OpenSSH encoder**: Rejected. Reinventing the wheel, error-prone.
- **Defer SSH to v1.1 entirely**: Considered. But SSH key storage is the most common use case for a personal keystore; including storage now while deferring provisioning keeps value high without complexity.

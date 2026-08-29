# ADR-008: OS Keyring via `keyring` Crate for Master Encryption Key

**Status**: Accepted
**Date**: 2026-08-29
**Deciders**: ForgeCode, RapidWebs Engineering, Security Team
**Supersedes**: None
**Related**: SPEC-2026-001 v1.1.0 (REQ-AUTH-001)

## Context

rw_secstore v1.1.0 introduces multi-factor unlock. The first factor is the OS keyring (libsecret on Linux, Credential Manager on Windows, Keychain on macOS). This stores a 256-bit Master Encryption Key (MEK) that bypasses Argon2id derivation.

Options for OS keyring access:

1. **`keyring` crate (Pure Rust wrapper)**: Cross-platform abstraction. Supports Linux (libsecret via dbus), macOS (Keychain), Windows (Credential Manager). Most popular Rust keyring lib.

2. **Platform-specific crates**: `linux-keyutils`, `keyring-rs` (older), `security-framework` (macOS). More work, more deps.

3. **Shell out to platform tools**: `secret-tool` (Linux), `security` (macOS), `cmdkey` (Windows). External deps, hard to test.

4. **TPM/HSM**: Out of scope for v1.

## Decision

Use the **`keyring` crate** for OS keyring access, with the **MEK (Master Encryption Key) pattern**.

**Pattern**:
1. On `init --keyring`: generate 256-bit random MEK
2. Store MEK in OS keyring with label `rw-secstore-master-key`
3. MEK replaces KEK (no Argon2id needed for keyring unlock)
4. On unlock: retrieve MEK from keyring → decrypt DEKs directly
5. Password becomes optional (fallback if keyring unavailable)

**Backend selection**:
- Linux: libsecret (preferred), secret-service over D-Bus
- macOS: Keychain
- Windows: Credential Manager (wincred)
- Fallback: error if none available (user must use password)

## Consequences

### Positive
- No master password typing required (UX win for daily use)
- MEK is stronger than password-derived KEK (256 random bits vs ~80 bits entropy)
- Cross-platform via single crate
- Fallback to password for recovery scenarios

### Negative
- Requires keyring service running (libsecret, keychain)
- On Linux headless servers without D-Bus, keyring unavailable (fallback to password)
- Keyring access requires user session (not systemd service without PAM)
- MEK is device-bound (no syncing across machines)

### Risks
- Keyring fragmentation across distros: tested on Ubuntu, Fedora, Arch
- Linux keyring can be cleared on logout (depends on PAM config)
- Lost keyring = lost MEK = must use password or backup code to recover

## Implementation Notes

```rust
use keyring::Entry;

const KEYRING_LABEL: &str = "rw-secstore-master-key";
const KEYRING_USER: &str = "default"; // Or actual OS user

pub fn store_mek(mek: &[u8; 32]) -> Result<()> {
    let entry = Entry::new(KEYRING_LABEL, KEYRING_USER)?;
    entry.set_password(&hex::encode(mek))?;
    Ok(())
}

pub fn retrieve_mek() -> Result<[u8; 32]> {
    let entry = Entry::new(KEYRING_LABEL, KEYRING_USER)?;
    let hex = entry.get_password()?;
    let bytes = hex::decode(&hex)?;
    let mut mek = [0u8; 32];
    mek.copy_from_slice(&bytes);
    Ok(mek)
}

pub fn remove_mek() -> Result<()> {
    let entry = Entry::new(KEYRING_LABEL, KEYRING_USER)?;
    entry.delete_credential()?;
    Ok(())
}
```

**Configuration**:
```toml
[keyring]
enabled = false
backend = "auto"  # auto, libsecret, wincred, keychain
label = "rw-secstore-master-key"
```

**Lifecycle**:
- `init --keyring`: generate MEK, store in keyring
- `config keyring enable`: generate MEK post-init, store in keyring (requires unlock to access DEKs to re-encrypt)
- `config keyring disable`: remove MEK from keyring (requires password unlock first)
- `unlock`: tries keyring → password → backup code (in order)

## Alternatives Reconsidered

- **TPM2 directly**: Cross-platform nightmare (Intel PTT, AMD fTPM, discrete TPM). Defer to v2.
- **PKCS#11**: Requires HSM. Defer to v2.
- **File-based MEK with 0o600**: Simpler but no UX win, no per-user isolation.
- **YubiKey/OpenPGP**: Hardware dep, niche. Defer to FIDO2 in v1.1.

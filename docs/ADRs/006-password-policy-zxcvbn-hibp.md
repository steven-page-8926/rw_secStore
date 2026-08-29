# ADR-006: Password Policy via zxcvbn + HIBP k-Anonymity

**Status**: Accepted
**Date**: 2026-08-29
**Deciders**: ForgeCode, RapidWebs Engineering, Security Team
**Supersedes**: None
**Related**: SPEC-2026-001 v1.1.0 (REQ-PWD-001 through REQ-PWD-004)

## Context

rw_secstore v1.1.0 requires strong password policy enforcement on the master password. Without a policy, users can pick weak passwords like "password123" that are trivially brute-forced.

Requirements:
- Minimum length, entropy, character class requirements
- Detection of common patterns (keyboard walks, repetitions)
- Breach detection (HaveIBeenPwned)
- Strength estimation (zxcvbn-style)

Options:

1. **Custom policy engine**: Build from scratch. Pro: zero deps. Con: reinventing, likely worse than established algorithms.

2. **`zxcvbn` crate (Pure Rust)**: Drop-in port of the Dropbox zxcvbn algorithm. Industry standard for password strength estimation.

3. **`pwned` crate (HIBP API)**: Online k-anonymity API check. 8-character SHA-1 prefix sent over HTTPS, returns list of suffixes seen >N times. Privacy-preserving (can't reconstruct full hash from prefix).

4. **Bundled top 100k common passwords**: Offline list, no network. Bundled at build time. No API key.

## Decision

Use **`zxcvbn` for strength estimation** + **bundled top-100k common passwords list (offline) for default breach check** + **opt-in HIBP k-anonymity API for online breach check**.

**Rationale**:
- zxcvbn is the de facto standard for password strength estimation
- Offline list provides zero-network breach detection by default
- HIBP opt-in for users who want stronger guarantees (with cache to limit API calls)
- All three are pure Rust (or trivially bundled data)

## Consequences

### Positive
- Users get industry-standard strength feedback
- No network dependency by default (offline mode)
- Opt-in online check respects privacy
- Configurable: users can disable breach check entirely

### Negative
- zxcvbn crate has had API changes (we'll pin to a specific version)
- Top-100k list adds ~1MB to binary
- HIBP API requires `reqwest` (we already have it via `rusqlite` deps? No, separate dep)

### Risks
- HIBP API rate limits: cache for 24h mitigates
- Top-100k list is per-language (we bundle English; other languages need separate list)
- zxcvbn may flag valid diceware passphrases as weak (entropy check is separate from pattern check)

## Implementation Notes

```rust
use zxcvbn::zxcvbn;

let entropy = zxcvbn(&password, &[]).unwrap();
let score = entropy.score(); // 0-4
let guesses = entropy.guesses(); // Estimated guesses needed

// HIBP offline check
if COMMON_PASSWORDS.contains(&password) {
    return Err(Error::PasswordBreached);
}

// HIBP online check (opt-in)
if config.breach_check == "online" {
    let prefix = sha1(&password)[0..5];
    let suffixes = hibp_api::query(prefix).await?;
    if suffixes.iter().any(|s| s.suffix == sha1(&password)[5..]) {
        return Err(Error::PasswordBreached);
    }
}
```

## Policy Configuration (Defaults)

```toml
[password_policy]
min_length = 16
min_entropy_bits = 80
require_uppercase = true
require_lowercase = true
require_digits = true
require_symbols = true
max_consecutive_identical = 3
history_depth = 5
breach_check = "offline"  # "offline" | "online" | "disabled"
```

## Alternatives Reconsidered

- **NIST SP 800-63B password guidelines**: Required for compliance. We'll add a `nist-strict` policy preset in v1.1.
- **Custom entropy calculation**: Insufficient. zxcvbn considers patterns, not just entropy.
- **HIBP only (no offline)**: Rejected for v1. Offline default = works air-gapped.

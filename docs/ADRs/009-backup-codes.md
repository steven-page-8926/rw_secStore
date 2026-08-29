# ADR-009: Backup Codes for Emergency Recovery

**Status**: Accepted
**Date**: 2026-08-29
**Deciders**: ForgeCode, RapidWebs Engineering, Security Team
**Supersedes**: None
**Related**: SPEC-2026-001 v1.1.0 (REQ-AUTH-002, REQ-AUTH-003)

## Context

rw_secstore v1.1.0 supports multi-factor unlock (password + keyring + backup codes). The third factor is **backup codes** — single-use recovery codes (Google/GitHub pattern) for emergency access when both password and keyring are unavailable.

Requirements:
- 8 codes (configurable, default 8)
- Single-use (consumed after one unlock)
- High entropy (80 bits each = sufficient to derive a key)
- Stored encrypted (not plaintext in DB)
- Displayed once on generation

Options:

1. **Standard pattern (Google/GitHub)**: 16-char base32 codes, 80 bits entropy each. User writes them down, keeps in safe.

2. **TOTP-style 6-digit codes**: Lower entropy (~20 bits), too easy to brute-force.

3. **Recovery key file (single key)**: 256-bit, but no per-use tracking.

4. **BIP-39 mnemonic**: 12/24 words. Overkill for backup codes, better suited for HD wallets.

## Decision

Implement **Google-style 16-character base32 backup codes** (80 bits entropy each), with 8 default count.

**Pattern**:
- 16 base32 chars (5 bits each) = 80 bits
- 8 codes per generation (configurable 1-20)
- Each code used once, then marked consumed
- Stored as Argon2id hash in DB (per-code salt)
- On unlock, code verified against hash, MEK decrypted, code marked consumed atomically
- Rate limit: 3 attempts per minute (prevents brute-force)

**Display format**: `ABCD-EFGH-IJKL-MNOP` (4 groups of 4 for readability)

## Consequences

### Positive
- Standard pattern (familiar to users)
- 80 bits × 8 codes = significant recovery budget
- Per-use tracking prevents code reuse
- Rate limiting prevents brute-force

### Negative
- 8 codes = 8 chances to lose the database (each consumed = one less recovery option)
- Must be stored somewhere (printed, password manager, safe)
- Display once on generation (UX: warn user strongly)

### Risks
- User loses all 8 codes + password + keyring = unrecoverable (documented)
- Brute-force: 80 bits = infeasible even at 1M attempts/sec (would take 38 million years)
- Generation must be cryptographically random (OsRng)

## Implementation Notes

```rust
use rand::rngs::OsRng;
use rand::RngCore;
use base32::{Alphabet, encode};

// Crockford base32 alphabet (excludes I, L, O, U for readability)
const BASE32_ALPHABET: Alphabet = Alphabet::Crockford;

pub fn generate_backup_code() -> String {
    let mut rng = OsRng;
    let mut bytes = [0u8; 10]; // 80 bits
    rng.fill_bytes(&mut bytes);
    let encoded = encode(BASE32_ALPHABET, &bytes);
    // Format: ABCD-EFGH-IJKL-MNOP (16 chars, 4 groups)
    format!(
        "{}-{}{}-{}{}-{}{}",
        &encoded[0..4], &encoded[4..5],
        &encoded[5..9], &encoded[9..10],
        &encoded[10..14], &encoded[14..15],
        &encoded[15..19], &encoded[19..20]
    )
}
```

**Storage**:
```sql
CREATE TABLE backup_codes (
    id TEXT PRIMARY KEY,         -- UUID v7
    code_hash TEXT NOT NULL,     -- Argon2id hash of code
    salt TEXT NOT NULL,          -- Per-code salt (base64)
    code_index INTEGER NOT NULL, -- 1-8 for display
    used_at INTEGER,             -- Null if unused
    created_at INTEGER NOT NULL,
    UNIQUE (code_index)
);
```

**Unlock flow**:
1. User: `unlock --backup-code ABCD-EFGH-IJKL-MNOP`
2. Strip dashes → 16 chars
3. Decode base32 → 10 bytes (80 bits)
4. For each unused code in DB: Argon2id verify(input, code_hash, salt)
5. If match: retrieve MEK from `keystore_meta` (encrypted with this code)
6. Mark code as used
7. Audit log: "unlock via backup code #3"

**MEK encryption by code**:
- During `backup-codes generate`: encrypt MEK with each code-derived key
- Store encrypted MEK per code in `backup_codes.encrypted_mek`
- (Alternative: encrypt MEK once with master_key derived from all codes combined; reject for simplicity)

**Rate limiting**:
- 3 failed attempts per minute per process
- Lockout after 10 failed attempts (audit log alert)

## Alternatives Reconsidered

- **6-digit codes (TOTP)**: Too low entropy. Reject.
- **BIP-39 mnemonic**: Overkill, confusing for non-crypto users. Reject for v1.
- **Recovery key (single 256-bit)**: No per-use tracking, no fallback. Reject.
- **PGP wordlist**: 512 words × 24 = poor entropy density. Reject.

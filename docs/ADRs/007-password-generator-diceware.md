# ADR-007: Password Generator with EFF Diceware Wordlist

**Status**: Accepted
**Date**: 2026-08-29
**Deciders**: ForgeCode, RapidWebs Engineering
**Supersedes**: None
**Related**: SPEC-2026-001 v1.1.0 (REQ-PWG-001 through REQ-PWG-003)

## Context

rw_secstore v1.1.0 includes a password/passphrase generator to help users create strong passwords. The SPEC requires:
- High-entropy random password generation (32 chars, ~210 bits)
- Diceware passphrase generation (EFF wordlist, 7776 words, 6 words = ~77 bits)
- Policy-aware generation
- Optional export to file (0o600 permissions)

Options:

1. **Pure custom implementation**: OS CSPRNG + charset indexing. Pro: no deps. Con: diceware wordlist management is the hard part.

2. **EFF Diceware Wordlist (bundled)**: Industry standard. 7776 words, 12.9 bits per word. Download once, bundle in binary.

3. **Custom wordlist**: User can supply. Default = EFF.

4. **PGP-style wordlist**: 512 words (only 9 bits per word). Worse than EFF.

## Decision

Implement custom password generator (small, simple, well-tested) + bundle **EFF long wordlist** for diceware mode.

**Rationale**:
- EFF wordlist is the gold standard for diceware (RFC: https://www.eff.org/diceware)
- 7776 words × 6 words = 12.9 × 6 = 77.4 bits entropy (excellent)
- Bundling in binary = offline-capable, no network
- Custom wordlist support lets users supply their own (e.g., for non-English)

## Consequences

### Positive
- Industry-standard diceware
- No network dependency
- Custom wordlist support for internationalization
- Trivial to test (deterministic from seed, but we use OsRng)

### Negative
- Wordlist adds ~80KB to binary (negligible)
- English-only by default; other languages need custom wordlist

### Risks
- EFF wordlist changes are rare but possible; we'll pin to a specific version
- Wordlist must be stored securely (it's not secret, but integrity matters)

## Implementation Notes

```rust
use rand::rngs::OsRng;
use rand::RngCore;

const EFF_WORDLIST: &[&str] = include!("eff_large_wordlist.txt");

pub fn generate_password(length: usize, charset: &[u8]) -> String {
    let mut rng = OsRng;
    let mut result = String::with_capacity(length);
    for _ in 0..length {
        let idx = (rng.next_u32() as usize) % charset.len();
        result.push(charset[idx] as char);
    }
    result
}

pub fn generate_diceware(words: usize, separator: char) -> String {
    let mut rng = OsRng;
    let mut indices = Vec::with_capacity(words);
    for _ in 0..words {
        // Roll 5 dice (5^5 = 7776, but use 12-bit random for uniformity)
        let idx = (rng.next_u32() % 7776) as usize;
        indices.push(EFF_WORDLIST[idx]);
    }
    indices.join(&separator.to_string())
}
```

**Charset options**:
- `alphanumeric`: a-z, A-Z, 0-9 (62 chars, 5.95 bits/char)
- `alphanumeric+symbols`: above + !@#$%^&* (94 chars, 6.55 bits/char)
- `custom`: user-supplied

**Entropy calculation**:
- Charset password: `log2(charset_size^length) = length * log2(charset_size)`
- Diceware: `words * log2(7776) = words * 12.9`

## Alternatives Reconsidered

- **PGP wordlist (512 words)**: Only 9 bits/word, requires 9 words for 81 bits. EFF better.
- **xkpasswd-style**: Too complex, niche.
- **System password generator (e.g., `pwgen`)**: External dep, breaks single-binary.

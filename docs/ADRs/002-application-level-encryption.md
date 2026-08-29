# ARCHITECTURE DECISION RECORD 002
## Industry Standard Format for ADRs (2026)

## Document Identification
- **ADR ID**: 002
- **Title**: Application-Level Encryption with Argon2id + AES-256-GCM
- **Status**: Accepted
- **Date**: 2026-08-28
- **Author**: ForgeCode / RapidWebs
- **Stakeholders**: RapidWebs Engineering, Security Team, Operations

## Table of Contents
1. [Context](#1-context)
2. [Decision](#2-decision)
3. [Status](#3-status)
4. [Consequences](#4-consequences)
5. [Implications](#5-implications)
6. [Related Documents](#6-related-documents)

---

## 1. Context

### Problem Statement
rw_secstore must protect sensitive key material (private keys, symmetric keys, secrets) at rest in the SQLite database. The encryption must:
- Be resistant to offline attacks if database file is stolen
- Allow master password change without full re-encryption of all data (efficient rekey)
- Use industry-standard, FIPS 140-3 approved algorithms
- Not require external key management infrastructure
- Support per-entry encryption keys for compartmentalization

### Drivers
- **Security**: Defense in depth - database encryption + application encryption
- **Compliance**: SOC2, ISO27001 require encryption of secrets at rest
- **Usability**: Single master password, no key files to manage
- **Performance**: Encryption/decryption must be fast for CLI UX
- **Portability**: Pure Rust implementation preferred

### Assumptions
- Master password has sufficient entropy (user responsibility, enforced by policy)
- Argon2id parameters can be tuned for target hardware
- AES-NI available on target CPUs (fallback to software)
- Threat model: stolen database file, not runtime memory extraction

### Constraints
- No HSM/PKCS#11 in v1
- No SQLCipher (licensing, system dependency)
- Must support password change (rekey) operation
- Must zeroize secrets in memory

## 2. Decision

### Decision Statement
**Use application-level encryption with a two-tier key hierarchy: Master Password → Argon2id → KEK → (per-entry) DEK → AES-256-GCM for key material.**

### Key Hierarchy

```
Master Password (user input)
        │
        ▼
    Argon2id (salt: 32 bytes, memory=64MB, iter=3, parallel=4)
        │
        ▼
    KEK (Key Encryption Key, 32 bytes)
        │
        ├──▶ DEK₁ (32 bytes, random) ──▶ AES-256-GCM ──▶ Entry 1 private key
        ├──▶ DEK₂ (32 bytes, random) ──▶ AES-256-GCM ──▶ Entry 2 private key
        ├──▶ DEK₃ (32 bytes, random) ──▶ AES-256-GCM ──▶ Entry 3 symmetric key
        └──▶ ...
```

### Storage Format (per encrypted entry)
```
[salt(32)][nonce(12)][ciphertext+tag]
 │         │         │
 │         │         └── AES-256-GCM output (plaintext + 16-byte tag)
 │         └── Random per encryption (96-bit)
 └── Random per entry (256-bit), used to derive DEK from KEK
```

Actually, simpler format per DeTLS reference:
```
[salt(32)][nonce(12)][ciphertext+tag]
```
Where:
- `salt`: 32 bytes, used with KEK to derive per-entry DEK via HKDF
- `nonce`: 12 bytes, random per encryption
- `ciphertext+tag`: AES-256-GCM output

### Considered Alternatives

#### Alternative 1: SQLCipher (Transparent Database Encryption)
- **Pros**: Encrypts entire database, no application changes
- **Cons**: 
  - Commercial license for full features
  - Single key for entire DB (no per-entry compartmentalization)
  - Password change requires full DB re-encryption (slow, risky)
  - System dependency (not pure Rust)
  - Less control over key derivation parameters

#### Alternative 2: Single KEK for All Entries (No DEK)
- **Pros**: Simpler, faster
- **Cons**: 
  - Key reuse across entries (cryptographic best practice violation)
  - If one entry's nonce reused, catastrophic failure
  - No forward secrecy between entries

#### Alternative 3: Age/rage (Modern Encryption Tool)
- **Pros**: Modern, simple, good CLI
- **Cons**: 
  - Designed for file encryption, not database records
  - No native Rust library for programmatic use (shell out required)
  - No per-entry key hierarchy

#### Alternative 4: libsodium/NaCl (crypto_secretbox)
- **Pros**: High-level API, hard to misuse
- **Cons**: 
  - XChaCha20-Poly1305 not FIPS 140-3 approved
  - Less common in enterprise environments
  - Argon2id not in libsodium (separate dependency)

#### Alternative 5: Per-Entry Password (No Master Password)
- **Pros**: Maximum compartmentalization
- **Cons**: 
  - Terrible UX (password per key)
  - No single unlock operation
  - Key management nightmare

### Decision Rationale
The two-tier hierarchy (KEK + per-entry DEK) provides:
1. **Compartmentalization**: Compromise of one DEK doesn't affect others
2. **Efficient Rekey**: Password change only re-wraps DEKs (not re-encrypts all key material)
3. **FIPS 140-3 Compliance**: Argon2id (KDF) + AES-256-GCM (AEAD) both approved
4. **Pure Rust**: `argon2`, `aes-gcm`, `hkdf` crates are pure Rust
5. **Reference Validation**: DeTLS uses identical pattern (Argon2id + AES-GCM per entry)
6. **Industry Standard**: Matches NIST SP 800-57 key hierarchy recommendations

### Implementation Approach
- `argon2` crate with `argon2id` variant
- `aes-gcm` crate with `Aes256Gcm` (AES-NI accelerated)
- `hkdf` crate for DEK derivation: `HKDF-SHA256(KEK, salt, info="rw-secstore-dek")`
- `zeroize` crate for automatic memory zeroization
- `subtle` crate for constant-time comparisons
- Salt stored per-entry (32 bytes)
- Nonce generated per encryption (12 bytes, random)
- KEK cached in memory only while unlocked (cleared on lock/exit)

## 3. Status
**Accepted** - Ready for implementation

## 4. Consequences

### 4.1 Positive Consequences
- Strong security: per-entry keys, authenticated encryption
- Efficient password change: only DEKs re-wrapped
- FIPS 140-3 compliant algorithms
- Pure Rust, no system dependencies
- Proven pattern (DeTLS reference)
- Compartmentalization limits blast radius

### 4.2 Negative Consequences
- Slightly more complex than single-key encryption
- Two encryption operations per entry (DEK wrap + data encrypt)
- Must manage salt/nonce storage per entry
- KEK in memory while unlocked (mitigated: zeroize on lock)

### 4.3 Neutral Consequences
- Backup includes encrypted DEKs (portable across password changes)
- Schema stores salt+nonce+ciphertext as single BLOB

## 5. Implications

### 5.1 Architectural Implications
- `CryptoService` module handles all encryption/decryption
- `KeystoreService` uses `CryptoService` for entry operations
- `rekey` operation: decrypt all DEKs with old KEK, re-encrypt with new KEK
- Memory management: `Zeroizing<Vec<u8>>` for all secrets

### 5.2 Technical Implications
- Dependencies: `argon2`, `aes-gcm`, `hkdf`, `zeroize`, `subtle`, `rand`
- Argon2id params configurable via config file
- Salt for KEK derivation stored in `keystore_meta` table
- Per-entry salt stored with encrypted blob

### 5.3 Organizational Implications
- Security team reviews crypto implementation
- Password policy documented (min length, complexity)
- Incident response: database theft = rotate master password + rekey

### 5.4 Financial Implications
- No licensing costs
- Pure Rust = no C/C++ audit surface

### 5.5 Schedule Implications
- Crypto module implemented first (foundation for all else)
- ~2-3 days for robust implementation with tests

## 6. Related Documents
- **SPEC-2026-001**: Core specification (encryption requirements)
- **ADR-001**: SQLite storage backend (encryption at application layer)
- **Reference**: DeTLS (polyjuicelab/DeTLS) - identical encryption pattern
- **NIST SP 800-57 Part 1**: Key Management Recommendations
- **RFC 9106**: Argon2 Memory-Hard Function
- **NIST SP 800-38D**: AES Galois/Counter Mode
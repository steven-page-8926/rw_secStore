# Bug Review: rw_secstore v1.1.0 Plan v2.1

**Audit ID**: BUG-2026-001-v1.1
**Date**: 2026-08-29
**Auditor**: ForgeCode
**Subject**: PLAN-2026-001 v2.1 (HIGH mode)
**Methodology**: Find logic errors, security bugs, code-quality issues before implementation

---

## Critical Bugs

### BUG-C-001 (CRITICAL): Argon2id params could be parsed from DB
**Description**: If params are stored in `keystore_meta` and attacker modifies them (downgrade), could brute-force.
**Fix**: Hardcoded minimums in code, params in DB are HINTS only (plan 1.3.1 partially addresses). Verify in code review.
**Location**: Plan §1.3.1

### BUG-C-002 (CRITICAL): No verification that `password` matches `password_hash` on rekey
**Description**: Rekey requires current password (per SPEC). Plan 2.5.4 doesn't specify verification step.
**Fix**: Plan 2.5.4 must verify current password before generating new KEK
**Location**: Plan §2.5.4

### BUG-C-003 (CRITICAL): HMAC key derived from KEK: chicken-and-egg
**Description**: HMAC seal (plan 1.8.1) uses KEK. But KEK is only available after unlock. On first open, no HMAC possible.
**Fix**: Plan 1.8.1 must use a "verification KEK" derived at init (e.g., from password + master salt + "verify" context), separate from encryption KEK
**Location**: Plan §1.8

### BUG-C-004 (CRITICAL): MEK encryption by backup code uses same KDF as password
**Description**: If backup code DB is leaked AND password DB is leaked, attacker can verify both.
**Fix**: Use separate Argon2id parameters (different memory/iterations) for backup codes to prevent rainbow table reuse
**Location**: Plan §1.4.4, §1.4.5

---

## High Bugs

### BUG-H-001 (HIGH): Off-by-one in key expiration check
**Description**: `expires_at < now` vs `expires_at <= now` could allow expired key use.
**Fix**: Use `expires_at <= now` (or `expires_at < now_unix_ms`) consistently
**Location**: Plan §2.1.4 (expires_at metadata)

### BUG-H-002 (HIGH): CSR nonce not bound to issuing CA
**Description**: CSR nonce in plan 3.3.6 doesn't bind to CA. Attacker can replay CSR for different CA.
**Fix**: Store `(ca_id, csr_hash, timestamp)` together
**Location**: Plan §3.3.6

### BUG-H-003 (HIGH): Password file read doesn't handle symlinks
**Description**: `--password-file /path/to/symlink` could point to attacker-controlled file.
**Fix**: Use `std::fs::canonicalize` to resolve, then check target permissions
**Location**: Plan §1.6.1

### BUG-H-004 (HIGH): Key generation race in concurrent `key store`
**Description**: Two processes generate keys, both write to DB. SQLite handles locking, but UUID generation could collide.
**Fix**: Use UUID v7 with sub-millisecond precision + retry on collision
**Location**: Plan §2.1.1-2.1.3

### BUG-H-005 (HIGH): Argon2id salt is 32 bytes (good) but stored in keystore_meta as TEXT
**Description**: SQLite TEXT type stores UTF-8, but base64 is ASCII. Round-trip could mangle.
**Fix**: Store as BLOB (raw bytes), not TEXT
**Location**: Plan §1.2.3 (schema)

### BUG-H-006 (HIGH): ECDSA signature verification doesn't specify hash function
**Description**: ECDSA requires explicit hash. Plan 2.5.2 just says "verify".
**Fix**: Use SHA-256 by default (configurable to SHA-384, SHA-512)
**Location**: Plan §2.5.2

### BUG-H-007 (HIGH): Backup restore doesn't verify HMAC seal
**Description**: Plan 4.2.1 restores from backup. But plan 1.8.1 puts HMAC seal in `keystore_meta`. If backup has different schema version, seal verification breaks.
**Fix**: Recompute seal after restore
**Location**: Plan §4.2.1

### BUG-H-008 (HIGH): Audit log HMAC chain initial value not defined
**Description**: `hmac_0 = ?` — what's the first entry's previous hash?
**Fix**: Define: `hmac_0 = HMAC(key, 0x00...00 || genesis_entry_id)` (deterministic genesis)
**Location**: Plan §2.8.2

### BUG-H-009 (HIGH): `keyring` crate API differences across versions
**Description**: `keyring` crate v2.x and v3.x have different APIs. Plan doesn't pin.
**Fix**: Pin to specific version (e.g., 3.0+)
**Location**: Plan §1.4.3

### BUG-H-010 (HIGH): EFF wordlist not loaded until first use
**Description**: First diceware generation will be slow (file I/O). Should be loaded once at startup.
**Fix**: `OnceCell<HashMap<u16, &'static str>>` with embedded wordlist via `include_str!`
**Location**: Plan §1.5.7

---

## Medium Bugs

### BUG-M-001 (MEDIUM): `now()` not specified to be monotonic
**Description**: System clock can jump (NTP). Audit timestamps should be monotonic.
**Fix**: Use `std::time::Instant` for monotonic time + `SystemTime` for wall clock
**Location**: Plan §2.8.1

### BUG-M-002 (MEDIUM): Path traversal in --db-path
**Description**: `--db-path ../../etc/passwd` could write to arbitrary location.
**Fix**: Validate path, ensure within user's home or XDG data dir
**Location**: Plan §1.7.4

### BUG-M-003 (MEDIUM): Default config path could conflict with system
**Description**: `/etc/rw-secstore/config.toml` if run as root? Plan doesn't say.
**Fix**: Explicitly: only `~/.config/rw-secstore/`, never `/etc/`
**Location**: Plan §1.7.1

### BUG-M-004 (MEDIUM): Hardcoded Argon2id memory minimum 64MB could be too high for CI
**Description**: Some CI environments have 256MB total memory. Argon2id 64MB × parallelism 4 = 256MB.
**Fix**: Already addressed via `RW_SECSTORE_FAST_KDF` env var (8MB/1iter in CI)
**Location**: Plan §1.3.1 (verify env var is documented)

### BUG-M-005 (MEDIUM): No validation of `key_algorithm` on import
**Description**: User provides PEM, system doesn't validate it's actually the claimed algorithm.
**Fix**: Parse public key from PEM, compare to claimed algorithm
**Location**: Plan §2.1.5

### BUG-M-006 (MEDIUM): Soft-deleted records still consume disk space
**Description**: Soft delete never frees space; only `purge` does.
**Fix**: Document; add `vacuum` command in v1.1
**Location**: Plan §2.6.3

### BUG-M-007 (MEDIUM): `clap` derive macros generate struct, not interface
**Description**: If user has unusual shell escaping, command parsing fails.
**Fix**: Use `clap::CommandFactory` for help generation; document common pitfalls
**Location**: Plan §1.7.3

### BUG-M-008 (MEDIUM): SSH key passphrase uses same Argon2id params as master password
**Description**: Double Argon2id cost = slow SSH key ops.
**Fix**: Use cheaper KDF (scrypt with lower params) for SSH key passphrase
**Location**: Plan §2.3.8

### BUG-M-009 (MEDIUM): Output format `csv` not tested for edge cases
**Description**: CSV with newlines in fields, embedded quotes, etc.
**Fix**: Use `csv` crate with proper escaping
**Location**: Plan §2.4.2

### BUG-M-010 (MEDIUM): Backup size reported as bytes but displayed in human-readable
**Description**: Inconsistent units could confuse users.
**Fix**: Always human-readable with explicit unit (e.g., "1.5 MB")
**Location**: Plan §4.1.2

### BUG-M-011 (MEDIUM): `key delete --soft` vs `key delete` behavior unclear
**Description**: SPEC says all delete is soft. Plan 2.6.1 vs 2.6.3 — which is default?
**Fix**: Document: `key delete` is soft, `key delete --purge` is hard
**Location**: Plan §2.6

### BUG-M-012 (MEDIUM): No mention of `setrlimit` for core dumps
**Description**: Core dump could contain decrypted keys.
**Fix**: Plan 5.4.4 must include `setrlimit(RLIMIT_CORE, 0)` at startup
**Location**: Plan §5.4.4

---

## Low Bugs

### BUG-L-001 (LOW): Inconsistent error types (`anyhow` vs `thiserror`)
**Fix**: Use `thiserror` for library errors, `anyhow` for CLI top-level

### BUG-L-002 (LOW): `unwrap()` in production code paths
**Fix**: Clippy rule `unwrap_used = "deny"`

### BUG-L-003 (LOW): Magic numbers (e.g., 0o600) scattered in code
**Fix**: Use named constants: `const DB_PERMS: u32 = 0o600`

### BUG-L-004 (LOW): `println!` for errors
**Fix**: Use `eprintln!` or `tracing::error!`

### BUG-L-005 (LOW): No `LICENSE` file in plan
**Fix**: Plan §7 should reference MIT LICENSE file

### BUG-L-006 (LOW): `Cargo.toml` workspace `members` should be sorted
**Fix**: Convention: sort members alphabetically

### BUG-L-007 (LOW): `Cargo.lock` not committed (per Rust convention)
**Fix**: Plan should explicitly state: commit `Cargo.lock` (it's an application, not a library)

### BUG-L-008 (LOW): No `Cargo.toml` lints section
**Fix**: Add `[lints.clippy]` and `[lints.rust]` sections

### BUG-L-009 (LOW): `unsafe` blocks allowed without justification
**Fix**: Clippy rule `unsafe_used = "deny"` in safe code, `unsafe_op_in_unsafe_fn = "deny"`

### BUG-L-010 (LOW): No documentation tests (`#[cfg(test)] mod tests` in docs)
**Fix**: Doctests for all public APIs

### BUG-L-011 (LOW): `dbg!` macro left in code
**Fix**: Clippy rule `dbg_macro = "deny"`

### BUG-L-012 (LOW): Inconsistent naming (e.g., `mek` vs `MEK` vs `Mek`)
**Fix**: Establish naming convention doc

### BUG-L-013 (LOW): `Result<(), Error>` instead of `Result<()>` when error is `()`
**Fix**: Use `Result<T>` where possible

### BUG-L-014 (LOW): No `Default` impl for config types
**Fix**: Provide `Default` for `Config`, `PasswordPolicy`, etc.

### BUG-L-015 (LOW): Excessive cloning (`clone()` everywhere)
**Fix**: Use references where possible; only clone when necessary

---

## Bug Review Summary

| Severity | Count |
|----------|-------|
| Critical | 4 |
| High | 10 |
| Medium | 12 |
| Low | 15 |
| **Total** | **41** |

### Required Actions (Critical)

1. **BUG-C-001**: Code-review check: hardcoded minimums
2. **BUG-C-002**: Add to plan 2.5.4: "Verify current password before rekey"
3. **BUG-C-003**: Plan 1.8.1 must derive separate "verification KEK" for HMAC seal
4. **BUG-C-004**: Use separate Argon2id params for backup code KDF

### High-Priority Actions

5. **BUG-H-001**: Consistent `<=` for expiration check
6. **BUG-H-002**: Bind CSR nonce to CA_id
7. **BUG-H-003**: Resolve symlinks before reading password file
8. **BUG-H-005**: Store salt as BLOB, not TEXT
9. **BUG-H-006**: Specify SHA-256 for ECDSA
10. **BUG-H-007**: Recompute HMAC seal after backup restore
11. **BUG-H-008**: Define HMAC chain genesis hash
12. **BUG-H-009**: Pin `keyring` crate version
13. **BUG-H-010**: Embed EFF wordlist via `include_str!`

---

**End of Bug Review**

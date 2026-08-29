# Bug Review — Logic, Security, Code Quality (HIGH Mode)

**Audit ID**: BUG-2026-001-HIGH
**Date**: 2026-08-29
**Auditor**: ForgeCode (plan-and-audit HIGH mode)
**Focus**: Logic errors, security anti-patterns, code quality risks in implementation plan
**SPEC Version**: 1.0.0
**Plan Version**: 1.0.0 (HIGH mode)

---

## Executive Summary

| Category | Count | Description |
|----------|-------|-------------|
| **Logic Errors** | 8 | Incorrect algorithms, state machine bugs, race conditions |
| **Security Anti-Patterns** | 10 | Crypto misuse, trust violations, insecure defaults |
| **Code Quality Risks** | 12 | Maintainability, testability, technical debt |
| **Total** | **30** | |

**Verdict**: **CONDITIONAL PASS** — Plan structure is sound but implementation details contain significant logic and security risks that must be addressed in task specifications.

---

## Logic Errors

### BUG-L-001: Database Migration — Schema Version Race Condition
**Location**: Plan Phase 1.2 (Database Schema + Migrations)
**Issue**: Migration runs on `open` but multiple processes could race on migration.
**Scenario**: 
1. Process A opens DB, sees v1, starts migration to v2
2. Process B opens DB, sees v1 (migration not committed), starts migration to v2
3. Both execute migration → constraint violations, data corruption
**Fix**: 
- Advisory lock (`PRAGMA locking_mode=EXCLUSIVE`) during migration
- Or: Single-process migration tool (`rw-secstore migrate`) run explicitly
- **Never** auto-migrate on library open

### BUG-L-002: WAL Mode — Checkpoint Starvation
**Location**: Plan Phase 1.2 (Pragmas)
**Issue**: `PRAGMA wal_autocheckpoint=1000` but long-running read transactions prevent checkpoint → WAL grows unbounded.
**Scenario**: 
1. Process A starts read transaction (holds `-shm` lock)
2. Process B writes 10k entries → WAL grows to GBs
3. Process A never commits → checkpoint never runs
4. Disk fills, performance degrades
**Fix**:
- Explicit `wal_checkpoint(TRUNCATE)` on `close` if writer
- Background checkpoint thread (if daemon mode)
- Monitor WAL size, warn if >100MB

### BUG-L-003: Key ID Generation — Collision Risk
**Location**: Plan Phase 2.1 (Key Creation)
**Issue**: UUIDv7 (timestamp + random) but if clock goes backward or same millisecond, collision possible.
**Scenario**: 
1. System clock adjusted backward (NTP)
2. Two keys created in same millisecond
3. UUIDv7 random portion (48 bits) — birthday bound at ~2^24 = 16M keys/ms
**Fix**:
- Use UUIDv4 (pure random, 122 bits) for key IDs
- Or: UUIDv7 + verify uniqueness on insert (retry on collision)
- Database `UNIQUE` constraint on `id` column (enforced)

### BUG-L-004: CA Serial Number — Collision / Predictability
**Location**: Plan Phase 3.1 (CA Creation)
**Issue**: Serial number generation method not specified. Sequential = predictable. Random = collision risk.
**Scenario**: 
- Sequential: Attacker predicts next serial → pre-compute collision
- Random 64-bit: Birthday bound at 2^32 = 4B certs (acceptable but not great)
**Fix**:
- RFC 5280: Serial MUST be unique per CA, positive, ≤20 octets
- Use 128-bit random (UUIDv4 without hyphens) or RFC 5280 compliant: `SHA256(issuer || time || counter)[:16]`
- Track issued serials in DB, reject duplicates

### BUG-L-005: Certificate Validity — Time Zone / DST Bugs
**Location**: Plan Phase 3.2 (Certificate Issuance)
**Issue**: `chrono::Utc::now()` for `not_before`/`not_after` but user input may be local time.
**Scenario**: 
- User specifies `--validity 365d` 
- Code adds `Duration::days(365)` to `Utc::now()`
- DST transition: 365 days ≠ 1 year in some zones
- Certificate expires 1 hour early/late
**Fix**:
- Always use UTC for certificate times
- Validity period = calendar duration (use `chrono::Duration::days` not hours)
- Document: "All times UTC. Validity is calendar days."

### BUG-L-006: Backup Restore — Partial Restore State
**Location**: Plan Phase 4.2 (Backup Restore)
**Issue**: Restore fails mid-way (disk full, corruption, kill -9) → DB in inconsistent state.
**Scenario**: 
1. Restore starts, writes 50% of entries
2. Disk full / process killed
3. DB has partial data, no rollback
4. Next open: schema version mismatch, foreign key violations
**Fix**:
- Restore to **temporary file** first
- Verify complete (row counts, checksums, schema)
- Atomic rename: `rename(temp, target)` (POSIX atomic)
- Original DB untouched until verify passes

### BUG-L-007: Rekey Operation — Partial Rekey State
**Location**: Plan Phase 2.4 (Rekey)
**Issue**: Rekey iterates entries, re-encrypts each. Failure mid-way → some entries old KEK, some new KEK.
**Scenario**: 
1. Rekey starts, processes 1000/5000 entries
2. Power loss / OOM kill
3. DB now has mixed KEK versions
4. Next unlock: which KEK to use?
**Fix**:
- **Single transaction**: `BEGIN IMMEDIATE` → rekey all → `COMMIT`
- Or: Add `kek_version` column, support multiple KEKs during transition
- Verify all entries rekeyed before committing
- Progress callback for UI (but transaction holds lock)

### BUG-L-008: Audit Log — Write Ordering vs Crash Consistency
**Location**: Plan Phase 2.5 (Audit Logging)
**Issue**: Audit entry written after operation completes. Crash between operation and audit write → operation unlogged.
**Scenario**: 
1. `key_delete` executes, DB committed
2. Power loss before audit write
3. Key deleted but no audit trail
**Fix**:
- Audit write **in same transaction** as operation (SQLite supports this)
- Or: Write-ahead audit log (append to file, fsync, then DB operation)
- Trade-off: Performance vs completeness

---

## Security Anti-Patterns

### BUG-S-001: Hardcoded Crypto Constants — No Algorithm Agility
**Location**: Plan Phase 1.3 (Crypto Module)
**Issue**: AES-256-GCM, Argon2id, HKDF-SHA256 hardcoded. No versioning, no negotiation.
**Risk**: 
- Algorithm break → no migration path
- Compliance requirements (FIPS, CNSA) unmet
- Cannot upgrade to PQ algorithms
**Fix**:
- Algorithm identifiers in DB header: `cipher: "AES-256-GCM", kdf: "Argon2id", kdf_params: {...}`
- Versioned crypto context: `v1: {cipher, kdf, params}`
- Migration path for algorithm change (re-encrypt all entries)

### BUG-S-002: Single Master Key — No Key Hierarchy
**Location**: Plan Phase 1.3 (Crypto Module)
**Issue**: One master password → one KEK → all DEKs. Compromise = total loss.
**Risk**: 
- No key separation (backup vs main, CA vs keystore)
- No key rotation without full re-encrypt
- No hardware key wrapping (HSM)
**Fix**:
- Key hierarchy: `Master Password → Root Key → Domain Keys (keystore, backup, CA, audit) → DEKs`
- Each domain: separate HKDF context
- Domain key rotation independent

### BUG-S-003: No Authenticated Encryption for Database File
**Location**: Plan Phase 1.2 (Database Schema)
**Issue**: SQLite file not encrypted at rest (only entry values encrypted). Schema, metadata, audit log visible.
**Risk**: 
- Metadata leakage (key names, types, timestamps, CA structure)
- Traffic analysis: which keys accessed when
- Schema reveals application structure
**Fix**: 
- **Option A**: SQLCipher (full DB encryption) — adds dependency, performance cost
- **Option B**: Encrypt sensitive columns only (current plan) + document metadata leakage
- **Option C**: File-level encryption (dm-crypt, BitLocker, FileVault) — OS responsibility
- **Decision**: Document metadata leakage, recommend full-disk encryption

### BUG-S-004: Password-Based Key Derivation — No Key Stretching Verification
**Location**: Plan Phase 1.3 (Crypto Module)
**Issue**: Argon2id output used directly as KEK. No verification that derivation worked correctly.
**Risk**: 
- Implementation bug → wrong KEK → data loss
- Parameter mismatch → silent corruption
**Fix**:
- Derive KEK → encrypt known test vector → store ciphertext in header
- On unlock: derive KEK → decrypt test vector → verify plaintext
- Fail fast if verification fails (wrong password OR bug)

### BUG-S-005: Key Import — No Validation of Private Key Consistency
**Location**: Plan Phase 2.2 (Key Import)
**Issue**: Import accepts private key but doesn't verify it matches public key / certificate.
**Risk**: 
- User imports mismatched key pair → signing fails silently later
- Malicious import → key substitution
**Fix**:
- On import: derive public from private → compare with provided public
- For certificates: verify private key signs certificate (proof of possession)
- Reject on mismatch

### BUG-S-006: Certificate Issuance — No Replay Protection
**Location**: Plan Phase 3.2 (Certificate Issuance)
**Issue**: CSR signed → certificate issued. Same CSR submitted twice → two certs with same key.
**Risk**: 
- Duplicate certificates (revocation complexity)
- Attacker replays CSR → gets valid cert
**Fix**:
- Track issued serials per CSR hash (SHA256 of CSR)
- Reject duplicate CSR (return existing cert or error)
- Option: Allow re-issue with `--force` (revoke old first)

### BUG-S-007: CRL Generation — No NextUpdate Enforcement
**Location**: Plan Phase 3.3 (CRL)
**Issue**: CRL `nextUpdate` field set but no enforcement of regeneration before expiry.
**Risk**: 
- Expired CRL → clients reject all certs (fail-closed) or accept all (fail-open)
- Operational burden: manual CRL regeneration
**Fix**:
- `nextUpdate` = `now() + configured_interval` (default 24h)
- Background task / cron: regenerate CRL before `nextUpdate - 1h`
- Alert if CRL stale

### BUG-S-008: Key Comparison — Public Key Only
**Location**: Plan Phase 2.3 (Key Comparison)
**Issue**: `compare` command compares public keys only. Private keys not compared.
**Risk**: 
- Two entries with same public key but different private keys → compare says "equal"
- User thinks keys identical, uses wrong private key
**Fix**:
- Compare: public key + key type + algorithm + parameters
- Separate command: `verify-possession` (sign challenge with private key)
- Document: "compare = public key equality only"

### BUG-S-009: Config File — TOML Parsing Without Schema Validation
**Location**: Plan Phase 1.3 (Config Module)
**Issue**: `toml::from_str` without schema validation. Malformed config → panic or silent defaults.
**Risk**: 
- Typos in config ignored → unexpected behavior
- Malicious config → logic bypass
**Fix**:
- Use `serde` with `deny_unknown_fields`
- Validate all fields on load (range checks, enum validation)
- Error on unknown fields (strict mode)

### BUG-S-010: CLI — No Input Sanitization for File Paths
**Location**: Plan Phase 1.4 (CLI Framework)
**Issue**: File paths from CLI used directly in `std::fs` operations. Path traversal possible.
**Risk**: 
- `rw-secstore import --file ../../../etc/passwd` → reads arbitrary files
- `rw-secstore backup --output /dev/sda` → destroys disk
**Fix**:
- Canonicalize paths: `std::fs::canonicalize()` 
- Restrict to allowed directories (config dir, current dir, explicit `--allow-path`)
- Reject absolute paths outside allowed dirs
- Validate output paths: not device files, not symlinks to sensitive locations

---

## Code Quality Risks

### BUG-Q-001: Error Handling — `unwrap()` / `expect()` in Production Code
**Location**: All phases
**Risk**: Panics in production → crash, no audit trail, potential data corruption.
**Fix**: 
- **Zero tolerance**: `clippy::unwrap_used`, `clippy::expect_used` = deny
- Use `Result` everywhere, `?` operator
- Custom error types with `thiserror`
- Context with `eyre`/`anyhow` for application errors

### BUG-Q-002: Async/Sync Mismatch — Blocking in Async Context
**Location**: Plan Phase 1.4 (CLI) — if any async used
**Risk**: `rusqlite` is sync. Using in async (tokio) without `spawn_blocking` → blocks executor.
**Fix**: 
- Keep CLI sync (no async needed for CLI)
- If daemon mode later: `tokio::task::spawn_blocking` for DB ops
- Or: Use `sqlx` (async) instead of `rusqlite`

### BUG-Q-003: Global State — Mutable Statics
**Location**: Plan Phase 1.3 (Crypto, Config)
**Risk**: Tests interfere, concurrency bugs, hidden dependencies.
**Fix**: 
- No `lazy_static`/`once_cell` for mutable state
- Pass dependencies explicitly (dependency injection)
- Config as `Arc<Config>` passed to functions

### BUG-Q-004: Testing — No Integration Test Database Isolation
**Location**: Plan Phase 1.5, 2.5, etc.
**Risk**: Tests share DB file → flaky tests, order dependence.
**Fix**: 
- Each test: `tempfile::tempdir()` → unique DB path
- `#[serial]` only if truly necessary
- Parallel test execution by default

### BUG-Q-005: Testing — No Property-Based Tests for Crypto
**Location**: Plan Phase 1.6 (Property Tests)
**Risk**: Crypto invariants untested (DEK uniqueness, nonce non-reuse, constant-time).
**Fix**: 
- `proptest` tests for all crypto functions
- Test vectors from RFCs (Argon2, AES-GCM, HKDF)
- Fuzz targets for parsers

### BUG-Q-006: Documentation — No Inline Safety Comments
**Location**: All crypto code
**Risk**: Maintainer doesn't know *why* specific construction used → changes break security.
**Fix**: 
- Every crypto function: `// SAFETY: ...` or `// SECURITY: ...` comment
- Explain: threat model, why this algorithm, why these parameters, what breaks if changed
- Link to SPEC/ADR requirements

### BUG-Q-007: Dependencies — No Version Pinning Strategy
**Location**: Plan Phase 1.1 (Cargo.toml)
**Risk**: `cargo update` breaks build, supply chain attack via new version.
**Fix**: 
- `Cargo.lock` committed to git
- `cargo deny` with `advisories` and `bans` (yanked versions)
- `cargo update --dry-run` in CI to detect updates

### BUG-Q-008: Build — No Reproducible Builds
**Location**: Plan Phase 5.x
**Risk**: Binary not reproducible → supply chain verification impossible.
**Fix**: 
- `CARGO_PROFILE_RELEASE_STRIP=symbols`
- `CARGO_PROFILE_RELEASE_DEBUG=false`
- `SOURCE_DATE_EPOCH` for timestamps
- `cargo-vet` for dependency auditing (post-v1)

### BUG-Q-009: Logging — Structured Logging Missing
**Location**: Plan Phase 2.5 (Audit) vs operational logging
**Risk**: Debugging production issues impossible without structured logs.
**Fix**: 
- `tracing` crate with `tracing-subscriber` (JSON output option)
- Structured fields: `operation`, `key_id`, `duration_ms`, `result`
- Separate from audit log (audit = security, tracing = ops)

### BUG-Q-010: CLI — No Command Timeout / Cancellation
**Location**: Plan Phase 1.4 (CLI Framework)
**Risk**: Long operations (rekey 100k keys) uncancelable, no progress.
**Fix**: 
- `ctrlc` crate for SIGINT handling
- Periodic cancellation check in long loops
- Progress bar with `indicatif` (already in plan)

### BUG-Q-011: Database — No Connection Pool for Daemon Mode
**Location**: Plan Phase 1.2 (Database)
**Risk**: If daemon mode added later, current per-command connection design fails.
**Fix**: 
- Design DB layer with `ConnectionManager` trait
- Implement `SingleConnection` (CLI) and `PooledConnection` (daemon)
- Abstract behind trait from day one

### BUG-Q-012: Key Types — Enum Exhaustiveness Not Enforced
**Location**: Plan Phase 2.1 (Key Types)
**Risk**: New key type added → match statements missing arms → compile error (good) but easy to forget in multiple places.
**Fix**: 
- Use `strum` crate for enum iteration / variant names
- Exhaustive matches enforced by compiler (Rust default)
- Single `KeyType` definition, re-export everywhere

---

## Required Fixes in Implementation Plan

### Phase 1 Additions:
- [ ] 1.2.1: Migration locking strategy (BUG-L-001)
- [ ] 1.2.2: WAL checkpoint strategy (BUG-L-002)
- [ ] 1.3.1: Algorithm versioning in header (BUG-S-001)
- [ ] 1.3.2: Key hierarchy design (BUG-S-002)
- [ ] 1.3.3: KEK verification test vector (BUG-S-004)
- [ ] 1.3.4: Config schema validation (BUG-S-009)
- [ ] 1.4.1: Path sanitization (BUG-S-010)
- [ ] 1.5.1: Test DB isolation (BUG-Q-004)
- [ ] 1.6.1: Property tests for crypto (BUG-Q-005)
- [ ] 1.7.1: Dependency pinning + deny (BUG-Q-007)
- [ ] 1.8.1: Reproducible build config (BUG-Q-008)

### Phase 2 Additions:
- [ ] 2.1.1: UUIDv4 for key IDs (BUG-L-003)
- [ ] 2.2.1: Private key consistency validation (BUG-S-005)
- [ ] 2.3.1: Compare = public only, document (BUG-S-008)
- [ ] 2.4.1: Rekey in single transaction (BUG-L-007)
- [ ] 2.5.1: Audit in same transaction (BUG-L-008)
- [ ] 2.6.1: Rate limiting unlock (BUG-S-002, ADV-H-002)
- [ ] 2.7.1: Secure password input only (BUG-S-001, ADV-H-001)
- [ ] 2.8.1: Secure erasure on delete (BUG-M-011)

### Phase 3 Additions:
- [ ] 3.1.1: CA serial number generation (BUG-L-004)
- [ ] 3.2.1: Certificate validity UTC only (BUG-L-005)
- [ ] 3.2.2: CSR replay protection (BUG-S-006)
- [ ] 3.3.1: CRL nextUpdate automation (BUG-S-007)
- [ ] 3.4.1: PKCS#12 interop test matrix (REV-H-003)

### Phase 4 Additions:
- [ ] 4.2.1: Atomic restore via temp file (BUG-L-006)
- [ ] 4.3.1: Backup independent encryption (BUG-S-006, ADV-H-006)
- [ ] 4.4.1: Corruption detection (REV-C-003)

### Phase 5 Additions:
- [ ] 5.1.1: Binary hardening verification (BUG-Q-008, ADV-M-009)
- [ ] 5.2.1: Structured logging (BUG-Q-009)
- [ ] 5.3.1: Windows compatibility (REV-H-004)
- [ ] 5.4.1: Fuzzing targets (ADV-M-005)
- [ ] 5.5.1: Command timeout/cancellation (BUG-Q-010)

---

## Sign-off Required

- [ ] All Logic Errors have fix tasks in revised plan
- [ ] All Security Anti-Patterns have mitigation tasks
- [ ] Code Quality Risks addressed or accepted with rationale
- [ ] `clippy::unwrap_used` = deny enforced in CI
- [ ] `clippy::expect_used` = deny enforced in CI
- [ ] Error handling strategy documented (thiserror + eyre)
- [ ] Testing strategy documented (unit + integration + property + fuzz)
- [ ] Documentation strategy for security-critical code
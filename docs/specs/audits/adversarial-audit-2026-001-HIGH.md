# Adversarial Audit — SPEC-2026-001-rw_secstore-core (HIGH Mode)

**Audit ID**: ADV-2026-001-HIGH
**Date**: 2026-08-29
**Auditor**: ForgeCode (plan-and-audit HIGH mode)
**Perspective**: Attacker / Red Team / Security Researcher
**SPEC Version**: 1.0.0
**Plan Version**: 1.0.0 (HIGH mode)

---

## Executive Summary

| Severity | Count | Description |
|----------|-------|-------------|
| **CRITICAL** | 6 | Exploitable vulnerabilities if implemented as specified |
| **HIGH** | 10 | Significant security weaknesses |
| **MEDIUM** | 14 | Defense-in-depth gaps |
| **LOW** | 8 | Hardening opportunities |
| **Total** | **38** | |

**Verdict**: **FAIL** — Multiple exploitable attack vectors identified. Critical findings represent real-world attack scenarios.

---

## Attack Surface Analysis

### Threat Model Assumptions (Per SPEC §3.2 NFR-SEC-001)
- **Attacker Capabilities**: Local filesystem read, malicious input, timing side-channels, offline brute-force
- **Trust Boundaries**: Single user, single machine, no network (v1)
- **Assets**: Master password, KEK, DEKs, private keys, certificates, audit logs

---

## CRITICAL Findings (Exploitable)

### ADV-C-001: Master Password in Process Memory — No Zeroization Guarantee
**Attack**: Attacker with `ptrace`/`gdb`/`coredump` access reads master password from heap/stack.
**SPEC Gap**: §3.2 NFR-SEC-002 mentions "zeroize" but no requirement for: immediate zeroization after use, `mlock` to prevent swap, secure allocator.
**Exploit**: `gdb -p <pid>` → `dump memory /tmp/mem.bin 0x...` → `strings /tmp/mem.bin | grep -i password`
**Mitigation Required**: 
- `zeroize::Zeroize` on all sensitive types (mandatory)
- `mlock` for master key pages (Phase 2+)
- Secure allocator (`hardened_malloc` or `jemalloc` with guard pages)
- Drop trait implementations that zeroize on scope exit

### ADV-C-002: Argon2id Parameters Not Enforced — Downgrade Attack
**Attack**: Attacker modifies database header to reduce `m_cost`/`t_cost`/`p_cost`, then brute-forces offline.
**SPEC Gap**: §3.1 FR-CRYPTO-001 stores params in header but no requirement to: validate params on load, reject below-minimum params, bind params to database identity.
**Exploit**: 
1. Steal database file
2. Hex-edit header: change `m_cost=65536` → `m_cost=1`
3. Offline brute-force at 1000x speed
**Mitigation Required**:
- Hardcoded minimum params in code (not configurable below threshold)
- Param validation on every `open`/`unlock`
- Param hash bound to database identity (prevent header swap)

### ADV-C-003: DEK Reuse Across Entries — Cross-Entry Decryption
**Attack**: If same DEK used for multiple entries, compromise of one entry reveals all.
**SPEC Gap**: §3.1 FR-CRYPTO-003 says "per-entry DEK" but no requirement for: cryptographic proof of uniqueness, HKDF context separation verification, DEK collision detection.
**Exploit**: If HKDF `info` parameter is constant or predictable, DEKs collide.
**Mitigation Required**:
- HKDF `info` = `entry_id || entry_type || version` (unique per entry)
- Runtime assertion: `DEK_i != DEK_j` for all `i != j` (debug builds)
- DEK derivation test vectors in property tests

### ADV-C-004: AES-GCM Nonce Reuse — Catastrophic Failure
**Attack**: Nonce reuse in AES-GCM reveals XOR of plaintexts and allows forgery.
**SPEC Gap**: §3.1 FR-CRYPTO-002 mentions AES-GCM but no requirement for: 96-bit random nonce per encryption, nonce collision detection, nonce construction method.
**Exploit**: If counter-based nonce and counter resets, or if random nonce collides (birthday bound at 2^32).
**Mitigation Required**:
- **Only** 96-bit random nonces from `OsRng` (never counter)
- Store nonce as prefix to ciphertext (12 bytes)
- Runtime check: track recent nonces in memory (debug), reject duplicates
- Property test: encrypt 10^6 entries, verify no nonce collisions

### ADV-C-005: Audit Log Tampering — No Tamper-Evidence Verification
**Attack**: Attacker modifies audit log to hide malicious activity (key extraction, CA abuse).
**SPEC Gap**: §3.1 FR-AUDIT-003 mentions "tamper-evident" but no requirement for: HMAC chain verification on every read, truncation detection, reordering detection, key separation from data encryption keys.
**Exploit**: 
1. Attacker gains write access to audit log
2. Deletes lines showing `key_export` operations
3. Recomputes checksums if simple CRC
4. Log appears intact
**Mitigation Required**:
- HMAC-SHA256 chain: `h_i = HMAC(k_audit, h_{i-1} || entry_i)`
- `k_audit` derived from master password via separate HKDF context
- Verify chain on **every** audit log read (not just write)
- Detect: truncation (chain breaks), reordering (hash mismatch), modification (hash mismatch)
- Append-only file with `O_APPEND` + `fsync`

### ADV-C-006: SQLite Database — No Integrity Verification on Load
**Attack**: Attacker modifies SQLite database file directly (hex editor, `sqlite3` CLI) to: change key metadata, insert malicious CA cert, alter audit log, bypass access controls.
**SPEC Gap**: §3.1 FR-DB-001 through FR-DB-004 no requirement for: database-level integrity check, page-level checksums, schema version binding, detection of external modification.
**Exploit**: 
1. `sqlite3 keystore.db "UPDATE keys SET public_key = '<attacker_key>' WHERE id = 'target'"`
2. Application loads modified DB without detection
3. Attacker's key now trusted
**Mitigation Required**:
- **Per-page HMAC** (SQLCipher style) OR **full-file HMAC** on header
- Header includes: schema version, param hash, page count, HMAC of all pages
- Verify on every `open` before any operation
- Reject DB if HMAC mismatch (do not attempt repair)

---

## HIGH Findings (Significant Weaknesses)

### ADV-H-001: Password Entry via CLI Args / Env Vars — Credential Leakage
**Attack**: User runs `rw-secstore unlock --password "secret"` → password in shell history, process table (`ps aux`), audit logs.
**SPEC Gap**: §3.1 FR-CLI-002 mentions "secure password input" but no explicit prohibition of CLI/env input.
**Mitigation**: 
- **Reject** password via CLI arg/env var (hard error)
- **Only** accept via TTY (`rpassword`) or stdin pipe (with warning)
- Document clearly: "Never pass password on command line"

### ADV-H-002: No Rate Limiting on Unlock Attempts — Online Brute Force
**Attack**: Attacker with local access runs `rw-secstore unlock` in loop with password dictionary.
**SPEC Gap**: No requirement for: attempt counting, exponential backoff, lockout, alerting.
**Mitigation**:
- In-memory attempt counter (resets on process exit — acceptable for CLI)
- Exponential backoff: 1s, 2s, 4s, 8s... max 60s
- After 10 failures: require `--force` flag + 5min wait
- Log failed attempts to audit log

### ADV-H-003: Certificate Validation — Time-of-Check/Time-of-Use (TOCTOU)
**Attack**: Certificate valid at check time, expires/revoked before use.
**SPEC Gap**: §3.1 FR-CA-007 mentions validation but no requirement for: re-validation at use time, caching with TTL, revocation checking at use.
**Mitigation**:
- Validate certificate chain **at time of use** (not just import)
- Cache validation result with short TTL (5 min)
- Check CRL/OCSP at use time (when implemented)

### ADV-H-004: Private Key Export — No Additional Authorization
**Attack**: Compromised user session exports all private keys via `rw-secstore export --all`.
**SPEC Gap**: §3.1 FR-KEY-004 allows export with master password only — no second factor, no confirmation, no rate limit.
**Mitigation**:
- Require explicit `--yes-i-understand` flag for bulk export
- Per-key confirmation prompt (interactive mode)
- Audit log entry with `--export-reason` required field
- Rate limit: max 5 exports/minute

### ADV-H-005: CA Private Key in Memory — Extended Exposure
**Attack**: During CA operations, CA private key stays in memory longer than necessary.
**SPEC Gap**: No requirement for: minimal key lifetime in memory, zeroization after each operation, separate process for CA ops.
**Mitigation**:
- Load CA key → sign → zeroize immediately
- Never cache CA key across commands
- Consider separate `rw-secstore-ca` binary for CA operations (reduces attack surface)

### ADV-H-006: Backup File — Encryption Key Derivation Weakness
**Attack**: Backup file uses same KEK derivation as main DB → backup compromise = main DB compromise.
**SPEC Gap**: §3.1 FR-BACKUP-002 mentions encryption but no requirement for: independent backup encryption key, separate KDF context, backup-specific salt.
**Mitigation**:
- Backup encryption key = `HKDF(master_key, "backup-v1", backup_salt)`
- `backup_salt` = 32 random bytes stored in backup header
- Different HKDF context from main DB

### ADV-H-007: Imported Certificate — No Path Length Constraint Enforcement
**Attack**: Attacker imports CA cert with `pathlen:0` but uses it to issue intermediate CA.
**SPEC Gap**: §3.1 FR-CA-003 mentions import validation but no requirement for: `basicConstraints pathlen` enforcement, `nameConstraints` enforcement, `policyConstraints` enforcement.
**Mitigation**:
- Full RFC 5280 path validation including all constraints
- Reject CA certs with `pathlen:0` used as intermediate
- Test with pathological cert chains

### ADV-H-008: Key Comparison — Timing Side Channel
**Attack**: `rw-secstore compare key1 key2` leaks key equality via timing.
**SPEC Gap**: §3.1 FR-KEY-008 mentions compare but no requirement for: constant-time comparison.
**Mitigation**:
- Use `subtle::ConstantTimeEq` for all key material comparisons
- Property test: verify constant-time property

### ADV-H-009: Configuration File — World-Readable by Default
**Attack**: Config file at `~/.config/rw-secstore/config.toml` contains database path, maybe hints — readable by other users.
**SPEC Gap**: §3.1 FR-CONFIG-001 no requirement for: config file permissions (0o600), sensitive data exclusion from config.
**Mitigation**:
- Config file `0o600` on create
- **Never** store passwords, keys, salts in config
- Config only: paths, UI preferences, non-sensitive defaults

### ADV-H-010: Random Number Generation — No Entropy Failure Handling
**Attack**: System entropy pool exhausted → `OsRng` blocks or returns weak entropy → weak keys generated.
**SPEC Gap**: §3.2 NFR-SEC-003 mentions entropy but no requirement for: entropy estimation, blocking vs non-blocking, failure mode, user notification.
**Mitigation**:
- Use `getrandom` crate (blocks until entropy available)
- Startup entropy health check (read 256 bytes, measure latency)
- Warn if entropy collection >100ms
- **Never** fall back to deterministic RNG

---

## MEDIUM Findings (Defense-in-Depth)

### ADV-M-001: No Memory Protection for Sensitive Data
**Gap**: No `mlock`/`VirtualLock` for master key, KEK, DEKs in RAM.
**Risk**: Swap leakage, cold boot attacks.
**Fix**: `memsecurity` crate or platform-specific `mlock` (Phase 2+).

### ADV-M-002: No Control Flow Integrity (CFI)
**Gap**: Rust default build has no CFI.
**Risk**: Memory corruption → control flow hijack.
**Fix**: `RUSTFLAGS="-Z sanitizer=cfi"` in CI (nightly), or `cargo-cfi`.

### ADV-M-003: No Stack Smashing Protection Verification
**Gap**: Stack canaries enabled by default but not verified.
**Risk**: Stack overflow bypass.
**Fix**: Verify `-C default-linker-args=-z,stack-protector-strong` in build.

### ADV-M-004: No Heap Hardening
**Gap**: Default allocator has no guard pages, no quarantine.
**Risk**: Use-after-free, heap overflow.
**Fix**: `jemalloc` with `background_thread:true, metadata_thp:always, guard_pages:true` or `hardened_malloc`.

### ADV-M-005: No Fuzzing Targets for Parsers
**Gap**: No fuzz targets for: SQLite parsing, X.509 parsing, PKCS#12 parsing, config parsing.
**Risk**: Parser bugs → RCE or DoS.
**Fix**: `cargo fuzz` targets for all parsers (Phase 1.6).

### ADV-M-006: No Dependency Vulnerability Scanning in CI
**Gap**: `cargo audit` not in CI pipeline.
**Risk**: Known vulnerable dependencies deployed.
**Fix**: `cargo audit` + `cargo deny` in CI (Phase 1.7).

### ADV-M-007: No SBOM Generation
**Gap**: No Software Bill of Materials.
**Risk**: Supply chain transparency, vulnerability tracking.
**Fix**: `cargo sbom` or `syft` in CI (Phase 1.7).

### ADV-M-008: No License Compliance Checking
**Gap**: 28 dependencies, no license audit.
**Risk**: GPL contamination, legal liability.
**Fix**: `cargo deny check licenses` in CI (Phase 1.7).

### ADV-M-009: No Binary Hardening Verification
**Gap**: No verification of: RELRO, PIE, NX, Fortify, CFI.
**Risk**: Exploit mitigations disabled.
**Fix**: `checksec` in CI, verify all protections enabled.

### ADV-M-010: No Secure Coding Standard Enforcement
**Gap**: No `clippy` security lints, no `rustsec` integration.
**Risk**: Preventable bugs.
**Fix**: `clippy::pedantic`, `clippy::cargo`, `rustsec` in CI.

### ADV-M-011: Key Deletion — No Secure Erasure
**Gap**: `DELETE FROM keys` marks pages free but data remains on disk.
**Risk**: Forensic recovery of deleted keys.
**Fix**: Overwrite key material before delete (application-level), or use SQLCipher with per-page encryption.

### ADV-M-012: No Process Isolation for CA Operations
**Gap**: CA private key in same process as keystore operations.
**Risk**: Keystore bug → CA key compromise.
**Fix**: Separate binary/process for CA (Phase 3+).

### ADV-M-013: No Audit Log Rotation / Retention
**Gap**: Audit log grows unbounded.
**Risk**: Disk exhaustion, log loss.
**Fix**: Configurable rotation (size/time), retention policy, signed rotation.

### ADV-M-014: No Secure Update Mechanism
**Gap**: No signed binary updates, no reproducibility verification.
**Risk**: Supply chain attack on update.
**Fix**: Reproducible builds, signed releases, `cargo-vet` (post-v1).

---

## LOW Findings (Hardening)

### ADV-L-001: No Seccomp-BPF Sandbox
**Idea**: Restrict syscalls for `rw-secstore` process (no network, no exec, limited fs).
**Effort**: High (platform-specific), defer to v2.

### ADV-L-002: No Capability-Based Security (Linux)
**Idea**: Run with minimal capabilities (`CAP_DAC_OVERRIDE` only for DB file).
**Effort**: Medium, defer to v2.

### ADV-L-003: No Hardware Security Module (HSM) Interface
**Idea**: PKCS#11 interface for HSM-backed keys.
**Effort**: High, out of scope v1 (noted in SPEC §3.4).

### ADV-L-004: No Remote Attestation
**Idea**: TPM-based attestation of keystore state.
**Effort**: High, out of scope v1.

### ADV-L-005: No Formal Verification of Crypto Code
**Idea**: Use `hax`/`creusot`/`kani` for formal verification of crypto primitives.
**Effort**: Very high, research project.

### ADV-L-006: No Side-Channel Resistant RSA/ECDSA
**Idea**: `rsa`/`ecdsa` crates may not be constant-time.
**Risk**: Timing attacks on signing.
**Fix**: Use `p256`/`p384`/`ed25519-dalek` with `subtle` backend (constant-time).

### ADV-L-007: No Post-Quantum Algorithm Support
**Idea**: ML-KEM, ML-DSA, SLH-DSA for future-proofing.
**Effort**: High, track NIST standardization, defer to v2.

### ADV-L-008: No Covert Channel Analysis
**Idea**: Analyze timing, cache, power side-channels in crypto operations.
**Effort**: Research-grade, defer.

---

## Attack Scenarios — Prioritized by Likelihood × Impact

| Scenario | Likelihood | Impact | Findings |
|----------|------------|--------|----------|
| Stolen laptop → offline brute-force | High | Critical | ADV-C-002, ADV-C-001 |
| Malicious DB modification → key substitution | Medium | Critical | ADV-C-006 |
| Audit log tampering → hide breach | Medium | High | ADV-C-005 |
| Nonce reuse → plaintext recovery | Low | Critical | ADV-C-004 |
| DEK collision → cross-entry decrypt | Low | Critical | ADV-C-003 |
| Password in shell history → credential leak | High | High | ADV-H-001 |
| Online brute-force unlock | Medium | High | ADV-H-002 |
| CA key memory exposure | Low | Critical | ADV-H-005 |
| Backup key derivation weakness | Low | High | ADV-H-006 |
| Certificate path validation bypass | Low | High | ADV-H-007 |

---

## Required Security Tasks for Implementation Plan

### Phase 1 (Foundation) — Must Include:
- [ ] 1.6 Property tests for crypto invariants (ADV-C-003, ADV-C-004, ADV-H-008)
- [ ] 1.7 Supply chain hardening (ADV-M-006, ADV-M-007, ADV-M-008)
- [ ] 1.8 Database integrity verification (ADV-C-006)
- [ ] 1.9 Secure memory handling (ADV-C-001, ADV-M-001)
- [ ] 1.10 Entropy health check (ADV-H-010)

### Phase 2 (Keystore) — Must Include:
- [ ] 2.6 Rate limiting on unlock (ADV-H-002)
- [ ] 2.7 Secure password input enforcement (ADV-H-001)
- [ ] 2.8 Key deletion secure erasure (ADV-M-011)
- [ ] 2.9 Constant-time key comparison (ADV-H-008)

### Phase 3 (CA) — Must Include:
- [ ] 3.5 Certificate path validation (ADV-H-003, ADV-H-007)
- [ ] 3.6 PKCS#12 interop testing (ADV-H-003)
- [ ] 3.7 CA key minimal lifetime (ADV-H-005)
- [ ] 3.8 Key usage policy enforcement (ADV-M-007)

### Phase 4 (Advanced) — Must Include:
- [ ] 4.5 Backup independent encryption (ADV-H-006)
- [ ] 4.6 Corruption detection + recovery (ADV-C-003, REV-C-003)
- [ ] 4.7 Audit log HMAC chain verification (ADV-C-005)

### Phase 5 (Polish) — Must Include:
- [ ] 5.3 Windows compatibility (ADV-H-004)
- [ ] 5.4 Binary hardening verification (ADV-M-009)
- [ ] 5.5 Fuzzing targets (ADV-M-005)
- [ ] 5.6 Comprehensive benchmarks (REV-H-007)

---

## Sign-off Required

- [ ] All CRITICAL findings have mitigation tasks in revised plan
- [ ] All HIGH findings have mitigation tasks or explicit risk acceptance
- [ ] MEDIUM findings triaged with timeline
- [ ] LOW findings documented for future consideration
- [ ] Attack scenario mitigations mapped to plan tasks
- [ ] Security review checkpoint added before each phase completion
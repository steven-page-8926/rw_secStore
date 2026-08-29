# Reverse Audit: rw_secstore v1.1.0 Plan v2.1

**Audit ID**: REV-2026-001-v1.1
**Date**: 2026-08-29
**Auditor**: ForgeCode
**Subject**: PLAN-2026-001 v2.1 (HIGH mode)
**Methodology**: Find gaps, security holes, and missing requirements not in SPEC

---

## Critical Findings

### REV-C-001 (CRITICAL): No plan for HSM/TPM-backed key storage
**Description**: SPEC doesn't require HSM in v1.0 (deferred to v2.0), but plan 5.4.1 "mlock for sensitive buffers" is insufficient against cold-boot attacks.
**Location**: Plan §5.4
**Impact**: Critical — sensitive keys in RAM after process exit
**Resolution**: Document limitation in README, accept for v1.0, add to v1.1 roadmap

### REV-C-002 (CRITICAL): No key destruction on auth failure
**Description**: After 3 failed unlock attempts, plan doesn't specify behavior. No mention of rate limiting or delay.
**Location**: Plan §1.4 (auth)
**Impact**: Critical — brute-force attack vector
**Resolution**: Add task 1.4.8: "Rate limiting on auth failures (exponential backoff, max 10 attempts before 1hr lockout)"

### REV-C-003 (CRITICAL): No tamper detection on keystore_meta
**Description**: HMAC seal (Plan 1.8.1) detects file-level tampering but doesn't bind to specific row-level changes.
**Location**: Plan §1.8
**Impact**: Critical — attacker with DB write access could modify `keystore_meta` (e.g., downgrade Argon2id params)
**Resolution**: Add per-row HMAC for `keystore_meta` rows (especially `password_policy`, `argon2_params`)

### REV-C-004 (CRITICAL): Backup code brute-force not rate-limited per code
**Description**: REQ-AUTH-003 specifies "Rate limiting: max 3 attempts per minute" but plan 1.4.5 doesn't enforce.
**Location**: Plan §1.4.5
**Impact**: Critical — backup codes have 80 bits entropy, but no rate-limit = brute force possible
**Resolution**: Plan already mentions "max 3 attempts per minute"; clarify it's enforced with persistent counter (not in-memory only)

---

## High Findings

### REV-H-001 (HIGH): Keyring MEK not backed up
**Description**: If user uses keyring and keyring is wiped (e.g., re-login, OS reinstall), all DEKs are unrecoverable.
**Location**: Plan §1.4.3, §4.4.3
**Impact**: High — single point of failure for keyring mode
**Resolution**: Add task 4.4.5: "`config keyring export` to write MEK to password-protected file (backup)"

### REV-H-002 (HIGH): Audit log doesn't capture who accessed what
**Description**: REQ-AUDIT-001 captures "actor" but plan 2.8.1 doesn't specify: actor = OS user, SESSION ID, or both.
**Location**: Plan §2.8
**Impact**: High — compliance audit needs full context
**Resolution**: Plan 2.8.1 should capture: actor (OS user), session_id (UUID per CLI invocation), terminal_pid

### REV-H-003 (HIGH): CSR nonce stored where?
**Description**: Plan 3.3.6 "CSR replay protection" but no specification of nonce storage location.
**Location**: Plan §3.3.6
**Impact**: High — implementation will diverge
**Resolution**: Store CSR hash in `csr_nonces` table (new), TTL = cert validity period

### REV-H-004 (HIGH): No spec for key rotation policy
**Description**: OI-009 says "key rotation policies" deferred to v1.1, but key rotation is a basic security control.
**Location**: SPEC §9 OI-009, Plan
**Impact**: High — operational concern
**Resolution**: For v1.0, document that rotation is manual (re-key, re-issue). Add `key rotate` command in v1.1

### REV-H-005 (HIGH): Test for concurrent keyring access missing
**Description**: Plan 1.4.3 implements keyring, but no test for: two processes simultaneously accessing same keyring.
**Location**: Plan §1.4.3
**Impact**: High — keyring may have different concurrency semantics per backend
**Resolution**: Add 1.4.9: "Concurrent keyring access test (file lock or OS-level lock)"

### REV-H-006 (HIGH): Password file export doesn't support encrypted export
**Description**: REQ-PWD-006 mentions "Optional: `--format json` with metadata" but no encryption of the file itself.
**Location**: Plan §1.6.2
**Impact**: High — password file in plaintext 0o600 is still plaintext
**Resolution**: Add 1.6.4: "Optional encryption of password file (age/GPG)"

### REV-H-007 (HIGH): SSH key passphrase is a separate concern from master password
**Description**: REQ-SSH-001 says "Optional passphrase on private key (in addition to master password)" — two passwords?
**Location**: SPEC §4.4, Plan §2.3.8
**Impact**: High — UX confusion, two passwords to remember
**Resolution**: Document clearly: SSH key passphrase encrypts the SSH private key (OpenSSH format), master password encrypts the entire DB entry. Two separate concerns.

### REV-H-008 (HIGH): CSR replay nonce could enable DoS
**Description**: Storing CSR nonces indefinitely = unbounded growth.
**Location**: Plan §3.3.6
**Impact**: High — disk space leak
**Resolution**: Cleanup task: "Prune csr_nonces older than max cert validity (398 days)"

---

## Medium Findings

### REV-M-001 (MEDIUM): No spec for cross-platform keyring backend differences
**Description**: `keyring` crate has different behavior per OS. Plan doesn't enumerate which backends are tested.
**Location**: Plan §1.4.3
**Resolution**: Add to plan: "Tested backends: libsecret (Linux), Keychain (macOS), Credential Manager (Windows). Failure mode: any backend unavailable → log warning, fall back to password."

### REV-M-002 (MEDIUM): EFF wordlist version not pinned
**Description**: Plan 1.5.7 says "EFF long wordlist" but doesn't pin a specific version.
**Location**: Plan §1.5.7
**Resolution**: Pin to `eff_large_wordlist.txt` v1.0 (2026-XX-XX) or current at impl time. Hash on first load.

### REV-M-003 (MEDIUM): No migration guide for adding keyring after init
**Description**: What if user initializes with password, then wants to enable keyring? Plan 4.4.3 says "enable" but no spec for re-encrypting DEKs.
**Location**: Plan §4.4.3
**Resolution**: Add 4.4.5: "When enabling keyring, re-encrypt all DEKs with MEK (requires unlock first)"

### REV-M-004 (MEDIUM): No mention of TTY detection for password input
**Description**: Plan 4.5.2 implements `rpassword` but doesn't address non-TTY environments (CI, scripts).
**Location**: Plan §4.5.2
**Resolution**: Add: "If !isatty() and RW_SECSTORE_PASSWORD not set → error with clear message"

### REV-M-005 (MEDIUM): Audit log pruning not specified
**Description**: Audit log retention is configurable (default 365 days) but no automatic cleanup task.
**Location**: SPEC §6.3 [audit]
**Resolution**: Add task 4.3.4: "Audit log pruning (background task or `--prune` command)"

### REV-M-006 (MEDIUM): ECDH/ECDSA signing uses different primitives
**Description**: Plan 2.1.2 generates ECDSA keys but doesn't specify curve handling for `verify`.
**Location**: Plan §2.5.2
**Resolution**: Specify: ECDSA verification uses SHA-256 hashing by default (configurable to SHA-384)

### REV-M-007 (MEDIUM): Key expiration not visible in list output
**Description**: REQ-KS-007 says "CLI shows expiration status in `list` and `get`" but plan 2.4.1 doesn't have a column for expires_at.
**Location**: Plan §2.4.1
**Resolution**: Add column "EXPIRES" to `key list` output, default sort: expired first

### REV-M-008 (MEDIUM): Backup code regeneration invalidates all
**Description**: REQ-AUTH-002 says "regenerate invalidates old, creates new" but no warning to user.
**Location**: SPEC §4.11
**Resolution**: Add: "Regeneration requires explicit confirmation (`--yes` to skip)"

---

## Low Findings

### REV-L-001 (LOW): Plan doesn't mention OpenSSL version detection
**Description**: PKCS#12 interop with OpenSSL depends on OpenSSL version. Plan 3.7.3 tests interop but doesn't specify version.
**Location**: Plan §3.7.3
**Resolution**: Test with OpenSSL 1.1.1+ and 3.0+

### REV-L-002 (LOW): No mention of `seccomp` or `AppArmor` sandboxing
**Description**: Optional Linux hardening not mentioned.
**Location**: Plan §5.4
**Resolution**: Document as optional post-v1.0

### REV-L-003 (LOW): Cryptography suite doesn't include quantum-resistant options
**Description**: No mention of ML-KEM, ML-DSA, etc.
**Location**: SPEC §3
**Resolution**: Document as v2.0+ feature (post-quantum migration)

### REV-L-004 (LOW): No spec for restoring audit log from backup
**Description**: Backup contains audit_log (optional), but no spec for restoring with chain verification.
**Location**: Plan §4.2
**Resolution**: When audit_log included in backup, recompute chain on restore (use backup's chain as seed)

### REV-L-005 (LOW): No mention of `man -k` integration
**Description**: Shell completions don't include apropos integration.
**Location**: Plan §4.5.1
**Resolution**: Defer to v1.1

### REV-L-006 (LOW): No spec for "unlock token caching"
**Description**: Each CLI invocation requires unlock. Could cache MEK/KEK in OS keyring for short period.
**Location**: Plan (general)
**Resolution**: Defer to v1.1 daemon mode

### REV-L-007 (LOW): Plan doesn't address what happens if DB file is replaced during operation
**Description**: TOCTOU between open and use.
**Location**: Plan §1.2
**Resolution**: Use file inode check on every operation (or use SQLite's built-in locking)

### REV-L-008 (LOW): No mention of `umask` interaction
**Description**: Plan creates files with explicit perms (0o600) but doesn't document interaction with umask.
**Location**: Plan §1.2.7
**Resolution**: Document: "All file creation uses explicit perms, umask is ignored"

---

## Reverse Audit Summary

| Severity | Count |
|----------|-------|
| Critical | 4 |
| High | 8 |
| Medium | 8 |
| Low | 8 |
| **Total** | **28** |

### Required Actions (Critical + High)

1. **REV-C-001**: Document HSM/TPM as v1.1+ limitation
2. **REV-C-002**: Add task 1.4.8 "Rate limiting on auth failures"
3. **REV-C-003**: Add per-row HMAC for `keystore_meta` critical rows
4. **REV-C-004**: Enforce backup code rate limit with persistent counter
5. **REV-H-001**: Add task 4.4.5 "Export MEK to backup file"
6. **REV-H-002**: Plan 2.8.1 must capture session_id + terminal_pid
7. **REV-H-003**: Plan 3.3.6 specifies `csr_nonces` table schema
8. **REV-H-004**: Document manual key rotation for v1.0
9. **REV-H-005**: Add 1.4.9 "Concurrent keyring access test"
10. **REV-H-006**: Add 1.6.4 "Optional encryption of password file"
11. **REV-H-007**: Document SSH key passphrase vs master password
12. **REV-H-008**: Add task for CSR nonce pruning

---

**End of Reverse Audit**

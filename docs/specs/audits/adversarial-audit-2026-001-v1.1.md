# Adversarial Audit: rw_secstore v1.1.0 Plan v2.1

**Audit ID**: ADV-2026-001-v1.1
**Date**: 2026-08-29
**Auditor**: ForgeCode (thinking like a hostile attacker)
**Subject**: PLAN-2026-001 v2.1 (HIGH mode)
**Methodology**: Find security weaknesses, attack vectors, and ways to bypass protections

---

## Attack Surface Inventory

```
┌──────────────────────────────────────────────────────────┐
│  Attack Surfaces                                          │
│  ────────────────                                         │
│  1. SQLite database file (.sqlite)                        │
│  2. Password file (--password-file)                       │
│  3. Backup JSON file                                      │
│  4. SSH exported keys (PEM, OpenSSH)                      │
│  5. PKCS#12 exported files                                │
│  6. OS Keyring (libsecret/wincred/keychain)               │
│  7. Configuration file (TOML)                             │
│  8. CLI arguments (--password)                            │
│  9. Environment variables (RW_SECSTORE_*)                 │
│  10. Audit log file                                       │
│  11. WAL/SHM files                                        │
│  12. Process memory                                       │
│  13. Network (deferred to v1.1, but consider USB)         │
└──────────────────────────────────────────────────────────┘
```

---

## Critical Findings

### ADV-C-001 (CRITICAL): `--password` arg exposes password in process list
**Description**: CLI option `--password PASS` is in plan §6.1 but exposes password to anyone with `ps` access.
**Attack**: `ps auxe | grep rw-secstore` shows full command line including password
**Mitigation**: Reject `--password` argument; require `--password-file`, `--password-file -` (stdin), or interactive `rpassword` prompt
**Resolution**: Add to plan: "Reject `--password` arg in v1.0 (security risk). Use --password-file or env var only."

### ADV-C-002 (CRITICAL): Env var `RW_SECSTORE_PASSWORD` visible to child processes
**Description**: If user sets env var, all child processes inherit it.
**Attack**: Any subprocess (e.g., `git commit` hook) can read `RW_SECSTORE_PASSWORD`
**Mitigation**: Document limitation; recommend `--password-file` or interactive prompt
**Resolution**: Add warning in docs; do NOT block (env var is the standard pattern for CI)

### ADV-C-003 (CRITICAL): No protection against local privilege escalation
**Description**: Plan doesn't address: what if attacker has user-level shell access to the machine?
**Attack**: Read DB file (unencrypted DEKs possible if key leaked), read keyring, read password file
**Mitigation**: Document threat model explicitly (Level 2 Zero-Knowledge Formal)
**Resolution**: Plan §7.1 should explicitly state: "NOT defended against: local user with shell access. Use FDE."

### ADV-C-004 (CRITICAL): Memory dump after unlock exposes all DEKs
**Description**: Once unlocked, all DEKs are in memory. Attacker with `gdb` or `/proc/pid/mem` can extract.
**Attack**: `gdb -p $(pidof rw-secstore)` and dump process memory
**Mitigation**: mlock (plan 5.4.1, but best-effort), signal handlers, short unlock windows
**Resolution**: Plan 5.4.1 must be HARDENED: "Use `mlock()` + `madvise(MADV_DONTDUMP)` to prevent core dumps"

---

## High Findings

### ADV-H-001 (HIGH): Backup JSON contains enough to brute-force password
**Description**: Backup includes encrypted private keys + salt + Argon2id params. Attacker can offline brute-force.
**Attack**: `argon2` + dictionary attack on stolen backup
**Mitigation**: Strong password policy (REQ-PWD-001), breach check (REQ-PWD-002)
**Resolution**: Plan already addresses via password policy; no action

### ADV-H-002 (HIGH): DEK reuse across entries if same salt
**Description**: Plan 1.3.3 uses HKDF with `entry_id` as info. But what if two entries have same ID (UUID collision)?
**Attack**: UUID v7 collision = 2^122 probability, but the consequences are real
**Mitigation**: Use `entry_id || created_at` as info; backup with collision check
**Resolution**: Plan 1.3.3 should use `entry_id || created_at` as HKDF info

### ADV-H-003 (HIGH): Audit log HMAC chain trusts the writer
**Description**: If the writer is compromised, HMAC chain is useless.
**Attack**: Compromised process writes fake audit entries with valid chain
**Mitigation**: Audit log written via separate, minimal code path; signed with separate key
**Resolution**: Plan 2.8.2 should derive audit HMAC key from a separate derivation (already specified in 4.1)

### ADV-H-004 (HIGH): No protection against rollback attacks (e.g., DB version replay)
**Description**: Attacker can backup the DB, modify current DB, then restore backup to "undo" changes.
**Attack**: Backup → modify → restore = silent reversion
**Mitigation**: Monotonic timestamp in audit log; reject "backward in time" audit entries
**Resolution**: Add 2.8.4: "Audit entry timestamp must be ≥ last entry timestamp; reject rollback"

### ADV-H-005 (HIGH): Backup code one-time use can be bypassed via DB manipulation
**Description**: If attacker has DB write access, can reset `used_at` on backup code = infinite reuse.
**Attack**: Modify backup_codes.used_at = NULL = re-use code
**Mitigation**: HMAC integrity check on each row
**Resolution**: Plan 1.8.1 must include per-row HMAC for `backup_codes` table

### ADV-H-006 (HIGH): Keyring entries accessible to all processes in user session
**Description**: On Linux libsecret, all processes in the same user session can read all keyring entries.
**Attack**: Any user-session process can read `rw-secstore-master-key`
**Mitigation**: Use Linux kernel keyring (session-specific) + libsecret; document limitation
**Resolution**: Plan 1.4.3 should use libsecret "session" collection, not "user" (default)

### ADV-H-007 (HIGH): SSH key passphrase is encrypted with master password, not with KDF
**Description**: Plan 2.3.8 uses Argon2id for SSH key passphrase verification. If master password is strong, fine. But if user sets weak master password, SSH key is also weak.
**Attack**: Brute-force master password → decrypt SSH key passphrase
**Mitigation**: Strong master password policy (already in place)
**Resolution**: No action; document chain of trust

### ADV-H-008 (HIGH): Race condition in keyring + key file fallback
**Description**: If both keyring and password file are configured, which takes precedence?
**Attack**: Time-of-check vs time-of-use (e.g., keyring deleted between check and use)
**Mitigation**: Explicit precedence: password file > keyring > interactive prompt
**Resolution**: Add precedence order to plan 1.4.6: "Configurable, default: --password-file > keyring > interactive"

### ADV-H-009 (HIGH): No size limit on backup file (DoS)
**Description**: Attacker with DB access can write a 1TB encrypted blob, breaking backups.
**Attack**: Fill DB with garbage, then trigger backup
**Mitigation**: Max file size check before write; configurable limit
**Resolution**: Add 4.1.4: "Backup size limit (default 1GB, configurable, reject with error if exceeded)"

### ADV-H-010 (HIGH): PEM parser trusts any PEM input
**Description**: Plan 1.4 imports CAs from PEM. Malicious PEM = arbitrary cert in our chain.
**Attack**: Import attacker cert as trusted CA
**Mitigation**: Path validation (plan 3.1.7), basic constraints check, key usage check
**Resolution**: Plan 3.1.7 must check: `basicConstraints CA:TRUE`, `keyUsage keyCertSign`, NOT self-signed as leaf

---

## Medium Findings

### ADV-M-001 (MEDIUM): CLI help text could leak sensitive defaults
**Description**: `--help` output is public; should not reveal internal paths or keys.
**Resolution**: Sanitize --help output (no absolute paths, no test data)

### ADV-M-002 (MEDIUM): Race condition in concurrent unlock attempts
**Description**: Two processes try to unlock simultaneously.
**Resolution**: Use SQLite file lock or flock()

### ADV-M-003 (MEDIUM): `reqwest` for HIBP leaks timing info
**Description**: Online HIBP check reveals intent to check.
**Resolution**: Document; add opt-in only, allow disable

### ADV-M-004 (MEDIUM): SIGINT during rekey could leave partial encryption
**Description**: Plan 2.5.4 "atomic single transaction" but signal handler might not respect.
**Resolution**: Signal handler must wait for transaction commit/abort before zeroizing

### ADV-M-005 (MEDIUM): No integrity check on backup file before restore
**Description**: Restore reads JSON, parses, writes to DB. What if JSON is corrupted mid-restore?
**Resolution**: Plan 4.2.1 must verify checksum BEFORE parsing, refuse restore on mismatch

### ADV-M-006 (MEDIUM): Audit log queries don't enforce rate limit
**Description**: Attacker with DB read can query audit log at 1M req/sec = DoS via disk I/O.
**Resolution**: Plan 4.3.2 pagination + max rows = 10000 per query (configurable)

### ADV-M-007 (MEDIUM): Zxcvbn is a port, may have subtle differences
**Description**: Rust zxcvbn port may score differently than reference implementation.
**Resolution**: Test suite comparing reference zxcvbn output for 100+ passwords

### ADV-M-008 (MEDIUM): Diceware words are case-sensitive in EFF list
**Description**: EFF wordlist uses specific case; capitalization options may break uniqueness.
**Resolution**: Always lowercase first, then apply capitalization

### ADV-M-009 (MEDIUM): No revocation list (CRL) for SSH certs
**Description**: Plan 3.6 implements SSH CA but no SSH CRL.
**Resolution**: Defer to v1.1 (SSH cert signing is mostly stubbed)

### ADV-M-010 (MEDIUM): Password change while process is running
**Description**: Rekey is atomic, but what if another process is using the old KEK?
**Resolution**: Use SQLite write lock during rekey; reject concurrent operations

### ADV-M-011 (MEDIUM): `zxcvbn` for diceware may give low score
**Description**: Diceware passphrases like "correct horse battery staple" get zxcvbn score 4 (best), but shorter diceware may score lower.
**Resolution**: Use entropy bits (zxcvbn guesses) not just score; require ≥80 bits

### ADV-M-012 (MEDIUM): Backup compression ratio may be info leak
**Description**: Compressed backups reveal content patterns.
**Resolution**: Use authenticated encryption (AES-GCM) before compression

### ADV-M-013 (MEDIUM): KDF parameters in config could be downgraded
**Description**: If user edits config to set memory=1MB, system could honor.
**Resolution**: Plan 1.3.1 hardcoded minimums already prevent this; verify in code review

### ADV-M-014 (MEDIUM): No rate limit on PKCS#12 password attempts
**Description**: PKCS#12 files are brute-forceable offline.
**Resolution**: Document; recommend strong PKCS#12 passwords

---

## Low Findings

### ADV-L-001 (LOW): `--json` output may include sensitive fields
**Resolution**: Explicit allowlist of JSON-serializable fields

### ADV-L-002 (LOW): Error messages may leak internal paths
**Resolution**: Sanitize error messages in production builds

### ADV-L-003 (LOW): WAL files may be left after crash
**Resolution**: Plan 4.7.2 must run `PRAGMA wal_checkpoint(TRUNCATE)` on clean shutdown

### ADV-L-004 (LOW): No secure memory for temporary key material
**Resolution**: Use `mlock` for DEKs (not just master key)

### ADV-L-005 (LOW): TTY input may be cached in terminal scrollback
**Resolution**: Document; recommend `--password-file` for scripting

### ADV-L-006 (LOW): CSV output may not quote special characters
**Resolution**: Use proper CSV escaping (commas, quotes, newlines)

### ADV-L-007 (LOW): Date format ambiguity in audit timestamps
**Resolution**: Always ISO 8601 (RFC 3339) with UTC

### ADV-L-008 (LOW): TOML config file mode not enforced
**Resolution**: 0o600 on config file (just like DB)

---

## Adversarial Audit Summary

| Severity | Count |
|----------|-------|
| Critical | 4 |
| High | 10 |
| Medium | 14 |
| Low | 8 |
| **Total** | **36** |

### Required Actions (Critical)

1. **ADV-C-001**: Reject `--password` CLI arg; use --password-file or interactive only
2. **ADV-C-002**: Document env var visibility limitation
3. **ADV-C-003**: Explicit threat model statement in plan
4. **ADV-C-004**: Harden mlock to MADV_DONTDUMP

### High-Priority Actions

5. **ADV-H-002**: Use `entry_id || created_at` as HKDF info
6. **ADV-H-004**: Audit log monotonic timestamp check
7. **ADV-H-005**: Per-row HMAC for backup_codes
8. **ADV-H-006**: libsecret "session" collection, not "user"
9. **ADV-H-008**: Explicit precedence: --password-file > keyring > interactive
10. **ADV-H-009**: Backup size limit
11. **ADV-H-010**: Stricter CA cert validation on import

---

**End of Adversarial Audit**

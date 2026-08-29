# SYNTHESIS: rw_secstore Core Implementation Plan
## Combining Forward + Reverse Audit Findings into Revised Plan

## Document Identification
- **SYNTHESIS ID**: SYNTHESIS-2026-001
- **Version**: 1.0.0
- **Date**: 2026-08-28
- **Author**: ForgeCode
- **Status**: Draft - Pending Sign-off

---

## Executive Summary

This synthesis combines findings from:
- **Forward Audit** (FORWARD-2026-001): ✅ Plan validates spec, 2 HIGH, 3 MEDIUM, 4 LOW findings
- **Reverse Audit** (REVERSE-2026-001): ❌ Plan has gaps, 3 CRITICAL, 5 HIGH, 8 MEDIUM, 6 LOW findings

**Net Result**: Plan requires significant revision before sign-off. Critical security gaps must be addressed.

---

## Consolidated Findings Matrix

| Severity | Forward | Reverse | Total | Must Fix |
|----------|---------|---------|-------|----------|
| 🔴 Critical | 0 | 3 | 3 | **YES** |
| 🟠 High | 2 | 5 | 7 | **YES** |
| 🟡 Medium | 3 | 8 | 11 | Recommended |
| 🔵 Low | 4 | 6 | 10 | Nice to have |

---

## Critical Findings Resolution (Mandatory)

### SYN-C-001: Threat Model (REV-C-001)
**Resolution**: Add threat model to SPEC §5.3 or create `docs/SECURITY.md`
**Plan Changes**:
- New Task 0.5: Document threat model (1h)
- Threat boundaries: Local attacker (DB file theft), Malicious input (CLI args), Side channels (timing), Memory extraction (swap/dump)
- Trust assumptions: OS kernel, hardware RNG, Rust memory safety
- Out of scope: Remote network attackers (no network service), HSM compromise, Evil maid (physical access)

### SYN-C-002: Constant-Time Operations (REV-C-002, FWD-M-003)
**Resolution**: Mandate `subtle` crate for all comparisons
**Plan Changes**:
- Task 1.4: Add `subtle` to crypto dependencies
- Implement `constant_time_eq` for key comparison (REQ-KS-005)
- Implement `constant_time_verify` for signature verification (REQ-KS-006)
- Add tests verifying constant-time property

### SYN-C-003: Secure Password Handling (REV-C-003)
**Resolution**: Use `Zeroizing<String>` for all password material
**Plan Changes**:
- Task 1.4: Add `zeroize` crate
- `MasterPassword` type wrapping `Zeroizing<String>`
- Zeroize on drop, prevent logging/debug output
- Clear from memory after KEK derivation

---

## High Findings Resolution (Mandatory)

### SYN-H-001: CRL Generation Complexity (FWD-H-001)
**Resolution**: Spike task before Phase 3
**Plan Changes**:
- New Task 3.0: CRL generation spike (4h) — before Task 3.1
- Use `der-parser` + `asn1_rs` for RFC 5280 CRL profile
- Validate with OpenSSL `crl -inform DER -text -noout`
- If spike > 8h, consider `x509-parser` CRL support or external tool

### SYN-H-002: PKCS#12 Interop (FWD-H-002)
**Resolution**: Interop test matrix in Phase 3
**Plan Changes**:
- Task 3.5: Add interop tests with OpenSSL, Windows certmgr, macOS Keychain
- Test vectors: RSA-2048, ECDSA-P256, Ed25519
- Document known limitations in README

### SYN-H-003: Connection Strategy (REV-H-001)
**Resolution**: Define and benchmark
**Plan Changes**:
- Task 1.5: Add connection pool option (default: per-command for simplicity)
- Benchmark: per-command vs pooled for 10/100/1000 concurrent readers
- Document tradeoffs in README

### SYN-H-004: Migration Testing (REV-H-002)
**Resolution**: Comprehensive migration test matrix
**Plan Changes**:
- Task 1.5: Add migration test module
- Test: v1→v2, v2→v3, v1→v3 (skip), rollback v2→v1 (documented as unsupported)
- Test: migration with data, migration with soft-deleted entries
- CI: Run migration tests on every PR

### SYN-H-005: CRL Distribution (REV-H-003)
**Resolution**: Document as out-of-scope for v1, add HTTP stub
**Plan Changes**:
- SPEC §2.2: Add "CRL distribution (HTTP/OCSP/LDAP)" to Out of Scope
- Task 3.3: Add `crl export --format pem|der|http` with local file server stub
- Document: "CRL distribution via external web server (Caddy/nginx)"

### SYN-H-006: Certificate Path Validation (REV-H-004)
**Resolution**: Add validation on import and use
**Plan Changes**:
- Task 3.1: Add `validate_chain()` using `x509-parser` + `webpki`/`rcgen` verification
- Validate: signature chain, validity periods, key usage, basic constraints, name constraints
- Reject invalid chains on import with clear error

### SYN-H-007: Entropy Validation (REV-H-005)
**Resolution**: Startup entropy health check
**Plan Changes**:
- Task 1.4: Add `entropy_check()` at keystore init/unlock
- Use `rand::rngs::OsRng` health check (try generating 32 bytes)
- Warn if entropy pool low (Linux: `/proc/sys/kernel/random/entropy_avail` < 1000)
- Fail hard if `getrandom` syscall fails

### SYN-H-008: Rekey Atomicity (FWD-M-001)
**Resolution**: Single transaction or two-phase
**Plan Changes**:
- Task 1.4: Implement rekey as single SQLite transaction
- Steps: BEGIN → derive new KEK → re-wrap all DEKs → update meta.salt → COMMIT
- On failure: ROLLBACK, original KEK unchanged
- Test: kill process mid-rekey, verify DB recoverable

### SYN-H-009: Argon2id CI Params (FWD-M-002)
**Resolution**: Configurable params, CI-friendly defaults
**Plan Changes**:
- Task 1.3: Add `argon2_ci_memory_kib`, `argon2_ci_iterations` to config
- Default: memory=64MB, iter=3; CI: memory=8MB, iter=1
- Document: "CI params reduce security for speed; never use in production"

### SYN-H-010: Revocation Reason Enum (FWD-M-003)
**Resolution**: Add RFC 5280 enum
**Plan Changes**:
- Task 3.1: Add `RevocationReason` enum to `ca.rs`
- Variants: Unspecified, KeyCompromise, CACompromise, AffiliationChanged, Superseded, CessationOfOperation, CertificateHold, RemoveFromCRL, PrivilegeWithdrawn, AACompromise
- Map to CRL reason codes (0-10)

---

## Medium Findings Resolution (Recommended)

### SYN-M-001: Key Expiration (REV-M-001)
**Resolution**: Optional `expires_at` field
**Plan Changes**:
- Task 2.1: Add `expires_at: Option<i64>` to `keys` table
- CLI: `key store --expires-in 30d` or `--expires-at TIMESTAMP`
- Background: Not enforced automatically (no daemon), but shown in `list` and `audit`

### SYN-M-002: Key Usage Tracking (REV-M-002)
**Resolution**: Add `last_accessed_at`, `access_count`
**Plan Changes**:
- Task 2.1: Add columns to `keys` table
- Update on `key get`, `key verify`, `cert issue` (for CA keys)
- CLI: `key list --unused-since 90d`

### SYN-M-003: Batch Operations (REV-M-003)
**Resolution**: Defer to v1.1
**Plan Changes**:
- SPEC §2.2: Add "Batch operations" to Out of Scope
- Document: "Use shell loops or scripting for bulk operations"

### SYN-M-004: Dry-Run Mode (REV-M-004)
**Resolution**: Add to all destructive commands
**Plan Changes**:
- Task 2.2: Add global `--dry-run` flag to CLI
- Implement in: `ca delete/purge`, `cert revoke/delete/purge`, `key delete/purge`, `backup restore`
- Dry-run shows what would change without writing

### SYN-M-005: Progress Indication (REV-M-005)
**Resolution**: Progress bars for long ops
**Plan Changes**:
- Task 1.4: Add `indicatif` crate for progress bars
- Show progress for: backup, restore, rekey, CA create (key gen), cert issue (key gen)
- Respect `--quiet` and `--json` flags (no progress in JSON mode)

### SYN-M-006: Config Validation (REV-M-006)
**Resolution**: Validate on load with clear errors
**Plan Changes**:
- Task 1.3: Add `config::validate()` called at startup
- Check: Argon2 params in range, paths exist/writable, cipher names valid
- Error: "Invalid config: argon2_memory_kib must be >= 1024"

### SYN-M-007: Database Integrity Check (REV-M-007)
**Resolution**: Add `verify` command
**Plan Changes**:
- Task 4.1: Add `audit verify` or `db verify` command
- Checks: `PRAGMA integrity_check`, `PRAGMA foreign_key_check`, schema version match, no orphaned entries
- Output: JSON with pass/fail per check

### SYN-M-008: HKDF Context Separation (REV-M-008)
**Resolution**: Use HKDF with context labels
**Plan Changes**:
- Task 1.4: Add `hkdf` crate
- DEK derivation: `HKDF-SHA256(KEK, salt, info="rw-secstore:dek:v1:{key_type}")`
- Context labels: `ca-root`, `ca-intermediate`, `cert-leaf`, `key-asymmetric`, `key-symmetric`, `secret`

---

## Low Findings Resolution (Phase 5 Polish)

| ID | Resolution | Phase |
|----|------------|-------|
| SYN-L-001 | Add `clap_mangen` for man page generation | 5 |
| SYN-L-002 | Add `tracing-subscriber` JSON layer config | 5 |
| SYN-L-003 | Add `MIGRATION_GUIDE.md` per version | 5 |
| SYN-L-004 | Dynamic completions for aliases (optional) | 5 |
| SYN-L-005 | Respect `CLICOLOR`, `CLICOLOR_FORCE`, `--color` | 5 |
| SYN-L-006 | `--version` shows build info (git commit, date, rustc) | 5 |

---

## Revised Plan: PLAN-2026-001-v2

### Phase 0: Research & Threat Model (Week 0) — NEW
| Task | Effort |
|------|--------|
| 0.1 Research (complete) | - |
| 0.2 Threat model document | 1h |
| 0.3 Security requirements finalization | 1h |

### Phase 1: Foundation (Week 1) — UPDATED
| Task | File(s) | Effort | Changes |
|------|---------|--------|---------|
| 1.1 Project setup & Cargo.toml | `Cargo.toml` | 2h | +uuid(v7), chrono, der-parser, asn1_rs, hkdf, subtle, zeroize, indicatif, criterion, tempfile, serial_test |
| 1.2 Error types | `src/error.rs` | 2h | +ConfigError, EntropyError |
| 1.3 Configuration + validation | `src/config.rs` | 4h | +validate(), CI params, precedence |
| 1.4 Crypto module | `src/crypto.rs` | 8h | +subtle, zeroize, hkdf, entropy check, rekey transaction, progress |
| 1.5 Storage + migrations + testing | `src/storage.rs` | 8h | +connection strategy, migration test matrix, integrity check |
| 1.6 Library entry point | `src/lib.rs` | 1h | - |

**Phase 1 Total**: ~25h (was 20h)

### Phase 2: Keystore Core (Week 1-2) — UPDATED
| Task | File(s) | Effort | Changes |
|------|---------|--------|---------|
| 2.1 Keystore service | `src/keystore.rs` | 8h | +expires_at, last_accessed, access_count, labels JSON |
| 2.2 CLI framework + global options | `src/cli.rs`, `src/main.rs` | 5h | +--dry-run, --color, progress, JSON output |
| 2.3 `init` command | `src/commands/init.rs` | 2h | +entropy check |
| 2.4 `unlock`/`lock`/`status` | `src/commands/unlock.rs` | 3h | +KEK caching with zeroize |
| 2.5 `key store`/`get`/`list`/`delete` | `src/commands/key.rs` | 5h | +--expires-in, --dry-run, progress |
| 2.6 `key compare`/`verify` | `src/commands/key.rs` | 4h | +constant-time (subtle) |

**Phase 2 Total**: ~27h (was 22h)

### Phase 3: Certificate Authority (Week 2-3) — UPDATED
| Task | File(s) | Effort | Changes |
|------|---------|--------|---------|
| 3.0 CRL generation spike | `src/ca_crl.rs` | 4h | NEW - spike before main CA work |
| 3.1 CA service + chain validation | `src/ca.rs` | 8h | +validate_chain(), RevocationReason enum |
| 3.2 Certificate issuance | `src/ca.rs` | 4h | - |
| 3.3 Revocation + CRL + export | `src/ca.rs` | 6h | +HTTP stub export, interop tests |
| 3.4 Renewal | `src/ca.rs` | 2h | - |
| 3.5 Import/Export (PEM, PKCS#12) | `src/ca.rs` | 4h | +interop test matrix |
| 3.6 CA/Cert CLI commands | `src/commands/ca.rs`, `src/commands/cert.rs` | 5h | +--dry-run, progress |

**Phase 3 Total**: ~33h (was 23h)

### Phase 4: Advanced Features (Week 3) — UPDATED
| Task | File(s) | Effort | Changes |
|------|---------|--------|---------|
| 4.1 Audit logging + verify | `src/audit.rs` | 4h | +db verify command |
| 4.2 Audit CLI commands | `src/commands/audit.rs` | 2h | - |
| 4.3 Backup/Restore | `src/backup.rs` | 5h | +progress, conflict resolution |
| 4.4 Backup CLI commands | `src/commands/backup.rs` | 2h | +--dry-run |
| 4.5 Config CLI commands | `src/commands/config.rs` | 3h | +rekey command, validation |
| 4.6 Shell completions | `src/commands/completion.rs` | 2h | +man page generation |

**Phase 4 Total**: ~18h (was 14h)

### Phase 5: Polish & Hardening (Week 3-4) — UPDATED
| Task | File(s) | Effort | Changes |
|------|---------|--------|---------|
| 5.1 Integration tests | `tests/integration_tests.rs` | 4h | +concurrent, crash, unicode, large scale |
| 5.2 README + docs + migration guide | `README.md`, `MIGRATION_GUIDE.md` | 3h | +threat model, config examples |
| 5.3 CI/CD pipeline | `.github/workflows/ci.yml` | 3h | +cargo audit, deny, clippy, coverage, benchmarks |
| 5.4 Performance benchmarks | `benches/` | 3h | +criterion for all perf targets |
| 5.5 Security review | - | 3h | +bandit, manual threat model review |

**Phase 5 Total**: ~16h (was 12h)

---

## Revised Totals

| Metric | Original | Revised | Delta |
|--------|----------|---------|-------|
| **Total Effort** | ~91h | ~122h | +34% |
| **Phase 1** | 20h | 25h | +25% |
| **Phase 2** | 22h | 27h | +23% |
| **Phase 3** | 23h | 33h | +43% |
| **Phase 4** | 14h | 18h | +29% |
| **Phase 5** | 12h | 16h | +33% |
| **Files** | 25 | 27 | +2 |
| **Dependencies** | ~20 | ~28 | +8 |

---

## Updated Acceptance Criteria (Additions)

| New Criteria | Source |
|--------------|--------|
| Threat model documented | SYN-C-001 |
| Constant-time key compare/verify | SYN-C-002 |
| Zeroizing master password | SYN-C-003 |
| Entropy health check at startup | SYN-H-007 |
| Migration test matrix (v1→v2, v2→v3, rollback) | SYN-H-004 |
| Certificate path validation on import | SYN-H-006 |
| Rekey as single transaction | SYN-H-008 |
| Config validation with clear errors | SYN-M-006 |
| Database integrity check command | SYN-M-007 |
| HKDF context separation for DEKs | SYN-M-008 |
| Dry-run on all destructive commands | SYN-M-004 |
| Progress bars for long operations | SYN-M-005 |

---

## Open Questions for Sign-off (Updated)

1. **Threat model scope**: Confirm local attacker + malicious input + side channels; exclude network/physical?
2. **Argon2id CI params**: memory=8MB, iter=1 acceptable for CI?
3. **CRL distribution**: Confirm out-of-scope for v1, HTTP stub sufficient?
4. **Connection strategy**: Per-command (simple) vs pooled (performance) — default per-command?
5. **Key expiration**: Optional field only, no enforcement — acceptable?
6. **Batch operations**: Confirm out-of-scope for v1?
7. **Man pages**: Generate at build time via `clap_mangen`?
8. **Config file location**: XDG (`~/.config/rw-secstore/`) vs project-local?

---

## Sign-off Checklist

Before approving this plan for TDD implementation:

- [ ] Threat model reviewed and approved
- [ ] All Critical findings resolved in revised plan
- [ ] All High findings resolved in revised plan
- [ ] Medium findings accepted/deferred with rationale
- [ ] Low findings scheduled for Phase 5
- [ ] Revised effort estimate (122h) accepted
- [ ] Open questions answered
- [ ] Dependencies approved (28 crates)
- [ ] CI/CD pipeline design accepted

---

## Next Steps

Upon sign-off:
1. **Phase 7**: TDD Implementation begins (Phase 1 tasks)
2. **Phase 8**: Adversarial Audit (after Phase 1-2 complete)
3. **Phase 9**: Bug Review (after Phase 3 complete)
4. **Phase 10**: Lint + Dead Code (continuous)
5. **Phase 11**: Test/Perf/Sec Documentation (Phase 5)

**Estimated Timeline**: 4 weeks (122h @ 30h/week) for Medium mode implementation.
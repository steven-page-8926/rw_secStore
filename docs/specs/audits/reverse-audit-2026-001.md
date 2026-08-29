# REVERSE AUDIT: rw_secstore Core Implementation Plan
## Finding Gaps in PLAN-2026-001 Against SPEC-2026-001 and Best Practices

## Document Identification
- **AUDIT ID**: REVERSE-2026-001
- **Version**: 1.0.0
- **Date**: 2026-08-28
- **Auditor**: ForgeCode (inline execution per plan-and-audit skill)
- **Status**: Complete

---

## Executive Summary

**Overall**: ⚠️ **PLAN HAS GAPS** — While forward coverage is good, the plan misses several critical implementation details, security considerations, and operational requirements.

**Critical Findings**: 3
**High Findings**: 5
**Medium Findings**: 8
**Low Findings**: 6

---

## Gap Analysis by Category

### 🔴 CRITICAL: Security & Correctness

| ID | Gap | SPEC Reference | Impact |
|----|-----|----------------|--------|
| REV-C-001 | **No threat model documented** — Plan doesn't define threat boundaries (local attacker, stolen DB, malicious input, side channels) | §5.3 Security Requirements | Cannot validate security controls without threat model |
| REV-C-002 | **No constant-time comparison for key verification** — REQ-KS-005/006 require constant-time but plan doesn't specify `subtle` crate usage | §4.3 REQ-KS-005/006, ADR-002 | Timing attacks on key comparison/verification |
| REV-C-003 | **No secure memory handling for master password** — Password read from CLI/env/file stays in `String` (not `Zeroizing`) | ADR-002, §5.3 | Master password in memory dumps, swap |

### 🟠 HIGH: Architecture & Implementation

| ID | Gap | SPEC Reference | Impact |
|----|-----|----------------|--------|
| REV-H-001 | **No connection pooling / reuse strategy** — Plan says "connection per command" but SQLite WAL benefits from persistent connections for concurrent readers | §7.4 Data Architecture, ADR-001 | Poor concurrent performance, lock contention |
| REV-H-002 | **No migration testing strategy** — Plan mentions migration runner but no test for v1→v2, v2→v3, rollback scenarios | REQ-DB-002, §8.1 TC-019 | Schema corruption risk in production |
| REV-H-003 | **No CRL distribution mechanism** — CRL generated but no HTTP/OCSP/ldap distribution, just file export | REQ-CA-004 | CRL useless without distribution |
| REV-H-004 | **No certificate path validation** — Plan issues certs but doesn't validate chains on import/use | REQ-CA-006, RFC 5280 | Invalid chains accepted |
| REV-H-005 | **No entropy source validation** — Plan uses `rand` but doesn't verify CSPRNG quality or handle entropy starvation | §5.3, ADR-002 | Weak keys on low-entropy systems (VMs, containers) |

### 🟡 MEDIUM: Functional Gaps

| ID | Gap | SPEC Reference | Impact |
|----|-----|----------------|--------|
| REV-M-001 | **No key expiration/TTL support** — Keys/secrets stored forever, no automatic expiry or warnings | Not in SPEC but expected for keystore | Operational burden, compliance gap |
| REV-M-002 | **No key usage tracking** — No "last used" timestamp, access count for audit/rotation | §5.3 Audit, REQ-AUDIT-001 | Cannot detect unused keys for rotation |
| REV-M-003 | **No batch operations** — CLI only supports single key/cert operations, no bulk import/export | Not in SPEC but CLI usability | Slow for large migrations |
| REV-M-004 | **No dry-run mode for destructive ops** — `delete`, `purge`, `revoke` have no `--dry-run` | Not in SPEC | Accidental data loss risk |
| REV-M-005 | **No progress indication for long ops** — Backup/restore/rekey on 10k entries need progress | §5.4 Usability | Poor UX, appears hung |
| REV-M-006 | **No config validation on load** — Invalid TOML/env values may cause runtime panic | §6.3 Config File | Misconfiguration silent until use |
| REV-M-007 | **No database integrity check command** — No `verify` or `fsck` equivalent for SQLite | Not in SPEC | Corruption undetected |
| REV-M-008 | **No key derivation for additional contexts** — Single KEK for all, no HKDF context separation for different key types | ADR-002 | Key separation not cryptographically enforced |

### 🔵 LOW: Polish & Developer Experience

| ID | Gap | SPEC Reference | Impact |
|----|-----|----------------|--------|
| REV-L-001 | **No man page generation** — Only `--help`, no `man rw-secstore` | §5.4 Usability | Standard Unix expectation |
| REV-L-002 | **No structured logging output** — Plan mentions JSON logging but no `tracing` subscriber config | §5.5 Operational | Hard to integrate with log aggregators |
| REV-L-003 | **No version upgrade guide** — Schema migrations need user-facing migration guide | Not in SPEC | User confusion on upgrades |
| REV-L-004 | **No shell completion for key aliases** — Completions only for commands, not dynamic values | §5.4, Task 4.6 | Reduced discoverability |
| REV-L-005 | **No color theme configuration** — Hardcoded colors, no `--color=never/auto/always` respect | §5.4 | Accessibility issue |
| REV-L-006 | **No `--version` output format** — Just version string, no build info (commit, date, rustc) | Not in SPEC | Debugging deployment issues |

---

## Missing Test Scenarios (Beyond SPEC §8.1)

| Missing Test | Why Needed |
|--------------|------------|
| Concurrent write stress test | SQLite WAL behavior under contention |
| Power loss during write (fsync) | Data integrity on crash |
| Maximum database size (10GB+) | Resource limits |
| Unicode in aliases/labels | Internationalization |
| Very long SAN lists (1000+) | DoS via certificate size |
| Expired CA issuing certs | Edge case validation |
| CRL with 10k revoked entries | Performance at scale |
| Backup/restore with corrupted source | Error handling |
| Rekey during concurrent access | Race condition |
| Config file with all env var overrides | Precedence testing |

---

## Missing ADR Traceability

| ADR | Plan Reference | Gap |
|-----|----------------|-----|
| ADR-001 SQLite | Task 1.5 | No link from code to ADR |
| ADR-002 Encryption | Task 1.4 | No link from code to ADR |
| ADR-003 CA | Task 3.1 | No link from code to ADR |
| ADR-004 CLI | Task 2.2 | No link from code to ADR |

**Recommendation**: Add `// ADR-XXX:` comments in relevant source files.

---

## Dependency Gaps (Cargo.toml)

| Missing Crate | Purpose | SPEC Reference |
|---------------|---------|----------------|
| `uuid` with `v7` feature | UUID v7 generation | §6.2 Schema |
| `chrono` | Timestamp handling | §6.2 Schema |
| `der-parser` / `asn1_rs` | CRL generation | REQ-CA-004, ADR-003 |
| `hkdf` | DEK derivation from KEK | ADR-002 |
| `subtle` | Constant-time comparison | REQ-KS-005/006 |
| `zeroize` | Memory zeroization | ADR-002, §5.3 |
| `criterion` | Benchmarks | Phase 5, §5.1 |
| `tempfile` | Test isolation | All test modules |
| `serial_test` | Sequential test execution | Integration tests |

---

## Operational Gaps

| Gap | Description | Mitigation |
|-----|-------------|------------|
| No systemd service file | For daemon mode (future) | Document as out of scope |
| No log rotation config | Audit log grows unbounded | Add retention to config |
| No SELinux/AppArmor profile | Confinement | Document as out of scope |
| No package signing | Supply chain | Add to CI/CD Phase 5 |
| No SBOM generation | Compliance | Add `cargo cyclonedx` to CI |

---

## SPEC vs Plan Discrepancies

| SPEC Item | Plan Status | Discrepancy |
|-----------|-------------|-------------|
| §5.1 "Unlock < 500ms (1000 entries)" | Not explicitly tested | Add benchmark test |
| §5.3 "Constant-time comparisons" | Not in crypto task | Add to Task 1.4 |
| §5.3 "Zeroize secrets on drop" | Not in crypto task | Add to Task 1.4 |
| §6.2 `labels` JSON column | Not in keystore task | Add to Task 2.1 |
| §6.2 `dns_names`/`ip_addresses` JSON | Not in CA task | Add to Task 3.1 |
| §6.3 Config precedence (env > file > default) | Not in config task | Add to Task 1.3 |
| §7.4 "Key hierarchy: Master→KEK→DEK" | Not in crypto task | Add to Task 1.4 |

---

## Recommendations Priority Order

### Must Fix Before Sign-off (Critical + High)
1. **REV-C-001**: Document threat model in SPEC or separate doc
2. **REV-C-002**: Add `subtle` crate to crypto module for constant-time ops
3. **REV-C-003**: Use `zeroize::Zeroizing<String>` for password handling
4. **REV-H-001**: Define connection strategy (pool vs per-command) with benchmarks
5. **REV-H-002**: Add migration test matrix (v1→v2, v2→v3, rollback)
6. **REV-H-003**: Document CRL distribution as out-of-scope or add HTTP server stub
7. **REV-H-004**: Add certificate path validation on import/use
8. **REV-H-005**: Add entropy health check at startup

### Should Fix Before Implementation (Medium)
9. **REV-M-001**: Add optional `expires_at` to key schema
10. **REV-M-002**: Add `last_accessed_at` to key schema
11. **REV-M-004**: Add `--dry-run` to all destructive commands
12. **REV-M-005**: Add progress bars for backup/restore/rekey
13. **REV-M-006**: Add config validation with clear error messages
14. **REV-M-007**: Add `verify` command for database integrity
15. **REV-M-008**: Use HKDF with context labels for DEK derivation

### Nice to Have (Low)
16-21. Address REV-L-001 through REV-L-006 in Phase 5 polish

---

## Conclusion

**REVERSE AUDIT FAILED** — The plan has significant gaps that must be addressed before sign-off. Critical security gaps (threat model, constant-time, memory handling) and architectural gaps (connection strategy, migration testing, CRL distribution) block production readiness.

**Required Actions**:
1. Update SPEC with threat model (or create SECURITY.md)
2. Revise PLAN to address all Critical and High findings
3. Add missing dependencies to Cargo.toml task
4. Add missing test scenarios to test plan
5. Re-run Forward Audit on revised plan

**Not Ready for Sign-off** → Return to Phase 2 (Plan Revision) after addressing findings.
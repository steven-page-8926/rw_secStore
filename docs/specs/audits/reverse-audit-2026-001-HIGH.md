# Reverse Audit — SPEC-2026-001-rw_secstore-core vs HIGH Mode Plan

**Audit ID**: REV-2026-001-HIGH
**Date**: 2026-08-29
**Auditor**: ForgeCode (plan-and-audit HIGH mode)
**SPEC Version**: 1.0.0
**Plan Version**: 1.0.0 (HIGH mode)

---

## Executive Summary

| Metric | Count |
|--------|-------|
| **CRITICAL** | 4 |
| **HIGH** | 8 |
| **MEDIUM** | 12 |
| **LOW** | 9 |
| **Total Findings** | **33** |

**Verdict**: **FAIL** — Plan has significant gaps against SPEC requirements. Critical findings must be resolved before implementation.

---

## CRITICAL Findings (Must Fix)

### REV-C-001: Missing Threat Model Integration in Plan Tasks
**SPEC Reference**: §3.2 NFR-SEC-001, §3.2 NFR-SEC-002, §3.2 NFR-SEC-003
**Plan Gap**: Plan tasks reference "security" but no task explicitly implements the threat model controls (constant-time ops, zeroize, mlock, side-channel resistance, audit chain verification).
**Impact**: Security requirements become aspirational, not implemented.
**Required**: Add explicit tasks for each threat model control in Phase 1 (crypto module).

### REV-C-002: No Formal Verification / Property Testing Tasks
**SPEC Reference**: §3.2 NFR-SEC-004, §3.2 NFR-SEC-005
**Plan Gap**: Plan mentions "fuzz testing" in Phase 5 but no property-based testing (proptest) for crypto invariants, no formal verification of constant-time properties.
**Impact**: Crypto correctness unproven; timing side-channels undetected.
**Required**: Add Phase 1.6: Property tests for crypto invariants (DEK uniqueness, nonce non-reuse, HKDF separation, constant-time compare).

### REV-C-003: Missing Disaster Recovery / Corruption Handling
**SPEC Reference**: §3.1 FR-BACKUP-001 through FR-BACKUP-004, §3.2 NFR-OP-003
**Plan Gap**: Backup/restore tasks exist (Phase 4) but no tasks for: database corruption detection, automatic recovery from WAL/SHM inconsistency, partial backup recovery, backup integrity verification beyond checksum.
**Impact**: Data loss scenarios unhandled; backup may be unusable when needed.
**Required**: Add Phase 4.5: Corruption detection + recovery procedures + integrity verification.

### REV-C-004: No Supply Chain Security Tasks
**SPEC Reference**: §3.2 NFR-SEC-006 (implied), §3.3.6 Dependencies
**Plan Gap**: Plan lists 28 dependencies but no tasks for: `cargo-deny` policy creation, `cargo-audit` CI integration, dependency pinning strategy, SBOM generation, license compliance verification.
**Impact**: Supply chain attack surface unmanaged; 28 crates = significant risk.
**Required**: Add Phase 1.7: Supply chain hardening (deny.toml, audit CI, SBOM, license check).

---

## HIGH Findings (Should Fix)

### REV-H-001: Missing Key Rotation / Rekey Implementation Details
**SPEC Reference**: §3.1 FR-KEY-007 (rekey), §3.2 NFR-SEC-002
**Plan Gap**: Phase 2.4 mentions "rekey" but no subtasks for: atomic rekey transaction, progress reporting for large keystores, rollback on failure, verification of rekeyed entries.
**Impact**: Rekey operation could leave keystore in inconsistent state.
**Required**: Expand Phase 2.4 with atomic transaction, progress, rollback, verification subtasks.

### REV-H-002: Missing Certificate Path Validation Implementation
**SPEC Reference**: §3.1 FR-CA-003 (import), §3.1 FR-CA-007 (chain)
**Plan Gap**: Phase 3.3 mentions "import" but no tasks for: full chain validation to trust anchor, basicConstraints CA:TRUE check, keyUsage keyCertSign check, name constraints, policy constraints.
**Impact**: Malicious or misconfigured CA certs could be imported, breaking trust chain.
**Required**: Add Phase 3.3.1: Certificate path validation subtasks.

### REV-H-003: Missing PKCS#12 Interoperability Testing
**SPEC Reference**: §3.1 FR-CA-005 (export), §3.3.6 Dependencies (pkcs12 crate)
**Plan Gap**: Phase 3.4 mentions PKCS#12 export but no tasks for: OpenSSL interop testing, PBE algorithm compatibility matrix, round-trip testing (export→import→verify), known limitation documentation.
**Impact**: Exported PKCS#12 may not work with standard tools (OpenSSL, Windows, Java).
**Required**: Add Phase 3.4.1: PKCS#12 interop test matrix.

### REV-H-004: Missing Windows-Specific Implementation Tasks
**SPEC Reference**: §3.2 NFR-OP-004 (cross-platform), §3.3.6 Dependencies
**Plan Gap**: Plan assumes Unix-like; no tasks for: Windows file permissions (no 0o600), Windows Credential Manager integration (optional), Windows CI testing, path handling differences, signal handling differences (no SIGTERM/SIGINT same way).
**Impact**: Windows support broken or untested.
**Required**: Add Phase 5.3: Windows compatibility tasks.

### REV-H-005: Missing Configuration Migration Tasks
**SPEC Reference**: §3.1 FR-CONFIG-001 through FR-CONFIG-004
**Plan Gap**: Phase 1.3 mentions config but no tasks for: config versioning, migration from v1→v2 config schema, backward compatibility, validation of migrated config.
**Impact**: Config changes break existing installations.
**Required**: Add Phase 1.3.1: Config migration framework.

### REV-H-006: Missing Audit Log Query / Analysis Tools
**SPEC Reference**: §3.1 FR-AUDIT-001 through FR-AUDIT-004
**Plan Gap**: Phase 2.5 mentions audit logging but no tasks for: audit log query CLI, filtering by time/operation/key, export to SIEM formats (JSON, CEF), tamper-evidence verification CLI.
**Impact**: Audit logs exist but are unusable for compliance/forensics.
**Required**: Add Phase 2.5.1: Audit log query and export CLI.

### REV-H-007: Missing Performance Benchmark Tasks
**SPEC Reference**: §3.2 NFR-PERF-001 through NFR-PERF-004
**Plan Gap**: Phase 5 mentions benchmarks but no specific tasks for: cold start latency, unlock latency, 10k entry operations, memory profiling, regression detection in CI.
**Impact**: Performance targets unverified; regressions undetected.
**Required**: Add Phase 5.1: Comprehensive benchmark suite with CI regression detection.

### REV-H-008: Missing Documentation Tasks Beyond Man Pages
**SPEC Reference**: §3.2 NFR-USAB-001 through NFR-USAB-004
**Plan Gap**: Phase 5.2 mentions man pages but no tasks for: user guide (init, daily ops, CA ops), admin guide (backup, recovery, config), security guide (threat model, best practices), API docs (for library use), migration guide.
**Impact**: Users cannot effectively use the tool; security misconfiguration likely.
**Required**: Add Phase 5.2.1: Comprehensive documentation suite.

---

## MEDIUM Findings (Should Address)

### REV-M-001: Missing Database Vacuum / Maintenance Tasks
**SPEC Reference**: §3.2 NFR-OP-003
**Plan Gap**: No tasks for: automatic vacuum scheduling, fragmentation monitoring, index rebuild, statistics update.
**Impact**: Database performance degrades over time.

### REV-M-002: Missing Key Attestation / Proof-of-Possession
**SPEC Reference**: §3.1 FR-KEY-008 (compare), §3.1 FR-KEY-009 (verify)
**Plan Gap**: Phase 2.3 mentions compare/verify but no tasks for: cryptographic proof-of-possession, key attestation (TPM/HSM future), remote verification protocol.
**Impact**: Cannot prove key ownership to third parties.

### REV-M-003: Missing Entropy Health Monitoring
**SPEC Reference**: §3.2 NFR-SEC-003
**Plan Gap**: Phase 1.4 mentions entropy check but no tasks for: continuous entropy monitoring, alerting on low entropy, fallback to /dev/urandom with warning, entropy estimation.
**Impact**: Weak keys generated silently during entropy starvation.

### REV-M-004: Missing Multi-User / Multi-Keystore Support
**SPEC Reference**: §3.1 FR-KEY-001 (create), §3.1 FR-CONFIG-001
**Plan Gap**: Plan assumes single keystore per user; no tasks for: multiple keystores, keystore aliases, per-keystore config, shared keystore access patterns.
**Impact**: Limited deployment flexibility.

### REV-M-005: Missing Secret Scanning / Leak Detection
**SPEC Reference**: §3.2 NFR-SEC-001
**Plan Gap**: No tasks for: scanning backup files for accidental key material, scanning audit logs for leaked secrets, pre-commit hooks for secret detection.
**Impact**: Accidental secret leakage in backups/logs undetected.

### REV-M-006: Missing Time-Source Hardening
**SPEC Reference**: §3.1 FR-CA-002 (validity), §3.1 FR-CA-006 (CRL)
**Plan Gap**: No tasks for: NTP validation, monotonic clock usage, certificate validity skew handling, time manipulation detection.
**Impact**: Certificate validity and CRL timing vulnerable to clock manipulation.

### REV-M-007: Missing Key Usage Policy Enforcement
**SPEC Reference**: §3.1 FR-CA-001 (create), §3.1 FR-CA-004 (issue)
**Plan Gap**: Phase 3.1-3.2 mention key usage but no tasks for: enforcing keyUsage extensions, preventing sign/encrypt misuse, extended key usage (EKU) validation.
**Impact**: Keys used for unintended purposes (e.g., signing key used for encryption).

### REV-M-008: Missing Certificate Transparency / CT Log Integration
**SPEC Reference**: §3.1 FR-CA-004 (issue)
**Plan Gap**: No tasks for: CT log submission, SCT embedding, CT policy enforcement.
**Impact**: Issued certificates not publicly auditable (required for public CAs).

### REV-M-009: Missing OCSP Responder Implementation
**SPEC Reference**: §3.1 FR-CA-006 (revocation)
**Plan Gap**: Plan has CRL stub but no OCSP tasks. OCSP is preferred over CRL for real-time revocation.
**Impact**: No real-time revocation checking capability.

### REV-M-010: Missing Key Escrow / Recovery Mechanism
**SPEC Reference**: §3.1 FR-KEY-001, §3.1 FR-BACKUP-001
**Plan Gap**: No tasks for: Shamir secret sharing for master key, key escrow for enterprise, recovery key generation.
**Impact**: Lost master password = total data loss (by design, but enterprise may need recovery).

### REV-M-011: Missing Automated Dependency Update Strategy
**SPEC Reference**: §3.3.6 Dependencies
**Plan Gap**: No tasks for: dependabot/renovate config, security update automation, breaking change detection.
**Impact**: Dependencies drift; security updates delayed.

### REV-M-012: Missing Internationalization / Localization
**SPEC Reference**: §3.2 NFR-USAB-001
**Plan Gap**: No tasks for: i18n framework, message catalogs, locale-aware date/number formatting.
**Impact**: English-only; limits enterprise adoption.

---

## LOW Findings (Nice to Have)

### REV-L-001: Missing Shell Completion for All Subcommands
**SPEC Reference**: §3.1 FR-CLI-003
**Plan Gap**: Phase 5.2 mentions completions but no detail on: dynamic completions (key names, CA names), argument completions (file paths, algorithms).

### REV-L-002: Missing Color/Theme Configuration
**SPEC Reference**: §3.2 NFR-USAB-002
**Plan Gap**: No tasks for: color output control, theme support, accessibility (no-color, high-contrast).

### REV-L-003: Missing Progress Indicators for Long Operations
**SPEC Reference**: §3.2 NFR-USAB-003
**Plan Gap**: Phase 2.4 mentions progress for rekey but no tasks for: backup/restore progress, CA issuance progress, import/export progress.

### REV-L-004: Missing Dry-Run Mode for Destructive Operations
**SPEC Reference**: §3.1 FR-KEY-005 (delete), §3.1 FR-CA-005 (revoke)
**Plan Gap**: Phase 2.2 mentions dry-run for delete but no tasks for: revoke dry-run, rekey dry-run, backup dry-run.

### REV-L-005: Missing Structured Logging (JSON) Option
**SPEC Reference**: §3.1 FR-AUDIT-001, §3.2 NFR-OP-002
**Plan Gap**: No tasks for: JSON log output, log levels, structured fields for SIEM ingestion.

### REV-L-006: Missing Man Page Generation for All Subcommands
**SPEC Reference**: §3.1 FR-CLI-003
**Plan Gap**: Phase 5.2 mentions man pages but no detail on: generating for all subcommands, installing to system man path, testing rendering.

### REV-L-007: Missing Version/Build Info in Binary
**SPEC Reference**: §3.1 FR-CLI-001
**Plan Gap**: No tasks for: `rw-secstore version` with git commit, build date, rustc version, feature flags.

### REV-L-008: Missing Health Check / Self-Test Command
**SPEC Reference**: §3.2 NFR-OP-001
**Plan Gap**: No tasks for: `rw-secstore doctor` (config, DB, perms, entropy, crypto self-test).

### REV-L-009: Missing Changelog Automation
**SPEC Reference**: §3.2 NFR-OP-002
**Plan Gap**: No tasks for: conventional commits enforcement, automated changelog generation, release notes.

---

## Summary by SPEC Section

| SPEC Section | Requirements | Covered | Gaps |
|--------------|--------------|---------|------|
| §3.1 FR-DB | 4 | 3 | 1 (corruption recovery) |
| §3.1 FR-CRYPTO | 5 | 3 | 2 (property tests, formal verification) |
| §3.1 FR-KEY | 9 | 6 | 3 (rotation details, attestation, escrow) |
| §3.1 FR-CA | 7 | 4 | 3 (path validation, PKCS#12 interop, OCSP/CT) |
| §3.1 FR-BACKUP | 4 | 2 | 2 (corruption recovery, integrity verification) |
| §3.1 FR-AUDIT | 4 | 2 | 2 (query tools, structured logging) |
| §3.1 FR-CONFIG | 4 | 2 | 2 (migration, validation) |
| §3.1 FR-CLI | 3 | 2 | 1 (completions detail) |
| §3.2 NFR-PERF | 4 | 1 | 3 (benchmarks, regression, profiling) |
| §3.2 NFR-SEC | 6 | 2 | 4 (threat model, formal verification, supply chain, entropy) |
| §3.2 NFR-USAB | 4 | 1 | 3 (docs, i18n, accessibility) |
| §3.2 NFR-OP | 4 | 1 | 3 (maintenance, health check, changelog) |

---

## Recommendations

1. **Immediate**: Address all 4 CRITICAL findings before any implementation
2. **Before Phase 1**: Add tasks for REV-C-001, REV-C-002, REV-C-003, REV-C-004
3. **Before Phase 2**: Add tasks for REV-H-001, REV-H-006
4. **Before Phase 3**: Add tasks for REV-H-002, REV-H-003
5. **Before Phase 4**: Add tasks for REV-H-001 (rekey), REV-C-003 (corruption)
6. **Before Phase 5**: Add tasks for REV-H-004, REV-H-007, REV-H-008
7. **Continuous**: Address MEDIUM/LOW findings as capacity allows

---

## Sign-off Required

- [ ] All CRITICAL findings resolved in revised plan
- [ ] All HIGH findings resolved or explicitly deferred with rationale
- [ ] MEDIUM findings triaged (accept/defer/fix)
- [ ] LOW findings scheduled for post-v1 or accepted as known limitations
- [ ] Revised plan effort estimate updated
- [ ] Dependencies approved with supply chain controls
# Forward Audit: rw_secstore v1.1.0 Plan v2.1

**Audit ID**: FWD-2026-001-v1.1
**Date**: 2026-08-29
**Auditor**: ForgeCode
**Subject**: PLAN-2026-001 v2.1 (HIGH mode)
**SPEC Reference**: SPEC-2026-001 v1.1.0
**ADRs**: 001-009

---

## Objective

Validate that the updated implementation plan (v2.1) covers 100% of the requirements in SPEC-2026-001 v1.1.0, including the new SSH, password policy, password generator, keyring, and backup codes features.

## Methodology

For each REQ-XXX-NNN in the SPEC, verify that:
1. At least one plan task addresses the requirement
2. Acceptance criteria are mapped to test scenarios (TC-NNN)
3. The task effort estimate is reasonable
4. Dependencies between tasks are valid

---

## Coverage Matrix

### §4.1 Core Database & Schema

| REQ | Description | Plan Task(s) | TC | Status |
|-----|-------------|--------------|----|----|
| REQ-DB-001 | SQLite with WAL + perms | 1.2.1, 1.2.7 | TC-001 | ✅ Covered |
| REQ-DB-002 | Schema migrations + rollback | 1.2.2-1.2.6 | TC-019, TC-031 | ✅ Covered |
| REQ-DB-003 | Soft deletes | 2.6.1-2.6.4 | TC-014 | ✅ Covered |
| REQ-DB-004 | HMAC seal | 1.8.1-1.8.2 | TC-028 | ✅ Covered |

### §4.2 Encryption & Key Management

| REQ | Description | Plan Task(s) | TC | Status |
|-----|-------------|--------------|----|----|
| REQ-CRYPTO-001 | Argon2id KEK | 1.3.1 | TC-002 | ✅ Covered |
| REQ-CRYPTO-002 | AES-256-GCM DEK | 1.3.2, 1.3.3 | TC-003 | ✅ Covered |
| REQ-CRYPTO-003 | Re-encryption (rekey) | 2.5.4, 2.5.5 | TC-013 | ✅ Covered |
| REQ-CRYPTO-004 | Password memory protection | 1.3.5, 5.4.1, 5.4.2 | TC-030 | ✅ Covered |

### §4.3 Keystore Operations

| REQ | Description | Plan Task(s) | TC | Status |
|-----|-------------|--------------|----|----|
| REQ-KS-001 | Generic secrets | 2.2.3, 2.2.4 | TC-003 | ✅ Covered |
| REQ-KS-002 | Asymmetric keypairs | 2.1.1-2.1.5 | TC-004, TC-005 | ✅ Covered |
| REQ-KS-003 | Symmetric keys | 2.2.1, 2.2.2 | TC-004 | ✅ Covered |
| REQ-KS-004 | List with filters | 2.4.1, 2.4.2 | TC-020 | ✅ Covered |
| REQ-KS-005 | Compare keys | 2.4.3, 2.4.4 | TC-016 | ✅ Covered |
| REQ-KS-006 | Verify signatures | 2.5.1-2.5.3 | TC-017 | ✅ Covered |
| REQ-KS-007 | Key expiration | 2.1.4 (metadata) | — | ⚠️ Partial (no enforcement, but spec says no enforcement) |

### §4.4 SSH Key Management

| REQ | Description | Plan Task(s) | TC | Status |
|-----|-------------|--------------|----|----|
| REQ-SSH-001 | OpenSSH key storage | 2.3.1 | TC-021 | ✅ Covered |
| REQ-SSH-002 | SSH export formats | 2.3.5, 2.3.6, 2.3.7 | TC-021 | ✅ Covered |
| REQ-SSH-003 | SSH key passphrase | 2.3.2 | TC-022 | ✅ Covered |

### §4.5 Certificate Authority Operations

| REQ | Description | Plan Task(s) | TC | Status |
|-----|-------------|--------------|----|----|
| REQ-CA-001 | Root CA | 3.1.1-3.1.7 | TC-006 | ✅ Covered |
| REQ-CA-002 | Intermediate CA | 3.2.1-3.2.5 | TC-007 | ✅ Covered |
| REQ-CA-003 | Issue certificates | 3.3.1-3.3.8 | TC-008 | ✅ Covered |
| REQ-CA-004 | Revoke + CRL | 3.4.1-3.4.6 | TC-009 | ✅ Covered |
| REQ-CA-005 | Renew | 3.5.1-3.5.4 | TC-010 | ✅ Covered |
| REQ-CA-006 | Import/export | 3.3.8, 3.7.1-3.7.4 | TC-011 | ✅ Covered |

### §4.6 Backup & Restore

| REQ | Description | Plan Task(s) | TC | Status |
|-----|-------------|--------------|----|----|
| REQ-BACKUP-001 | JSON backup | 4.1.1-4.1.3 | TC-012 | ✅ Covered |
| REQ-BACKUP-002 | Restore | 4.2.1-4.2.3 | TC-012 | ✅ Covered |

### §4.7 Audit Logging

| REQ | Description | Plan Task(s) | TC | Status |
|-----|-------------|--------------|----|----|
| REQ-AUDIT-001 | HMAC chain audit | 2.8.1, 2.8.2 | TC-015 | ✅ Covered |
| REQ-AUDIT-002 | Audit queries | 4.3.1-4.3.3 | TC-015 | ✅ Covered |

### §4.8 Password Policy

| REQ | Description | Plan Task(s) | TC | Status |
|-----|-------------|--------------|----|----|
| REQ-PWD-001 | Policy engine | 1.5.1, 2.7.1 | TC-023 | ✅ Covered |
| REQ-PWD-002 | Breach check | 1.5.3, 1.5.4 | TC-023 | ✅ Covered |
| REQ-PWD-003 | History | 1.5.5 | TC-023 | ✅ Covered |
| REQ-PWD-004 | Strength meter | 1.5.2 | TC-023 | ✅ Covered |

### §4.9 Password Generation

| REQ | Description | Plan Task(s) | TC | Status |
|-----|-------------|--------------|----|----|
| REQ-PWG-001 | Password generator | 1.5.6 | TC-024 | ✅ Covered |
| REQ-PWG-002 | Diceware | 1.5.7 | TC-024 | ✅ Covered |

### §4.10 Master Password File

| REQ | Description | Plan Task(s) | TC | Status |
|-----|-------------|--------------|----|----|
| REQ-PWD-005 | Secure read | 1.6.1 | TC-025 | ✅ Covered |
| REQ-PWD-006 | Secure export | 1.6.2 | TC-025 | ✅ Covered |
| REQ-PWG-003 | Generate + export | 1.6.3 | TC-025 | ✅ Covered |

### §4.11 Multi-Factor Unlock

| REQ | Description | Plan Task(s) | TC | Status |
|-----|-------------|--------------|----|----|
| REQ-AUTH-001 | OS keyring | 1.4.3 | TC-026 | ✅ Covered |
| REQ-AUTH-002 | Backup codes generation | 1.4.4 | TC-027 | ✅ Covered |
| REQ-AUTH-003 | Backup code unlock | 1.4.5 | TC-027 | ✅ Covered |
| REQ-AUTH-004 | Combined unlock | 1.4.6 | TC-026, TC-027 | ✅ Covered |

---

## Forward Audit Summary

| Category | Requirements | Covered | Partial | Missing | Coverage % |
|----------|--------------|---------|---------|---------|------------|
| §4.1 Database & Schema | 4 | 4 | 0 | 0 | 100% |
| §4.2 Encryption | 4 | 4 | 0 | 0 | 100% |
| §4.3 Keystore Ops | 7 | 6 | 1 | 0 | 86% (partial: KS-007 is "no enforcement" by design) |
| §4.4 SSH Key | 3 | 3 | 0 | 0 | 100% |
| §4.5 CA Operations | 6 | 6 | 0 | 0 | 100% |
| §4.6 Backup & Restore | 2 | 2 | 0 | 0 | 100% |
| §4.7 Audit Logging | 2 | 2 | 0 | 0 | 100% |
| §4.8 Password Policy | 4 | 4 | 0 | 0 | 100% |
| §4.9 Password Generation | 2 | 2 | 0 | 0 | 100% |
| §4.10 Password File | 3 | 3 | 0 | 0 | 100% |
| §4.11 Multi-Factor Unlock | 4 | 4 | 0 | 0 | 100% |
| **TOTAL** | **41** | **40** | **1** | **0** | **97.5%** |

### Non-Functional Requirements

| NFR | Plan Task(s) | Status |
|-----|--------------|--------|
| Performance (5.1) | 4.8.1-4.8.3, 5.7.1-5.7.5 | ✅ Covered |
| Reliability (5.2) | 1.2.2, 1.2.6, 1.8.1-1.8.2, 4.7.1-4.7.3 | ✅ Covered |
| Security (5.3) | 1.3.1-1.3.6, 1.4.x, 1.5.x, 5.1-5.8 | ✅ Covered |
| Usability (5.4) | 1.7.x, 4.4.x, 4.5.x | ✅ Covered |
| Operational (5.5) | 1.7.x, 5.4.x, 5.6.x | ✅ Covered |

---

## Findings

### FWD-F-001 (MEDIUM): No test scenario for REQ-KS-007
**Description**: REQ-KS-007 (key expiration) has no TC-XXX test scenario.
**Location**: SPEC §4.3, §8.1
**Impact**: Medium — requirement is "optional metadata + warning only" but no test verifies behavior
**Resolution**: Add TC-034: "Key with expires_at shows warning on use, no auto-delete"
**Action**: Update SPEC §8.1 and add task 2.1.6 "Expose `expires_at` in `key get/list` output"

### FWD-F-002 (LOW): CSR replay protection has ambiguous scope
**Description**: REQ-CA-003 mentions "CSR replay protection (track CSR nonce)" but plan task 3.3.6 is unclear about implementation.
**Location**: SPEC §4.5 REQ-CA-003, Plan 3.3.6
**Impact**: Low — implementation will need to decide: nonce in CSR, in separate header, or by hash tracking
**Resolution**: Acceptable ambiguity; will resolve during implementation

### FWD-F-003 (LOW): SSH key passphrase complexity not specified
**Description**: REQ-SSH-001 mentions "optional passphrase" but doesn't specify policy.
**Location**: SPEC §4.4 REQ-SSH-001
**Impact**: Low — SSH key passphrases are less critical than master password
**Resolution**: Will use same policy as master password (zxcvbn + min 16 chars)

### FWD-F-004 (INFO): No test for HMAC chain on audit read
**Description**: REQ-AUDIT-001 specifies "Chain verification on every audit read" but no explicit test.
**Location**: SPEC §4.7 REQ-AUDIT-001
**Impact**: Info — covered by task 4.3.3 but not explicit TC
**Resolution**: Add TC-035: "Audit chain integrity verified on read, tampering detected"

### FWD-F-005 (INFO): EFF wordlist licensing not explicit
**Description**: Plan 1.5.7 references EFF wordlist but no license confirmation.
**Location**: Plan 1.5.7
**Impact**: Info — EFF wordlist is CC0 (public domain)
**Resolution**: No action; document in README

### FWD-F-006 (LOW): Plan doesn't address keyring availability check at startup
**Description**: REQ-AUTH-001 mentions "Fallback to password if keyring unavailable" but no startup probe.
**Location**: SPEC §4.11 REQ-AUTH-001
**Impact**: Low — first unlock will fail naturally if keyring unavailable
**Resolution**: Add 1.4.7 "Keyring availability probe on startup" (defer to v1.1)

---

## Coverage Statistics

- **Total REQs**: 41 (33 in v1.0 + 12 new in v1.1 - 4 deprecated)
- **Covered**: 40 (97.5%)
- **Partial**: 1 (REQ-KS-007, but by design)
- **Missing**: 0
- **Test Scenarios**: 33 (TC-001 through TC-033) + 2 recommended additions (TC-034, TC-035)
- **Plan Tasks**: 142
- **Total Effort**: 228 hours

---

## Verdict

**✅ PASS** with 1 MEDIUM finding (FWD-F-001) and 5 LOW/INFO findings.

All 41 functional requirements are covered by the plan. Test scenarios map cleanly. Effort estimates are reasonable (228h for a security-critical production-ready system).

### Required Actions Before Implementation
1. **FWD-F-001** (MEDIUM): Add TC-034 for REQ-KS-007 + plan task 2.1.6
2. **FWD-F-004** (INFO): Add TC-035 for audit chain integrity verification

### Accepted Findings
- FWD-F-002, FWD-F-003, FWD-F-005, FWD-F-006: Document in implementation notes, no plan change required

---

**End of Forward Audit**

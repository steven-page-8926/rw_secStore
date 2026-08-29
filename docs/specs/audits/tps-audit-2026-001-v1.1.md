# Test/Perf/Sec Documentation Audit: rw_secstore v1.1.0 Plan v2.1

**Audit ID**: TPS-2026-001-v1.1
**Date**: 2026-08-29
**Auditor**: ForgeCode
**Subject**: PLAN-2026-001 v2.1 (HIGH mode)
**Methodology**: Verify test, performance, and security documentation completeness

---

## Test Documentation

### Required Test Categories

| Category | Plan Task | Documented? | Status |
|----------|-----------|-------------|--------|
| Unit tests | All tasks | Per-task TDD | ✅ Plan specifies |
| Integration tests | Phase 4.7 | Section in plan | ✅ Documented |
| Property tests (Hypothesis) | 1.10.x | Section in plan | ✅ Documented |
| Fuzz tests | 5.2.x | Section in plan | ✅ Documented |
| End-to-end CLI tests | Phase 4.5 | Implicit | ⚠️ Add explicit section |
| Security tests | 1.3.4, 2.4.4, 5.8.x | Scattered | ⚠️ Add section |
| Performance benchmarks | 4.8.x, 5.7.x | Section in plan | ✅ Documented |
| Migration tests | 1.2.6, 1.2.7 | Documented | ✅ Good |
| Concurrency tests | 2.9.3, 4.7.3 | Documented | ✅ Good |
| Cross-platform tests | 5.3.x | Section in plan | ✅ Documented |

### Test Coverage Targets (from SPEC §8.2)

| Module | Target | Plan Documents? | Status |
|--------|--------|-----------------|--------|
| crypto | 95% | Plan 5.7.x | ✅ |
| storage | 90% | Plan 5.7.x | ✅ |
| keystore | 90% | Plan 5.7.x | ✅ |
| ca | 85% | Plan 5.7.x | ✅ |
| backup | 90% | Plan 5.7.x | ✅ |
| audit | 85% | Plan 5.7.x | ✅ |
| cli | 80% | Plan 5.7.x | ✅ |
| auth | 90% | Not specified | ⚠️ |
| ssh | 85% | Not specified | ⚠️ |
| policy | 90% | Not specified | ⚠️ |
| **Overall** | **85%** | Plan 5.7.x | ✅ |

### Property Tests Required (from plan 1.10.x)

| Property | Plan Task | Documented? |
|----------|-----------|-------------|
| Argon2id determinism | 1.10.2 | ✅ |
| AES-GCM round-trip | 1.10.3 | ✅ |
| HKDF context separation | 1.10.4 | ✅ |
| Nonce uniqueness | 1.10.5 | ✅ |
| Backup code base32 | 1.10.6 | ✅ |
| Password gen entropy | 1.10.7 | ✅ |
| Constant-time compare | 1.10.8 | ✅ |
| SSH key round-trip | 2.3.9 | ✅ |

---

## Performance Documentation

### Required Benchmarks (from SPEC §5.1)

| Metric | Target | Plan Task | Documented? |
|--------|--------|-----------|-------------|
| Startup Time | < 100ms | 5.7.4 | ✅ |
| Unlock Time | < 500ms (1k) | 5.7.5 | ✅ |
| Key Store | < 50ms | 4.8.1 | ✅ |
| Key Retrieve | < 30ms | 4.8.1 | ✅ |
| List (1k) | < 100ms | 4.8.1 | ✅ |
| CA Create | < 2s (RSA-4096) | 4.8.1 | ✅ |
| Cert Issue | < 500ms (RSA-2048) | 4.8.1 | ✅ |
| Backup (1k) | < 5s | 4.8.1 | ✅ |
| Restore (1k) | < 10s | 4.8.1 | ✅ |
| SSH Key Gen | < 100ms (Ed25519) | 4.8.1 | ✅ |
| Password Gen | < 10ms | 4.8.1 | ✅ |
| Password Check | < 50ms | 4.8.1 | ✅ |
| Keyring Unlock | < 200ms | 4.8.1 | ✅ |
| Backup Code Unlock | < 1s | 4.8.1 | ✅ |

### Benchmark Tool

Plan specifies Criterion (good). Should also include:
- `cargo bench --workspace` for all benchmarks
- Historical tracking (criterion stores results in `target/criterion/`)
- Regression detection (fail if 10% slower than baseline)

### Performance Profiling

Plan 5.7.2 mentions memory profiling. Should add:
- `cargo flamegraph` for CPU hotspots
- `heaptrack` or `dhat` for memory
- `perf` for cache analysis (side-channel concern)

---

## Security Documentation

### Threat Model (from plan 7.1)

| Item | Documented? | Status |
|------|-------------|--------|
| Threat model stated | Section 1 | ✅ |
| In-scope attacks | Section 1 | ✅ |
| Out-of-scope attacks | Section 1 | ✅ |
| Mitigation per attack | Implicit | ⚠️ Add explicit mapping |
| Residual risk | Not specified | ⚠️ Add |

### Security Audit Checklist

| Check | Plan Task | Documented? |
|-------|-----------|-------------|
| `cargo audit` | 5.1.1 | ✅ |
| `cargo deny` | 5.1.2 | ✅ |
| SBOM | 5.1.3 | ✅ |
| Fuzz testing | 5.2.x | ✅ |
| Constant-time verification | 1.3.4, 2.4.4 | ✅ |
| Pen test (self) | 5.8.x | ✅ |
| External pen test | 5.8.4 | ✅ |
| Side-channel testing | 5.8.3 | ✅ |
| Timing attack testing | 5.8.1 | ✅ |

### Required Security Documentation

| Document | Plan Section | Status |
|----------|--------------|--------|
| `SECURITY.md` | 5.5.3 | ✅ |
| Threat model | Plan 7.1 + dedicated doc | ⚠️ Add dedicated doc |
| Security advisories process | Implicit | ⚠️ Add |
| Incident response | Not specified | ⚠️ Add |
| Cryptographic review | Plan 5.8.2 | ✅ |
| Supply chain policy | Plan 5.1.x | ✅ |

### Compliance Documentation

| Standard | Plan Section | Status |
|----------|--------------|--------|
| FIPS 140-3 algorithms | SPEC §5.3, Plan 5.4 | ✅ |
| NIST SP 800-57 key mgmt | SPEC §3, references | ✅ |
| NIST SP 800-63B password | SPEC §4.8, Plan 1.5.x | ✅ |
| SOC 2 audit logging | SPEC §4.7 | ✅ |
| ISO 27001 | SPEC §2.4 | ✅ |
| GDPR right-to-erasure | SPEC §4.7 (purge) | ✅ |

---

## Findings

### TPS-F-001 (MEDIUM): No dedicated test plan document
**Description**: Test info scattered across plan, SPEC, and risk register.
**Resolution**: Create `docs/TEST_PLAN.md` with full test matrix

### TPS-F-002 (MEDIUM): No security test suite separately tracked
**Description**: Security tests mixed with unit tests.
**Resolution**: Use `#[cfg(feature = "security-tests")]` or `tests/security/` directory

### TPS-F-003 (MEDIUM): No benchmark baseline established
**Description**: Plan 5.7.5 measures but doesn't establish baseline.
**Resolution**: Establish baseline on first run, fail CI on >10% regression

### TPS-F-004 (LOW): No memory profiling in plan
**Description**: Plan 5.7.2 says "memory usage profiling" but no tool specified.
**Resolution**: Specify `dhat` or `heaptrack`

### TPS-F-005 (LOW): No coverage threshold enforcement
**Description**: Plan specifies targets but no enforcement mechanism.
**Resolution**: Use `cargo-tarpaulin` with `--fail-under 85`

### TPS-F-006 (LOW): No threat model document
**Description**: Threat model in plan but not a dedicated document.
**Resolution**: Create `docs/THREAT_MODEL.md` with full analysis

### TPS-F-007 (LOW): No security advisory policy
**Description**: SECURITY.md mentioned but no process for handling.
**Resolution**: Document process: receive → triage → fix → disclose

### TPS-F-008 (LOW): No fuzz corpus management
**Description**: Fuzz tests will create corpus, but no management plan.
**Resolution**: Document: corpus in `fuzz/corpus/`, regression in `fuzz/artifacts/`

---

## TPS Audit Summary

| Severity | Count |
|----------|-------|
| Medium | 3 |
| Low | 5 |
| **Total** | **8** |

### Required Actions (Medium)

1. **TPS-F-001**: Create `docs/TEST_PLAN.md`
2. **TPS-F-002**: Separate security test suite
3. **TPS-F-003**: Establish benchmark baseline + regression detection

### Low-Priority Actions

4. **TPS-F-004**: Specify memory profiling tool
5. **TPS-F-005**: Add coverage threshold enforcement
6. **TPS-F-006**: Create dedicated `THREAT_MODEL.md`
7. **TPS-F-007**: Document security advisory process
8. **TPS-F-008**: Document fuzz corpus management

---

**End of Test/Perf/Sec Documentation Audit**

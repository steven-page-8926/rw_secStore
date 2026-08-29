# Test / Performance / Security Documentation Audit (HIGH Mode)

**Audit ID**: TPS-2026-001-HIGH
**Date**: 2026-08-29
**Auditor**: ForgeCode (plan-and-audit HIGH mode)
**Focus**: Test strategy, performance benchmarks, security documentation requirements
**SPEC Version**: 1.0.0
**Plan Version**: 1.0.0 (HIGH mode)

---

## Executive Summary

| Category | Count | Description |
|----------|-------|-------------|
| **Test Strategy Gaps** | 12 | Missing test types, coverage targets, test infrastructure |
| **Performance Requirements** | 8 | Undefined benchmarks, regression detection, profiling |
| **Security Documentation** | 10 | Threat model, crypto design, audit procedures, compliance |
| **Total** | **30** | |

**Verdict**: **CONDITIONAL PASS** — Plan has test/perf/sec tasks but lacks detailed specifications. Must define before implementation.

---

## Test Strategy Documentation

### TEST-001: Test Pyramid Definition
**Required**: Explicit test pyramid with targets.

| Layer | Target | Tools | Coverage |
|-------|--------|-------|----------|
| **Unit** | 80%+ | `cargo test` | All pure functions, crypto primitives, parsers |
| **Integration** | 100% critical paths | `cargo test --test integration` | DB ops, CLI commands, CA workflows |
| **Property** | 20+ properties | `proptest` | Crypto invariants, serialization round-trip |
| **Fuzz** | 10+ targets | `cargo fuzz` | Parsers (X.509, PKCS#12, SQL, config) |
| **Contract** | N/A | N/A | N/A (no external API) |
| **E2E** | 5 scenarios | Custom | Full workflows: init→add→get→backup→restore |

**Coverage Targets**:
- Overall: ≥85% line, ≥70% branch
- Crypto module: ≥95% line, ≥90% branch
- CA module: ≥90% line, ≥80% branch
- CLI: ≥70% line (harder to test)

### TEST-002: Test Infrastructure Requirements

```rust
// tests/common/mod.rs — Shared test infrastructure
pub struct TestEnv {
    pub temp_dir: tempfile::TempDir,
    pub db_path: PathBuf,
    pub config_path: PathBuf,
    pub master_password: String,
    pub cli: CliHarness,
}

impl TestEnv {
    pub fn new() -> Self { ... }
    pub fn init_keystore(&self) -> Result<()> { ... }
    pub fn unlock(&self) -> Result<()> { ... }
    pub fn add_key(&self, name: &str, key_type: KeyType) -> Result<KeyId> { ... }
    // ...
}

pub struct CliHarness {
    pub binary: PathBuf,
}
impl CliHarness {
    pub fn run(&self, args: &[&str]) -> CliResult { ... }
    pub fn run_with_input(&self, args: &[&str], input: &str) -> CliResult { ... }
}
```

### TEST-003: Property-Based Test Specifications

**Crypto Properties** (Phase 1.6):
```rust
// tests/properties/crypto_properties.rs
proptest! {
    // P1: Encrypt/Decrypt round-trip
    #[test]
    fn encrypt_decrypt_roundtrip(plaintext in any::<Vec<u8>>(), password in any::<String>()) {
        let dek = derive_dek(&password)?;
        let (ct, nonce) = encrypt(&dek, &plaintext)?;
        let pt = decrypt(&dek, &ct, &nonce)?;
        prop_assert_eq!(pt, plaintext);
    }

    // P2: DEK uniqueness — different entry_id → different DEK
    #[test]
    fn dek_uniqueness(entry_id_a in any::<String>(), entry_id_b in any::<String>()) {
        prop_assume!(entry_id_a != entry_id_b);
        let kek = [0u8; 32];
        let salt = [1u8; 32];
        let dek_a = derive_dek_hkdf(&kek, &entry_id_a, &salt);
        let dek_b = derive_dek_hkdf(&kek, &entry_id_b, &salt);
        prop_assert_ne!(dek_a, dek_b);
    }

    // P3: Nonce non-reuse — random nonces don't collide in 10k samples
    #[test]
    fn nonce_non_reuse(nonces in proptest::collection::vec(any::<[u8; 12]>, 10000)) {
        let mut seen = std::collections::HashSet::new();
        for nonce in nonces {
            prop_assert!(seen.insert(nonce), "Nonce collision detected");
        }
    }

    // P4: Constant-time comparison
    #[test]
    fn constant_time_compare(a in any::<[u8; 32]>(), b in any::<[u8; 32]>()) {
        let eq = subtle::ConstantTimeEq::ct_eq(&a, &b);
        // Can't test timing in proptest, but verify correctness
        prop_assert_eq!(eq.unwrap_u8() == 1, a == b);
    }

    // P5: Argon2id deterministic for same inputs
    #[test]
    fn argon2id_deterministic(password in any::<String>(), salt in any::<[u8; 32]>()) {
        let hash1 = argon2id_hash(&password, &salt, PROD_PARAMS)?;
        let hash2 = argon2id_hash(&password, &salt, PROD_PARAMS)?;
        prop_assert_eq!(hash1, hash2);
    }

    // P6: HKDF context separation
    #[test]
    fn hkdf_context_separation(ikm in any::<[u8; 32]>(), salt in any::<[u8; 32]>()) {
        let ctx1 = b"domain:keystore";
        let ctx2 = b"domain:backup";
        let okm1 = hkdf_expand(&ikm, &salt, ctx1);
        let okm2 = hkdf_expand(&ikm, &salt, ctx2);
        prop_assert_ne!(okm1, okm2);
    }
}
```

### TEST-004: Fuzz Target Specifications

```rust
// fuzz/fuzz_targets.rs
#![no_main]
use libfuzzer_sys::fuzz_target;

// Target 1: X.509 Certificate Parsing
fuzz_target!(|data: &[u8]| {
    let _ = x509_parser::parse_x509_certificate(data);
});

// Target 2: PKCS#12 Parsing
fuzz_target!(|data: &[u8]| {
    let _ = pkcs12::parse(data, "");
});

// Target 3: SQLite SQL Parsing (via rusqlite prepare)
fuzz_target!(|data: &[u8]| {
    if let Ok(sql) = std::str::from_utf8(data) {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        let _ = conn.prepare(sql);
    }
});

// Target 4: Config TOML Parsing
fuzz_target!(|data: &[u8]| {
    if let Ok(toml) = std::str::from_utf8(data) {
        let _ = toml::from_str::<Config>(toml);
    }
});

// Target 5: Password/Key Material Handling
fuzz_target!(|data: &[u8]| {
    // Test zeroize, secret handling
    let mut secret = zeroize::Zeroizing::new(data.to_vec());
    secret.zeroize();
});

// Target 6: ASN.1/DER Parsing
fuzz_target!(|data: &[u8]| {
    let _ = der_parser::parse_der(data);
});
```

### TEST-005: Integration Test Scenarios

| Scenario | Description | Assertions |
|----------|-------------|------------|
| **IT-001** | Full lifecycle: init → add RSA → get → export → delete | Key recovered matches original, audit log complete |
| **IT-002** | CA workflow: create CA → issue cert → revoke → verify CRL | Cert valid, revoked cert in CRL, unrevoked not in CRL |
| **IT-003** | Backup/Restore: init → add 100 keys → backup → corrupt DB → restore → verify all | All 100 keys recovered, integrity verified |
| **IT-004** | Rekey: init → add 1000 keys → rekey → verify all decryptable | All keys decrypt with new password, old password fails |
| **IT-005** | Concurrent access simulation: multiple CLI processes | No DB corruption, WAL checkpoint works |

### TEST-006: Test Data Management

- **Test vectors**: RFC 7914 (Argon2), RFC 5116 (AES-GCM), RFC 5869 (HKDF), RFC 5280 (X.509)
- **Golden files**: Pre-generated certificates, CRLs, PKCS#12 bundles for interop testing
- **Corpus**: Fuzzing corpus from real certificates, configs, SQL

### TEST-007: CI Test Pipeline

```yaml
# .github/workflows/test.yml
jobs:
  unit:
    runs-on: ubuntu-latest
    steps:
      - cargo test --lib --all-features
  integration:
    runs-on: ubuntu-latest
    steps:
      - cargo test --test integration --all-features
  property:
    runs-on: ubuntu-latest
    steps:
      - cargo test --test properties --all-features
  fuzz:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - cargo fuzz run fuzz_x509 -- -max_total_time=300
      - cargo fuzz run fuzz_pkcs12 -- -max_total_time=300
      - cargo fuzz run fuzz_sql -- -max_total_time=300
      - cargo fuzz run fuzz_config -- -max_total_time=300
  coverage:
    runs-on: ubuntu-latest
    steps:
      - cargo install cargo-llvm-cov
      - cargo llvm-cov --all-features --workspace --lcov --output-path lcov.info
      - bash <(curl -s https://codecov.io/bash) -f lcov.info
```

### TEST-008: Test Environment Matrix

| OS | Rust | SQLite | Features |
|----|------|--------|----------|
| Ubuntu 22.04 | stable | bundled | all |
| Ubuntu 24.04 | stable | bundled | all |
| macOS-latest | stable | bundled | all |
| windows-latest | stable | bundled | all |
| Ubuntu 22.04 | beta | bundled | all |
| Ubuntu 22.04 | nightly | bundled | all (for CFI, sanitizers) |

### TEST-009: Mutation Testing (Phase 5+)

- Tool: `cargo-mutants` or `mutagen`
- Target: Crypto module, CA validation logic
- Threshold: ≥80% mutation score

### TEST-010: Contract Testing (N/A for CLI)

### TEST-011: Chaos Testing (Phase 5+)

- Kill process during: write, rekey, backup, restore
- Verify: No corruption, recoverable state

### TEST-012: Regression Test Registry

- Every bug fix → regression test
- Registry: `tests/regressions/` with issue number
- CI runs all regression tests

---

## Performance Requirements Documentation

### PERF-001: Benchmark Specifications

| Benchmark | Target | Measurement |
|-----------|--------|-------------|
| **Cold start** (binary launch + config load) | <100ms | `hyperfine --warmup 3 'rw-secstore version'` |
| **Unlock** (Argon2id + DB open) | <500ms (prod), <50ms (CI) | `hyperfine 'rw-secstore unlock'` |
| **Key add** (RSA-2048 generate + encrypt + store) | <200ms | `hyperfine 'rw-secstore add --type rsa-2048 key1'` |
| **Key get** (decrypt + output) | <50ms | `hyperfine 'rw-secstore get key1'` |
| **Key list** (10k entries) | <200ms | `hyperfine 'rw-secstore list'` |
| **CA issue** (RSA-2048 cert) | <500ms | `hyperfine 'rw-secstore ca issue ...'` |
| **Backup** (10k entries) | <5s | `hyperfine 'rw-secstore backup out.bak'` |
| **Restore** (10k entries) | <10s | `hyperfine 'rw-secstore restore out.bak'` |
| **Rekey** (10k entries) | <30s | `hyperfine 'rw-secstore rekey'` |

### PERF-002: Memory Profiling

- Tool: `heaptrack`, `valgrind --tool=massif`
- Targets: Peak memory <100MB for 10k entries
- Leak detection: Zero leaks in 1hr soak test

### PERF-003: Database Performance

- WAL mode: Verify concurrent reads don't block
- Page size: 4096 (default) — benchmark 8192
- Index usage: `EXPLAIN QUERY PLAN` for all queries
- Vacuum: Measure fragmentation over time

### PERF-004: Crypto Performance

- Argon2id: 64MB/3iter = ~500ms on modern CPU
- AES-GCM: >1GB/s (hardware accelerated)
- HKDF: >100MB/s
- Key generation: RSA-2048 <200ms, Ed25519 <5ms

### PERF-005: CI Regression Detection

```yaml
# .github/workflows/bench.yml
- name: Benchmark
  run: |
    cargo bench --all-features -- --save-baseline main
    # On PR: compare against main baseline
    cargo bench --all-features -- --baseline main
  # Fail if any benchmark regresses >10%
```

### PERF-006: Scalability Targets

| Scale | Entries | DB Size | List Time | Backup Time |
|-------|---------|---------|-----------|-------------|
| Small | 100 | <1MB | <50ms | <1s |
| Medium | 1,000 | <10MB | <100ms | <10s |
| Large | 10,000 | <100MB | <200ms | <60s |
| X-Large | 100,000 | <1GB | <1s | <10min |

### PERF-007: Startup Time Breakdown

| Component | Target | Optimization |
|-----------|--------|--------------|
| Binary load | <10ms | Strip symbols, LTO |
| Config parse | <5ms | Minimal TOML |
| DB open (WAL) | <20ms | Pragmas optimized |
| Argon2id (CI) | <50ms | 8MB/1iter |
| Argon2id (Prod) | <500ms | 64MB/3iter |

### PERF-008: Profiling Infrastructure

```rust
// benches/benches.rs
use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};

fn bench_crypto(c: &mut Criterion) {
    let mut group = c.benchmark_group("crypto");
    for size in [16, 256, 4096, 65536] {
        group.bench_with_input(BenchmarkId::new("aes_gcm_encrypt", size), &size, |b, &size| {
            b.iter(|| encrypt(&dek, &vec![0u8; size]));
        });
    }
    group.finish();
}

criterion_group!(benches, bench_crypto, bench_db, bench_ca);
criterion_main!(benches);
```

---

## Security Documentation Requirements

### SEC-001: Threat Model Document
**Path**: `docs/security/THREAT_MODEL.md`
**Content**:
- Asset inventory (what we protect)
- Trust boundaries (process, user, machine)
- Attacker capabilities (per SPEC §3.2 NFR-SEC-001)
- Attack trees for each asset
- Mitigations mapped to requirements
- Residual risks accepted

### SEC-002: Cryptographic Design Document
**Path**: `docs/security/CRYPTO_DESIGN.md`
**Content**:
- Key hierarchy diagram
- Algorithm choices with rationale
- Parameter selections with references
- Key derivation flows (HKDF contexts)
- Nonce/IV construction
- AEAD usage (AES-GCM)
- Password hashing (Argon2id)
- Random number generation
- Key lifecycle (generation, storage, rotation, destruction)
- Known limitations

### SEC-003: Security Audit Checklist
**Path**: `docs/security/AUDIT_CHECKLIST.md`
**Content**:
- Pre-release audit checklist
- Dependency review process
- Crypto implementation review
- Side-channel resistance verification
- Fuzzing results review
- Penetration test scope

### SEC-004: Secure Deployment Guide
**Path**: `docs/security/DEPLOYMENT_GUIDE.md`
**Content**:
- File permissions (0o600 DB, 0o700 dir)
- Full-disk encryption recommendation
- Backup encryption key management
- Audit log protection
- Network isolation (if daemon mode)
- SELinux/AppArmor profiles

### SEC-005: Incident Response Playbook
**Path**: `docs/security/INCIDENT_RESPONSE.md`
**Content**:
- Compromise detection (audit log anomalies)
- Key rotation procedure (emergency)
- Backup recovery procedure
- Forensic preservation
- Communication plan

### SEC-006: Compliance Mapping
**Path**: `docs/security/COMPLIANCE.md`
**Content**:
- FIPS 140-3: Algorithm certifications, self-assessment
- Common Criteria: EAL mapping
- SOC 2: Controls mapping
- GDPR: Data protection, right to erasure (key deletion)
- NIST 800-57: Key management

### SEC-007: Vulnerability Disclosure Policy
**Path**: `SECURITY.md` (root)
**Content**:
- Reporting process
- Response timeline
- Disclosure coordination
- Credit policy

### SEC-008: Secure Coding Guidelines
**Path**: `docs/security/CODING_GUIDELINES.md`
**Content**:
- Crypto coding rules (no branches on secrets, constant-time)
- Error handling (no panic, no info leak)
- Memory management (zeroize, no stack secrets)
- Dependency review
- Code review checklist

### SEC-009: Penetration Test Report Template
**Path**: `docs/security/PENTEST_TEMPLATE.md`
**Content**:
- Scope
- Methodology
- Findings template
- Remediation tracking

### SEC-010: Security Changelog
**Path**: `docs/security/CHANGELOG_SECURITY.md`
**Content**:
- Security-relevant changes per version
- CVE references
- Migration notes for security updates

---

## Documentation Deliverables Checklist

### Test Documentation
- [ ] `docs/testing/TEST_STRATEGY.md` — Test pyramid, targets, infrastructure
- [ ] `docs/testing/PROPERTY_TESTS.md` — Property test specifications
- [ ] `docs/testing/FUZZ_TARGETS.md` — Fuzz target specifications
- [ ] `docs/testing/INTEGRATION_SCENARIOS.md` — E2E scenarios
- [ ] `docs/testing/CI_PIPELINE.md` — CI configuration
- [ ] `tests/common/mod.rs` — Test harness implementation

### Performance Documentation
- [ ] `docs/performance/BENCHMARKS.md` — Benchmark specs, targets, CI regression
- [ ] `docs/performance/PROFILING.md` — Profiling tools, memory analysis
- [ ] `docs/performance/SCALABILITY.md` — Scale targets, capacity planning
- [ ] `benches/benches.rs` — Criterion benchmarks

### Security Documentation
- [ ] `docs/security/THREAT_MODEL.md`
- [ ] `docs/security/CRYPTO_DESIGN.md`
- [ ] `docs/security/AUDIT_CHECKLIST.md`
- [ ] `docs/security/DEPLOYMENT_GUIDE.md`
- [ ] `docs/security/INCIDENT_RESPONSE.md`
- [ ] `docs/security/COMPLIANCE.md`
- [ ] `SECURITY.md` (root)
- [ ] `docs/security/CODING_GUIDELINES.md`
- [ ] `docs/security/PENTEST_TEMPLATE.md`
- [ ] `docs/security/CHANGELOG_SECURITY.md`

---

## Implementation Plan Additions

### Phase 1 (Foundation) — Test/Perf/Sec Infrastructure:
- [ ] 1.9: Test harness (`tests/common/mod.rs`)
- [ ] 1.10: Property test suite (`tests/properties/`)
- [ ] 1.11: Fuzz targets (`fuzz/`)
- [ ] 1.12: CI test pipeline (`.github/workflows/test.yml`)
- [ ] 1.13: Benchmark infrastructure (`benches/`)
- [ ] 1.14: CI benchmark regression (`.github/workflows/bench.yml`)
- [ ] 1.15: Lint CI (`.github/workflows/lint.yml`)
- [ ] 1.16: Security docs skeleton (`docs/security/`)

### Phase 2 (Keystore) — Test Implementation:
- [ ] 2.9: Unit tests for keystore module
- [ ] 2.10: Integration tests for key lifecycle
- [ ] 2.11: Property tests for key operations

### Phase 3 (CA) — Test Implementation:
- [ ] 3.9: Unit tests for CA module
- [ ] 3.10: Integration tests for CA workflows
- [ ] 3.11: PKCS#12 interop tests (golden files)

### Phase 4 (Advanced) — Test Implementation:
- [ ] 4.8: Backup/restore integration tests
- [ ] 4.9: Corruption injection tests
- [ ] 4.10: Chaos tests (kill during operations)

### Phase 5 (Polish) — Documentation + Advanced Testing:
- [ ] 5.6: Complete all test/perf/sec documentation
- [ ] 5.7: Mutation testing setup
- [ ] 5.8: Penetration test (internal)
- [ ] 5.9: Compliance self-assessment
- [ ] 5.10: Security changelog initialized

---

## Sign-off Required

- [ ] Test strategy documented and approved
- [ ] Performance targets documented and approved
- [ ] Security documentation structure approved
- [ ] CI pipeline configuration approved
- [ ] Test infrastructure tasks added to Phase 1
- [ ] Benchmark infrastructure tasks added to Phase 1
- [ ] Security documentation tasks distributed across phases
- [ ] Coverage targets accepted
- [ ] Fuzzing targets accepted
- [ ] Compliance scope accepted
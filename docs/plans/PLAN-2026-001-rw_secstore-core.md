# IMPLEMENTATION PLAN: rw_secstore Core Keystore & Certificate Authority
## Medium Mode — Systematic Implementation with Audit Cycles

## Document Identification
- **PLAN ID**: PLAN-2026-001
- **Version**: 1.0.0
- **Status**: Draft
- **Date**: 2026-08-28
- **Author**: ForgeCode / RapidWebs
- **Based on**: SPEC-2026-001-rw_secstore-core.md

---

## 1. Mode Selection Rationale

**Selected Mode: MEDIUM**

| Criterion | Assessment |
|-----------|------------|
| Files touched | ~25+ files (new project) |
| Database/Caching | SQLite + in-memory KEK cache |
| Reusable feature | Yes - core library + CLI |
| Security-critical | Yes - encryption, CA operations |
| Public API | Yes - CLI is public interface |
| Compliance | SOC2/ISO27001 audit logging required |

**Medium Mode Requirements (Phases 0-11):**
- ✅ Phase 0: Research (COMPLETE - REFERENCE_PROJECTS_ANALYSIS.md)
- ✅ Phase 1: Spec (COMPLETE - SPEC-2026-001)
- 🔄 Phase 2: Plan (THIS DOCUMENT)
- ⏳ Phase 3: Forward Audit
- ⏳ Phase 4: Reverse Audit
- ⏳ Phase 5: Synthesis
- ⏳ Phase 6: Sign-off
- ⏳ Phase 7: TDD Implementation
- ⏳ Phase 8: Adversarial Audit
- ⏳ Phase 9: Bug Review
- ⏳ Phase 10: Lint + Dead Code
- ⏳ Phase 11: Test/Perf/Sec Documentation

---

## 2. File Manifest

### 2.1 New Files to Create

| File | Lines (est.) | Description |
|------|--------------|-------------|
| `Cargo.toml` | 80 | Project manifest with all dependencies |
| `src/lib.rs` | 50 | Library entry point, module exports |
| `src/main.rs` | 100 | Binary entry point, CLI dispatch |
| `src/error.rs` | 120 | Error types with `thiserror` |
| `src/config.rs` | 150 | Configuration loading (TOML + env) |
| `src/crypto.rs` | 300 | Argon2id + AES-GCM encryption |
| `src/storage.rs` | 400 | SQLite connection, migrations, repositories |
| `src/keystore.rs` | 350 | Key/secret CRUD operations |
| `src/ca.rs` | 500 | CA operations (create, issue, revoke, CRL) |
| `src/audit.rs` | 200 | Audit logging |
| `src/backup.rs` | 250 | Backup/restore operations |
| `src/cli.rs` | 400 | Clap CLI definitions |
| `src/commands/init.rs` | 80 | `init` command |
| `src/commands/unlock.rs` | 100 | `unlock`/`lock`/`status` commands |
| `src/commands/ca.rs` | 300 | CA subcommands |
| `src/commands/cert.rs` | 300 | Certificate subcommands |
| `src/commands/key.rs` | 250 | Key/secret subcommands |
| `src/commands/backup.rs` | 150 | Backup/restore subcommands |
| `src/commands/audit.rs` | 150 | Audit query subcommands |
| `src/commands/config.rs` | 100 | Config subcommands |
| `src/commands/completion.rs` | 50 | Shell completions |
| `tests/integration_tests.rs` | 500 | Integration test suite |
| `tests/crypto_tests.rs` | 200 | Crypto unit tests |
| `tests/storage_tests.rs` | 200 | Storage unit tests |
| `tests/ca_tests.rs` | 300 | CA integration tests |
| `tests/cli_tests.rs` | 200 | CLI integration tests |

**Total: ~25 files, ~5,500 lines**

### 2.2 Existing Files to Modify

| File | Changes |
|------|---------|
| `README.md` | Update with actual CLI usage |
| `config.example.toml` | Align with actual config schema |
| `Makefile` | Add test, build, install targets |
| `.github/workflows/ci.yml` | Add test stages |

---

## 3. Phase Breakdown & Dependencies

### Phase 1: Foundation (Week 1)
**Dependencies**: None

| Task | File(s) | Effort | TDD Tests |
|------|---------|--------|-----------|
| 1.1 Project setup & Cargo.toml | `Cargo.toml` | 2h | - |
| 1.2 Error types | `src/error.rs` | 2h | `tests/error_tests.rs` |
| 1.3 Configuration | `src/config.rs` | 3h | `tests/config_tests.rs` |
| 1.4 Crypto module (Argon2id + AES-GCM) | `src/crypto.rs` | 6h | `tests/crypto_tests.rs` |
| 1.5 Storage layer (SQLite + migrations) | `src/storage.rs` | 6h | `tests/storage_tests.rs` |
| 1.6 Library entry point | `src/lib.rs` | 1h | - |

**Phase 1 Deliverable**: `cargo test` passes for crypto, storage, config

### Phase 2: Keystore Core (Week 1-2)
**Dependencies**: Phase 1 complete

| Task | File(s) | Effort | TDD Tests |
|------|---------|--------|-----------|
| 2.1 Keystore service (CRUD) | `src/keystore.rs` | 6h | `tests/keystore_tests.rs` |
| 2.2 CLI framework + global options | `src/cli.rs`, `src/main.rs` | 4h | `tests/cli_tests.rs` |
| 2.3 `init` command | `src/commands/init.rs` | 2h | `tests/cli_tests.rs` |
| 2.4 `unlock`/`lock`/`status` commands | `src/commands/unlock.rs` | 3h | `tests/cli_tests.rs` |
| 2.5 `key store`/`get`/`list`/`delete` | `src/commands/key.rs` | 4h | `tests/cli_tests.rs` |
| 2.6 `key compare`/`verify` | `src/commands/key.rs` | 3h | `tests/cli_tests.rs` |

**Phase 2 Deliverable**: Full keystore CLI working, `cargo test` passes

### Phase 3: Certificate Authority (Week 2)
**Dependencies**: Phase 1 complete (can parallel with Phase 2)

| Task | File(s) | Effort | TDD Tests |
|------|---------|--------|-----------|
| 3.1 CA service (create root/intermediate) | `src/ca.rs` | 6h | `tests/ca_tests.rs` |
| 3.2 Certificate issuance | `src/ca.rs` | 4h | `tests/ca_tests.rs` |
| 3.3 Revocation + CRL | `src/ca.rs` | 4h | `tests/ca_tests.rs` |
| 3.4 Renewal | `src/ca.rs` | 2h | `tests/ca_tests.rs` |
| 3.5 Import/Export (PEM, PKCS#12) | `src/ca.rs` | 3h | `tests/ca_tests.rs` |
| 3.6 CA CLI commands | `src/commands/ca.rs`, `src/commands/cert.rs` | 4h | `tests/cli_tests.rs` |

**Phase 3 Deliverable**: Full CA CLI working, `cargo test` passes

### Phase 4: Advanced Features (Week 2-3)
**Dependencies**: Phase 2, 3 complete

| Task | File(s) | Effort | TDD Tests |
|------|---------|--------|-----------|
| 4.1 Audit logging | `src/audit.rs` | 3h | `tests/audit_tests.rs` |
| 4.2 Audit CLI commands | `src/commands/audit.rs` | 2h | `tests/cli_tests.rs` |
| 4.3 Backup/Restore | `src/backup.rs` | 4h | `tests/backup_tests.rs` |
| 4.4 Backup CLI commands | `src/commands/backup.rs` | 2h | `tests/cli_tests.rs` |
| 4.5 Config CLI commands | `src/commands/config.rs` | 2h | `tests/cli_tests.rs` |
| 4.6 Shell completions | `src/commands/completion.rs` | 1h | - |

**Phase 4 Deliverable**: All features complete, `cargo test` passes

### Phase 5: Polish & Hardening (Week 3)
**Dependencies**: Phase 4 complete

| Task | File(s) | Effort | TDD Tests |
|------|---------|--------|-----------|
| 5.1 Integration tests | `tests/integration_tests.rs` | 4h | - |
| 5.2 README + docs update | `README.md` | 2h | - |
| 5.3 CI/CD pipeline | `.github/workflows/ci.yml` | 2h | - |
| 5.4 Performance benchmarks | `benches/` | 2h | - |
| 5.5 Security review | - | 2h | - |

**Phase 5 Deliverable**: Release-ready binary, all checks pass

---

## 4. TDD Test Plan

### 4.1 Unit Tests (per module)

| Module | Test File | Key Test Cases |
|--------|-----------|----------------|
| `crypto` | `tests/crypto_tests.rs` | KEK derivation, encrypt/decrypt roundtrip, rekey, zeroize |
| `storage` | `tests/storage_tests.rs` | Migration, WAL mode, FK constraints, soft delete |
| `keystore` | `tests/keystore_tests.rs` | CRUD all key types, compare, verify, labels |
| `ca` | `tests/ca_tests.rs` | CA create, cert issue, revoke, CRL, renew, import/export |
| `audit` | `tests/audit_tests.rs` | Log capture, query filters, immutability |
| `backup` | `tests/backup_tests.rs` | Round-trip, schema migration, checksum, conflict resolution |

### 4.2 Integration Tests

| Test File | Scenarios |
|-----------|-----------|
| `tests/integration_tests.rs` | Full workflow: init → unlock → CA → cert → key → backup → restore |
| `tests/cli_tests.rs` | All CLI commands, JSON output, error handling, exit codes |

### 4.3 Test Commands

```bash
# Unit tests (fast)
cargo test --lib -- crypto::tests
cargo test --lib -- storage::tests
cargo test --lib -- keystore::tests
cargo test --lib -- ca::tests

# Integration tests
cargo test --test integration_tests
cargo test --test cli_tests

# Full suite
cargo test --all-targets

# With coverage
cargo llvm-cov --all-targets --workspace --lcov --output-path lcov.info
```

---

## 5. Rollback Plan

| Phase | Commit Strategy | Rollback Command |
|-------|-----------------|------------------|
| 1 | `feat: foundation - crypto, storage, config` | `git revert HEAD` |
| 2 | `feat: keystore core - CRUD, CLI` | `git revert HEAD` |
| 3 | `feat: CA - create, issue, revoke, CRL` | `git revert HEAD` |
| 4 | `feat: advanced - audit, backup, config` | `git revert HEAD` |
| 5 | `feat: polish - tests, docs, CI` | `git revert HEAD` |

**Per-task commits** within each phase for finer rollback granularity.

---

## 6. Acceptance Criteria (from SPEC)

### 6.1 Functional (All Must Pass)

- [ ] TC-001: Initialize new keystore, verify schema version
- [ ] TC-002: Unlock with correct password, fail with incorrect
- [ ] TC-003: Store/retrieve secret, verify encryption at rest
- [ ] TC-004: Generate RSA/ECDSA/Ed25519 key pairs
- [ ] TC-005: Import existing PEM key pair
- [ ] TC-006: Create root CA, verify self-signed
- [ ] TC-007: Create intermediate CA, verify chain
- [ ] TC-008: Issue leaf certificate, verify signature chain
- [ ] TC-009: Revoke certificate, verify CRL contains it
- [ ] TC-010: Renew certificate, verify old revoked, new valid
- [ ] TC-011: Export/import CA as PKCS#12
- [ ] TC-012: Backup/restore round-trip
- [ ] TC-013: Change master password, verify re-encryption
- [ ] TC-014: Soft delete + purge workflow
- [ ] TC-015: Audit log captures all mutating operations
- [ ] TC-016: Key comparison (match/mismatch)
- [ ] TC-017: Signature verification with stored public key
- [ ] TC-018: Concurrent access (multiple processes)
- [ ] TC-019: Schema migration from v1 to v2
- [ ] TC-020: Large keystore (10k entries) performance

### 6.2 Non-Functional

- [ ] Binary size < 50MB (striped, musl)
- [ ] Startup < 100ms (empty DB)
- [ ] Unlock < 500ms (1000 entries)
- [ ] Zero critical/high `cargo audit` findings
- [ ] Zero `cargo deny` violations
- [ ] All tests pass on Linux, macOS, Windows

---

## 7. Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| CRL generation complexity | Medium | High | Start early, use `der-parser` reference |
| PKCS#12 interop issues | Medium | Medium | Test with OpenSSL, browsers |
| Argon2id params tuning | Low | Medium | Configurable, sensible defaults |
| SQLite locking on NFS | Low | High | Document limitation, warn in README |
| Schema migration bugs | Medium | High | Test migration v1→v2 in CI |
| Memory zeroization gaps | Low | Critical | Use `zeroize` crate, audit all secret handling |

---

## 7. Open Questions for Sign-off

1. **Argon2id defaults**: Memory=64MB, iter=3, parallel=4 OK for target hardware?
2. **Key profile defaults**: RSA-4096 for CA, RSA-2048 for leaf certs?
3. **CRL validity period**: 30 days default?
4. **Backup compression**: gzip by default or optional?
5. **Audit log retention**: 365 days / 100k entries default?
6. **Config file location**: `~/.config/rw-secstore/config.toml` (XDG) or project-local?

---

## 8. Next Steps

1. **Forward Audit** (Phase 3): Validate every SPEC claim against this plan
2. **Reverse Audit** (Phase 4): Find gaps in this plan
3. **Synthesis** (Phase 5): Combine findings into revised plan
4. **Sign-off** (Phase 6): Your approval before TDD implementation begins

---

## Appendix: Command Mapping (SPEC → Plan)

| SPEC Command | Plan Task | Phase |
|--------------|-----------|-------|
| `init` | 1.3, 2.3 | 1, 2 |
| `unlock`/`lock`/`status` | 2.4 | 2 |
| `ca create/list/show/import/export/delete/purge` | 3.1, 3.6 | 3 |
| `cert issue/list/show/revoke/renew/export/delete/purge` | 3.2-3.6 | 3 |
| `key store/get/list/compare/verify/delete/purge` | 2.5, 2.6 | 2 |
| `backup/restore` | 4.3, 4.4 | 4 |
| `audit` | 4.1, 4.2 | 4 |
| `config` | 1.3, 4.5 | 1, 4 |
| `completion` | 4.6 | 4 |
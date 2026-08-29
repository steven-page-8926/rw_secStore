# PLAN-2026-001: rw_secstore Core Implementation Plan v2.1 (HIGH mode)

**Plan ID**: PLAN-2026-001
**Version**: 2.1.0
**Date**: 2026-08-29
**Status**: Draft (Pre-Audit)
**Author**: ForgeCode / RapidWebs
**Supersedes**: PLAN-2026-001 v2.0 (HIGH mode)
**Related**:
- SPEC-2026-001 v1.1.0
- ADRs 001-009
- Feature Extension Analysis FEA-2026-001

---

## Executive Summary

This plan details the implementation of **rw_secstore v1.0.0**, a quad-purpose security tool: keystore + certificate authority + SSH key manager + multi-factor authentication. The implementation is structured as 5 phases over an estimated **228 hours** (revised from v2.0's 188h to incorporate the 5 new feature areas: SSH, password policy, password generator, password file, keyring+backup codes).

### Key Metrics

| Metric | Value |
|--------|-------|
| **Total Effort** | 228h (revised from 188h) |
| **Total Tasks** | 142 (revised from 128) |
| **Workspace Crates** | 4 (core, cli, crypto, storage) |
| **Dependencies** | ~35 crates |
| **Test Scenarios** | 33 (TC-001 through TC-033) |
| **Phases** | 5 (Foundation → Keystore → CA → Advanced → Polish) |

### v2.0 → v2.1 Changes

| Area | v2.0 | v2.1 | Delta |
|------|------|------|-------|
| **Foundation (Phase 1)** | 42h | 56h | +14h (auth, policy, gen, file) |
| **Keystore (Phase 2)** | 38h | 54h | +16h (SSH core) |
| **CA (Phase 3)** | 48h | 52h | +4h (SSH CA type) |
| **Advanced (Phase 4)** | 28h | 28h | 0h (no change) |
| **Polish (Phase 5)** | 32h | 38h | +6h (keyring tests, Windows) |
| **Total** | 188h | **228h** | **+40h (+21%)** |

---

## Phase 1: Foundation (56 hours)

**Goal**: Establish workspace, core infrastructure, crypto primitives, and authentication foundations.

**Gate Criteria**:
- Workspace builds with all lint/test gates passing
- Database schema migrations work v1→v2→v3 with rollback
- Crypto module: Argon2id + AES-GCM + HKDF + constant-time ops + zeroize
- 6+ property tests passing
- `init`, `unlock`, `lock` commands work with password
- `key store` / `key get` work (with policy enforcement)
- Keyring unlock works on Linux/macOS (smoke test)
- Backup codes generate and verify

### 1.1 Workspace & Project Setup (4 hours)

| Task | Description | Acceptance | Hours |
|------|-------------|------------|-------|
| 1.1.1 | Create workspace `Cargo.toml` with 4 members | `cargo build --workspace` succeeds | 1 |
| 1.1.2 | Configure `rust-toolchain.toml` (MSRV 1.75) | `rustup` picks up toolchain | 0.5 |
| 1.1.3 | Set up `.cargo/config.toml` with target settings | Builds for x86_64-unknown-linux-gnu | 0.5 |
| 1.1.4 | Create `clippy.toml` with strict lints | `cargo clippy --workspace -- -D warnings` passes | 0.5 |
| 1.1.5 | Set up `rustfmt.toml` | `cargo fmt --check` passes | 0.5 |
| 1.1.6 | Configure `cargo-deny.toml` (license + advisory) | `cargo deny check` passes | 1 |

### 1.2 Database Schema & Migrations (8 hours)

| Task | Description | Acceptance | Hours |
|------|-------------|------------|-------|
| 1.2.1 | Implement `Connection` wrapper (per-command, WAL mode) | Opens DB, sets pragmas | 1 |
| 1.2.2 | Create `migrations` module with version tracking | Schema versions persist | 1 |
| 1.2.3 | Migration 001: initial schema (all tables) | Test: v0→v1 succeeds | 2 |
| 1.2.4 | Migration 002: add HMAC seal column | Test: v1→v2 succeeds | 1 |
| 1.2.5 | Migration 003: add backup_codes + password_history | Test: v2→v3 succeeds | 1 |
| 1.2.6 | Migration rollback test (v3→v2→v1) | Test: rollback succeeds | 1 |
| 1.2.7 | File permissions: 0o600 DB, 0o700 parent dir | Test: perms verified | 1 |

### 1.3 Crypto Primitives (10 hours)

| Task | Description | Acceptance | Hours |
|------|-------------|------------|-------|
| 1.3.1 | Argon2id KDF with hardcoded minimums | Prod: 64MB/3, CI: 8MB/1 via env | 2 |
| 1.3.2 | AES-256-GCM encryption/decryption | Encrypt/decrypt round-trip | 2 |
| 1.3.3 | HKDF-SHA256 for DEK derivation | Same input → same output | 1 |
| 1.3.4 | Constant-time comparison (`subtle`) | Naive vs subtle comparison test | 1 |
| 1.3.5 | Zeroize integration (`Zeroizing<>`) | Memory zeroized on drop | 1 |
| 1.3.6 | CSPRNG wrapper (OsRng only, no fallback) | Random bytes generation | 1 |
| 1.3.7 | Crypto version header (algorithm agility) | Versioned encryption format | 2 |

### 1.4 Authentication Infrastructure (10 hours) — NEW in v2.1

| Task | Description | Acceptance | Hours |
|------|-------------|------------|-------|
| 1.4.1 | AuthService trait (unlock methods) | Pluggable auth backend | 1 |
| 1.4.2 | Password unlock (Argon2id-derived KEK) | Unlock with correct/wrong pwd | 2 |
| 1.4.3 | Keyring integration (`keyring` crate) | MEK generated/stored/retrieved | 3 |
| 1.4.4 | Backup code generation (base32, 80 bits) | 8 codes, single-use | 1 |
| 1.4.5 | Backup code unlock flow (Argon2id verify) | Code unlocks, marked consumed | 2 |
| 1.4.6 | Combined unlock (keyring → password → code) | Priority order respected | 1 |

### 1.5 Password Policy & Generator (8 hours) — NEW in v2.1

| Task | Description | Acceptance | Hours |
|------|-------------|------------|-------|
| 1.5.1 | Policy engine: length/entropy/charset rules | Reject non-compliant passwords | 2 |
| 1.5.2 | zxcvbn integration for strength | Score 0-4 + suggestions | 1 |
| 1.5.3 | HIBP offline list (top 100k bundled) | Common passwords rejected | 1 |
| 1.5.4 | HIBP online check (k-anonymity, opt-in) | API call + cache | 1 |
| 1.5.5 | Password history (Argon2id hashes) | Reject reuse of last 5 | 1 |
| 1.5.6 | Password generator (charset modes) | 32-char alphanumeric = 190 bits | 1 |
| 1.5.7 | Diceware generator (EFF wordlist bundled) | 6 words = 77 bits | 1 |

### 1.6 Master Password File (3 hours) — NEW in v2.1

| Task | Description | Acceptance | Hours |
|------|-------------|------------|-------|
| 1.6.1 | Secure read (validate 0o600/0o400) | Reject world-readable files | 1 |
| 1.6.2 | Export command (0o600 perms, 0o700 parent) | File created with correct perms | 1 |
| 1.6.3 | Atomic init with generated password | Single op: init + write file | 1 |

### 1.7 Configuration & CLI Framework (4 hours)

| Task | Description | Acceptance | Hours |
|------|-------------|------------|-------|
| 1.7.1 | Config struct (TOML deserialization) | Load default config | 1 |
| 1.7.2 | XDG path resolution (`directories` crate) | Resolves to XDG paths | 0.5 |
| 1.7.3 | Clap 4.x CLI structure with derive | `rw-secstore --help` works | 1 |
| 1.7.4 | Global options (--db-path, --password, --method) | All options parsed | 1 |
| 1.7.5 | Man page generation (`clap_mangen`) | `rw-secstore.1` generated | 0.5 |

### 1.8 Database Integrity (HMAC Seal) (3 hours)

| Task | Description | Acceptance | Hours |
|------|-------------|------------|-------|
| 1.8.1 | HMAC-SHA256 seal on commit | Seal updates with mutations | 2 |
| 1.8.2 | Verify on open (detect corruption) | Tampered DB triggers warning | 1 |

### 1.9 Error Handling & Logging (2 hours)

| Task | Description | Acceptance | Hours |
|------|-------------|------------|-------|
| 1.9.1 | `Error` enum with `thiserror` | Typed errors | 1 |
| 1.9.2 | `tracing` setup (JSON to stderr) | Logs visible | 1 |

### 1.10 Property Tests & Initial Test Infrastructure (4 hours)

| Task | Description | Acceptance | Hours |
|------|-------------|------------|-------|
| 1.10.1 | Hypothesis setup + conftest | Test runner works | 0.5 |
| 1.10.2 | Property: Argon2id determinism (same input → same KEK) | Test passes | 0.5 |
| 1.10.3 | Property: AES-GCM round-trip (encrypt → decrypt) | Test passes | 0.5 |
| 1.10.4 | Property: HKDF context separation (different info → different DEK) | Test passes | 0.5 |
| 1.10.5 | Property: Nonce uniqueness (1000 random nonces all unique) | Test passes | 0.5 |
| 1.10.6 | Property: Backup code base32 round-trip | Test passes | 0.5 |
| 1.10.7 | Property: Password generator entropy bounds | Test passes | 0.5 |
| 1.10.8 | Property: Constant-time compare correctness | Test passes | 0.5 |

**Phase 1 Total: 56 hours**

---

## Phase 2: Keystore Core (54 hours)

**Goal**: Implement core keystore operations including SSH key support.

**Gate Criteria**:
- All REQ-KS-001 through REQ-KS-007 implemented and tested
- All REQ-SSH-001 through REQ-SSH-003 implemented
- `key` and `ssh` command groups fully functional
- Integration tests for 10k entries
- Property tests for SSH key round-trip

### 2.1 Asymmetric Key Operations (6 hours)

| Task | Description | Acceptance | Hours |
|------|-------------|------------|-------|
| 2.1.1 | RSA keypair generation (2048/3072/4096) | Generate, store, retrieve | 2 |
| 2.1.2 | ECDSA keypair generation (P-256/P-384) | Generate, store, retrieve | 1 |
| 2.1.3 | Ed25519 keypair generation | Generate, store, retrieve | 1 |
| 2.1.4 | Public key extraction (PEM) | Extract public from private | 1 |
| 2.1.5 | Private/public consistency check on import | Reject mismatched | 1 |

### 2.2 Symmetric Key & Secret Operations (4 hours)

| Task | Description | Acceptance | Hours |
|------|-------------|------------|-------|
| 2.2.1 | AES-256 key generation | Generate, store, retrieve | 1 |
| 2.2.2 | ChaCha20-Poly1305 key generation | Generate, store, retrieve | 1 |
| 2.2.3 | Generic secret storage (string + bytes) | Store/retrieve secret | 1 |
| 2.2.4 | Binary secret (base64 in CLI) | `--data-base64` works | 1 |

### 2.3 SSH Key Operations (10 hours) — NEW in v2.1

| Task | Description | Acceptance | Hours |
|------|-------------|------------|-------|
| 2.3.1 | `ssh store` — generate Ed25519/RSA/ECDSA via `ssh-key` | Generate OpenSSH format | 2 |
| 2.3.2 | `ssh store --generate-passphrase` — diceware passphrase | Passphrase generated, encrypted | 1 |
| 2.3.3 | `ssh get` — retrieve with optional `--reveal-passphrase` | Retrieve private/public | 1 |
| 2.3.4 | `ssh list` — list with filter/sort | Table output | 1 |
| 2.3.5 | `ssh export --format openssh` | Export OpenSSH private key | 1 |
| 2.3.6 | `ssh export --format pkcs8` | Export PKCS#8 PEM | 1 |
| 2.3.7 | `ssh export --format public` | Export authorized_keys format | 1 |
| 2.3.8 | SSH key passphrase verification (Argon2id) | Wrong passphrase rejected | 1 |
| 2.3.9 | Property test: SSH key OpenSSH round-trip | Test passes | 1 |

### 2.4 Key Listing, Filtering, Comparison (4 hours)

| Task | Description | Acceptance | Hours |
|------|-------------|------------|-------|
| 2.4.1 | `key list` with filters (type, label) | Filter works | 1 |
| 2.4.2 | Output formats: table/json/csv | All formats work | 1 |
| 2.4.3 | `key compare <a1> <a2>` with SHA-256 fingerprint | Compare works | 1 |
| 2.4.4 | Constant-time comparison for symmetric keys | No timing leak | 1 |

### 2.5 Key Verification & Rekey (5 hours)

| Task | Description | Acceptance | Hours |
|------|-------------|------------|-------|
| 2.5.1 | `key verify --data --signature` (RSA-PSS/PKCS1) | Verify signature | 1 |
| 2.5.2 | ECDSA signature verification | Verify signature | 0.5 |
| 2.5.3 | Ed25519 signature verification | Verify signature | 0.5 |
| 2.5.4 | `rekey` (atomic, single transaction) | All entries re-encrypted | 2 |
| 2.5.5 | Rekey progress indication (indicatif) | Progress bar shows | 1 |

### 2.6 Soft Delete & Purge (3 hours)

| Task | Description | Acceptance | Hours |
|------|-------------|------------|-------|
| 2.6.1 | Soft delete (set deleted_at) | List excludes deleted | 1 |
| 2.6.2 | `list --include-deleted` | Shows soft-deleted | 0.5 |
| 2.6.3 | `purge` (permanent delete) | Removes from DB | 1 |
| 2.6.4 | `purge --before <date>` (batch purge) | Batch works | 0.5 |

### 2.7 Policy/Auth Integration (3 hours)

| Task | Description | Acceptance | Hours |
|------|-------------|------------|-------|
| 2.7.1 | Password policy on `key store` operations | Reject weak pwd | 1 |
| 2.7.2 | Keyring unlock used for `key get` | MEK decrypts DEK | 1 |
| 2.7.3 | Backup code unlock for `key get` | Code unlocks, consumed | 1 |

### 2.8 Audit Logging for Keystore (3 hours)

| Task | Description | Acceptance | Hours |
|------|-------------|------------|-------|
| 2.8.1 | Audit entries for create/read/delete | All ops logged | 1 |
| 2.8.2 | HMAC chain on audit entries | Chain verifiable | 1.5 |
| 2.8.3 | `audit --entity key` query | Filter works | 0.5 |

### 2.9 Integration Tests (4 hours)

| Task | Description | Acceptance | Hours |
|------|-------------|------------|-------|
| 2.9.1 | 10k entry stress test (performance) | < 5s list | 1 |
| 2.9.2 | Soft delete + purge round-trip | All entries removed | 1 |
| 2.9.3 | Concurrent access (multiple processes) | No race conditions | 2 |

**Phase 2 Total: 54 hours**

---

## Phase 3: CA Operations (52 hours)

**Goal**: Implement certificate authority operations and SSH CA.

**Gate Criteria**:
- All REQ-CA-001 through REQ-CA-006 implemented
- Root and intermediate CA creation, cert issuance, revocation, CRL
- SSH CA support (`ca_type='ssh_ca'`) for OpenSSH certs
- PKCS#12 export interop tested with OpenSSL

### 3.1 CA Creation (8 hours)

| Task | Description | Acceptance | Hours |
|------|-------------|------------|-------|
| 3.1.1 | Root CA generation (rcgen) | Self-signed cert | 2 |
| 3.1.2 | Subject DN builder (CN, O, OU, C, ST, L) | DN parsed correctly | 1 |
| 3.1.3 | Validity period + notBefore/notAfter | Dates correct | 1 |
| 3.1.4 | Basic constraints + key usage extensions | X.509 compliant | 1 |
| 3.1.5 | CA storage with full metadata | Stored correctly | 1 |
| 3.1.6 | Pathlen enforcement | Reject if too deep | 1 |
| 3.1.7 | Path validation on external CA import | Validate chain | 1 |

### 3.2 Intermediate CA (6 hours)

| Task | Description | Acceptance | Hours |
|------|-------------|------------|-------|
| 3.2.1 | CSR generation | CSR valid | 1 |
| 3.2.2 | Parent signing (requires unlock) | Intermediate signed | 2 |
| 3.2.3 | Chain storage (intermediate + parents) | Chain retrievable | 1 |
| 3.2.4 | Pathlen decrement | Correct value | 1 |
| 3.2.5 | `ca list` filter by type | Lists roots + intermediates | 1 |

### 3.3 Certificate Issuance (10 hours)

| Task | Description | Acceptance | Hours |
|------|-------------|------------|-------|
| 3.3.1 | `cert issue` with SANs (DNS/IP) | SANs in cert | 2 |
| 3.3.2 | Key profile can differ from CA | Custom key gen | 1 |
| 3.3.3 | Validity period | Correct dates | 1 |
| 3.3.4 | Key usage + ext key usage | X.509 compliant | 1 |
| 3.3.5 | Serial number generation (UUID-based) | Unique serials | 1 |
| 3.3.6 | CSR replay protection (track CSR nonce) | Replay rejected | 2 |
| 3.3.7 | `cert list` / `cert show` | Query works | 1 |
| 3.3.8 | `cert export` (PEM/PKCS#12) | Export works | 1 |

### 3.4 Revocation & CRL (6 hours)

| Task | Description | Acceptance | Hours |
|------|-------------|------------|-------|
| 3.4.1 | `cert revoke --reason` | Marks revoked | 1 |
| 3.4.2 | CRL generation (rcgen) | Valid CRL | 2 |
| 3.4.3 | CRL number increment | Monotonic | 0.5 |
| 3.4.4 | nextUpdate setting (default 30 days) | Correct | 0.5 |
| 3.4.5 | CRL export (PEM/DER) | Export works | 1 |
| 3.4.6 | CRL HTTP distribution stub (TODO v2.0) | Stub returns empty CRL | 1 |

### 3.5 Renewal (4 hours)

| Task | Description | Acceptance | Hours |
|------|-------------|------------|-------|
| 3.5.1 | `cert renew --days` | New cert issued | 1 |
| 3.5.2 | Old cert revoked (superseded) | Marked revoked | 1 |
| 3.5.3 | Same key reused | No new keypair | 1 |
| 3.5.4 | Chain preserved | Full chain in new cert | 1 |

### 3.6 SSH CA (4 hours) — NEW in v2.1

| Task | Description | Acceptance | Hours |
|------|-------------|------------|-------|
| 3.6.1 | SSH CA type in ca_type field | Stored as `ssh_ca` | 1 |
| 3.6.2 | SSH key type validation (ed25519/rsa only) | Validate | 1 |
| 3.6.3 | SSH certificate signing (placeholder for v1.1) | Stub with TODO | 1 |
| 3.6.4 | `ca list --type ssh_ca` | Filter works | 1 |

### 3.7 PKCS#12 Interop (4 hours)

| Task | Description | Acceptance | Hours |
|------|-------------|------------|-------|
| 3.7.1 | PKCS#12 export with separate password | Export works | 1 |
| 3.7.2 | PKCS#12 import (validate chain) | Import works | 1 |
| 3.7.3 | OpenSSL interop test (`openssl pkcs12 -info`) | Compatible | 1 |
| 3.7.4 | Document PKCS#12 limitations | README updated | 1 |

### 3.8 CA Audit (2 hours)

| Task | Description | Acceptance | Hours |
|------|-------------|------------|-------|
| 3.8.1 | Audit entries for CA operations | All logged | 1 |
| 3.8.2 | `audit --entity certificate` query | Filter works | 1 |

### 3.9 CA Integration Tests (8 hours)

| Task | Description | Acceptance | Hours |
|------|-------------|------------|-------|
| 3.9.1 | Root CA → Intermediate → Leaf chain test | Valid chain | 2 |
| 3.9.2 | CRL distribution point test | CRL valid | 2 |
| 3.9.3 | Cert renewal end-to-end | New + old cert | 1 |
| 3.9.4 | Revocation + CRL regeneration | Updated CRL | 1 |
| 3.9.5 | OpenSSL interop test (cert verify) | OpenSSL accepts | 2 |

**Phase 3 Total: 52 hours**

---

## Phase 4: Advanced Features (28 hours)

**Goal**: Backup/restore, advanced queries, hardening.

**Gate Criteria**:
- Atomic backup/restore
- DB corruption detection and recovery
- Chaos testing (random failure injection)

### 4.1 Backup Format (4 hours)

| Task | Description | Acceptance | Hours |
|------|-------------|------------|-------|
| 4.1.1 | JSON serialization of all entities | Complete backup | 2 |
| 4.1.2 | Checksum (SHA-256) on backup file | Verifiable | 1 |
| 4.1.3 | Gzip compression option | `--compress` works | 1 |

### 4.2 Restore (4 hours)

| Task | Description | Acceptance | Hours |
|------|-------------|------------|-------|
| 4.2.1 | Atomic restore (temp file + rename) | All-or-nothing | 2 |
| 4.2.2 | Schema migration on restore (older versions) | Migrate applied | 1 |
| 4.2.3 | Conflict resolution (skip/overwrite/rename) | All strategies work | 1 |

### 4.3 Audit Query Enhancements (3 hours)

| Task | Description | Acceptance | Hours |
|------|-------------|------------|-------|
| 4.3.1 | Time range filters | `--since/--until` | 1 |
| 4.3.2 | Pagination for large results | `--limit/--offset` | 1 |
| 4.3.3 | HMAC chain verification on read | Status displayed | 1 |

### 4.4 Config Management (3 hours)

| Task | Description | Acceptance | Hours |
|------|-------------|------------|-------|
| 4.4.1 | `config show` | Display config | 0.5 |
| 4.4.2 | `config set <key> <value>` | Update config | 1 |
| 4.4.3 | `config keyring enable/disable/status` | All work | 1 |
| 4.4.4 | `config backup-codes list/regenerate` | Both work | 0.5 |

### 4.5 CLI Polish (4 hours)

| Task | Description | Acceptance | Hours |
|------|-------------|------------|-------|
| 4.5.1 | Shell completions (bash/zsh/fish/pwsh) | All generated | 2 |
| 4.5.2 | Interactive password input (`rpassword`) | Hidden input | 1 |
| 4.5.3 | Dry-run mode for destructive ops | `--dry-run` works | 1 |

### 4.6 DB Verification (3 hours)

| Task | Description | Acceptance | Hours |
|------|-------------|------------|-------|
| 4.6.1 | `verify` command (integrity check) | Detects corruption | 1 |
| 4.6.2 | `verify --repair` (rebuild from audit chain) | Repair works | 2 |

### 4.7 Chaos Testing (4 hours)

| Task | Description | Acceptance | Hours |
|------|-------------|------------|-------|
| 4.7.1 | Random failure injection (disk full, permission denied) | Handles gracefully | 2 |
| 4.7.2 | Crash recovery (kill -9 mid-write) | Recovers from WAL | 1 |
| 4.7.3 | Concurrent process safety | No data corruption | 1 |

### 4.8 Performance Optimization (3 hours)

| Task | Description | Acceptance | Hours |
|------|-------------|------------|-------|
| 4.8.1 | Benchmark all REQ-PERF targets | All meet targets | 1 |
| 4.8.2 | Optimize slow paths if needed | < 5% deviation | 1 |
| 4.8.3 | Add connection warm-up if needed | Cold start < 100ms | 1 |

**Phase 4 Total: 28 hours**

---

## Phase 5: Polish, Hardening & Release (38 hours)

**Goal**: Production-ready release with security hardening, comprehensive testing, and documentation.

**Gate Criteria**:
- Zero critical/high findings in `cargo audit`
- Zero high/critical findings in `cargo deny`
- 100k entry stress test passes
- 1M+ fuzz iterations pass
- All 33 test scenarios pass
- Coverage ≥85% line, ≥95% crypto
- Pen test complete
- Windows support verified
- All documentation complete

### 5.1 Supply Chain Security (4 hours)

| Task | Description | Acceptance | Hours |
|------|-------------|------------|-------|
| 5.1.1 | `cargo audit` integration in CI | Runs on every PR | 1 |
| 5.1.2 | `cargo deny` configuration | License + advisory gates | 1 |
| 5.1.3 | SBOM generation (CycloneDX) | `bom.json` produced | 1 |
| 5.1.4 | Dependency review process | Documented | 1 |

### 5.2 Fuzz Testing (4 hours)

| Task | Description | Acceptance | Hours |
|------|-------------|------------|-------|
| 5.2.1 | Fuzz harness: DB parsing | 1M iter, 0 crashes | 1 |
| 5.2.2 | Fuzz harness: cert parsing | 1M iter, 0 crashes | 1 |
| 5.2.3 | Fuzz harness: ASN.1 decoding | 1M iter, 0 crashes | 1 |
| 5.2.4 | Fuzz harness: password handling | 1M iter, 0 crashes | 1 |

### 5.3 Cross-Platform Support (4 hours)

| Task | Description | Acceptance | Hours |
|------|-------------|------------|-------|
| 5.3.1 | Windows build verification | Builds on windows-latest | 1 |
| 5.3.2 | macOS build verification | Builds on macos-latest | 1 |
| 5.3.3 | Linux ARM64 build | Builds on aarch64 | 1 |
| 5.3.4 | Keyring testing on all 3 platforms | All work | 1 |

### 5.4 Hardening (6 hours)

| Task | Description | Acceptance | Hours |
|------|-------------|------------|-------|
| 5.4.1 | mlock for sensitive buffers | Best-effort | 1 |
| 5.4.2 | Signal handlers (zeroize on SIGTERM/INT/HUP) | Cleanup on signal | 1 |
| 5.4.3 | Stack canary verification | Enabled in release | 0.5 |
| 5.4.4 | PIE + RELRO + NX | Default release profile | 0.5 |
| 5.4.5 | Strip symbols in release | Binary < 50MB | 0.5 |
| 5.4.6 | Reproducible builds | Same source → same binary | 2 |
| 5.4.7 | Threat model self-assessment | Documented | 0.5 |

### 5.5 Documentation (8 hours)

| Task | Description | Acceptance | Hours |
|------|-------------|------------|-------|
| 5.5.1 | README.md (install, quickstart, examples) | Complete | 2 |
| 5.5.2 | Architecture overview | Diagrams + prose | 1 |
| 5.5.3 | Security policy (SECURITY.md) | Vulnerability disclosure | 1 |
| 5.5.4 | Contributing guide (CONTRIBUTING.md) | Dev setup | 1 |
| 5.5.5 | Migration guide (v0.x → v1.0) | Step-by-step | 1 |
| 5.5.6 | Man pages for all commands | Generated | 1 |
| 5.5.7 | Example workflows (scripts/) | Real-world usage | 1 |

### 5.6 CI/CD Pipeline (4 hours)

| Task | Description | Acceptance | Hours |
|------|-------------|------------|-------|
| 5.6.1 | GitHub Actions: lint + test + bench | All pass | 1 |
| 5.6.2 | Coverage reporting (tarpaulin) | ≥85% line | 1 |
| 5.6.3 | Release workflow (tag → binary) | Automatic | 1 |
| 5.6.4 | Code signing (cosign/minisign) | Signed binaries | 1 |

### 5.7 Stress & Performance (4 hours)

| Task | Description | Acceptance | Hours |
|------|-------------|------------|-------|
| 5.7.1 | 100k entry stress test | All ops < 2x target | 1 |
| 5.7.2 | Memory usage profiling | < 200MB peak | 1 |
| 5.7.3 | Binary size verification | < 50MB | 0.5 |
| 5.7.4 | Startup time benchmark | < 100ms | 0.5 |
| 5.7.5 | Unlock time benchmark (1k entries) | < 500ms | 1 |

### 5.8 Penetration Testing (4 hours) — NEW in v2.1

| Task | Description | Acceptance | Hours |
|------|-------------|------------|-------|
| 5.8.1 | Self-assessment: timing attacks | No leaks | 1 |
| 5.8.2 | Self-assessment: key recovery attacks | No feasible attack | 1 |
| 5.8.3 | Self-assessment: side-channel (cache) | Constant-time | 1 |
| 5.8.4 | External pen test (if time permits) | Report | 1 |

**Phase 5 Total: 38 hours**

---

## Total Effort Summary

| Phase | Description | Hours |
|-------|-------------|-------|
| **Phase 1** | Foundation (workspace, schema, crypto, auth, policy, gen) | 56 |
| **Phase 2** | Keystore Core (keys, secrets, SSH) | 54 |
| **Phase 3** | CA Operations (X.509, SSH CA) | 52 |
| **Phase 4** | Advanced Features (backup, audit, chaos) | 28 |
| **Phase 5** | Polish, Hardening, Release | 38 |
| **Total** | | **228** |

---

## Workspace Structure

```
rw-secstore/
├── Cargo.toml                  # Workspace root
├── Cargo.lock
├── rust-toolchain.toml         # MSRV 1.75
├── .cargo/
│   └── config.toml             # Build config
├── clippy.toml                 # Lint rules
├── rustfmt.toml                # Formatting
├── deny.toml                   # cargo-deny config
├── crates/
│   ├── core/                   # Domain logic (no CLI deps)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── auth/           # AuthService, password, keyring, backup codes
│   │       ├── ca/             # CAService, cert operations
│   │       ├── keystore/       # KeystoreService, key ops
│   │       ├── ssh/            # SshService, SSH key ops
│   │       ├── policy/         # PolicyService, zxcvbn, HIBP
│   │       ├── audit/          # AuditService, HMAC chain
│   │       ├── backup/         # BackupService
│   │       ├── config/         # ConfigService
│   │       └── error.rs
│   ├── cli/                    # CLI binary
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── main.rs
│   │       ├── commands/
│   │       │   ├── init.rs
│   │       │   ├── unlock.rs
│   │       │   ├── ca.rs
│   │       │   ├── cert.rs
│   │       │   ├── key.rs
│   │       │   ├── ssh.rs
│   │       │   ├── pwgen.rs
│   │       │   ├── backup.rs
│   │       │   ├── audit.rs
│   │       │   └── config.rs
│   │       └── output.rs       # Formatters (table/json/csv)
│   ├── crypto/                 # Reusable crypto primitives
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── argon2.rs       # Argon2id KDF
│   │       ├── aes_gcm.rs      # AES-256-GCM
│   │       ├── hkdf.rs         # HKDF-SHA256
│   │       ├── constant_time.rs
│   │       ├── random.rs       # OsRng wrapper
│   │       ├── seal.rs         # HMAC seal
│   │       └── version.rs      # Algorithm agility
│   └── storage/                # SQLite + migrations
│       ├── Cargo.toml
│       └── src/
│           ├── lib.rs
│           ├── connection.rs   # Per-command connection
│           ├── migrations/     # Version migrations
│           ├── repositories/   # CA, cert, key, audit, etc.
│           └── permissions.rs  # File perms
├── tests/                      # Integration tests
│   ├── cli/
│   ├── crypto/
│   └── storage/
├── docs/
│   ├── SPECs/
│   ├── ADRs/
│   ├── plans/
│   ├── reports/
│   └── audits/
├── scripts/                    # Dev scripts
│   ├── run_baseline_suite.sh
│   ├── generate_man_pages.sh
│   └── verify_release.sh
├── .github/
│   └── workflows/
│       ├── ci.yml
│       ├── coverage.yml
│       └── release.yml
├── Dockerfile                  # Multi-stage build
├── Makefile                    # Dev tasks
├── README.md
├── LICENSE
├── CONTRIBUTING.md
├── SECURITY.md
└── CHANGELOG.md
```

---

## Dependencies (35 crates)

| Crate | Version | Purpose |
|-------|---------|---------|
| `rusqlite` | latest (bundled) | SQLite bindings |
| `argon2` | latest | Argon2id KDF |
| `aes-gcm` | latest | AES-256-GCM |
| `chacha20poly1305` | latest | ChaCha20-Poly1305 |
| `hkdf` | latest | HKDF-SHA256 |
| `sha2` | latest | SHA-2 family |
| `hmac` | latest | HMAC-SHA256 |
| `rcgen` | latest | Certificate generation |
| `x509-parser` | latest | Certificate parsing |
| `der-parser` | latest | DER/ASN.1 |
| `asn1-rs` | latest | ASN.1 structures |
| `pem` | latest | PEM encoding |
| `pkcs12` | latest | PKCS#12 support |
| `ssh-key` | latest | SSH key parsing/generation |
| `uuid` | latest (v7) | UUID generation |
| `chrono` | latest | Date/time |
| `clap` | 4.x | CLI framework |
| `clap_mangen` | latest | Man page gen |
| `serde` | latest | Serialization |
| `serde_json` | latest | JSON |
| `toml` | latest | Config parsing |
| `directories` | latest | XDG paths |
| `zeroize` | latest | Memory zeroization |
| `subtle` | latest | Constant-time |
| `keyring` | latest | OS keyring |
| `rpassword` | latest | Secure password input |
| `zxcvbn` | latest | Password strength |
| `rand` | latest | RNG |
| `anyhow` | latest | Error context |
| `thiserror` | latest | Typed errors |
| `tracing` | latest | Logging |
| `tracing-subscriber` | latest | Log subscriber |
| `base64` | latest | Base64 |
| `hex` | latest | Hex |
| `indicatif` | latest | Progress bars |
| `qrcode` | latest | QR codes |
| `reqwest` | latest (optional) | HIBP API |

**Dev dependencies**:
- `hypothesis` — property tests
- `criterion` — benchmarks
- `proptest` — quickcheck
- `cargo-fuzz` — fuzz testing
- `mockall` — mocking
- `tempfile` — temp dirs
- `assert_cmd` — CLI testing
- `predicates` — CLI assertions

---

## Risk Register

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| `ssh-key` crate has edge cases | M | M | Fall back to PKCS#8 PEM |
| `keyring` crate backend fragmentation | M | M | Test on 3 distros, fallback to password |
| Backup code rate-limit too strict | L | L | Configurable, document |
| HIBP API rate limit | L | L | 24h cache, opt-in only |
| Property tests flaky | L | M | Pin seed, fixed examples |
| Windows file permissions broken | H | M | Document limitation, accept |
| Migration rollback edge case | M | H | Extensive test matrix v1→v2→v3 |
| Audit chain perf on 100k entries | M | M | Benchmark, optimize if needed |

---

## Success Criteria (Recap from SPEC §8.2)

- All 33 test scenarios pass
- Zero critical/high `cargo audit` findings
- Zero high/critical `cargo deny` findings
- Binary < 50MB
- Coverage ≥85% line, ≥95% crypto
- 6+ property tests pass
- 1M+ fuzz iterations, 0 crashes
- All phase gate criteria met
- Windows + macOS + Linux builds all succeed
- Documentation complete
- Pen test (self) clean

---

## Next Steps

1. **Run HIGH mode pipeline** (forward audit, reverse audit, adversarial, bug review, lint, TPS, synthesis)
2. **Review all audit findings** and integrate resolutions into plan
3. **Sign-off** with user
4. **Phase 1 forward + reverse audit** (per user request)
5. **Begin implementation** with Phase 1 tasks

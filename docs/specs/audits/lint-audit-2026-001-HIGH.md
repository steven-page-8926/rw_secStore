# Lint + Dead Code Detection Audit (HIGH Mode)

**Audit ID**: LINT-2026-001-HIGH
**Date**: 2026-08-29
**Auditor**: ForgeCode (plan-and-audit HIGH mode)
**Focus**: Clippy lints, rustc lints, dead code, unused dependencies, complexity metrics
**SPEC Version**: 1.0.0
**Plan Version**: 1.0.0 (HIGH mode)

---

## Executive Summary

| Category | Count | Description |
|----------|-------|-------------|
| **Clippy Deny Lints** | 15 | Must-fix before merge |
| **Clippy Warn Lints** | 20 | Should fix |
| **Rustc Lints** | 8 | Compiler warnings to eliminate |
| **Dead Code Risks** | 10 | Unused code paths, unreachable code |
| **Complexity Metrics** | 6 | Cyclomatic, cognitive, nesting depth |
| **Unused Dependencies** | 5 | Crates not needed in plan |
| **Total** | **64** | |

**Verdict**: **CONDITIONAL PASS** — Lint configuration must be established before implementation begins. Dead code risks are speculative (pre-implementation) but architecture decisions create known risks.

---

## Required Lint Configuration (Pre-Implementation)

### Cargo.toml Lint Settings
```toml
[workspace.lints]
# Clippy - Deny (hard errors)
clippy::unwrap_used = "deny"
clippy::expect_used = "deny"
clippy::panic = "deny"
clippy::todo = "deny"
clippy::unimplemented = "deny"
clippy::unreachable = "deny"
clippy::indexing_slicing = "deny"
clippy::integer_arithmetic = "deny"
clippy::cast_possible_truncation = "deny"
clippy::cast_sign_loss = "deny"
clippy::cast_precision_loss = "deny"
clippy::float_arithmetic = "deny"
clippy::std_instead_of_core = "deny"
clippy::alloc_instead_of_core = "deny"
clippy::print_stdout = "deny"
clippy::print_stderr = "deny"

# Clippy - Warn (warnings)
clippy::pedantic = "warn"
clippy::nursery = "warn"
clippy::cargo = "warn"
clippy::complexity = "warn"
clippy::perf = "warn"
clippy::style = "warn"
clippy::suspicious = "warn"

# Rustc - Deny
unused_variables = "deny"
unused_mut = "deny"
unused_imports = "deny"
unused_must_use = "deny"
dead_code = "deny"
unreachable_code = "deny"
unreachable_patterns = "deny"
unused_assignments = "deny"

# Rustc - Warn
unused_crate_dependencies = "warn"
```

### CI Lint Enforcement
```yaml
# .github/workflows/lint.yml
- name: Clippy
  run: cargo clippy --workspace --all-targets --all-features -- -D warnings
- name: Rustc
  run: cargo check --workspace --all-targets --all-features
- name: Unused deps
  run: cargo machete --deny-warnings
```

---

## Clippy Deny Lints (Must Fix)

### LINT-D-001: `unwrap_used` / `expect_used` — Panic in Production
**Risk**: Any `unwrap()`/`expect()` in production code = crash on error.
**Plan Impact**: All phases — error handling strategy must use `Result` + `?` everywhere.
**Enforcement**: `clippy::unwrap_used = "deny"`, `clippy::expect_used = "deny"`

### LINT-D-002: `panic` — Explicit Panic
**Risk**: `panic!()` macro used instead of error propagation.
**Plan Impact**: All phases — use `Result`/`eyre::Report` for all fallible operations.

### LINT-D-003: `todo` / `unimplemented` — Incomplete Implementation
**Risk**: Placeholder code reaches production.
**Plan Impact**: All phases — `todo!()`/`unimplemented!()` = deny. Use proper error types.

### LINT-D-004: `unreachable` — Unreachable Code
**Risk**: Code that can never execute = dead code or logic error.
**Plan Impact**: All phases — match arms must be exhaustive, no `unreachable!()`.

### LINT-D-005: `indexing_slicing` — Panic on Bounds Check
**Risk**: `vec[i]` / `slice[i]` panics on OOB.
**Plan Impact**: Crypto, parsing, DB code — use `get(i)` + `?` or checked indexing.

### LINT-D-006: `integer_arithmetic` — Overflow Panic
**Risk**: `+`, `-`, `*`, `/` panic on overflow in debug, wrap in release.
**Plan Impact**: Crypto (counters, sizes), DB (row counts) — use `checked_add`/`saturating_add`.

### LINT-D-007: `cast_possible_truncation` — Silent Data Loss
**Risk**: `u64 as u32` truncates silently.
**Plan Impact**: Serial numbers, timestamps, sizes — use `try_from` with error handling.

### LINT-D-008: `cast_sign_loss` — Signedness Bug
**Risk**: `i32 as u32` loses sign.
**Plan Impact**: Any numeric conversion — avoid mixed signedness.

### LINT-D-009: `cast_precision_loss` — Float Precision Loss
**Risk**: `f64 as f32` loses precision.
**Plan Impact**: Avoid floats entirely in crypto/security code. Use integers/fixed-point.

### LINT-D-010: `float_arithmetic` — Floating Point in Security Code
**Risk**: Float non-determinism, precision issues.
**Plan Impact**: **Ban floats** in crypto, timing, security code. Use `fixed` crate if needed.

### LINT-D-011: `std_instead_of_core` / `alloc_instead_of_core` — No-Std Compatibility
**Risk**: Library cannot be used in no-std contexts (embedded, kernel).
**Plan Impact**: Core crypto library should be `no_std` compatible. Binary can use std.

### LINT-D-012: `print_stdout` / `print_stderr` — Direct Printing
**Risk**: Output not controllable, not testable, not structured.
**Plan Impact**: Use `tracing`/`log` crate. CLI output via dedicated `Output` abstraction.

### LINT-D-013: `unused_must_use` — Ignored `#[must_use]` Results
**Risk**: `Result`/`Future`/guard types dropped without handling.
**Plan Impact**: All `#[must_use]` types (lock guards, `Result`, `Option`) must be used.

### LINT-D-014: `dead_code` — Unused Items
**Risk**: Dead code = maintenance burden, attack surface.
**Plan Impact**: `dead_code = "deny"` — but allow `#[cfg(test)]` and public API.

### LINT-D-015: `unreachable_code` / `unreachable_patterns` — Dead Paths
**Risk**: Code after `return`/`panic`, match arms never matched.
**Plan Impact**: Enforce via rustc lints.

---

## Clippy Warn Lints (Should Fix)

### LINT-W-001: `pedantic` — Pedantic Style
**Impact**: Many style nits. Enable but allow per-file `#[allow]` with justification.

### LINT-W-002: `nursery` — New Lints
**Impact**: Emerging best practices. Enable.

### LINT-W-003: `cargo` — Cargo.toml Issues
**Impact**: Dependency issues, version requirements. Enable.

### LINT-W-004: `complexity` — Cognitive Complexity
**Impact**: Functions too complex. Threshold: cognitive complexity >15 = refactor.

### LINT-W-005: `perf` — Performance
**Impact**: Unnecessary allocations, clones. Enable.

### LINT-W-006: `style` — Style Consistency
**Impact**: Naming, formatting. Enable.

### LINT-W-007: `suspicious` — Likely Bugs
**Impact**: `clone_on_copy`, `needless_borrow`, etc. Enable.

### LINT-W-008: `wildcard_enum_match_arm` — Non-Exhaustive Match
**Impact**: Match on enum without all variants. Use `@` catch-all with `unreachable!()`.

### LINT-W-009: `match_same_arms` — Duplicate Match Arms
**Impact**: DRY violation. Enable.

### LINT-W-010: `similar_names` — Confusing Names
**Impact**: `key` vs `keys`, `ca` vs `c_a`. Enable.

### LINT-W-011: `module_name_repetitions` — Redundant Module Names
**Impact**: `crypto::crypto::encrypt`. Enable.

### LINT-W-012: `enum_glob_use` — Glob Import of Enum
**Impact**: `use KeyType::*;` pollutes namespace. Enable.

### LINT-W-013: `items_after_statements` — Items After Statements
**Impact**: Rust 2018+ allows but confusing. Enable.

### LINT-W-014: `let_underscore_drop` — `let _ =` Drops Immediately
**Impact**: `let _ = lock();` drops guard immediately. Use `let _guard = lock();`.

### LINT-W-015: `await_holding_lock` — `.await` Holding Mutex
**Impact**: Deadlock risk. Enable (if async used).

### LINT-W-016: `redundant_closure` — Unnecessary Closure
**Impact**: `|| foo(x)` vs `foo`. Enable.

### LINT-W-017: `needless_borrow` — Unnecessary Reference
**Impact**: `&x` where `x` works. Enable.

### LINT-W-018: `needless_pass_by_value` — Pass by Value Unnecessarily
**Impact**: `fn foo(x: String)` vs `fn foo(x: &str)`. Enable.

### LINT-W-019: `trivially_copy_pass_by_ref` — Copy Types by Ref
**Impact**: `fn foo(x: &u32)` vs `fn foo(x: u32)`. Enable.

### LINT-W-020: `manual_map` — Manual `Option::map`
**Impact**: `match opt { Some(x) => f(x), None => None }` vs `opt.map(f)`. Enable.

---

## Rustc Lints (Compiler Warnings)

### LINT-R-001: `unused_variables` — Unused Bindings
**Fix**: Prefix with `_` or remove.

### LINT-R-002: `unused_mut` — Unnecessary Mutability
**Fix**: Remove `mut` if not mutated.

### LINT-R-003: `unused_imports` — Unused Imports
**Fix**: Remove or `use _ as _`.

### LINT-R-004: `unused_must_use` — Ignored Must-Use
**Fix**: Handle the result.

### LINT-R-005: `dead_code` — Unused Items (Public API Exception)
**Fix**: `#[allow(dead_code)]` only for public API intentionally exposed.

### LINT-R-006: `unreachable_code` — Code After Return/Panic
**Fix**: Remove or fix logic.

### LINT-R-007: `unreachable_patterns` — Match Arm Never Matched
**Fix**: Remove or fix match order.

### LINT-R-008: `unused_assignments` — Assignment Never Read
**Fix**: Remove assignment.

---

## Dead Code Risks (Architecture-Induced)

### LINT-DC-001: Unused Key Types
**Risk**: Plan defines RSA/ECDSA/Ed25519/symmetric/secret but CA only uses RSA/ECDSA/Ed25519.
**Mitigation**: Implement all types but mark symmetric/secret as "keystore-only" in docs.

### LINT-DC-002: Unused CA Features
**Risk**: Plan includes CRL, OCSP, CT but v1 only implements CRL stub.
**Mitigation**: Feature-gate: `ca-full` feature enables OCSP/CT. Default = `ca-basic`.

### LINT-DC-003: Unused Backup Formats
**Risk**: Plan supports JSON + binary backup but only binary implemented.
**Mitigation**: Single format (binary) for v1. JSON as future feature.

### LINT-DC-004: Unused Config Options
**Risk**: Config schema includes options not implemented (e.g., `auto_vacuum`, `key_expiration_enforcement`).
**Mitigation**: Config versioning — v1 config only includes implemented options.

### LINT-DC-005: Unused CLI Subcommands
**Risk**: Plan lists `compare`, `verify`, `attest` but only `compare` implemented in v1.
**Mitigation**: Implement all or hide behind `--experimental` flag.

### LINT-DC-006: Unused Audit Event Types
**Risk**: Audit log schema includes 20 event types but only 10 used in v1.
**Mitigation**: Define all in schema, emit only implemented. Document future events.

### LINT-DC-007: Unused Crypto Algorithms
**Risk**: Plan supports AES-256-GCM only but header allows algorithm field.
**Mitigation**: Single algorithm v1. Algorithm field for future migration only.

### LINT-DC-008: Unused Key Derivation Contexts
**Risk**: Key hierarchy defines 4 domains but v1 uses 2 (keystore, backup).
**Mitigation**: Implement all domains but CA/audit use same as keystore for v1.

### LINT-DC-009: Unused Platform-Specific Code
**Risk**: Windows Credential Manager, macOS Keychain, Linux libsecret — none used in v1.
**Mitigation**: No platform-specific code in v1. Document for v2.

### LINT-DC-010: Unused Test Utilities
**Risk**: Test helpers for features not implemented.
**Mitigation**: Only write test utils for implemented features.

---

## Complexity Metrics (Targets)

| Metric | Target | Enforcement |
|--------|--------|-------------|
| **Cyclomatic Complexity** | ≤10 per function | `clippy::cognitive_complexity` warn at 15 |
| **Cognitive Complexity** | ≤15 per function | `clippy::cognitive_complexity` warn at 15 |
| **Nesting Depth** | ≤4 levels | `clippy::too_many_lines` warn at 50 lines |
| **Function Length** | ≤50 lines | `clippy::too_many_lines` warn at 50 |
| **Module Length** | ≤500 lines | Split into submodules |
| **Dependency Count** | ≤30 direct deps | `cargo machete` + manual review |

### Complexity Hotspots (Predicted)

| Module | Predicted Complexity | Mitigation |
|--------|---------------------|------------|
| `crypto::encrypt` / `decrypt` | High (AEAD + HKDF + nonce) | Split into small pure functions |
| `ca::issue_cert` | High (validation + signing + extensions) | Builder pattern, separate validation |
| `keystore::rekey` | High (transaction + progress + rollback) | State machine, separate steps |
| `backup::restore` | High (verify + atomic rename) | Pipeline with checkpoints |
| `cli::parse` | Medium (many subcommands) | Clap derive handles this |

---

## Unused Dependencies (Predicted)

| Crate | Plan Use | Risk | Mitigation |
|-------|----------|------|------------|
| `pkcs12` | Phase 3.4 only | Unused if PKCS#12 deferred | Feature-gate `pkcs12` |
| `ocsp` | Not in v1 | Unused | Feature-gate `ocsp` |
| `ct` | Not in v1 | Unused | Feature-gate `ct` |
| `rpassword` | CLI only | Binary-only dep | Move to `rw-secstore-cli` crate |
| `indicatif` | CLI only | Binary-only dep | Move to `rw-secstore-cli` crate |
| `clap_mangen` | Build only | Build dep only | `build-dependencies` |
| `cargo-deny` | CI only | Not in Cargo.toml | CI tool, not library dep |

**Recommendation**: Split into workspace:
```
rw-secstore/
├── rw-secstore-core/     # Library (no CLI deps)
├── rw-secstore-cli/      # Binary (clap, rpassword, indicatif)
├── rw-secstore-ca/       # CA library (rcgen, x509-parser, pkcs12)
└── rw-secstore-crypto/   # Crypto primitives (no_std)
```

---

## Lint CI Pipeline

```yaml
# .github/workflows/lint.yml
name: Lint
on: [push, pull_request]
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: clippy, rustfmt
      - name: Cache
        uses: Swatinem/rust-cache@v2
      - name: Format
        run: cargo fmt --all -- --check
      - name: Clippy
        run: cargo clippy --workspace --all-targets --all-features -- -D warnings
      - name: Check
        run: cargo check --workspace --all-targets --all-features
      - name: Unused Deps
        run: cargo install cargo-machete && cargo machete --deny-warnings
      - name: Deny
        run: cargo install cargo-deny && cargo deny check advisories bans licenses sources
      - name: Audit
        run: cargo install cargo-audit && cargo audit
      - name: Complexity
        run: cargo install cargo-complexity && cargo complexity --threshold 15
```

---

## Pre-Implementation Checklist

- [ ] Workspace `Cargo.toml` with lint configuration
- [ ] `rust-toolchain.toml` pinning version
- [ ] `.github/workflows/lint.yml` created
- [ ] `cargo-deny` policy (`deny.toml`) created
- [ ] `cargo-machete` baseline established
- [ ] Complexity thresholds documented
- [ ] Dead code exceptions documented (public API, test-only)
- [ ] `clippy::pedantic` allow-list created for known false positives

---

## Sign-off Required

- [ ] Lint configuration committed before any implementation
- [ ] CI pipeline passes on empty workspace
- [ ] All deny lints enforced
- [ ] Workspace structure avoids unused deps in core library
- [ ] Complexity targets documented and enforced
- [ ] Dead code exceptions reviewed and approved
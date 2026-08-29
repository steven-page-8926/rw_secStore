# Lint + Dead Code Audit: rw_secstore v1.1.0 Plan v2.1

**Audit ID**: LINT-2026-001-v1.1
**Date**: 2026-08-29
**Auditor**: ForgeCode
**Subject**: PLAN-2026-001 v2.1 (HIGH mode)
**Methodology**: Configure lints, detect dead code, set up CI gates

---

## Required Lint Configuration

### 1. `Cargo.toml` Workspace `[lints]` Section

```toml
[workspace.lints.clippy]
# Correctness
unwrap_used = "deny"
expect_used = "deny"
panic = "deny"
todo = "deny"
unimplemented = "deny"
dbg_macro = "deny"
print_stdout = "deny"
print_stderr = "deny"
# Style
module_name_repetitions = "allow"  # Common in Rust, allow
must_use_candidate = "warn"
# Security
unsafe_used = "deny"  # No unsafe in safe code
# Performance
needless_collect = "warn"
or_fun_call = "warn"
# Clarity
redundant_clone = "warn"

[workspace.lints.rust]
unsafe_code = "deny"
unsafe_op_in_unsafe_fn = "deny"
missing_docs = "warn"
```

### 2. `clippy.toml`

```toml
# Cognitive complexity threshold
cognitive-complexity-threshold = 30
# Function size
too-many-arguments-threshold = 7
too-many-lines-threshold = 200
# Type complexity
type-complexity-threshold = 250
# Single-match
single-match-threshold = 5
```

### 3. `rustfmt.toml`

```toml
edition = "2021"
max_width = 100
tab_spaces = 4
imports_granularity = "Crate"
group_imports = "StdExternalCrate"
reorder_imports = true
trailing_comma = "Vertical"
```

---

## Dead Code Detection

### Tools

1. **`cargo machete`** — Find unused dependencies
2. **`cargo udeps`** — Find unused dependencies (requires nightly)
3. **`cargo-geiger`** — Find unsafe code
4. **`cargo-deny`** — License + advisory checks

### CI Gate

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
      - run: cargo fmt --check
      - run: cargo clippy --workspace --all-targets -- -D warnings
      - run: cargo machete
      - run: cargo deny check
      - run: cargo geiger
```

---

## Findings

### LINT-F-001 (HIGH): Plan doesn't specify lint configuration
**Description**: Plan 1.1.4 mentions `clippy.toml` but doesn't list specific lints.
**Resolution**: Add explicit `[lints]` section to plan (see above)

### LINT-F-002 (HIGH): No `#![deny(unsafe_code)]` at crate root
**Description**: Should be enforced at crate level for safety-critical code.
**Resolution**: All 4 crates should have `#![deny(unsafe_code)]` in `lib.rs`

### LINT-F-003 (MEDIUM): No doctests required
**Description**: Public API should have doctests.
**Resolution**: Add `missing_docs = "warn"` and require doctests in `[lints.rust]`

### LINT-F-004 (MEDIUM): No `#[must_use]` on constructors
**Description**: Constructors like `Keystore::new()` should be `#[must_use]`.
**Resolution**: Add `must_use_candidate = "warn"` to clippy lints

### LINT-F-005 (LOW): No naming convention document
**Description**: Project-wide naming conventions not specified.
**Resolution**: Add `docs/NAMING.md` with conventions

### LINT-F-006 (LOW): No formatting check in CI
**Description**: `cargo fmt --check` not in plan.
**Resolution**: Add to plan 1.1.5 and CI workflow

### LINT-F-007 (LOW): No `cargo geiger` for unsafe tracking
**Description**: Should monitor unsafe code even if banned in our code.
**Resolution**: Add `cargo geiger` to CI (informational)

---

## Cargo-Deny Configuration

### `deny.toml`

```toml
[graph]
all-features = true

[advisories]
version = 2
db-path = "~/.cargo/advisory-db"
db-urls = ["https://github.com/rustsec/advisory-db"]

[licenses]
version = 2
allow = [
    "MIT",
    "Apache-2.0",
    "Apache-2.0 WITH LLVM-exception",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "CC0-1.0",
    "Unicode-DFS-2016",
    "Unicode-3.0",
    "MPL-2.0",
    "Zlib",
]
confidence-threshold = 0.8

[bans]
multiple-versions = "warn"
wildcards = "deny"
highlight = "all"
deny = []
skip = []
skip-tree = []

[sources]
unknown-registry = "deny"
unknown-git = "deny"
allow-registry = ["https://github.com/rust-lang/crates.io-index"]
allow-git = []
```

---

## Pre-commit Hooks

### `.pre-commit-config.yaml`

```yaml
repos:
  - repo: local
    hooks:
      - id: cargo-fmt
        name: cargo fmt
        entry: cargo fmt --all -- --check
        language: system
        pass_filenames: false
      - id: cargo-clippy
        name: cargo clippy
        entry: cargo clippy --workspace --all-targets -- -D warnings
        language: system
        pass_filenames: false
      - id: cargo-test
        name: cargo test
        entry: cargo test --workspace
        language: system
        pass_filenames: false
```

---

## Required Plan Updates

1. Plan §1.1.4: Add full `[lints]` configuration
2. Plan §1.1.5: Add `rustfmt.toml` with project settings
3. Plan §1.1.6: Add `deny.toml` with license/advisory settings
4. Plan §5.6: Add `cargo geiger` and `cargo machete` to CI
5. Plan §7.5: Add `#![deny(unsafe_code)]` to all crate roots
6. Plan §5.4.6: Add formatting check to CI

---

## Lint Audit Summary

| Severity | Count |
|----------|-------|
| High | 2 |
| Medium | 2 |
| Low | 3 |
| **Total** | **7** |

### Required Actions (High)

1. **LINT-F-001**: Plan must include explicit `[lints]` configuration
2. **LINT-F-002**: All crates have `#![deny(unsafe_code)]`

---

**End of Lint + Dead Code Audit**

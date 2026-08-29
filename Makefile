# rw_secstore Makefile
# Common development tasks

.PHONY: help build test lint fmt check docs clean install release docker

# Default target
help:
	@echo "rw_secstore - Available targets:"
	@echo "  build       - Build the project"
	@echo "  test        - Run all tests"
	@echo "  lint        - Run clippy linter"
	@echo "  fmt         - Format code with rustfmt"
	@echo "  check       - Run all checks (fmt, lint, test)"
	@echo "  docs        - Build documentation"
	@echo "  clean       - Clean build artifacts"
	@echo "  install     - Install binary locally"
	@echo "  release     - Build release binary"
	@echo "  docker      - Build Docker image"
	@echo "  audit       - Run security audit"
	@echo "  deny        - Run cargo-deny checks"

# Build debug
build:
	cargo build --all-targets --all-features

# Build release
release:
	cargo build --release --all-targets --all-features

# Run tests
test:
	cargo test --all-targets --all-features

# Run tests with no default features
test-minimal:
	cargo test --all-targets --no-default-features

# Run clippy
lint:
	cargo clippy --all-targets --all-features -- -D warnings

# Format code
fmt:
	cargo fmt --all --check

# Format code (fix)
fmt-fix:
	cargo fmt --all

# Run all checks
check: fmt lint test

# Build documentation
docs:
	cargo doc --all-features --no-deps --document-private-items

# Clean build artifacts
clean:
	cargo clean

# Install binary locally
install:
	cargo install --path . --all-features

# Build Docker image
docker:
	docker build -t rw_secstore:latest .

# Run security audit
audit:
	cargo install cargo-audit --locked 2>/dev/null || true
	cargo audit

# Run cargo-deny
deny:
	cargo install cargo-deny --locked 2>/dev/null || true
	cargo deny check

# Generate code coverage
coverage:
	cargo install cargo-llvm-cov --locked 2>/dev/null || true
	cargo llvm-cov --all-features --workspace --html

# Update dependencies
update:
	cargo update

# Check for outdated dependencies
outdated:
	cargo install cargo-outdated --locked 2>/dev/null || true
	cargo outdated

# Run benchmarks
bench:
	cargo bench --all-features

# Pre-commit checks
pre-commit: fmt lint test

# CI simulation
ci: check audit deny docs
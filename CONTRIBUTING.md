# Contributing to rw_secStore

Thank you for your interest in contributing to rw_secStore! This document provides guidelines for contributing to the project.

## Code of Conduct

This project adheres to the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## How to Contribute

### Reporting Bugs

Before creating a bug report, please check existing issues to avoid duplicates. When creating a bug report, include:

- Clear, descriptive title
- Steps to reproduce
- Expected vs actual behavior
- Environment details (OS, Rust version, etc.)
- Relevant logs or error messages

### Suggesting Enhancements

Enhancement suggestions are welcome! Please provide:

- Clear description of the enhancement
- Use case / motivation
- Proposed solution (if any)
- Alternatives considered

### Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests and linting (`cargo test && cargo clippy`)
5. Commit with conventional commits (`feat:`, `fix:`, `docs:`, etc.)
6. Push to your fork
7. Open a Pull Request

## Development Setup

```bash
# Clone
git clone https://github.com/rapidwebs/rw_secStore.git
cd rw_secStore

# Install dependencies
cargo build

# Run tests
cargo test

# Run linter
cargo clippy -- -D warnings

# Format code
cargo fmt --check
```

## Coding Standards

- Follow [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- Use `cargo fmt` for formatting
- Pass `cargo clippy` with no warnings
- Write tests for new functionality
- Document public APIs with `///` comments
- Follow semantic versioning

## Commit Message Convention

We use [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `chore`, `security`

Examples:
- `feat(crypto): add Ed25519 key support`
- `fix(api): handle null response in token endpoint`
- `docs: update deployment guide for Kubernetes 1.28`

## Testing

- Unit tests in `src/` modules (`#[cfg(test)]`)
- Integration tests in `tests/`
- Property-based tests with `proptest` where applicable
- Target: >90% code coverage

## Security

For security vulnerabilities, see [SECURITY.md](SECURITY.md). Do not open public issues for security problems.

## Release Process

1. Maintainers create release branch
2. Version bump in `Cargo.toml`
3. Changelog updated
4. Tagged release (`vX.Y.Z`)
5. Published to crates.io

## Questions?

Open a discussion or reach out to the maintainers.
# ARCHITECTURE DECISION RECORD 001
## Industry Standard Format for ADRs (2026)

## Document Identification
- **ADR ID**: 001
- **Title**: SQLite as Primary Storage Backend
- **Status**: Accepted
- **Date**: 2026-08-28
- **Author**: ForgeCode / RapidWebs
- **Stakeholders**: RapidWebs Engineering, Security Team, Operations

## Table of Contents
1. [Context](#1-context)
2. [Decision](#2-decision)
3. [Status](#3-status)
4. [Consequences](#4-consequences)
5. [Implications](#5-implications)
6. [Related Documents](#6-related-documents)

---

## 1. Context

### Problem Statement
rw_secstore needs a reliable, portable, single-file storage backend for cryptographic keys, certificates, and audit logs. The storage must support:
- ACID transactions for data integrity
- Concurrent read access (multiple CLI invocations)
- Schema evolution over time
- Zero-configuration deployment
- Portable backup (file copy)
- Encryption at application layer

### Drivers
- **Simplicity**: Single binary with no external service dependencies
- **Portability**: Database file must be copyable across machines/OSes
- **Auditability**: SQLite database is inspectable with standard tools
- **Reliability**: Proven track record, used in billions of devices
- **Performance**: WAL mode provides good concurrent read performance
- **Ecosystem**: Excellent Rust bindings via `rusqlite`

### Assumptions
- SQLite 3.35+ features available (WAL, JSON1, generated columns)
- Database size < 10GB (well within SQLite limits)
- Single-writer model acceptable (CLI tool, not high-throughput service)
- File system supports POSIX locking (or Windows equivalent)

### Constraints
- No external database server (PostgreSQL, MySQL, etc.)
- No embedded key-value stores requiring separate compilation (LMDB, RocksDB)
- Must work on Linux, macOS, Windows without system dependencies

## 2. Decision

### Decision Statement
**Use SQLite as the sole storage backend for rw_secstore, accessed via `rusqlite` with bundled SQLite compilation.**

### Considered Alternatives

#### Alternative 1: PostgreSQL (embedded via pg_embedded)
- **Pros**: Full SQL, robust, familiar
- **Cons**: Large binary size (~50MB+), complex deployment, overkill for CLI tool

#### Alternative 2: LMDB (via `heed` or `lmdb-rs`)
- **Pros**: Fast, ACID, zero-copy reads
- **Cons**: No native Rust implementation (C library), map size limits, less portable, no SQL

#### Alternative 3: RocksDB (via `rocksdb` crate)
- **Pros**: High performance, column families
- **Cons**: C++ dependency, large binary, complex tuning, overkill

#### Alternative 4: Sled (pure Rust)
- **Pros**: Pure Rust, good performance
- **Cons**: No SQL, less mature, limited tooling, no standard backup format

#### Alternative 5: File-based (JSON/YAML per entry)
- **Pros**: Human readable, simple
- **Cons**: No transactions, no concurrent access, no indexing, corruption risk

#### Alternative 6: SQLCipher (encrypted SQLite)
- **Pros**: Transparent encryption at rest
- **Cons**: Requires system SQLCipher, licensing (commercial), key management complexity

### Decision Rationale
SQLite provides the optimal balance of:
1. **Zero external dependencies** (bundled via `rusqlite` with `bundled` feature)
2. **Single file** - trivial backup, copy, inspect
3. **SQL + ACID** - familiar, reliable, transactional
4. **WAL mode** - concurrent readers, single writer
5. **Schema migrations** - `PRAGMA user_version` + migration table
6. **Tooling** - `sqlite3` CLI, DB Browser, programmatic access
7. **Rust ecosystem** - `rusqlite` is mature, well-maintained
8. **Reference validation** - Both minica and db-keystore successfully use SQLite

### Implementation Approach
- Enable `bundled` feature in `rusqlite` for consistent SQLite version
- Use WAL mode (`PRAGMA journal_mode=WAL`)
- Enable foreign keys (`PRAGMA foreign_keys=ON`)
- Set busy timeout (5000ms) with retry logic
- Schema version table for migrations
- Application-level encryption (not SQLCipher) for flexibility

## 3. Status
**Accepted** - Ready for implementation

## 4. Consequences

### 4.1 Positive Consequences
- Single binary deployment (~15-20MB with musl)
- Database file is portable across platforms
- Standard tooling for inspection/debugging
- Proven reliability in production (minica, db-keystore)
- Excellent Rust integration
- No operational overhead (no server to manage)

### 4.2 Negative Consequences
- Single writer limitation (mitigated: CLI tool, low contention)
- No built-in replication/HA (out of scope for v1)
- File locking issues on network filesystems (documented limitation)
- 140TB theoretical limit (practical limit much lower, but sufficient)

### 4.3 Neutral Consequences
- Schema migrations required for evolution
- Connection pooling not needed (single connection per CLI invocation)

## 5. Implications

### 5.1 Architectural Implications
- Storage layer is a thin wrapper over `rusqlite::Connection`
- Repository pattern for each entity type
- Migration runner at startup
- Connection per command (short-lived)

### 5.2 Technical Implications
- `rusqlite` with `bundled`, `modern_sqlite`, `uuid` features
- `serde_json` for JSON columns (labels, SANs)
- `chrono` for timestamp handling (stored as INTEGER ms)
- `uuid` with `v7` feature for time-sortable IDs

### 5.3 Organizational Implications
- Team needs SQLite knowledge (basic)
- Schema changes require migration scripts
- Backup strategy: file copy or `backup` command

### 5.4 Financial Implications
- Zero licensing costs
- Minimal infrastructure (no DB server)

### 5.5 Schedule Implications
- No delay - SQLite integration is straightforward
- Migration framework needed early (v0.1)

## 6. Related Documents
- **SPEC-2026-001**: Core specification (database schema section)
- **ADR-002**: Application-level encryption (supersedes SQLCipher consideration)
- **Reference**: minica (wushilin/minica) - SQLite CA implementation
- **Reference**: db-keystore (stevelr/db-keystore) - SQLite keystore patterns
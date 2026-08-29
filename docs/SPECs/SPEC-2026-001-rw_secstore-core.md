# SPECIFICATION: rw_secstore Core Keystore & Certificate Authority
## Industry Standard Format for Software Specifications (2026)

## Document Identification
- **SPEC ID**: SPEC-2026-001
- **Version**: 1.1.0
- **Status**: Draft
- **Date**: 2026-08-29
- **Author**: ForgeCode / RapidWebs
- **Stakeholders**: RapidWebs Engineering, Security Team, Operations
- **Supersedes**: v1.0.0 (2026-08-28)

## Table of Contents
1. [Purpose](#1-purpose)
2. [Scope](#2-scope)
3. [Definitions and Acronyms](#3-definitions-and-acronyms)
4. [Functional Requirements](#4-functional-requirements)
5. [Non-Functional Requirements](#5-non-functional-requirements)
6. [Interfaces](#6-interfaces)
7. [Architecture Constraints](#7-architecture-constraints)
8. [Acceptance Criteria](#8-acceptance-criteria)
9. [Open Issues](#9-open-issues)
10. [Appendix](#10-appendix)

---

## 1. Purpose

rw_secstore is a minimal, enterprise-grade secure keystore and certificate authority that provides a single-file SQLite database for storing, managing, and provisioning cryptographic keys, certificates, and SSH credentials. It serves as:

- A **secrets vault** (symmetric keys, asymmetric key pairs, generic secrets)
- A **certificate authority** (issuing, revoking, and managing X.509 certificates)
- An **SSH key manager** (storing, exporting, and provisioning SSH credentials for fleet management)
- A **multi-factor authentication store** (master password, OS keyring, backup codes)

**Problem Statement**: Existing solutions are either too complex (HashiCorp Vault, Smallstep), too limited (simple file-based keystores), or lack integrated support for SSH fleet management. rw_secstore fills this gap with a minimal, auditable, single-binary solution purpose-built for sysadmins managing a fleet of VMs, servers, workstations, and GitHub accounts.

**Value Delivered**:
- Single binary deployment with zero external dependencies
- SQLite database file is portable, backupable, and inspectable
- Quad-purpose: keystore + CA + SSH key manager + multi-factor unlock
- Enterprise-grade encryption (Argon2id + AES-256-GCM)
- Strong master password policy with generator and breach detection
- Flexible unlock: master password, OS keyring, or backup codes
- Full audit trail for compliance with HMAC chain integrity
- CLI-first design for automation and scripting

---

## 2. Scope

### 2.1 In Scope (v1.0)

| Category | Features |
|----------|----------|
| **Core Storage** | SQLite database with schema migrations, WAL mode, soft deletes, HMAC integrity seal |
| **Encryption** | Master password OR OS keyring unlock, per-entry encryption (Argon2id + AES-256-GCM) |
| **Keystore Operations** | Store, retrieve, list, delete, compare, verify keys/secrets |
| **CA Operations** | Create root/intermediate CAs, issue certificates, revoke, CRL generation |
| **Key Types** | RSA (2048/4096), ECDSA (P-256/P-384), Ed25519, AES-256, ChaCha20-Poly1305, generic secrets |
| **SSH Keys** | Storage and export in OpenSSH/PEM/PKCS#8 formats |
| **Import/Export** | PEM, PKCS#12, JSON backup/restore, SSH formats |
| **Audit** | Structured audit logging for all operations with HMAC chain |
| **CLI** | Full command-line interface with subcommands |
| **Configuration** | TOML config file, environment variable overrides |
| **Password Policy** | zxcvbn strength, HIBP offline breach check, history |
| **Password Generator** | High-entropy charset, diceware EFF wordlist, policy-aware |
| **Password File** | Secure read/export with 0o600 permissions |
| **Multi-Factor Unlock** | Password, OS keyring (libsecret/wincred/keychain), backup codes |

### 2.2 Out of Scope (v1.0)

| Category | Excluded Features | Deferred To |
|----------|-------------------|-------------|
| **SSH Provisioning** | Automatic `authorized_keys` deployment to remote hosts | v1.1 |
| **SSH Certificates** | OpenSSH certificate signing | v1.1 |
| **SSH Agent** | Direct ssh-agent integration | v1.2 |
| **known_hosts Management** | Managed known_hosts database | v1.2 |
| **FIDO2/WebAuthn** | Hardware security key unlock | v1.1 |
| **Network Services** | No HTTP/gRPC server, no remote API | v2.0 |
| **Multi-user** | Single-user, no RBAC | v2.0 |
| **HSM/PKCS#11** | No hardware security module integration | v2.0 |
| **ACME/Let's Encrypt** | No automatic certificate management | v2.0 |
| **Cluster/HA** | No replication, clustering, or HA | v2.0 |
| **Web UI** | No graphical or web interface | v2.0 |
| **Secret Rotation** | No automatic rotation policies | v1.1 |
| **Plugin System** | No extensibility framework | v2.0 |

### 2.3 Assumptions

1. SQLite 3.35+ is available (WAL mode, JSON1 extension)
2. Target platforms: Linux (x86_64, aarch64), macOS (Intel/Apple Silicon), Windows (x86_64)
3. Rust 1.75+ for compilation
4. Optional OS keyring: libsecret (Linux), Credential Manager (Windows), Keychain (macOS)
5. User has secure storage location for master password file or password manager
6. Database file fits in available disk space (no sharding)
7. Threat model: local attacker with filesystem read, malicious input, side-channel timing (Level 2 Zero-Knowledge Formal)

### 2.4 Constraints

| Constraint | Detail |
|------------|--------|
| **Regulatory** | Must support audit logging for SOC2/ISO27001 compliance |
| **Technical** | Single binary < 50MB, startup < 100ms |
| **Security** | FIPS 140-3 compatible algorithms only |
| **Operational** | Zero-downtime backup (copy database file) |
| **Compatibility** | Database forward-compatible (newer version reads older) |
| **Usability** | Default unlock should work without advanced configuration |

---

## 3. Definitions and Acronyms

| Term | Definition |
|------|------------|
| **CA** | Certificate Authority |
| **CRL** | Certificate Revocation List |
| **DN** | Distinguished Name (X.500) |
| **SAN** | Subject Alternative Name |
| **PEM** | Privacy-Enhanced Mail (Base64-encoded DER) |
| **PKCS#12** | Personal Information Exchange Syntax Standard |
| **Argon2id** | Memory-hard key derivation function (RFC 9106) |
| **AES-GCM** | AES Galois/Counter Mode (authenticated encryption) |
| **WAL** | Write-Ahead Logging (SQLite journal mode) |
| **UUID v7** | Time-sortable UUID (RFC 9562) |
| **DEK** | Data Encryption Key |
| **KEK** | Key Encryption Key (derived from master password) |
| **MEK** | Master Encryption Key (256-bit random, stored in OS keyring) |
| **Soft Delete** | Mark record as deleted without removing from DB |
| **TOFU** | Trust On First Use |
| **zxcvbn** | Password strength estimation algorithm |
| **HIBP** | Have I Been Pwned (breach database) |
| **EFF** | Electronic Frontier Foundation (diceware wordlist) |
| **FIDO2** | Fast Identity Online 2 (WebAuthn + CTAP2) |
| **HSM** | Hardware Security Module |
| **RBAC** | Role-Based Access Control |
| **HMAC** | Hash-based Message Authentication Code |
| **HKDF** | HMAC-based Extract-and-Expand Key Derivation Function (RFC 5869) |

---

## 4. Functional Requirements

### 4.1 Core Database & Schema

**REQ-DB-001**: The system SHALL use SQLite as the sole storage backend.
- **Given**: A new or existing database file path
- **When**: The keystore is initialized or opened
- **Then**: SQLite database is created/opened with WAL mode enabled, foreign keys enforced, and file permissions set to 0o600
- **Acceptance Criteria**:
  - Database file created if not exists
  - `PRAGMA journal_mode=WAL` executed
  - `PRAGMA foreign_keys=ON` executed
  - Database file permissions verified as 0o600 on open
  - Parent directory created with 0o700 if needed
  - WAL and SHM files inherit 0o600 permissions
  - Schema version table exists and is readable

**REQ-DB-002**: The system SHALL maintain a schema version table for migrations.
- **Given**: Database with schema version N
- **When**: Application starts with schema version M > N
- **Then**: Migrations N→N+1→...→M are applied atomically with rollback support
- **Acceptance Criteria**:
  - Each migration runs in a transaction
  - Rollback on any migration failure
  - Schema version updated only after successful migration
  - Pre-migration backup created (optional, configurable)
  - Migrations tested for v1→v2→v3 + rollback in CI

**REQ-DB-003**: The system SHALL implement soft deletes for all entities.
- **Given**: Any entity (CA, certificate, key, secret, SSH key)
- **When**: Delete operation is requested
- **Then**: Record marked with `deleted_at` timestamp, excluded from normal queries
- **Acceptance Criteria**:
  - `deleted_at` column on all entity tables
  - Default queries filter `WHERE deleted_at IS NULL`
  - `list --include-deleted` shows soft-deleted entries
  - `purge` command permanently removes soft-deleted entries

**REQ-DB-004**: The system SHALL maintain database integrity via HMAC seal.
- **Given**: Any database mutation
- **When**: Committing a transaction
- **Then**: Full-file HMAC-SHA256 computed and stored in header
- **Acceptance Criteria**:
  - HMAC key derived from KEK/MEK (separate HKDF context)
  - On open: HMAC verified, warn if mismatch (corruption detected)
  - Seal stored in `keystore_meta` table

### 4.2 Encryption & Key Management

**REQ-CRYPTO-001**: The system SHALL derive a Key Encryption Key (KEK) from the master password using Argon2id.
- **Given**: Master password provided by user
- **When**: Keystore is unlocked via password
- **Then**: KEK derived with Argon2id (configurable params with safe minimums)
- **Acceptance Criteria**:
  - Salt: 32 bytes cryptographically random per database
  - Default params: memory=64MB, iterations=3, parallelism=4
  - Production minimum: memory=64MB, iterations=3
  - CI test params: memory=8MB, iterations=1 (via `RW_SECSTORE_FAST_KDF=1`)
  - KEK: 32 bytes (256-bit)
  - Constant-time comparison for password verification (subtle crate)
  - Salt stored in `keystore_meta` table
  - Hardcoded minimums prevent downgrade attacks

**REQ-CRYPTO-002**: The system SHALL encrypt each private key/secret independently using AES-256-GCM.
- **Given**: Plaintext key material and KEK (or MEK)
- **When**: Storing a new entry
- **Then**: Per-entry DEK generated, encrypted with KEK/MEK, key material encrypted with DEK
- **Acceptance Criteria**:
  - Format: `[salt(32)][nonce(12)][ciphertext+tag]`
  - DEK: 32 bytes random per entry via HKDF
  - HKDF context: includes entry_id (prevents cross-entry key derivation)
  - Nonce: 12 bytes (96-bit) random per encryption
  - Authenticated encryption (GCM tag verified on decrypt)
  - Zeroize plaintext DEK and key material after encryption
  - No nonce reuse (random generation, 2^32 limit)

**REQ-CRYPTO-003**: The system SHALL support re-encryption (rekey) when master password changes.
- **Given**: Unlocked keystore with current master password
- **When**: User requests password change
- **Then**: All entries re-encrypted with new KEK in a single atomic transaction
- **Acceptance Criteria**:
  - Atomic operation (all-or-nothing via single transaction)
  - Original password required for verification
  - Progress indication for large keystores (>2s)
  - Rollback on failure (transaction revert)
  - Password history updated

**REQ-CRYPTO-004**: The system SHALL protect master password in memory.
- **Given**: Master password in memory
- **When**: Keystore is locked or process exits
- **Then**: Password zeroized via `zeroize` crate
- **Acceptance Criteria**:
  - Use `Zeroizing<String>` or `Secret<String>` wrapper
  - Clear on `Drop` implementation
  - Signal handlers zeroize on SIGTERM/SIGINT/SIGHUP
  - mlock sensitive buffers (best-effort, fallback if not permitted)

### 4.3 Keystore Operations

**REQ-KS-001**: The system SHALL store and retrieve generic secrets.
- **Given**: Alias, secret value (string or bytes), optional metadata
- **When**: `key store <alias>` command executed
- **Then**: Secret encrypted and stored with alias
- **Acceptance Criteria**:
  - Alias unique per keystore (configurable)
  - Metadata: labels (key-value pairs), description
  - Retrieval returns plaintext (after auth)
  - Binary secrets supported (base64 encoded in CLI)

**REQ-KS-002**: The system SHALL store and retrieve asymmetric key pairs.
- **Given**: Alias, key type (RSA/ECDSA/Ed25519), optional existing key material
- **When**: `key store --type asymmetric` executed
- **Then**: Key pair generated or imported, private key encrypted, public key stored plaintext
- **Acceptance Criteria**:
  - RSA: 2048, 3072, 4096 bits
  - ECDSA: P-256 (prime256v1), P-384 (secp384r1)
  - Ed25519: 256-bit
  - Public key available without unlock (for verification)
  - Private key requires unlock
  - Private/public key consistency validated on import

**REQ-KS-003**: The system SHALL store and retrieve symmetric keys.
- **Given**: Alias, key type (AES-256, ChaCha20-Poly1305), optional existing key
- **When**: `key store --type symmetric` executed
- **Then**: Key generated or imported, encrypted and stored
- **Acceptance Criteria**:
  - AES-256: 32-byte key
  - ChaCha20-Poly1305: 32-byte key
  - Key never exposed in plaintext except on explicit `get --reveal`

**REQ-KS-004**: The system SHALL list keys with filtering options.
- **Given**: Populated keystore
- **When**: `key list` executed
- **Then**: Table output with alias, type, created, labels
- **Acceptance Criteria**:
  - Filter by type: `--type asymmetric|symmetric|secret`
  - Filter by label: `--label key=value`
  - Sort by: alias, created, type
  - Output formats: table, json, csv

**REQ-KS-005**: The system SHALL compare two keys for equality.
- **Given**: Two key aliases
- **When**: `key compare <alias1> <alias2>` executed
- **Then**: Comparison result (match/mismatch) with fingerprint
- **Acceptance Criteria**:
  - Compares public key material for asymmetric
  - Compares key bytes for symmetric (requires both unlocked)
  - Shows SHA-256 fingerprint of each
  - Constant-time comparison (subtle crate)

**REQ-KS-006**: The system SHALL verify signatures using stored public keys.
- **Given**: Key alias, data, signature
- **When**: `key verify <alias> --data <data> --signature <sig>` executed
- **Then**: Verification result (valid/invalid)
- **Acceptance Criteria**:
  - Supports RSA-PSS, RSA-PKCS1v15, ECDSA, Ed25519
  - Data from file, stdin, or string
  - Signature in base64, hex, or raw bytes
  - Clear error on algorithm mismatch

**REQ-KS-007**: The system SHALL support key expiration as optional metadata.
- **Given**: Key with optional `expires_at` timestamp
- **When**: Key is used (get, sign, decrypt)
- **Then**: Warning displayed if expired
- **Acceptance Criteria**:
  - `expires_at` is optional in metadata
  - No automatic deletion on expiration
  - CLI shows expiration status in `list` and `get`
  - No enforcement of expiration

### 4.4 SSH Key Management

**REQ-SSH-001**: The system SHALL store and manage SSH key pairs in OpenSSH format.
- **Given**: Alias, key type (ed25519, rsa, ecdsa), optional passphrase
- **When**: `ssh store <alias> --type ed25519` executed
- **Then**: SSH key pair generated in OpenSSH format, private key encrypted, public key in authorized_keys format
- **Acceptance Criteria**:
  - Ed25519 (preferred), RSA-4096, ECDSA-P256/P384
  - Private key: OpenSSH format (BEGIN OPENSSH PRIVATE KEY)
  - Public key: OpenSSH format (ssh-ed25519 AAAA... comment)
  - Optional passphrase on private key (in addition to master password)
  - Comment field for identification (user@host)
  - Stored in `ssh_keys` table with FK to `keys` table

**REQ-SSH-002**: The system SHALL export SSH keys in standard formats.
- **Given**: SSH key alias
- **When**: `ssh export <alias> --format openssh|pem|pkcs8` executed
- **Then**: Key exported in requested format
- **Acceptance Criteria**:
  - OpenSSH private key format (default)
  - PKCS#8 PEM format (for interop with OpenSSL)
  - Public key in authorized_keys format
  - Optional: encrypt export with separate password (`--export-password`)

**REQ-SSH-003**: The system SHALL generate SSH key passphrases using the password generator.
- **Given**: SSH key generation request
- **When**: `ssh store --generate-passphrase` executed
- **Then**: High-entropy passphrase generated, displayed once, stored encrypted
- **Acceptance Criteria**:
  - Diceware passphrase (6 words, ~77 bits entropy) by default
  - Stored encrypted with master password
  - Displayed once on generation (with `--reveal` flag)
  - Retrievable via `ssh get --reveal-passphrase`

### 4.5 Certificate Authority Operations

**REQ-CA-001**: The system SHALL create root Certificate Authorities.
- **Given**: Alias, subject DN, key profile, validity period
- **When**: `ca create <alias> --type root` executed
- **Then**: Self-signed root CA certificate and private key generated and stored
- **Acceptance Criteria**:
  - Key profiles: RSA-2048, RSA-4096, ECDSA-P256, ECDSA-P384, Ed25519
  - Subject DN: CN, O, OU, C, ST, L
  - Validity: configurable days (default 3650 = 10 years)
  - Basic Constraints: CA=true, pathlen=0 (configurable)
  - Key Usage: keyCertSign, cRLSign
  - Stored as CA entry with type=CaRoot

**REQ-CA-002**: The system SHALL create intermediate Certificate Authorities.
- **Given**: Alias, subject DN, key profile, validity, parent CA alias
- **When**: `ca create <alias> --type intermediate --ca <parent>` executed
- **Then**: CSR generated, signed by parent CA, certificate chain stored
- **Acceptance Criteria**:
  - Parent CA must be unlocked
  - Pathlen decremented from parent
  - Full chain stored (intermediate + parent certs)
  - Can issue leaf certificates
  - Certificate path validation on import (if importing external CA)

**REQ-CA-003**: The system SHALL issue end-entity certificates.
- **Given**: CA alias, subject CN, SANs (DNS/IP), key profile, validity
- **When**: `cert issue <ca-alias> <cn>` executed
- **Then**: Certificate signed by CA, stored with private key
- **Acceptance Criteria**:
  - SANs: multiple DNS names and IP addresses
  - Key profile can differ from CA
  - Validity: configurable (default 365 days)
  - Key Usage: digitalSignature, keyEncipherment (configurable)
  - Extended Key Usage: serverAuth, clientAuth (configurable)
  - Certificate stored with reference to issuing CA
  - CSR replay protection (track CSR nonce)

**REQ-CA-004**: The system SHALL revoke certificates and maintain CRL.
- **Given**: CA alias, certificate alias, revocation reason
- **When**: `cert revoke <ca-alias> <cert-alias> --reason <reason>` executed
- **Then**: Certificate marked revoked, CRL regenerated
- **Acceptance Criteria**:
  - Reasons: unspecified, keyCompromise, caCompromise, affiliationChanged, superseded, cessationOfOperation, certificateHold, removeFromCRL, privilegeWithdrawn, aaCompromise
  - CRL includes all revoked certs for that CA
  - CRL number increments
  - nextUpdate set (default 30 days)
  - CRL stored in CA entry, exportable as PEM/DER
  - CRL distribution via HTTP stub (TODO v2.0 for full HTTP)

**REQ-CA-005**: The system SHALL renew certificates.
- **Given**: CA alias, certificate alias, new validity period
- **When**: `cert renew <ca-alias> <cert-alias> --days <days>` executed
- **Then**: New certificate issued with same key, old certificate revoked (superseded)
- **Acceptance Criteria**:
  - Same key pair reused
  - Old cert revoked with reason=superseded
  - New validity from now
  - Chain preserved

**REQ-CA-006**: The system SHALL import and export CAs and certificates.
- **Given**: CA or certificate alias
- **When**: `ca export` or `cert export` executed
- **Then**: PEM or PKCS#12 output
- **Acceptance Criteria**:
  - Formats: PEM (cert only), PEM (cert+key), PKCS#12
  - PKCS#12 password protected (separate from master password)
  - Chain included for intermediates
  - Import validates chain and stores appropriately
  - PKCS#12 interop tested with OpenSSL

### 4.6 Backup & Restore

**REQ-BACKUP-001**: The system SHALL create portable JSON backups.
- **Given**: Unlocked keystore
- **When**: `backup --output <file>` executed
- **Then**: JSON file with all entries (encrypted private keys), schema version, metadata
- **Acceptance Criteria**:
  - Includes: all CAs, certificates, keys, SSH keys, secrets, audit log (optional)
  - Encrypted private keys remain encrypted (portable across passwords)
  - Schema version included for migration on restore
  - Checksum (SHA-256) of backup file
  - Compressed option (gzip)

**REQ-BACKUP-002**: The system SHALL restore from backup.
- **Given**: Backup file, target database path (new or existing)
- **When**: `restore <backup-file>` executed
- **Then**: Database populated with backup contents atomically
- **Acceptance Criteria**:
  - Schema migration applied if backup version older
  - Master password required (to re-encrypt DEKs)
  - Integrity check via checksum
  - Conflict resolution: skip, overwrite, rename
  - Audit log entry for restore operation
  - Atomic: use temp file + rename pattern

### 4.7 Audit Logging

**REQ-AUDIT-001**: The system SHALL log all mutating operations with HMAC chain integrity.
- **Given**: Any write operation (create, update, delete, import, export)
- **When**: Operation completes
- **Then**: Audit entry written with timestamp, operation, entity, user, result, and HMAC link to previous entry
- **Acceptance Criteria**:
  - Fields: id, timestamp, operation, entity_type, entity_id, actor, success, details, hmac_chain
  - Actor: CLI user (from env/OS), or "system"
  - Details: JSON with relevant parameters (no secrets)
  - Immutable append-only (soft delete only)
  - HMAC chain: `hmac_i = HMAC(key, hmac_{i-1} || entry_i)` where key is separate HKDF derivation
  - Chain verification on every audit read (detect truncation/modification)
  - Queryable via `audit` command

**REQ-AUDIT-002**: The system SHALL support audit log queries.
- **Given**: Populated audit log
- **When**: `audit --since <time> --operation <op> --entity <type>` executed
- **Then**: Filtered audit entries displayed
- **Acceptance Criteria**:
  - Time range filters
  - Operation type filter
  - Entity type filter
  - Output formats: table, json, csv
  - Pagination for large results
  - Chain integrity status shown

### 4.8 Password Policy

**REQ-PWD-001**: The system SHALL enforce configurable password policies on master password.
- **Given**: Password policy configuration
- **When**: User sets/changes master password
- **Then**: Password validated against policy, rejected if non-compliant
- **Acceptance Criteria**:
  - Minimum length (default: 16, configurable 12-128)
  - Minimum entropy (default: 80 bits, configurable)
  - Character class requirements: upper, lower, digit, symbol (configurable)
  - Maximum consecutive identical chars (default: 3)
  - No common patterns (keyboard walks, repeated sequences)
  - Policy stored in `keystore_meta`, enforced on init/rekey

**REQ-PWD-002**: The system SHALL check passwords against known breaches.
- **Given**: Password to validate
- **When**: Password policy check runs
- **Then**: Password checked against HaveIBeenPwned API (k-anonymity) or offline list
- **Acceptance Criteria**:
  - Offline mode: bundled top 100k common passwords (configurable)
  - Online mode: HIBP k-anonymity API (SHA-1 prefix, opt-in)
  - Configurable: enabled/disabled, online/offline/both
  - Cache results for 24h (online mode)
  - Clear error message if breached

**REQ-PWD-003**: The system SHALL prevent password reuse.
- **Given**: Password history configuration (default: 5)
- **When**: User changes master password
- **Then**: New password checked against history, rejected if reused
- **Acceptance Criteria**:
  - Store Argon2id hash of previous passwords (not plaintext)
  - Configurable history depth (1-20)
  - History migrated on rekey
  - Clear error: "Password used previously"

**REQ-PWD-004**: The system SHALL estimate and display password strength.
- **Given**: Password input (during init/change)
- **When**: Password entered
- **Then**: Real-time strength meter displayed (entropy, time-to-crack)
- **Acceptance Criteria**:
  - zxcvbn algorithm (or equivalent)
  - Display: entropy bits, estimated crack time, suggestions
  - Non-blocking (warning only, not enforcement)
  - Available via `pwgen --check <password>`

### 4.9 Password Generation

**REQ-PWG-001**: The system SHALL generate high-entropy passwords.
- **Given**: Generation parameters (length, charset, policy)
- **When**: `pwgen [--length N] [--charset SET] [--policy]` executed
- **Then**: Cryptographically random password generated
- **Acceptance Criteria**:
  - Default: 32 chars, full ASCII printable (94 chars) = ~210 bits entropy
  - Charset options: alphanumeric, alphanumeric+symbols, diceware, custom
  - Diceware: EFF wordlist (7776 words), configurable word count (default 6 = ~77 bits)
  - Policy-aware: generates password compliant with current policy
  - Multiple candidates: `--count N` generates N options
  - Output: plaintext (stdout) or `--output-file` (with permissions 0o600)

**REQ-PWG-002**: The system SHALL support passphrase generation (diceware).
- **Given**: Wordlist, word count, separator
- **When**: `pwgen --diceware --words 6 --separator "-"` executed
- **Then**: Passphrase generated
- **Acceptance Criteria**:
  - EFF long wordlist (7776 words) bundled
  - Custom wordlist support (file path)
  - Separator: space, dash, underscore, none
  - Capitalization options: none, first, random, all
  - Entropy calculation displayed

### 4.10 Master Password File Handling

**REQ-PWD-005**: The system SHALL securely read master password from file.
- **Given**: File path with master password
- **When**: `--password-file /path/to/password` used
- **Then**: Password read securely, trailing newline stripped, file permissions validated
- **Acceptance Criteria**:
  - File MUST be 0o600 or 0o400 (reject world-readable)
  - Read entire file, strip single trailing newline only
  - Support `--password-file -` for stdin (with TTY check)
  - Clear error if permissions too open

**REQ-PWD-006**: The system SHALL export master password to file securely.
- **Given**: Unlocked keystore, target file path
- **When**: `config export-password --output /path/to/password` executed
- **Then**: Master password written to file with 0o600 permissions
- **Acceptance Criteria**:
  - File created with 0o600 (owner read/write only)
  - Parent directory created with 0o700 if needed
  - Warning: "This file contains your master password. Protect it."
  - Optional: `--format json` with metadata (created_at, policy_version)
  - Confirmation required unless `--yes`

**REQ-PWG-003**: The system SHALL generate master password and export to file in one command.
- **Given**: Generation parameters, output path
- **When**: `init --generate-password --password-file /path/to/password` executed
- **Then**: Keystore initialized with generated password, password written to file
- **Acceptance Criteria**:
  - Single atomic operation
  - Password generated per policy
  - File written with 0o600
  - Password displayed once (unless `--quiet`)
  - QR code option for mobile transfer (`--qr`)

### 4.11 Multi-Factor Unlock & Recovery

**REQ-AUTH-001**: The system SHALL support OS keyring as encryption key source.
- **Given**: Configured keyring backend (libsecret, Windows Credential Manager, macOS Keychain)
- **When**: `init --keyring` or `config keyring enable` executed
- **Then**: Master encryption key (MEK) generated, stored in OS keyring, password becomes optional
- **Acceptance Criteria**:
  - Generate 256-bit MEK (not password-derived)
  - Store in OS keyring with label "rw-secstore-master-key"
  - On unlock: retrieve from keyring → decrypt DEKs directly (bypass Argon2id)
  - Fallback to password if keyring unavailable
  - `keyring status` shows backend, key present/absent
  - `keyring remove` removes key (requires password fallback)

**REQ-AUTH-002**: The system SHALL support backup codes for emergency recovery.
- **Given**: Unlocked keystore
- **When**: `config backup-codes generate --count 8` executed
- **Then**: 8 one-time backup codes generated, displayed, stored encrypted
- **Acceptance Criteria**:
  - Format: 16 chars base32 (e.g., "ABCD-EFGH-IJKL-MNOP") = 80 bits each
  - Each code single-use (marked consumed after use)
  - Codes encrypt MEK via separate Argon2id derivation (different salt/context)
  - Stored in `backup_codes` table (encrypted, not plaintext)
  - Display once with warning: "Save these codes. They cannot be shown again."
  - `backup-codes list` shows used/unused (not the codes themselves)
  - `backup-codes regenerate` invalidates old, creates new

**REQ-AUTH-003**: The system SHALL unlock with backup code.
- **Given**: Locked keystore, valid unused backup code
- **When**: `unlock --backup-code ABCD-EFGH-IJKL-MNOP` executed
- **Then**: Keystore unlocked, backup code marked consumed
- **Acceptance Criteria**:
  - Code verified via Argon2id (separate salt, same params)
  - On success: decrypt MEK → decrypt DEKs
  - Code marked consumed atomically with unlock
  - Audit log: "unlock via backup code #3"
  - Rate limiting: max 3 attempts per minute

**REQ-AUTH-004**: The system SHALL support combined unlock methods.
- **Given**: Multiple unlock methods configured
- **When**: `unlock` executed
- **Then**: Try methods in order: keyring → password → backup code
- **Acceptance Criteria**:
  - Configurable priority order
  - `--method keyring|password|backup-code` to force specific
  - First success wins
  - Clear error if all fail

---

## 5. Non-Functional Requirements

### 5.1 Performance Requirements

| Metric | Target | Condition |
|--------|--------|-----------|
| **Startup Time** | < 100ms | Cold start, empty DB |
| **Unlock Time** | < 500ms | 1000 entries, Argon2id default |
| **Key Store** | < 50ms | Single entry, unlocked |
| **Key Retrieve** | < 30ms | Single entry, unlocked |
| **List (1000 entries)** | < 100ms | Unlocked, table output |
| **CA Create** | < 2s | RSA-4096, 10yr validity |
| **Cert Issue** | < 500ms | RSA-2048, 1yr validity |
| **Backup (1000 entries)** | < 5s | JSON output, no compression |
| **Restore (1000 entries)** | < 10s | With re-encryption |
| **SSH Key Generate** | < 100ms | Ed25519 |
| **Password Generate** | < 10ms | 32-char charset |
| **Password Check (zxcvbn)** | < 50ms | Any password |
| **Keyring Unlock** | < 200ms | Local keyring, no Argon2id |
| **Backup Code Unlock** | < 1s | Argon2id on backup code |

### 5.2 Reliability Requirements

| Requirement | Target |
|-------------|--------|
| **Availability** | N/A (CLI tool, not a service) |
| **Data Integrity** | SQLite ACID + application-level HMAC + audit chain |
| **Corruption Detection** | Schema version + HMAC seal + backup checksums |
| **Recovery** | Restore from backup < 30s for 10k entries |
| **Migration Safety** | v1→v2→v3 + rollback tested in CI |

### 5.3 Security Requirements

| Requirement | Specification |
|-------------|---------------|
| **Authentication** | Master password (Argon2id), OS keyring (MEK), or backup codes |
| **Authorization** | Single user, full access when unlocked |
| **Encryption at Rest** | AES-256-GCM per entry, Argon2id KEK or random MEK |
| **Encryption in Transit** | N/A (local file only) |
| **Key Derivation** | Argon2id (memory=64MB, iter=3, parallel=4) — hardcoded minimums |
| **Key Wrapping** | AES-256-GCM (DEK wrapped by KEK/MEK) |
| **Random Source** | OS CSPRNG (getrandom, /dev/urandom, BCryptGenRandom) |
| **Memory Protection** | Zeroize secrets on drop (zeroize crate), mlock best-effort |
| **Side-Channel** | Constant-time comparisons (subtle crate) |
| **Audit** | All mutating operations logged with HMAC chain |
| **Compliance** | Algorithms: FIPS 140-3 approved |
| **File Permissions** | Database 0o600, parent dir 0o700, password files 0o600 |
| **Password Policy** | Min 16 chars, 80 bits entropy, history of 5, breach check |
| **Supply Chain** | cargo audit + cargo-deny + SBOM in CI |
| **Threat Model** | Level 2 Zero-Knowledge Formal |

### 5.4 Usability Requirements

| Requirement | Target |
|-------------|--------|
| **CLI Help** | `rw-secstore --help`, `rw-secstore <cmd> --help` |
| **Shell Completions** | bash, zsh, fish, powershell (via clap_mangen) |
| **Man Pages** | Generated at build time via clap_mangen |
| **Error Messages** | Actionable, no stack traces by default |
| **Progress Indication** | Long operations (>2s) show progress |
| **Config File** | XDG: `~/.config/rw-secstore/config.toml` (fallback: `~/.rw-secstore/config.toml`) |
| **Default Unlock** | Should work without advanced configuration (password) |

### 5.5 Operational Requirements

| Requirement | Specification |
|-------------|---------------|
| **Deployment** | Single static binary (musl) |
| **Configuration** | TOML file + env vars (RW_SECSTORE_*) |
| **Logging** | Structured JSON to stderr (optional) |
| **Updates** | Binary replacement, DB auto-migrates |
| **Backup** | File copy (SQLite) or `backup` command |
| **Platforms** | Linux (x86_64, aarch64), macOS (Intel/Apple Silicon), Windows (x86_64) |
| **CI** | lint, test, bench, fuzz, deny, audit, coverage |

---

## 6. Interfaces

### 6.1 Command-Line Interface

```
rw-secstore [GLOBAL_OPTIONS] <COMMAND> [COMMAND_OPTIONS]

GLOBAL_OPTIONS:
  --db-path PATH          Database file path (default: XDG data dir)
  --config PATH           Config file path
  --password PASS         Master password (env: RW_SECSTORE_PASSWORD)
  --password-file PATH    Read password from file (permissions validated)
  --method METHOD         Unlock method: password|keyring|backup-code
  --no-color              Disable colored output
  --json                  JSON output for all commands
  -v, --verbose           Verbose logging
  -q, --quiet             Suppress non-error output
  --version               Show version
  -h, --help              Show help

COMMANDS:
  init                    Initialize new keystore [--generate-password] [--keyring] [--qr]
  unlock                  Unlock keystore [--method <method>] [--backup-code <code>]
  lock                    Lock keystore (clear KEK/MEK from memory)
  status                  Show keystore status

  ca create               Create CA (root/intermediate)
  ca list                 List CAs
  ca show                 Show CA details
  ca import               Import CA from PEM/PKCS12
  ca export               Export CA to PEM/PKCS12
  ca delete               Delete CA (soft)
  ca purge                Permanently delete CA

  cert issue              Issue certificate
  cert list               List certificates
  cert show               Show certificate details
  cert revoke             Revoke certificate
  cert renew              Renew certificate
  cert export             Export certificate
  cert delete             Delete certificate (soft)
  cert purge              Permanently delete certificate

  key store               Store key/secret
  key get                 Retrieve key/secret
  key list                List keys
  key compare             Compare two keys
  key verify              Verify signature
  key delete              Delete key (soft)
  key purge               Permanently delete key

  ssh store               Store/generate SSH key pair
  ssh get                 Retrieve SSH key
  ssh list                List SSH keys
  ssh export              Export SSH key (openssh, pem, pkcs8)

  pwgen                   Generate secure password/passphrase
  pwgen --check           Check password strength

  backup                  Create backup
  restore                 Restore from backup

  audit                   Query audit log
  config                  Manage configuration (keyring, backup-codes, etc.)
  completion              Generate shell completions
```

### 6.2 Data Formats

#### Database Schema (SQLite) — Updated for v1.1.0

```sql
-- Schema version tracking
CREATE TABLE schema_version (
    version INTEGER PRIMARY KEY,
    applied_at INTEGER NOT NULL,
    description TEXT
);

-- Keystore metadata (salt, config, HMAC seal)
CREATE TABLE keystore_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
-- Keys: salt, argon2_params, hmac_seal, password_policy,
--       keyring_enabled, unlock_methods_priority, schema_version

-- Certificate Authorities
CREATE TABLE certificate_authorities (
    id TEXT PRIMARY KEY,
    alias TEXT NOT NULL UNIQUE,
    ca_type TEXT NOT NULL,            -- 'root' | 'intermediate' | 'ssh_ca'
    parent_id TEXT,
    subject_dn TEXT NOT NULL,
    common_name TEXT NOT NULL,
    country_code TEXT,
    state TEXT,
    city TEXT,
    organization TEXT,
    organization_unit TEXT,
    key_profile TEXT NOT NULL,
    digest_algorithm TEXT NOT NULL,
    valid_days INTEGER NOT NULL,
    not_before INTEGER NOT NULL,
    not_after INTEGER NOT NULL,
    cert_pem TEXT NOT NULL,
    encrypted_key_pem TEXT NOT NULL,
    pkcs12_blob BLOB,
    crl_der BLOB,
    crl_number INTEGER DEFAULT 0,
    crl_updated_at INTEGER,
    pathlen INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    deleted_at INTEGER,
    FOREIGN KEY (parent_id) REFERENCES certificate_authorities(id)
);

-- Certificates
CREATE TABLE certificates (
    id TEXT PRIMARY KEY,
    ca_id TEXT NOT NULL,
    alias TEXT NOT NULL,
    subject_dn TEXT NOT NULL,
    common_name TEXT NOT NULL,
    country_code TEXT,
    state TEXT,
    city TEXT,
    organization TEXT,
    organization_unit TEXT,
    dns_names TEXT,                   -- JSON array
    ip_addresses TEXT,                -- JSON array
    key_profile TEXT NOT NULL,
    digest_algorithm TEXT NOT NULL,
    valid_days INTEGER NOT NULL,
    not_before INTEGER NOT NULL,
    not_after INTEGER NOT NULL,
    cert_pem TEXT NOT NULL,
    encrypted_key_pem TEXT NOT NULL,
    serial_number TEXT NOT NULL,
    revoked_at INTEGER,
    revocation_reason TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    deleted_at INTEGER,
    FOREIGN KEY (ca_id) REFERENCES certificate_authorities(id) ON DELETE CASCADE,
    UNIQUE (ca_id, serial_number)
);

-- Generic Keys/Secrets
CREATE TABLE keys (
    id TEXT PRIMARY KEY,
    alias TEXT NOT NULL UNIQUE,
    key_type TEXT NOT NULL,           -- 'asymmetric' | 'symmetric' | 'secret'
    key_algorithm TEXT NOT NULL,
    public_key_pem TEXT,
    encrypted_private_key BLOB NOT NULL,
    labels TEXT,                      -- JSON object
    description TEXT,
    expires_at INTEGER,               -- Optional expiration (REQ-KS-007)
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    deleted_at INTEGER
);

-- SSH Keys (REQ-SSH-001)
CREATE TABLE ssh_keys (
    id TEXT PRIMARY KEY,
    key_id TEXT NOT NULL UNIQUE,
    key_format TEXT NOT NULL DEFAULT 'openssh',
    comment TEXT,
    passphrase_encrypted BOOLEAN DEFAULT FALSE,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (key_id) REFERENCES keys(id) ON DELETE CASCADE
);

-- Backup Codes (REQ-AUTH-002)
CREATE TABLE backup_codes (
    id TEXT PRIMARY KEY,
    code_hash TEXT NOT NULL,          -- Argon2id hash
    salt TEXT NOT NULL,               -- Per-code salt (base64)
    code_index INTEGER NOT NULL,      -- 1-8 for display
    used_at INTEGER,
    created_at INTEGER NOT NULL,
    UNIQUE (code_index)
);

-- Password History (REQ-PWD-003)
CREATE TABLE password_history (
    id TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,      -- Argon2id hash
    salt TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

-- Audit Log
CREATE TABLE audit_log (
    id TEXT PRIMARY KEY,
    timestamp INTEGER NOT NULL,
    operation TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id TEXT,
    actor TEXT NOT NULL,
    success BOOLEAN NOT NULL,
    details TEXT,
    error_message TEXT,
    hmac_chain TEXT NOT NULL          -- HMAC-SHA256 chain link (REQ-AUDIT-001)
);

-- Indexes
CREATE INDEX idx_certificates_ca_id ON certificates(ca_id, created_at);
CREATE INDEX idx_certificates_alias ON certificates(alias);
CREATE INDEX idx_keys_alias ON keys(alias);
CREATE INDEX idx_keys_type ON keys(key_type);
CREATE INDEX idx_ssh_keys_key_id ON ssh_keys(key_id);
CREATE INDEX idx_backup_codes_index ON backup_codes(code_index);
CREATE INDEX idx_audit_timestamp ON audit_log(timestamp);
CREATE INDEX idx_audit_entity ON audit_log(entity_type, entity_id);
CREATE INDEX idx_audit_operation ON audit_log(operation);
```

#### Backup Format (JSON) — Unchanged from v1.0

### 6.3 Configuration File (TOML) — Updated for v1.1.0

```toml
# XDG: ~/.config/rw-secstore/config.toml
# Legacy fallback: ~/.rw-secstore/config.toml

[database]
path = "~/.local/share/rw-secstore/db.sqlite"  # XDG data dir
wal_mode = true
foreign_keys = true
busy_timeout_ms = 5000

[encryption]
argon2_memory_kib = 65536      # 64 MB (minimum)
argon2_iterations = 3          # Minimum
argon2_parallelism = 4
aes_gcm_tag_length = 16

[password_policy]
min_length = 16
min_entropy_bits = 80
require_uppercase = true
require_lowercase = true
require_digits = true
require_symbols = true
max_consecutive_identical = 3
history_depth = 5
breach_check = "offline"       # "offline" | "online" | "disabled"
breach_check_cache_hours = 24

[ca]
default_key_profile = "rsa:4096"
default_digest = "sha256"
default_validity_days = 365
default_ca_validity_days = 3650
default_pathlen = 0

[certificate]
default_key_profile = "rsa:2048"
default_digest = "sha256"
default_validity_days = 365
default_key_usage = ["digitalSignature", "keyEncipherment"]
default_ext_key_usage = ["serverAuth", "clientAuth"]

[ssh]
default_key_type = "ed25519"
default_comment_format = "rw-secstore-{alias}@{hostname}"

[keyring]
enabled = false
backend = "auto"               # auto, libsecret, wincred, keychain
label = "rw-secstore-master-key"

[backup_codes]
count = 8
length = 16
charset = "base32"

[backup]
compress = false
include_audit_log = true

[audit]
enabled = true
max_entries = 100000
retention_days = 365

[cli]
output_format = "table"        # table, json, csv
color = true
pager = "auto"
unlock_methods_priority = ["keyring", "password", "backup-code"]
```

### 6.4 Dependencies (Updated for v1.1.0)

| Crate | Purpose | Version Policy |
|-------|---------|----------------|
| `rusqlite` | SQLite bindings | Latest stable (bundled) |
| `argon2` | Argon2id KDF | Latest stable |
| `aes-gcm` | AES-256-GCM | Latest stable |
| `chacha20poly1305` | ChaCha20-Poly1305 | Latest stable |
| `hkdf` | HKDF-SHA256 | Latest stable |
| `sha2` | SHA-2 family | Latest stable |
| `rcgen` | Certificate generation | Latest stable |
| `x509-parser` | Certificate parsing | Latest stable |
| `der-parser` | DER/ASN.1 parsing | Latest stable |
| `asn1-rs` | ASN.1 structures | Latest stable |
| `pem` | PEM encoding | Latest stable |
| `pkcs12` | PKCS#12 support | Latest stable |
| `ssh-key` | SSH key parsing/generation | Latest stable |
| `uuid` | UUID v7 generation | Latest stable with `v7` feature |
| `chrono` | Date/time | Latest stable |
| `clap` | CLI framework | Latest stable (derive API) |
| `clap_mangen` | Man page generation | Latest stable |
| `serde` + `serde_json` | Serialization | Latest stable |
| `toml` | Config parsing | Latest stable |
| `directories` | XDG paths | Latest stable |
| `zeroize` | Memory zeroization | Latest stable |
| `subtle` | Constant-time ops | Latest stable |
| `keyring` | OS keyring abstraction | Latest stable |
| `rpassword` | Secure password input | Latest stable |
| `zxcvbn` | Password strength estimation | Latest stable |
| `anyhow` | Error handling | Latest stable |
| `thiserror` | Error types | Latest stable |
| `tracing` + `tracing-subscriber` | Logging | Latest stable |
| `base64` | Base64 encoding | Latest stable |
| `hex` | Hex encoding | Latest stable |
| `indicatif` | Progress bars | Latest stable |
| `qrcode` | QR code generation | Latest stable |

---

## 7. Architecture Constraints

### 7.1 Architectural Patterns

1. **Single Binary**: All functionality in one executable
2. **Library + Binary**: Core logic in `lib.rs`, CLI in `main.rs`
3. **Module Per Domain**: `crypto`, `storage`, `ca`, `keystore`, `ssh`, `audit`, `auth`, `policy`, `cli`, `config`
4. **Connection Strategy**: Per-command connection (simple, no pooling for CLI)
5. **Error Handling**: `thiserror` for typed errors, `anyhow` for context
6. **Async Not Required**: Synchronous operations (CLI tool, no server)
7. **Key Hierarchy**: Master Password → KEK → DEK → Key Material (or MEK → DEK)
8. **Algorithm Agility**: Versioned crypto header for future migration

### 7.2 Technology Stack

- **Language**: Rust 2021 edition, MSRV 1.75
- **Database**: SQLite via `rusqlite` (bundled SQLite, no system dependency)
- **Crypto**: Pure Rust (`ring`/`aws-lc-rs` for primitives, `rcgen` for certs, `ssh-key` for SSH)
- **Serialization**: `serde` with `serde_json`, `toml`
- **CLI**: `clap` 4.x with derive macros
- **Keyring**: `keyring` crate (abstraction over libsecret/wincred/keychain)

### 7.3 Deployment Architecture

```
┌─────────────────────────────────────────┐
│         rw-secstore binary              │
├─────────────────────────────────────────┤
│  CLI Layer (clap)                       │
├─────────────────────────────────────────┤
│  Commands: ca, cert, key, ssh, pwgen,  │
│            backup, audit, config        │
├─────────────────────────────────────────┤
│  Core Services                          │
│  ├── KeystoreService                    │
│  ├── CAService                          │
│  ├── SshService                         │
│  ├── CryptoService                      │
│  ├── AuditService (with HMAC chain)     │
│  ├── AuthService (password/keyring/codes)│
│  ├── PolicyService (zxcvbn + HIBP)      │
│  └── BackupService                      │
├─────────────────────────────────────────┤
│  Storage Layer (rusqlite)               │
│  ├── Per-command connection             │
│  ├── Migrations (transactional)         │
│  └── Repositories                       │
├─────────────────────────────────────────┤
│  SQLite Database File (0o600)           │
└─────────────────────────────────────────┘
```

### 7.4 Data Architecture

- **Single Writer**: SQLite handles concurrency (WAL mode)
- **Schema Evolution**: Additive migrations only (no column drops), with rollback tested
- **Encryption Boundary**: Application-level (not transparent DB encryption)
- **Key Hierarchy**:
  - Password mode: Master Password → Argon2id → KEK → DEK (per entry, via HKDF) → Key Material
  - Keyring mode: MEK (256-bit random) → DEK → Key Material
  - Backup code mode: Backup Code → Argon2id → MEK recovery
- **File Permissions**: DB 0o600, parent dir 0o700, password files 0o600

### 7.5 Workspace Structure (4 crates)

```
rw-secstore/
├── Cargo.toml                  # Workspace
├── crates/
│   ├── core/                   # Domain logic (no CLI)
│   │   ├── Cargo.toml
│   │   └── src/
│   ├── cli/                    # CLI binary
│   │   ├── Cargo.toml
│   │   └── src/
│   ├── crypto/                 # Reusable crypto primitives
│   │   ├── Cargo.toml
│   │   └── src/
│   └── storage/                # SQLite + migrations
│       ├── Cargo.toml
│       └── src/
```

---

## 8. Acceptance Criteria

### 8.1 Test Scenarios

| Scenario | Description |
|----------|-------------|
| **TC-001** | Initialize new keystore, verify schema version |
| **TC-002** | Unlock with correct password, fail with incorrect |
| **TC-003** | Store/retrieve secret, verify encryption at rest |
| **TC-004** | Generate RSA/ECDSA/Ed25519 key pairs |
| **TC-005** | Import existing PEM key pair |
| **TC-006** | Create root CA, verify self-signed |
| **TC-007** | Create intermediate CA, verify chain |
| **TC-008** | Issue leaf certificate, verify signature chain |
| **TC-009** | Revoke certificate, verify CRL contains it |
| **TC-010** | Renew certificate, verify old revoked, new valid |
| **TC-011** | Export/import CA as PKCS#12 |
| **TC-012** | Backup/restore round-trip |
| **TC-013** | Change master password, verify re-encryption |
| **TC-014** | Soft delete + purge workflow |
| **TC-015** | Audit log captures all mutating operations with HMAC chain |
| **TC-016** | Key comparison (match/mismatch) |
| **TC-017** | Signature verification with stored public key |
| **TC-018** | Concurrent access (multiple processes) |
| **TC-019** | Schema migration from v1 to v2 to v3 + rollback |
| **TC-020** | Large keystore (10k entries) performance |
| **TC-021** | SSH key generation (ed25519, rsa, ecdsa) and export |
| **TC-022** | SSH key passphrase generation and storage |
| **TC-023** | Password policy enforcement (min length, entropy, chars) |
| **TC-024** | Password generator (charset + diceware) |
| **TC-025** | Master password file (read + export) with 0o600 |
| **TC-026** | OS keyring unlock (libsecret/wincred/keychain) |
| **TC-027** | Backup code generation and single-use unlock |
| **TC-028** | Database HMAC seal integrity check |
| **TC-029** | Constant-time password comparison (no timing leak) |
| **TC-030** | Zeroize memory on lock and signal |
| **TC-031** | Migration rollback on failure |
| **TC-032** | Property tests: HKDF context separation, nonce uniqueness |
| **TC-033** | Fuzz tests: DB parse, cert parse, ASN.1, password |

### 8.2 Success Criteria

- All functional requirements implemented and tested
- Zero critical/high vulnerabilities in `cargo audit`
- Zero high/critical findings in `cargo deny`
- Binary size < 50MB (striped, musl)
- All acceptance criteria tests pass (TC-001 through TC-033)
- Documentation complete (README, man pages, --help)
- Test coverage: ≥85% line, ≥95% crypto module
- Property tests pass: 6+ crypto invariants
- Fuzz tests run clean: 0 crashes in 1M iterations
- All Phase gate criteria met

### 8.3 Non-Functional Test Requirements

- **Security**: `cargo audit`, `cargo deny`, fuzzing on parsers (1M+ iterations)
- **Performance**: Benchmarks for all REQ-PERF targets
- **Compatibility**: Test on Linux, macOS, Windows
- **Stress**: 100k entries, concurrent operations
- **Penetration**: External pen test before v1.0 release

---

## 9. Open Issues

| Issue | Impact | Owner | Due Date |
|-------|--------|-------|----------|
| **OI-001**: Network/daemon mode for remote access | Blocks multi-user, API use cases | TBD | v2.0 |
| **OI-002**: HSM/PKCS#11 integration | Required for FIPS 140-3 Level 2+ | TBD | v2.0 |
| **OI-003**: SSH key provisioning automation | Fleet management blocker | TBD | v1.1 |
| **OI-004**: OpenSSH certificate support | SSH CA use case | TBD | v1.1 |
| **OI-005**: FIDO2/WebAuthn hardware unlock | High-security unlock | TBD | v1.1 |
| **OI-006**: SSH agent integration | Developer UX | TBD | v1.2 |
| **OI-007**: known_hosts management | Operational hygiene | TBD | v1.2 |
| **OI-008**: Automatic certificate renewal (ACME) | Operational convenience | TBD | v2.0 |
| **OI-009**: Key rotation policies | Compliance requirement | TBD | v1.1 |
| **OI-010**: Windows DPAPI integration for password storage | UX improvement | TBD | v1.1 |
| **OI-011**: Database encryption at rest (SQLCipher/libSQL) | Defense in depth | TBD | v1.2 |
| **OI-012**: mlock for master key in RAM (always) | Memory protection | TBD | v1.1 |

---

## 10. Appendix

### 10.1 References

1. **minica** (wushilin/minica) - SQLite CA implementation reference
2. **DeTLS** (polyjuicelab/DeTLS) - Encrypted keystore reference
3. **db-keystore** (stevelr/db-keystore) - SQLite keystore patterns
4. **RFC 5280** - X.509 Certificate Profile
5. **RFC 9106** - Argon2 Memory-Hard Function
6. **RFC 9562** - UUID Version 7
7. **NIST SP 800-57** - Key Management Recommendations
8. **FIPS 140-3** - Cryptographic Module Validation
9. **RFC 5869** - HKDF (HMAC-based Extract-and-Expand Key Derivation Function)
10. **NIST SP 800-63B** - Digital Identity Guidelines (password policy)
11. **EFF Diceware Wordlist** - https://www.eff.org/diceware
12. **HaveIBeenPwned API** - https://haveibeenpwned.com/API/v3
13. **OpenSSH Key Format** - https://github.com/openssh/openssh-portable
14. **WebAuthn/FIDO2** - https://www.w3.org/TR/webauthn-2/

### 10.2 Change Log

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | 2026-08-28 | ForgeCode | Initial specification |
| 1.1.0 | 2026-08-29 | ForgeCode | Added SSH key management, password policy/generator, keyring, backup codes; updated scope, requirements, schema, config, dependencies; added 12 new requirements, 5 new ADRs, 13 new test scenarios |

### 10.3 Approval Signatures

| Role | Name | Signature | Date |
|------|------|-----------|------|
| Product Owner | | | |
| Architect | | | |
| Security Lead | | |
| QA Lead | | | |
| Stakeholder Representative | | | |

---

## Specification Quality Checklist

- [x] Each requirement is one observable behavior with SHALL/MUST
- [x] No implementation details are baked into requirements
- [x] Every requirement has at least one testable scenario
- [x] Important edge and error cases have scenarios
- [x] Uses RFC 2119 keywords correctly (MUST, SHOULD, MAY)
- [x] Avoids vague terms like "should be fast" or "user-friendly"
- [x] Specifies outcomes and constraints, not implementation steps
- [x] Includes measurable, quantifiable acceptance criteria
- [x] Addresses security, performance, and usability considerations
- [x] Clear distinction between in-scope and out-of-scope items
- [x] Assumptions and constraints are explicitly stated
- [x] Threat model explicitly stated (Level 2 Zero-Knowledge Formal)
- [x] Password policy and generator included
- [x] Multi-factor unlock specified (password + keyring + backup codes)
- [x] SSH key management included
- [x] Algorithm agility via versioned crypto header
- [x] All security requirements trace to threat model

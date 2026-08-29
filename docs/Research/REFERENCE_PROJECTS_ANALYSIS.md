# Reference Projects Analysis for rw_secStore

## Overview
This document analyzes three reference projects cloned to `~/.references/` to inform the design of rw_secStore - a minimal certificate authority and secure keystore using SQLite.

---

## 1. minica (wushilin/minica) - **Primary Reference**

**Type**: Full-featured Certificate Authority Server (Rust + SQLite + OpenSSL)
**Location**: `~/.references/minica/`

### Key Architectural Decisions

#### Database Schema (SQLite)
- **Tables**: `certificate_authorities`, `certificates`, `ca_locks`, `users`, `schema_version`
- **Soft deletes**: `deleted` boolean column on all entities
- **Schema versioning**: Dedicated `schema_version` table with migration support
- **Indexes**: 
  - `idx_certificates_ca_id` on `(ca_id, created_at)` for CA-scoped queries
  - `idx_certificates_trash` partial index on `updated_at WHERE deleted = 1`
- **Foreign keys**: Enabled with `ON DELETE CASCADE` for certificates → CAs

#### CA Entity Model
```rust
struct CaMeta {
    id: String,                    // 12-char alphanumeric
    common_name: String,           // X.509 CN
    country_code, state, city, organization, organization_unit: String,
    subject: String,               // Full DN
    issue_time: i64,               // Unix timestamp (ms)
    valid_days: i64,
    key_profile: String,           // "rsa:2048", "ecdsa:prime256v1"
    digest_algorithm: String,      // "sha256"
}
```

#### Secrets Storage (Encrypted in DB)
```rust
struct CaSecrets {
    cert_pem: Vec<u8>,      // CA certificate
    key_pem: Vec<u8>,       // CA private key (encrypted)
    pkcs12: Vec<u8>,        // PKCS#12 bundle
    password: Vec<u8>,      // Key password
    index_txt: Vec<u8>,     // OpenSSL index.txt (serial tracking)
    serial_txt: Vec<u8>,    // OpenSSL serial.txt
    crl_der: Vec<u8>,       // CRL in DER format
    crl_updated_at: i64,
}
```

#### Certificate Entity Model
```rust
struct CertMeta {
    id: String,
    ca_id: String,              // FK to CA
    common_name: String,
    // ... same DN fields as CA ...
    dns_list: Vec<String>,      // SAN DNS names
    ip_list: Vec<String>,       // SAN IP addresses
    key_profile: String,
    digest_algorithm: String,
    revoked_at: Option<i64>,
    revocation_reason: Option<String>,
}
```

#### Key Features for rw_secStore
1. **Locking mechanism**: `ca_locks` table with TTL for concurrent signing operations
2. **Backup/Restore**: Full YAML export/import with schema version tracking
3. **Migration system**: Pre-migration backup, schema version checking, ALTER TABLE for additions
4. **WAL mode**: SQLite WAL for better concurrency
5. **Key profiles**: Support for RSA (2048/4096) and ECDSA (prime256v1)
6. **CRL management**: Automatic CRL generation and storage
7. **Soft deletes**: Trash/restore functionality

---

## 2. DeTLS (polyjuicelab/DeTLS) - **Keystore Reference**

**Type**: TLS library with encrypted keystore (Rust + JSON file storage)
**Location**: `~/.references/DeTLS/`

### Key Architectural Decisions

#### Keystore Format (JSON file)
```rust
struct KeyStore {
    path: PathBuf,
    keys: HashMap<String, KeyMetadata>,
}

struct KeyMetadata {
    alias: String,
    public_key_hex: String,
    encrypted_key: Vec<u8>,     // [salt(32)][nonce(12)][ciphertext]
    created_at: DateTime<Utc>,
}
```

#### Encryption (AES-256-GCM + Argon2id)
```rust
// Format: [salt(32)][nonce(12)][ciphertext+tag]
const SALT_LENGTH: usize = 32;
const NONCE_LENGTH: usize = 12;

// Argon2id for key derivation
fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32]>

// AES-256-GCM for encryption
fn encrypt_private_key(key: &[u8], password: &str) -> Result<Vec<u8>>
fn decrypt_private_key(encrypted: &[u8], password: &str) -> Result<Vec<u8>>
```

#### Key Features for rw_secStore
1. **Password-based encryption**: Argon2id + AES-GCM (industry standard)
2. **Per-key encryption**: Each key encrypted independently with unique salt/nonce
3. **Metadata separation**: Public key info stored in plaintext, private key encrypted
4. **Simple CRUD**: import, export, get, list, delete operations
5. **Persistence**: JSON file with atomic writes

---

## 3. db-keystore (stevelr/db-keystore) - **SQLite Keystore Reference**

**Type**: SQLite-backed credential store implementing keyring-core traits (Rust + Turso/libSQL)
**Location**: `~/.references/db-keystore/`

### Key Architectural Decisions

#### Database Schema
```sql
CREATE TABLE credentials (
    service TEXT NOT NULL,
    user TEXT NOT NULL,
    uuid TEXT NOT NULL,           -- UUID v7 (time-sortable)
    secret BLOB NOT NULL,         -- Encrypted secret
    comment TEXT
);

CREATE TABLE keystore_meta (
    key TEXT NOT NULL PRIMARY KEY,
    value TEXT NOT NULL
);

-- Unique index when allow_ambiguity=false
CREATE UNIQUE INDEX uidx_credentials_service_user ON credentials (service, user);

-- Optional performance index
CREATE INDEX idx_credentials_service_user ON credentials (service, user);
```

#### Encryption Options (Turso/libSQL native)
- **Ciphers**: `aegis256`, `aes256gcm`, `aegis128l`, `aes128gcm`
- **Key management**: Hex-encoded keys stored in `Zeroizing` buffers
- **Per-database encryption**: Whole database encrypted at rest

#### Concurrency Model
- **File backend**: Reopens DB per operation, releases lock immediately
- **WAL mode**: `PRAGMA journal_mode=WAL`
- **Busy timeout**: 5000ms with exponential backoff retry
- **Checkpoint on close**: `PRAGMA wal_checkpoint(TRUNCATE)` to prevent WAL issues across processes

#### Key Features for rw_secStore
1. **Multi-process safe**: File lock released between operations
2. **UUID v7**: Time-sortable identifiers
3. **Flexible uniqueness**: `allow_ambiguity` flag for multiple credentials per (service,user)
4. **Regex search**: Service/user/uuid/comment regex filtering
5. **Rekey support**: Verified out-of-place DEK rotation
6. **Zeroize**: Secrets wiped from memory on drop

---

## Synthesis: Design Recommendations for rw_secStore

### 1. Storage Backend: SQLite (like minica + db-keystore)
- Single file, portable, ACID, supports WAL for concurrency
- Schema versioning from day one
- Soft deletes for audit trail

### 2. Encryption: Application-level (like DeTLS) + Optional DB-level (like db-keystore)
- **Per-key encryption**: Argon2id + AES-256-GCM (DeTLS pattern)
- **Format**: `[salt(32)][nonce(12)][ciphertext+tag]`
- **Optional**: Turso/libSQL native encryption for whole DB

### 3. Entity Model: CA + Certificates + Generic Secrets
```rust
// Core entities
enum KeyType {
    CaRoot,           // CA root certificate + key
    CaIntermediate,   // Intermediate CA
    Certificate,      // Leaf certificate
    SymmetricKey,     // AES/HMAC keys
    AsymmetricKey,    // RSA/ECDSA/Ed25519 key pairs
    Secret,           // Generic secrets (API keys, passwords)
}

struct KeyEntry {
    id: String,                    // UUID v7
    key_type: KeyType,
    alias: String,                 // Human-readable name
    labels: HashMap<String, String>, // Flexible metadata
    // Type-specific fields...
    public_key: Option<Vec<u8>>,   // For asymmetric
    encrypted_private: Vec<u8>,    // Encrypted with master password
    created_at: i64,
    updated_at: i64,
    deleted_at: Option<i64>,
    revoked_at: Option<i64>,
    revocation_reason: Option<String>,
}
```

### 4. CA Operations (from minica)
- Create CA (root/intermediate)
- Issue certificates
- Revoke certificates
- Generate CRL
- Renew certificates
- Import/Export CA
- Backup/Restore entire keystore

### 5. Keystore Operations (from DeTLS + db-keystore)
- Store/retrieve keys by alias
- List keys with filtering
- Compare keys (fingerprint matching)
- Verify key authenticity (signature verification)
- Redact/delete keys (soft + hard)
- Search by metadata/regex

### 6. Security Features
- Master password for keystore unlock
- Per-key encryption (different passwords optional)
- Argon2id with configurable parameters
- Constant-time comparisons
- Zeroize secrets on drop
- Audit logging for all operations

### 7. CLI Interface
```
rw-secstore init [--path PATH] [--cipher CIPHER]
rw-secstore ca create <alias> [--type root|intermediate] [--profile PROFILE]
rw-secstore ca list
rw-secstore ca show <alias>
rw-secstore ca import <alias> <cert.pem> <key.pem>
rw-secstore ca export <alias> [--format pem|pkcs12]
rw-secstore ca delete <alias>
rw-secstore cert issue <ca-alias> <cn> [--san DNS:...,IP:...] [--profile PROFILE]
rw-secstore cert revoke <ca-alias> <cert-alias> [--reason REASON]
rw-secstore cert renew <ca-alias> <cert-alias> [--days DAYS]
rw-secstore cert list [--ca CA_ALIAS]
rw-secstore key store <alias> [--type TYPE] [--value VALUE|--file FILE]
rw-secstore key get <alias>
rw-secstore key list [--type TYPE]
rw-secstore key compare <alias1> <alias2>
rw-secstore key verify <alias> [--signature SIG] [--data DATA]
rw-secstore key delete <alias>
rw-secstore backup [--output FILE]
rw-secstore restore <backup-file>
rw-secstore audit [--since TIMESTAMP]
```

---

## Implementation Priority

### Phase 1: Core Infrastructure
1. SQLite schema with migrations
2. Encryption module (Argon2id + AES-GCM)
3. Basic keystore CRUD (store, get, list, delete)
4. CLI framework with subcommands

### Phase 2: CA Operations
1. CA creation (root/intermediate)
2. Certificate issuance
3. Certificate listing/retrieval
4. Revocation + CRL

### Phase 3: Advanced Features
1. Key comparison/verification
2. Backup/Restore
3. Audit logging
4. Import/Export (PEM, PKCS#12)

### Phase 4: Polish
1. Configuration file support
2. Shell completions
3. Man pages
4. Integration tests
# Feature Extension Analysis: SSH Key Management + Enhanced Auth

**Analysis ID**: FEA-2026-001
**Date**: 2026-08-29
**Analyst**: ForgeCode
**Current SPEC**: SPEC-2026-001 v1.0.0
**Current Plan**: PLAN-2026-001 v2.0 (HIGH mode)

---

## Executive Summary

| Feature | Current SPEC Coverage | Effort to Add | Priority | Recommended Phase |
|---------|----------------------|---------------|----------|-------------------|
| **1. SSH Key Store/Provisioning** | ❌ Not covered | +16h | HIGH | Phase 2 (Keystore) |
| **2. Password Policy Enforcement** | ❌ Not covered | +6h | HIGH | Phase 1 (Foundation) |
| **3. High-Security Password Generator** | ❌ Not covered | +4h | MEDIUM | Phase 1 (Foundation) |
| **4. Master Password from File** | ✅ Partial (`--password-file`) | +2h | HIGH | Phase 1 (Foundation) |
| **5. Encryption Key in Keyring + Backup Codes** | ❌ Not covered | +20h | HIGH | Phase 3 (CA) / Phase 4 |

**Total Additional Effort**: ~48h (bringing total from 188h → **236h**)

---

## Detailed Analysis by Feature

---

### 1. SSH Key Store & Provisioning

#### Current SPEC Gap
- **REQ-KS-002** covers asymmetric keys (RSA/ECDSA/Ed25519) but **no SSH-specific handling**
- No SSH key format support (OpenSSH private key format, authorized_keys, known_hosts)
- No provisioning/deployment automation
- No SSH certificate support (OpenSSH certificates)

#### Required Additions

**New Functional Requirements:**

```markdown
### 4.3.x SSH Key Management

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

**REQ-SSH-002**: The system SHALL export SSH keys in standard formats.
- **Given**: SSH key alias
- **When**: `ssh export <alias> --format openssh|pem|pkcs8` executed
- **Then**: Key exported in requested format
- **Acceptance Criteria**:
  - OpenSSH private key format (default)
  - PKCS#8 PEM format (for interop)
  - Public key in authorized_keys format
  - Optional: encrypt export with separate password

**REQ-SSH-003**: The system SHALL provision SSH keys to remote hosts.
- **Given**: SSH key alias, target host(s), username, optional port
- **When**: `ssh provision <alias> --host user@host --host user@host2` executed
- **Then**: Public key appended to `~/.ssh/authorized_keys` on each target
- **Acceptance Criteria**:
  - SSH connection via system SSH client (ssh command)
  - Idempotent: key only added once (check fingerprint)
  - Supports SSH config aliases
  - Dry-run mode (`--dry-run`)
  - Parallel provisioning with progress
  - Rollback on partial failure (remove keys added)

**REQ-SSH-004**: The system SHALL manage SSH certificates (OpenSSH certificate format).
- **Given**: CA alias (SSH CA), key alias, principals, validity
- **When**: `ssh cert-issue <ca-alias> <key-alias> --principal user@host` executed
- **Then**: OpenSSH certificate generated and stored
- **Acceptance Criteria**:
  - User and host certificates
  - Principals: user@host, hostnames, IPs
  - Validity interval (start/end)
  - Critical options: force-command, source-address, no-port-forwarding, etc.
  - Extensions: permit-X11-forwarding, permit-agent-forwarding, etc.
  - Certificate stored alongside key pair

**REQ-SSH-005**: The system SHALL manage known_hosts entries.
- **Given**: Hostname, public key/fingerprint
- **When**: `ssh known-hosts add <host> --key <alias>` executed
- **Then**: Entry added to managed known_hosts database
- **Acceptance Criteria**:
  - Store: hostname, key type, public key, fingerprint, added_at
  - Verify: `ssh known-hosts verify <host>` checks against stored
  - Export: `ssh known-hosts export` → OpenSSH known_hosts format
  - TOFU (Trust On First Use) support

**REQ-SSH-006**: The system SHALL support SSH agent integration.
- **Given**: Unlocked keystore with SSH keys
- **When**: `ssh agent` executed
- **Then**: Keys added to running ssh-agent (via `ssh-add`)
- **Acceptance Criteria**:
  - Add all or filtered SSH keys to agent
  - Remove keys from agent
  - List keys in agent with source tracking
  - Lifetime option for agent keys
```

#### Database Schema Additions

```sql
-- SSH Keys (extends keys table with SSH-specific fields)
CREATE TABLE ssh_keys (
    id TEXT PRIMARY KEY,              -- UUID v7
    key_id TEXT NOT NULL UNIQUE,      -- FK to keys.id
    key_format TEXT NOT NULL DEFAULT 'openssh',  -- 'openssh', 'pkcs8', 'pem'
    comment TEXT,                     -- user@host
    passphrase_encrypted BOOLEAN DEFAULT FALSE,  -- Additional passphrase on SSH key
    created_at INTEGER NOT NULL,
    FOREIGN KEY (key_id) REFERENCES keys(id) ON DELETE CASCADE
);

-- SSH Certificates
CREATE TABLE ssh_certificates (
    id TEXT PRIMARY KEY,              -- UUID v7
    ca_id TEXT NOT NULL,              -- FK to certificate_authorities.id (type=ssh_ca)
    key_id TEXT NOT NULL,             -- FK to keys.id
    cert_type TEXT NOT NULL,          -- 'user' | 'host'
    principals TEXT NOT NULL,         -- JSON array: ["user@host", "hostname"]
    valid_after INTEGER NOT NULL,     -- Unix timestamp ms
    valid_before INTEGER NOT NULL,    -- Unix timestamp ms
    critical_options TEXT,            -- JSON object
    extensions TEXT,                  -- JSON object
    serial_number TEXT NOT NULL,      -- Hex string
    cert_blob BLOB NOT NULL,          -- OpenSSH certificate binary
    created_at INTEGER NOT NULL,
    revoked_at INTEGER,
    revocation_reason TEXT,
    FOREIGN KEY (ca_id) REFERENCES certificate_authorities(id),
    FOREIGN KEY (key_id) REFERENCES keys(id)
);

-- Known Hosts
CREATE TABLE known_hosts (
    id TEXT PRIMARY KEY,              -- UUID v7
    hostname TEXT NOT NULL,
    key_type TEXT NOT NULL,           -- 'ssh-ed25519', 'ssh-rsa', 'ecdsa-sha2-nistp256'
    public_key BLOB NOT NULL,         -- Raw public key bytes
    fingerprint_sha256 TEXT NOT NULL, -- SHA-256 fingerprint
    source TEXT NOT NULL,             -- 'manual', 'scan', 'provision'
    added_at INTEGER NOT NULL,
    verified_at INTEGER,
    UNIQUE (hostname, fingerprint_sha256)
);

-- SSH CA (extends certificate_authorities with ca_type='ssh_ca')
-- Add to certificate_authorities:
-- ca_type: 'root' | 'intermediate' | 'ssh_ca'
-- For ssh_ca: key_profile must be ed25519 or rsa
```

#### CLI Additions

```
ssh store           Store/generate SSH key pair
ssh get             Retrieve SSH key (public or private with --reveal)
ssh list            List SSH keys
ssh export          Export SSH key (openssh, pem, pkcs8)
ssh provision       Provision public key to remote hosts
ssh cert-issue      Issue OpenSSH certificate
ssh cert-list       List SSH certificates
ssh cert-revoke     Revoke SSH certificate
ssh known-hosts     Manage known_hosts (add, verify, export, scan)
ssh agent           Manage ssh-agent integration
```

#### Implementation Effort: ~16h
- Phase 2.1: SSH key type + storage (3h)
- Phase 2.2: SSH export/import (2h)
- Phase 2.3: Provisioning engine (4h)
- Phase 3.x: SSH CA + certificates (4h)
- Phase 2.x: known_hosts + agent (3h)

---

### 2. Password Policy Enforcement

#### Current SPEC Gap
- **REQ-CRYPTO-001** derives KEK from master password but **no policy enforcement**
- No minimum length, complexity, entropy requirements
- No breach checking (HaveIBeenPwned)
- No password history / reuse prevention

#### Required Additions

**New Functional Requirements:**

```markdown
### 4.2.x Password Policy

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
  - Policy stored in keystore_meta, enforced on init/rekey

**REQ-PWD-002**: The system SHALL check passwords against known breaches.
- **Given**: Password to validate
- **When**: Password policy check runs
- **Then**: Password checked against HaveIBeenPwned API (k-anonymity)
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
```

#### Configuration Additions

```toml
[password_policy]
min_length = 16
min_entropy_bits = 80
require_uppercase = true
require_lowercase = true
require_digits = true
require_symbols = true
max_consecutive_identical = 3
history_depth = 5
breach_check = "offline"  # "offline" | "online" | "disabled"
breach_check_cache_hours = 24
```

#### Implementation Effort: ~6h
- Phase 1.3: zxcvbn integration + policy engine (3h)
- Phase 1.3: HIBP offline list + online API (2h)
- Phase 1.3: Password history on rekey (1h)

---

### 3. High-Security Password Generator

#### Current SPEC Gap
- No password generation capability
- User must provide own master password

#### Required Additions

**New Functional Requirements:**

```markdown
### 4.2.x Password Generation

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
  - Output: plaintext (stdout) or `--output-file` (with permissions 0600)

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

**REQ-PWG-003**: The system SHALL support password generation for SSH keys.
- **Given**: SSH key generation request
- **When**: `ssh store --generate-passphrase` executed
- **Then**: High-entropy passphrase generated for SSH key
- **Acceptance Criteria**:
  - Separate from master password
  - Stored encrypted with master password
  - Displayed once on generation (with `--reveal`)
  - Diceware default for memorability
```

#### CLI Additions

```
pwgen               Generate secure password/passphrase
pwgen --check       Check password strength (zxcvbn)
pwgen --diceware    Generate diceware passphrase
pwgen --policy      Generate policy-compliant password
```

#### Implementation Effort: ~4h
- Phase 1.3: Core generator (OSRNG + charset) (1h)
- Phase 1.3: Diceware + EFF wordlist (2h)
- Phase 1.3: Policy-aware generation (1h)

---

### 4. Master Password from File (Enhanced)

#### Current SPEC Status
- **CLI Global Options** already includes `--password-file PATH` (line 433)
- But: **no secure handling, no export, no generation integration**

#### Required Enhancements

```markdown
### 4.2.x Master Password File Handling

**REQ-PWD-005**: The system SHALL securely read master password from file.
- **Given**: File path with master password
- **When**: `--password-file /path/to/password` used
- **Then**: Password read securely, trailing newline stripped, file permissions validated
- **Acceptance Criteria**:
  - File MUST be 0600 or 0400 (reject world-readable)
  - Read entire file, strip single trailing newline only
  - Support `--password-file -` for stdin (with TTY check)
  - Clear error if permissions too open

**REQ-PWD-006**: The system SHALL export master password to file securely.
- **Given**: Unlocked keystore, target file path
- **When**: `config export-password --output /path/to/password` executed
- **Then**: Master password written to file with 0600 permissions
- **Acceptance Criteria**:
  - File created with 0600 (owner read/write only)
  - Parent directory created with 0700 if needed
  - Warning: "This file contains your master password. Protect it."
  - Optional: `--format json` with metadata (created_at, policy_version)
  - Confirmation required unless `--yes`

**REQ-PWG-004**: The system SHALL generate master password and export to file in one command.
- **Given**: Generation parameters, output path
- **When**: `init --generate-password --password-file /path/to/password` executed
- **Then**: Keystore initialized with generated password, password written to file
- **Acceptance Criteria**:
  - Single atomic operation
  - Password generated per policy
  - File written with 0600
  - Password displayed once (unless `--quiet`)
  - QR code option for mobile transfer (`--qr`)
```

#### Implementation Effort: ~2h (enhancement to existing)
- Phase 1.4: Permission validation + secure read (1h)
- Phase 1.4: Export command + atomic init integration (1h)

---

### 5. Encryption Key in Keyring + Backup Codes

#### Current SPEC Gap
- **Single master password only** (Assumption 2.3.5)
- No alternative unlock methods
- No recovery mechanism for lost password
- No OS keyring integration

#### Required Additions

**New Functional Requirements:**

```markdown
### 4.2.x Multi-Factor Unlock & Recovery

**REQ-AUTH-001**: The system SHALL support OS keyring as encryption key source.
- **Given**: Configured keyring backend (libsecret, Windows Credential Manager, macOS Keychain)
- **When**: `init --keyring` or `config set keyring.enabled true` executed
- **Then**: Master encryption key generated, stored in OS keyring, password becomes optional
- **Acceptance Criteria**:
  - Generate 256-bit master key (not password-derived)
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
  - Codes encrypt master key (or KEK) via separate Argon2id derivation
  - Stored in `backup_codes` table (encrypted, not plaintext)
  - Display once with warning: "Save these codes. They cannot be shown again."
  - `config backup-codes list` shows used/unused (not the codes themselves)
  - `config backup-codes regenerate` invalidates old, creates new

**REQ-AUTH-003**: The system SHALL unlock with backup code.
- **Given**: Locked keystore, valid unused backup code
- **When**: `unlock --backup-code ABCD-EFGH-IJKL-MNOP` executed
- **Then**: Keystore unlocked, backup code marked consumed
- **Acceptance Criteria**:
  - Code verified via Argon2id (separate salt, same params)
  - On success: decrypt master key → decrypt DEKs
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

**REQ-AUTH-005**: The system SHALL support hardware security keys (FIDO2/WebAuthn) for unlock.
- **Given**: Registered FIDO2 credential
- **When**: `unlock --fido2` executed
- **Then**: WebAuthn assertion requested, verified, used to decrypt master key
- **Acceptance Criteria**:
  - Register: `config fido2 register` (CTAP2, resident key)
  - Unlock: `unlock --fido2` (platform or roaming authenticator)
  - Credential ID stored, public key stored
  - Master key encrypted with credential-derived key
  - Optional: user verification required (UV)
  - Post-v1: defer to v1.1 (complexity)
```

#### Database Schema Additions

```sql
-- Backup Codes
CREATE TABLE backup_codes (
    id TEXT PRIMARY KEY,              -- UUID v7
    code_hash TEXT NOT NULL,          -- Argon2id hash of code
    salt TEXT NOT NULL,               -- Per-code salt (base64)
    code_index INTEGER NOT NULL,      -- 1-8 for display
    used_at INTEGER,                  -- Null if unused
    created_at INTEGER NOT NULL,
    UNIQUE (code_index)
);

-- Keyring / FIDO2 Metadata (in keystore_meta)
-- keyring_enabled = "true|false"
-- keyring_backend = "libsecret|wincred|keychain"
-- master_key_id = "keyring entry name"
-- fido2_credential_id = "base64..."
-- fido2_public_key = "base64..."
-- unlock_methods_priority = "keyring,password,backup-code,fido2"
```

#### CLI Additions

```
config keyring enable           Enable OS keyring unlock
config keyring disable          Disable OS keyring unlock
config keyring status           Show keyring status
config backup-codes generate    Generate backup codes
config backup-codes list        List backup code status (used/unused)
config backup-codes regenerate  Regenerate backup codes
config fido2 register           Register FIDO2 credential (v1.1)
config fido2 list               List registered credentials
unlock --method keyring|password|backup-code|fido2
unlock --backup-code CODE       Unlock with backup code
```

#### Implementation Effort: ~20h
- Phase 1.4: Keyring abstraction + backends (6h)
- Phase 1.4: Backup codes generation + storage (4h)
- Phase 1.4: Backup code unlock flow (3h)
- Phase 3.x: FIDO2/WebAuthn (defer to v1.1, 7h)

---

## Integrated SPEC Impact

### New Tables Added
| Table | Purpose | Rows (Typical) |
|-------|---------|----------------|
| `ssh_keys` | SSH-specific key metadata | 10-1000 |
| `ssh_certificates` | OpenSSH certificates | 10-500 |
| `known_hosts` | SSH known_hosts management | 50-5000 |
| `backup_codes` | Emergency recovery codes | 8 |

### New CLI Commands
| Command Group | Commands |
|---------------|----------|
| `ssh` | store, get, list, export, provision, cert-issue, cert-list, cert-revoke, known-hosts, agent |
| `pwgen` | generate, check, diceware |
| `config` | keyring, backup-codes, fido2 (v1.1) |
| `unlock` | --method, --backup-code, --fido2 |

### New Configuration Sections
```toml
[password_policy]
# ... (see above)

[ssh]
default_key_type = "ed25519"
default_comment_format = "rw-secstore-{alias}@{hostname}"
provision_parallel = 4
provision_timeout_sec = 30
known_hosts_path = "~/.ssh/known_hosts"

[keyring]
enabled = false
backend = "auto"  # auto, libsecret, wincred, keychain
label = "rw-secstore-master-key"

[backup_codes]
count = 8
length = 16
charset = "base32"

[fido2]  # v1.1
enabled = false
require_uv = true
```

---

## Updated Plan v2.1 — Phase Adjustments

### Phase 1: Foundation (42h → **54h**, +12h)
| New Task | Description | Hours |
|----------|-------------|-------|
| 1.3.5 | Password policy engine (zxcvbn + HIBP) | 3h |
| 1.3.6 | Password generator (charset + diceware) | 2h |
| 1.4.2 | Password file secure read/export | 1h |
| 1.4.3 | Keyring abstraction (libsecret/wincred/keychain) | 4h |
| 1.4.4 | Backup codes generation + unlock | 2h |

### Phase 2: Keystore Core (38h → **54h**, +16h)
| New Task | Description | Hours |
|----------|-------------|-------|
| 2.1.2 | SSH key type + OpenSSH format | 3h |
| 2.2.2 | SSH export/import (openssh, pem, pkcs8) | 2h |
| 2.3.2 | SSH provisioning engine | 4h |
| 2.4.2 | known_hosts management | 2h |
| 2.5.2 | SSH agent integration | 2h |
| 2.6.2 | Password policy enforcement on init/rekey | 1h |
| 2.7.2 | Password generator integration | 1h |
| 2.8.2 | Keyring unlock + backup code unlock | 1h |

### Phase 3: CA Operations (48h → **52h**, +4h)
| New Task | Description | Hours |
|----------|-------------|-------|
| 3.5.6 | SSH CA type + certificate issuance | 4h |

### Phase 4: Advanced Features (28h → **28h**, no change)
- Backup codes already in Phase 1.4.4

### Phase 5: Polish (32h → **38h**, +6h)
| New Task | Description | Hours |
|----------|-------------|-------|
| 5.3.2 | SSH provisioning Windows compat | 2h |
| 5.6.2 | Keyring backend testing (Linux/macOS/Windows) | 2h |
| 5.7.2 | SSH/docs for new features | 2h |

---

## Feasibility Assessment

| Feature | Feasibility | Risk | Recommendation |
|---------|-------------|------|----------------|
| **SSH Key Store** | ✅ High | Low | Core feature, well-understood formats |
| **Password Policy** | ✅ High | Low | zxcvbn crate exists, HIBP API simple |
| **Password Generator** | ✅ High | Low | Pure Rust, no external deps |
| **Password File** | ✅ High | Low | Enhancement to existing `--password-file` |
| **Keyring + Backup Codes** | ✅ Medium | Medium | Keyring backends vary; backup codes well-understood |
| **FIDO2/WebAuthn** | ⚠️ Medium | High | Complex, defer to v1.1 |

### Key Risks

1. **Keyring Backend Fragmentation**: Linux (libsecret), Windows (CredMan), macOS (Keychain) all different APIs. Use `keyring` crate (abstraction) but test thoroughly.

2. **Backup Code Security**: Must use separate Argon2id derivation (different salt/context) from master password. If backup code database leaked, attacker gets 8 high-entropy codes but each is single-use and rate-limited.

3. **SSH Provisioning Reliability**: Depends on system SSH client, network, host keys. Must handle: host key verification, connection timeouts, partial failures, idempotency.

4. **Master Key vs Password-Derived**: Keyring stores raw 256-bit key. If user switches from password → keyring, must re-encrypt all DEKs. Migration path needed.

5. **Complexity Budget**: +48h = 25% increase. Ensure Phase 1 gate criteria still achievable.

---

## Recommended Approach

### Option A: Full Integration (Recommended)
Add all 5 features to v1. Total: **236h**. Single cohesive release.

### Option B: Phased Delivery
- **v1.0** (188h): Core keystore + CA + password policy + generator + password file
- **v1.1** (+20h): SSH key management + provisioning
- **v1.2** (+16h): Keyring + backup codes + FIDO2

### Option C: Minimal v1 + Extensions
- **v1.0** (188h): Current plan only
- **Extensions**: Separate crates (`rw-secstore-ssh`, `rw-secstore-auth`) loaded via plugin system (post-v1)

---

## My Recommendation: **Option A with Scope Adjustment**

**Include in v1.0:**
1. ✅ SSH key storage + export (core formats)
2. ✅ Password policy + generator + file export
3. ✅ Keyring unlock (libsecret/wincred/keychain via `keyring` crate)
4. ✅ Backup codes (8 codes, single-use)

**Defer to v1.1:**
1. ⏸ SSH provisioning (network-dependent, complex error handling)
2. ⏸ SSH certificates (OpenSSH cert format, niche)
3. ⏸ known_hosts management (can use system file directly)
4. ⏸ SSH agent integration (nice-to-have)
5. ⏸ FIDO2/WebAuthn (complex, hardware-dependent)

**Adjusted Total: ~210h** (manageable, delivers 80% value)

---

## Updated Open Issues (Add to SPEC §9)

| Issue | Impact | Owner | Due Date |
|-------|--------|-------|----------|
| **OI-007**: SSH key provisioning automation | Fleet management blocker | TBD | v1.1 |
| **OI-008**: OpenSSH certificate support | SSH CA use case | TBD | v1.1 |
| **OI-009**: FIDO2/WebAuthn hardware unlock | High-security unlock | TBD | v1.1 |
| **OI-010**: SSH agent integration | Developer UX | TBD | v1.2 |
| **OI-011**: known_hosts management | Operational hygiene | TBD | v1.2 |

---

## Decision Required

Please confirm:

- [ ] **Approach**: Option A (full), Option B (phased), or Option C (minimal + extensions)?
- [ ] **SSH Provisioning**: Include in v1.0 or defer to v1.1?
- [ ] **SSH Certificates**: Include in v1.0 or defer to v1.1?
- [ ] **Keyring Backends**: Support all three (Linux/Windows/macOS) in v1.0?
- [ ] **Backup Codes**: 8 codes default, base32 format accepted?
- [ ] **Password Policy**: Default min 16 chars, 80 bits entropy accepted?
- [ ] **Diceware**: EFF wordlist bundled accepted?
- [ ] **Effort**: 210h (adjusted) or 236h (full) accepted?

Once confirmed, I'll update the SPEC, ADRs, and Plan v2.1 accordingly.
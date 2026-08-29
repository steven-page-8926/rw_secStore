# ARCHITECTURE DECISION RECORD 003
## Industry Standard Format for ADRs (2026)

## Document Identification
- **ADR ID**: 003
- **Title**: Certificate Authority Implementation with rcgen + x509-parser
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
rw_secstore must function as a Certificate Authority capable of:
- Creating root and intermediate CAs
- Issuing end-entity certificates (TLS server/client, code signing, etc.)
- Managing certificate revocation (CRL generation)
- Certificate renewal
- Import/export in standard formats (PEM, PKCS#12)

The implementation must use pure Rust where possible, produce standards-compliant X.509 certificates, and integrate with the SQLite storage layer.

### Drivers
- **Standards Compliance**: RFC 5280 compliant certificates
- **Pure Rust**: No OpenSSL dependency for core operations
- **Flexibility**: Support RSA, ECDSA, Ed25519 key types
- **Integration**: Works with application-level encryption (ADR-002)
- **Reference Validation**: minica uses OpenSSL via `openssl` crate; we prefer pure Rust

### Assumptions
- `rcgen` crate sufficient for certificate generation (supports all needed key types)
- `x509-parser` + `pem` for parsing/inspection
- `pkcs12` crate for PKCS#12 support
- CRL generation via `rcgen` or manual ASN.1
- OCSP out of scope for v1

### Constraints
- No OpenSSL system dependency (pure Rust preferred)
- Must support key profiles: RSA-2048/3072/4096, ECDSA-P256/P384, Ed25519
- Must support custom extensions (SAN, EKU, policies)
- Private keys encrypted per ADR-002

## 2. Decision

### Decision Statement
**Use `rcgen` for certificate generation, `x509-parser` + `pem` for parsing, and `pkcs12` crate for PKCS#12 support. Implement CRL generation manually using `der-parser`/`asn1_rs` or via `rcgen` extensions.**

### Considered Alternatives

#### Alternative 1: OpenSSL via `openssl` crate (like minica)
- **Pros**: Mature, complete feature set, battle-tested
- **Cons**: 
  - Requires OpenSSL system library (deployment complexity)
  - FFI boundary (safety, audit surface)
  - Version compatibility issues
  - Larger binary size
  - Not pure Rust

#### Alternative 2: `rcgen` + `x509-parser` (Pure Rust)
- **Pros**: 
  - Pure Rust, no system dependencies
  - Modern API, type-safe
  - Supports RSA, ECDSA, Ed25519
  - Active maintenance
  - Used in production (cert-manager, etc.)
- **Cons**: 
  - CRL support limited (manual implementation needed)
  - OCSP not supported
  - Some advanced extensions missing

#### Alternative 3: `certval` + `webpki` (Verification focused)
- **Pros**: Excellent verification
- **Cons**: No generation capabilities

#### Alternative 4: `pki` crate (Higher level)
- **Pros**: CA management built-in
- **Cons**: 
  - Less mature
  - Opinionated architecture
  - May not fit our storage model

#### Alternative 5: Custom ASN.1 with `der-parser`/`asn1_rs`
- **Pros**: Full control
- **Cons**: 
  - High effort, error-prone
  - Reinventing the wheel
  - Security risk if done incorrectly

### Decision Rationale
`rcgen` + `x509-parser` provides the best balance:
1. **Pure Rust** - No OpenSSL dependency, easier deployment
2. **Standards Compliant** - Generates RFC 5280 valid certificates
3. **Key Type Support** - RSA, ECDSA (P-256/P-384), Ed25519 all supported
4. **Extension Support** - SAN, Key Usage, EKU, Basic Constraints, Policies
5. **Active Maintenance** - Regular updates, used in major projects
6. **Reference Validation** - While minica uses OpenSSL, the industry is moving to pure Rust (cert-manager, AWS LC, etc.)

For CRL: `rcgen` doesn't have built-in CRL generation. We'll implement using `der-parser`/`asn1_rs` following RFC 5280 CRL profile. This is a well-defined, bounded scope.

### Implementation Approach

#### Certificate Generation (`rcgen`)
```rust
use rcgen::{Certificate, CertificateParams, KeyPair, SanType, IsCa, BasicConstraints};

let mut params = CertificateParams::new(vec![cn.clone()])?;
params.distinguished_name = DistinguishedName::new();
params.distinguished_name.push(DnType::CommonName, cn);
params.distinguished_name.push(DnType::OrganizationName, org);
// ... other DN fields

params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained); // or pathlen
params.key_usages = vec![
    KeyUsagePurpose::KeyCertSign,
    KeyUsagePurpose::CrlSign,
];
// For leaf certs:
params.key_usages = vec![
    KeyUsagePurpose::DigitalSignature,
    KeyUsagePurpose::KeyEncipherment,
];
params.extended_key_usages = vec![
    ExtendedKeyUsagePurpose::ServerAuth,
    ExtendedKeyUsagePurpose::ClientAuth,
];

// SANs
for dns in dns_names {
    params.subject_alt_names.push(SanType::DnsName(dns));
}
for ip in ip_addresses {
    params.subject_alt_names.push(SanType::IpAddress(ip.parse()?));
}

let key_pair = KeyPair::generate_for(&key_algorithm)?; // or from existing PEM
let cert = Certificate::from_params(params)?.serialize_der_with_signer(&key_pair)?;
```

#### Certificate Parsing (`x509-parser`)
```rust
use x509_parser::prelude::*;

let (_, cert) = X509Certificate::from_der(&der)?;
// Access: cert.subject(), cert.issuer(), cert.validity(), cert.extensions()
```

#### PKCS#12 (`pkcs12` crate)
```rust
use pkcs12::PFX;

let pfx = PFX::new(&cert_chain, &private_key, "password")?;
let der = pfx.to_der()?;
```

#### CRL Generation (Manual with `der-parser`/`asn1_rs`)
```rust
// RFC 5280 CRL structure:
// CertificateList ::= SEQUENCE {
//   tbsCertList          TBSCertList,
//   signatureAlgorithm   AlgorithmIdentifier,
//   signatureValue       BIT STRING
// }
//
// TBSCertList ::= SEQUENCE {
//   version                 Version OPTIONAL,
//   signature               AlgorithmIdentifier,
//   issuer                  Name,
//   thisUpdate              Time,
//   nextUpdate              Time OPTIONAL,
//   revokedCertificates     SEQUENCE OF RevokedCertificate OPTIONAL,
//   crlExtensions           [0] EXPLICIT Extensions OPTIONAL
// }
```

## 3. Status
**Accepted** - Ready for implementation

## 4. Consequences

### 4.1 Positive Consequences
- Pure Rust, single binary deployment
- Modern, type-safe API
- Standards-compliant certificates
- No system dependencies
- Smaller binary (~15-20MB vs 50MB+ with OpenSSL)
- Easier security audit (no FFI)

### 4.2 Negative Consequences
- CRL generation requires manual ASN.1 implementation
- OCSP not supported (out of scope for v1)
- Some obscure X.509 extensions not supported
- Less battle-tested than OpenSSL (though widely used)

### 4.3 Neutral Consequences
- Need to handle DER/PEM conversion manually
- Certificate chain building is manual (but straightforward)

## 5. Implications

### 5.1 Architectural Implications
- `CAService` module uses `rcgen` for generation
- `CertificateRepository` stores DER/PEM in SQLite
- `CryptoService` provides key pairs for signing
- CRL generation as separate function in `CAService`

### 5.2 Technical Implications
- Dependencies: `rcgen`, `x509-parser`, `pem`, `pkcs12`, `der-parser`, `asn1_rs`
- Key algorithms mapped to `rcgen::KeyPair` variants
- Serial numbers: RFC 5280 requires positive, unique per CA (use UUID v7 timestamp portion)
- Validity: `chrono` for time handling

### 5.3 Organizational Implications
- Team needs X.509 knowledge (RFC 5280)
- Security review of CRL implementation
- Testing: interop with OpenSSL, browsers, curl

### 5.4 Financial Implications
- No licensing costs
- Pure Rust = reduced audit surface

### 5.5 Schedule Implications
- Certificate generation: ~2 days
- CRL generation: ~2 days (ASN.1 work)
- PKCS#12: ~1 day
- Testing/interop: ~2 days

## 6. Related Documents
- **SPEC-2026-001**: Core specification (CA requirements)
- **ADR-001**: SQLite storage (certificate storage schema)
- **ADR-002**: Encryption (private key encryption)
- **Reference**: minica (wushilin/minica) - OpenSSL-based CA reference
- **RFC 5280**: Internet X.509 PKI Certificate and CRL Profile
- **RFC 5912**: New Algorithms for PKIX (Ed25519, etc.)
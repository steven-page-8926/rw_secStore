# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security vulnerability in rw_secStore, please report it responsibly:

**Do not open a public issue.**

Instead, please email security@rapidwebs.org with:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fixes

We will acknowledge receipt within 48 hours and provide a timeline for resolution.

## Security Best Practices

- Keep dependencies updated
- Use hardware security modules (HSM) for production keys
- Enable audit logging
- Rotate secrets regularly
- Use least-privilege access policies
- Monitor for anomalous access patterns

## Cryptographic Standards

- AES-256-GCM for symmetric encryption
- Ed25519 for signatures
- X25519 for key exchange
- Argon2id for password hashing
- TLS 1.3 for transport security
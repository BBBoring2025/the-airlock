# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 5.x     | ✅        |
| < 5.0   | ❌        |

## Reporting a Vulnerability

- **Email**: security@[TBD]
- **Do NOT** open a public GitHub issue for security vulnerabilities
- **Expected response time**: 48 hours
- **Coordinated disclosure**: 90 days

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

## Security Design

THE AIRLOCK is built on the following security principles:

1. **Defense in depth**: 7-layer security architecture — no single point of failure
2. **Fail-closed**: CDR failure → quarantine (never copy the original)
3. **Least privilege**: Capability-less daemon + restricted root helper with only 4 commands
4. **Air-gapped**: No network interface, no telemetry, no phone-home — ever
5. **Key separation**: Report signing key ≠ update signing key — device compromise does not enable fleet-wide supply-chain attacks

## Security Architecture Overview

```
Layer 1: BadUSB Block     — USB device class filtering (sysfs + udev)
Layer 2: Mount Policy     — Read-only source, noexec/nosuid/nodev
Layer 3: File Validator   — Symlink blocking, path traversal, extension filter
Layer 4: Multi-Scanner    — ClamAV + YARA + entropy + magic byte + hash
Layer 5: CDR Engine       — PDF rasterize, Office→PDF, image strip, text normalize
Layer 6: Signed Reports   — Ed25519-signed JSON with per-file SHA-256
Layer 7: Offline Updates  — Ed25519-signed update packages
```

## Threat Model

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for detailed threat analysis, trust boundaries, and accepted risks.

## Key Management

See [docs/KEY_MANAGEMENT.md](docs/KEY_MANAGEMENT.md) for dual-keypair architecture, key rotation procedures, and compromise response.

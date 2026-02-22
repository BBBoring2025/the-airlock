# THE AIRLOCK — Release Notes

---

## v5.1.1 — Fortress-Hardened (2026-02-19)

### 🔐 Security Enhancements

- **Key Separation Architecture**: Dual Ed25519 keypair system — report signing key
  (device-specific) separated from update verification key (vendor-managed offline).
  Device compromise no longer enables fleet-wide supply-chain attacks.
- **Helper Socket Hardening**: `SO_PEERCRED` peer credential verification on Unix domain
  socket. Only the `airlock` user can communicate with the privileged helper.
- **Paranoid Policy Sandbox Enforcement**: `paranoid` security policy now REQUIRES bwrap
  sandbox for CDR operations. Missing sandbox → CDR blocked (not degraded).
- **Rate Limiting**: Helper socket enforces per-connection rate limits via
  `ThreadPoolExecutor(max_workers=4)` to prevent DoS abuse.

### ✅ Quality & Testing

- **185 Total Tests**: 185 passed (0 skipped)
  - CDR Engine: 15 tests
  - Scanner (ClamAV + YARA + entropy + magic): 15 tests
  - USB Guard: 10 tests
  - Key Separation: 5 tests
  - File Validator, Crypto, Config, Policy, Archive, Report: remaining
- **CI Pipeline**: GitHub Actions with pytest + coverage, ruff lint, mypy type check,
  stale version detection
- **Performance Benchmarks**: `scripts/benchmark.py` — SHA-256, entropy, safe_copy,
  magic byte, CDR PDF, ClamAV scan with statistical reporting

### 🏗️ Architecture

- **Processing Pipeline Extraction**: `app/processing_pipeline.py` — FileProcessor class
  extracted from daemon.py (1459 → 1057 lines, -28%). Clean separation of file processing
  pipeline (scan → decide → CDR/copy/quarantine) from daemon orchestration (USB detection,
  mount management, event loop).
- **Dependency Injection**: FileProcessor receives all dependencies via constructor,
  hardware events via callback. No global state.
- **Type Hints**: Full type annotations across all modules (mypy compatible)
- **Lint Configuration**: `pyproject.toml` ruff config with project-specific rules

### 📖 Documentation

- `docs/THREAT_MODEL.md` — Trust boundaries, 8-threat matrix (T1-T8), accepted risks
- `docs/OPERATIONS_GUIDE.md` — Daily usage, log management, updates, troubleshooting
- `docs/KEY_MANAGEMENT.md` — Dual keypair architecture, rotation procedures
- `SECURITY.md` — Vulnerability reporting, security design principles

### ⚡ Performance

- Benchmark suite: 6 tests with min/max/mean/median/stddev reporting
- JSON output for CI integration (`benchmark_results.json`)
- Graceful skip for missing external tools (Ghostscript, ClamAV)

### Upgrade from v5.0.8

1. Backup `/opt/airlock/config/airlock.yaml` and `/opt/airlock/keys/`
2. `sudo systemctl stop airlock airlock-helper`
3. Deploy new files, re-run `scripts/setup.sh`
4. Generate new update keypair: `scripts/generate_keys.sh --generate-update-keypair`
5. Copy `update_verify.pub` to device, store `update_signing.key` offline
6. `sudo systemctl start airlock airlock-helper`

**IMPORTANT**: v5.1.1 introduces key separation. Existing single-keypair setups must
generate the new update keypair. See `docs/KEY_MANAGEMENT.md` for details.

---

## v5.0.8 — Final Release (Fortress-Hardened)

**THE AIRLOCK** is an air-gapped USB sanitization station for Raspberry Pi.
It scans untrusted USB media, disarms risky content (CDR), and produces a safe output USB plus a signed audit report.

### Highlights

- ✅ **7-Layer Security Architecture** — BadUSB protection, mount hardening, file validation, AV scanning (ClamAV + YARA), Content Disarm & Reconstruction, signed reports, offline updates
- ✅ **Privilege Separation** — Capability-less daemon + hardened privileged helper (4 commands only)
- ✅ **Offline Updater Integrity** — Symlink detection + path traversal rejection on UPDATE USB
- ✅ **Filesystem-Aware Mounting** — FAT/exFAT/NTFS auto-inject uid/gid/umask=0077
- ✅ **systemd Hardening** — NoNewPrivileges, ProtectSystem=strict, MemoryDenyWriteExecute, PrivateNetwork, UMask=0077
- ✅ **131 Unit Tests Passed, 5 Skipped (PyNaCl), 0 Failures, 0 Warnings**
- ✅ **MIT License, Clean Release Package**

### Security Notes & Limitations

This system significantly reduces USB-borne risk, but **no solution can guarantee 100% protection** against:
- Hardware attacks like **USB Killer**
- Highly advanced BadUSB/firmware-level threats beyond HID/CDC class blocking

Use with appropriate operational security (air-gapped workflow, controlled environment).

### Checksums

See `SHA256SUMS.txt` in release assets.

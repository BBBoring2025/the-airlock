# THE AIRLOCK v5.1.1 — Release Checklist

## A. Pre-Release Verification

- [x] `VERSION` → `5.1.1`
- [x] `app/config.py` → `VERSION == "5.1.1"`
- [x] `config/airlock.yaml` → `version: "5.1.1"`
- [x] `grep -R "5.0.8"` → 0 results in code/config/service/script (RELEASE_NOTES hariç)
- [x] `LICENSE` → MIT License
- [x] `README.md` → English, complete

## B. Code Quality

- [x] `python3 -m py_compile` → 0 errors (all .py files)
- [x] `pytest -q` → 185 passed, 0 skipped, 0 failed, 0 warnings
- [x] No `shell=True` in app code
- [x] No `followlinks=True` in app code
- [x] `ruff check app/ tests/` → clean or exit-zero
- [x] `mypy app/ --ignore-missing-imports` → no critical errors

## C. Security Verification

- [x] Key separation: `report_signing.key` ≠ `update_signing.key`
- [x] Key separation tests pass (`test_key_separation.py`)
- [x] Helper socket: `SO_PEERCRED` peer verification active
- [x] Paranoid policy: bwrap required for CDR
- [x] No private keys in repository (`keys/*.key` in `.gitignore`)

## D. Documentation

- [x] `docs/THREAT_MODEL.md` — Trust boundaries + threat matrix
- [x] `docs/OPERATIONS_GUIDE.md` — Operational procedures
- [x] `docs/KEY_MANAGEMENT.md` — Dual keypair architecture
- [x] `SECURITY.md` — Vulnerability reporting policy
- [x] `docs/release/RELEASE_NOTES.md` — v5.1.1 entry added

## E. Performance

- [x] `scripts/benchmark.py` runs without error
- [x] Benchmark results: SHA-256, entropy, safe_copy, magic byte tested
- [ ] CDR PDF benchmark (requires Ghostscript on target)
- [ ] ClamAV benchmark (requires ClamAV on target)

## F. Release Package

- [ ] Terminal `zip -r -X` (no Finder)
- [ ] No `__MACOSX/`, `__pycache__/`, `.pytest_cache/`, `.claude/`, `.DS_Store`
- [ ] SHA256 checksum generated → `SHA256SUMS.txt`

## G. Raspberry Pi Acceptance Test

- [ ] `systemctl status airlock` → active
- [ ] `systemctl status airlock-helper` → active
- [ ] DIRTY USB → detected, mounted read-only
- [ ] CLEAN USB → scan + CDR + copy + signed report
- [ ] FAT/NTFS USB → umask=0077 confirmed
- [ ] Malicious update USB → REJECTED (signature verification)
- [ ] Valid update USB → applied (Ed25519 verified)
- [ ] No OLED/LED → daemon runs without crash (graceful degrade)
- [ ] Key separation: `update_signing.key` NOT on device

## H. GitHub Release

- [ ] `git tag v5.1.1` pushed
- [ ] Release notes published
- [ ] Assets: zip + SHA256SUMS.txt uploaded

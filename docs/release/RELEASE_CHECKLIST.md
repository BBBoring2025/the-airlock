# THE AIRLOCK v5.0.8 — Release Checklist

## A. Pre-Release Verification

- [x] `VERSION` → `5.0.8`
- [x] `app/config.py` → `VERSION == "5.0.8"`
- [x] `config/airlock.yaml` → `version: "5.0.8"`
- [x] `grep -R "5.0.7"` → 0 results in code/config/service/script
- [x] `LICENSE` → MIT License
- [x] `README.md` → 144 lines, English, complete

## B. Code Quality

- [x] `python3 -m py_compile` → 0 errors (all .py files)
- [x] `pytest -q` → 131 passed, 5 skipped (PyNaCl), 0 failed, 0 warnings
- [x] No `shell=True` in app code
- [x] No `followlinks=True` in app code

## C. Release Package

- [x] Terminal `zip -r -X` (no Finder)
- [x] No `__MACOSX/`, `__pycache__/`, `.pytest_cache/`, `.claude/`, `.DS_Store`
- [x] SHA256 checksum generated

## D. Raspberry Pi Acceptance Test

- [ ] `systemctl status airlock` → active
- [ ] `systemctl status airlock-helper` → active
- [ ] DIRTY USB → detected, mounted read-only
- [ ] CLEAN USB → scan + CDR + copy + signed report
- [ ] FAT/NTFS USB → umask=0077 confirmed
- [ ] Malicious update USB → REJECTED
- [ ] Valid update USB → applied
- [ ] No OLED/LED → daemon runs without crash (graceful degrade)

## E. GitHub Release

- [ ] `git tag v5.0.8` pushed
- [ ] Release notes published
- [ ] Assets: zip + SHA256SUMS.txt uploaded

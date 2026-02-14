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

### Installation

On Raspberry Pi OS (Bookworm):

```bash
sudo bash scripts/setup.sh
sudo systemctl enable --now airlock airlock-helper
```

### Hardware Requirements

| Component | Required | Notes |
|-----------|----------|-------|
| Raspberry Pi 4/5 | ✅ | Pi 5 recommended |
| USB Hub | ✅ | For simultaneous DIRTY + CLEAN USB |
| OLED Display | Optional | SSD1306 128x64 |
| LED Strip | Optional | WS2812B status indicators |
| Button | Optional | Physical scan trigger |

### Upgrade from Previous Versions

1. Backup `/opt/airlock/config/airlock.yaml` and `/opt/airlock/keys/`
2. `sudo systemctl stop airlock airlock-helper`
3. Deploy new files, re-run `scripts/setup.sh`
4. `sudo systemctl start airlock airlock-helper`

### Checksums

See `SHA256SUMS.txt` in release assets.

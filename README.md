# THE AIRLOCK v5.1.1 FORTRESS-HARDENED

Air-gapped USB sanitization station built on Raspberry Pi 5 (8GB). THE AIRLOCK
intercepts files from untrusted USB drives, scans them with multiple engines,
applies Content Disarm & Reconstruction (CDR), and writes sanitized files to a
clean USB drive — all without any network connection.

## Why THE AIRLOCK?

USB drives remain a primary attack vector for air-gapped networks. Threats
include BadUSB/Rubber Ducky keystroke injection, malware-laden documents,
weaponized PDFs and Office files, archive bombs, and USB Killer electrical
attacks. THE AIRLOCK provides automated, policy-driven defense at the physical
perimeter — no human judgment required during file transfer.

## 7-Layer Security Architecture

| Layer | Component         | Function                                           |
|-------|-------------------|----------------------------------------------------|
| 1     | **BadUSB Block**  | USB device class filtering via sysfs + udev rules. Only Mass Storage (0x08) allowed. HID/CDC/Wireless instantly deauthorized. |
| 2     | **Mount Policy**  | Read-only source mount enforced at kernel level via privileged helper. `noexec,nosuid,nodev` on all mounts. |
| 3     | **File Validator** | Symlink blocking, path traversal detection, dangerous extension filter, filename sanitization. |
| 4     | **Multi-Engine Scanner** | ClamAV signatures, YARA rules, Shannon entropy analysis, magic byte verification, known-bad hash matching. |
| 5     | **CDR Engine**    | PDF rasterization (Ghostscript), Office-to-PDF conversion (LibreOffice), image metadata stripping, text UTF-8 normalization. Optional bwrap sandbox. |
| 6     | **Signed Reports** | Ed25519-signed JSON reports with per-file SHA-256 hashes, detections, and CDR status. |
| 7     | **Offline Updates** | ClamAV/YARA/hash updates via Ed25519-signed USB packages. Symlink and path traversal hardened. |

## Hardware Requirements

| Component           | Required | Notes                                    |
|---------------------|----------|------------------------------------------|
| Raspberry Pi 4/5    | Yes      | 8 GB RAM recommended                     |
| Powered USB Hub     | Yes      | Electrical isolation from USB Killer      |
| microSD 32 GB+      | Yes      | Class 10 / A2 recommended                |
| SSD1306 OLED 128x64 | Optional | I2C status display                       |
| RGB LED / NeoPixel  | Optional | Visual status indicator                  |
| Speaker / Buzzer    | Optional | Audio feedback                           |
| Momentary Button    | Optional | Short press = eject, long press = shutdown |

All optional hardware gracefully degrades — the daemon runs without it.

## Quick Install

```bash
# Raspberry Pi OS Bookworm (64-bit)
git clone https://github.com/BBBoring2025/the-airlock.git /opt/airlock
cd /opt/airlock
sudo scripts/setup.sh
sudo reboot
```

The setup script handles all 19 installation steps: system packages, Python
venv, ClamAV database, YARA rules, Ed25519 keys, udev rules, systemd services,
and self-tests.

## Usage Flow

```
  DIRTY USB ───► [ THE AIRLOCK ] ───► CLEAN USB
                       │
            ┌──────────┼──────────┐
            │          │          │
        USB Guard   Scanner    CDR
        (Layer 1)  (Layer 4)  (Layer 5)
            │          │          │
            └──────────┼──────────┘
                       │
                Signed Report
                 (Layer 6)
```

1. Label the source USB: `DIRTY`, `KIRLI`, `SOURCE`, or `INPUT`
2. Label the target USB: `CLEAN`, `TEMIZ`, `TARGET`, or `OUTPUT`
3. Insert the source USB first, then the target USB
4. THE AIRLOCK processes automatically: validate → scan → CDR → copy
5. LED / OLED / buzzer indicates completion or threat detection
6. Signed JSON report is written to both target USB and local log

## Architecture

```
┌────────────────────────────────────────────────────────┐
│              airlock.service  (non-root)                │
│  ┌─────────┬───────────┬─────────┬───────┬──────────┐  │
│  │USBGuard │ Validator │ Scanner │  CDR  │ Reporter │  │
│  │ Layer 1 │ Layer 3   │ Layer 4 │ Lay.5 │ Layer 6  │  │
│  └────┬────┴─────┬─────┴────┬────┴───┬───┴────┬─────┘  │
│       └──────────┴──────────┴────────┴────────┘         │
│                  Unix Socket (helper.sock)               │
└──────────────────────────┬───────────────────────────────┘
                           │
                ┌──────────▼───────────┐
                │ airlock-helper.svc   │
                │  (root, 4 commands)  │
                │ mount │ umount       │
                │ deauth│ update_clamav│
                └──────────────────────┘
```

## Configuration

Edit `/opt/airlock/config/airlock.yaml`. Three built-in security policies:

- **paranoid** — Block Office files, archives, unknown types. CDR failure = quarantine.
- **balanced** (default) — Allow all common types with CDR. Unknown = copy with warning.
- **convenient** — Maximum compatibility. CDR failure = copy to unsanitized folder.

USBGuard integration is optional and disabled by default. Enable in `airlock.yaml`
under `usb_guard.enabled: true` (requires rules.conf configuration).

## Security Notes & Limitations

- **BadUSB:** Protection uses sysfs interface class checks + udev rules. Firmware-level
  attacks during initial enumeration may evade detection (race condition risk).
- **Known-bad VID:PID:** Teensy, Rubber Ducky, Arduino Leonardo, etc. are blocked, but
  cloned VID:PIDs cannot be caught.
- **USB Killer:** Electrical overvoltage cannot be detected by software. Use a powered
  USB hub with optical isolation for physical protection.
- **CDR Sandbox:** Bubblewrap (bwrap) isolates Ghostscript and LibreOffice. System
  gracefully degrades if bwrap is unavailable. Sandbox does not protect against kernel
  exploits; consider grsecurity or AppArmor for additional hardening.
- **Update Integrity:** Offline update packages are Ed25519-signed. Update directories
  are scanned for symlinks and path traversal before any files are processed.

## Offline Updates

1. Prepare an UPDATE USB with `manifest.json`, signature file, and update components
2. Sign `manifest.json` with the Ed25519 private key
3. Label the USB as `UPDATE` or `GÜNCELLEME`
4. Insert — THE AIRLOCK verifies signature, hashes, and integrity before applying

See `AIRLOCK_V4_FORTRESS_ARCHITECTURE.md` for full update package format.

## License

This project is licensed under the [MIT License](LICENSE).

## Contributing

1. Follow coding rules in `CLAUDE.md`
2. Python 3.11+, type hints required, docstrings on all public methods
3. Use `pathlib.Path` (not `str` for file paths)
4. Never use `shell=True` in subprocess calls
5. Run `python -m pytest tests/ -v` before submitting changes

#!/usr/bin/env python3
"""
THE AIRLOCK v5.1.1 FORTRESS-HARDENED — Entry Point

systemd servis olarak çalıştırılır:
    ExecStart=/opt/airlock/venv/bin/python3 /opt/airlock/app/main.py

Manuel çalıştırma:
    python3 -m app.main
    python3 app/main.py
    python3 app/main.py --config /path/to/airlock.yaml
    python3 app/main.py --policy paranoid
    python3 app/main.py --version

Komut satırı argümanları:
    --config PATH    : Alternatif yapılandırma dosyası yolu
    --policy NAME    : Aktif politikayı geçersiz kıl (paranoid/balanced/convenient)
    --version        : Sürüm bilgisi göster ve çık
    --dry-run        : Daemon'ı başlatmadan yapılandırmayı doğrula
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from app.config import CODENAME, POLICIES, VERSION


def parse_args() -> argparse.Namespace:
    """Komut satırı argümanlarını parse et."""
    parser = argparse.ArgumentParser(
        prog="airlock",
        description=f"THE AIRLOCK v{VERSION} {CODENAME} — USB Sanitization Station",
    )

    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        metavar="PATH",
        help="Alternatif airlock.yaml yapılandırma dosyası yolu",
    )

    parser.add_argument(
        "--policy",
        type=str,
        choices=list(POLICIES.keys()),
        default=None,
        metavar="NAME",
        help="Aktif güvenlik politikasını geçersiz kıl (paranoid/balanced/convenient)",
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"THE AIRLOCK v{VERSION} {CODENAME}",
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Daemon'ı başlatmadan yapılandırmayı doğrula ve çık",
    )

    return parser.parse_args()


def main() -> int:
    """
    Ana giriş noktası.

    Returns:
        Çıkış kodu: 0 = başarılı, 1 = hata
    """
    args = parse_args()

    # ── Yapılandırma yükle ──
    from app.config import AirlockConfig  # noqa: PLC0415

    config = AirlockConfig.load(args.config)

    # Politika override
    if args.policy:
        config.active_policy = args.policy

    # Yapılandırma doğrulama
    errors = config.validate()
    if errors:
        for err in errors:
            print(f"[HATA] Yapılandırma: {err}", file=sys.stderr)
        if args.dry_run:
            return 1

    # ── Dry-run modu ──
    if args.dry_run:
        print(f"THE AIRLOCK v{VERSION} {CODENAME}")
        print(f"Yapılandırma: {'OK' if not errors else 'HATALI'}")
        print(f"Aktif politika: {config.active_policy}")
        print(f"ClamAV: {'açık' if config.clamav_enabled else 'kapalı'}")
        print(f"YARA: {'açık' if config.yara_enabled else 'kapalı'}")
        print(f"OCR: {'açık' if config.ocr_enabled else 'kapalı'}")
        print(f"OLED: {'açık' if config.oled_enabled else 'kapalı'}")
        print(f"LED mod: {config.led_mode}")
        print(f"Ses: {'açık' if config.audio_enabled else 'kapalı'}")
        return 0

    # ── Daemon başlat ──
    from app.daemon import AirlockDaemon  # noqa: PLC0415

    daemon = None
    exit_code = 0

    try:
        daemon = AirlockDaemon(config_path=args.config)

        # Politika override (daemon oluşturulduktan sonra)
        if args.policy:
            daemon._config.active_policy = args.policy

        daemon.run()

    except KeyboardInterrupt:
        print("\n[AIRLOCK] Klavye ile durduruldu (Ctrl+C)", file=sys.stderr)

    except Exception as exc:
        logging.getLogger("AIRLOCK.MAIN").critical(
            "Daemon çöktü: %s", exc, exc_info=True,
        )
        print(f"[KRİTİK] Daemon çöktü: {exc}", file=sys.stderr)
        exit_code = 1

    finally:
        if daemon is not None:
            try:
                daemon.cleanup()
            except Exception:
                pass

    return exit_code


if __name__ == "__main__":
    sys.exit(main())

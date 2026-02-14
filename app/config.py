"""
THE AIRLOCK v5.0.8 FORTRESS-HARDENED — Merkezi Yapılandırma Modülü

Tüm yapılandırma bu modülden okunur.
YAML dosyasından yüklenir, sabitler burada tanımlanır.
Güvenlik politikaları: PARANOID / BALANCED / CONVENIENT

Kullanım:
    from app.config import AirlockConfig
    cfg = AirlockConfig.load()
    policy = cfg.active_policy_settings
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Any, Dict, FrozenSet, Optional, Set

logger = logging.getLogger("AIRLOCK.CONFIG")

# ─────────────────────────────────────────────
# SÜRÜM
# ─────────────────────────────────────────────

VERSION = "5.0.8"
CODENAME = "FORTRESS-HARDENED"

# ─────────────────────────────────────────────
# DİZİNLER
# ─────────────────────────────────────────────

BASE_DIR = Path("/opt/airlock")

DIRECTORIES: Dict[str, Path] = {
    "base": BASE_DIR,
    "app": BASE_DIR / "app",
    "config": BASE_DIR / "config",
    "policies": BASE_DIR / "config" / "policies",
    "tmp": BASE_DIR / "tmp",
    "logs": BASE_DIR / "data" / "logs",
    "quarantine": BASE_DIR / "data" / "quarantine",
    "yara_rules": BASE_DIR / "data" / "yara_rules",
    "yara_core": BASE_DIR / "data" / "yara_rules" / "core",
    "yara_custom": BASE_DIR / "data" / "yara_rules" / "custom",
    "clamav": BASE_DIR / "data" / "clamav",
    "sounds": BASE_DIR / "data" / "sounds",
    "keys": BASE_DIR / "keys",
}

# ─────────────────────────────────────────────
# GÜVENLİK POLİTİKALARI
# ─────────────────────────────────────────────


@dataclass(frozen=True)
class SecurityPolicy:
    """Değiştirilemez güvenlik politikası tanımı."""

    name: str
    cdr_on_failure: str
    unknown_extension: str
    archive_handling: str
    max_file_size_mb: int
    entropy_threshold: float
    ocr_enabled: bool
    allow_images: bool
    allow_text: bool
    allow_pdf: bool
    allow_office: bool


POLICIES: Dict[str, SecurityPolicy] = {
    "paranoid": SecurityPolicy(
        name="paranoid",
        cdr_on_failure="quarantine",
        unknown_extension="block",
        archive_handling="block",
        max_file_size_mb=100,
        entropy_threshold=7.0,
        ocr_enabled=False,
        allow_images=True,
        allow_text=True,
        allow_pdf=True,
        allow_office=False,
    ),
    "balanced": SecurityPolicy(
        name="balanced",
        cdr_on_failure="quarantine",
        unknown_extension="copy_with_warning",
        archive_handling="scan_and_extract",
        max_file_size_mb=500,
        entropy_threshold=7.5,
        ocr_enabled=True,
        allow_images=True,
        allow_text=True,
        allow_pdf=True,
        allow_office=True,
    ),
    "convenient": SecurityPolicy(
        name="convenient",
        cdr_on_failure="copy_unsanitized_folder",
        unknown_extension="copy_with_warning",
        archive_handling="scan_and_extract",
        max_file_size_mb=2048,
        entropy_threshold=7.9,
        ocr_enabled=True,
        allow_images=True,
        allow_text=True,
        allow_pdf=True,
        allow_office=True,
    ),
}

# ─────────────────────────────────────────────
# TEHLİKELİ UZANTILAR
# ─────────────────────────────────────────────

DANGEROUS_EXTENSIONS: FrozenSet[str] = frozenset({
    # Çalıştırılabilir
    ".exe", ".dll", ".sys", ".drv", ".ocx", ".com", ".scr", ".pif", ".cpl",
    # Script
    ".bat", ".cmd", ".ps1", ".psm1", ".psd1", ".vbs", ".vbe",
    ".js", ".jse", ".ws", ".wsf", ".wsc", ".wsh", ".msc",
    # Office Macro
    ".docm", ".dotm", ".xlsm", ".xltm", ".xlam",
    ".pptm", ".potm", ".ppam", ".ppsm", ".sldm",
    # Diğer tehlikeli
    ".hta", ".crt", ".ins", ".isp", ".reg", ".inf",
    ".scf", ".lnk", ".url", ".jar", ".war",
    ".msi", ".msp", ".application", ".gadget",
    # Disk image (autorun riski)
    ".iso", ".img", ".vhd", ".vhdx",
})

# ─────────────────────────────────────────────
# CDR DESTEKLİ MIME TÜRLERİ
# ─────────────────────────────────────────────

CDR_SUPPORTED: Dict[str, str] = {
    "application/pdf": "rasterize",
    "application/msword": "office_to_pdf_rasterize",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "office_to_pdf_rasterize",
    "application/vnd.ms-excel": "office_to_pdf_rasterize",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": "office_to_pdf_rasterize",
    "application/vnd.ms-powerpoint": "office_to_pdf_rasterize",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": "office_to_pdf_rasterize",
}

# Resim MIME türleri — CDR: metadata strip + re-encode
CDR_IMAGE_TYPES: FrozenSet[str] = frozenset({
    "image/jpeg",
    "image/png",
    "image/gif",
    "image/bmp",
    "image/tiff",
    "image/webp",
})

# Metin MIME türleri — CDR: UTF-8 normalisation + control char strip
CDR_TEXT_TYPES: FrozenSet[str] = frozenset({
    "text/plain",
    "text/csv",
    "text/xml",
    "application/json",
    "application/xml",
    "text/yaml",
    "application/x-yaml",
})

# ─────────────────────────────────────────────
# ARŞİV SINIRLAMALARI
# ─────────────────────────────────────────────


@dataclass(frozen=True)
class ArchiveLimits:
    """Arşiv açma güvenlik limitleri."""

    max_depth: int = 3
    max_total_size_mb: int = 1024
    max_file_count: int = 1000
    max_single_file_mb: int = 500
    compression_ratio_limit: int = 100
    timeout_seconds: int = 120
    encrypted_policy: str = "block"


ARCHIVE_LIMITS = ArchiveLimits()

# ─────────────────────────────────────────────
# USB SINIF FİLTRELERİ
# ─────────────────────────────────────────────


class USBClass(IntEnum):
    """USB cihaz sınıfları."""

    AUDIO = 0x01
    CDC = 0x02
    HID = 0x03
    PHYSICAL = 0x05
    IMAGE = 0x06
    PRINTER = 0x07
    MASS_STORAGE = 0x08
    HUB = 0x09
    CDC_DATA = 0x0A
    SMART_CARD = 0x0B
    VIDEO = 0x0E
    WIRELESS = 0xE0
    MISC = 0xEF
    VENDOR_SPEC = 0xFF


ALLOWED_USB_CLASSES: FrozenSet[int] = frozenset({
    USBClass.MASS_STORAGE,
})

BLOCKED_USB_CLASSES: FrozenSet[int] = frozenset({
    USBClass.HID,
    USBClass.CDC,
    USBClass.CDC_DATA,
    USBClass.VIDEO,
    USBClass.SMART_CARD,
    USBClass.WIRELESS,
    USBClass.MISC,
    USBClass.VENDOR_SPEC,
})

# Bilinen BadUSB cihazları (VID:PID)
KNOWN_BAD_USB_DEVICES: FrozenSet[str] = frozenset({
    "16c0:0486",  # Teensy
    "1781:0c9f",  # Teensy variant
    "2341:8036",  # Arduino Leonardo (HID mode)
    "2341:8037",  # Arduino Micro (HID mode)
    "1b4f:9205",  # SparkFun Pro Micro (HID)
    "1b4f:9206",  # SparkFun Pro Micro (HID)
    "05ac:0256",  # Fake Apple keyboard
    "1fc9:0003",  # NXP LPC (USB Rubber Ducky platform)
    "2e8a:0005",  # Raspberry Pi Pico (BadUSB script platform)
})

# ─────────────────────────────────────────────
# DONANIM PİN ATAMALARI
# ─────────────────────────────────────────────


@dataclass(frozen=True)
class GPIOConfig:
    """GPIO pin atamaları."""

    button: int = 21
    led_red: int = 17
    led_green: int = 27
    led_blue: int = 22
    buzzer: int = 24


@dataclass(frozen=True)
class I2CConfig:
    """I2C yapılandırması."""

    oled_address: int = 0x3C
    oled_width: int = 128
    oled_height: int = 64


GPIO_PINS = GPIOConfig()
I2C_CONFIG = I2CConfig()

# ─────────────────────────────────────────────
# MOUNT AYARLARI
# ─────────────────────────────────────────────

SOURCE_MOUNT_OPTIONS = "ro,noexec,nosuid,nodev,noatime"
TARGET_MOUNT_OPTIONS = "rw,noexec,nosuid,nodev,noatime"

ALLOWED_FILESYSTEMS: FrozenSet[str] = frozenset({
    "vfat", "exfat", "ntfs", "ext4", "ext3",
})

# ─────────────────────────────────────────────
# USB ETİKETLERİ
# ─────────────────────────────────────────────

SOURCE_USB_LABELS: FrozenSet[str] = frozenset({
    "KIRLI", "DIRTY", "SOURCE", "INPUT",
})

TARGET_USB_LABELS: FrozenSet[str] = frozenset({
    "TEMIZ", "CLEAN", "TARGET", "OUTPUT",
})

UPDATE_USB_LABELS: FrozenSet[str] = frozenset({
    "UPDATE", "GÜNCELLEME",
})

# ─────────────────────────────────────────────
# TARAMA AYARLARI
# ─────────────────────────────────────────────

CLAMAV_SOCKET = Path("/var/run/clamav/clamd.ctl")
YARA_TIMEOUT_SECONDS = 30
ENTROPY_SUSPICIOUS_THRESHOLD = 7.5
ENTROPY_VERY_HIGH_THRESHOLD = 7.9

# ─────────────────────────────────────────────
# CDR AYARLARI
# ─────────────────────────────────────────────

PDF_DPI = 200
JPEG_QUALITY = 90
OCR_LANGUAGES = "tur+eng"

# ─────────────────────────────────────────────
# LOGLAMA AYARLARI
# ─────────────────────────────────────────────

LOG_LEVEL = "INFO"
LOG_MAX_SIZE_MB = 50
LOG_MAX_FILES = 10

# ─────────────────────────────────────────────
# DOSYA DOĞRULAMA LİMİTLERİ
# ─────────────────────────────────────────────

MAX_FILENAME_LENGTH = 255
MAX_PATH_DEPTH = 20
MAX_TOTAL_FILES = 10_000
MAX_TOTAL_SIZE_GB = 32

# ─────────────────────────────────────────────
# YAML'DAN YÜKLEME
# ─────────────────────────────────────────────


@dataclass
class AirlockConfig:
    """
    Çalışma zamanı yapılandırması.

    airlock.yaml dosyasından yüklenir.
    YAML bulunamazsa varsayılan değerlerle çalışır.
    """

    version: str = VERSION
    codename: str = CODENAME
    active_policy: str = "balanced"

    # Donanım
    oled_enabled: bool = True
    oled_address: int = 0x3C
    led_mode: str = "rgb"
    audio_enabled: bool = True
    audio_volume: int = 80
    button_enabled: bool = True
    button_pin: int = 21

    # Tarama
    clamav_enabled: bool = True
    clamav_socket: Path = CLAMAV_SOCKET
    yara_enabled: bool = True
    yara_timeout: int = YARA_TIMEOUT_SECONDS
    entropy_enabled: bool = True
    magic_byte_check: bool = True
    hash_check: bool = True

    # CDR
    pdf_dpi: int = PDF_DPI
    jpeg_quality: int = JPEG_QUALITY
    ocr_enabled: bool = True
    ocr_languages: str = OCR_LANGUAGES
    video_cdr: bool = False
    image_strip_metadata: bool = True
    cdr_require_sandbox: bool = False  # True → bwrap yoksa CDR reddedilir

    # Arşiv
    archive_limits: ArchiveLimits = field(default_factory=ArchiveLimits)

    # Loglama
    log_level: str = LOG_LEVEL
    log_max_size_mb: int = LOG_MAX_SIZE_MB
    log_max_files: int = LOG_MAX_FILES
    log_to_console: bool = True

    # Mount noktaları — privileged helper regex ile uyumlu OLMALI
    mount_source: str = "/mnt/airlock_source"
    mount_target: str = "/mnt/airlock_target"
    mount_update: str = "/mnt/airlock_update"

    # USBGuard entegrasyonu (opsiyonel)
    usb_guard_enabled: bool = False
    usb_guard_mode: str = "monitor"   # "monitor" | "enforce"

    # Güncelleme
    require_update_signature: bool = True
    update_public_key_path: Path = field(
        default_factory=lambda: DIRECTORIES["keys"] / "update_verify.pub"
    )

    @property
    def active_policy_settings(self) -> SecurityPolicy:
        """Aktif güvenlik politikası ayarlarını döndür."""
        return POLICIES.get(self.active_policy, POLICIES["balanced"])

    @classmethod
    def load(cls, config_path: Optional[Path] = None) -> AirlockConfig:
        """
        YAML dosyasından yapılandırma yükle.

        YAML bulunamazsa veya okunamazsa varsayılan değerlerle döner.
        Hata durumunda sessizce geçmez — loglar.

        Args:
            config_path: YAML dosya yolu. None ise varsayılan konum kullanılır.

        Returns:
            AirlockConfig instance
        """
        if config_path is None:
            config_path = DIRECTORIES["config"] / "airlock.yaml"

        if not config_path.exists():
            logger.warning(
                "Yapılandırma dosyası bulunamadı: %s — varsayılan değerler kullanılıyor",
                config_path,
            )
            return cls()

        try:
            import yaml  # noqa: PLC0415 — lazy import, Pi'de yüklü olmayabilir

            raw: Dict[str, Any] = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
        except Exception as exc:
            logger.error(
                "Yapılandırma dosyası okunamadı: %s — %s — varsayılan değerler kullanılıyor",
                config_path,
                exc,
            )
            return cls()

        return cls._from_dict(raw)

    @classmethod
    def _from_dict(cls, raw: Dict[str, Any]) -> AirlockConfig:
        """Ham YAML sözlüğünden AirlockConfig oluştur."""
        hw = raw.get("hardware", {})
        scan = raw.get("scanning", {})
        cdr = raw.get("cdr", {})
        arch = raw.get("archive", {})
        log = raw.get("logging", {})
        upd = raw.get("update", {})
        mnt = raw.get("mount", {})
        usbg = raw.get("usb_guard", {})

        archive_limits = ArchiveLimits(
            max_depth=arch.get("max_depth", ARCHIVE_LIMITS.max_depth),
            max_total_size_mb=arch.get("max_total_size_mb", ARCHIVE_LIMITS.max_total_size_mb),
            max_file_count=arch.get("max_file_count", ARCHIVE_LIMITS.max_file_count),
            max_single_file_mb=arch.get("max_single_file_mb", ARCHIVE_LIMITS.max_single_file_mb),
            compression_ratio_limit=arch.get(
                "compression_ratio_limit", ARCHIVE_LIMITS.compression_ratio_limit
            ),
            timeout_seconds=arch.get("timeout_seconds", ARCHIVE_LIMITS.timeout_seconds),
            encrypted_policy=arch.get("encrypted_policy", ARCHIVE_LIMITS.encrypted_policy),
        )

        clamav_socket_str = scan.get("clamav_socket", str(CLAMAV_SOCKET))

        return cls(
            version=raw.get("version", VERSION),
            codename=raw.get("codename", CODENAME),
            active_policy=raw.get("active_policy", "balanced"),
            # Donanım
            oled_enabled=hw.get("oled_enabled", True),
            oled_address=hw.get("oled_address", 0x3C),
            led_mode=hw.get("led_mode", "rgb"),
            audio_enabled=hw.get("audio_enabled", True),
            audio_volume=hw.get("audio_volume", 80),
            button_enabled=hw.get("button_enabled", True),
            button_pin=hw.get("button_pin", 21),
            # Tarama
            clamav_enabled=scan.get("clamav_enabled", True),
            clamav_socket=Path(clamav_socket_str),
            yara_enabled=scan.get("yara_enabled", True),
            yara_timeout=scan.get("yara_timeout", YARA_TIMEOUT_SECONDS),
            entropy_enabled=scan.get("entropy_enabled", True),
            magic_byte_check=scan.get("magic_byte_check", True),
            hash_check=scan.get("hash_check", True),
            # CDR
            pdf_dpi=cdr.get("pdf_dpi", PDF_DPI),
            jpeg_quality=cdr.get("jpeg_quality", JPEG_QUALITY),
            ocr_enabled=cdr.get("ocr_enabled", True),
            ocr_languages=cdr.get("ocr_languages", OCR_LANGUAGES),
            video_cdr=cdr.get("video_cdr", False),
            image_strip_metadata=cdr.get("image_strip_metadata", True),
            cdr_require_sandbox=cdr.get("require_sandbox", False),
            # Mount noktaları
            mount_source=mnt.get("source", "/mnt/airlock_source"),
            mount_target=mnt.get("target", "/mnt/airlock_target"),
            mount_update=mnt.get("update", "/mnt/airlock_update"),
            # Arşiv
            archive_limits=archive_limits,
            # Loglama
            log_level=log.get("level", LOG_LEVEL),
            log_max_size_mb=log.get("max_log_size_mb", LOG_MAX_SIZE_MB),
            log_max_files=log.get("max_log_files", LOG_MAX_FILES),
            log_to_console=log.get("log_to_console", True),
            # USBGuard
            usb_guard_enabled=usbg.get("enabled", False),
            usb_guard_mode=usbg.get("mode", "monitor"),
            # Güncelleme
            require_update_signature=upd.get("require_signature", True),
            update_public_key_path=Path(
                upd.get("public_key_path", str(DIRECTORIES["keys"] / "update_verify.pub"))
            ),
        )

    def validate(self) -> list[str]:
        """
        Yapılandırma değerlerini doğrula.

        Returns:
            Hata mesajları listesi. Boş liste = geçerli.
        """
        errors: list[str] = []

        if self.active_policy not in POLICIES:
            errors.append(
                f"Geçersiz politika: '{self.active_policy}'. "
                f"Geçerli: {list(POLICIES.keys())}"
            )

        if not 100 <= self.pdf_dpi <= 600:
            errors.append(f"PDF DPI aralık dışı: {self.pdf_dpi} (100-600 olmalı)")

        if not 50 <= self.jpeg_quality <= 100:
            errors.append(f"JPEG kalitesi aralık dışı: {self.jpeg_quality} (50-100 olmalı)")

        if not 0 <= self.audio_volume <= 100:
            errors.append(f"Ses seviyesi aralık dışı: {self.audio_volume} (0-100 olmalı)")

        if self.led_mode not in ("rgb", "neopixel"):
            errors.append(f"Geçersiz LED modu: '{self.led_mode}' (rgb/neopixel olmalı)")

        if self.archive_limits.max_depth < 1:
            errors.append("Arşiv max_depth en az 1 olmalı")

        if self.archive_limits.compression_ratio_limit < 10:
            errors.append("Sıkıştırma oranı limiti en az 10 olmalı")

        # USBGuard mod kontrolü
        if self.usb_guard_mode not in ("monitor", "enforce"):
            errors.append(
                f"Geçersiz usb_guard_mode: '{self.usb_guard_mode}' "
                "(monitor/enforce olmalı)"
            )

        # Mount noktaları — helper regex ile uyum kontrolü
        import re as _re  # noqa: PLC0415 — validate() nadir çağrılır
        _mount_re = _re.compile(r"^/mnt/airlock_(source|target|update)$")
        for mp_name, mp_val in [
            ("mount_source", self.mount_source),
            ("mount_target", self.mount_target),
            ("mount_update", self.mount_update),
        ]:
            if not _mount_re.match(mp_val):
                errors.append(
                    f"{mp_name} helper regex ile uyumsuz: '{mp_val}' — "
                    "sadece /mnt/airlock_(source|target|update) izinli"
                )

        if errors:
            for err in errors:
                logger.error("Yapılandırma hatası: %s", err)

        return errors

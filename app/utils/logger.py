"""
THE AIRLOCK v5.1.1 FORTRESS-HARDENED — Yapılandırılmış Loglama

Özellikler:
  - Dosya + konsol çıktısı
  - RotatingFileHandler (boyut bazlı rotasyon)
  - Yapılandırılmış format: zaman + seviye + modül + mesaj
  - config.py / AirlockConfig'den yapılandırma
  - Log dizini yoksa oluşturur
  - Birden fazla çağrıda aynı handler eklenmez

Kullanım:
    from app.utils.logger import setup_logging
    setup_logging()  # Varsayılan ayarlarla

    # veya config ile:
    setup_logging(config=cfg)

    # Modül içinde:
    import logging
    logger = logging.getLogger("AIRLOCK.SCANNER")
    logger.info("Tarama başladı")
"""

from __future__ import annotations

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from app.config import AirlockConfig

# ─────────────────────────────────────────────
# Sabitler
# ─────────────────────────────────────────────

_DEFAULT_LOG_DIR = Path("/opt/airlock/data/logs")
_DEFAULT_LOG_FILE = "airlock.log"
_DEFAULT_LEVEL = "INFO"
_DEFAULT_MAX_SIZE_MB = 50
_DEFAULT_MAX_FILES = 10

_LOG_FORMAT = (
    "%(asctime)s | %(levelname)-8s | %(name)-24s | %(message)s"
)
_LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# Handler ekleme koruması (birden fazla setup_logging çağrısında tekrarlama önleme)
_initialized: bool = False


# ─────────────────────────────────────────────
# Ana Fonksiyon
# ─────────────────────────────────────────────


def setup_logging(
    config: Optional[AirlockConfig] = None,
    log_dir: Optional[Path] = None,
    log_file: str = _DEFAULT_LOG_FILE,
    level: Optional[str] = None,
    max_size_mb: Optional[int] = None,
    max_files: Optional[int] = None,
    console: Optional[bool] = None,
) -> logging.Logger:
    """
    Uygulama genelinde loglama yapılandırmasını kur.

    AirlockConfig verilmişse değerler ondan okunur.
    Parametre olarak verilen değerler config'i geçersiz kılar (override).

    Args:
        config: AirlockConfig instance (opsiyonel)
        log_dir: Log dizini. None ise config veya varsayılan.
        log_file: Log dosya adı.
        level: Log seviyesi ("DEBUG", "INFO", "WARNING", "ERROR").
        max_size_mb: Dosya başına maksimum boyut (MB).
        max_files: Rotasyonda tutulacak dosya sayısı.
        console: Konsola da yazsın mı.

    Returns:
        Kök AIRLOCK logger'ı
    """
    global _initialized

    # Config'den değerler
    if config is not None:
        _log_dir = log_dir or Path(config.log_level).parent if False else _DEFAULT_LOG_DIR
        _level = level or config.log_level
        _max_size = max_size_mb if max_size_mb is not None else config.log_max_size_mb
        _max_files = max_files if max_files is not None else config.log_max_files
        _console = console if console is not None else config.log_to_console
    else:
        _log_dir = log_dir or _DEFAULT_LOG_DIR
        _level = level or _DEFAULT_LEVEL
        _max_size = max_size_mb if max_size_mb is not None else _DEFAULT_MAX_SIZE_MB
        _max_files = max_files if max_files is not None else _DEFAULT_MAX_FILES
        _console = console if console is not None else True

    # ── Dizin hazırlığı ──
    try:
        _log_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        # SD kart sorununda /tmp'ye fallback
        _log_dir = Path("/tmp")

    log_path = _log_dir / log_file

    # ── Seviye ──
    numeric_level = getattr(logging, _level.upper(), logging.INFO)

    # ── Kök logger (AIRLOCK namespace) ──
    root_logger = logging.getLogger("AIRLOCK")

    # Tekrar ekleme koruması
    if _initialized:
        root_logger.setLevel(numeric_level)
        return root_logger

    root_logger.setLevel(numeric_level)

    formatter = logging.Formatter(
        fmt=_LOG_FORMAT,
        datefmt=_LOG_DATE_FORMAT,
    )

    # ── Dosya handler (RotatingFileHandler) ──
    try:
        file_handler = RotatingFileHandler(
            filename=str(log_path),
            maxBytes=_max_size * 1024 * 1024,
            backupCount=_max_files,
            encoding="utf-8",
        )
        file_handler.setLevel(numeric_level)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)
    except OSError as exc:
        # Dosya handler kurulamazsa sadece konsola yaz
        sys.stderr.write(f"[AIRLOCK] Log dosyası açılamadı: {exc}\n")

    # ── Konsol handler ──
    if _console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(numeric_level)
        console_handler.setFormatter(formatter)
        root_logger.addHandler(console_handler)

    _initialized = True

    root_logger.info(
        "Loglama başlatıldı — seviye=%s, dosya=%s, max=%dMB x %d",
        _level, log_path, _max_size, _max_files,
    )

    return root_logger


def get_logger(name: str) -> logging.Logger:
    """
    Modül için AIRLOCK namespace altında logger döndür.

    Args:
        name: Modül adı (ör: "SCANNER", "CDR", "USB_GUARD")

    Returns:
        logging.Logger: AIRLOCK.{name} logger'ı

    Kullanım:
        logger = get_logger("SCANNER")
        logger.info("Tarama başladı")
    """
    return logging.getLogger(f"AIRLOCK.{name}")


def reset_logging() -> None:
    """
    Loglama durumunu sıfırla.

    Test ortamında veya yeniden yapılandırma için kullanılır.
    Tüm handler'ları kaldırır.
    """
    global _initialized

    root_logger = logging.getLogger("AIRLOCK")
    for handler in root_logger.handlers[:]:
        handler.close()
        root_logger.removeHandler(handler)

    _initialized = False

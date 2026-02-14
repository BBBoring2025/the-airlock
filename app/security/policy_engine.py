"""
THE AIRLOCK v5.0.8 FORTRESS-HARDENED — Merkezi Politika Karar Motoru

Tüm dosya işleme kararlarını merkezileştirir.
daemon.py'deki dağınık if/elif zinciri yerine tek bir karar noktası.

Karar akışı:
  1. Tehdit → QUARANTINE (politikadan bağımsız)
  2. Arşiv → policy.archive_handling'e göre BLOCK/CDR/COPY
  3. Tehlikeli uzantı → policy.unknown_extension'a göre BLOCK/QUARANTINE
  4. CDR desteklenen MIME → CDR
  5. Resim → policy.allow_images'a göre CDR/COPY/BLOCK
  6. Metin → policy.allow_text'e göre CDR/COPY/BLOCK
  7. Bilinmeyen tür → policy.unknown_extension'a göre COPY/BLOCK/QUARANTINE

Kullanım:
    from app.security.policy_engine import decide_file_action, FileAction
    action = decide_file_action(scan_result, mime, ext, policy, cdr_ok)
"""

from __future__ import annotations

import logging
from enum import Enum, auto
from pathlib import Path
from typing import Optional

from app.config import (
    CDR_IMAGE_TYPES,
    CDR_SUPPORTED,
    CDR_TEXT_TYPES,
    DANGEROUS_EXTENSIONS,
    SecurityPolicy,
)

logger = logging.getLogger("AIRLOCK.POLICY")

# Arşiv MIME türleri — is_archive flag'i olmasa da MIME'dan tanınır
_ARCHIVE_MIME_TYPES = frozenset({
    "application/zip",
    "application/x-zip-compressed",
    "application/x-tar",
    "application/gzip",
    "application/x-gzip",
    "application/x-bzip2",
    "application/x-xz",
    "application/x-7z-compressed",
    "application/x-rar-compressed",
    "application/vnd.rar",
})


class FileAction(Enum):
    """Dosya için alınacak karar."""

    COPY = auto()           # Doğrudan kopyala (temiz)
    CDR_DOCUMENT = auto()   # PDF/Office CDR uygula
    CDR_IMAGE = auto()      # Resim metadata strip
    CDR_TEXT = auto()        # Metin encoding temizleme
    QUARANTINE = auto()     # Karantinaya al
    BLOCK = auto()          # Engelle (rapora yaz, kopyalama)


def decide_file_action(
    *,
    is_threat: bool,
    mime_type: str,
    extension: str,
    policy: SecurityPolicy,
    is_archive: bool = False,
    cdr_available: bool = True,
) -> FileAction:
    """
    Tek dosya için politika kararı ver.

    Args:
        is_threat: Tarama sonucu tehdit tespit edildi mi?
        mime_type: Dosyanın MIME türü.
        extension: Dosya uzantısı (noktalı, ör: '.pdf').
        policy: Aktif güvenlik politikası.
        is_archive: Dosya arşiv mi? (zip, tar, 7z, rar)
        cdr_available: CDR araçları (gs, soffice vb.) mevcut mu?

    Returns:
        FileAction: Uygulanacak aksiyon.
    """
    ext_lower = extension.lower()

    # ── Kural 1: Tehdit → her zaman QUARANTINE ──
    if is_threat:
        logger.info("KARAR: QUARANTINE — tehdit tespit edildi (mime=%s)", mime_type)
        return FileAction.QUARANTINE

    # ── Kural 2: Arşiv → politikaya göre ──
    if is_archive:
        if policy.archive_handling == "block":
            logger.info("KARAR: BLOCK — arşiv engellendi (politika=%s)", policy.name)
            return FileAction.BLOCK
        # "extract" veya "extract_cdr" → daemon arşivi açıp her dosyayı ayrı işleyecek
        # Bu fonksiyon arşiv içeriğini değil, arşivin kendisini değerlendirir
        logger.info("KARAR: COPY — arşiv işlenecek (politika=%s)", policy.name)
        return FileAction.COPY

    # ── Kural 3: Tehlikeli uzantı → politikaya göre ──
    if ext_lower in DANGEROUS_EXTENSIONS:
        logger.info("KARAR: BLOCK — tehlikeli uzantı: %s", ext_lower)
        return FileAction.BLOCK

    # ── Kural 4: CDR desteklenen doküman (PDF/Office) ──
    if mime_type in CDR_SUPPORTED:
        # Politika izin veriyor mu?
        if mime_type == "application/pdf" and not policy.allow_pdf:
            logger.info("KARAR: BLOCK — PDF engelli (politika=%s)", policy.name)
            return FileAction.BLOCK
        if mime_type != "application/pdf" and not policy.allow_office:
            logger.info("KARAR: BLOCK — Office engelli (politika=%s)", policy.name)
            return FileAction.BLOCK

        if cdr_available:
            logger.info("KARAR: CDR_DOCUMENT — mime=%s", mime_type)
            return FileAction.CDR_DOCUMENT
        else:
            # CDR araçları yok → politikaya göre
            if policy.cdr_on_failure == "quarantine":
                return FileAction.QUARANTINE
            elif policy.cdr_on_failure == "block":
                return FileAction.BLOCK
            else:
                return FileAction.COPY

    # ── Kural 5: Resim ──
    if mime_type in CDR_IMAGE_TYPES:
        if not policy.allow_images:
            logger.info("KARAR: BLOCK — resim engelli (politika=%s)", policy.name)
            return FileAction.BLOCK
        if cdr_available:
            logger.info("KARAR: CDR_IMAGE — mime=%s", mime_type)
            return FileAction.CDR_IMAGE
        else:
            return FileAction.COPY

    # ── Kural 6: Metin ──
    if mime_type in CDR_TEXT_TYPES:
        if not policy.allow_text:
            logger.info("KARAR: BLOCK — metin engelli (politika=%s)", policy.name)
            return FileAction.BLOCK
        logger.info("KARAR: CDR_TEXT — mime=%s", mime_type)
        return FileAction.CDR_TEXT

    # ── Kural 7: Arşiv MIME türü (is_archive flag'i olmasa bile) ──
    if mime_type in _ARCHIVE_MIME_TYPES:
        if policy.archive_handling == "block":
            logger.info(
                "KARAR: BLOCK — arsiv MIME (is_archive=False, mime=%s, politika=%s)",
                mime_type, policy.name,
            )
            return FileAction.BLOCK
        logger.info(
            "KARAR: COPY — arsiv MIME islenecek (mime=%s, politika=%s)",
            mime_type, policy.name,
        )
        return FileAction.COPY

    # ── Kural 8: Bilinmeyen tür → politikaya göre ──
    unknown_policy = policy.unknown_extension
    if unknown_policy == "block":
        logger.info("KARAR: BLOCK — bilinmeyen tür (politika=%s, mime=%s)", policy.name, mime_type)
        return FileAction.BLOCK
    elif unknown_policy == "quarantine":
        logger.info("KARAR: QUARANTINE — bilinmeyen tür (politika=%s, mime=%s)", policy.name, mime_type)
        return FileAction.QUARANTINE
    else:
        # "allow" veya başka → kopyala
        logger.info("KARAR: COPY — bilinmeyen tür izinli (politika=%s, mime=%s)", policy.name, mime_type)
        return FileAction.COPY

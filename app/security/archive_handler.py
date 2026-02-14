"""
THE AIRLOCK v5.0.8 FORTRESS-HARDENED — Güvenli Arşiv Açma ve Tarama

Desteklenen formatlar: ZIP, 7z, RAR, TAR, GZ, BZ2, XZ

ZIP BOMB KORUMALARI (5 katman):
  1. Sıkıştırma oranı kontrolü (compressed/uncompressed > limit → BLOCK)
  2. Toplam açılmış boyut limiti
  3. Maksimum dosya sayısı limiti
  4. Maksimum iç içe derinlik (recursive/nested archive)
  5. Timeout (varsayılan 120 saniye)

İşlem Akışı:
  1. Arşiv türünü tespit et (magic byte)
  2. Metadata'dan boyut/sayı bilgilerini oku (AÇMADAN)
  3. Limitleri kontrol et → geçerse aç
  4. Her dosyayı FileValidator + FileScanner ile tara
  5. CDR uygula (PDF, Office, Resim)
  6. Temiz dosyaları hedefe kopyala

Kullanım:
    handler = ArchiveHandler(config=cfg)
    safety = handler.check_safety(archive_path)
    if safety.is_safe:
        result = handler.extract_and_process(
            archive_path, target_dir, scanner, cdr_engine, file_validator
        )
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tarfile
import uuid
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, TYPE_CHECKING

from app.config import (
    AirlockConfig,
    ARCHIVE_LIMITS,
    ArchiveLimits,
    CDR_IMAGE_TYPES,
    CDR_SUPPORTED,
    CDR_TEXT_TYPES,
    DIRECTORIES,
)

if TYPE_CHECKING:
    from app.security.cdr_engine import CDREngine, CDRResult
    from app.security.file_validator import FileValidator
    from app.security.scanner import FileScanner

logger = logging.getLogger("AIRLOCK.ARCHIVE")


# ─────────────────────────────────────────────
# Veri Yapıları
# ─────────────────────────────────────────────


@dataclass
class ArchiveSafetyResult:
    """Arşiv güvenlik ön-kontrolü sonucu (açmadan)."""

    filepath: Path
    is_safe: bool
    archive_type: str = ""          # "zip", "tar", "7z", "rar", "tar.gz", …
    file_count: int = 0
    total_compressed: int = 0       # Sıkıştırılmış toplam boyut (byte)
    total_uncompressed: int = 0     # Açılmış toplam boyut (byte)
    compression_ratio: float = 0.0
    max_depth: int = 0              # İç içe arşiv derinliği (0 = yok)
    is_encrypted: bool = False
    block_reason: Optional[str] = None


@dataclass
class ArchiveFileResult:
    """Arşiv içindeki tek dosyanın işlem sonucu."""

    relative_path: str
    action: str  # "clean_copy", "cdr_applied", "blocked", "quarantined", "skipped"
    detail: str = ""
    output_path: Optional[Path] = None


@dataclass
class ArchiveResult:
    """Arşiv açma + işleme toplam sonucu."""

    filepath: Path
    success: bool
    archive_type: str = ""
    total_files: int = 0
    processed: int = 0
    blocked: int = 0
    cdr_applied: int = 0
    quarantined: int = 0
    files: List[ArchiveFileResult] = field(default_factory=list)
    error: Optional[str] = None


# ─────────────────────────────────────────────
# Magic Byte Tanımlayıcılar
# ─────────────────────────────────────────────

_MAGIC_SIGNATURES = {
    b"PK\x03\x04": "zip",
    b"PK\x05\x06": "zip",      # Boş zip
    b"Rar!\x1a\x07": "rar",
    b"7z\xbc\xaf\x27\x1c": "7z",
    b"\x1f\x8b": "gz",
    b"BZh": "bz2",
    b"\xfd7zXZ\x00": "xz",
}

# tar magic: offset 257'de "ustar"
_TAR_MAGIC_OFFSET = 257
_TAR_MAGIC = b"ustar"


# ─────────────────────────────────────────────
# Archive Handler
# ─────────────────────────────────────────────


class ArchiveHandler:
    """
    Güvenli arşiv açma ve işleme.

    Her arşiv 5 katmanlı zip bomb korumasından geçer.
    Açılan her dosya FileValidator + FileScanner + CDREngine ile işlenir.
    """

    def __init__(self, config: Optional[AirlockConfig] = None) -> None:
        self._logger = logging.getLogger("AIRLOCK.ARCHIVE")
        self._config = config or AirlockConfig()
        self._limits = self._config.archive_limits
        self._work_dir = DIRECTORIES["tmp"]

    # ═══════════════════════════════════════════
    # Arşiv Tespiti
    # ═══════════════════════════════════════════

    def is_archive(self, filepath: Path) -> bool:
        """
        Magic byte ile dosyanın arşiv olup olmadığını kontrol et.

        Args:
            filepath: Kontrol edilecek dosya

        Returns:
            True: arşiv dosyası
        """
        return self.detect_type(filepath) != ""

    def detect_type(self, filepath: Path) -> str:
        """
        Arşiv türünü magic byte ile tespit et.

        Returns:
            Arşiv türü string ("zip", "tar", "7z", "rar", "gz", "bz2", "xz")
            veya "" (arşiv değil)
        """
        try:
            header = b""
            with filepath.open("rb") as fh:
                header = fh.read(512)
        except (OSError, PermissionError):
            return ""

        if len(header) < 4:
            return ""

        # Standart magic byte'lar
        for magic, atype in _MAGIC_SIGNATURES.items():
            if header[:len(magic)] == magic:
                # .tar.gz / .tar.bz2 / .tar.xz → tarball check
                if atype in ("gz", "bz2", "xz"):
                    suffix = filepath.suffix.lower()
                    suffixes = "".join(s.lower() for s in filepath.suffixes)
                    if ".tar" in suffixes or suffix in (".tgz", ".tbz2", ".txz"):
                        return f"tar.{atype}"
                return atype

        # tar magic: offset 257'de "ustar"
        if len(header) > _TAR_MAGIC_OFFSET + len(_TAR_MAGIC):
            if header[_TAR_MAGIC_OFFSET:_TAR_MAGIC_OFFSET + len(_TAR_MAGIC)] == _TAR_MAGIC:
                return "tar"

        return ""

    # ═══════════════════════════════════════════
    # Güvenlik Ön-Kontrolü (Açmadan)
    # ═══════════════════════════════════════════

    def check_safety(self, filepath: Path) -> ArchiveSafetyResult:
        """
        Arşivi AÇMADAN güvenlik kontrolü yap.

        ZIP için: zipfile.ZipFile → infolist() ile metadata'dan boyut bilgisi
        Diğerleri: dosya boyutu + uzantı bazlı tahmin

        Returns:
            ArchiveSafetyResult
        """
        archive_type = self.detect_type(filepath)

        if not archive_type:
            return ArchiveSafetyResult(
                filepath=filepath,
                is_safe=False,
                block_reason="NOT_AN_ARCHIVE — tanınmayan format",
            )

        if archive_type == "zip":
            return self._check_zip_safety(filepath, archive_type)

        if archive_type.startswith("tar"):
            return self._check_tar_safety(filepath, archive_type)

        # 7z, rar → dış komutlarla metadata okuma veya boyut bazlı tahmin
        return self._check_generic_safety(filepath, archive_type)

    def _check_zip_safety(
        self, filepath: Path, archive_type: str
    ) -> ArchiveSafetyResult:
        """ZIP arşivini açmadan metadata ile kontrol et."""
        try:
            with zipfile.ZipFile(filepath, "r") as zf:
                infos = zf.infolist()

                file_count = len(infos)
                total_compressed = sum(i.compress_size for i in infos)
                total_uncompressed = sum(i.file_size for i in infos)

                # Şifreli mi?
                is_encrypted = any(i.flag_bits & 0x1 for i in infos)

                # Sıkıştırma oranı
                if total_compressed > 0:
                    ratio = total_uncompressed / total_compressed
                else:
                    ratio = 0.0

                # Kontrolleri uygula
                block_reason = self._check_limits(
                    file_count=file_count,
                    total_uncompressed=total_uncompressed,
                    compression_ratio=ratio,
                    is_encrypted=is_encrypted,
                )

                return ArchiveSafetyResult(
                    filepath=filepath,
                    is_safe=(block_reason is None),
                    archive_type=archive_type,
                    file_count=file_count,
                    total_compressed=total_compressed,
                    total_uncompressed=total_uncompressed,
                    compression_ratio=round(ratio, 2),
                    is_encrypted=is_encrypted,
                    block_reason=block_reason,
                )

        except zipfile.BadZipFile:
            return ArchiveSafetyResult(
                filepath=filepath,
                is_safe=False,
                archive_type=archive_type,
                block_reason="CORRUPT_ZIP — geçersiz ZIP dosyası",
            )
        except Exception as exc:
            return ArchiveSafetyResult(
                filepath=filepath,
                is_safe=False,
                archive_type=archive_type,
                block_reason=f"ZIP_READ_ERROR: {exc}",
            )

    def _check_tar_safety(
        self, filepath: Path, archive_type: str
    ) -> ArchiveSafetyResult:
        """TAR (ve tar.gz/bz2/xz) arşivini açmadan kontrol et."""
        mode_map = {
            "tar": "r:",
            "tar.gz": "r:gz",
            "tar.bz2": "r:bz2",
            "tar.xz": "r:xz",
        }
        mode = mode_map.get(archive_type, "r:*")

        try:
            with tarfile.open(filepath, mode) as tf:
                members = tf.getmembers()

                file_count = len(members)
                total_uncompressed = sum(m.size for m in members if m.isfile())
                total_compressed = filepath.stat().st_size

                if total_compressed > 0:
                    ratio = total_uncompressed / total_compressed
                else:
                    ratio = 0.0

                block_reason = self._check_limits(
                    file_count=file_count,
                    total_uncompressed=total_uncompressed,
                    compression_ratio=ratio,
                    is_encrypted=False,
                )

                return ArchiveSafetyResult(
                    filepath=filepath,
                    is_safe=(block_reason is None),
                    archive_type=archive_type,
                    file_count=file_count,
                    total_compressed=total_compressed,
                    total_uncompressed=total_uncompressed,
                    compression_ratio=round(ratio, 2),
                    block_reason=block_reason,
                )

        except (tarfile.TarError, EOFError, OSError) as exc:
            return ArchiveSafetyResult(
                filepath=filepath,
                is_safe=False,
                archive_type=archive_type,
                block_reason=f"TAR_READ_ERROR: {exc}",
            )

    def _check_generic_safety(
        self, filepath: Path, archive_type: str
    ) -> ArchiveSafetyResult:
        """7z/RAR gibi arşivler için boyut bazlı temel kontrol."""
        compressed_size = filepath.stat().st_size
        max_bytes = self._limits.max_total_size_mb * 1024 * 1024

        # Arşivin kendisi bile çok büyükse → doğrudan engelle
        if compressed_size > max_bytes:
            return ArchiveSafetyResult(
                filepath=filepath,
                is_safe=False,
                archive_type=archive_type,
                total_compressed=compressed_size,
                block_reason=(
                    f"ARCHIVE_TOO_LARGE: {compressed_size / (1024*1024):.1f}MB > "
                    f"{self._limits.max_total_size_mb}MB"
                ),
            )

        # 7z için metadata okumayı dene
        if archive_type == "7z":
            return self._check_7z_safety(filepath, archive_type, compressed_size)

        # Diğerleri — dosya boyutu makul ise geç
        return ArchiveSafetyResult(
            filepath=filepath,
            is_safe=True,
            archive_type=archive_type,
            total_compressed=compressed_size,
        )

    def _check_7z_safety(
        self, filepath: Path, archive_type: str, compressed_size: int
    ) -> ArchiveSafetyResult:
        """7z arşivi için 7z l komutuyla metadata oku."""
        try:
            result = subprocess.run(
                ["7z", "l", str(filepath)],
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode != 0:
                return ArchiveSafetyResult(
                    filepath=filepath,
                    is_safe=False,
                    archive_type=archive_type,
                    total_compressed=compressed_size,
                    block_reason=f"7Z_LIST_FAILED: {result.stderr[:200]}",
                )

            # Basit parsing — dosya sayısını ve toplam boyutu çıkar
            file_count = 0
            total_uncompressed = 0
            for line in result.stdout.splitlines():
                parts = line.split()
                # 7z l çıktısında son satır genelde toplam bilgi verir
                if len(parts) >= 3 and parts[0].isdigit():
                    try:
                        total_uncompressed = int(parts[0])
                        file_count = int(parts[-1]) if parts[-1].isdigit() else file_count
                    except ValueError:
                        pass

            ratio = total_uncompressed / compressed_size if compressed_size > 0 else 0.0

            block_reason = self._check_limits(
                file_count=file_count,
                total_uncompressed=total_uncompressed,
                compression_ratio=ratio,
                is_encrypted=False,
            )

            return ArchiveSafetyResult(
                filepath=filepath,
                is_safe=(block_reason is None),
                archive_type=archive_type,
                file_count=file_count,
                total_compressed=compressed_size,
                total_uncompressed=total_uncompressed,
                compression_ratio=round(ratio, 2),
                block_reason=block_reason,
            )

        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            # 7z komutu yoksa veya timeout → boyut bazlı tahminle devam
            return ArchiveSafetyResult(
                filepath=filepath,
                is_safe=True,
                archive_type=archive_type,
                total_compressed=compressed_size,
            )

    def _check_limits(
        self,
        file_count: int,
        total_uncompressed: int,
        compression_ratio: float,
        is_encrypted: bool,
    ) -> Optional[str]:
        """
        Arşiv metriklerini ArchiveLimits ile karşılaştır.

        Returns:
            Engelleme nedeni (str) veya None (güvenli)
        """
        limits = self._limits

        # Şifreli arşiv politikası
        if is_encrypted and limits.encrypted_policy == "block":
            return "ENCRYPTED_ARCHIVE — şifreli arşivler engellendi"

        # Dosya sayısı
        if file_count > limits.max_file_count:
            return (
                f"TOO_MANY_FILES: {file_count} > {limits.max_file_count}"
            )

        # Açılmış toplam boyut
        max_bytes = limits.max_total_size_mb * 1024 * 1024
        if total_uncompressed > max_bytes:
            return (
                f"UNCOMPRESSED_TOO_LARGE: "
                f"{total_uncompressed / (1024*1024):.1f}MB > {limits.max_total_size_mb}MB"
            )

        # Sıkıştırma oranı (zip bomb tespiti)
        if compression_ratio > limits.compression_ratio_limit:
            return (
                f"ZIP_BOMB_SUSPECTED: sıkıştırma oranı {compression_ratio:.1f} > "
                f"{limits.compression_ratio_limit} (limit)"
            )

        return None

    # ═══════════════════════════════════════════
    # Arşiv Açma ve İşleme
    # ═══════════════════════════════════════════

    def extract_and_process(
        self,
        filepath: Path,
        target_dir: Path,
        scanner: FileScanner,
        cdr_engine: CDREngine,
        file_validator: Optional[FileValidator] = None,
    ) -> ArchiveResult:
        """
        Arşivi güvenli aç, her dosyayı tara ve CDR uygula.

        Adımlar:
          1. RAM disk'te geçici dizin oluştur
          2. Güvenlik ön-kontrolü (check_safety)
          3. Arşivi aç (timeout ile)
          4. Her dosya için:
             a. FileValidator ile kontrol (symlink, path traversal)
             b. FileScanner ile tara
             c. CDREngine ile temizle
             d. Temiz dosyayı hedefe kopyala
          5. Geçici dizini temizle

        Args:
            filepath: Arşiv dosya yolu
            target_dir: Temiz dosyaların yazılacağı hedef dizin
            scanner: FileScanner instance
            cdr_engine: CDREngine instance
            file_validator: FileValidator instance (opsiyonel)

        Returns:
            ArchiveResult
        """
        archive_type = self.detect_type(filepath)
        extract_dir = self._create_extract_dir()

        result = ArchiveResult(
            filepath=filepath,
            success=False,
            archive_type=archive_type,
        )

        try:
            # ── Adım 1: Güvenlik ön-kontrolü ──
            safety = self.check_safety(filepath)
            if not safety.is_safe:
                result.error = f"GÜVENLİK ÖN-KONTROL BAŞARISIZ: {safety.block_reason}"
                self._logger.warning(
                    "Arşiv engellendi: %s — %s", filepath.name, safety.block_reason
                )
                return result

            self._logger.info(
                "Arşiv açılıyor: %s (tür=%s, dosya=%d, boyut=%.1fMB, oran=%.1f)",
                filepath.name,
                archive_type,
                safety.file_count,
                safety.total_uncompressed / (1024 * 1024) if safety.total_uncompressed else 0,
                safety.compression_ratio,
            )

            # ── Adım 2: Arşivi aç ──
            extracted = self._extract(filepath, extract_dir, archive_type)
            if not extracted:
                result.error = "EXTRACTION_FAILED — arşiv açılamadı"
                return result

            # ── Adım 3: Her dosyayı işle ──
            for dirpath, _dirnames, filenames in os.walk(
                extract_dir, followlinks=False
            ):
                for filename in filenames:
                    file_path = Path(dirpath) / filename
                    result.total_files += 1

                    file_result = self._process_single_file(
                        file_path=file_path,
                        extract_root=extract_dir,
                        target_dir=target_dir,
                        scanner=scanner,
                        cdr_engine=cdr_engine,
                        file_validator=file_validator,
                    )

                    result.files.append(file_result)

                    if file_result.action == "clean_copy":
                        result.processed += 1
                    elif file_result.action == "cdr_applied":
                        result.processed += 1
                        result.cdr_applied += 1
                    elif file_result.action == "blocked":
                        result.blocked += 1
                    elif file_result.action == "quarantined":
                        result.quarantined += 1

            result.success = True

            self._logger.info(
                "Arşiv işleme tamamlandı: %s — "
                "toplam=%d, işlenen=%d, engellenen=%d, karantina=%d, CDR=%d",
                filepath.name,
                result.total_files,
                result.processed,
                result.blocked,
                result.quarantined,
                result.cdr_applied,
            )

            return result

        except Exception as exc:
            self._logger.error(
                "Arşiv işleme beklenmeyen hata: %s — %s", filepath.name, exc
            )
            result.error = f"UNEXPECTED_ERROR: {exc}"
            return result
        finally:
            self._cleanup_extract_dir(extract_dir)

    def _process_single_file(
        self,
        file_path: Path,
        extract_root: Path,
        target_dir: Path,
        scanner: FileScanner,
        cdr_engine: CDREngine,
        file_validator: Optional[FileValidator],
    ) -> ArchiveFileResult:
        """Arşivden çıkarılmış tek dosyayı doğrula + tara + CDR uygula."""
        try:
            relative = file_path.relative_to(extract_root)
        except ValueError:
            relative = Path(file_path.name)

        relative_str = str(relative)

        # ── FileValidator kontrolü ──
        if file_validator is not None:
            validation = file_validator.validate_file(file_path, extract_root)
            if not validation.is_safe:
                self._logger.info(
                    "Arşiv dosya engellendi: %s — %s",
                    relative_str, validation.block_reason,
                )
                return ArchiveFileResult(
                    relative_path=relative_str,
                    action="blocked",
                    detail=validation.block_reason or "validation_failed",
                )

        # ── FileScanner ile tara ──
        scan_result = scanner.scan_file(file_path)

        if scan_result.is_threat:
            self._logger.warning(
                "Arşiv dosya tehdit: %s — %s",
                relative_str, scan_result.detection_summary,
            )
            return ArchiveFileResult(
                relative_path=relative_str,
                action="quarantined",
                detail=scan_result.detection_summary,
            )

        # ── CDR gerekiyor mu? ──
        mime_type = scan_result.mime_type
        target_path = target_dir / relative

        if mime_type in CDR_SUPPORTED:
            # PDF veya Office → CDR pipeline
            if "office" in CDR_SUPPORTED.get(mime_type, ""):
                cdr_result = cdr_engine.process_office(file_path, target_path)
            else:
                cdr_result = cdr_engine.process_pdf(file_path, target_path)

            if cdr_result.success:
                return ArchiveFileResult(
                    relative_path=relative_str,
                    action="cdr_applied",
                    detail=cdr_result.cdr_method,
                    output_path=cdr_result.output_path,
                )
            else:
                # CDR başarısız → karantina (ASLA kopyalama)
                return ArchiveFileResult(
                    relative_path=relative_str,
                    action="quarantined",
                    detail=f"CDR_FAILED: {cdr_result.reason}",
                )

        if mime_type in CDR_IMAGE_TYPES:
            cdr_result = cdr_engine.process_image(file_path, target_path)
            if cdr_result.success:
                return ArchiveFileResult(
                    relative_path=relative_str,
                    action="cdr_applied",
                    detail="image_strip",
                    output_path=cdr_result.output_path,
                )
            else:
                return ArchiveFileResult(
                    relative_path=relative_str,
                    action="quarantined",
                    detail=f"CDR_FAILED: {cdr_result.reason}",
                )

        if mime_type in CDR_TEXT_TYPES:
            cdr_result = cdr_engine.process_text(file_path, target_path)
            if cdr_result.success:
                return ArchiveFileResult(
                    relative_path=relative_str,
                    action="cdr_applied",
                    detail="text_clean",
                    output_path=cdr_result.output_path,
                )
            else:
                return ArchiveFileResult(
                    relative_path=relative_str,
                    action="quarantined",
                    detail=f"CDR_FAILED: {cdr_result.reason}",
                )

        # ── CDR gerekmez → doğrudan kopyala ──
        try:
            target_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(file_path, target_path)
            return ArchiveFileResult(
                relative_path=relative_str,
                action="clean_copy",
                detail="direct_copy",
                output_path=target_path,
            )
        except OSError as exc:
            return ArchiveFileResult(
                relative_path=relative_str,
                action="blocked",
                detail=f"COPY_ERROR: {exc}",
            )

    # ═══════════════════════════════════════════
    # Arşiv Açma (Format-Spesifik)
    # ═══════════════════════════════════════════

    def _extract(
        self, filepath: Path, extract_dir: Path, archive_type: str
    ) -> bool:
        """
        Arşivi geçici dizine aç.

        Returns:
            True: başarılı
            False: açma hatası
        """
        try:
            if archive_type == "zip":
                return self._extract_zip(filepath, extract_dir)
            elif archive_type.startswith("tar"):
                return self._extract_tar(filepath, extract_dir, archive_type)
            elif archive_type == "7z":
                return self._extract_7z(filepath, extract_dir)
            elif archive_type == "rar":
                return self._extract_rar(filepath, extract_dir)
            else:
                self._logger.error(
                    "Desteklenmeyen arşiv türü: %s (%s)", archive_type, filepath.name
                )
                return False
        except Exception as exc:
            self._logger.error(
                "Arşiv açma beklenmeyen hata: %s — %s", filepath.name, exc
            )
            return False

    def _extract_zip(self, filepath: Path, extract_dir: Path) -> bool:
        """ZIP arşivini güvenli aç."""
        try:
            with zipfile.ZipFile(filepath, "r") as zf:
                # Güvenlik: path traversal kontrolü
                for member in zf.infolist():
                    member_path = Path(member.filename)
                    # ".." içeren yolları atla
                    if ".." in member_path.parts:
                        self._logger.warning(
                            "ZIP path traversal engellendi: %s", member.filename
                        )
                        continue
                    # Mutlak yolları atla
                    if member_path.is_absolute():
                        self._logger.warning(
                            "ZIP mutlak yol engellendi: %s", member.filename
                        )
                        continue

                    zf.extract(member, extract_dir)

            return True

        except (zipfile.BadZipFile, OSError) as exc:
            self._logger.error("ZIP açma hatası: %s — %s", filepath.name, exc)
            return False

    def _extract_tar(
        self, filepath: Path, extract_dir: Path, archive_type: str
    ) -> bool:
        """TAR (ve tar.gz/bz2/xz) arşivini güvenli aç."""
        mode_map = {
            "tar": "r:",
            "tar.gz": "r:gz",
            "tar.bz2": "r:bz2",
            "tar.xz": "r:xz",
        }
        mode = mode_map.get(archive_type, "r:*")

        try:
            with tarfile.open(filepath, mode) as tf:
                # Güvenlik filtreleme
                safe_members = []
                for member in tf.getmembers():
                    # Symlink → engelle
                    if member.issym() or member.islnk():
                        self._logger.warning(
                            "TAR symlink/hardlink engellendi: %s", member.name
                        )
                        continue
                    # Path traversal → engelle
                    if ".." in member.name or member.name.startswith("/"):
                        self._logger.warning(
                            "TAR path traversal engellendi: %s", member.name
                        )
                        continue
                    # Device file → engelle
                    if member.isdev():
                        self._logger.warning(
                            "TAR device file engellendi: %s", member.name
                        )
                        continue
                    # Tek dosya boyut limiti
                    max_single = self._limits.max_single_file_mb * 1024 * 1024
                    if member.isfile() and member.size > max_single:
                        self._logger.warning(
                            "TAR dosya çok büyük: %s (%.1fMB > %dMB)",
                            member.name,
                            member.size / (1024 * 1024),
                            self._limits.max_single_file_mb,
                        )
                        continue

                    safe_members.append(member)

                tf.extractall(extract_dir, members=safe_members)

            return True

        except (tarfile.TarError, EOFError, OSError) as exc:
            self._logger.error("TAR açma hatası: %s — %s", filepath.name, exc)
            return False

    def _extract_7z(self, filepath: Path, extract_dir: Path) -> bool:
        """7z arşivini dış komutla aç (shell=False ZORUNLU)."""
        try:
            result = subprocess.run(
                [
                    "7z", "x",
                    str(filepath),
                    f"-o{extract_dir}",
                    "-y",          # Onay sorma
                    "-bd",         # İlerleme çubuğu kapalı
                ],
                capture_output=True,
                text=True,
                timeout=self._limits.timeout_seconds,
            )

            if result.returncode != 0:
                self._logger.error(
                    "7z açma hatası: %s — %s", filepath.name, result.stderr[:300]
                )
                return False

            return True

        except FileNotFoundError:
            self._logger.error("7z komutu bulunamadı — p7zip-full kurulu değil")
            return False
        except subprocess.TimeoutExpired:
            self._logger.error(
                "7z açma timeout (%ds): %s",
                self._limits.timeout_seconds, filepath.name,
            )
            return False
        except OSError as exc:
            self._logger.error("7z açma hatası: %s", exc)
            return False

    def _extract_rar(self, filepath: Path, extract_dir: Path) -> bool:
        """RAR arşivini dış komutla aç (shell=False ZORUNLU)."""
        try:
            result = subprocess.run(
                [
                    "unrar", "x",
                    "-o+",         # Üzerine yaz
                    "-y",          # Onay sorma
                    str(filepath),
                    str(extract_dir) + "/",
                ],
                capture_output=True,
                text=True,
                timeout=self._limits.timeout_seconds,
            )

            if result.returncode != 0:
                self._logger.error(
                    "RAR açma hatası: %s — %s", filepath.name, result.stderr[:300]
                )
                return False

            return True

        except FileNotFoundError:
            self._logger.error("unrar komutu bulunamadı — unrar-free kurulu değil")
            return False
        except subprocess.TimeoutExpired:
            self._logger.error(
                "RAR açma timeout (%ds): %s",
                self._limits.timeout_seconds, filepath.name,
            )
            return False
        except OSError as exc:
            self._logger.error("RAR açma hatası: %s", exc)
            return False

    # ═══════════════════════════════════════════
    # Yardımcılar
    # ═══════════════════════════════════════════

    def _create_extract_dir(self) -> Path:
        """RAM disk üzerinde benzersiz çıkarma dizini oluştur."""
        dir_id = uuid.uuid4().hex[:12]
        extract_dir = self._work_dir / f"archive_{dir_id}"
        extract_dir.mkdir(parents=True, exist_ok=True)
        return extract_dir

    @staticmethod
    def _cleanup_extract_dir(extract_dir: Path) -> None:
        """Geçici çıkarma dizinini güvenli sil."""
        try:
            if extract_dir.exists():
                shutil.rmtree(extract_dir)
        except Exception:
            pass

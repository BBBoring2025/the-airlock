"""
THE AIRLOCK v5.0.8 FORTRESS-HARDENED — KATMAN 4: Dosya Ön Kontrolleri

Tarama öncesi güvenlik kontrolleri:
  1. Symlink tespiti → ENGELLE (istasyon dosya sistemi sızıntısı riski)
  2. Path traversal (../../etc/passwd gibi isimler) → ENGELLE
  3. Özel karakter / uzun dosya adı kontrolü
  4. Toplam dosya sayısı ve boyut limiti
  5. Hardlink kontrolü (inode manipulation)
  6. Device file / FIFO / socket kontrolü
  7. Tehlikeli uzantı kontrolü

Hedef USB koruması:
  - safe_copy_no_symlink: Hedef USB'ye yazarken symlink kontrolü
  - safe_mkdir_no_symlink: Dizin oluştururken symlink kontrolü
  - validate_target_path: Her parent dizini target_root içinde mi kontrolü

GÜVENLİK KURALI: Symlink → ASLA takip etme → Engelle + logla

Kullanım:
    validator = FileValidator(policy=policy)
    result = validator.validate_file(filepath, source_root)
    batch = validator.validate_batch(source_root)

    # Hedef USB'ye güvenli yazma:
    safe_copy_no_symlink(source, target, target_root)
    safe_mkdir_no_symlink(target_dir, target_root)
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from app.config import (
    DANGEROUS_EXTENSIONS,
    MAX_FILENAME_LENGTH,
    MAX_PATH_DEPTH,
    MAX_TOTAL_FILES,
    MAX_TOTAL_SIZE_GB,
    SecurityPolicy,
)

logger = logging.getLogger("AIRLOCK.FILE_VALIDATOR")


# ─────────────────────────────────────────────
# Veri Yapıları
# ─────────────────────────────────────────────


@dataclass
class ValidationResult:
    """Tek dosya doğrulama sonucu."""

    filepath: Path
    is_safe: bool
    block_reason: Optional[str] = None
    warnings: List[str] = field(default_factory=list)


@dataclass
class BatchValidationResult:
    """Toplu doğrulama sonucu."""

    source_root: Path
    total_files: int = 0
    total_size_bytes: int = 0
    safe_files: List[Path] = field(default_factory=list)
    blocked_files: List[ValidationResult] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    is_within_limits: bool = True
    limit_violation: Optional[str] = None


# ─────────────────────────────────────────────
# Tehlikeli Dosya Adı Pattern'leri
# ─────────────────────────────────────────────

# Derlenmiş regex pattern'leri — modül yüklendiğinde bir kez derlenir
_DANGEROUS_PATTERNS = [
    re.compile(r"\.\."),            # Path traversal
    re.compile(r"[\x00-\x1f]"),    # Kontrol karakterleri (tab/newline hariç — dosya adında olmamalı)
    re.compile(r"[<>:\"|?*]"),     # Windows'ta geçersiz karakterler
]


# ─────────────────────────────────────────────
# File Validator
# ─────────────────────────────────────────────


class FileValidator:
    """
    Dosya güvenlik doğrulayıcı.

    Her dosyayı 7 aşamalı kontrolden geçirir.
    Toplu kontrol ile dosya/boyut limitlerini doğrular.
    """

    def __init__(self, policy: Optional[SecurityPolicy] = None) -> None:
        """
        Args:
            policy: Aktif güvenlik politikası. None ise sadece temel kontroller.
        """
        self._logger = logging.getLogger("AIRLOCK.FILE_VALIDATOR")
        self._policy = policy

    # ── Tek Dosya Doğrulama ──

    def validate_file(
        self, filepath: Path, source_root: Path
    ) -> ValidationResult:
        """
        Tek dosyayı 7 aşamalı güvenlik kontrolünden geçir.

        Kontroller (sırasıyla):
          1. Symlink mi? → BLOCK
          2. Gerçek yolu source_root dışına çıkıyor mu? → BLOCK
          3. Dosya adı tehlikeli karakter içeriyor mu? → BLOCK
          4. Dosya adı çok uzun mu? → BLOCK
          5. Hardlink mi? (nlink > 1 ve regular file) → WARN
          6. Device file / FIFO / socket mi? → BLOCK
          7. Tehlikeli uzantı mı? → BLOCK

        Args:
            filepath: Kontrol edilecek dosya yolu
            source_root: Kaynak USB mount kökü (resolve sınırı)

        Returns:
            ValidationResult: Doğrulama sonucu
        """
        warnings: List[str] = []

        # ── Kontrol 1: SYMLINK TESPİTİ ──
        # GÜVENLİK KURALI: Symlink → ASLA takip etme
        if filepath.is_symlink():
            reason = f"SYMLINK_DETECTED: {filepath} → {os.readlink(filepath)}"
            self._logger.warning("ENGEL: %s", reason)
            return ValidationResult(
                filepath=filepath, is_safe=False, block_reason=reason
            )

        # ── Kontrol 2: PATH TRAVERSAL ──
        # resolve() ile gerçek yolu hesapla, source_root içinde mi kontrol et
        try:
            real_path = filepath.resolve(strict=False)
            real_root = source_root.resolve(strict=False)
            real_path.relative_to(real_root)
        except ValueError:
            reason = (
                f"PATH_TRAVERSAL: {filepath} gerçek yolu kaynak dışına çıkıyor "
                f"(resolved: {real_path})"
            )
            self._logger.warning("ENGEL: %s", reason)
            return ValidationResult(
                filepath=filepath, is_safe=False, block_reason=reason
            )

        # ── Kontrol 3: TEHLİKELİ DOSYA ADI ──
        filename = filepath.name
        for pattern in _DANGEROUS_PATTERNS:
            if pattern.search(filename):
                reason = (
                    f"DANGEROUS_FILENAME: '{filename}' — "
                    f"tehlikeli pattern: {pattern.pattern}"
                )
                self._logger.warning("ENGEL: %s", reason)
                return ValidationResult(
                    filepath=filepath, is_safe=False, block_reason=reason
                )

        # ── Kontrol 4: UZUN DOSYA ADI ──
        if len(filename) > MAX_FILENAME_LENGTH:
            reason = (
                f"FILENAME_TOO_LONG: '{filename[:50]}...' "
                f"({len(filename)} > {MAX_FILENAME_LENGTH})"
            )
            self._logger.warning("ENGEL: %s", reason)
            return ValidationResult(
                filepath=filepath, is_safe=False, block_reason=reason
            )

        # ── Kontrol 5: STAT TEMELLİ KONTROLLER ──
        try:
            file_stat = filepath.lstat()  # lstat: symlink'i takip etmez
        except (OSError, PermissionError) as exc:
            reason = f"STAT_FAILED: {filepath} — {exc}"
            self._logger.warning("ENGEL: %s", reason)
            return ValidationResult(
                filepath=filepath, is_safe=False, block_reason=reason
            )

        file_mode = file_stat.st_mode

        # 5a. Device file mi?
        if stat.S_ISBLK(file_mode) or stat.S_ISCHR(file_mode):
            reason = f"DEVICE_FILE: {filepath}"
            self._logger.warning("ENGEL: %s", reason)
            return ValidationResult(
                filepath=filepath, is_safe=False, block_reason=reason
            )

        # 5b. FIFO (named pipe) mi?
        if stat.S_ISFIFO(file_mode):
            reason = f"FIFO_DETECTED: {filepath}"
            self._logger.warning("ENGEL: %s", reason)
            return ValidationResult(
                filepath=filepath, is_safe=False, block_reason=reason
            )

        # 5c. Socket mi?
        if stat.S_ISSOCK(file_mode):
            reason = f"SOCKET_DETECTED: {filepath}"
            self._logger.warning("ENGEL: %s", reason)
            return ValidationResult(
                filepath=filepath, is_safe=False, block_reason=reason
            )

        # 5d. Hardlink kontrolü (nlink > 1 ve regular file → WARN)
        if stat.S_ISREG(file_mode) and file_stat.st_nlink > 1:
            warn_msg = (
                f"HARDLINK: {filepath} — nlink={file_stat.st_nlink} "
                "(birden fazla hard link)"
            )
            self._logger.info("UYARI: %s", warn_msg)
            warnings.append(warn_msg)

        # ── Kontrol 6: DOSYA BOYUTU ──
        if self._policy and stat.S_ISREG(file_mode):
            max_bytes = self._policy.max_file_size_mb * 1024 * 1024
            if file_stat.st_size > max_bytes:
                reason = (
                    f"FILE_TOO_LARGE: {filepath} — "
                    f"{file_stat.st_size / (1024*1024):.1f}MB > "
                    f"{self._policy.max_file_size_mb}MB"
                )
                self._logger.warning("ENGEL: %s", reason)
                return ValidationResult(
                    filepath=filepath, is_safe=False, block_reason=reason
                )

        # ── Kontrol 7: TEHLİKELİ UZANTI ──
        extension = filepath.suffix.lower()
        if extension in DANGEROUS_EXTENSIONS:
            reason = f"DANGEROUS_EXTENSION: {filepath} — uzantı: {extension}"
            self._logger.warning("ENGEL: %s", reason)
            return ValidationResult(
                filepath=filepath, is_safe=False, block_reason=reason
            )

        # Gizli dosya uyarısı (engelleme değil)
        if filename.startswith("."):
            warn_msg = f"HIDDEN_FILE: {filepath}"
            self._logger.info("UYARI: %s", warn_msg)
            warnings.append(warn_msg)

        return ValidationResult(
            filepath=filepath,
            is_safe=True,
            warnings=warnings,
        )

    # ── Toplu Doğrulama ──

    def validate_batch(self, source_root: Path) -> BatchValidationResult:
        """
        Tüm dosya ağacını doğrula.

        Kontroller:
          - Toplam dosya sayısı limiti
          - Toplam boyut limiti
          - Dizin derinliği limiti
          - Her dosya için validate_file()

        Args:
            source_root: Kaynak USB mount kökü

        Returns:
            BatchValidationResult: Tüm doğrulama sonuçları
        """
        result = BatchValidationResult(source_root=source_root)
        max_total_bytes = MAX_TOTAL_SIZE_GB * 1024 * 1024 * 1024

        self._logger.info("Toplu doğrulama başlıyor: %s", source_root)

        if not source_root.exists():
            result.is_within_limits = False
            result.limit_violation = f"Kaynak dizin bulunamadı: {source_root}"
            self._logger.error(result.limit_violation)
            return result

        # Dosya ağacını tara — symlink'leri TAKİP ETME (followlinks=False)
        for dirpath, dirnames, filenames in os.walk(
            source_root, followlinks=False
        ):
            current_dir = Path(dirpath)

            # Dizin derinliği kontrolü
            try:
                relative = current_dir.relative_to(source_root)
                depth = len(relative.parts)
            except ValueError:
                depth = 0

            if depth > MAX_PATH_DEPTH:
                result.is_within_limits = False
                result.limit_violation = (
                    f"Dizin derinliği limiti aşıldı: {depth} > {MAX_PATH_DEPTH} — {current_dir}"
                )
                self._logger.error(result.limit_violation)
                return result

            for filename in filenames:
                filepath = current_dir / filename
                result.total_files += 1

                # Toplam dosya sayısı kontrolü
                if result.total_files > MAX_TOTAL_FILES:
                    result.is_within_limits = False
                    result.limit_violation = (
                        f"Toplam dosya sayısı limiti aşıldı: "
                        f"{result.total_files} > {MAX_TOTAL_FILES}"
                    )
                    self._logger.error(result.limit_violation)
                    return result

                # Dosya boyutunu topla (symlink değilse)
                if not filepath.is_symlink():
                    try:
                        file_size = filepath.lstat().st_size
                        result.total_size_bytes += file_size
                    except OSError:
                        pass

                # Toplam boyut kontrolü
                if result.total_size_bytes > max_total_bytes:
                    result.is_within_limits = False
                    result.limit_violation = (
                        f"Toplam boyut limiti aşıldı: "
                        f"{result.total_size_bytes / (1024**3):.1f}GB > {MAX_TOTAL_SIZE_GB}GB"
                    )
                    self._logger.error(result.limit_violation)
                    return result

                # Dosya doğrulama
                validation = self.validate_file(filepath, source_root)

                if validation.is_safe:
                    result.safe_files.append(filepath)
                else:
                    result.blocked_files.append(validation)

                if validation.warnings:
                    result.warnings.extend(validation.warnings)

        self._logger.info(
            "Toplu doğrulama tamamlandı: %d dosya, %d güvenli, %d engelli, "
            "toplam %.1f MB",
            result.total_files,
            len(result.safe_files),
            len(result.blocked_files),
            result.total_size_bytes / (1024 * 1024),
        )

        return result


# ─────────────────────────────────────────────
# Hedef USB Symlink Koruması (modül seviyesi fonksiyonlar)
# ─────────────────────────────────────────────


def validate_target_path(target: Path, target_root: Path) -> bool:
    """
    Hedef path'in her bileşenini symlink ve path traversal için kontrol et.

    Kontroller:
      1. target ve tüm parent'ları symlink mi?
      2. os.path.realpath ile resolve edilen path target_root dışına çıkıyor mu?

    GÜVENLİK: Saldırgan hedef USB'de önceden symlink oluşturmuş olabilir.
    Bu symlink /etc/shadow gibi sistem dosyasına işaret edebilir.

    Args:
        target: Hedef dosya/dizin yolu.
        target_root: Hedef USB mount kökü.

    Returns:
        True: güvenli, False: symlink veya traversal tespit edildi.
    """
    _log = logging.getLogger("AIRLOCK.FILE_VALIDATOR")

    # Hedef root'un kendisini resolve et
    real_root = os.path.realpath(str(target_root))

    # Hedefin tüm bileşenlerini kontrol et (root'tan hedefe doğru)
    parts_to_check: List[Path] = list(reversed(list(target.parents)))
    parts_to_check.append(target)

    for component in parts_to_check:
        component_str = str(component)

        # Skip: target_root'un üstündeki bileşenler (/, /opt, /opt/airlock, ...)
        try:
            component.relative_to(target_root)
        except ValueError:
            continue

        # Kontrol 1: Symlink mi?
        if component.is_symlink():
            link_target = os.readlink(component_str)
            _log.warning(
                "TARGET SYMLINK BLOCKED: %s -> %s",
                component, link_target,
            )
            return False

        # Kontrol 2: Resolve edilen path root dışına çıkıyor mu?
        real_component = os.path.realpath(component_str)
        if not real_component.startswith(real_root):
            _log.warning(
                "TARGET PATH TRAVERSAL BLOCKED: %s resolves to %s (outside %s)",
                component, real_component, real_root,
            )
            return False

    return True


def safe_mkdir_no_symlink(target_dir: Path, target_root: Path) -> bool:
    """
    Hedef USB'de dizin oluştur — symlink koruması ile.

    Her parent dizini kontrol eder: symlink veya path traversal varsa BLOCK.

    Args:
        target_dir: Oluşturulacak dizin yolu.
        target_root: Hedef USB mount kökü.

    Returns:
        True: dizin güvenle oluşturuldu. False: güvenlik ihlali.
    """
    _log = logging.getLogger("AIRLOCK.FILE_VALIDATOR")

    if not validate_target_path(target_dir, target_root):
        return False

    try:
        target_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        _log.error("Hedef dizin oluşturulamadı: %s — %s", target_dir, exc)
        return False

    # mkdir sonrası tekrar kontrol (TOCTOU minimizasyonu)
    real_dir = os.path.realpath(str(target_dir))
    real_root = os.path.realpath(str(target_root))
    if not real_dir.startswith(real_root):
        _log.warning(
            "TARGET POST-MKDIR TRAVERSAL: %s resolves to %s", target_dir, real_dir,
        )
        return False

    return True


def safe_copy_no_symlink(source: Path, target: Path, target_root: Path) -> bool:
    """
    Dosyayı hedef USB'ye kopyala — symlink koruması ile.

    Kontroller:
      1. target_path'in tüm parent'ları symlink mi / traversal mi? → BLOCK
      2. target_path'in kendisi symlink mi? → BLOCK
      3. Parent dizin güvenle oluştur (safe_mkdir_no_symlink)
      4. Kopyala
      5. Kopyalama sonrası hedef resolve kontrolü (TOCTOU minimizasyonu)

    Args:
        source: Kaynak dosya yolu.
        target: Hedef dosya yolu.
        target_root: Hedef USB mount kökü.

    Returns:
        True: dosya güvenle kopyalandı. False: güvenlik ihlali.
    """
    _log = logging.getLogger("AIRLOCK.FILE_VALIDATOR")

    # Hedef zaten varsa ve symlink ise → BLOCK
    if target.is_symlink():
        link_dest = os.readlink(str(target))
        _log.warning(
            "TARGET FILE SYMLINK BLOCKED: %s -> %s", target, link_dest,
        )
        return False

    # Parent dizini güvenle oluştur
    if not safe_mkdir_no_symlink(target.parent, target_root):
        return False

    # Path kontrolü (tüm bileşenler)
    if not validate_target_path(target, target_root):
        return False

    # Kopyala
    try:
        shutil.copy2(source, target)
    except OSError as exc:
        _log.error("Güvenli kopyalama hatası: %s → %s — %s", source, target, exc)
        return False

    # Post-copy TOCTOU kontrolü
    real_target = os.path.realpath(str(target))
    real_root = os.path.realpath(str(target_root))
    if not real_target.startswith(real_root):
        _log.critical(
            "POST-COPY TRAVERSAL DETECTED — dosya siliniyor: %s → %s",
            target, real_target,
        )
        try:
            target.unlink()
        except OSError:
            pass
        return False

    return True

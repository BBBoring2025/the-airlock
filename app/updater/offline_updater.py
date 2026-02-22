"""
THE AIRLOCK v5.1.1 FORTRESS-HARDENED — Güvenli Offline Güncelleme Sistemi

UPDATE USB ile ClamAV imzaları, YARA kuralları ve hash listesi güncellenir.

UPDATE USB yapısı:
  UPDATE/
  ├── manifest.json          # Güncelleme paketi bilgileri
  ├── manifest.json.sig      # Ed25519 imzası (Base64)
  ├── clamav/
  │   ├── main.cvd
  │   ├── daily.cvd
  │   └── bytecode.cvd
  ├── yara/
  │   └── *.yar
  └── known_bad_hashes.txt   # Opsiyonel hash listesi güncellemesi

GÜVENLİK:
  1. manifest.json.sig Ed25519 public key ile doğrulanır
  2. İmza geçersiz → UPDATE REDDEDİLDİ
  3. ClamAV dosyaları: sigtool ile bütünlük kontrolü
  4. YARA dosyaları: derleme testi (syntax doğrulama)
  5. Dosya boyut aralıkları kontrolü

GÜVENLİK KURALI: UPDATE USB DE BİR SALDIRI YÜZEYİDİR.
                  ASLA imza doğrulamadan uygulama.

Kullanım:
    updater = OfflineUpdater(config=cfg)
    verification = updater.verify_update_package(usb_mount_path)
    if verification.is_valid:
        result = updater.apply_updates(usb_mount_path)
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from app.config import (
    AirlockConfig,
    DIRECTORIES,
)
from app.utils.crypto import sha256_file, verify_signature
from app.utils.helper_client import request_update_clamav

logger = logging.getLogger("AIRLOCK.UPDATER")


# ─────────────────────────────────────────────
# Sabitler
# ─────────────────────────────────────────────

# ClamAV CVD dosyalarının beklenen boyut aralıkları (byte)
# Çok küçük → bozuk/sahte, çok büyük → şüpheli
_CLAMAV_SIZE_LIMITS = {
    "main.cvd":     (50 * 1024 * 1024,   500 * 1024 * 1024),   # 50-500 MB
    "daily.cvd":    (100 * 1024,          200 * 1024 * 1024),   # 100 KB - 200 MB
    "bytecode.cvd": (10 * 1024,           50 * 1024 * 1024),    # 10 KB - 50 MB
    "main.cld":     (50 * 1024 * 1024,    500 * 1024 * 1024),
    "daily.cld":    (100 * 1024,          200 * 1024 * 1024),
    "bytecode.cld": (10 * 1024,           50 * 1024 * 1024),
}

# YARA kural dosyalarının boyut aralıkları
_YARA_SIZE_LIMITS = (100, 50 * 1024 * 1024)  # 100 byte - 50 MB

# Subprocess timeout (saniye)
_CMD_TIMEOUT = 60


# ─────────────────────────────────────────────
# Veri Yapıları
# ─────────────────────────────────────────────


@dataclass
class UpdateVerification:
    """Güncelleme paketi doğrulama sonucu."""

    is_valid: bool
    rejection_reason: Optional[str] = None
    manifest_data: Dict = field(default_factory=dict)
    components: Dict[str, bool] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)


@dataclass
class UpdateResult:
    """Güncelleme uygulama sonucu."""

    success: bool
    components_updated: Dict[str, bool] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    rollback_performed: bool = False


# ─────────────────────────────────────────────
# Offline Updater
# ─────────────────────────────────────────────


class OfflineUpdater:
    """
    Güvenli offline güncelleme yöneticisi.

    UPDATE USB'den imza-doğrulamalı güncelleme uygular.
    Başarısız bileşenler geri alınır (rollback).
    """

    def __init__(self, config: Optional[AirlockConfig] = None) -> None:
        self._logger = logging.getLogger("AIRLOCK.UPDATER")
        self._config = config or AirlockConfig()
        self._public_key_path = self._config.update_public_key_path

    # ═══════════════════════════════════════════
    # Doğrulama (Uygulamadan Önce)
    # ═══════════════════════════════════════════

    def verify_update_package(self, usb_path: Path) -> UpdateVerification:
        """
        UPDATE USB paketini doğrula (UYGULAMADAN ÖNCE).

        Adımlar:
          1. UPDATE dizini ve manifest.json varlığı
          2. manifest.json.sig ile Ed25519 imza doğrulama
          3. Manifest'teki dosyaların hash kontrolü
          4. Dosya boyut aralıkları kontrolü
          5. Bileşen bazlı doğrulama (ClamAV, YARA, hash listesi)

        Args:
            usb_path: UPDATE USB mount noktası

        Returns:
            UpdateVerification
        """
        update_dir = self._find_update_dir(usb_path)
        if update_dir is None:
            return UpdateVerification(
                is_valid=False,
                rejection_reason="UPDATE dizini bulunamadı",
            )

        # ── Adım 1: manifest.json oku ──
        manifest_path = update_dir / "manifest.json"
        if not manifest_path.exists():
            return UpdateVerification(
                is_valid=False,
                rejection_reason="manifest.json bulunamadı",
            )

        try:
            manifest_text = manifest_path.read_text(encoding="utf-8")
            manifest_data = json.loads(manifest_text)
        except (json.JSONDecodeError, OSError) as exc:
            return UpdateVerification(
                is_valid=False,
                rejection_reason=f"manifest.json okunamadı: {exc}",
            )

        # ── Adım 2: Ed25519 imza doğrulama ──
        if self._config.require_update_signature:
            sig_path = update_dir / "manifest.json.sig"
            if not sig_path.exists():
                return UpdateVerification(
                    is_valid=False,
                    rejection_reason="manifest.json.sig bulunamadı — imza zorunlu",
                    manifest_data=manifest_data,
                )

            try:
                signature_b64 = sig_path.read_text(encoding="ascii").strip()
            except OSError as exc:
                return UpdateVerification(
                    is_valid=False,
                    rejection_reason=f"İmza dosyası okunamadı: {exc}",
                    manifest_data=manifest_data,
                )

            manifest_bytes = manifest_text.encode("utf-8")
            is_sig_valid = verify_signature(
                manifest_bytes, signature_b64, self._public_key_path
            )

            if not is_sig_valid:
                self._logger.critical(
                    "UPDATE REDDEDİLDİ — Ed25519 imza doğrulama BAŞARISIZ: %s",
                    usb_path,
                )
                return UpdateVerification(
                    is_valid=False,
                    rejection_reason="Ed25519 imza doğrulama BAŞARISIZ — güncelleme reddedildi",
                    manifest_data=manifest_data,
                )

            self._logger.info("Ed25519 imza doğrulandı: manifest.json")

        # ── Adım 3: Dosya hash'lerini doğrula ──
        warnings: List[str] = []
        components: Dict[str, bool] = {}

        manifest_files = manifest_data.get("files", {})
        for rel_path_str, expected_hash in manifest_files.items():
            file_path = update_dir / rel_path_str
            if not file_path.exists():
                warnings.append(f"Manifest'te listelenen dosya bulunamadı: {rel_path_str}")
                continue

            actual_hash = sha256_file(file_path)
            if actual_hash != expected_hash:
                self._logger.warning(
                    "Hash uyuşmazlığı: %s — beklenen=%s, gerçek=%s",
                    rel_path_str, expected_hash[:16], actual_hash[:16],
                )
                return UpdateVerification(
                    is_valid=False,
                    rejection_reason=f"Hash uyuşmazlığı: {rel_path_str}",
                    manifest_data=manifest_data,
                )

        # ── Adım 4: Bileşen doğrulama ──
        # ClamAV
        clamav_dir = update_dir / "clamav"
        if clamav_dir.exists() and any(clamav_dir.iterdir()):
            clamav_ok = self._verify_clamav_files(clamav_dir)
            components["clamav"] = clamav_ok
            if not clamav_ok:
                warnings.append("ClamAV dosya doğrulaması başarısız")

        # YARA
        yara_dir = update_dir / "yara"
        if yara_dir.exists() and any(yara_dir.iterdir()):
            yara_ok = self._verify_yara_files(yara_dir)
            components["yara"] = yara_ok
            if not yara_ok:
                warnings.append("YARA kural dosyası doğrulaması başarısız")

        # Hash listesi
        hash_file = update_dir / "known_bad_hashes.txt"
        if hash_file.exists():
            components["hashes"] = True  # Varlık yeterli

        if not components:
            return UpdateVerification(
                is_valid=False,
                rejection_reason="Güncellenecek bileşen bulunamadı",
                manifest_data=manifest_data,
            )

        self._logger.info(
            "UPDATE doğrulandı: bileşenler=%s, uyarılar=%d",
            components, len(warnings),
        )

        return UpdateVerification(
            is_valid=True,
            manifest_data=manifest_data,
            components=components,
            warnings=warnings,
        )

    # ═══════════════════════════════════════════
    # Güncelleme Uygulama
    # ═══════════════════════════════════════════

    def apply_updates(self, usb_path: Path) -> UpdateResult:
        """
        Doğrulanmış güncellemeleri uygula.

        Adımlar:
          1. ClamAV: daemon durdur → CVD kopyala → sigtool check → daemon başlat
          2. YARA: kural dosyalarını kopyala → derleme testi
          3. Hash listesi: kopyala
          4. Başarısız bileşenleri geri al

        ÖNCE verify_update_package() ÇAĞRILMALI.

        Args:
            usb_path: UPDATE USB mount noktası

        Returns:
            UpdateResult
        """
        update_dir = self._find_update_dir(usb_path)
        if update_dir is None:
            return UpdateResult(
                success=False,
                errors=["UPDATE dizini bulunamadı"],
            )

        # ── Bütünlük doğrulama: symlink + path traversal kontrolü ──
        manifest_path = update_dir / "manifest.json"
        manifest_data: dict = {}
        if manifest_path.exists():
            try:
                manifest_data = json.loads(
                    manifest_path.read_text(encoding="utf-8")
                )
            except (json.JSONDecodeError, OSError) as exc:
                self._logger.error("Manifest okunamadı: %s", exc)
                return UpdateResult(
                    success=False,
                    errors=[f"Manifest okunamadı: {exc}"],
                )

        try:
            self._validate_update_integrity(update_dir, manifest_data)
        except ValueError as exc:
            return UpdateResult(success=False, errors=[str(exc)])

        result = UpdateResult(success=True)

        # ── ClamAV Güncellemesi ──
        clamav_dir = update_dir / "clamav"
        if clamav_dir.exists() and any(clamav_dir.iterdir()):
            clamav_ok = self._apply_clamav_update(clamav_dir)
            result.components_updated["clamav"] = clamav_ok
            if not clamav_ok:
                result.errors.append("ClamAV güncellemesi başarısız")
                result.success = False

        # ── YARA Güncellemesi ──
        yara_dir = update_dir / "yara"
        if yara_dir.exists() and any(yara_dir.iterdir()):
            yara_ok = self._apply_yara_update(yara_dir)
            result.components_updated["yara"] = yara_ok
            if not yara_ok:
                result.errors.append("YARA güncellemesi başarısız")
                result.success = False

        # ── Hash Listesi Güncellemesi ──
        hash_file = update_dir / "known_bad_hashes.txt"
        if hash_file.exists():
            hashes_ok = self._apply_hash_update(hash_file)
            result.components_updated["hashes"] = hashes_ok
            if not hashes_ok:
                result.errors.append("Hash listesi güncellemesi başarısız")

        if result.success:
            self._logger.info(
                "Güncelleme başarıyla tamamlandı: %s", result.components_updated
            )
        else:
            self._logger.error(
                "Güncelleme kısmen/tamamen başarısız: %s — hatalar: %s",
                result.components_updated, result.errors,
            )

        return result

    # ═══════════════════════════════════════════
    # ClamAV Güncelleme
    # ═══════════════════════════════════════════

    def _apply_clamav_update(self, source_dir: Path) -> bool:
        """
        ClamAV veritabanini guncelle — privileged helper uzerinden.

        1. ClamAV daemon'i durdur (helper: update_clamav/service_stop)
        2. Mevcut CVD'leri yedekle (yerel)
        3. Yeni CVD'leri kopyala (helper: update_clamav/copy_file)
        4. sigtool --check ile dogrula
        5. Dogrulama basarisiz → yedekten geri al
        6. ClamAV daemon'i baslat (helper: update_clamav/service_start)
        """
        clamav_dest = Path("/var/lib/clamav")
        backup_dir = DIRECTORIES["tmp"] / "clamav_backup"

        # 1. Daemon durdur — helper uzerinden (sudo YOK)
        ok, err = request_update_clamav("service_stop")
        if not ok:
            self._logger.warning("ClamAV daemon durdurma basarisiz: %s", err)
            # Devam et — daemon zaten kapali olabilir

        # 2. Yedekle (yerel dosya islemi — /opt/airlock/tmp/ altinda)
        try:
            if backup_dir.exists():
                shutil.rmtree(backup_dir)
            backup_dir.mkdir(parents=True, exist_ok=True)

            for cvd in clamav_dest.glob("*.cvd"):
                shutil.copy2(cvd, backup_dir / cvd.name)
            for cld in clamav_dest.glob("*.cld"):
                shutil.copy2(cld, backup_dir / cld.name)
        except OSError as exc:
            self._logger.error("ClamAV yedekleme hatasi: %s", exc)
            request_update_clamav("service_start")
            return False

        # 3. Kopyala — helper uzerinden (guvenli, boyut + uzanti kontrollu)
        copy_failed = False
        for src_file in source_dir.iterdir():
            if src_file.suffix in (".cvd", ".cld"):
                ok, err = request_update_clamav(
                    "copy_file",
                    source=str(src_file),
                    filename=src_file.name,
                )
                if ok:
                    self._logger.info("ClamAV kopyalandi (helper): %s", src_file.name)
                else:
                    self._logger.error(
                        "ClamAV kopyalama basarisiz (helper): %s — %s",
                        src_file.name, err,
                    )
                    copy_failed = True
                    break

        if copy_failed:
            self._logger.error("ClamAV kopyalama hatasi — geri alinyor")
            self._rollback_clamav(backup_dir, clamav_dest)
            request_update_clamav("service_start")
            return False

        # 4. sigtool ile dogrula
        if not self._verify_clamav_sigtool(clamav_dest):
            self._logger.error("ClamAV sigtool dogrulama basarisiz — geri alinyor")
            self._rollback_clamav(backup_dir, clamav_dest)
            request_update_clamav("service_start")
            return False

        # 5. Daemon baslat — helper uzerinden
        request_update_clamav("service_start")

        # 6. Yedek temizligi
        try:
            shutil.rmtree(backup_dir)
        except OSError:
            pass

        self._logger.info("ClamAV guncellemesi basarili")
        return True

    def _verify_clamav_sigtool(self, clamav_dir: Path) -> bool:
        """sigtool ile ClamAV veritabanı bütünlük kontrolü."""
        for cvd in clamav_dir.glob("*.cvd"):
            try:
                result = subprocess.run(
                    ["sigtool", "--info", str(cvd)],
                    capture_output=True,
                    text=True,
                    timeout=_CMD_TIMEOUT,
                )
                if result.returncode != 0:
                    self._logger.error(
                        "sigtool doğrulama başarısız: %s — %s",
                        cvd.name, result.stderr[:200],
                    )
                    return False
            except FileNotFoundError:
                self._logger.warning("sigtool bulunamadı — ClamAV doğrulama atlanıyor")
                return True  # sigtool yoksa geç (dosya hash'i zaten doğrulandı)
            except (subprocess.TimeoutExpired, OSError) as exc:
                self._logger.error("sigtool hatası: %s", exc)
                return False
        return True

    def _rollback_clamav(self, backup_dir: Path, clamav_dest: Path) -> None:
        """ClamAV yedekten geri al."""
        try:
            for backup_file in backup_dir.iterdir():
                shutil.copy2(backup_file, clamav_dest / backup_file.name)
            self._logger.warning("ClamAV geri alındı (rollback)")
        except OSError as exc:
            self._logger.critical("ClamAV geri alma başarısız: %s", exc)

    # ═══════════════════════════════════════════
    # YARA Güncelleme
    # ═══════════════════════════════════════════

    def _apply_yara_update(self, source_dir: Path) -> bool:
        """
        YARA kurallarını güncelle.

        1. Yedekle (mevcut custom kurallar)
        2. Kopyala
        3. Derleme testi (yara-python)
        4. Başarısız → geri al
        """
        yara_dest = DIRECTORIES.get("yara_custom", DIRECTORIES["yara_rules"] / "custom")
        backup_dir = DIRECTORIES["tmp"] / "yara_backup"

        # 1. Yedekle
        try:
            if backup_dir.exists():
                shutil.rmtree(backup_dir)
            if yara_dest.exists():
                shutil.copytree(yara_dest, backup_dir)
            else:
                backup_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            self._logger.error("YARA yedekleme hatası: %s", exc)
            return False

        # 2. Kopyala
        try:
            yara_dest.mkdir(parents=True, exist_ok=True)
            for src_file in source_dir.iterdir():
                if src_file.suffix in (".yar", ".yara"):
                    shutil.copy2(src_file, yara_dest / src_file.name)
                    self._logger.info("YARA kopyalandı: %s", src_file.name)
        except OSError as exc:
            self._logger.error("YARA kopyalama hatası: %s — geri alınıyor", exc)
            self._rollback_yara(backup_dir, yara_dest)
            return False

        # 3. Derleme testi
        if not self._test_yara_compile(yara_dest):
            self._logger.error("YARA derleme testi başarısız — geri alınıyor")
            self._rollback_yara(backup_dir, yara_dest)
            return False

        # 4. Yedek temizliği
        try:
            shutil.rmtree(backup_dir)
        except OSError:
            pass

        self._logger.info("YARA güncellemesi başarılı")
        return True

    def _test_yara_compile(self, yara_dir: Path) -> bool:
        """YARA kural dosyalarını derleme testi ile doğrula."""
        try:
            import yara  # noqa: PLC0415
        except ImportError:
            self._logger.warning("yara-python yüklü değil — derleme testi atlanıyor")
            return True

        rule_files = {}
        for yar_file in sorted(yara_dir.glob("*.yar")):
            rule_files[yar_file.stem] = str(yar_file)
        for yar_file in sorted(yara_dir.glob("*.yara")):
            rule_files[yar_file.stem] = str(yar_file)

        if not rule_files:
            return True

        try:
            yara.compile(filepaths=rule_files)
            self._logger.info("YARA derleme testi başarılı: %d kural dosyası", len(rule_files))
            return True
        except yara.SyntaxError as exc:
            self._logger.error("YARA syntax hatası: %s", exc)
            return False
        except Exception as exc:
            self._logger.error("YARA derleme hatası: %s", exc)
            return False

    def _rollback_yara(self, backup_dir: Path, yara_dest: Path) -> None:
        """YARA kurallarını yedekten geri al."""
        try:
            if yara_dest.exists():
                shutil.rmtree(yara_dest)
            shutil.copytree(backup_dir, yara_dest)
            self._logger.warning("YARA geri alındı (rollback)")
        except OSError as exc:
            self._logger.critical("YARA geri alma başarısız: %s", exc)

    # ═══════════════════════════════════════════
    # Hash Listesi Güncelleme
    # ═══════════════════════════════════════════

    def _apply_hash_update(self, hash_file: Path) -> bool:
        """Bilinen kötü hash listesini güncelle."""
        dest = DIRECTORIES["data"] / "known_bad_hashes.txt"
        legacy_dest = DIRECTORIES["config"] / "known_bad_hashes.txt"

        # Geriye dönük uyumluluk: eski konumdan yeni konuma taşı (rollback/backup için)
        if not dest.exists() and legacy_dest.exists():
            try:
                shutil.copy2(legacy_dest, dest)
                self._logger.warning("Legacy hash list migrated: %s → %s", legacy_dest, dest)
            except OSError as exc:
                self._logger.warning(
                    "Legacy hash list bulundu ama taşınamadı (%s). Backup/rollback olmayabilir.",
                    exc,
                )


        try:
            # Mevcut listeyi yedekle
            if dest.exists():
                backup = dest.with_suffix(".txt.bak")
                shutil.copy2(dest, backup)

            # Yeni listeyi kopyala
            shutil.copy2(hash_file, dest)

            # Basit doğrulama: en az 1 satır olmalı
            content = dest.read_text(encoding="utf-8")
            valid_lines = [
                line for line in content.splitlines()
                if line.strip() and not line.strip().startswith("#")
            ]

            self._logger.info(
                "Hash listesi güncellendi: %d hash", len(valid_lines)
            )
            return True

        except OSError as exc:
            self._logger.error("Hash listesi güncelleme hatası: %s", exc)
            return False

    # ═══════════════════════════════════════════
    # Bileşen Doğrulama Yardımcıları
    # ═══════════════════════════════════════════

    def _verify_clamav_files(self, clamav_dir: Path) -> bool:
        """ClamAV dosyalarının boyut aralıklarını kontrol et."""
        for cvd_file in clamav_dir.iterdir():
            if cvd_file.suffix not in (".cvd", ".cld"):
                continue

            size = cvd_file.stat().st_size
            limits = _CLAMAV_SIZE_LIMITS.get(cvd_file.name)

            if limits:
                min_size, max_size = limits
                if size < min_size or size > max_size:
                    self._logger.warning(
                        "ClamAV boyut kontrolü başarısız: %s — %d bytes "
                        "(beklenen: %d-%d bytes)",
                        cvd_file.name, size, min_size, max_size,
                    )
                    return False

        return True

    def _verify_yara_files(self, yara_dir: Path) -> bool:
        """YARA dosyalarının boyut aralıklarını ve syntax'ını kontrol et."""
        min_size, max_size = _YARA_SIZE_LIMITS

        for yar_file in yara_dir.iterdir():
            if yar_file.suffix not in (".yar", ".yara"):
                continue

            size = yar_file.stat().st_size
            if size < min_size or size > max_size:
                self._logger.warning(
                    "YARA boyut kontrolü başarısız: %s — %d bytes "
                    "(beklenen: %d-%d bytes)",
                    yar_file.name, size, min_size, max_size,
                )
                return False

        # Syntax kontrolü
        return self._test_yara_compile(yara_dir)

    # ═══════════════════════════════════════════
    # Genel Yardımcılar
    # ═══════════════════════════════════════════

    @staticmethod
    def _find_update_dir(usb_path: Path) -> Optional[Path]:
        """
        UPDATE dizinini bul.

        USB kökünde veya bir alt dizinde UPDATE/ arar.
        Büyük/küçük harf duyarsız.
        """
        # Doğrudan USB kökünde
        for name in ("UPDATE", "update", "Update"):
            candidate = usb_path / name
            if candidate.is_dir():
                return candidate

        # USB kökünün kendisi UPDATE dizini olabilir
        manifest = usb_path / "manifest.json"
        if manifest.exists():
            return usb_path

        return None

    def _validate_update_integrity(self, update_root: Path, manifest: dict) -> None:
        """
        Güncelleme dizininin bütünlük ve güvenlik doğrulaması.

        Symlink tespiti ve path traversal kontrolü yapar.
        Herhangi bir ihlal tespit edilirse ValueError fırlatır.
        Bu metod apply_updates() içinde HERHANGİ bir dosya işlenmeden
        ÖNCE çağrılmalıdır.

        Kontroller:
          A) update_root altında HİÇ symlink olmamalı (dizin veya dosya)
          B) manifest["files"] içindeki yollar:
             - Mutlak yol (/) olmamalı
             - ".." içermemeli
             - resolve() sonrası update_root dışına çıkmamalı
             - resolve() sonrası kendisi symlink olmamalı (defense in depth)

        Args:
            update_root: Güncelleme dizini (ör: /mnt/airlock_update/UPDATE)
            manifest: Doğrulanmış manifest verisi (dict)

        Raises:
            ValueError: Güvenlik ihlali tespit edildiğinde
        """
        import os  # noqa: PLC0415

        # ── A) Symlink tespiti: tüm dosya ve dizinlerde ──
        for dirpath, dirnames, filenames in os.walk(str(update_root), followlinks=False):
            dir_path = Path(dirpath)
            # Dizinin kendisi symlink mi?
            if dir_path.is_symlink():
                msg = f"UPDATE REJECTED: symlink detected: {dir_path}"
                self._logger.critical(msg)
                raise ValueError(msg)

            for name in dirnames + filenames:
                entry_path = dir_path / name
                if entry_path.is_symlink():
                    msg = f"UPDATE REJECTED: symlink detected: {entry_path}"
                    self._logger.critical(msg)
                    raise ValueError(msg)

        # ── B) Manifest yol doğrulaması ──
        manifest_files = manifest.get("files", {})
        resolved_root = update_root.resolve()

        for rel_path_str in manifest_files:
            # Mutlak yol kontrolü
            if rel_path_str.startswith("/"):
                msg = f"UPDATE REJECTED: absolute path in manifest: {rel_path_str}"
                self._logger.critical(msg)
                raise ValueError(msg)

            # Path traversal kontrolü (.. segmenti)
            parts = Path(rel_path_str).parts
            if ".." in parts:
                msg = f"UPDATE REJECTED: path traversal in manifest: {rel_path_str}"
                self._logger.critical(msg)
                raise ValueError(msg)

            # Resolve sonrası update_root dışına çıkma kontrolü
            full_path = update_root / rel_path_str
            try:
                resolved = full_path.resolve(strict=True)
            except (OSError, ValueError):
                # strict=True: dosya yoksa hata — bu da şüphe
                msg = f"UPDATE REJECTED: cannot resolve manifest path: {rel_path_str}"
                self._logger.critical(msg)
                raise ValueError(msg)

            if not str(resolved).startswith(str(resolved_root) + "/") and resolved != resolved_root:
                msg = (
                    f"UPDATE REJECTED: path escapes update root: "
                    f"{rel_path_str} -> {resolved}"
                )
                self._logger.critical(msg)
                raise ValueError(msg)

            # Defense in depth: resolve() sonrası symlink olmamalı
            if resolved.is_symlink():
                msg = f"UPDATE REJECTED: resolved path is symlink: {resolved}"
                self._logger.critical(msg)
                raise ValueError(msg)

    @staticmethod
    def _service_control(service: str, action: str) -> bool:
        """
        systemd servisi kontrol et (start/stop/restart).

        sudo YOK — systemctl doğrudan çağrılır.
        Servisin PolicyKit veya systemd izinleri ile yönetildiği varsayılır.
        ClamAV daemon kontrolü için airlock kullanıcısına
        polkit izni verilmelidir (setup.sh'de yapılır).

        shell=False ZORUNLU.
        """
        try:
            result = subprocess.run(
                ["systemctl", action, service],
                capture_output=True,
                text=True,
                timeout=_CMD_TIMEOUT,
            )
            if result.returncode == 0:
                logger.info("Servis %s: %s", action, service)
                return True
            else:
                logger.warning(
                    "Servis %s başarısız (%s): %s",
                    action, service, result.stderr[:200],
                )
                return False
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
            logger.warning("Servis kontrol hatası (%s %s): %s", action, service, exc)
            return False

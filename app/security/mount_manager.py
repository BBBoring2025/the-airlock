"""
THE AIRLOCK v5.1.1 FORTRESS-HARDENED — KATMAN 3: Güvenli Mount Yönetimi

USB'leri ASLA otomount'a bırakmayız.
  Kaynak USB: SADECE read-only mount (ro,noexec,nosuid,nodev)
  Hedef USB:  noexec,nosuid,nodev ile mount

Her mount işleminde:
  1. Filesystem türü tespiti (sadece FAT32, exFAT, NTFS, ext4, ext3)
  2. Kontrollü mount (seçeneklerle)
  3. Mount sonrası doğrulama (/proc/mounts)
  4. Güvenli unmount (sync + lazy fallback)

Kullanım:
    mm = MountManager()
    fs = mm.detect_filesystem("/dev/sda1")
    mm.mount_source("/dev/sda1", "/mnt/source")
    mm.mount_target("/dev/sdb1", "/mnt/target")
    mm.safe_unmount("/mnt/source")
"""

from __future__ import annotations

import logging
import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from app.config import (
    ALLOWED_FILESYSTEMS,
    SOURCE_MOUNT_OPTIONS,
    TARGET_MOUNT_OPTIONS,
)
from app.utils.helper_client import request_mount, request_umount

logger = logging.getLogger("AIRLOCK.MOUNT")


# ─────────────────────────────────────────────
# Veri Yapıları
# ─────────────────────────────────────────────


@dataclass
class MountResult:
    """Mount işlemi sonucu."""

    success: bool
    device: str
    mountpoint: str
    filesystem: str
    options: str
    error: Optional[str] = None


@dataclass
class FilesystemInfo:
    """Tespit edilen dosya sistemi bilgisi."""

    device: str
    fstype: str
    label: Optional[str] = None
    uuid: Optional[str] = None
    is_supported: bool = False


# ─────────────────────────────────────────────
# Mount Manager
# ─────────────────────────────────────────────


class MountManager:
    """
    Güvenli USB mount/unmount yöneticisi.

    Tüm mount işlemleri kontrollüdür:
    - Filesystem türü önceden doğrulanır
    - Mount seçenekleri zorunludur
    - Mount sonrası durum doğrulanır
    - Unmount güvenli yapılır (sync + verify)
    """

    # Mount/unmount komutları için timeout (saniye)
    _CMD_TIMEOUT = 15

    def __init__(self) -> None:
        self._logger = logging.getLogger("AIRLOCK.MOUNT")

    # ── Filesystem Tespiti ──

    def detect_filesystem(self, device: str) -> FilesystemInfo:
        """
        blkid ile cihazın dosya sistemi türünü tespit et.

        Args:
            device: Blok cihaz yolu (ör: /dev/sda1)

        Returns:
            FilesystemInfo: Dosya sistemi bilgileri + desteklenme durumu
        """
        fstype = ""
        label: Optional[str] = None
        uuid: Optional[str] = None

        # blkid ile tür tespiti (shell=False ZORUNLU)
        try:
            result = subprocess.run(
                ["blkid", "-o", "value", "-s", "TYPE", device],
                capture_output=True,
                text=True,
                timeout=self._CMD_TIMEOUT,
            )
            if result.returncode == 0:
                fstype = result.stdout.strip().lower()
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
            self._logger.error("Filesystem tespiti başarısız (%s): %s", device, exc)

        # Etiket tespiti
        try:
            result = subprocess.run(
                ["blkid", "-o", "value", "-s", "LABEL", device],
                capture_output=True,
                text=True,
                timeout=self._CMD_TIMEOUT,
            )
            if result.returncode == 0:
                label = result.stdout.strip() or None
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

        # UUID tespiti
        try:
            result = subprocess.run(
                ["blkid", "-o", "value", "-s", "UUID", device],
                capture_output=True,
                text=True,
                timeout=self._CMD_TIMEOUT,
            )
            if result.returncode == 0:
                uuid = result.stdout.strip() or None
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

        is_supported = fstype in ALLOWED_FILESYSTEMS

        info = FilesystemInfo(
            device=device,
            fstype=fstype,
            label=label,
            uuid=uuid,
            is_supported=is_supported,
        )

        if not fstype:
            self._logger.warning("Filesystem türü tespit edilemedi: %s", device)
        elif not is_supported:
            self._logger.warning(
                "Desteklenmeyen filesystem: %s (%s) — izin verilen: %s",
                fstype,
                device,
                sorted(ALLOWED_FILESYSTEMS),
            )
        else:
            self._logger.info(
                "Filesystem tespit edildi: %s (%s) etiket=%s",
                fstype,
                device,
                label,
            )

        return info

    # ── Kaynak USB Mount (READ-ONLY) ──

    def mount_source(self, device: str, mountpoint: str) -> MountResult:
        """
        Kaynak (kirli) USB'yi READ-ONLY mount et.

        ASLA read-write mount edilmez.
        Seçenekler: ro,noexec,nosuid,nodev,noatime

        Args:
            device: Blok cihaz yolu
            mountpoint: Mount noktası dizini

        Returns:
            MountResult: İşlem sonucu
        """
        return self._do_mount(
            device=device,
            mountpoint=mountpoint,
            options=SOURCE_MOUNT_OPTIONS,
            label="KAYNAK (ro)",
        )

    # ── Hedef USB Mount (RW + güvenlik seçenekleri) ──

    def mount_target(self, device: str, mountpoint: str) -> MountResult:
        """
        Hedef (temiz) USB'yi güvenli yazılabilir mount et.

        Seçenekler: rw,noexec,nosuid,nodev,noatime

        Args:
            device: Blok cihaz yolu
            mountpoint: Mount noktası dizini

        Returns:
            MountResult: İşlem sonucu
        """
        return self._do_mount(
            device=device,
            mountpoint=mountpoint,
            options=TARGET_MOUNT_OPTIONS,
            label="HEDEF (rw)",
        )

    # ── Güvenli Unmount ──

    def safe_unmount(self, mountpoint: str) -> bool:
        """
        Güvenli unmount prosedürü:
          1. sync — tüm bekleyen yazmaları diske yaz
          2. umount — normal unmount
          3. Başarısız → umount -l (lazy unmount)
          4. Mount noktasının gerçekten boşaldığını doğrula

        Args:
            mountpoint: Unmount edilecek dizin

        Returns:
            True: başarılı unmount
            False: unmount başarısız
        """
        mp = Path(mountpoint)

        # Privileged helper üzerinden unmount (sync + lazy fallback helper tarafında yapılır)
        ok, error = request_umount(str(mp))
        if ok:
            self._logger.info("Unmount başarılı (helper): %s", mp)
            return True

        self._logger.warning("Helper unmount başarısız: %s — %s", mp, error)

        # Doğrulama: gerçekten hâlâ mount'lu mu?
        if self._is_mounted(str(mp)):
            self._logger.critical(
                "UNMOUNT BAŞARISIZ — hâlâ mount durumunda: %s", mp
            )
            return False

        return True

    # ── Mount Doğrulama ──

    def verify_mount(self, mountpoint: str, expected_ro: bool = False) -> bool:
        """
        Mount durumunu /proc/mounts veya findmnt ile doğrula.

        Args:
            mountpoint: Kontrol edilecek mount noktası
            expected_ro: True ise read-only olması bekleniyor

        Returns:
            True: mount doğrulandı (ve ro/rw beklentiyle uyuşuyor)
            False: doğrulama başarısız
        """
        try:
            result = subprocess.run(
                ["findmnt", "-n", "-o", "OPTIONS", mountpoint],
                capture_output=True,
                text=True,
                timeout=self._CMD_TIMEOUT,
            )
            if result.returncode != 0:
                self._logger.error(
                    "Mount doğrulama başarısız — %s mount değil", mountpoint
                )
                return False

            actual_options = result.stdout.strip()

            if expected_ro and "ro" not in actual_options.split(","):
                self._logger.critical(
                    "GÜVENLİK İHLALİ: %s READ-ONLY olması gerekirken değil! Seçenekler: %s",
                    mountpoint,
                    actual_options,
                )
                return False

            # Güvenlik seçenekleri kontrolü
            required_flags = {"noexec", "nosuid", "nodev"}
            actual_set = set(actual_options.split(","))
            missing = required_flags - actual_set

            if missing:
                self._logger.warning(
                    "Eksik güvenlik seçenekleri (%s): %s — mevcut: %s",
                    mountpoint,
                    missing,
                    actual_options,
                )

            self._logger.info(
                "Mount doğrulandı: %s — seçenekler: %s", mountpoint, actual_options
            )
            return True

        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
            self._logger.error("Mount doğrulama hatası: %s", exc)
            return False

    # ── Dahili Yardımcılar ──

    def _do_mount(
        self,
        device: str,
        mountpoint: str,
        options: str,
        label: str,
    ) -> MountResult:
        """
        Ortak mount prosedürü.

        Adımlar:
          1. Filesystem tespiti
          2. Desteklenmeyen filesystem kontrolü
          3. Mount noktası hazırlığı
          4. mount komutu (shell=False ZORUNLU)
          5. Mount sonrası doğrulama
        """
        # 1. Filesystem tespiti
        fs_info = self.detect_filesystem(device)

        if not fs_info.fstype:
            return MountResult(
                success=False,
                device=device,
                mountpoint=mountpoint,
                filesystem="",
                options=options,
                error="Filesystem türü tespit edilemedi",
            )

        if not fs_info.is_supported:
            return MountResult(
                success=False,
                device=device,
                mountpoint=mountpoint,
                filesystem=fs_info.fstype,
                options=options,
                error=f"Desteklenmeyen filesystem: {fs_info.fstype}",
            )

        # 2. Mount noktasını hazırla
        mp = Path(mountpoint)
        try:
            mp.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            return MountResult(
                success=False,
                device=device,
                mountpoint=mountpoint,
                filesystem=fs_info.fstype,
                options=options,
                error=f"Mount noktası oluşturulamadı: {exc}",
            )

        # 3. Zaten mount edilmiş mi kontrol et
        if self._is_mounted(mountpoint):
            self._logger.warning(
                "%s zaten mount edilmiş — önce unmount ediliyor", mountpoint
            )
            self.safe_unmount(mountpoint)

        # 4. Mount komutu — privileged helper üzerinden (sudo YOK, CAP YOK)
        self._logger.info(
            "%s mount ediliyor (helper): %s → %s (fs=%s, opts=%s)",
            label,
            device,
            mountpoint,
            fs_info.fstype,
            options,
        )

        ok, error = request_mount(device, mountpoint, fs_info.fstype, options)
        if not ok:
            self._logger.error(
                "Mount başarısız (helper): %s → %s — %s", device, mountpoint, error
            )
            return MountResult(
                success=False,
                device=device,
                mountpoint=mountpoint,
                filesystem=fs_info.fstype,
                options=options,
                error=f"helper mount başarısız: {error}",
            )

        # 5. Mount doğrulama
        expected_ro = "ro" in options.split(",")
        if not self.verify_mount(mountpoint, expected_ro=expected_ro):
            self._logger.error(
                "Mount doğrulama başarısız — güvenli unmount yapılıyor: %s", mountpoint
            )
            self.safe_unmount(mountpoint)
            return MountResult(
                success=False,
                device=device,
                mountpoint=mountpoint,
                filesystem=fs_info.fstype,
                options=options,
                error="Mount doğrulaması başarısız oldu",
            )

        self._logger.info(
            "%s mount başarılı: %s → %s", label, device, mountpoint
        )
        return MountResult(
            success=True,
            device=device,
            mountpoint=mountpoint,
            filesystem=fs_info.fstype,
            options=options,
        )

    def _is_mounted(self, mountpoint: str) -> bool:
        """
        /proc/mounts'tan mount durumunu kontrol et.

        findmnt yerine /proc/mounts doğrudan okunur (daha hızlı).
        """
        try:
            mounts_data = Path("/proc/mounts").read_text(encoding="utf-8")
            # Her satır: device mountpoint fstype options ...
            for line in mounts_data.splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[1] == mountpoint:
                    return True
        except (FileNotFoundError, PermissionError, OSError):
            # macOS veya test ortamında /proc/mounts olmayabilir
            try:
                result = subprocess.run(
                    ["mount"],
                    capture_output=True,
                    text=True,
                    timeout=self._CMD_TIMEOUT,
                )
                if result.returncode == 0 and mountpoint in result.stdout:
                    return True
            except (subprocess.TimeoutExpired, OSError):
                pass

        return False

    def get_usb_label(self, device: str) -> Optional[str]:
        """
        USB cihazının etiketini döndür.

        USB tipi belirleme için kullanılır:
        KIRLI/DIRTY/SOURCE → kaynak USB
        TEMIZ/CLEAN/TARGET → hedef USB
        UPDATE → güncelleme USB'si

        Args:
            device: Blok cihaz yolu

        Returns:
            Etiket string'i veya None
        """
        fs_info = self.detect_filesystem(device)
        return fs_info.label

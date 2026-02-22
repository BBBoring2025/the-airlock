"""
THE AIRLOCK v5.1.1 FORTRESS-HARDENED — Ana Daemon

Tüm modülleri orkestre eder. systemd servis olarak çalışır.

ANA DÖNGÜ:
  1. Başlat → Bileşenleri initialize et
  2. USB bekle (pyudev ile dinle)
  3. USB takıldı:
     a. USBGuard kontrolü → Engellendi? → Alarm + devam
     b. USB tipi belirle (KIRLI / TEMİZ / UPDATE)
     c. Her iki USB hazır → İşleme başla
     d. UPDATE USB → Güncelleme uygula
  4. İşleme (process_usb):
     a. Kaynak USB'yi ro mount
     b. Dosyaları doğrula (symlink, path traversal, boyut)
     c. Her dosyayı tara (ClamAV + YARA + entropy + magic)
     d. CDR uygula (PDF/Office/Resim/Metin)
     e. Temiz USB'ye yaz
     f. Rapor üret + imzala
  5. Tamamlandı → LED/OLED/ses ile bildir
  6. USB çıkarılmasını bekle → başa dön

GÜVENLİK KURALLARI:
  - CDR başarısız → ASLA kopyalama → Karantinaya al
  - Symlink → ASLA takip etme
  - USB HID/CDC → ASLA izin verme → Deauthorize
  - subprocess → ASLA shell=True
  - Kaynak USB → ASLA read-write mount
  - Hata durumunda → ASLA sessizce geçme → Logla

Kullanım:
    daemon = AirlockDaemon(config_path="/opt/airlock/config/airlock.yaml")
    daemon.run()
"""

from __future__ import annotations

import logging
import os
import shutil
import signal
import sys
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional

from app.config import (
    AirlockConfig,
    CDR_IMAGE_TYPES,
    CDR_TEXT_TYPES,
    DANGEROUS_EXTENSIONS,
    DIRECTORIES,
    SOURCE_USB_LABELS,
    TARGET_USB_LABELS,
    UPDATE_USB_LABELS,
    VERSION,
    CODENAME,
)
from app.utils.logger import setup_logging, get_logger
from app.utils.crypto import sha256_file

# Güvenlik modülleri
from app.security.usb_guard import USBGuard, USBDeviceInfo
from app.security.mount_manager import MountManager
from app.security.file_validator import FileValidator
from app.security.scanner import FileScanner, ScanResult
from app.security.cdr_engine import CDREngine
from app.security.archive_handler import ArchiveHandler
from app.security.report_generator import (
    ReportGenerator,
    ScanSession,
    FileEntry,
    USBSourceInfo,
)
from app.updater.offline_updater import OfflineUpdater
from app.processing_pipeline import FileProcessor

# ── Donanım modülleri (opsiyonel — yoksa graceful degrade) ──
try:
    from app.hardware.oled_display import OLEDDisplay  # type: ignore[import-not-found]
except ImportError:
    OLEDDisplay = None  # type: ignore[assignment,misc]

try:
    from app.hardware.led_controller import LEDController  # type: ignore[import-not-found]
except ImportError:
    LEDController = None  # type: ignore[assignment,misc]

try:
    from app.hardware.audio_feedback import AudioFeedback  # type: ignore[import-not-found]
except ImportError:
    AudioFeedback = None  # type: ignore[assignment,misc]

try:
    from app.hardware.button_handler import ButtonHandler  # type: ignore[import-not-found]
except ImportError:
    ButtonHandler = None  # type: ignore[assignment,misc]


logger = get_logger("DAEMON")


# ─────────────────────────────────────────────
# USB Slot Durumu
# ─────────────────────────────────────────────

_USB_TYPE_SOURCE = "source"
_USB_TYPE_TARGET = "target"
_USB_TYPE_UPDATE = "update"
_USB_TYPE_UNKNOWN = "unknown"


# ─────────────────────────────────────────────
# AirlockDaemon
# ─────────────────────────────────────────────


class AirlockDaemon:
    """
    THE AIRLOCK v5.1.1 FORTRESS-HARDENED — Ana orkestrasyon daemon'ı.

    Tüm güvenlik katmanlarını, donanım kontrollerini ve
    raporlama/güncelleme sistemlerini yönetir.
    """

    VERSION = VERSION
    CODENAME = CODENAME

    def __init__(self, config_path: Optional[Path] = None) -> None:
        """
        Tüm bileşenleri başlat.

        Args:
            config_path: airlock.yaml dosya yolu. None ise varsayılan konum.
        """
        # ── Yapılandırma ──
        self._config = AirlockConfig.load(config_path)
        errors = self._config.validate()
        if errors:
            logger.warning(
                "Yapılandırma hataları: %s — varsayılanlarla devam ediliyor",
                errors,
            )

        # ── Loglama ──
        setup_logging(config=self._config)
        self._logger = get_logger("DAEMON")

        # ── Güvenlik modülleri ──
        self._usb_guard = USBGuard()
        self._mount_manager = MountManager()
        self._file_validator = FileValidator(
            policy=self._config.active_policy_settings,
        )
        self._scanner = FileScanner(config=self._config)
        self._cdr_engine = CDREngine(config=self._config)
        self._archive_handler = ArchiveHandler(config=self._config)
        self._report_generator = ReportGenerator(config=self._config)
        self._updater = OfflineUpdater(config=self._config)

        # ── Donanım (opsiyonel — yoksa None) ──
        self._oled = self._init_oled()
        self._led = self._init_led()
        self._audio = self._init_audio()
        self._button = self._init_button()

        # ── Dosya işleme pipeline ──
        self._processor = FileProcessor(
            config=self._config,
            cdr_engine=self._cdr_engine,
            archive_handler=self._archive_handler,
            scanner=self._scanner,
            file_validator=self._file_validator,
            logger=self._logger,
            hw_event_callback=self._hw_event,
            oled=self._oled,
        )

        # ── Durum ──
        self._running = False
        self._processing = False
        self._source_device: Optional[str] = None   # /dev/sdX1
        self._target_device: Optional[str] = None
        self._source_mount: Optional[str] = None     # /mnt/airlock_source
        self._target_mount: Optional[str] = None

        # Mount noktaları — config'den oku, helper regex ile uyumlu OLMALI
        self._source_mountpoint = self._config.mount_source
        self._target_mountpoint = self._config.mount_target

        self._logger.info(
            "AirlockDaemon v%s %s başlatıldı — politika: %s, mount: %s/%s",
            self.VERSION, self.CODENAME, self._config.active_policy,
            self._source_mountpoint, self._target_mountpoint,
        )

    # ═══════════════════════════════════════════
    # ANA DÖNGÜ
    # ═══════════════════════════════════════════

    def run(self) -> None:
        """
        Ana daemon döngüsünü başlat.

        pyudev ile USB olaylarını dinler.
        pyudev yoksa polling fallback kullanır.
        SIGTERM/SIGINT ile temiz kapanış.
        """
        self._running = True
        self._install_signal_handlers()

        # Açılış sekansı
        self._on_startup()

        self._logger.info("USB dinleme başlıyor...")

        try:
            self._run_udev_monitor()
        except ImportError:
            self._logger.warning(
                "pyudev yüklü değil — polling fallback moduna geçiliyor"
            )
            self._run_polling_fallback()
        except Exception as exc:
            self._logger.critical("Ana döngü beklenmeyen hata: %s", exc)
        finally:
            self.cleanup()

    def _run_udev_monitor(self) -> None:
        """pyudev ile USB olaylarını dinle."""
        import pyudev  # noqa: PLC0415

        context = pyudev.Context()
        monitor = pyudev.Monitor.from_netlink(context)
        monitor.filter_by(subsystem="block")

        self._logger.info("pyudev monitor başlatıldı (subsystem=block)")

        for device in iter(monitor.poll, None):
            if not self._running:
                break

            action = device.action
            dev_node = device.device_node

            if not dev_node:
                continue

            # Sadece partition'ları dinle (sdX1, sdX2, …)
            if not dev_node.startswith("/dev/sd"):
                continue

            self._logger.debug("USB olay: %s %s", action, dev_node)

            if action == "add":
                self._on_usb_add(dev_node, device)
            elif action == "remove":
                self._on_usb_remove(dev_node)

    def _run_polling_fallback(self) -> None:
        """
        pyudev yoksa basit polling ile /dev/sd* değişimlerini izle.

        Her 2 saniyede bir kontrol eder.
        """
        known_devices: set = set()

        while self._running:
            current = set()
            dev_path = Path("/dev")

            for entry in dev_path.iterdir():
                name = entry.name
                # sdX1, sdX2, … formatındaki partition'lar
                if name.startswith("sd") and len(name) >= 4 and name[-1].isdigit():
                    current.add(str(entry))

            # Yeni cihazlar
            for dev in current - known_devices:
                self._logger.info("Polling: yeni cihaz tespit edildi: %s", dev)
                self._on_usb_add(dev, None)

            # Çıkarılan cihazlar
            for dev in known_devices - current:
                self._logger.info("Polling: cihaz çıkarıldı: %s", dev)
                self._on_usb_remove(dev)

            known_devices = current
            time.sleep(2)

    # ═══════════════════════════════════════════
    # USB OLAY İŞLEYİCİLERİ
    # ═══════════════════════════════════════════

    def _on_usb_add(self, dev_node: str, udev_device: object) -> None:
        """
        USB cihazı takıldığında çağrılır.

        Adımlar:
          1. USBGuard kontrolü
          2. USB tipi belirle (KIRLI/TEMİZ/UPDATE)
          3. İlgili slot'a ata
          4. Her iki slot doluysa → process_usb()
          5. UPDATE USB → güncelleme uygula
        """
        self._hw_event("usb_detect")

        # ── Adım 1: USBGuard kontrolü ──
        # Block device'ın parent USB cihazını bul
        sysfs_path = self._find_sysfs_path(dev_node)
        if sysfs_path:
            usb_info = self._usb_guard.check_device(sysfs_path)
            if not usb_info.is_allowed:
                self._usb_guard.deauthorize_device(usb_info)
                self._on_usb_blocked(usb_info)
                return
        else:
            self._logger.debug(
                "sysfs yolu bulunamadı: %s — USBGuard atlanıyor", dev_node
            )

        # ── Adım 2: USB etiketini oku → tip belirle ──
        label = self._mount_manager.get_usb_label(dev_node)
        usb_type = self._determine_usb_type(label)

        self._logger.info(
            "USB tespit edildi: %s — etiket=%s, tip=%s",
            dev_node, label, usb_type,
        )

        if self._oled:
            try:
                type_names = {
                    _USB_TYPE_SOURCE: "KAYNAK (Kirli)",
                    _USB_TYPE_TARGET: "HEDEF (Temiz)",
                    _USB_TYPE_UPDATE: "UPDATE",
                    _USB_TYPE_UNKNOWN: f"Bilinmeyen: {label}",
                }
                self._oled.show_usb_detected(type_names.get(usb_type, usb_type))
            except Exception:
                pass

        # ── Adım 3: Slot'a ata ──
        if usb_type == _USB_TYPE_SOURCE:
            self._source_device = dev_node
            self._logger.info("Kaynak USB atandı: %s", dev_node)

        elif usb_type == _USB_TYPE_TARGET:
            self._target_device = dev_node
            self._logger.info("Hedef USB atandı: %s", dev_node)

        elif usb_type == _USB_TYPE_UPDATE:
            self._handle_update_usb(dev_node)
            return

        else:
            # Bilinmeyen etiket — ilk boş slot'a ata
            if self._source_device is None:
                self._source_device = dev_node
                self._logger.info(
                    "Bilinmeyen etiket '%s' → kaynak slot'a atandı: %s",
                    label, dev_node,
                )
            elif self._target_device is None:
                self._target_device = dev_node
                self._logger.info(
                    "Bilinmeyen etiket '%s' → hedef slot'a atandı: %s",
                    label, dev_node,
                )
            else:
                self._logger.warning(
                    "Tüm slot'lar dolu, USB yok sayılıyor: %s", dev_node
                )
                return

        # ── Adım 4: İki USB de hazırsa işleme başla ──
        if self._source_device and self._target_device:
            self._logger.info(
                "Her iki USB hazır — işleme başlıyor: kaynak=%s, hedef=%s",
                self._source_device, self._target_device,
            )
            # İşlemeyi ayrı thread'de başlat (UI güncellemeleri için)
            processing_thread = threading.Thread(
                target=self._process_usb_safe,
                name="airlock-process",
                daemon=True,
            )
            processing_thread.start()

    def _on_usb_remove(self, dev_node: str) -> None:
        """USB cihazı çıkarıldığında çağrılır."""
        if dev_node == self._source_device:
            self._logger.info("Kaynak USB çıkarıldı: %s", dev_node)
            if self._processing:
                self._logger.warning("İşlem devam ederken kaynak USB çıkarıldı!")
            self._source_device = None
            self._safe_unmount(self._source_mountpoint)

        elif dev_node == self._target_device:
            self._logger.info("Hedef USB çıkarıldı: %s", dev_node)
            if self._processing:
                self._logger.warning("İşlem devam ederken hedef USB çıkarıldı!")
            self._target_device = None
            self._safe_unmount(self._target_mountpoint)

        # Slot'lar boşaldıysa idle moduna dön
        if not self._source_device and not self._target_device and not self._processing:
            self._set_idle_state()

    def _on_usb_blocked(self, usb_info: USBDeviceInfo) -> None:
        """BadUSB engelleme — alarm ve bildirim."""
        self._logger.critical(
            "⚠ USB ENGELLENDİ: %s — %s",
            usb_info.display_name, usb_info.block_reason,
        )

        # Donanım alarmı
        if self._led:
            try:
                self._led.blink("blocked", count=10, interval=0.15)
            except Exception:
                pass

        if self._audio:
            try:
                self._audio.play("usb_blocked")
            except Exception:
                pass

        if self._oled:
            try:
                self._oled.show_usb_blocked(
                    usb_info.block_reason or "Unknown threat"
                )
            except Exception:
                pass

    # ═══════════════════════════════════════════
    # ANA İŞLEME AKIŞI
    # ═══════════════════════════════════════════

    def _process_usb_safe(self) -> None:
        """process_usb() wrapper — exception'ları yakalar."""
        try:
            self.process_usb()
        except Exception as exc:
            self._logger.critical("İşleme hatası: %s", exc, exc_info=True)
            self._hw_event("error")
            if self._oled:
                try:
                    self._oled.show_error(str(exc)[:60])
                except Exception:
                    pass
        finally:
            self._processing = False

    def process_usb(self) -> None:
        """
        Ana işleme akışı.

        Tam pipeline: mount → validate → scan → CDR → rapor.
        """
        self._processing = True
        self._hw_event("scanning")

        session = ScanSession(policy=self._config.active_policy)
        session.start()

        source_dev = self._source_device
        target_dev = self._target_device

        if not source_dev or not target_dev:
            self._logger.error("İşleme iptal — kaynak veya hedef eksik")
            self._processing = False
            return

        # ── 1. Kaynak USB'yi READ-ONLY mount ──
        source_result = self._mount_manager.mount_source(
            source_dev, self._source_mountpoint
        )
        if not source_result.success:
            self._logger.error(
                "Kaynak USB mount başarısız: %s — %s",
                source_dev, source_result.error,
            )
            self._processing = False
            self._hw_event("error")
            return

        self._source_mount = self._source_mountpoint

        # Kaynak USB bilgilerini session'a ekle
        fs_info = self._mount_manager.detect_filesystem(source_dev)
        session.usb_source = USBSourceInfo(
            filesystem=source_result.filesystem,
            label=fs_info.label or "",
        )

        # ── 2. Hedef USB'yi mount ──
        target_result = self._mount_manager.mount_target(
            target_dev, self._target_mountpoint
        )
        if not target_result.success:
            self._logger.error(
                "Hedef USB mount başarısız: %s — %s",
                target_dev, target_result.error,
            )
            self._safe_unmount(self._source_mountpoint)
            self._processing = False
            self._hw_event("error")
            return

        self._target_mount = self._target_mountpoint

        source_root = Path(self._source_mountpoint)
        target_root = Path(self._target_mountpoint)

        # ── 3. Toplu dosya doğrulama ──
        self._logger.info("Dosya doğrulama başlıyor...")
        batch_result = self._file_validator.validate_batch(source_root)

        if not batch_result.is_within_limits:
            self._logger.error(
                "Toplu doğrulama limiti aşıldı: %s",
                batch_result.limit_violation,
            )
            self._finish_processing(session, source_root, target_root)
            return

        # Engellenen dosyaları session'a ekle
        for blocked in batch_result.blocked_files:
            # GÜVENLİK: Symlink dosyalarda sha256_file() ve .stat() ÇAĞIRMA!
            # Symlink'i takip etmek saldırganın istediği şeydir.
            if blocked.filepath.is_symlink():
                # Sadece os.readlink() ile hedefi string olarak rapora yaz
                try:
                    link_target = os.readlink(blocked.filepath)
                except OSError:
                    link_target = "<okunamadı>"

                entry = FileEntry(
                    original_path=str(blocked.filepath.relative_to(source_root)),
                    original_sha256="",  # ASLA hesaplama — symlink takip riski
                    original_size=0,     # ASLA stat çağırma — symlink takip riski
                    action="blocked_symlink",
                    detections=[{
                        "engine": "validator",
                        "rule": "SYMLINK_BLOCKED",
                        "detail": f"symlink -> {link_target}",
                    }],
                )
            else:
                # Normal engellenen dosya — güvenle sha256/stat yapılabilir
                try:
                    file_sha256 = sha256_file(blocked.filepath) if blocked.filepath.exists() else ""
                except OSError:
                    file_sha256 = ""
                try:
                    file_size = blocked.filepath.lstat().st_size if blocked.filepath.exists() else 0
                except OSError:
                    file_size = 0

                entry = FileEntry(
                    original_path=str(blocked.filepath.relative_to(source_root)),
                    original_sha256=file_sha256,
                    original_size=file_size,
                    action="blocked",
                    detections=[{
                        "engine": "validator",
                        "rule": "FILE_VALIDATION",
                        "detail": blocked.block_reason or "",
                    }],
                )
            session.add_file(entry)

        # ── 4. Her güvenli dosyayı işle ──
        safe_files = batch_result.safe_files
        total = len(safe_files)
        self._logger.info("İşlenecek dosya sayısı: %d", total)

        for idx, filepath in enumerate(safe_files, 1):
            if not self._running:
                self._logger.warning("İşlem iptal edildi (signal)")
                break

            try:
                relative = filepath.relative_to(source_root)
            except ValueError:
                relative = Path(filepath.name)

            # OLED ilerleme
            if self._oled:
                try:
                    self._oled.show_scanning(
                        filename=filepath.name[:20],
                        progress=int(idx / total * 100),
                        current=idx,
                        total=total,
                        threats=session.summary.threats_detected,
                    )
                except Exception:
                    pass

            # ── 4. Dosyayı işle (tarama → karar → CDR/kopya/karantina) ──
            self._processor.process_file(
                filepath, relative, source_root, target_root, session
            )

        # ── 5. Rapor üret ve yaz ──
        self._finish_processing(session, source_root, target_root)

    # ═══════════════════════════════════════════
    # İŞLEM TAMAMLAMA
    # ═══════════════════════════════════════════

    def _finish_processing(
        self,
        session: ScanSession,
        source_root: Path,
        target_root: Path,
    ) -> None:
        """İşlemi tamamla: rapor üret, manifest yaz, unmount, bildir."""
        session.finish()

        # Rapor üret
        report = self._report_generator.generate(session)

        # Rapor yaz (USB + log dizini)
        self._report_generator.write_report(
            report, target_root, DIRECTORIES["logs"], sign=True
        )

        # Manifest yaz
        self._report_generator.write_manifest(session.files, target_root)

        # Unmount
        self._safe_unmount(self._source_mountpoint)
        self._safe_unmount(self._target_mountpoint)
        self._source_mount = None
        self._target_mount = None

        # Donanım bildirimi
        summary = session.summary
        has_threats = summary.threats_detected > 0

        if self._oled:
            try:
                self._oled.show_complete(
                    total=summary.total_files,
                    clean=summary.processed,
                    threats=summary.threats_detected,
                    duration=summary.duration_seconds,
                )
            except Exception:
                pass

        if has_threats:
            self._hw_event("threat")
        else:
            self._hw_event("complete")

        self._logger.info(
            "═══ İŞLEM TAMAMLANDI ═══ "
            "toplam=%d, işlenen=%d, engel=%d, karantina=%d, "
            "CDR=%d, CDR_fail=%d, tehdit=%d, süre=%.1fs",
            summary.total_files, summary.processed,
            summary.blocked, summary.quarantined,
            summary.cdr_applied, summary.cdr_failed,
            summary.threats_detected, summary.duration_seconds,
        )

    # ═══════════════════════════════════════════
    # UPDATE USB
    # ═══════════════════════════════════════════

    def _handle_update_usb(self, dev_node: str) -> None:
        """UPDATE USB tespit edildiğinde güncelleme uygula."""
        self._logger.info("UPDATE USB tespit edildi: %s", dev_node)
        self._hw_event("update")

        if self._oled:
            try:
                self._oled.show_update("Doğrulama", 10)
            except Exception:
                pass

        # Mount (read-only) — config'den oku
        update_mountpoint = self._config.mount_update
        mount_result = self._mount_manager.mount_source(dev_node, update_mountpoint)
        if not mount_result.success:
            self._logger.error("UPDATE USB mount başarısız: %s", mount_result.error)
            self._hw_event("error")
            return

        try:
            update_path = Path(update_mountpoint)

            # Doğrula
            verification = self._updater.verify_update_package(update_path)
            if not verification.is_valid:
                self._logger.error(
                    "UPDATE REDDEDİLDİ: %s", verification.rejection_reason
                )
                self._hw_event("error")
                if self._oled:
                    try:
                        self._oled.show_error(f"UPDATE RED: {verification.rejection_reason[:40]}")
                    except Exception:
                        pass
                return

            if self._oled:
                try:
                    self._oled.show_update("Uygulanıyor", 50)
                except Exception:
                    pass

            # Uygula
            result = self._updater.apply_updates(update_path)

            if result.success:
                self._logger.info("Güncelleme başarılı: %s", result.components_updated)
                # Scanner cache'lerini yenile
                self._scanner.reload_yara_rules()
                self._scanner.reload_known_hashes()
                self._hw_event("complete")
                if self._oled:
                    try:
                        self._oled.show_update("Tamamlandı", 100)
                    except Exception:
                        pass
            else:
                self._logger.error("Güncelleme kısmen başarısız: %s", result.errors)
                self._hw_event("error")

        finally:
            self._safe_unmount(update_mountpoint)

    # ═══════════════════════════════════════════
    # BUTON CALLBACK'LERİ
    # ═══════════════════════════════════════════

    def _handle_short_press(self) -> None:
        """Kısa basış: güvenli çıkar — işlemi durdur + USB unmount."""
        self._logger.info("Buton: kısa basış — güvenli çıkar")
        self._hw_event("button")

        self._processing = False  # İşlemi durdur signal'i

        self._safe_unmount(self._source_mountpoint)
        self._safe_unmount(self._target_mountpoint)
        self._source_device = None
        self._target_device = None
        self._source_mount = None
        self._target_mount = None

        self._set_idle_state()

    def _handle_long_press(self) -> None:
        """Uzun basış: sistemi kapat."""
        self._logger.info("Buton: uzun basış — sistem kapatılıyor")

        if self._oled:
            try:
                self._oled.show_shutdown()
            except Exception:
                pass

        if self._audio:
            try:
                self._audio.play("shutdown", blocking=True)
            except Exception:
                pass

        self.cleanup()

        import subprocess  # noqa: PLC0415
        try:
            subprocess.run(
                ["systemctl", "poweroff"],
                timeout=10,
                shell=False,
            )
        except Exception as exc:
            self._logger.error("Shutdown başarısız: %s", exc)

    # ═══════════════════════════════════════════
    # SIGNAL HANDLER
    # ═══════════════════════════════════════════

    def _install_signal_handlers(self) -> None:
        """SIGTERM ve SIGINT handler'larını kur."""
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)

    def _signal_handler(self, signum: int, frame: object) -> None:
        """Sinyal yakalandığında temiz kapanış."""
        sig_name = signal.Signals(signum).name
        self._logger.info("Sinyal alındı: %s — temiz kapanış başlıyor", sig_name)
        self._running = False

    # ═══════════════════════════════════════════
    # TEMİZLİK
    # ═══════════════════════════════════════════

    def cleanup(self) -> None:
        """Tüm kaynakları temizle — daemon kapanırken çağrılır."""
        self._logger.info("Temizlik başlıyor...")
        self._running = False

        # Mount noktalarını unmount et
        self._safe_unmount(self._source_mountpoint)
        self._safe_unmount(self._target_mountpoint)

        # Donanım temizliği
        if self._led:
            try:
                self._led.off()
                self._led.cleanup()
            except Exception:
                pass

        if self._oled:
            try:
                self._oled.clear()
            except Exception:
                pass

        if self._audio:
            try:
                self._audio.cleanup()
            except Exception:
                pass

        if self._button:
            try:
                self._button.cleanup()
            except Exception:
                pass

        self._logger.info("Temizlik tamamlandı — daemon kapanıyor")

    # ═══════════════════════════════════════════
    # DAHİLİ YARDIMCILAR
    # ═══════════════════════════════════════════

    def _on_startup(self) -> None:
        """Açılış sekansı — logo, ses, LED."""
        self._logger.info(
            "═══ THE AIRLOCK v%s %s ═══", self.VERSION, self.CODENAME,
        )

        if self._oled:
            try:
                self._oled.show_splash()
            except Exception:
                pass

        if self._audio:
            try:
                self._audio.play("startup")
            except Exception:
                pass

        if self._led:
            try:
                self._led.pulse("startup", duration=1.5)
            except Exception:
                pass

        time.sleep(2)
        self._set_idle_state()

    def _set_idle_state(self) -> None:
        """Bekleme moduna geç — LED mavi, OLED bekleme ekranı."""
        if self._led:
            try:
                self._led.set_color("idle")
            except Exception:
                pass

        if self._oled:
            try:
                self._oled.show_idle()
            except Exception:
                pass

    def _hw_event(self, event: str) -> None:
        """Donanım olayı — LED + ses birlikte."""
        led_map = {
            "usb_detect": None,
            "scanning": "scanning",
            "cdr": "cdr",
            "threat": "threat",
            "complete": "complete",
            "error": "threat",
            "blocked": "blocked",
            "update": "update",
            "button": None,
        }

        audio_map = {
            "usb_detect": "usb_detect",
            "scanning": None,
            "cdr": None,
            "threat": "threat",
            "complete": "complete",
            "error": "error",
            "blocked": "usb_blocked",
            "update": None,
            "button": "button",
        }

        color = led_map.get(event)
        if color and self._led:
            try:
                if event in ("threat", "blocked"):
                    self._led.blink(color, count=5, interval=0.2)
                elif event == "cdr":
                    self._led.blink(color, count=2, interval=0.3)
                else:
                    self._led.set_color(color)
            except Exception:
                pass

        sound = audio_map.get(event)
        if sound and self._audio:
            try:
                self._audio.play(sound)
            except Exception:
                pass

    def _safe_unmount(self, mountpoint: str) -> None:
        """Güvenli unmount — hata logla ama çökertme."""
        try:
            mount_path = Path(mountpoint)
            if mount_path.exists():
                self._mount_manager.safe_unmount(mountpoint)
        except Exception as exc:
            self._logger.error("Unmount hatası (%s): %s", mountpoint, exc)

    @staticmethod
    def _determine_usb_type(label: Optional[str]) -> str:
        """USB etiketinden cihaz tipini belirle."""
        if not label:
            return _USB_TYPE_UNKNOWN

        label_upper = label.upper()

        if label_upper in {lbl.upper() for lbl in SOURCE_USB_LABELS}:
            return _USB_TYPE_SOURCE
        if label_upper in {lbl.upper() for lbl in TARGET_USB_LABELS}:
            return _USB_TYPE_TARGET
        if label_upper in {lbl.upper() for lbl in UPDATE_USB_LABELS}:
            return _USB_TYPE_UPDATE

        return _USB_TYPE_UNKNOWN

    @staticmethod
    def _find_sysfs_path(dev_node: str) -> Optional[str]:
        """
        /dev/sdX1 → /sys/bus/usb/devices/X-Y sysfs yolunu bul.

        /sys/block/sdX → device → ../../../ ile USB cihaz dizinine ulaşır.
        """
        # /dev/sda1 → sda
        dev_name = Path(dev_node).name
        # Partition numarasını kaldır → disk adı
        disk_name = dev_name.rstrip("0123456789")

        device_link = Path(f"/sys/block/{disk_name}/device")

        if not device_link.exists():
            return None

        try:
            real_path = device_link.resolve()
            # USB cihaz dizinine kadar çık (idVendor dosyası olan dizin)
            current = real_path
            for _ in range(10):
                if (current / "idVendor").exists():
                    return str(current)
                current = current.parent
                if current == Path("/"):
                    break
        except (OSError, ValueError):
            pass

        return None

    # ── Donanım Initialization (opsiyonel) ──

    def _init_oled(self) -> Optional[object]:
        """OLED ekranı başlat. Yoksa None döner."""
        if not self._config.oled_enabled or OLEDDisplay is None:
            return None
        try:
            oled = OLEDDisplay(address=self._config.oled_address)
            if hasattr(oled, "available") and not oled.available:
                self._logger.info("OLED ekran bulunamadı — devre dışı")
                return None
            self._logger.info("OLED ekran başlatıldı")
            return oled
        except Exception as exc:
            self._logger.info("OLED başlatma hatası: %s — devre dışı", exc)
            return None

    def _init_led(self) -> Optional[object]:
        """LED kontrolcüsü başlat. Yoksa None döner."""
        if LEDController is None:
            return None
        try:
            led = LEDController(mode=self._config.led_mode)
            if hasattr(led, "available") and not led.available:
                self._logger.info("LED bulunamadı — devre dışı")
                return None
            self._logger.info("LED kontrolcüsü başlatıldı (mod=%s)", self._config.led_mode)
            return led
        except Exception as exc:
            self._logger.info("LED başlatma hatası: %s — devre dışı", exc)
            return None

    def _init_audio(self) -> Optional[object]:
        """Ses sistemi başlat. Yoksa None döner."""
        if not self._config.audio_enabled or AudioFeedback is None:
            return None
        try:
            audio = AudioFeedback()
            if hasattr(audio, "available") and not audio.available:
                self._logger.info("Ses sistemi bulunamadı — devre dışı")
                return None
            self._logger.info("Ses sistemi başlatıldı")
            return audio
        except Exception as exc:
            self._logger.info("Ses başlatma hatası: %s — devre dışı", exc)
            return None

    def _init_button(self) -> Optional[object]:
        """Buton handler başlat. Yoksa None döner."""
        if not self._config.button_enabled or ButtonHandler is None:
            return None
        try:
            button = ButtonHandler(
                pin=self._config.button_pin,
                on_short_press=self._handle_short_press,
                on_long_press=self._handle_long_press,
            )
            if hasattr(button, "available") and not button.available:
                self._logger.info("Buton bulunamadı — devre dışı")
                return None
            self._logger.info("Buton handler başlatıldı (pin=%d)", self._config.button_pin)
            return button
        except Exception as exc:
            self._logger.info("Buton başlatma hatası: %s — devre dışı", exc)
            return None

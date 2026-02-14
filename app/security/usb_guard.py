"""
THE AIRLOCK v5.0.8 FORTRESS-HARDENED — KATMAN 1: USB Cihaz Sınıfı Kontrolü

BadUSB / Rubber Ducky korumasının TEMELİ.
USB takıldığında cihazın kendini nasıl tanıttığını kontrol eder.
Sadece Mass Storage (class 0x08) sınıfına izin verir.
HID (klavye/fare), CDC, Wireless vb. → ANINDA ENGELLE + DEAUTHORIZE

Katmanlı savunma:
  1. USBGuard (kernel seviyesi) — udev kuralları ile
  2. Python sysfs kontrolü — runtime doğrulama (bu modül)
  3. Bilinen kötü VID:PID listesi

Kullanım:
    guard = USBGuard()
    result = guard.check_device("/sys/bus/usb/devices/1-1")
    if not result.is_allowed:
        guard.deauthorize_device(result)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from app.config import (
    ALLOWED_USB_CLASSES,
    BLOCKED_USB_CLASSES,
    KNOWN_BAD_USB_DEVICES,
    USBClass,
)
from app.utils.helper_client import request_deauthorize

logger = logging.getLogger("AIRLOCK.USB_GUARD")


# ─────────────────────────────────────────────
# Veri Yapıları
# ─────────────────────────────────────────────


@dataclass
class USBDeviceInfo:
    """Tespit edilen USB cihazının tüm bilgileri."""

    sysfs_path: str
    bus: str
    device: str
    vendor_id: str
    product_id: str
    manufacturer: str
    product: str
    serial: str
    device_class: int
    interface_classes: List[int] = field(default_factory=list)
    is_allowed: bool = True
    block_reason: Optional[str] = None

    @property
    def device_id(self) -> str:
        """VID:PID formatında cihaz tanımlayıcı."""
        return f"{self.vendor_id}:{self.product_id}"

    @property
    def display_name(self) -> str:
        """İnsan-okunabilir cihaz adı."""
        return f"{self.manufacturer} {self.product} ({self.device_id})"


# ─────────────────────────────────────────────
# USB Guard Ana Sınıfı
# ─────────────────────────────────────────────


class USBGuard:
    """
    USB cihaz sınıfı kontrolcüsü.

    sysfs üzerinden cihaz bilgilerini okur, güvenlik kontrollerini uygular.
    İzin verilmeyen cihazları kernel seviyesinde deauthorize eder.

    Kullanım:
        guard = USBGuard()
        info = guard.check_device("/sys/bus/usb/devices/1-1")
        if not info.is_allowed:
            guard.deauthorize_device(info)
    """

    def __init__(self) -> None:
        self._logger = logging.getLogger("AIRLOCK.USB_GUARD")

    # ── Ana Kontrol ──

    def check_device(self, sysfs_path: str) -> USBDeviceInfo:
        """
        USB cihazını sysfs üzerinden kontrol et.

        5 aşamalı kontrol:
          1. Bilinen kötü cihaz mı? (VID:PID)
          2. Device class tehlikeli mi?
          3. Interface class'larında tehlikeli var mı?
          4. Hiç interface yok mu? (şüpheli)
          5. Karışık interface'ler mi? (composite device trick)

        Args:
            sysfs_path: /sys/bus/usb/devices/ altındaki cihaz yolu

        Returns:
            USBDeviceInfo: Cihaz bilgileri + izin durumu
        """
        path = Path(sysfs_path)

        # Temel bilgileri sysfs'ten oku
        vid = self._read_sysfs(path / "idVendor", "0000")
        pid = self._read_sysfs(path / "idProduct", "0000")
        device_class = int(self._read_sysfs(path / "bDeviceClass", "0"), 16)
        manufacturer = self._read_sysfs(path / "manufacturer", "Unknown")
        product = self._read_sysfs(path / "product", "Unknown")
        serial = self._read_sysfs(path / "serial", "N/A")

        # Interface sınıflarını oku
        # ÖNEMLİ: Composite device'lar birden fazla interface'e sahip olabilir
        interface_classes = self._read_interface_classes(path)

        # Güvenlik kararını ver
        is_allowed, block_reason = self._evaluate_device(
            vid=vid,
            pid=pid,
            device_class=device_class,
            interface_classes=interface_classes,
        )

        info = USBDeviceInfo(
            sysfs_path=sysfs_path,
            bus=path.parent.name if path.parent else "",
            device=path.name,
            vendor_id=vid,
            product_id=pid,
            manufacturer=manufacturer,
            product=product,
            serial=serial,
            device_class=device_class,
            interface_classes=interface_classes,
            is_allowed=is_allowed,
            block_reason=block_reason,
        )

        # Sonucu logla
        if is_allowed:
            self._logger.info(
                "USB İZİN VERİLDİ: %s [sınıf=0x%02x, interface=%s]",
                info.display_name,
                device_class,
                [f"0x{c:02x}" for c in interface_classes],
            )
        else:
            self._logger.warning(
                "USB ENGELLENDİ: %s — %s [sınıf=0x%02x, interface=%s, seri=%s]",
                info.display_name,
                block_reason,
                device_class,
                [f"0x{c:02x}" for c in interface_classes],
                serial,
            )

        return info

    # ── Deauthorize ──

    def deauthorize_device(self, device_info: USBDeviceInfo) -> bool:
        """
        Cihazı kernel seviyesinde deauthorize et.

        /sys/bus/usb/devices/<device>/authorized → 0 yazarak
        cihazın tüm iletişimini keser.

        Privileged helper üzerinden yapılır — ana servis root değildir.
        udev kuralları da ayrıca /usr/local/bin/airlock-deauth ile engeller.

        Args:
            device_info: Engellenecek cihaz bilgisi

        Returns:
            True: başarıyla deauthorize edildi
            False: deauthorize başarısız
        """
        auth_path = f"/sys/bus/usb/devices/{device_info.device}/authorized"

        # Privileged helper üzerinden deauthorize
        ok, error = request_deauthorize(auth_path)
        if ok:
            self._logger.warning(
                "DEAUTHORIZED (helper): %s (%s)",
                device_info.display_name,
                device_info.block_reason,
            )
            return True

        self._logger.error("Helper deauthorize başarısız: %s — %s", auth_path, error)

        # Fallback: doğrudan yazma dene (eğer izin varsa)
        try:
            Path(auth_path).write_text("0")
            self._logger.warning(
                "DEAUTHORIZED (direct fallback): %s (%s)",
                device_info.display_name,
                device_info.block_reason,
            )
            return True
        except (PermissionError, FileNotFoundError, OSError) as exc:
            self._logger.error("Direct deauthorize de başarısız: %s", exc)

        self._logger.critical(
            "DEAUTHORIZE BAŞARISIZ — TEHLİKELİ CİHAZ AKTİF KALABİLİR: %s",
            device_info.display_name,
        )
        return False

    # ── Toplu Tarama ──

    def scan_all_devices(self) -> List[USBDeviceInfo]:
        """
        Şu anda bağlı tüm USB cihazlarını kontrol et.

        /sys/bus/usb/devices/ altındaki tüm cihazları tarar.
        Hub cihazları (class 0x09) atlanır.

        Returns:
            Tespit edilen tüm cihaz bilgileri listesi
        """
        devices: List[USBDeviceInfo] = []
        usb_devices_path = Path("/sys/bus/usb/devices")

        if not usb_devices_path.exists():
            self._logger.warning("sysfs USB dizini bulunamadı: %s", usb_devices_path)
            return devices

        for device_dir in sorted(usb_devices_path.iterdir()):
            # Sadece gerçek USB cihaz dizinlerini kontrol et (X-Y formatında)
            if not (device_dir / "idVendor").exists():
                continue

            info = self.check_device(str(device_dir))
            devices.append(info)

        return devices

    # ── Dahili Yardımcılar ──

    def _evaluate_device(
        self,
        vid: str,
        pid: str,
        device_class: int,
        interface_classes: List[int],
    ) -> tuple[bool, Optional[str]]:
        """
        5 aşamalı güvenlik değerlendirmesi.

        Returns:
            (is_allowed, block_reason) tuple
        """
        device_id = f"{vid}:{pid}"

        # Kontrol 1: Bilinen kötü cihaz mı?
        if device_id in KNOWN_BAD_USB_DEVICES:
            return False, f"KNOWN_BAD_DEVICE: {device_id}"

        # Kontrol 2: Device class seviyesinde tehlikeli mi?
        if device_class in BLOCKED_USB_CLASSES:
            return False, f"BLOCKED_DEVICE_CLASS: 0x{device_class:02x} ({self._class_name(device_class)})"

        # Kontrol 3: Interface class'larında tehlikeli var mı?
        for iface_class in interface_classes:
            # Hub (0x09) interface'i normal — atla
            if iface_class == USBClass.HUB:
                continue
            if iface_class not in ALLOWED_USB_CLASSES:
                return (
                    False,
                    f"BLOCKED_INTERFACE_CLASS: 0x{iface_class:02x} ({self._class_name(iface_class)})",
                )

        # Kontrol 4: Hiç interface yok → şüpheli
        if not interface_classes:
            return False, "NO_INTERFACES_DETECTED"

        # Kontrol 5: Sadece Mass Storage olmalı (composite device trick koruması)
        non_hub_interfaces = [c for c in interface_classes if c != USBClass.HUB]
        if non_hub_interfaces and not all(
            c == USBClass.MASS_STORAGE for c in non_hub_interfaces
        ):
            return (
                False,
                f"MIXED_INTERFACES: {[f'0x{c:02x}' for c in non_hub_interfaces]}",
            )

        return True, None

    def _read_interface_classes(self, device_path: Path) -> List[int]:
        """
        Cihazın tüm interface sınıflarını oku.

        sysfs'te interface dizinleri X-Y:C.I formatındadır.
        Her birinin altındaki bInterfaceClass dosyasından sınıf kodu okunur.
        """
        classes: List[int] = []

        for iface_dir in sorted(device_path.glob("*:*")):
            iface_class_file = iface_dir / "bInterfaceClass"
            if not iface_class_file.exists():
                continue
            try:
                raw = iface_class_file.read_text().strip()
                classes.append(int(raw, 16))
            except (ValueError, PermissionError, OSError):
                self._logger.debug(
                    "Interface sınıfı okunamadı: %s", iface_class_file
                )

        return classes

    @staticmethod
    def _read_sysfs(path: Path, default: str = "") -> str:
        """sysfs dosyasını güvenli oku. Hata durumunda varsayılan döndür."""
        try:
            return path.read_text().strip()
        except (FileNotFoundError, PermissionError, OSError):
            return default

    @staticmethod
    def _class_name(class_code: int) -> str:
        """USB sınıf kodunun insan-okunabilir adı."""
        names = {
            0x01: "Audio",
            0x02: "CDC",
            0x03: "HID",
            0x05: "Physical",
            0x06: "Image",
            0x07: "Printer",
            0x08: "MassStorage",
            0x09: "Hub",
            0x0A: "CDC-Data",
            0x0B: "SmartCard",
            0x0E: "Video",
            0xE0: "Wireless",
            0xEF: "Miscellaneous",
            0xFF: "VendorSpecific",
        }
        return names.get(class_code, f"Unknown(0x{class_code:02x})")

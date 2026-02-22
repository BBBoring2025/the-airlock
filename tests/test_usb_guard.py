"""
THE AIRLOCK v5.1.1 FORTRESS-HARDENED — USB Guard Hermetic Tests

Tum testler HERMETIK: sysfs yapısı tempdir'de simüle edilir.
subprocess çağrısı YOK — USBGuard tamamen sysfs I/O tabanlı.

Test edilen modül: app/security/usb_guard.py

Kullanım:
    python -m pytest tests/test_usb_guard.py -v
"""

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from app.security.usb_guard import USBDeviceInfo, USBGuard


class _USBGuardTestBase(unittest.TestCase):
    """Ortak setUp/tearDown — sahte sysfs dizin yapısı."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp(prefix="airlock_usb_test_")
        self.sysfs_root = Path(self.tmpdir) / "sys" / "bus" / "usb" / "devices"
        self.sysfs_root.mkdir(parents=True)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _create_device(
        self,
        name: str,
        vendor_id: str = "0781",
        product_id: str = "5567",
        device_class: str = "00",
        manufacturer: str = "SanDisk",
        product: str = "Cruzer",
        serial: str = "ABC123",
        interfaces: dict[str, str] | None = None,
    ) -> Path:
        """
        Sahte sysfs USB cihaz dizini oluştur.

        interfaces: {"1-1:1.0": "08", "1-1:1.1": "03"} gibi
        """
        dev_dir = self.sysfs_root / name
        dev_dir.mkdir(parents=True)

        (dev_dir / "idVendor").write_text(vendor_id)
        (dev_dir / "idProduct").write_text(product_id)
        (dev_dir / "bDeviceClass").write_text(device_class)
        (dev_dir / "manufacturer").write_text(manufacturer)
        (dev_dir / "product").write_text(product)
        (dev_dir / "serial").write_text(serial)

        if interfaces is not None:
            for iface_name, iface_class in interfaces.items():
                iface_dir = dev_dir / iface_name
                iface_dir.mkdir()
                (iface_dir / "bInterfaceClass").write_text(iface_class)

        return dev_dir


# ═══════════════════════════════════════════════
# USB Device Classification Tests
# ═══════════════════════════════════════════════


class TestUSBDeviceClassification(_USBGuardTestBase):
    """USB cihaz sınıf kontrol testleri — 5 aşamalı değerlendirme."""

    def test_mass_storage_allowed(self) -> None:
        """Mass Storage (0x08) cihaz → izin verilmeli."""
        dev_dir = self._create_device(
            "1-1",
            device_class="00",
            interfaces={"1-1:1.0": "08"},  # Mass Storage
        )
        guard = USBGuard()
        info = guard.check_device(str(dev_dir))

        self.assertTrue(info.is_allowed)
        self.assertIsNone(info.block_reason)
        self.assertEqual(info.vendor_id, "0781")

    def test_hid_device_blocked(self) -> None:
        """HID (0x03) device class → ENGELLENMELİ."""
        dev_dir = self._create_device(
            "1-2",
            device_class="03",  # HID
            interfaces={"1-2:1.0": "03"},
        )
        guard = USBGuard()
        info = guard.check_device(str(dev_dir))

        self.assertFalse(info.is_allowed)
        self.assertIn("BLOCKED_DEVICE_CLASS", info.block_reason)

    def test_known_bad_vid_pid_blocked(self) -> None:
        """Teensy VID:PID (16c0:0486) → bilinen kötü cihaz ENGELLENMELİ."""
        dev_dir = self._create_device(
            "1-3",
            vendor_id="16c0",
            product_id="0486",
            device_class="00",
            manufacturer="Teensy",
            product="HalfKay Bootloader",
            interfaces={"1-3:1.0": "08"},  # Mass Storage olsa bile!
        )
        guard = USBGuard()
        info = guard.check_device(str(dev_dir))

        self.assertFalse(info.is_allowed)
        self.assertIn("KNOWN_BAD_DEVICE", info.block_reason)

    def test_cdc_interface_blocked(self) -> None:
        """CDC (0x02) interface → ENGELLENMELİ."""
        dev_dir = self._create_device(
            "1-4",
            device_class="00",
            interfaces={"1-4:1.0": "02"},  # CDC
        )
        guard = USBGuard()
        info = guard.check_device(str(dev_dir))

        self.assertFalse(info.is_allowed)
        self.assertIn("BLOCKED_INTERFACE_CLASS", info.block_reason)

    def test_no_interfaces_blocked(self) -> None:
        """Interface yok → şüpheli, ENGELLENMELİ."""
        dev_dir = self._create_device(
            "1-5",
            device_class="00",
            interfaces={},  # Hiç interface yok
        )
        guard = USBGuard()
        info = guard.check_device(str(dev_dir))

        self.assertFalse(info.is_allowed)
        self.assertIn("NO_INTERFACES", info.block_reason)

    def test_mixed_interfaces_blocked(self) -> None:
        """Mass Storage + HID karışık → BLOCKED_INTERFACE_CLASS (HID yakalanır).

        NOT: _evaluate_device'te Kontrol 3 (interface class filtresi) Kontrol 5'ten
        (MIXED_INTERFACES) önce çalışır. HID (0x03) BLOCKED_USB_CLASSES'ta olduğu
        için Kontrol 3'te yakalanır. Bu doğru davranıştır — composite device trick
        her durumda engellenir.
        """
        dev_dir = self._create_device(
            "1-6",
            device_class="00",
            interfaces={
                "1-6:1.0": "08",  # Mass Storage
                "1-6:1.1": "03",  # HID — BadUSB trick!
            },
        )
        guard = USBGuard()
        info = guard.check_device(str(dev_dir))

        self.assertFalse(info.is_allowed)
        # HID interface Kontrol 3'te yakalanır (BLOCKED_INTERFACE_CLASS)
        self.assertIn("BLOCKED_INTERFACE_CLASS", info.block_reason)
        self.assertIn("0x03", info.block_reason)


# ═══════════════════════════════════════════════
# Deauthorize Tests
# ═══════════════════════════════════════════════


class TestDeauthorize(_USBGuardTestBase):
    """USB deauthorize testleri — helper + fallback."""

    @patch("app.security.usb_guard.request_deauthorize")
    def test_deauthorize_via_helper_success(self, mock_deauth: MagicMock) -> None:
        """Helper başarılı → True döner."""
        mock_deauth.return_value = (True, None)

        guard = USBGuard()
        device_info = USBDeviceInfo(
            sysfs_path="/sys/bus/usb/devices/1-1",
            bus="usb1",
            device="1-1",
            vendor_id="16c0",
            product_id="0486",
            manufacturer="Teensy",
            product="HalfKay",
            serial="N/A",
            device_class=0x00,
            interface_classes=[0x03],
            is_allowed=False,
            block_reason="KNOWN_BAD_DEVICE",
        )

        result = guard.deauthorize_device(device_info)

        self.assertTrue(result)
        mock_deauth.assert_called_once()

    @patch("app.security.usb_guard.request_deauthorize")
    def test_deauthorize_helper_fails_direct_fallback(self, mock_deauth: MagicMock) -> None:
        """Helper başarısız → direct write fallback."""
        mock_deauth.return_value = (False, "HELPER_UNAVAILABLE")

        guard = USBGuard()

        # Sahte authorized dosyası oluştur
        dev_dir = self._create_device("1-7", interfaces={"1-7:1.0": "03"})
        auth_file = Path(self.tmpdir) / "sys" / "bus" / "usb" / "devices" / "1-7" / "authorized"
        auth_file.write_text("1")

        device_info = USBDeviceInfo(
            sysfs_path=str(dev_dir),
            bus="usb1",
            device="1-7",
            vendor_id="dead",
            product_id="beef",
            manufacturer="Evil",
            product="BadUSB",
            serial="N/A",
            device_class=0x00,
            interface_classes=[0x03],
            is_allowed=False,
            block_reason="BLOCKED_INTERFACE_CLASS",
        )

        # Fallback path'i düzelt — deauthorize_device auth_path'i
        # f"/sys/bus/usb/devices/{device_info.device}/authorized" olarak oluşturur
        # Bu test ortamında gerçek /sys kullanamayız, mock ile çözelim
        with patch("app.security.usb_guard.Path") as mock_path_cls:
            mock_path_instance = MagicMock()
            mock_path_cls.return_value = mock_path_instance
            mock_path_instance.write_text.return_value = None

            result = guard.deauthorize_device(device_info)

        self.assertTrue(result)


# ═══════════════════════════════════════════════
# Scan All Devices Tests
# ═══════════════════════════════════════════════


class TestScanAllDevices(_USBGuardTestBase):
    """Toplu cihaz tarama testleri."""

    def test_scan_all_devices_finds_devices(self) -> None:
        """2 USB cihaz → 2 USBDeviceInfo döner."""
        # Cihaz 1: Mass Storage (izinli)
        self._create_device(
            "1-1",
            vendor_id="0781",
            product_id="5567",
            device_class="00",
            interfaces={"1-1:1.0": "08"},
        )
        # Cihaz 2: HID (engelli)
        self._create_device(
            "1-2",
            vendor_id="dead",
            product_id="beef",
            device_class="03",
            interfaces={"1-2:1.0": "03"},
        )

        guard = USBGuard()

        # scan_all_devices /sys/bus/usb/devices path'ini kullanır
        # Bunu test sysfs'imize yönlendirmemiz gerekiyor
        with patch("app.security.usb_guard.Path") as mock_path_cls:
            # Path("/sys/bus/usb/devices") çağrısını yakala
            real_path = Path

            def path_side_effect(arg=""):
                if str(arg) == "/sys/bus/usb/devices":
                    return real_path(self.sysfs_root)
                return real_path(arg)

            mock_path_cls.side_effect = path_side_effect

            devices = guard.scan_all_devices()

        self.assertEqual(len(devices), 2)
        # En az biri izinli, en az biri engelli
        allowed = [d for d in devices if d.is_allowed]
        blocked = [d for d in devices if not d.is_allowed]
        self.assertTrue(len(allowed) >= 1)
        self.assertTrue(len(blocked) >= 1)

    def test_scan_all_no_sysfs(self) -> None:
        """sysfs dizini yok → boş liste."""
        guard = USBGuard()

        nonexistent = Path(self.tmpdir) / "nonexistent"

        with patch("app.security.usb_guard.Path") as mock_path_cls:
            real_path = Path

            def path_side_effect(arg=""):
                if str(arg) == "/sys/bus/usb/devices":
                    return real_path(nonexistent)
                return real_path(arg)

            mock_path_cls.side_effect = path_side_effect

            devices = guard.scan_all_devices()

        self.assertEqual(len(devices), 0)


if __name__ == "__main__":
    unittest.main()

# THE AIRLOCK v5.1.1 "FORTRESS-HARDENED"
# Tam Mimari Dokümantasyon — Claude Code İçin İmplementasyon Rehberi

---

## 1. VİZYON VE POZİSYONLAMA

### Ne Yapıyoruz?
Raspberry Pi 5 (8GB) üzerinde çalışan, air-gapped (internetsiz), açık kaynaklı bir **USB Sanitization İstasyonu**.
Güvenilmeyen bir USB'den gelen dosyaları tarar, temizler, dönüştürür ve güvenli bir USB'ye aktarır.

### Rakiplerimiz ve Farkımız

| Rakip | Fiyat | Eksikleri | Bizim Avantajımız |
|-------|-------|-----------|-------------------|
| OPSWAT MetaDefender Kiosk | $15,000-50,000 | Kapalı kaynak, pahalı | Açık kaynak, $50-80 maliyet |
| CIRCLean (CIRCL) | Ücretsiz | BadUSB koruması yok, CDR yok, OCR yok | 7+ katmanlı güvenlik |
| Sasa GateScanner | $10,000+ | Sadece kurumsal | Bireysel kullanıcıya da uygun |
| ODIX FileWall | Kurumsal lisans | Cloud bağımlı | Tamamen offline |

### Hedef Kullanıcılar
- Devlet kurumları, askeri birimler
- Gazeteciler, aktivistler
- Endüstriyel kontrol sistemleri (SCADA/ICS)
- IT departmanları, SOC ekipleri
- Matbaa, copy center, fotoğrafçı
- Güvenlik araştırmacıları

---

## 2. SİSTEM MİMARİSİ

### 2.1 Genel Akış

```
USB TAKILDI
    │
    ▼
[KATMAN 1] USB CİHAZ SINIFI KONTROLÜ (USBGuard)
    │ HID/CDC/RNDIS → ENGELLE + ALARM
    │ Mass Storage → İZİN VER
    ▼
[KATMAN 2] USB FINGERPRINT (VID/PID loglama)
    │ Bilinen kötü cihazlar → ENGELLE
    │ Bilinmeyen → DEVAM + LOG
    ▼
[KATMAN 3] GÜVENLİ MOUNT (ro, noexec, nosuid, nodev)
    │
    ▼
[KATMAN 4] ÖN KONTROLLER
    │ ├── Symlink tespiti → ENGELLE
    │ ├── Path traversal tespiti → ENGELLE
    │ ├── Dosya sistemi anomali kontrolü → LOG
    │ └── Toplam boyut kontrolü → SINIRLA
    ▼
[KATMAN 5] DOSYA TARAMA
    │ ├── ClamAV (8M+ imza)
    │ ├── YARA (özel kurallar)
    │ ├── Entropy analizi (>7.5 = şüpheli)
    │ ├── Magic byte doğrulama (uzantı-içerik eşleşmesi)
    │ └── Hash kontrolü (bilinen kötü hash'ler)
    ▼
[KATMAN 6] İÇERİK DEZENFEKSIYON (CDR)
    │ ├── PDF → Rasterize → OCR → Searchable PDF
    │ ├── Office → PDF → Rasterize → OCR → Searchable PDF
    │ ├── Resim → Metadata temizle + re-encode
    │ ├── Arşiv → Güvenli açma (zip bomb korumalı) → İçeriği tara
    │ └── Diğer → Politikaya göre (kopyala / engelle)
    ▼
[KATMAN 7] ÇIKTI DOĞRULAMA
    │ ├── Temiz dosyaların hash'ini hesapla
    │ ├── Rapor oluştur (JSON + imzalı)
    │ └── Manifest dosyası yaz
    ▼
TEMİZ USB'YE YAZ + RAPOR
```

### 2.2 Dizin Yapısı

```
/opt/airlock/
├── app/                          # Ana uygulama
│   ├── __init__.py
│   ├── main.py                   # Entry point
│   ├── daemon.py                 # Ana daemon (AirlockDaemon)
│   ├── config.py                 # Yapılandırma ve sabitler
│   │
│   ├── security/                 # Güvenlik katmanları
│   │   ├── __init__.py
│   │   ├── usb_guard.py          # USB cihaz sınıfı kontrolü
│   │   ├── usb_fingerprint.py    # VID/PID loglama ve filtreleme
│   │   ├── mount_manager.py      # Güvenli mount/unmount
│   │   ├── file_validator.py     # Symlink, path traversal, boyut kontrolleri
│   │   ├── scanner.py            # ClamAV + YARA + entropy + magic byte
│   │   ├── cdr_engine.py         # Content Disarm & Reconstruction
│   │   ├── archive_handler.py    # Arşiv açma (zip bomb korumalı)
│   │   └── report_generator.py   # İmzalı JSON rapor + manifest
│   │
│   ├── hardware/                 # Donanım kontrolleri
│   │   ├── __init__.py
│   │   ├── oled_display.py       # SSD1306 OLED ekran
│   │   ├── led_controller.py     # RGB LED kontrolü
│   │   ├── audio_feedback.py     # Ses efektleri
│   │   └── button_handler.py     # Fiziksel buton (GPIO)
│   │
│   ├── updater/                  # Güncelleme sistemi
│   │   ├── __init__.py
│   │   └── offline_updater.py    # UPDATE USB ile güncelleme (imza doğrulamalı)
│   │
│   └── utils/                    # Yardımcı araçlar
│       ├── __init__.py
│       ├── logger.py             # Yapılandırılmış loglama
│       └── crypto.py             # Hash, imza, doğrulama
│
├── config/                       # Yapılandırma dosyaları
│   ├── airlock.yaml              # Ana yapılandırma
│   ├── policies/                 # Güvenlik politikaları
│   │   ├── paranoid.yaml         # En katı mod
│   │   ├── balanced.yaml         # Dengeli mod (varsayılan)
│   │   └── convenient.yaml       # Kullanışlı mod
│   └── known_bad_hashes.txt      # Bilinen kötü dosya hash'leri
│
├── data/                         # Veri dizinleri
│   ├── yara_rules/               # YARA kuralları
│   │   ├── core/                 # Temel kurallar
│   │   └── custom/               # Kullanıcı kuralları
│   ├── clamav/                   # ClamAV veritabanı (symlink → /var/lib/clamav)
│   ├── quarantine/               # Karantina dizini
│   ├── logs/                     # Log dizini
│   └── sounds/                   # Ses dosyaları
│
├── keys/                         # Kriptografik anahtarlar
│   ├── report_signing.key        # Rapor imzalama anahtarı (Ed25519)
│   └── update_verify.pub         # Update doğrulama public key
│
├── systemd/                      # Servis dosyaları
│   └── airlock.service           # systemd unit
│
├── scripts/                      # Yardımcı scriptler
│   ├── setup.sh                  # Kurulum scripti
│   ├── generate_keys.sh          # Anahtar üretimi
│   ├── generate_sounds.py        # Ses dosyası üretimi
│   ├── create_update_usb.sh      # UPDATE USB hazırlama aracı
│   └── self_test.py              # Otomatik test suite
│
├── tests/                        # Test dosyaları
│   ├── test_scanner.py
│   ├── test_cdr.py
│   ├── test_usb_guard.py
│   ├── test_archive.py
│   ├── test_report.py
│   └── samples/                  # Test dosyaları (EICAR, test PDF, vb.)
│       ├── eicar.com.txt         # EICAR test virüsü
│       ├── test_macro.docm       # Test macro dosyası
│       ├── test_js.pdf           # JavaScript içeren test PDF
│       └── zipbomb_test.zip      # Zip bomb test
│
├── tmp/                          # RAM disk (tmpfs 512MB)
│
├── venv/                         # Python sanal ortamı
│
└── VERSION                       # Sürüm dosyası: "4.0.0"
```

---

## 3. MODÜL DETAYLARI

### 3.1 config.py — Yapılandırma ve Sabitler

```python
"""
Tüm yapılandırma merkezi. YAML dosyasından okunur.
Güvenlik politikaları: PARANOID / BALANCED / CONVENIENT
"""

# ─── GÜVENLİK POLİTİKALARI ───

POLICIES = {
    "paranoid": {
        "cdr_on_failure": "quarantine",      # CDR başarısızsa: karantina (ASLA kopyalama)
        "unknown_extension": "block",         # Bilinmeyen uzantı: engelle
        "archive_handling": "block",          # Arşivler: engelle
        "max_file_size_mb": 100,              # Maksimum dosya boyutu
        "entropy_threshold": 7.0,             # Entropy eşiği (düşük = daha hassas)
        "ocr_enabled": False,                 # OCR kapalı (hız için)
        "allow_images": True,
        "allow_text": True,
        "allow_pdf": True,                    # CDR ile
        "allow_office": False,                # Office tamamen engelle
    },
    "balanced": {
        "cdr_on_failure": "quarantine",       # CDR başarısızsa: karantina
        "unknown_extension": "copy_with_warning",
        "archive_handling": "scan_and_extract",
        "max_file_size_mb": 500,
        "entropy_threshold": 7.5,
        "ocr_enabled": True,
        "allow_images": True,
        "allow_text": True,
        "allow_pdf": True,
        "allow_office": True,                 # CDR ile
    },
    "convenient": {
        "cdr_on_failure": "copy_unsanitized_folder",  # Ayrı "UNSANITIZED" klasörüne koy
        "unknown_extension": "copy_with_warning",
        "archive_handling": "scan_and_extract",
        "max_file_size_mb": 2048,
        "entropy_threshold": 7.9,
        "ocr_enabled": True,
        "allow_images": True,
        "allow_text": True,
        "allow_pdf": True,
        "allow_office": True,
    }
}

# ─── TEHLİKELİ UZANTILAR ───

DANGEROUS_EXTENSIONS = {
    # Çalıştırılabilir
    '.exe', '.dll', '.sys', '.drv', '.ocx', '.com', '.scr', '.pif', '.cpl',
    # Script
    '.bat', '.cmd', '.ps1', '.psm1', '.psd1', '.vbs', '.vbe',
    '.js', '.jse', '.ws', '.wsf', '.wsc', '.wsh', '.msc',
    # Office Macro
    '.docm', '.dotm', '.xlsm', '.xltm', '.xlam',
    '.pptm', '.potm', '.ppam', '.ppsm', '.sldm',
    # Diğer tehlikeli
    '.hta', '.crt', '.ins', '.isp', '.reg', '.inf',
    '.scf', '.lnk', '.url', '.jar', '.war',
    '.msi', '.msp', '.application', '.gadget',
    '.com', '.pif', '.cpl',
    # Disk image (autorun riski)
    '.iso', '.img', '.vhd', '.vhdx',
}

# ─── CDR DESTEKLİ TÜRLER ───

CDR_SUPPORTED = {
    'application/pdf': 'rasterize',
    'application/msword': 'office_to_pdf_rasterize',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document': 'office_to_pdf_rasterize',
    'application/vnd.ms-excel': 'office_to_pdf_rasterize',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': 'office_to_pdf_rasterize',
    'application/vnd.ms-powerpoint': 'office_to_pdf_rasterize',
    'application/vnd.openxmlformats-officedocument.presentationml.presentation': 'office_to_pdf_rasterize',
}

# ─── ARŞİV SINIRLAMALARI ───

ARCHIVE_LIMITS = {
    "max_depth": 3,                    # Maksimum iç içe derinlik
    "max_total_size_mb": 1024,         # Toplam açılmış boyut limiti
    "max_file_count": 1000,            # Maksimum dosya sayısı
    "max_single_file_mb": 500,         # Tek dosya boyut limiti
    "compression_ratio_limit": 100,    # Sıkıştırma oranı limiti (zip bomb)
    "timeout_seconds": 120,            # Açma timeout
    "encrypted_policy": "block",       # Şifreli arşiv: engelle
}

# ─── USB SINIF FİLTRELERİ ───

ALLOWED_USB_CLASSES = {
    0x08,  # Mass Storage
}

BLOCKED_USB_CLASSES = {
    0x03,  # HID (klavye, fare) — Rubber Ducky koruması
    0x02,  # CDC (seri port, modem)
    0x0A,  # CDC-Data
    0x0E,  # Video
    0x0B,  # Smart Card
    0xE0,  # Wireless Controller
    0xEF,  # Miscellaneous (composite device trick)
    0xFF,  # Vendor Specific (birçok BadUSB bunu kullanır)
}

# ─── DONANIM PİN ATAMALARI ───

GPIO_PINS = {
    "button": 21,
    "led_red": 17,
    "led_green": 27,
    "led_blue": 22,
    "buzzer": 24,
}

I2C_CONFIG = {
    "oled_address": 0x3C,
    "oled_width": 128,
    "oled_height": 64,
}

# ─── DİZİNLER ───

DIRECTORIES = {
    "base": "/opt/airlock",
    "tmp": "/opt/airlock/tmp",          # RAM disk (tmpfs)
    "logs": "/opt/airlock/data/logs",
    "quarantine": "/opt/airlock/data/quarantine",
    "yara_rules": "/opt/airlock/data/yara_rules",
    "sounds": "/opt/airlock/data/sounds",
    "keys": "/opt/airlock/keys",
}
```

### 3.2 security/usb_guard.py — USB Cihaz Sınıfı Kontrolü

```python
"""
KATMAN 1: USB Cihaz Sınıfı Kontrolü

BadUSB/Rubber Ducky korumasının TEMELİ.
USB takıldığında cihazın kendini nasıl tanıttığını kontrol eder.
Sadece Mass Storage (class 0x08) sınıfına izin verir.
HID (klavye/fare), CDC, Wireless vb. → ANINDA ENGELLE

İmplementasyon Seçenekleri (birini seç):

SEÇENEK A — USBGuard (önerilen, en güvenli):
  - usbguard paketi kurulur
  - /etc/usbguard/rules.conf dosyasına kurallar yazılır
  - Kernel seviyesinde engelleme

SEÇENEK B — udev kuralları (daha basit, yeterli güvenlik):
  - /etc/udev/rules.d/99-airlock.rules dosyası oluşturulur
  - Belirli sınıflar engellenir

SEÇENEK C — sysfs kontrolü (yazılım seviyesi):
  - /sys/bus/usb/devices/ dizininden cihaz bilgileri okunur
  - bInterfaceClass değeri kontrol edilir
  - İzin verilmeyenler deauthorize edilir

ÖNERİ: Üçünü de katmanlı uygula:
1. USBGuard kernel seviyesinde filtreler
2. udev kuralları ek güvenlik sağlar  
3. Python kodu runtime'da doğrular

DETAYLI İMPLEMENTASYON:
"""

import subprocess
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import IntEnum
import logging

logger = logging.getLogger("USB_GUARD")


class USBClass(IntEnum):
    """USB cihaz sınıfları"""
    AUDIO = 0x01
    CDC = 0x02          # Communications — modem/seri port gibi davranabilir
    HID = 0x03          # Human Interface Device — RUBBER DUCKY BUNU KULLANIR
    PHYSICAL = 0x05
    IMAGE = 0x06
    PRINTER = 0x07
    MASS_STORAGE = 0x08  # ← Sadece buna izin veriyoruz
    HUB = 0x09
    CDC_DATA = 0x0A
    SMART_CARD = 0x0B
    VIDEO = 0x0E
    WIRELESS = 0xE0
    MISC = 0xEF          # Composite device — trick için kullanılabilir
    VENDOR_SPEC = 0xFF   # Vendor specific — BadUSB riski yüksek


@dataclass
class USBDeviceInfo:
    """USB cihaz bilgileri"""
    bus: str
    device: str
    vendor_id: str        # VID
    product_id: str       # PID
    manufacturer: str
    product: str
    serial: str
    device_class: int
    interface_classes: List[int]
    is_allowed: bool
    block_reason: Optional[str] = None


class USBGuard:
    """
    USB cihaz sınıfı kontrolcüsü.
    
    Kullanım:
        guard = USBGuard()
        result = guard.check_device("/sys/bus/usb/devices/1-1")
        if not result.is_allowed:
            guard.deauthorize_device(result)
            # LED kırmızı, buzzer alarm
    """
    
    ALLOWED_CLASSES = {USBClass.MASS_STORAGE}
    
    # Bilinen BadUSB cihazları (VID:PID)
    KNOWN_BAD_DEVICES = {
        "16c0:0486",  # Teensy (sık BadUSB platformu)
        "1781:0c9f",  # Teensy variant
        "2341:8036",  # Arduino Leonardo (HID mode)
        "2341:8037",  # Arduino Micro (HID mode)
        "1b4f:9205",  # SparkFun Pro Micro (HID)
        "1b4f:9206",  # SparkFun Pro Micro (HID)
        "05ac:0256",  # Fake Apple keyboard (yaygın BadUSB trick)
        "1fc9:0003",  # NXP LPC (USB Rubber Ducky platform)
        "2e8a:0005",  # Raspberry Pi Pico (BadUSB script platformu)
        # Daha fazla eklenebilir...
    }
    
    def __init__(self):
        self.logger = logging.getLogger("USB_GUARD")
    
    def check_device(self, sysfs_path: str) -> USBDeviceInfo:
        """
        USB cihazını kontrol et.
        
        /sys/bus/usb/devices/<device>/ altındaki dosyalardan:
        - idVendor, idProduct
        - bDeviceClass
        - <interface>/bInterfaceClass (her interface için)
        - manufacturer, product, serial
        
        Returns:
            USBDeviceInfo: Cihaz bilgileri ve izin durumu
        """
        path = Path(sysfs_path)
        
        # Temel bilgileri oku
        vid = self._read_sysfs(path / "idVendor", "0000")
        pid = self._read_sysfs(path / "idProduct", "0000")
        device_class = int(self._read_sysfs(path / "bDeviceClass", "0"), 16)
        manufacturer = self._read_sysfs(path / "manufacturer", "Unknown")
        product = self._read_sysfs(path / "product", "Unknown")
        serial = self._read_sysfs(path / "serial", "N/A")
        
        # Interface sınıflarını oku (önemli: composite device'lar birden fazla interface'e sahip)
        interface_classes = []
        for iface_dir in sorted(path.glob("*:*")):
            iface_class_file = iface_dir / "bInterfaceClass"
            if iface_class_file.exists():
                try:
                    iface_class = int(iface_class_file.read_text().strip(), 16)
                    interface_classes.append(iface_class)
                except (ValueError, PermissionError):
                    pass
        
        # Karar ver
        is_allowed = True
        block_reason = None
        
        # Kontrol 1: Bilinen kötü cihaz mı?
        device_id = f"{vid}:{pid}"
        if device_id in self.KNOWN_BAD_DEVICES:
            is_allowed = False
            block_reason = f"KNOWN_BAD_DEVICE: {device_id}"
        
        # Kontrol 2: Device class tehlikeli mi?
        if device_class in {USBClass.HID, USBClass.CDC, USBClass.WIRELESS, USBClass.VENDOR_SPEC}:
            is_allowed = False
            block_reason = f"BLOCKED_DEVICE_CLASS: 0x{device_class:02x}"
        
        # Kontrol 3: Interface class'larında tehlikeli var mı?
        # ÖNEMLİ: Composite device hem Mass Storage hem HID olarak gelebilir
        for iface_class in interface_classes:
            if iface_class not in self.ALLOWED_CLASSES and iface_class != 0x09:  # Hub OK
                is_allowed = False
                block_reason = f"BLOCKED_INTERFACE_CLASS: 0x{iface_class:02x} ({self._class_name(iface_class)})"
                break
        
        # Kontrol 4: Hiç interface yok → şüpheli
        if not interface_classes:
            is_allowed = False
            block_reason = "NO_INTERFACES_DETECTED"
        
        # Kontrol 5: Sadece Mass Storage interface'i olmalı
        mass_storage_only = all(c == USBClass.MASS_STORAGE for c in interface_classes)
        if interface_classes and not mass_storage_only:
            is_allowed = False
            block_reason = f"MIXED_INTERFACES: {[f'0x{c:02x}' for c in interface_classes]}"
        
        info = USBDeviceInfo(
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
            block_reason=block_reason
        )
        
        # Logla
        if is_allowed:
            self.logger.info(f"USB İZİN: {vid}:{pid} {manufacturer} {product}")
        else:
            self.logger.warning(f"USB ENGEL: {vid}:{pid} {manufacturer} {product} — {block_reason}")
        
        return info
    
    def deauthorize_device(self, device_info: USBDeviceInfo) -> bool:
        """
        Cihazı kernel seviyesinde deauthorize et.
        /sys/bus/usb/devices/<device>/authorized → 0
        """
        auth_file = Path(f"/sys/bus/usb/devices/{device_info.device}/authorized")
        try:
            auth_file.write_text("0")
            self.logger.warning(f"DEAUTHORIZED: {device_info.vendor_id}:{device_info.product_id}")
            return True
        except (PermissionError, FileNotFoundError) as e:
            self.logger.error(f"Deauthorize başarısız: {e}")
            # Fallback: subprocess ile
            try:
                subprocess.run(
                    ['sudo', 'sh', '-c', f'echo 0 > {auth_file}'],
                    capture_output=True, timeout=5
                )
                return True
            except Exception:
                return False
    
    def _read_sysfs(self, path: Path, default: str = "") -> str:
        try:
            return path.read_text().strip()
        except (FileNotFoundError, PermissionError):
            return default
    
    def _class_name(self, class_code: int) -> str:
        names = {
            0x01: "Audio", 0x02: "CDC", 0x03: "HID",
            0x05: "Physical", 0x06: "Image", 0x07: "Printer",
            0x08: "MassStorage", 0x09: "Hub", 0x0A: "CDC-Data",
            0x0B: "SmartCard", 0x0E: "Video", 0xE0: "Wireless",
            0xEF: "Miscellaneous", 0xFF: "VendorSpecific"
        }
        return names.get(class_code, f"Unknown(0x{class_code:02x})")
```

### 3.3 security/mount_manager.py — Güvenli Mount Yönetimi

```python
"""
KATMAN 3: Güvenli Mount Yönetimi

USB'leri ASLA otomount'a bırakmayız.
Kaynak USB: SADECE read-only mount
Hedef USB: noexec,nosuid,nodev ile mount
Her durumda nodev, nosuid, noexec

Ayrıca:
- Mount öncesi filesystem type kontrolü (sadece FAT32, exFAT, NTFS, ext4)
- Mount sonrası gerçek mount durumu doğrulaması
- Güvenli unmount (sync + lazy umount fallback)
"""

class MountManager:
    
    ALLOWED_FILESYSTEMS = {'vfat', 'exfat', 'ntfs', 'ext4', 'ext3'}
    
    SOURCE_MOUNT_OPTIONS = "ro,noexec,nosuid,nodev,noatime"
    TARGET_MOUNT_OPTIONS = "rw,noexec,nosuid,nodev,noatime"
    
    def detect_filesystem(self, device: str) -> str:
        """blkid ile filesystem türünü tespit et"""
        # subprocess.run(['blkid', '-o', 'value', '-s', 'TYPE', device])
        pass
    
    def mount_source(self, device: str, mountpoint: str) -> bool:
        """
        Kaynak USB'yi READ-ONLY mount et.
        mount -t <fs> -o ro,noexec,nosuid,nodev <device> <mountpoint>
        
        Mount sonrası doğrulama:
        - /proc/mounts'ta gerçekten ro mu?
        - mountpoint erişilebilir mi?
        """
        pass
    
    def mount_target(self, device: str, mountpoint: str) -> bool:
        """
        Hedef USB'yi güvenli yazılabilir mount et.
        mount -t <fs> -o rw,noexec,nosuid,nodev <device> <mountpoint>
        """
        pass
    
    def safe_unmount(self, mountpoint: str) -> bool:
        """
        Güvenli unmount:
        1. sync
        2. umount
        3. Başarısız olursa: umount -l (lazy)
        4. Mount noktasının gerçekten unmount olduğunu doğrula
        """
        pass
    
    def verify_mount(self, mountpoint: str, expected_options: str) -> bool:
        """
        /proc/mounts veya findmnt ile gerçek mount durumunu doğrula.
        Beklenen seçeneklerle karşılaştır.
        """
        pass
```

### 3.4 security/file_validator.py — Dosya Ön Kontrolleri

```python
"""
KATMAN 4: Dosya Ön Kontrolleri

Tarama öncesi güvenlik kontrolleri:
1. Symlink tespiti → ENGELLE (istasyon dosya sistemi sızıntısı riski)
2. Path traversal (../../etc/passwd gibi isimler) → ENGELLE
3. Özel karakter / uzun dosya adı kontrolü
4. Toplam dosya sayısı ve boyut limiti
5. Hardlink kontrolü (inode manipulation)
6. Device file kontrolü (/dev/ gibi)
"""

class FileValidator:
    
    MAX_FILENAME_LENGTH = 255
    MAX_PATH_DEPTH = 20
    MAX_TOTAL_FILES = 10000
    MAX_TOTAL_SIZE_GB = 32  # USB kapasitesine göre
    
    # Tehlikeli dosya adı pattern'leri
    DANGEROUS_PATTERNS = [
        r'\.\.',           # Path traversal
        r'[\x00-\x1f]',   # Control characters
        r'^\.hidden',      # Gizli dosyalar (opsiyonel uyarı)
    ]
    
    def validate_file(self, filepath: Path, source_root: Path) -> ValidationResult:
        """
        Tek dosyayı doğrula.
        
        Kontroller:
        1. Symlink mi? → BLOCK
        2. Gerçek yolu source_root dışına çıkıyor mu? → BLOCK (resolve + relative_to)
        3. Dosya adı tehlikeli karakter içeriyor mu? → BLOCK
        4. Dosya boyutu limiti aşıyor mu? → BLOCK
        5. Hardlink mi? (nlink > 1 ve regular file) → WARN
        6. Device file mi? → BLOCK
        7. FIFO/socket mi? → BLOCK
        
        Returns:
            ValidationResult(is_safe, block_reason, warnings)
        """
        pass
    
    def validate_batch(self, source_root: Path) -> BatchValidationResult:
        """
        Tüm dosya ağacını doğrula.
        Toplam dosya sayısı, toplam boyut, derinlik kontrolleri.
        """
        pass
```

### 3.5 security/scanner.py — Çok Motorlu Tarama

```python
"""
KATMAN 5: Çok Motorlu Dosya Tarama

4 tarama motoru paralel/sıralı çalışır:

1. ClamAV — 8M+ malware imzası (pyclamd ile daemon'a bağlan)
2. YARA — Pattern matching (özel kurallar dahil)
3. Entropy Analizi — Yüksek entropy = şüpheli (packed/encrypted payload)
4. Magic Byte Doğrulama — Uzantı ile gerçek dosya türü eşleşiyor mu?

Ek: Bilinen kötü hash kontrolü (SHA-256)
"""

import math
from collections import Counter

class FileScanner:
    
    # Entropy eşikleri
    ENTROPY_SUSPICIOUS = 7.5   # Bu üstü = şüpheli (normal metin ~4-5, sıkıştırılmış ~8)
    ENTROPY_VERY_HIGH = 7.9    # Bu üstü = büyük ihtimalle encrypted/packed
    
    def scan_file(self, filepath: Path) -> ScanResult:
        """
        Dosyayı tüm motorlarla tara.
        
        Returns:
            ScanResult:
                is_threat: bool
                threat_level: "clean" | "suspicious" | "malicious"
                detections: List[Detection]
                    - engine: "clamav" | "yara" | "entropy" | "magic" | "hash"
                    - rule_name: str
                    - details: str
                mime_type: str
                sha256: str
                entropy: float
                file_size: int
        """
        pass
    
    def _scan_clamav(self, filepath: Path) -> Optional[Detection]:
        """
        ClamAV daemon'a bağlan ve dosyayı tara.
        
        Bağlantı: pyclamd.ClamdUnixSocket() veya ClamdNetworkSocket()
        Metod: clamd.scan(str(filepath))
        
        ÖNEMLİ: ClamAV daemon'ın çalışıyor olması gerekir.
        Daemon yoksa: subprocess ile clamscan fallback.
        """
        pass
    
    def _scan_yara(self, filepath: Path) -> List[Detection]:
        """
        YARA kurallarıyla tara.
        
        Kurallar:
        - /opt/airlock/data/yara_rules/core/      → temel imzalar
        - /opt/airlock/data/yara_rules/custom/     → kullanıcı kuralları
        
        Her .yar dosyasını derle ve uygula.
        Timeout: dosya başına 30 saniye.
        """
        pass
    
    def _calculate_entropy(self, filepath: Path) -> float:
        """
        Shannon entropy hesapla.
        
        H = -Σ p(x) * log2(p(x))
        
        Normal metin dosyası: ~4.0-5.0
        Sıkıştırılmış dosya: ~7.5-8.0
        Şifrelenmiş payload: ~7.9-8.0
        Rastgele veri: ~8.0
        
        İlk 1MB üzerinden hesapla (performans).
        """
        data = filepath.read_bytes()[:1024*1024]  # İlk 1MB
        if not data:
            return 0.0
        
        counter = Counter(data)
        length = len(data)
        entropy = -sum(
            (count/length) * math.log2(count/length)
            for count in counter.values()
        )
        return round(entropy, 4)
    
    def _verify_magic_bytes(self, filepath: Path) -> Optional[Detection]:
        """
        Dosyanın magic byte'larını kontrol et.
        Uzantı .jpg ama içerik PE executable → TEHLİKELİ
        
        python-magic kütüphanesi ile MIME type tespit et,
        uzantıdan beklenen MIME ile karşılaştır.
        
        Eşleşmezse: Detection döndür.
        """
        pass
    
    def _check_known_hashes(self, sha256: str) -> Optional[Detection]:
        """
        SHA-256 hash'ini bilinen kötü hash listesiyle karşılaştır.
        /opt/airlock/config/known_bad_hashes.txt dosyasından oku.
        Set kullan (O(1) lookup).
        """
        pass
```

### 3.6 security/cdr_engine.py — İçerik Dezenfeksiyon Motoru

```python
"""
KATMAN 6: Content Disarm & Reconstruction

EN KRİTİK MODÜL. Dosyaları "silahsızlandırır".

ALTIN KURAL: CDR başarısız olursa → ASLA orijinali kopyalama.
             Karantinaya al + raporda "CDR_FAILED" olarak işaretle.

İşlem akışları:

PDF:
  PDF → ImageMagick/Ghostscript → JPG (sayfa sayfa)
    → (opsiyonel) Tesseract OCR → Searchable PDF
    → img2pdf ile birleştir → TEMİZ PDF

Office (docx, xlsx, pptx):
  Office → LibreOffice headless → PDF
    → PDF CDR akışı (yukarıdaki gibi)
    → TEMİZ PDF (orijinal format kaybolur ama güvenli)

Resim (jpg, png, gif, bmp, tiff):
  Resim → Pillow ile aç → Metadata temizle (EXIF, GPS, XMP)
    → Yeniden encode et (orijinal codec ile)
    → TEMİZ RESİM

Video (mp4, avi, mkv):
  Video → ffmpeg ile re-encode (metadata strip)
    → TEMİZ VİDEO
    (ÖNEMLİ: Bu yavaş olabilir, opsiyonel)

Metin (txt, csv, json, xml, yaml):
  → UTF-8 olarak oku, kontrol karakterlerini temizle
  → Yeniden yaz
"""

class CDREngine:
    
    # RAM disk üzerinde çalış
    WORK_DIR = Path("/opt/airlock/tmp")
    
    # Rasterization ayarları
    PDF_DPI = 200         # 150-300 arası (200 dengeli)
    JPEG_QUALITY = 90     # JPEG kalitesi
    OCR_LANGUAGE = "tur+eng"  # Tesseract dil desteği
    
    def process_pdf(self, source: Path, target: Path, 
                    policy: str = "balanced") -> CDRResult:
        """
        PDF CDR pipeline:
        
        1. Benzersiz job dizini oluştur (RAM disk üzerinde)
        2. Ghostscript ile PDF → JPG (sayfa sayfa)
           - gs -dNOPAUSE -dBATCH -sDEVICE=jpeg -r{DPI}
             -dJPEGQ={QUALITY} -sOutputFile=page_%04d.jpg input.pdf
           - VEYA ImageMagick: convert -density {DPI} -quality {QUALITY}
        3. (Policy izin veriyorsa) Tesseract OCR:
           - tesseract page_001.jpg page_001 -l {LANG} pdf
           - Bu "searchable PDF" üretir (metin seçilebilir)
        4. Sayfaları birleştir:
           - OCR varsa: pdfunite ile
           - OCR yoksa: img2pdf ile (veya convert)
        5. Temizlik (job dizinini sil)
        
        BAŞARISIZLIK DURUMU:
        - subprocess timeout → CDRResult(success=False, reason="TIMEOUT")
        - convert hatası → CDRResult(success=False, reason="CONVERSION_ERROR")
        - 0 sayfa üretildi → CDRResult(success=False, reason="NO_PAGES")
        
        HİÇBİR DURUMDA orijinal dosyayı hedefe kopyalama.
        Başarısız → return CDRResult(success=False) ve daemon karantinaya alsın.
        
        Returns:
            CDRResult:
                success: bool
                reason: str (başarısızlık nedeni, başarılıysa "OK")
                pages_processed: int
                ocr_applied: bool
                output_path: Optional[Path]
                original_sha256: str
                output_sha256: str
        """
        pass
    
    def process_office(self, source: Path, target: Path,
                       policy: str = "balanced") -> CDRResult:
        """
        Office CDR pipeline:
        
        1. LibreOffice headless ile PDF'e çevir:
           soffice --headless --convert-to pdf --outdir {job_dir} {source}
        2. Üretilen PDF'i process_pdf() ile işle
        3. Çıktı dosya adı: {orijinal_stem}_SANITIZED.pdf
        
        NOT: Orijinal format (docx, xlsx, pptx) KAYBOLUR.
        Bu bilinçli bir güvenlik kararı. Kullanıcıya bildirilmeli.
        """
        pass
    
    def process_image(self, source: Path, target: Path) -> CDRResult:
        """
        Resim CDR pipeline:
        
        1. Pillow ile aç (PIL.Image.open)
        2. Metadata temizle:
           - EXIF verisi (GPS, kamera bilgisi, tarih)
           - XMP verisi
           - IPTC verisi
           - ICC profili (opsiyonel koru)
        3. Yeniden encode et:
           - JPEG → JPEG (aynı kalitede)
           - PNG → PNG
           - Diğer → PNG'ye çevir
        4. Kaydet (metadata olmadan)
        
        Bu, resim dosyasına gömülmüş steganografi veya
        exploit payload'larını da temizler.
        """
        pass
    
    def process_text(self, source: Path, target: Path) -> CDRResult:
        """
        Metin CDR pipeline:
        
        1. Binary içerik kontrolü (NUL byte varsa → block)
        2. Encoding tespit et (chardet)
        3. UTF-8 olarak oku
        4. Kontrol karakterlerini temizle (\\x00-\\x08, \\x0e-\\x1f)
           Tab (\\x09), newline (\\x0a), carriage return (\\x0d) KORU
        5. UTF-8 olarak yeniden yaz
        """
        pass
    
    def _cleanup_job(self, job_dir: Path):
        """Job dizinini güvenli sil (RAM disk boşalt)"""
        import shutil
        try:
            shutil.rmtree(job_dir)
        except Exception:
            pass
```

### 3.7 security/archive_handler.py — Güvenli Arşiv Açma

```python
"""
Arşiv dosyalarını güvenli açma ve tarama.

Desteklenen formatlar: ZIP, 7z, RAR, TAR, GZ, BZ2, XZ

ZIP BOMB KORUMALARI:
1. Sıkıştırma oranı kontrolü (compressed/uncompressed > limit → BLOCK)
2. Toplam açılmış boyut limiti
3. Maksimum dosya sayısı limiti
4. Maksimum iç içe derinlik (recursive zip)
5. Timeout (120 saniye)

AKIŞ:
1. Arşiv türünü tespit et
2. Metadata'dan boyut/sayı bilgilerini oku (açmadan)
3. Limitleri kontrol et → geçerse aç
4. Her dosyayı ayrı ayrı tara (scanner.scan_file)
5. CDR uygula (PDF, Office, Resim)
6. Temiz dosyaları düz dizin yapısında hedefe kopyala
"""

class ArchiveHandler:
    
    def is_archive(self, filepath: Path) -> bool:
        """Magic byte ile arşiv mi kontrol et"""
        pass
    
    def check_safety(self, filepath: Path) -> ArchiveSafetyResult:
        """
        Arşivi AÇMADAN güvenlik kontrolü yap.
        
        ZIP: zipfile.ZipFile → infolist() ile dosya listesi ve boyutları
        Sıkıştırma oranı = toplam_uncompressed / toplam_compressed
        Oran > LIMIT → ZIP BOMB şüphesi
        
        Returns:
            ArchiveSafetyResult:
                is_safe: bool
                file_count: int
                total_compressed: int
                total_uncompressed: int
                compression_ratio: float
                max_depth: int
                block_reason: Optional[str]
        """
        pass
    
    def extract_and_process(self, filepath: Path, target_dir: Path,
                            scanner, cdr_engine) -> ArchiveResult:
        """
        Arşivi güvenli aç, her dosyayı tara ve CDR uygula.
        
        1. RAM disk'te geçici dizin oluştur
        2. Arşivi aç (timeout ile)
        3. Her dosya için:
           a. file_validator ile kontrol
           b. scanner ile tara
           c. cdr_engine ile temizle
           d. Temiz dosyayı hedefe kopyala
        4. Geçici dizini temizle
        """
        pass
```

### 3.8 security/report_generator.py — İmzalı Rapor Üretimi

```python
"""
KATMAN 7: İmzalı Rapor ve Manifest Üretimi

Her tarama oturumu sonunda:
1. JSON rapor dosyası üretilir
2. Tüm dosyaların hash manifest'i oluşturulur
3. Rapor Ed25519 anahtarıyla imzalanır
4. Rapor hem log dizinine hem temiz USB'ye kopyalanır

RAPOR FORMATI:
{
    "version": "4.0.0",
    "timestamp": "2025-02-08T14:30:00Z",
    "station_id": "AIRLOCK-xxxx",  # Cihaz unique ID
    "policy": "balanced",
    "summary": {
        "total_files": 65,
        "processed": 60,
        "blocked": 3,
        "quarantined": 2,
        "cdr_applied": 15,
        "cdr_failed": 0,
        "threats_detected": 2,
        "clean_copied": 45,
        "duration_seconds": 42.5
    },
    "usb_source": {
        "vendor_id": "0781",
        "product_id": "5583",
        "manufacturer": "SanDisk",
        "serial": "XXXX",
        "filesystem": "exfat",
        "total_size_mb": 1024
    },
    "files": [
        {
            "original_path": "documents/report.pdf",
            "original_sha256": "abc123...",
            "original_size": 1048576,
            "action": "cdr_rasterize",
            "output_path": "documents/report_SANITIZED.pdf",
            "output_sha256": "def456...",
            "output_size": 2097152,
            "detections": [],
            "ocr_applied": true,
            "entropy": 6.2
        },
        {
            "original_path": "tools/setup.exe",
            "original_sha256": "ghi789...",
            "original_size": 524288,
            "action": "blocked",
            "output_path": null,
            "detections": [
                {"engine": "extension", "rule": "DANGEROUS_EXT", "detail": ".exe"}
            ],
            "entropy": 7.8
        }
    ],
    "signature": "base64_ed25519_signature..."
}
"""

class ReportGenerator:
    
    def generate(self, scan_session: ScanSession) -> Report:
        """Rapor üret"""
        pass
    
    def sign_report(self, report_json: str) -> str:
        """Ed25519 ile imzala"""
        # from nacl.signing import SigningKey
        pass
    
    def verify_report(self, report_json: str, signature: str) -> bool:
        """İmzayı doğrula"""
        pass
    
    def write_manifest(self, target_dir: Path, files: List[FileEntry]):
        """
        Temiz USB'ye SHA-256 manifest dosyası yaz.
        manifest.sha256 formatı:
        abc123...  documents/report_SANITIZED.pdf
        def456...  images/photo.jpg
        """
        pass
```

### 3.9 hardware/oled_display.py — OLED Ekran Kontrolü

```python
"""
SSD1306 OLED Ekran Kontrolü (128x64 pixel, I2C)

Ekran Durumları:
- SPLASH: Açılış logosu + versiyon
- IDLE: "USB bekleniyor..." + animasyon
- USB_DETECTED: "Kaynak/Hedef/Update USB tespit edildi"
- USB_BLOCKED: "⚠ BLOCKED: HID Device" (BadUSB uyarısı)
- SCANNING: Progress bar + dosya adı + tehdit sayısı
- THREAT: Kırmızı uyarı + tehdit detayı
- CDR: "CDR: dosya.pdf → Rasterize..."
- COMPLETE: Özet (dosya sayısı, tehdit, süre)
- UPDATE: Güncelleme ilerlemesi
- SHUTDOWN: Kapanış mesajı
- ERROR: Hata detayı

Kütüphane: luma.oled (luma.core)
Font: PIL.ImageFont (Truetype veya bitmap)

ÖNEMLİ: OLED yoksa (I2C cihaz bulunamadı) sessizce devam et.
Tüm metodlar try/except ile sarılmalı. Donanım hatası daemon'ı çökertmemeli.
"""

from luma.core.interface.serial import i2c
from luma.oled.device import ssd1306
from PIL import Image, ImageDraw, ImageFont

class OLEDDisplay:
    
    def __init__(self, address=0x3C):
        """
        I2C bağlantısı kur. Cihaz bulunamazsa self.available = False
        """
        self.available = False
        try:
            serial = i2c(port=1, address=address)
            self.device = ssd1306(serial, width=128, height=64)
            self.available = True
        except Exception:
            pass
    
    def show_splash(self):
        """Açılış ekranı: 'THE AIRLOCK v4.0 FORTRESS'"""
        pass
    
    def show_idle(self):
        """Bekleme ekranı: 'USB bekleniyor...' + basit animasyon"""
        pass
    
    def show_usb_blocked(self, reason: str):
        """BadUSB engelleme uyarısı: '⚠ USB BLOCKED' + sebep"""
        pass
    
    def show_scanning(self, filename: str, progress: int, 
                      current: int, total: int, threats: int):
        """Tarama ilerleme ekranı"""
        pass
    
    def show_threat(self, filename: str, threat_name: str):
        """Tehdit uyarı ekranı"""
        pass
    
    def show_cdr(self, filename: str, cdr_type: str):
        """CDR işlem ekranı"""
        pass
    
    def show_complete(self, total: int, clean: int, 
                      threats: int, duration: float):
        """Tamamlandı özet ekranı"""
        pass
    
    def show_update(self, component: str, progress: int):
        """Güncelleme ilerleme ekranı"""
        pass
    
    def show_error(self, message: str):
        """Hata ekranı"""
        pass
    
    def clear(self):
        """Ekranı temizle"""
        pass
```

### 3.10 hardware/led_controller.py — RGB LED Kontrolü

```python
"""
RGB LED Kontrolü

Renk Kodları:
- MAVİ (sabit): Bekleme modu
- SARI (yanıp sönen): Tarama/işlem devam
- YEŞİL (sabit): Tamamlandı, temiz
- KIRMIZI (yanıp sönen): Tehdit tespit edildi / USB engellendi
- KIRMIZI (sabit): BadUSB engellendi
- MOR (sabit): Güncelleme modu
- TURUNCU (hızlı yanıp sönen): CDR işlemi
- BEYAZ (pulse): Sistem açılış/kapanış

İki mod desteklenmeli:
1. Ayrı RGB LED'ler (GPIO PWM ile) — 3 pin
2. WS2812B (NeoPixel) — tek pin, rpi_ws281x ile

GPIO kullanılamıyorsa sessizce devam et.
"""

class LEDController:
    
    COLORS = {
        'idle':      (0, 0, 255),     # Mavi
        'scanning':  (255, 200, 0),   # Sarı
        'complete':  (0, 255, 0),     # Yeşil
        'threat':    (255, 0, 0),     # Kırmızı
        'blocked':   (255, 0, 0),     # Kırmızı
        'update':    (128, 0, 255),   # Mor
        'cdr':       (255, 128, 0),   # Turuncu
        'startup':   (255, 255, 255), # Beyaz
    }
    
    def __init__(self, mode='rgb'):
        """mode: 'rgb' (3 ayrı LED) veya 'neopixel' (WS2812B)"""
        pass
    
    def set_color(self, color_name: str):
        """Sabit renk ayarla"""
        pass
    
    def blink(self, color_name: str, count: int = 3, interval: float = 0.3):
        """Yanıp söndür (non-blocking, thread ile)"""
        pass
    
    def pulse(self, color_name: str, duration: float = 2.0):
        """Yavaşça parla ve sön (breathing effect)"""
        pass
    
    def off(self):
        """LED'i kapat"""
        pass
    
    def cleanup(self):
        """GPIO temizliği"""
        pass
```

### 3.11 hardware/audio_feedback.py — Ses Efektleri

```python
"""
Ses Efektleri

Olaylar ve sesleri:
- startup: Kısa melodi (sistem açıldı)
- usb_detect: Tek tık (USB algılandı)
- usb_blocked: Alarm (BadUSB engellendi) — 3 kısa yüksek bip
- file_done: Kısa tık (dosya işlendi)
- threat: Uyarı sesi (tehdit bulundu) — düşük tonlu uzun bip
- complete: Başarı melodisi (işlem tamamlandı)
- error: Düşük ton (hata oluştu)
- button: Tık sesi (buton basıldı)
- shutdown: Kapanış sesi

Ses üretimi: numpy ile sine wave → WAV dosyası
Çalma: pygame.mixer veya aplay

Ses yoksa (hoparlör bağlı değil) sessizce devam et.

generate_sounds.py scripti kurulumda çalıştırılıp
/opt/airlock/data/sounds/ dizinine WAV dosyalarını yazar.
"""

class AudioFeedback:
    
    def __init__(self, sounds_dir="/opt/airlock/data/sounds"):
        """pygame.mixer başlat. Başarısız olursa self.available = False"""
        pass
    
    def play(self, event_name: str, blocking: bool = False):
        """
        Ses çal.
        blocking=True: sesin bitmesini bekle (shutdown gibi durumlar için)
        """
        pass
    
    def cleanup(self):
        """pygame.mixer kapat"""
        pass
```

### 3.12 hardware/button_handler.py — Fiziksel Buton

```python
"""
Fiziksel Buton Kontrolü (GPIO 21)

Davranışlar:
- Kısa basış (< 3 saniye): Güvenli çıkar (işlemi durdur + USB unmount)
- Uzun basış (≥ 3 saniye): Sistemi kapat

Debounce: 50ms
Pull-up resistor: Dahili (GPIO.PUD_UP)

GPIO kullanılamıyorsa sessizce devam et.
"""

class ButtonHandler:
    
    LONG_PRESS_THRESHOLD = 3.0  # saniye
    
    def __init__(self, pin=21, on_short_press=None, on_long_press=None):
        """
        GPIO event detect kur.
        BOTH edge (basıldı + bırakıldı) dinle.
        Basılma süresini ölç.
        """
        pass
    
    def cleanup(self):
        """GPIO temizliği"""
        pass
```

### 3.13 updater/offline_updater.py — Güvenli Offline Güncelleme

```python
"""
Offline Güncelleme Sistemi

UPDATE USB yapısı:
UPDATE/
├── manifest.json          # Güncelleme paketi bilgileri
├── manifest.json.sig      # Ed25519 imzası
├── clamav/
│   ├── main.cvd
│   ├── daily.cvd
│   └── bytecode.cvd
├── yara/
│   └── *.yar
└── known_bad_hashes.txt   # (opsiyonel) Hash listesi güncellemesi

GÜVENLİK:
1. manifest.json.sig doğrulanır (Ed25519 public key ile)
2. İmza geçersiz → UPDATE REDDEDİLDİ
3. ClamAV dosyaları: sigtool ile bütünlük kontrolü
4. YARA dosyaları: yara-python ile syntax kontrolü (derleme testi)
5. Dosya boyut aralıkları kontrolü (çok küçük/büyük → şüpheli)

UPDATE USB DE BİR SALDIRI YÜZEYİDİR.
Bu yüzden USBGuard kontrolünden geçtikten sonra,
read-only mount ve imza doğrulamasıyla güvenli hale getirilir.
"""

class OfflineUpdater:
    
    def verify_update_package(self, usb_path: Path) -> UpdateVerification:
        """
        1. manifest.json oku
        2. manifest.json.sig ile imza doğrula
        3. Listelenen dosyaların hash'lerini kontrol et
        4. Dosya boyut aralıklarını kontrol et
        
        Returns:
            UpdateVerification:
                is_valid: bool
                rejection_reason: Optional[str]
                components: Dict[str, bool]  # {"clamav": True, "yara": True}
        """
        pass
    
    def apply_updates(self, usb_path: Path) -> UpdateResult:
        """
        Doğrulanmış güncellemeleri uygula.
        
        1. ClamAV daemon'ı durdur
        2. CVD dosyalarını kopyala
        3. sigtool --check ile doğrula
        4. ClamAV daemon'ı başlat
        5. YARA kurallarını kopyala
        6. YARA kurallarını derleme testi yap
        7. Başarısız olanları geri al
        """
        pass
```

### 3.14 daemon.py — Ana Daemon

```python
"""
THE AIRLOCK v4.0 FORTRESS — Ana Daemon

Tüm modülleri orkestre eder.
systemd servis olarak çalışır.

ANA DÖNGÜ:
1. Başlat → Bileşenleri initialize et
2. USB bekle
3. USB takıldı:
   a. USBGuard kontrolü → Engellendi? → Alarm + devam et
   b. USB tipi belirle (KIRLI / TEMIZ / UPDATE)
   c. Her iki USB hazır → İşleme başla
   d. UPDATE USB → Güncelleme uygula
4. İşleme:
   a. Kaynak USB'yi ro mount et
   b. Dosyaları doğrula (symlink, path traversal)
   c. Her dosyayı tara (ClamAV + YARA + entropy + magic)
   d. CDR uygula
   e. Temiz USB'ye yaz
   f. Rapor üret
5. Tamamlandı → LED/OLED/ses ile bildir
6. USB çıkarılmasını bekle → başa dön

SANDBOX:
systemd service dosyasında şu kısıtlamalar:
- NoNewPrivileges=true
- ProtectSystem=strict
- PrivateTmp=true
- ProtectHome=true
- RestrictAddressFamilies=AF_UNIX AF_LOCAL
- MemoryDenyWriteExecute=true (CDR subprocess'leri hariç)
"""

class AirlockDaemon:
    
    VERSION = "4.0.0"
    CODENAME = "FORTRESS"
    
    def __init__(self, config_path="/opt/airlock/config/airlock.yaml"):
        """
        Tüm bileşenleri başlat:
        - Config yükle (policy seç)
        - USBGuard
        - MountManager
        - FileValidator
        - FileScanner (ClamAV + YARA + entropy + magic)
        - CDREngine
        - ArchiveHandler
        - ReportGenerator
        - OLEDDisplay
        - LEDController
        - AudioFeedback
        - ButtonHandler
        - OfflineUpdater
        - Logger
        """
        pass
    
    def run(self):
        """Ana döngü"""
        pass
    
    def _on_usb_event(self, action: str, device_path: str):
        """
        udev veya pyudev ile USB olaylarını dinle.
        
        action == "add":
          1. USBGuard.check_device()
          2. İzin verilmediyse → alarm + return
          3. Etiket kontrolü (KIRLI / TEMIZ / UPDATE)
          4. İlgili slot'a ata
          5. Her iki slot doluysa → process_usb()
          
        action == "remove":
          1. Hangi slot boşaldı?
          2. İşlem devam ediyorsa → abort
          3. Slot'u temizle
        """
        pass
    
    def process_usb(self):
        """
        Ana işleme akışı.
        
        1. Kaynak USB'yi MountManager ile ro mount et
        2. FileValidator ile toplu kontrol
        3. Dosya listesini oluştur
        4. Her dosya için:
            a. scanner.scan_file()
            b. Tehdit varsa → karantina + log
            c. Tehlikeli uzantı → engelle + log
            d. CDR gerekiyorsa → cdr_engine.process_*()
            e. CDR başarısız → karantina (ASLA kopyalama)
            f. Arşiv → archive_handler.extract_and_process()
            g. Temiz → hedefe kopyala
            h. OLED/LED güncelle
        5. Rapor üret
        6. Rapor imzala
        7. Raporu hem log'a hem temiz USB'ye yaz
        8. Manifest dosyası yaz
        9. OLED: özet göster
        10. LED: sonuç rengi
        11. Ses: tamamlandı / tehdit melodisi
        """
        pass
    
    def _handle_short_press(self):
        """Güvenli çıkar: işlemi durdur + USB unmount"""
        pass
    
    def _handle_long_press(self):
        """Sistem kapat: temizlik + shutdown"""
        pass
    
    def cleanup(self):
        """Tüm kaynakları temizle"""
        pass
```

---

## 4. SYSTEMD SERVİS DOSYASI

```ini
# /etc/systemd/system/airlock.service

[Unit]
Description=THE AIRLOCK v4.0 FORTRESS — USB Sanitization Station
After=multi-user.target
Wants=clamav-daemon.service

[Service]
Type=simple
User=airlock
Group=airlock
WorkingDirectory=/opt/airlock
ExecStart=/opt/airlock/venv/bin/python3 /opt/airlock/app/main.py
Restart=always
RestartSec=5

# ── Güvenlik Sertleştirme ──
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true

# Ağ erişimi engelle (air-gapped)
RestrictAddressFamilies=AF_UNIX AF_LOCAL
PrivateNetwork=true

# Sadece gerekli dizinlere yazma izni
ReadWritePaths=/opt/airlock/data /opt/airlock/tmp /opt/airlock/data/logs
ReadOnlyPaths=/opt/airlock/app /opt/airlock/config /opt/airlock/keys

# Capabilities
AmbientCapabilities=CAP_SYS_RAWIO
CapabilityBoundingSet=CAP_SYS_RAWIO

# USB ve GPIO erişimi için ek izinler
SupplementaryGroups=gpio i2c audio plugdev disk

[Install]
WantedBy=multi-user.target
```

---

## 5. UDEV KURALLARI

```bash
# /etc/udev/rules.d/99-airlock-usb.rules

# Sadece Mass Storage cihazlarına izin ver
# HID cihazlarını (Rubber Ducky vb.) engelle
ACTION=="add", SUBSYSTEM=="usb", ATTR{bInterfaceClass}=="03", \
    RUN+="/bin/sh -c 'echo 0 > /sys%p/../../authorized'"

# CDC cihazlarını engelle
ACTION=="add", SUBSYSTEM=="usb", ATTR{bInterfaceClass}=="02", \
    RUN+="/bin/sh -c 'echo 0 > /sys%p/../../authorized'"

# Wireless cihazlarını engelle
ACTION=="add", SUBSYSTEM=="usb", ATTR{bInterfaceClass}=="e0", \
    RUN+="/bin/sh -c 'echo 0 > /sys%p/../../authorized'"

# Vendor Specific engelle
ACTION=="add", SUBSYSTEM=="usb", ATTR{bInterfaceClass}=="ff", \
    RUN+="/bin/sh -c 'echo 0 > /sys%p/../../authorized'"

# Mass Storage takıldığında airlock daemon'a bildir
ACTION=="add", SUBSYSTEM=="block", KERNEL=="sd[a-z]*", \
    TAG+="systemd", ENV{SYSTEMD_WANTS}="airlock-usb@%k.service"
```

---

## 6. KURULUM SCRİPTİ (setup.sh) İÇERİĞİ

Kurulum scriptinin yapması gerekenler (sırasıyla):

```
1. Sistem güncelleme (apt update && upgrade)
2. Gerekli paketler:
   - python3-pip python3-venv python3-dev python3-pil python3-smbus
   - i2c-tools git
   - clamav clamav-daemon
   - imagemagick ghostscript
   - tesseract-ocr tesseract-ocr-tur tesseract-ocr-eng
   - img2pdf qpdf poppler-utils
   - libreoffice-writer-nogui libreoffice-calc-nogui libreoffice-impress-nogui
   - ffmpeg (video CDR için)
   - p7zip-full unrar-free
   - alsa-utils
   - python3-gpiozero python3-rpi.gpio
   - usbguard (opsiyonel, SEÇENEK A için)
3. ImageMagick PDF policy düzeltmesi
4. I2C etkinleştirme
5. Log2Ram kurulumu
6. tmpfs (512MB RAM disk) kurulumu
7. Dizin yapısı oluşturma
8. 'airlock' kullanıcısı oluşturma (gpio, i2c, audio, plugdev, disk grupları)
9. Python venv + pip install:
   - luma.oled luma.core Pillow pygame
   - yara-python python-magic pyclamd
   - RPi.GPIO rpi_ws281x gpiozero
   - PyNaCl (Ed25519 imzalama)
   - chardet (encoding tespiti)
   - PyYAML (config dosyası)
   - psutil watchdog pyudev
10. YARA kuralları indirme (signature-base + yara-rules)
11. ClamAV ilk veritabanı indirme + freshclam devre dışı bırakma
12. Ses dosyaları üretme (generate_sounds.py)
13. Kriptografik anahtar üretme (Ed25519 key pair)
14. udev kuralları kurma
15. systemd service kurma + enable
16. Swap optimizasyonu (swappiness=10)
17. EICAR test dosyası oluşturma
18. Self-test çalıştırma (self_test.py)
19. Reboot uyarısı
```

---

## 7. YAPELANDIRMA DOSYASI (airlock.yaml)

```yaml
# /opt/airlock/config/airlock.yaml

version: "4.0.0"
codename: "FORTRESS"

# Aktif güvenlik politikası
# Seçenekler: paranoid, balanced, convenient
active_policy: "balanced"

# Politika değiştirmek için buton kombinasyonu veya
# config dosyasını düzenle + servis restart

# Donanım
hardware:
  oled_enabled: true
  oled_address: 0x3C
  led_mode: "rgb"          # "rgb" veya "neopixel"
  audio_enabled: true
  audio_volume: 80         # 0-100
  button_enabled: true
  button_pin: 21

# USB etiketleri
usb:
  source_labels: ["KIRLI", "DIRTY", "SOURCE", "INPUT"]
  target_labels: ["TEMIZ", "CLEAN", "TARGET", "OUTPUT"]
  update_labels: ["UPDATE", "GÜNCELLEME"]

# Tarama
scanning:
  clamav_enabled: true
  clamav_socket: "/var/run/clamav/clamd.ctl"
  yara_enabled: true
  yara_timeout: 30
  entropy_enabled: true
  magic_byte_check: true
  hash_check: true

# CDR
cdr:
  pdf_dpi: 200
  jpeg_quality: 90
  ocr_enabled: true
  ocr_languages: "tur+eng"
  video_cdr: false          # Video re-encode (yavaş, varsayılan kapalı)
  image_strip_metadata: true
  
# Arşiv
archive:
  max_depth: 3
  max_total_size_mb: 1024
  max_file_count: 1000
  compression_ratio_limit: 100
  timeout_seconds: 120

# Loglama
logging:
  level: "INFO"
  max_log_size_mb: 50
  max_log_files: 10
  log_to_console: true

# Güncelleme
update:
  require_signature: true
  public_key_path: "/opt/airlock/keys/update_verify.pub"
```

---

## 8. TEST SENARYOLARI (self_test.py)

```python
"""
THE AIRLOCK v4.0 Self-Test Suite

Kurulumdan sonra ve periyodik olarak çalıştırılır.
Tüm bileşenleri test eder.

Test Kategorileri:

1. DONANIM TESTLERİ
   - [T01] OLED bağlantısı (I2C detect)
   - [T02] LED çalışması (her renk 0.5 sn)
   - [T03] Buzzer çalışması (test bip)
   - [T04] Buton GPIO okuma

2. YAZILIM TESTLERİ
   - [T05] ClamAV daemon bağlantısı
   - [T06] EICAR test virüsü tespiti (ClamAV)
   - [T07] YARA kuralları yüklenmesi ve derlenmesi
   - [T08] YARA test pattern tespiti
   - [T09] Entropy hesaplama doğruluğu
   - [T10] Magic byte doğrulama (uzantı-içerik eşleşmesi)
   - [T11] ImageMagick PDF desteği (convert komutu)
   - [T12] Ghostscript çalışması
   - [T13] Tesseract OCR çalışması
   - [T14] LibreOffice headless çalışması
   - [T15] img2pdf çalışması

3. GÜVENLİK TESTLERİ
   - [T16] CDR: Test PDF → rasterize → çıktı JS içermiyor mu?
   - [T17] CDR başarısızlık: Bozuk PDF → karantinaya mı gitti?
   - [T18] Symlink tespiti
   - [T19] Path traversal tespiti
   - [T20] Tehlikeli uzantı engelleme
   - [T21] Zip bomb tespiti (yüksek sıkıştırma oranı)
   - [T22] Ed25519 imzalama ve doğrulama

4. ENTEGRASYON TESTLERİ
   - [T23] Tam pipeline: test dosyası → tara → CDR → çıktı → rapor
   - [T24] Rapor JSON formatı doğrulama
   - [T25] Manifest SHA-256 doğrulama

Çıktı formatı:
[PASS] T01 — OLED bağlantısı (0x3C tespit edildi)
[PASS] T02 — LED testi (RGB çalışıyor)
[FAIL] T03 — Buzzer testi (ses çıkışı algılanamadı)
[SKIP] T04 — Buton testi (GPIO kullanılamıyor)
...
═══════════════════════════════════════
SONUÇ: 23/25 PASS | 1 FAIL | 1 SKIP
"""
```

---

## 9. v3.0 → v4.0 KARŞILAŞTIRMA

| Özellik | v3.0 | v4.0 FORTRESS |
|---------|------|---------------|
| BadUSB Koruması | ❌ Yok | ✅ USBGuard + udev + sysfs |
| USB Fingerprint (VID/PID) | ❌ | ✅ Bilinen kötü cihaz listesi |
| Mount Güvenliği | Otomount | ✅ ro,noexec,nosuid,nodev |
| ClamAV | Yarım entegrasyon | ✅ Tam daemon entegrasyonu |
| YARA | ✅ Var | ✅ Var + syntax doğrulama |
| Entropy Analizi | ❌ | ✅ Shannon entropy |
| Magic Byte Doğrulama | ❌ | ✅ Uzantı-içerik eşleşme |
| CDR Başarısızlık | ⚠️ Sessiz kopyalama | ✅ Karantina (ASLA kopyalama) |
| OCR | ❌ | ✅ Tesseract (opsiyonel) |
| Arşiv Açma | ❌ Engelle | ✅ Güvenli açma (zip bomb korumalı) |
| Symlink Koruması | ❌ | ✅ Tespit + engelleme |
| Path Traversal | ❌ | ✅ Tespit + engelleme |
| Rapor İmzalama | ❌ | ✅ Ed25519 |
| Resim Metadata Temizleme | ❌ | ✅ EXIF/GPS/XMP strip |
| Video CDR | ❌ | ✅ ffmpeg re-encode (opsiyonel) |
| Güncelleme Güvenliği | Basit kopyalama | ✅ İmza doğrulama + bütünlük |
| systemd Sandbox | ❌ | ✅ Tam sertleştirme |
| Güvenlik Politikaları | Tek mod | ✅ Paranoid/Balanced/Convenient |
| Self-Test | ❌ | ✅ 25 otomatik test |
| Modüler Mimari | Monolitik | ✅ 14+ bağımsız modül |
| Eksik Modüller | 4 modül eksik | ✅ Tüm modüller dahil |
| Hash Manifest | ❌ | ✅ SHA-256 manifest + imza |

---

## 10. CLAUDE CODE İÇİN TALİMATLAR

### Uygulama Sırası (Önerilen)

```
AŞAMA 1 — TEMEL ALTYAPI (önce çalışsın):
1. config.py
2. utils/logger.py
3. utils/crypto.py
4. hardware/oled_display.py (stub ile başla)
5. hardware/led_controller.py (stub ile başla)
6. hardware/audio_feedback.py (stub ile başla)
7. hardware/button_handler.py

AŞAMA 2 — GÜVENLİK ÇEKİRDEĞİ:
8. security/usb_guard.py
9. security/mount_manager.py
10. security/file_validator.py
11. security/scanner.py (ClamAV + YARA + entropy + magic)

AŞAMA 3 — CDR + ARŞİV:
12. security/cdr_engine.py
13. security/archive_handler.py

AŞAMA 4 — RAPORLAMA + GÜNCELLEME:
14. security/report_generator.py
15. updater/offline_updater.py

AŞAMA 5 — ORKESTRASYON:
16. daemon.py (tüm modülleri birleştir)
17. main.py (entry point)

AŞAMA 6 — KURULUM + TEST:
18. scripts/setup.sh
19. scripts/generate_sounds.py
20. scripts/generate_keys.sh
21. systemd/airlock.service
22. udev kuralları
23. tests/self_test.py

AŞAMA 7 — DONANIM MODÜLLERINI TAMAMLA:
24. OLED ekran gerçek implementasyonu
25. LED gerçek implementasyonu
26. Ses gerçek implementasyonu
```

### Kodlama Standartları

```
- Python 3.11+ (Pi OS Bookworm ile gelen versiyon)
- Type hints zorunlu (typing modülü)
- Dataclass kullan (namedtuple değil)
- Her modül bağımsız çalışabilmeli (donanım yoksa graceful degrade)
- Her public metod docstring içermeli
- Hata yakalama: donanım hataları daemon'ı çökertmemeli
- Logging: her önemli olay loglanmalı
- Güvenlik: subprocess çağrıları shell=False ile
- Timeout: tüm subprocess çağrılarına timeout
- Path: str yerine pathlib.Path kullan
- Config: hardcoded değer yok, config.py/airlock.yaml'dan oku
```

### Kritik Güvenlik Kuralları (ASLA İHLAL ETMEYİN)

```
1. CDR başarısız → ASLA orijinali kopyalama → Karantinaya al
2. Symlink → ASLA takip etme → Engelle + logla
3. USB HID/CDC → ASLA izin verme → Deauthorize + alarm
4. subprocess → ASLA shell=True kullanma
5. Mount → ASLA otomount'a bırakma → Kontrollü mount
6. UPDATE USB → ASLA imza doğrulamadan uygulama
7. Kaynak USB → ASLA read-write mount etme
8. Rapor → ASLA imzasız bırakma
9. Hata durumunda → ASLA sessizce geçme → Logla + kullanıcıyı bildir
10. RAM disk doldu → ASLA SD karta fallback yazma → İşlemi durdur
```

---

## 11. GELECEĞİN TEKNOLOJİLERİ (v5.0 İÇİN FİKİRLER)

Bu versiyonda implementasyon yok ama mimari hazırlığı yapılabilir:

1. **Data Diode**: İki ayrı Pi — dirty side + clean side, arada tek yönlü aktarım
2. **Local ML Anomaly Detection**: TinyML ile dosya yapısı anomali tespiti
3. **E-Ink Dashboard**: Düşük güçlü, her zaman açık durum ekranı
4. **USB-C PD Analiz**: USB Power Delivery protokol analizi (USB Killer tespiti)
5. **Blockchain Audit Trail**: Merkle tree tabanlı değiştirilemez log zinciri
6. **Remote Attestation**: TPM ile cihaz bütünlüğü doğrulama
7. **Multi-Station Sync**: Birden fazla AIRLOCK istasyonunun merkezi yönetimi
8. **AI-Powered YARA Rule Generation**: Yeni tehditlerden otomatik kural üretimi

---

*THE AIRLOCK v4.0 FORTRESS — "Güvenilmeyen hiçbir şey içeri girmez. Silahsızlandırılmadan hiçbir şey dışarı çıkmaz."*

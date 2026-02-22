# THE AIRLOCK v5.1.1 FORTRESS-HARDENED — Proje Talimatları

## Sen Nesin?
Bu proje Raspberry Pi 5 (8GB) üzerinde çalışan air-gapped USB sanitization istasyonudur. Güvenilmeyen USB'deki dosyaları tarar, temizler (CDR), güvenli USB'ye aktarır.

## Mimari Döküman
Tüm detaylar AIRLOCK_V4_FORTRESS_ARCHITECTURE.md dosyasında. HER ZAMAN önce bu dosyayı oku.

## Kodlama Kuralları
- Python 3.11+ (Raspberry Pi OS Bookworm)
- Type hints ZORUNLU
- Dataclass kullan
- Her public metod docstring içermeli
- pathlib.Path kullan (str değil)
- subprocess çağrılarında shell=False ve timeout ZORUNLU
- Hardcoded değer YOK — config.py veya airlock.yaml'dan oku

## Güvenlik Kuralları (ASLA İHLAL ETME)
1. CDR başarısız → ASLA orijinali kopyalama → Karantinaya al
2. Symlink → ASLA takip etme → Engelle + logla
3. USB HID/CDC → ASLA izin verme → Deauthorize + alarm
4. subprocess → ASLA shell=True kullanma
5. Kaynak USB → ASLA read-write mount etme
6. Hata durumunda → ASLA sessizce geçme → Logla
7. Privileged işlem → ASLA ana serviste yapma → helper_client kullan

## Donanım Toleransı
GPIO, OLED, LED, buzzer YOKSA graceful degrade et. Donanım hatası daemon'ı çökertMEmeli.

## Bilinen Sınırlamalar

### BadUSB Koruması
- BadUSB koruması USB HID/CDC sınıf engelleme ile sağlanır (sysfs interface class kontrolü + udev kuralları).
- Bu koruma firmware seviyesinde %100 garanti vermez. Gelişmiş saldırılar (ör: initial enumeration sırasında Mass Storage olarak görünüp sonra HID'e geçen cihazlar) runtime sysfs polling ile tespit edilmeye çalışılır, ancak race condition riski vardır.
- Bilinen kötü VID:PID listesi (Teensy, Rubber Ducky, Arduino Leonardo vb.) ek koruma sağlar, ancak klonlanmış VID:PID'ler yakalananamaz.

### USB Killer / Fiziksel Saldırılar
- USB Killer (elektriksel aşırı gerilim saldırısı) yazılımla tespit edilemez.
- Fiziksel koruma için powered USB hub ile donanım izolasyonu önerilir. Hub, yüksek gerilim dalgasını absorbe ederek ana kartı korur.
- Optik izolasyonlu USB hub en güvenli çözümdür.

### CDR Sandbox (bwrap)
- Bubblewrap (bwrap) sandbox sadece Ghostscript ve LibreOffice çağrılarını izole eder.
- bwrap kurulu değilse sistem graceful degrade yapar — CDR sandbox'sız çalışır.
- Sandbox, kernel exploit'lerine karşı tam koruma sağlamaz; ek güvenlik için grsecurity veya AppArmor profilleri önerilir.

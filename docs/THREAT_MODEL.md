# THE AIRLOCK — Threat Model & Trust Boundaries

## Genel Bakış

THE AIRLOCK, air-gapped ağlara dosya aktarımında savunma sağlayan USB sanitization istasyonudur.
Bu doküman güven sınırlarını, tehdit vektörlerini, koruma katmanlarını ve kabul edilen riskleri tanımlar.

---

## Trust Boundaries (Güven Sınırları)

### 1. Kaynak USB (UNTRUSTED)

**Güven seviyesi**: Sıfır — tamamen güvenilmez

Dosya sistemi, dosya içerikleri, dosya adları ve USB firmware HEPSİ saldırı vektörüdür.

**Koruma katmanları**:
- **Layer 1**: USBGuard — sysfs interface class kontrolü, sadece Mass Storage (0x08) izinli
- **Layer 2**: Mount Policy — read-only mount, noexec/nosuid/nodev
- **Layer 3**: FileValidator — symlink engelleme, path traversal tespiti, tehlikeli uzantı filtresi
- **Layer 4**: Scanner — ClamAV, YARA, Shannon entropy, magic byte doğrulama, bilinen-kötü hash
- **Layer 5**: CDR Engine — PDF rasterizasyon, Office-to-PDF, image metadata stripping, text normalizasyon

### 2. Hedef USB (SEMI-TRUSTED)

**Güven seviyesi**: Kısmi — dosya sistemi manipüle edilmiş olabilir

Hedef USB'nin dosya sistemi, saldırgan tarafından önceden symlink saldırısı için hazırlanmış olabilir.

**Koruma**:
- `safe_copy_no_symlink()` — kopyalama öncesi symlink kontrolü
- `validate_target_path()` — path traversal tespiti
- `safe_mkdir_no_symlink()` — dizin oluşturmada symlink kontrolü

### 3. Update USB (CONDITIONALLY TRUSTED)

**Güven seviyesi**: Koşullu — Ed25519 imza doğrulaması sonrası güvenilir

Güncelleme paketleri sadece imza doğrulaması geçtikten sonra uygulanır.
Private key cihazda DEĞİLDİR (Key Separation mimarisi — Sprint 2).

**Koruma**:
- Ed25519 imza doğrulaması (manifest.json)
- Symlink taraması (güncelleme dizininde)
- Path traversal kontrolü
- Dosya hash doğrulaması

### 4. Host OS (TRUSTED)

**Güven seviyesi**: Güvenilir — kontrollü ortam

Raspberry Pi OS (Bookworm), systemd, Linux kernel.

**Koruma**:
- systemd sandbox (ProtectSystem, ProtectHome, NoNewPrivileges)
- Privilege separation (non-root daemon + root helper)
- SO_PEERCRED ile socket peer doğrulama
- ThreadPoolExecutor ile DoS önleme

### 5. CDR Toolchain (CONDITIONALLY TRUSTED)

**Güven seviyesi**: Koşullu — CVE riski var

Ghostscript, LibreOffice ve diğer CDR araçları CVE'lere maruz kalabilir.

**Koruma**:
- Bubblewrap (bwrap) sandbox — izole execution
- Timeout limitleri
- Kaynak limitleri
- Graceful degrade (bwrap yoksa CDR sandbox'sız çalışır)

---

## Tehdit Matrisi

| ID | Tehdit | Olasılık | Etki | Koruma | Kalan Risk |
|----|--------|----------|------|--------|------------|
| T1 | BadUSB (HID/CDC injection) | Yüksek | Yüksek | USBGuard + sysfs class check + known-bad VID:PID | Enumeration race condition, klonlanmış VID:PID |
| T2 | Malicious file content | Yüksek | Yüksek | 4-engine scanner (ClamAV+YARA+entropy+magic) + CDR | Zero-day malware |
| T3 | CDR toolchain exploit | Orta | Yüksek | bwrap sandbox + timeout + resource limits | Kernel exploit via sandbox escape |
| T4 | Update tampering | Düşük | Kritik | Ed25519 + key separation (update key offline) | update_signing.key compromise |
| T5 | Target USB symlink attack | Orta | Orta | safe_copy_no_symlink + validate_target_path | TOCTOU race condition (minimal) |
| T6 | USB Killer (electrical) | Düşük | Yüksek | YAZILIMLA ÇÖZÜLEMEZ | Powered/optik izolasyonlu USB hub gerekli |
| T7 | Helper socket abuse | Düşük | Orta | Rate limit + SO_PEERCRED + ThreadPoolExecutor(4) | airlock kullanıcısı compromise |
| T8 | SD card corruption | Orta | Düşük-Orta | tmpfs kullanımı, log rotation | Wear-out (fiziksel ömür) |

---

## Tehdit Detayları

### T1: BadUSB / Rubber Ducky

**Saldırı**: USB cihaz Mass Storage olarak görünür, sonra HID'e geçiş yapar (composite device trick).

**Savunma zinciri**:
1. udev kuralları — sadece bInterfaceClass=08 (Mass Storage) izinli
2. sysfs runtime polling — interface class değişikliği tespit
3. Bilinen-kötü VID:PID listesi (Teensy 0x16c0:0x0486, Rubber Ducky 0x03eb:0x2401, vb.)
4. Composite device engelleme — birden fazla interface class algılanırsa red

**Kalan risk**: Initial enumeration sırasında firmware tarafından sağlanan class bilgisi yanıltıcı olabilir. Polling ile yakalanmaya çalışılır ancak race condition riski vardır.

### T2: Kötü Amaçlı Dosya İçeriği

**Saldırı**: PDF exploit, Office macro, polyglot dosya, yüksek entropi (şifrelenmiş payload).

**Savunma zinciri**:
1. ClamAV imza taraması (daemon + CLI fallback)
2. YARA kural taraması (özel kurallar)
3. Shannon entropy analizi (şüpheli yüksek entropy tespiti)
4. Magic byte doğrulama (MIME uyumsuzluğu tespiti)
5. CDR — dosya yeniden oluşturma (metadata/macro temizleme)

**Kalan risk**: Henüz imzası olmayan (zero-day) zararlılar CDR'dan geçebilir. Rasterizasyon bu riski minimize eder.

### T4: Güncelleme Manipülasyonu (Supply-Chain)

**Saldırı**: Sahte güncelleme paketi ile tüm filo ele geçirme.

**Savunma (Key Separation — v5.1.1)**:
- Rapor keypair (cihazda): `report_signing.key` + `report_verify.pub`
- Güncelleme keypair (offline): `update_signing.key` + `update_verify.pub`
- `update_signing.key` ASLA cihazda tutulmaz
- Cihaz ele geçirilse bile sahte güncelleme imzalanamaz

### T6: USB Killer

**Saldırı**: Elektriksel aşırı gerilim ile donanım hasarı.

**Savunma**: YAZILIMLA ÇÖZÜLEMEZ. Powered USB hub ile donanım izolasyonu gereklidir.
Optik izolasyonlu USB hub en güvenli çözümdür.

---

## Kabul Edilen Riskler

Bu riskler, mevcut mimari ile tamamen elimine edilemez:

1. **Firmware-level BadUSB**: USB firmware saldırıları yazılım katmanında %100 engellenemez
2. **USB Killer (elektriksel)**: Sadece donanım çözümü (powered/optik izolasyonlu hub) ile azaltılabilir
3. **Kernel exploit via bwrap escape**: bwrap user-space sandbox'tır; kernel exploit'lerine karşı tam koruma sağlamaz
4. **Zero-day malware**: Henüz imzası olmayan zararlılar tüm tarama motorlarını atlatabilir; CDR bu riski azaltır
5. **TOCTOU race conditions**: symlink kontrolleri ile gerçek dosya işleme arasındaki zaman farkı teorik olarak exploit edilebilir (pratik risk minimal)

---

## Güvenlik Mimarisi Özeti

```
┌─────────────────────────────────────────────────────┐
│  UNTRUSTED           TRUST BOUNDARY          TRUSTED │
│                                                      │
│  Kaynak USB ──►  [L1] USBGuard                       │
│                  [L2] Mount Policy (ro)               │
│                  [L3] File Validator                  │
│                  [L4] Multi-Engine Scanner            │
│                  [L5] CDR Engine (sandbox)            │
│                  [L6] Signed Report          ──► Hedef│
│                                                  USB │
│  Update USB ──►  [L7] Ed25519 Signature              │
│                       (key separation)               │
└─────────────────────────────────────────────────────┘
```

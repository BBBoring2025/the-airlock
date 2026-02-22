# THE AIRLOCK — Operasyon Rehberi

## Günlük Kullanım

1. **DIRTY** etiketli USB'yi takın (kaynak — güvenilmeyen dosyalar)
2. **CLEAN** etiketli USB'yi takın (hedef — sanitize edilmiş dosyalar)
3. İşlem otomatik başlar (LED yanıp söner, OLED ilerleme gösterir)
4. **Yeşil LED** = tamamlandı, **Kırmızı LED** = tehdit bulundu
5. OLED ekranda ilerleme yüzdesi ve sonuç bilgisi
6. Rapor CLEAN USB'ye JSON dosyası olarak yazılır (Ed25519 imzalı)

### Kabul Edilen USB Etiketleri

| Tip | Kabul Edilen Etiketler |
|-----|----------------------|
| Kaynak (güvenilmeyen) | `DIRTY`, `KIRLI`, `SOURCE`, `INPUT` |
| Hedef (temiz) | `CLEAN`, `TEMIZ`, `TARGET`, `OUTPUT` |
| Güncelleme | `UPDATE`, `GÜNCELLEME` |

---

## İlk Kurulum Sonrası Kontrol

```bash
# Servis durumları
sudo systemctl status airlock
sudo systemctl status airlock-helper

# Self-test (tüm bileşenleri kontrol eder)
cd /opt/airlock
python -m tests.self_test

# Anahtar dosyaları kontrol
ls -la /opt/airlock/keys/
# Beklenen: report_signing.key (0600), report_verify.pub (0644), update_verify.pub (0644)
```

---

## Log Yönetimi

### Log Konumları

| Log | Konum | Açıklama |
|-----|-------|----------|
| Daemon log | `/opt/airlock/data/logs/` | Ana daemon logları |
| systemd journal | `journalctl -u airlock` | Sistem seviyesi loglar |
| Helper log | `journalctl -u airlock-helper` | Privileged helper logları |
| Rapor arşivi | `/opt/airlock/data/reports/` | İşlem raporları (JSON) |

### Canlı İzleme

```bash
# Ana daemon logları
journalctl -u airlock -f

# Helper logları
journalctl -u airlock-helper -f

# Her iki servis birlikte
journalctl -u airlock -u airlock-helper -f
```

### Log Rotasyonu

Otomatik rotasyon: max **50MB** x **10** dosya. Yapılandırma: `airlock.yaml` → `logging` bölümü.

---

## Güncelleme Prosedürü

### Offline Güncelleme (Normal)

1. **Offline makinede** güncelleme paketi hazırlayın:
   - ClamAV veritabanı güncellemeleri
   - YARA kuralları
   - Bilinen-kötü hash listesi
   - `manifest.json` ile dosya listesi ve hash'ler

2. **Güncelleme imzalayın** (güvenli ortamda):
   ```bash
   # update_signing.key ile manifest imzala
   python -c "from app.utils.crypto import sign_file; print(sign_file('manifest.json', 'update_signing.key'))"
   ```

3. **UPDATE etiketli USB'ye kopyalayın** ve AIRLOCK'a takın

4. Otomatik doğrulama ve uygulama:
   - Ed25519 imza doğrulama
   - Dosya hash kontrolü
   - Symlink/path traversal kontrolü
   - Başarılı → güncelleme uygulanır
   - Başarısız → güncelleme reddedilir, cihaz mevcut haliyle devam eder

---

## Sorun Giderme

| Belirti | Olası Neden | Çözüm |
|---------|------------|-------|
| USB tanınmadı | Etiket yanlış | Doğru etiket kullanın: DIRTY/KIRLI/SOURCE/INPUT |
| Mount hatası | Desteklenmeyen dosya sistemi | FAT32, exFAT, NTFS veya ext4 kullanın |
| ClamAV hatası | Daemon çökmüş | `sudo systemctl restart clamav-daemon` |
| OLED ekran yok | I2C bağlantısı | `i2cdetect -y 1` ile 0x3C adresi kontrol (opsiyonel donanım) |
| LED çalışmıyor | GPIO bağlantısı | GPIO pin bağlantısını kontrol edin (opsiyonel donanım) |
| Helper bağlantı hatası | Socket izinleri | `ls -la /run/airlock/helper.sock` — 0660 root:airlock olmalı |
| Tüm dosyalar karantinaya alınıyor | Paranoid politika | `airlock.yaml` → `active_policy: balanced` yapın |
| Servis başlamıyor | Yapılandırma hatası | `journalctl -u airlock -n 50` ile son logları inceleyin |

### Servis Yeniden Başlatma

```bash
# Sadece daemon
sudo systemctl restart airlock

# Sadece helper
sudo systemctl restart airlock-helper

# Her ikisi
sudo systemctl restart airlock airlock-helper
```

---

## Karantina Yönetimi

### Konum

```
/opt/airlock/data/quarantine/
```

### Temizlik

```bash
# 30 günden eski dosyaları listele
find /opt/airlock/data/quarantine/ -type f -mtime +30

# 30 günden eski dosyaları sil
sudo find /opt/airlock/data/quarantine/ -type f -mtime +30 -delete
```

### Uyarılar

- **KESİNLİKLE** karantina dosyalarını başka bir sisteme taşımayın
- Karantina dosyaları potansiyel olarak zararlıdır
- Analiz gerekiyorsa izole bir sandbox ortamında yapın

---

## Güvenlik Politikaları

| Politika | Açıklama | Kullanım Senaryosu |
|----------|----------|-------------------|
| **paranoid** | Office engellenir, arşivler engellenir, bilinmeyen tipler engellenir, CDR başarısızlığı = karantina | Yüksek güvenlikli ortamlar |
| **balanced** (varsayılan) | Tüm yaygın tipler CDR ile işlenir, bilinmeyen = uyarıyla kopyala | Genel kullanım |
| **convenient** | Maksimum uyumluluk, CDR başarısızlığı = sanitize edilmemiş klasöre kopyala | Düşük riskli ortamlar |

Politika değiştirme:
```yaml
# /opt/airlock/config/airlock.yaml
active_policy: "balanced"  # paranoid | balanced | convenient
```

---

## Yedekleme

### Kritik Dosyalar

| Dosya/Dizin | Öncelik | Açıklama |
|------------|---------|----------|
| `/opt/airlock/config/airlock.yaml` | Yüksek | Ana yapılandırma |
| `/opt/airlock/keys/` | Kritik | Ed25519 anahtarları (GÜVENLİ YEDEKLE) |
| `/opt/airlock/data/reports/` | Orta | İşlem raporları arşivi |

### Yedekleme Notları

- `report_signing.key` yedeğini **şifreli olarak** saklayın
- `update_signing.key` cihazda OLMAMALIDIR — sadece güvenli offline depoda
- `update_verify.pub` kaybedilirse cihaz güncelleme alamaz
- Yedekleme USB'si ayrı bir etiketle (BACKUP) tanımlanmaz — manuel kopyalama yapın

# THE AIRLOCK v5.1.1 — Anahtar Yönetimi (Key Management)

## Genel Bakış

AIRLOCK, güvenlik açısından iki farklı Ed25519 keypair kullanır.
Anahtar ayrımının temel nedeni: **cihaz ele geçirilmesi ≠ filo ele geçirilmesi**.

## İki Keypair Mimarisi

### 1. Rapor İmzalama Keypair (Device-Specific)

| Dosya | Konum | İzin |
|-------|-------|------|
| `report_signing.key` | `/opt/airlock/keys/` | `0600` (airlock user) |
| `report_verify.pub` | `/opt/airlock/keys/` | `0644` |

- **Üretim yeri**: Cihaz üzerinde (`generate_keys.sh`)
- **Amaç**: Tarama raporlarını imzalar — raporun bu cihazdan geldiğini kanıtlar
- **Özel anahtar**: Cihazda kalır — cihaza özeldir
- **Risk**: Cihaz ele geçirilirse sadece O cihazın raporları taklit edilebilir

### 2. Güncelleme Doğrulama Keypair (Vendor-Managed)

| Dosya | Konum | İzin |
|-------|-------|------|
| `update_signing.key` | **Offline güvenli depolama** | Sadece vendor erişimi |
| `update_verify.pub` | `/opt/airlock/keys/` | `0644` |

- **Üretim yeri**: Güvenli offline ortam (`generate_keys.sh --generate-update-keypair`)
- **Amaç**: Offline güncellemelerin bütünlüğünü doğrular
- **Özel anahtar**: ASLA cihazda tutulmaz — USB ile kopyalandıktan sonra silinir
- **Risk**: Sadece vendor'ın güvenli deposu ele geçirilirse tüm filo etkilenir

## Neden Ayrı Keypair?

Eski mimari (tek keypair) şu saldırı senaryosuna açıktı:

```
Saldırgan → Cihazı ele geçirir → report_signing.key elde eder
         → AYNI anahtar update_verify.pub'ın karşılığı
         → Sahte güncelleme imzalayabilir
         → TÜM FİLOYU ELE GEÇİRİR (supply-chain attack)
```

Yeni mimari (iki keypair):

```
Saldırgan → Cihazı ele geçirir → report_signing.key elde eder
         → Bu anahtar SADECE rapor imzalar
         → update_signing.key cihazda YOK
         → Sahte güncelleme İMZALAYAMAZ
         → Sadece tek cihaz etkilenir
```

## Anahtar Üretim Prosedürü

### Yeni Cihaz Kurulumu

```bash
# 1. Rapor keypair üret (cihaz üzerinde)
sudo /opt/airlock/scripts/generate_keys.sh

# 2. Güncelleme keypair üret (güvenli offline ortamda)
sudo /opt/airlock/scripts/generate_keys.sh --generate-update-keypair

# 3. update_verify.pub dosyasını cihaza kopyala
sudo cp update_verify.pub /opt/airlock/keys/
sudo chmod 0644 /opt/airlock/keys/update_verify.pub

# 4. update_signing.key dosyasını GÜVENLİ OFFLINE DEPOYA taşı
# KRİTİK: Bu dosyayı cihazda BIRAKMAYIN!
```

### Mevcut Cihaz Geçişi

Eski tek-keypair sisteminden yeni dual-keypair sistemine geçiş:

```bash
# 1. Mevcut report_signing.key yedekle
sudo cp /opt/airlock/keys/report_signing.key /opt/airlock/keys/report_signing.key.backup

# 2. Yeni rapor keypair üret (eski key üzerine yazılır)
sudo /opt/airlock/scripts/generate_keys.sh

# 3. Güncelleme keypair üret (ayrı ortamda önerilir)
sudo /opt/airlock/scripts/generate_keys.sh --generate-update-keypair
```

## Anahtar Rotasyonu

### Rapor Anahtarı Rotasyonu (Düşük Risk)

Her cihaz kendi rapor anahtarını bağımsız olarak döndürebilir:

```bash
sudo /opt/airlock/scripts/generate_keys.sh
# Eski anahtar otomatik yedeklenir (.backup uzantısıyla)
```

### Güncelleme Anahtarı Rotasyonu (Yüksek Dikkat)

1. Yeni update keypair üret (güvenli offline ortamda)
2. Yeni `update_verify.pub` dosyasını TÜM cihazlara dağıt
3. Bundan sonraki güncellemeleri yeni anahtar ile imzala
4. Eski `update_signing.key` dosyasını güvenli şekilde yok et

**DİKKAT**: Güncelleme anahtarı rotasyonu tüm filoyu etkiler. Yanlış yapılırsa
hiçbir cihaz güncelleme alamaz.

## Tehdit Senaryoları ve Yanıtlar

| Senaryo | Etki | Yanıt |
|---------|------|-------|
| Tek cihaz fiziksel ele geçirilme | report_signing.key ifşa | Cihazı devre dışı bırak, yeni rapor keypair üret |
| report_signing.key sızdırıldı | Sahte raporlar üretilebilir | report_verify.pub değiştir, eski raporları yeniden doğrula |
| update_signing.key sızdırıldı | TÜM filo tehlikede | Acil güncelleme anahtarı rotasyonu, tüm cihazlara yeni pub dağıt |
| update_verify.pub bozuldu | Geçerli güncellemeler reddedilir | Yeni update_verify.pub kopyala |

## Yapılandırma

`config/airlock.yaml` dosyasında anahtar yolları:

```yaml
update:
  require_signature: true
  public_key_path: "/opt/airlock/keys/update_verify.pub"

report:
  signing_key_path: "/opt/airlock/keys/report_signing.key"
  verify_key_path: "/opt/airlock/keys/report_verify.pub"
```

## Kriptografik Detaylar

- **Algoritma**: Ed25519 (Curve25519 üzerinde EdDSA)
- **Anahtar boyutu**: 256-bit (32 byte)
- **İmza boyutu**: 512-bit (64 byte)
- **Kütüphane**: PyNaCl (libsodium binding)
- **Kodlama**: Base64 (dosya depolama ve imza taşıma)

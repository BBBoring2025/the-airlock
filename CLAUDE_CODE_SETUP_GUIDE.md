# THE AIRLOCK v4.0 — Claude Code Kurulum ve Kullanım Rehberi
## Mac + Claude Max için Adım Adım

---

## ADIM 1: Claude Code Kurulumu (2 dakika)

Terminal'i aç (Spotlight → "Terminal" yaz) ve şu komutu yapıştır:

```bash
curl -fsSL https://cli.claude.com/install.sh | sh
```

Kurulum bittikten sonra doğrula:

```bash
claude --version
```

Versiyon numarası görüyorsan kurulum tamam.

> ⚠️ Eğer "command not found" hatası alırsan, Terminal'i kapat-aç ve tekrar dene.

---

## ADIM 2: Giriş Yap (1 dakika)

```bash
claude
```

İlk çalıştırmada tarayıcı açılacak → Claude Max hesabınla giriş yap (OAuth).
"Authorized" mesajı gelince Terminal'e dön. Artık hazırsın.

---

## ADIM 3: Proje Klasörünü Hazırla

```bash
# Masaüstünde proje klasörü oluştur
mkdir -p ~/Desktop/airlock-v4
cd ~/Desktop/airlock-v4
```

---

## ADIM 4: CLAUDE.md Dosyasını Oluştur (EN ÖNEMLİ ADIM)

Bu dosya Claude Code'un "beyni". Her oturum başında otomatik okunur.
Aşağıdaki komutu çalıştırarak dosyayı oluştur:

```bash
cat > CLAUDE.md << 'CLAUDEMD'
# THE AIRLOCK v4.0 FORTRESS — Proje Talimatları

## Sen Nesin?
Bu proje Raspberry Pi 5 (8GB) üzerinde çalışan air-gapped USB sanitization
istasyonudur. Güvenilmeyen USB'deki dosyaları tarar, temizler (CDR), güvenli
USB'ye aktarır.

## Mimari Döküman
Tüm detaylar `AIRLOCK_V4_FORTRESS_ARCHITECTURE.md` dosyasında.
HER ZAMAN önce bu dosyayı oku. O ana referansın.

## Kodlama Kuralları
- Python 3.11+ (Raspberry Pi OS Bookworm)
- Type hints ZORUNLU (typing modülü)
- Dataclass kullan (namedtuple değil)
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

## Donanım Toleransı
GPIO, OLED, LED, buzzer YOKSA → graceful degrade et.
Donanım hatası daemon'ı çökertMEmeli. Her donanım çağrısı try/except ile sarılmalı.

## Dizin Yapısı
```
/opt/airlock/
├── app/                    # Ana uygulama
│   ├── main.py             # Entry point
│   ├── daemon.py           # Ana daemon
│   ├── config.py           # Yapılandırma
│   ├── security/           # Güvenlik modülleri
│   ├── hardware/           # Donanım kontrolleri
│   ├── updater/            # Güncelleme sistemi
│   └── utils/              # Yardımcı araçlar
├── config/                 # YAML yapılandırma
├── data/                   # Veri dizinleri
├── keys/                   # Kriptografik anahtarlar
├── systemd/                # Servis dosyası
├── scripts/                # Kurulum scriptleri
└── tests/                  # Test dosyaları
```

## İmplementasyon Sırası
Mimari dokümandaki Bölüm 10'daki 7 aşamayı sırayla takip et.
Her modülü yaz, syntax kontrol et (python3 -m py_compile), sonrakine geç.

## Test
- Her modül sonrası: `python3 -m py_compile <dosya>`
- Import testi: `python3 -c "from app.security.scanner import FileScanner"`
CLAUDEMD
```

---

## ADIM 5: Mimari Dökümanları Klasöre Kopyala

İndirdiğin iki dosyayı proje klasörüne kopyala:

```bash
# Finder'dan sürükle-bırak veya:
cp ~/Downloads/AIRLOCK_V4_FORTRESS_ARCHITECTURE.md ~/Desktop/airlock-v4/
cp ~/Downloads/CLAUDE_CODE_INSTRUCTIONS.md ~/Desktop/airlock-v4/
```

Kontrol et:

```bash
ls -la ~/Desktop/airlock-v4/
```

Şunları görmelisin:
```
CLAUDE.md
AIRLOCK_V4_FORTRESS_ARCHITECTURE.md
CLAUDE_CODE_INSTRUCTIONS.md
```

---

## ADIM 6: Claude Code'u Başlat ve İlk Komutu Ver

```bash
cd ~/Desktop/airlock-v4
claude
```

Claude Code açılınca şunu yapıştır:

---

### 🎯 CLAUDE CODE'A VERECEĞİN İLK KOMUT:

```
AIRLOCK_V4_FORTRESS_ARCHITECTURE.md dosyasını oku. Bu, Raspberry Pi 5 üzerinde 
çalışacak air-gapped USB sanitization istasyonunun tam mimari dökümanı.

Şimdi bu dökümanı takip ederek projeyi inşa etmeye başla:

1. Önce Bölüm 10'daki "Uygulama Sırası"nı oku
2. AŞAMA 1'den başla (Temel Altyapı)
3. Her modülü yaz, python3 -m py_compile ile syntax kontrol et
4. Bir aşama bitince bana bildir, sonraki aşamaya geçelim

Dizin yapısını oluşturarak başla, sonra config.py ile devam et.
Her dosyayı /opt/airlock/ altına değil, bu proje dizinine yaz (sonra Pi'ye taşıyacağız).
```

---

## CLAUDE CODE KULLANIM İPUÇLARI

### Temel Komutlar (oturum içinde)

| Komut | Ne Yapar |
|-------|----------|
| `/help` | Komut listesi |
| `/init` | CLAUDE.md otomatik oluştur (bizim zaten var) |
| `# not ekle` | CLAUDE.md'ye kalıcı not ekle |
| `/clear` | Konuşma geçmişini temizle |
| `/cost` | Ne kadar token harcandığını göster |
| `Escape` | Çalışan işlemi iptal et |
| `Ctrl+C` | Claude Code'dan çık |

### Önemli Bilgiler

- **Context window dolabilir**: Uzun oturumlarda Claude "unutmaya" başlar.
  Bu olursa yeni oturum aç (`claude` komutu ile). CLAUDE.md sayesinde bağlamı kaybetmez.

- **Her oturum = 1 aşama**: En iyi sonuç için her aşamayı ayrı oturumda yap.
  Aşama bitince çık, yeni oturum aç, "AŞAMA 2'ye geç" de.

- **Dosya izinleri**: Claude Code dosya oluşturmak/düzenlemek isteyince izin sorar.
  "Yes, allow all edits during this session" seçeneğini seç (güvenli).

- **Hata olursa**: Claude Code kendisi görecek ve düzeltecek. 
  Sen sadece "bu hatayı düzelt" de yeter.

### Oturum Akışı (Aşama Aşama)

```
OTURUM 1: "Mimari dökümanı oku ve AŞAMA 1'i tamamla (temel altyapı)"
   → config.py, logger.py, crypto.py, hardware stub'ları
   → Çık

OTURUM 2: "AŞAMA 2'ye geç — güvenlik çekirdeğini yaz"
   → usb_guard.py, mount_manager.py, file_validator.py, scanner.py
   → Çık

OTURUM 3: "AŞAMA 3 — CDR engine ve arşiv handler"
   → cdr_engine.py, archive_handler.py
   → Çık

OTURUM 4: "AŞAMA 4 — raporlama ve güncelleme sistemi"
   → report_generator.py, offline_updater.py
   → Çık

OTURUM 5: "AŞAMA 5 — ana daemon, tüm modülleri birleştir"
   → daemon.py, main.py
   → Çık

OTURUM 6: "AŞAMA 6 — kurulum scripti, systemd, testler"
   → setup.sh, airlock.service, self_test.py
   → Çık

OTURUM 7: "AŞAMA 7 — donanım modüllerini tamamla (OLED, LED, ses)"
   → Gerçek implementasyonlar
   → Çık
```

---

## SORUN GİDERME

### "command not found: claude"
```bash
# PATH'e ekle
export PATH="$HOME/.local/bin:$PATH"
# Kalıcı yap
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

### Kurulum başarısız olursa (alternatif yol)
```bash
# npm ile kur (Node.js gerekir)
# Önce Node.js: https://nodejs.org adresinden LTS indir
npm install -g @anthropic-ai/claude-code
```

### Claude Code yavaş çalışıyorsa
```bash
# Doktor komutu ile kontrol et
claude doctor
```

### Context window doldu uyarısı
Yeni oturum aç:
```bash
# Çık
Ctrl+C
# Tekrar başla
claude
# "Devam et" de
```

---

## ÖNCESİ / SONRASI KARŞILAŞTIRMA

```
ÖNCESİ (v3.0):
├── airlock_daemon_v3.py     # 823 satır, 4 modül eksik
├── setup_airlock_v3.sh      # Eksik servis dosyası
└── airlock_v3_docs.md       # Sadece dokümantasyon

SONRASI (v4.0 FORTRESS):
├── app/
│   ├── main.py
│   ├── daemon.py
│   ├── config.py
│   ├── security/
│   │   ├── usb_guard.py          # YENİ: BadUSB koruması
│   │   ├── mount_manager.py      # YENİ: Güvenli mount
│   │   ├── file_validator.py     # YENİ: Symlink/traversal koruması
│   │   ├── scanner.py            # YENİ: ClamAV + YARA + entropy + magic
│   │   ├── cdr_engine.py         # YENİ: OCR destekli CDR
│   │   ├── archive_handler.py    # YENİ: Zip bomb korumalı
│   │   └── report_generator.py   # YENİ: İmzalı raporlar
│   ├── hardware/
│   │   ├── oled_display.py       # TAMAMLANDI
│   │   ├── led_controller.py     # TAMAMLANDI
│   │   ├── audio_feedback.py     # TAMAMLANDI
│   │   └── button_handler.py     # TAMAMLANDI
│   ├── updater/
│   │   └── offline_updater.py    # YENİ: İmza doğrulamalı
│   └── utils/
│       ├── logger.py
│       └── crypto.py             # YENİ: Ed25519 imzalama
├── config/
│   ├── airlock.yaml
│   └── policies/                 # YENİ: 3 güvenlik profili
├── systemd/
│   └── airlock.service           # YENİ: Sandbox'lı servis
├── scripts/
│   ├── setup.sh                  # GÜNCEL: Tam kurulum
│   └── self_test.py              # YENİ: 25 otomatik test
└── tests/                        # YENİ: Birim testler
```

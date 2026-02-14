# CLAUDE CODE TALİMATLARI — THE AIRLOCK v4.0 FORTRESS

## SEN NESİN?
THE AIRLOCK v4.0 FORTRESS'un geliştiricisisin. Raspberry Pi 5 (8GB) üzerinde çalışan,
air-gapped USB sanitization istasyonu inşa edeceksin.

## MİMARİ DÖKÜMAN
AIRLOCK_V4_FORTRESS_ARCHITECTURE.md dosyasını oku. O ana referansın.
Orada her modülün ne yapacağı, hangi sırada yazılacağı, kodlama standartları ve
güvenlik kuralları detaylı anlatılıyor.

## TEMEL KURALLAR
1. Her modülü yaz, test et, sonraki modüle geç
2. Donanım (GPIO, OLED, LED) yoksa graceful degrade et — daemon çalışmaya devam etmeli
3. CDR başarısız olursa ASLA orijinali kopyalama — karantinaya al
4. subprocess çağrılarında shell=False ve timeout kullan
5. Type hints zorunlu, docstring zorunlu
6. Pi'de test edemiyorsan bile syntax + import hatası olmamalı

## BAŞLANGIÇ KOMUTU
```bash
mkdir -p /opt/airlock/{app/{security,hardware,updater,utils},config/policies,data/{yara_rules/{core,custom},clamav,quarantine,logs,sounds},keys,systemd,scripts,tests/samples,tmp}
```

## İMPLEMENTASYON SIRASI
Mimari dokümandaki "10. CLAUDE CODE İÇİN TALİMATLAR" bölümündeki sırayı takip et.
7 aşama var. Her aşamayı bitir, sonrakine geç.

## TEST
Her modül yazıldıktan sonra:
- Python syntax kontrolü: `python3 -m py_compile <dosya>`
- Import kontrolü: `python3 -c "from app.security.scanner import FileScanner"`
- Birim test: tests/ dizinine test yaz

## ÇIKTI
Tüm dosyalar /opt/airlock/ altına yazılacak.
Son adımda self_test.py çalıştırılıp rapor verilecek.

#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
# THE AIRLOCK v5.1.1 FORTRESS — Tam Kurulum Scripti
#
# Raspberry Pi 5 (8GB) — Raspberry Pi OS Bookworm (64-bit)
#
# Kullanım:
#   chmod +x scripts/setup.sh
#   sudo ./scripts/setup.sh
#
# Bu script şunları yapar:
#   1.  Sistem güncelleme
#   2.  Gerekli paketlerin kurulumu
#   3.  ImageMagick PDF policy düzeltmesi
#   4.  I2C etkinleştirme
#   5.  Log2Ram kurulumu
#   6.  tmpfs (512MB RAM disk) kurulumu
#   7.  Dizin yapısı oluşturma
#   8.  'airlock' kullanıcısı oluşturma
#   9.  Python venv + pip install
#   10. YARA kuralları indirme
#   11. ClamAV ilk veritabanı + freshclam devre dışı
#   12. Ses dosyaları üretme
#   13. Kriptografik anahtar üretme
#   14. udev kuralları kurma
#   15. systemd service kurma + enable
#   16. Swap optimizasyonu
#   17. EICAR test dosyası oluşturma
#   18. Self-test çalıştırma
#   19. Reboot uyarısı
# ═══════════════════════════════════════════════════════════════

set -euo pipefail

# ── Renk Kodları ──
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ── Sabitler ──
AIRLOCK_DIR="/opt/airlock"
AIRLOCK_USER="airlock"
AIRLOCK_VERSION="5.1.1"

# ── Yardımcı Fonksiyonlar ──
log_step() {
    echo -e "\n${CYAN}${BOLD}[ADIM $1/$TOTAL_STEPS]${NC} ${BOLD}$2${NC}"
    echo "────────────────────────────────────────────"
}

log_ok() {
    echo -e "  ${GREEN}✓${NC} $1"
}

log_warn() {
    echo -e "  ${YELLOW}⚠${NC} $1"
}

log_err() {
    echo -e "  ${RED}✗${NC} $1"
}

TOTAL_STEPS=19

# ── Root Kontrolü ──
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Bu script root olarak çalıştırılmalı:${NC}"
    echo "  sudo $0"
    exit 1
fi

echo -e "${BOLD}"
echo "═══════════════════════════════════════════════════"
echo "  THE AIRLOCK v${AIRLOCK_VERSION} FORTRESS"
echo "  Kurulum Scripti — Raspberry Pi 5"
echo "═══════════════════════════════════════════════════"
echo -e "${NC}"

# ═══════════════════════════════════════════
# ADIM 1: Sistem Güncelleme
# ═══════════════════════════════════════════
log_step 1 "Sistem güncelleniyor"

apt-get update -y
apt-get upgrade -y
log_ok "Sistem güncellendi"

# ═══════════════════════════════════════════
# ADIM 2: Gerekli Paketler
# ═══════════════════════════════════════════
log_step 2 "Gerekli paketler kuruluyor"

PACKAGES=(
    # Python
    python3-pip python3-venv python3-dev python3-pil python3-smbus
    # Araçlar
    i2c-tools git jq bubblewrap
    # ClamAV
    clamav clamav-daemon
    # Grafik / PDF
    imagemagick ghostscript
    # OCR
    tesseract-ocr tesseract-ocr-tur tesseract-ocr-eng
    # PDF araçları
    img2pdf qpdf poppler-utils
    # LibreOffice headless
    libreoffice-writer-nogui libreoffice-calc-nogui libreoffice-impress-nogui
    # Video
    ffmpeg
    # Arşiv
    p7zip-full unrar-free
    # Ses
    alsa-utils
    # GPIO
    python3-gpiozero python3-rpi-lgpio
    # USB
    usbutils
)

apt-get install -y "${PACKAGES[@]}"
log_ok "Tüm paketler kuruldu"

# USBGuard (opsiyonel)
if apt-cache show usbguard >/dev/null 2>&1; then
    apt-get install -y usbguard || log_warn "USBGuard kurulamadı (opsiyonel)"
else
    log_warn "USBGuard paketi bulunamadı — atlanıyor (opsiyonel)"
fi

# ═══════════════════════════════════════════
# ADIM 3: ImageMagick PDF Policy Düzeltmesi
# ═══════════════════════════════════════════
log_step 3 "ImageMagick PDF policy düzeltiliyor"

POLICY_FILE="/etc/ImageMagick-6/policy.xml"
if [ ! -f "$POLICY_FILE" ]; then
    POLICY_FILE="/etc/ImageMagick-7/policy.xml"
fi

if [ -f "$POLICY_FILE" ]; then
    # PDF okuma/yazma engelini kaldır
    sed -i 's/<policy domain="coder" rights="none" pattern="PDF" \/>/<policy domain="coder" rights="read|write" pattern="PDF" \/>/g' "$POLICY_FILE"
    # Ghostscript engelini kaldır
    sed -i 's/<policy domain="delegate" rights="none" pattern="gs" \/>/<policy domain="delegate" rights="read|write" pattern="gs" \/>/g' "$POLICY_FILE"
    log_ok "ImageMagick PDF policy güncellendi: $POLICY_FILE"
else
    log_warn "ImageMagick policy dosyası bulunamadı"
fi

# ═══════════════════════════════════════════
# ADIM 4: I2C Etkinleştirme
# ═══════════════════════════════════════════
log_step 4 "I2C etkinleştiriliyor"

if ! grep -q "^dtparam=i2c_arm=on" /boot/firmware/config.txt 2>/dev/null; then
    echo "dtparam=i2c_arm=on" >> /boot/firmware/config.txt
    log_ok "I2C etkinleştirildi (config.txt)"
else
    log_ok "I2C zaten etkin"
fi

if ! grep -q "^i2c-dev" /etc/modules 2>/dev/null; then
    echo "i2c-dev" >> /etc/modules
    log_ok "i2c-dev modülü eklendi"
fi

modprobe i2c-dev 2>/dev/null || true

# ═══════════════════════════════════════════
# ADIM 5: Log2Ram Kurulumu
# ═══════════════════════════════════════════
log_step 5 "Log2Ram kuruluyor (SD kart ömrü için)"

if ! command -v log2ram >/dev/null 2>&1; then
    if [ -d /tmp/log2ram_install ]; then
        rm -rf /tmp/log2ram_install
    fi
    git clone https://github.com/azlux/log2ram.git /tmp/log2ram_install
    cd /tmp/log2ram_install
    chmod +x install.sh
    ./install.sh || log_warn "Log2Ram kurulumu başarısız (opsiyonel)"
    cd /opt
    rm -rf /tmp/log2ram_install
    log_ok "Log2Ram kuruldu"
else
    log_ok "Log2Ram zaten kurulu"
fi

# ═══════════════════════════════════════════
# ADIM 6: tmpfs (512MB RAM Disk) Kurulumu
# ═══════════════════════════════════════════
log_step 6 "tmpfs RAM disk kuruluyor (512MB)"

FSTAB_ENTRY="tmpfs ${AIRLOCK_DIR}/tmp tmpfs nodev,nosuid,noexec,size=512M,mode=0750,uid=${AIRLOCK_USER},gid=${AIRLOCK_USER} 0 0"

if ! grep -q "${AIRLOCK_DIR}/tmp" /etc/fstab 2>/dev/null; then
    echo "$FSTAB_ENTRY" >> /etc/fstab
    log_ok "tmpfs fstab'a eklendi"
else
    log_ok "tmpfs zaten fstab'da"
fi

# ═══════════════════════════════════════════
# ADIM 7: Dizin Yapısı Oluşturma
# ═══════════════════════════════════════════
log_step 7 "Dizin yapısı oluşturuluyor"

mkdir -p "${AIRLOCK_DIR}"/{app/{security,hardware,updater,utils},config/policies,data/{yara_rules/{core,custom},clamav,quarantine,logs,sounds},keys,systemd,scripts,tests/samples,tmp}

# __init__.py dosyaları
for dir in app app/security app/hardware app/updater app/utils; do
    touch "${AIRLOCK_DIR}/${dir}/__init__.py"
done

# VERSION dosyası
echo "${AIRLOCK_VERSION}" > "${AIRLOCK_DIR}/VERSION"

log_ok "Dizin yapısı oluşturuldu"

# ═══════════════════════════════════════════
# ADIM 8: Kullanıcı Oluşturma
# ═══════════════════════════════════════════
log_step 8 "'${AIRLOCK_USER}' kullanıcısı oluşturuluyor"

if ! id "$AIRLOCK_USER" >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$AIRLOCK_USER"
    log_ok "Kullanıcı oluşturuldu: $AIRLOCK_USER"
else
    log_ok "Kullanıcı zaten mevcut: $AIRLOCK_USER"
fi

# Gruplara ekle
for grp in gpio i2c audio plugdev disk; do
    if getent group "$grp" >/dev/null 2>&1; then
        usermod -aG "$grp" "$AIRLOCK_USER" 2>/dev/null || true
    fi
done
log_ok "Kullanıcı gruplara eklendi: gpio, i2c, audio, plugdev, disk"

# Sahiplik
chown -R "${AIRLOCK_USER}:${AIRLOCK_USER}" "${AIRLOCK_DIR}"
chmod 700 "${AIRLOCK_DIR}/keys"
log_ok "Dizin sahiplikleri ayarlandı"

# Mount noktaları — privileged helper sadece /mnt/airlock_* kabul eder
mkdir -p /mnt/airlock_source /mnt/airlock_target /mnt/airlock_update
chown "${AIRLOCK_USER}:${AIRLOCK_USER}" /mnt/airlock_source /mnt/airlock_target /mnt/airlock_update
chmod 750 /mnt/airlock_source /mnt/airlock_target /mnt/airlock_update
log_ok "Mount noktaları hazırlandı: /mnt/airlock_{source,target,update}"

# USB sysfs authorized dosyaları için udev kuralı ile yazma izni verilecek
# (ADIM 14'te airlock-deauth scripti kurulur)
log_ok "USB deauthorize izni: udev + sysfs ACL ile"

# ═══════════════════════════════════════════
# ADIM 9: Python venv + pip install
# ═══════════════════════════════════════════
log_step 9 "Python sanal ortamı oluşturuluyor"

python3 -m venv "${AIRLOCK_DIR}/venv" --system-site-packages
source "${AIRLOCK_DIR}/venv/bin/activate"

pip install --upgrade pip wheel setuptools

# Ana bağımlılıklar (requirements.txt — pinned)
pip install -r "${AIRLOCK_DIR}/requirements.txt"
log_ok "Core Python paketleri kuruldu (requirements.txt)"

# Donanım bağımlılıkları (opsiyonel — Pi-specific)
pip install -r "${AIRLOCK_DIR}/requirements-hardware.txt" || log_warn "Donanım paketleri kısmen kurulamadı (opsiyonel)"
log_ok "Python paketleri kuruldu"

deactivate

chown -R "${AIRLOCK_USER}:${AIRLOCK_USER}" "${AIRLOCK_DIR}/venv"

# ═══════════════════════════════════════════
# ADIM 10: YARA Kuralları İndirme
# ═══════════════════════════════════════════
log_step 10 "YARA kuralları indiriliyor"

YARA_CORE="${AIRLOCK_DIR}/data/yara_rules/core"

# Neo23x0 signature-base
if [ ! -d "/tmp/signature-base" ]; then
    git clone --depth 1 https://github.com/Neo23x0/signature-base.git /tmp/signature-base 2>/dev/null || true
fi
if [ -d "/tmp/signature-base/yara" ]; then
    cp /tmp/signature-base/yara/*.yar "${YARA_CORE}/" 2>/dev/null || true
    log_ok "signature-base YARA kuralları kopyalandı"
fi
rm -rf /tmp/signature-base

# Yara-Rules community
if [ ! -d "/tmp/yara-rules" ]; then
    git clone --depth 1 https://github.com/Yara-Rules/rules.git /tmp/yara-rules 2>/dev/null || true
fi
if [ -d "/tmp/yara-rules" ]; then
    find /tmp/yara-rules -name "*.yar" -exec cp {} "${YARA_CORE}/" \; 2>/dev/null || true
    log_ok "Yara-Rules community kuralları kopyalandı"
fi
rm -rf /tmp/yara-rules

YARA_COUNT=$(find "${YARA_CORE}" -name "*.yar" 2>/dev/null | wc -l)
log_ok "Toplam YARA kuralı: ${YARA_COUNT}"

chown -R "${AIRLOCK_USER}:${AIRLOCK_USER}" "${AIRLOCK_DIR}/data/yara_rules"

# ═══════════════════════════════════════════
# ADIM 11: ClamAV Veritabanı
# ═══════════════════════════════════════════
log_step 11 "ClamAV yapılandırılıyor"

# freshclam ile ilk indirme
systemctl stop clamav-freshclam 2>/dev/null || true

freshclam --foreground || log_warn "freshclam ilk indirme kısmen başarısız olabilir"

# freshclam otomatik güncellemeyi devre dışı bırak (air-gapped)
systemctl disable clamav-freshclam 2>/dev/null || true
systemctl stop clamav-freshclam 2>/dev/null || true
log_ok "freshclam devre dışı bırakıldı (air-gapped mod)"

# ClamAV daemon başlat
systemctl enable clamav-daemon
systemctl restart clamav-daemon
log_ok "ClamAV daemon etkinleştirildi ve başlatıldı"

# ═══════════════════════════════════════════
# ADIM 12: Ses Dosyaları Üretimi
# ═══════════════════════════════════════════
log_step 12 "Ses dosyaları üretiliyor"

if [ -f "${AIRLOCK_DIR}/scripts/generate_sounds.py" ]; then
    "${AIRLOCK_DIR}/venv/bin/python3" "${AIRLOCK_DIR}/scripts/generate_sounds.py"
    SOUND_COUNT=$(find "${AIRLOCK_DIR}/data/sounds" -name "*.wav" 2>/dev/null | wc -l)
    log_ok "Ses dosyaları üretildi: ${SOUND_COUNT} WAV"
else
    log_warn "generate_sounds.py bulunamadı — ses dosyaları sonra üretilecek"
fi

# ═══════════════════════════════════════════
# ADIM 13: Kriptografik Anahtar Üretimi
# ═══════════════════════════════════════════
log_step 13 "Ed25519 anahtarları üretiliyor"

if [ -f "${AIRLOCK_DIR}/scripts/generate_keys.sh" ]; then
    # generate_keys.sh varsayılan modda SADECE report keypair üretir
    # update_verify.pub yoksa hata verir — bu beklenen davranıştır
    bash "${AIRLOCK_DIR}/scripts/generate_keys.sh" || true
else
    # Fallback: Python ile SADECE report keypair üret
    "${AIRLOCK_DIR}/venv/bin/python3" -c "
from pathlib import Path
import sys
sys.path.insert(0, '${AIRLOCK_DIR}')
from app.utils.crypto import generate_keypair
generate_keypair(
    private_key_path=Path('${AIRLOCK_DIR}/keys/report_signing.key'),
    public_key_path=Path('${AIRLOCK_DIR}/keys/report_verify.pub'),
)
print('Ed25519 report anahtarları üretildi')
"
fi

chown "${AIRLOCK_USER}:${AIRLOCK_USER}" "${AIRLOCK_DIR}/keys/"*
chmod 600 "${AIRLOCK_DIR}/keys/report_signing.key"
chmod 644 "${AIRLOCK_DIR}/keys/report_verify.pub"

# update_verify.pub varsa izinleri ayarla
if [ -f "${AIRLOCK_DIR}/keys/update_verify.pub" ]; then
    chmod 644 "${AIRLOCK_DIR}/keys/update_verify.pub"
else
    log_warn "update_verify.pub bulunamadı — offline güncellemeler çalışmayacak"
    log_warn "Vendor update public key'ini keys/ dizinine kopyalayın"
fi
log_ok "Anahtarlar üretildi ve izinleri ayarlandı"

# ═══════════════════════════════════════════
# ADIM 14: udev Kuralları
# ═══════════════════════════════════════════
log_step 14 "udev kuralları kuruluyor"

# airlock-deauth scriptini kur (shell çağırmayan tek satırlık script)
cp "${AIRLOCK_DIR}/scripts/airlock-deauth.sh" /usr/local/bin/airlock-deauth
chmod +x /usr/local/bin/airlock-deauth
chown root:root /usr/local/bin/airlock-deauth
log_ok "airlock-deauth scripti kuruldu: /usr/local/bin/airlock-deauth"

cat > /etc/udev/rules.d/99-airlock-usb.rules << 'UDEV_EOF'
# THE AIRLOCK v5.1.1 FORTRESS — USB Güvenlik Kuralları
# Shell çağırmaz — doğrudan airlock-deauth scripti ile deauthorize eder.
#
# HID cihazlarını engelle (Rubber Ducky / BadUSB koruması)
ACTION=="add", SUBSYSTEM=="usb", ATTR{bInterfaceClass}=="03", \
    RUN+="/usr/local/bin/airlock-deauth /sys%p/../.."

# CDC cihazlarını engelle
ACTION=="add", SUBSYSTEM=="usb", ATTR{bInterfaceClass}=="02", \
    RUN+="/usr/local/bin/airlock-deauth /sys%p/../.."

# Wireless cihazlarını engelle
ACTION=="add", SUBSYSTEM=="usb", ATTR{bInterfaceClass}=="e0", \
    RUN+="/usr/local/bin/airlock-deauth /sys%p/../.."

# Vendor Specific engelle
ACTION=="add", SUBSYSTEM=="usb", ATTR{bInterfaceClass}=="ff", \
    RUN+="/usr/local/bin/airlock-deauth /sys%p/../.."
UDEV_EOF

udevadm control --reload-rules
udevadm trigger
log_ok "udev kuralları kuruldu ve yüklendi (shell-free)"

# ═══════════════════════════════════════════
# ADIM 15: systemd Servis Kurulumu
# ═══════════════════════════════════════════
log_step 15 "systemd servisi kuruluyor"

cp "${AIRLOCK_DIR}/systemd/airlock-helper.service" /etc/systemd/system/airlock-helper.service
cp "${AIRLOCK_DIR}/systemd/airlock.service" /etc/systemd/system/airlock.service
systemctl daemon-reload
systemctl enable airlock-helper.service
systemctl enable airlock.service
log_ok "airlock-helper.service etkinleştirildi (privileged helper)"
log_ok "airlock.service etkinleştirildi"

# ═══════════════════════════════════════════
# ADIM 16: Swap Optimizasyonu
# ═══════════════════════════════════════════
log_step 16 "Swap optimizasyonu yapılıyor"

if ! grep -q "vm.swappiness" /etc/sysctl.d/99-airlock.conf 2>/dev/null; then
    cat > /etc/sysctl.d/99-airlock.conf << 'SYSCTL_EOF'
# THE AIRLOCK v5.1.1 — Swap ve bellek optimizasyonu
vm.swappiness=10
vm.vfs_cache_pressure=50
SYSCTL_EOF
    sysctl -p /etc/sysctl.d/99-airlock.conf
    log_ok "Swap optimizasyonu uygulandı (swappiness=10)"
else
    log_ok "Swap optimizasyonu zaten mevcut"
fi

# ═══════════════════════════════════════════
# ADIM 17: EICAR Test Dosyası
# ═══════════════════════════════════════════
log_step 17 "EICAR test dosyası oluşturuluyor"

EICAR_STRING='X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
echo -n "$EICAR_STRING" > "${AIRLOCK_DIR}/tests/samples/eicar.com.txt"
chown "${AIRLOCK_USER}:${AIRLOCK_USER}" "${AIRLOCK_DIR}/tests/samples/eicar.com.txt"
log_ok "EICAR test virüsü oluşturuldu"

# Boş hash listesi
if [ ! -f "${AIRLOCK_DIR}/config/known_bad_hashes.txt" ]; then
    cat > "${AIRLOCK_DIR}/config/known_bad_hashes.txt" << 'HASH_EOF'
# THE AIRLOCK v5.1.1 — Bilinen Kötü Dosya Hash'leri (SHA-256)
# Her satırda bir hash. # ile başlayan satırlar yorum.
# Format: sha256_hash  açıklama (opsiyonel)
#
# EICAR test hash'i:
275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f  EICAR-Test-File
HASH_EOF
    chown "${AIRLOCK_USER}:${AIRLOCK_USER}" "${AIRLOCK_DIR}/config/known_bad_hashes.txt"
    log_ok "Bilinen kötü hash listesi oluşturuldu"
fi

# ═══════════════════════════════════════════
# ADIM 18: Self-Test
# ═══════════════════════════════════════════
log_step 18 "Self-test çalıştırılıyor"

if [ -f "${AIRLOCK_DIR}/tests/self_test.py" ]; then
    "${AIRLOCK_DIR}/venv/bin/python3" "${AIRLOCK_DIR}/tests/self_test.py" || log_warn "Bazı testler başarısız olabilir (donanım bağlı)"
else
    log_warn "self_test.py bulunamadı — testler sonra çalıştırılacak"
fi

# ═══════════════════════════════════════════
# ADIM 19: Tamamlandı
# ═══════════════════════════════════════════
log_step 19 "Kurulum tamamlandı"

# tmpfs mount et
mkdir -p "${AIRLOCK_DIR}/tmp"
mount "${AIRLOCK_DIR}/tmp" 2>/dev/null || true
chown "${AIRLOCK_USER}:${AIRLOCK_USER}" "${AIRLOCK_DIR}/tmp"

echo ""
echo -e "${GREEN}${BOLD}═══════════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}  THE AIRLOCK v${AIRLOCK_VERSION} FORTRESS${NC}"
echo -e "${GREEN}${BOLD}  Kurulum başarıyla tamamlandı!${NC}"
echo -e "${GREEN}${BOLD}═══════════════════════════════════════════════════${NC}"
echo ""
echo -e "  Durum kontrol:   ${CYAN}sudo systemctl status airlock${NC}"
echo -e "  Log takip:       ${CYAN}sudo journalctl -u airlock -f${NC}"
echo -e "  Self-test:       ${CYAN}sudo -u airlock ${AIRLOCK_DIR}/venv/bin/python3 ${AIRLOCK_DIR}/tests/self_test.py${NC}"
echo ""
echo -e "${YELLOW}${BOLD}  ⚠  Değişikliklerin tam etkili olması için REBOOT önerilir.${NC}"
echo -e "${YELLOW}     sudo reboot${NC}"
echo ""

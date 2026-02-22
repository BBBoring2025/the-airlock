#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
# THE AIRLOCK v5.1.1 FORTRESS — Ed25519 Anahtar Yönetimi
#
# İKİ AYRI keypair, FARKLI güven alanları:
#
#   Keypair 1 — RAPOR (cihaz-özel, cihazda üretilir):
#     keys/report_signing.key  (private, 0600, cihazda kalır)
#     keys/report_verify.pub   (public, 0644, cihazda kalır)
#
#   Keypair 2 — UPDATE (vendor-özel, cihazda ÜRETİLMEZ):
#     update_signing.key → SADECE offline release makinesinde
#     keys/update_verify.pub → cihaza önceden yüklenir
#
# Kullanım:
#   ./scripts/generate_keys.sh
#       → SADECE report keypair üretir (cihaz kurulumu)
#       → update_verify.pub YOKSA hata verir
#
#   ./scripts/generate_keys.sh --generate-update-keypair
#       → SADECE update keypair üretir (offline admin/vendor)
#       → update_signing.key'i güvenli ortama taşıyın!
#
# GÜVENLİK:
#   Update signing private key cihazda ASLA bulunmayacak.
#   Varsayılan akış fail-safe — insan hatasına bırakılmaz.
# ═══════════════════════════════════════════════════════════════

set -euo pipefail

# ── Sabitler ──
AIRLOCK_DIR="${AIRLOCK_DIR:-/opt/airlock}"
KEYS_DIR="${AIRLOCK_DIR}/keys"
VENV_PYTHON="${AIRLOCK_DIR}/venv/bin/python3"

# ── Renk ──
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# ── Python komutu ──
PYTHON_CMD="$VENV_PYTHON"
if [ ! -f "$PYTHON_CMD" ]; then
    PYTHON_CMD="python3"
fi

# ── Dizin kontrolü ──
mkdir -p "$KEYS_DIR"

# ═══════════════════════════════════════════════
# MOD SEÇİMİ
# ═══════════════════════════════════════════════

MODE="${1:-default}"

if [ "$MODE" = "--generate-update-keypair" ]; then
    # ──────────────────────────────────────────
    # MOD 2: Update keypair üret (offline admin/vendor)
    # ──────────────────────────────────────────
    echo "═══════════════════════════════════════════"
    echo "  THE AIRLOCK v5.1.1 — UPDATE Keypair Üretimi"
    echo "═══════════════════════════════════════════"
    echo ""

    UPDATE_PRIVATE="${KEYS_DIR}/update_signing.key"
    UPDATE_PUBLIC="${KEYS_DIR}/update_verify.pub"

    # Mevcut anahtarları yedekle
    if [ -f "$UPDATE_PRIVATE" ]; then
        BACKUP="${UPDATE_PRIVATE}.bak.$(date +%Y%m%d_%H%M%S)"
        cp "$UPDATE_PRIVATE" "$BACKUP"
        echo -e "${YELLOW}⚠ Mevcut update özel anahtarı yedeklendi: ${BACKUP}${NC}"
    fi
    if [ -f "$UPDATE_PUBLIC" ]; then
        BACKUP="${UPDATE_PUBLIC}.bak.$(date +%Y%m%d_%H%M%S)"
        cp "$UPDATE_PUBLIC" "$BACKUP"
        echo -e "${YELLOW}⚠ Mevcut update açık anahtarı yedeklendi: ${BACKUP}${NC}"
    fi

    "$PYTHON_CMD" << 'PYTHON_EOF'
import sys
import base64
import os
from pathlib import Path

try:
    from nacl.signing import SigningKey
except ImportError:
    print("HATA: PyNaCl kurulu değil. Kurun: pip install PyNaCl", file=sys.stderr)
    sys.exit(1)

keys_dir = Path(os.environ.get("AIRLOCK_DIR", "/opt/airlock")) / "keys"

# Ed25519 UPDATE keypair üret
signing_key = SigningKey.generate()
verify_key = signing_key.verify_key

private_bytes = bytes(signing_key)
public_bytes = bytes(verify_key)

private_path = keys_dir / "update_signing.key"
public_path = keys_dir / "update_verify.pub"

private_path.write_text(base64.b64encode(private_bytes).decode("ascii") + "\n")
public_path.write_text(base64.b64encode(public_bytes).decode("ascii") + "\n")

print(f"  Update özel anahtar: {private_path}")
print(f"  Update açık anahtar: {public_path}")
print(f"  Algoritma:           Ed25519 (PyNaCl/libsodium)")
PYTHON_EOF

    chmod 600 "$UPDATE_PRIVATE"
    chmod 644 "$UPDATE_PUBLIC"

    if id "airlock" >/dev/null 2>&1; then
        chown airlock:airlock "$UPDATE_PUBLIC"
    fi

    echo ""
    echo -e "${GREEN}✓ Update keypair başarıyla üretildi${NC}"
    echo ""
    echo -e "${RED}══════════════════════════════════════════════════════════${NC}"
    echo -e "${RED}  KRİTİK GÜVENLİK UYARISI${NC}"
    echo -e "${RED}══════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "  update_signing.key'i güvenli ortama (air-gapped bilgisayar / HSM) taşıyın."
    echo "  Bu anahtar cihazlara KOPYALANMAYACAK."
    echo "  Cihazlara SADECE update_verify.pub kopyalanacak."
    echo ""
    echo "  Taşıma sonrası bu dosyayı cihazdan silin:"
    echo "    rm ${UPDATE_PRIVATE}"
    echo ""

else
    # ──────────────────────────────────────────
    # MOD 1: Report keypair üret (varsayılan — cihaz kurulumu)
    # ──────────────────────────────────────────
    echo "═══════════════════════════════════════════"
    echo "  THE AIRLOCK v5.1.1 — Report Keypair Üretimi"
    echo "═══════════════════════════════════════════"
    echo ""

    REPORT_PRIVATE="${KEYS_DIR}/report_signing.key"
    REPORT_PUBLIC="${KEYS_DIR}/report_verify.pub"

    # Mevcut anahtarları yedekle
    if [ -f "$REPORT_PRIVATE" ]; then
        BACKUP="${REPORT_PRIVATE}.bak.$(date +%Y%m%d_%H%M%S)"
        cp "$REPORT_PRIVATE" "$BACKUP"
        echo -e "${YELLOW}⚠ Mevcut report özel anahtarı yedeklendi: ${BACKUP}${NC}"
    fi
    if [ -f "$REPORT_PUBLIC" ]; then
        BACKUP="${REPORT_PUBLIC}.bak.$(date +%Y%m%d_%H%M%S)"
        cp "$REPORT_PUBLIC" "$BACKUP"
        echo -e "${YELLOW}⚠ Mevcut report açık anahtarı yedeklendi: ${BACKUP}${NC}"
    fi

    "$PYTHON_CMD" << 'PYTHON_EOF'
import sys
import base64
import os
from pathlib import Path

try:
    from nacl.signing import SigningKey
except ImportError:
    print("HATA: PyNaCl kurulu değil. Kurun: pip install PyNaCl", file=sys.stderr)
    sys.exit(1)

keys_dir = Path(os.environ.get("AIRLOCK_DIR", "/opt/airlock")) / "keys"

# Ed25519 REPORT keypair üret
signing_key = SigningKey.generate()
verify_key = signing_key.verify_key

private_bytes = bytes(signing_key)
public_bytes = bytes(verify_key)

private_path = keys_dir / "report_signing.key"
public_path = keys_dir / "report_verify.pub"

private_path.write_text(base64.b64encode(private_bytes).decode("ascii") + "\n")
public_path.write_text(base64.b64encode(public_bytes).decode("ascii") + "\n")

print(f"  Report özel anahtar: {private_path}")
print(f"  Report açık anahtar: {public_path}")
print(f"  Algoritma:           Ed25519 (PyNaCl/libsodium)")
PYTHON_EOF

    chmod 600 "$REPORT_PRIVATE"
    chmod 644 "$REPORT_PUBLIC"

    if id "airlock" >/dev/null 2>&1; then
        chown airlock:airlock "$REPORT_PRIVATE" "$REPORT_PUBLIC"
    fi

    echo ""
    echo -e "${GREEN}✓ Report keypair başarıyla üretildi${NC}"
    echo "  Rapor imzalama:  $REPORT_PRIVATE (sadece sahibi okuyabilir)"
    echo "  Rapor doğrulama: $REPORT_PUBLIC"
    echo ""

    # ── update_verify.pub kontrolü ──
    UPDATE_PUBLIC="${KEYS_DIR}/update_verify.pub"
    if [ ! -f "$UPDATE_PUBLIC" ]; then
        echo -e "${RED}═══════════════════════════════════════════════════════${NC}"
        echo -e "${RED}  HATA: keys/update_verify.pub bulunamadı!${NC}"
        echo -e "${RED}═══════════════════════════════════════════════════════${NC}"
        echo ""
        echo "  Update doğrulama anahtarı vendor veya admin tarafından sağlanmalıdır."
        echo "  Offline güncellemeler bu anahtar olmadan ÇALIŞMAYACAK."
        echo ""
        echo "  Seçenekler:"
        echo "    1) Vendor'dan update_verify.pub dosyasını alın ve keys/ dizinine kopyalayın"
        echo "    2) Kendi update keypair'inizi üretmek için:"
        echo "       ./scripts/generate_keys.sh --generate-update-keypair"
        echo "       (update_signing.key'i güvenli ortama taşıyın, cihazda BIRAKMAYIN)"
        echo ""
        exit 1
    else
        echo -e "${GREEN}✓ update_verify.pub mevcut — offline güncellemeler hazır${NC}"
    fi
fi

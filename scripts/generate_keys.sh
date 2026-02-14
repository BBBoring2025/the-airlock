#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
# THE AIRLOCK v5.0.8 FORTRESS — Ed25519 Anahtar Çifti Üretimi
#
# Üretilen anahtarlar:
#   - keys/report_signing.key   — Rapor imzalama özel anahtarı
#   - keys/update_verify.pub    — Güncelleme doğrulama açık anahtarı
#
# Anahtarlar PyNaCl (Ed25519) formatındadır (Base64 encoded).
#
# Kullanım:
#   chmod +x scripts/generate_keys.sh
#   ./scripts/generate_keys.sh
#   # veya
#   sudo -u airlock ./scripts/generate_keys.sh
#
# Güvenlik:
#   - Özel anahtar sadece sahibi tarafından okunabilir (0600)
#   - Açık anahtar herkes tarafından okunabilir (0644)
#   - Mevcut anahtarlar üzerine yazılMAZ (yedek alınır)
# ═══════════════════════════════════════════════════════════════

set -euo pipefail

# ── Sabitler ──
AIRLOCK_DIR="${AIRLOCK_DIR:-/opt/airlock}"
KEYS_DIR="${AIRLOCK_DIR}/keys"
VENV_PYTHON="${AIRLOCK_DIR}/venv/bin/python3"

PRIVATE_KEY="${KEYS_DIR}/report_signing.key"
PUBLIC_KEY="${KEYS_DIR}/update_verify.pub"

# ── Renk ──
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo "═══════════════════════════════════════════"
echo "  THE AIRLOCK v5.0.8 — Anahtar Üretimi"
echo "═══════════════════════════════════════════"

# ── Dizin kontrolü ──
mkdir -p "$KEYS_DIR"

# ── Mevcut anahtarları yedekle ──
if [ -f "$PRIVATE_KEY" ]; then
    BACKUP="${PRIVATE_KEY}.bak.$(date +%Y%m%d_%H%M%S)"
    cp "$PRIVATE_KEY" "$BACKUP"
    echo -e "${YELLOW}⚠ Mevcut özel anahtar yedeklendi: ${BACKUP}${NC}"
fi

if [ -f "$PUBLIC_KEY" ]; then
    BACKUP="${PUBLIC_KEY}.bak.$(date +%Y%m%d_%H%M%S)"
    cp "$PUBLIC_KEY" "$BACKUP"
    echo -e "${YELLOW}⚠ Mevcut açık anahtar yedeklendi: ${BACKUP}${NC}"
fi

# ── Python ile anahtar üret ──
PYTHON_CMD="$VENV_PYTHON"
if [ ! -f "$PYTHON_CMD" ]; then
    PYTHON_CMD="python3"
fi

"$PYTHON_CMD" << 'PYTHON_EOF'
import sys
import base64
from pathlib import Path

try:
    from nacl.signing import SigningKey
except ImportError:
    print("HATA: PyNaCl kurulu değil. Kurun: pip install PyNaCl", file=sys.stderr)
    sys.exit(1)

import os
keys_dir = Path(os.environ.get("AIRLOCK_DIR", "/opt/airlock")) / "keys"

# Ed25519 anahtar çifti üret
signing_key = SigningKey.generate()
verify_key = signing_key.verify_key

private_bytes = bytes(signing_key)
public_bytes = bytes(verify_key)

# Dosyalara yaz (Base64)
private_path = keys_dir / "report_signing.key"
public_path = keys_dir / "update_verify.pub"

private_path.write_text(base64.b64encode(private_bytes).decode("ascii") + "\n")
public_path.write_text(base64.b64encode(public_bytes).decode("ascii") + "\n")

print(f"  Özel anahtar: {private_path}")
print(f"  Açık anahtar: {public_path}")
print(f"  Algoritma:    Ed25519 (PyNaCl/libsodium)")
print(f"  Özel boyut:   {len(private_bytes)} byte")
print(f"  Açık boyut:   {len(public_bytes)} byte")
PYTHON_EOF

# ── İzinleri ayarla ──
chmod 600 "$PRIVATE_KEY"
chmod 644 "$PUBLIC_KEY"

# airlock kullanıcısı varsa sahipliği ver
if id "airlock" >/dev/null 2>&1; then
    chown airlock:airlock "$PRIVATE_KEY" "$PUBLIC_KEY"
fi

echo ""
echo -e "${GREEN}✓ Ed25519 anahtar çifti başarıyla üretildi${NC}"
echo ""
echo "  Rapor imzalama:       $PRIVATE_KEY (sadece sahibi okuyabilir)"
echo "  Güncelleme doğrulama: $PUBLIC_KEY"
echo ""
echo "  ÖNEMLİ: Özel anahtarı güvenli saklayın!"
echo "  UPDATE USB imzalamak için özel anahtarın bir kopyasını"
echo "  güvenli bir ortamda (ör: air-gapped bilgisayar) tutun."
echo ""

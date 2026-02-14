#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# THE AIRLOCK v5.0.8 — GitHub Release Script
# Bu dosyayı çalıştırma, adımları tek tek Terminal'e yapıştır!
# ═══════════════════════════════════════════════════════════════

# ─── ADIM 1: GitHub'da repo oluştur ───
# https://github.com/new adresine git
# Repo adı: the-airlock
# Description: Air-gapped USB sanitization station for Raspberry Pi
# Public seç
# README/LICENSE/gitignore EKLEME (zaten var)
# "Create repository" tıkla

# ─── ADIM 2: Yerel Git repo başlat ───
cd ~/Desktop/"the airlockV5.01"
git init
git add .
git commit -m "THE AIRLOCK v5.0.8 — Fortress-Hardened Final Release

7-layer security architecture:
- BadUSB HID/CDC deauth protection
- Filesystem-aware mount hardening (FAT/NTFS umask)
- File validation + policy engine
- ClamAV + YARA scanning
- Content Disarm & Reconstruction (CDR)
- Ed25519 signed audit reports
- Offline signed updates with integrity validation

136 tests, 0 failures, 0 warnings.
Privilege separation: capability-less daemon + hardened helper.
systemd hardening: NoNewPrivileges, ProtectSystem=strict, UMask=0077."

# ─── ADIM 3: GitHub remote ekle ───
# KULLANICI_ADIN yerine kendi GitHub kullanıcı adını yaz!
git remote add origin https://github.com/KULLANICI_ADIN/the-airlock.git
git branch -M main
git push -u origin main

# ─── ADIM 4: Release tag oluştur ve push et ───
git tag -a v5.0.8 -m "v5.0.8 Final Release — Fortress-Hardened"
git push origin v5.0.8

# ─── ADIM 5: SHA256 checksum oluştur ───
cd ~/Desktop
cp "the-airlock-v5.0.8-final.zip" .  # zip'in burada olduğundan emin ol
shasum -a 256 "the-airlock-v5.0.8-final.zip" > SHA256SUMS.txt
cat SHA256SUMS.txt

# ─── ADIM 6: GitHub Release sayfası ───
# https://github.com/KULLANICI_ADIN/the-airlock/releases/new adresine git
# Tag: v5.0.8 seç
# Title: v5.0.8 — Final Release (Fortress-Hardened)
# Description: RELEASE_NOTES.md içeriğini yapıştır
# Assets olarak şunları sürükle:
#   - the-airlock-v5.0.8-final.zip
#   - SHA256SUMS.txt
# "Publish release" tıkla

echo "✅ GitHub Release tamamlandı!"

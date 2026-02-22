"""
THE AIRLOCK v5.1.1 FORTRESS-HARDENED — Kriptografik Yardımcılar

Özellikler:
  - Ed25519 anahtar çifti üretimi
  - Ed25519 ile veri imzalama
  - Ed25519 imza doğrulama
  - SHA-256 dosya hash hesaplama
  - SHA-256 byte hash hesaplama

Kütüphane: PyNaCl (libsodium binding)
  - nacl.signing.SigningKey   → özel anahtar (imzalama)
  - nacl.signing.VerifyKey    → açık anahtar (doğrulama)

Kullanım:
    from app.utils.crypto import (
        generate_keypair,
        sign_data,
        verify_signature,
        sha256_file,
        sha256_bytes,
    )

    # Anahtar üret
    private_key, public_key = generate_keypair()

    # İmzala
    signature = sign_data(data, private_key_path)

    # Doğrula
    is_valid = verify_signature(data, signature, public_key_path)

    # Hash
    digest = sha256_file(filepath)
"""

from __future__ import annotations

import base64
import hashlib
import logging
from pathlib import Path
from typing import Optional, Tuple

logger = logging.getLogger("AIRLOCK.CRYPTO")


# ─────────────────────────────────────────────
# SHA-256
# ─────────────────────────────────────────────


def sha256_file(filepath: Path) -> str:
    """
    Dosyanın SHA-256 hash'ini hesapla.

    Büyük dosyalar için 64KB bloklar halinde okur.

    Args:
        filepath: Hash'lenecek dosya

    Returns:
        Hex-encoded SHA-256 hash (64 karakter)
        Hata durumunda boş string
    """
    sha = hashlib.sha256()
    try:
        with filepath.open("rb") as fh:
            while True:
                chunk = fh.read(65536)
                if not chunk:
                    break
                sha.update(chunk)
    except (OSError, PermissionError) as exc:
        logger.error("SHA-256 hesaplama hatası (%s): %s", filepath, exc)
        return ""
    return sha.hexdigest()


def sha256_bytes(data: bytes) -> str:
    """
    Byte dizisinin SHA-256 hash'ini hesapla.

    Args:
        data: Hash'lenecek veri

    Returns:
        Hex-encoded SHA-256 hash
    """
    return hashlib.sha256(data).hexdigest()


# ─────────────────────────────────────────────
# Ed25519 Anahtar Üretimi
# ─────────────────────────────────────────────


def generate_keypair(
    private_key_path: Optional[Path] = None,
    public_key_path: Optional[Path] = None,
) -> Tuple[bytes, bytes]:
    """
    Yeni Ed25519 anahtar çifti üret.

    Yollar verilmişse dosyalara yazar (Base64 encoded).

    Args:
        private_key_path: Özel anahtar dosya yolu (opsiyonel)
        public_key_path: Açık anahtar dosya yolu (opsiyonel)

    Returns:
        (private_key_bytes, public_key_bytes) tuple

    Raises:
        ImportError: PyNaCl yüklü değilse
    """
    from nacl.signing import SigningKey  # noqa: PLC0415

    signing_key = SigningKey.generate()
    verify_key = signing_key.verify_key

    private_bytes = bytes(signing_key)
    public_bytes = bytes(verify_key)

    # Dosyalara yaz (Base64)
    if private_key_path is not None:
        private_key_path.parent.mkdir(parents=True, exist_ok=True)
        private_key_path.write_text(
            base64.b64encode(private_bytes).decode("ascii") + "\n",
            encoding="ascii",
        )
        # Sadece sahibi okuyabilsin
        private_key_path.chmod(0o600)
        logger.info("Ed25519 özel anahtar üretildi: %s", private_key_path)

    if public_key_path is not None:
        public_key_path.parent.mkdir(parents=True, exist_ok=True)
        public_key_path.write_text(
            base64.b64encode(public_bytes).decode("ascii") + "\n",
            encoding="ascii",
        )
        logger.info("Ed25519 açık anahtar üretildi: %s", public_key_path)

    return private_bytes, public_bytes


# ─────────────────────────────────────────────
# Ed25519 İmzalama
# ─────────────────────────────────────────────


def sign_data(data: bytes, private_key_path: Path) -> str:
    """
    Veriyi Ed25519 özel anahtarla imzala.

    Args:
        data: İmzalanacak veri (bytes)
        private_key_path: Özel anahtar dosyası (Base64 encoded)

    Returns:
        Base64-encoded imza string

    Raises:
        FileNotFoundError: Anahtar dosyası bulunamadıysa
        ValueError: Anahtar formatı geçersizse
        ImportError: PyNaCl yüklü değilse
    """
    from nacl.signing import SigningKey  # noqa: PLC0415

    key_b64 = private_key_path.read_text(encoding="ascii").strip()
    key_bytes = base64.b64decode(key_b64)
    signing_key = SigningKey(key_bytes)

    signed = signing_key.sign(data)
    signature = signed.signature  # Sadece imza (64 byte)

    return base64.b64encode(signature).decode("ascii")


def sign_file(filepath: Path, private_key_path: Path) -> str:
    """
    Dosyanın içeriğini Ed25519 ile imzala.

    Args:
        filepath: İmzalanacak dosya
        private_key_path: Özel anahtar dosyası

    Returns:
        Base64-encoded imza string
    """
    data = filepath.read_bytes()
    return sign_data(data, private_key_path)


# ─────────────────────────────────────────────
# Ed25519 Doğrulama
# ─────────────────────────────────────────────


def verify_signature(
    data: bytes,
    signature_b64: str,
    public_key_path: Path,
) -> bool:
    """
    Ed25519 imzasını açık anahtarla doğrula.

    Args:
        data: Orijinal veri (bytes)
        signature_b64: Base64-encoded imza
        public_key_path: Açık anahtar dosyası (Base64 encoded)

    Returns:
        True: imza geçerli
        False: imza geçersiz veya hata
    """
    try:
        from nacl.signing import VerifyKey  # noqa: PLC0415
        from nacl.exceptions import BadSignatureError  # noqa: PLC0415
    except ImportError:
        logger.error("PyNaCl yüklü değil — imza doğrulama yapılamıyor")
        return False

    try:
        key_b64 = public_key_path.read_text(encoding="ascii").strip()
        key_bytes = base64.b64decode(key_b64)
        verify_key = VerifyKey(key_bytes)

        signature_bytes = base64.b64decode(signature_b64)
        verify_key.verify(data, signature_bytes)

        return True

    except BadSignatureError:
        logger.warning("Ed25519 imza doğrulama BAŞARISIZ — imza geçersiz")
        return False
    except FileNotFoundError:
        logger.error("Açık anahtar dosyası bulunamadı: %s", public_key_path)
        return False
    except (ValueError, Exception) as exc:
        logger.error("İmza doğrulama hatası: %s", exc)
        return False


def verify_file_signature(
    filepath: Path,
    signature_b64: str,
    public_key_path: Path,
) -> bool:
    """
    Dosyanın Ed25519 imzasını doğrula.

    Args:
        filepath: Doğrulanacak dosya
        signature_b64: Base64-encoded imza
        public_key_path: Açık anahtar dosyası

    Returns:
        True: geçerli
        False: geçersiz
    """
    try:
        data = filepath.read_bytes()
    except OSError as exc:
        logger.error("Dosya okunamadı (%s): %s", filepath, exc)
        return False

    return verify_signature(data, signature_b64, public_key_path)


# ─────────────────────────────────────────────
# Yardımcılar
# ─────────────────────────────────────────────


def load_public_key(public_key_path: Path) -> Optional[bytes]:
    """
    Açık anahtarı dosyadan yükle.

    Args:
        public_key_path: Base64-encoded açık anahtar dosyası

    Returns:
        Anahtar byte'ları veya None (hata durumunda)
    """
    try:
        key_b64 = public_key_path.read_text(encoding="ascii").strip()
        return base64.b64decode(key_b64)
    except (FileNotFoundError, ValueError, OSError) as exc:
        logger.error("Açık anahtar yüklenemedi (%s): %s", public_key_path, exc)
        return None


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """
    Timing-safe byte karşılaştırma.

    Side-channel saldırılarına karşı sabit zamanlı karşılaştırma.
    """
    import hmac  # noqa: PLC0415
    return hmac.compare_digest(a, b)

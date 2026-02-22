"""
THE AIRLOCK v5.1.1 FORTRESS-HARDENED — Offline Updater Integrity Tests

Test edilenler:
  1. Symlink tespiti → UPDATE reddedilmeli
  2. Path traversal (..) → UPDATE reddedilmeli
  3. Mutlak yol → UPDATE reddedilmeli
  4. update_root dışına çıkan yol → UPDATE reddedilmeli
  5. Temiz güncelleme → kabul edilmeli

Kullanım:
    python -m pytest tests/test_offline_updater_integrity.py -v
    python -m unittest tests.test_offline_updater_integrity -v
"""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from app.updater.offline_updater import OfflineUpdater
from app.config import AirlockConfig


class TestUpdateIntegrityValidation(unittest.TestCase):
    """_validate_update_integrity() güvenlik kontrolü testleri."""

    def setUp(self) -> None:
        """Test ortamı: geçici dizin + UPDATE/ klasörü."""
        self.tmpdir = tempfile.mkdtemp(prefix="airlock_test_")
        self.update_root = Path(self.tmpdir) / "UPDATE"
        self.update_root.mkdir()

        # İmza gerektirmeyen config ile OfflineUpdater oluştur
        cfg = AirlockConfig(require_update_signature=False)
        self.updater = OfflineUpdater(config=cfg)

    def tearDown(self) -> None:
        """Geçici dizini temizle."""
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _create_manifest(self, files: dict[str, str]) -> dict:
        """Test manifest oluştur ve diske yaz."""
        manifest: dict = {"version": "test", "files": files}
        manifest_path = self.update_root / "manifest.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        return manifest

    # ── Symlink Tespiti ──

    def test_symlink_in_update_dir_rejected(self) -> None:
        """Güncelleme dizininde dosya symlink varsa ValueError fırlatılmalı."""
        # Gerçek dosya — update dizini DIŞINDA
        real_file = Path(self.tmpdir) / "outside.txt"
        real_file.write_text("payload")

        # UPDATE dizini İÇİNE symlink oluştur
        link_path = self.update_root / "evil_link.txt"
        link_path.symlink_to(real_file)

        manifest = self._create_manifest({})

        with self.assertRaises(ValueError) as ctx:
            self.updater._validate_update_integrity(self.update_root, manifest)
        self.assertIn("symlink", str(ctx.exception).lower())

    def test_symlink_directory_in_update_dir_rejected(self) -> None:
        """Güncelleme dizininde symlink dizin varsa ValueError fırlatılmalı."""
        # Gerçek dizin — update dizini DIŞINDA
        real_dir = Path(self.tmpdir) / "outside_dir"
        real_dir.mkdir()
        (real_dir / "payload.txt").write_text("data")

        # UPDATE dizini İÇİNE dizin symlink oluştur
        link_dir = self.update_root / "evil_dir"
        link_dir.symlink_to(real_dir)

        manifest = self._create_manifest({})

        with self.assertRaises(ValueError) as ctx:
            self.updater._validate_update_integrity(self.update_root, manifest)
        self.assertIn("symlink", str(ctx.exception).lower())

    # ── Path Traversal Tespiti ──

    def test_dotdot_path_in_manifest_rejected(self) -> None:
        """Manifest içinde '..' path segmenti varsa ValueError fırlatılmalı."""
        manifest = self._create_manifest({"../etc/passwd": "abcdef1234567890"})

        with self.assertRaises(ValueError) as ctx:
            self.updater._validate_update_integrity(self.update_root, manifest)
        self.assertIn("traversal", str(ctx.exception).lower())

    def test_absolute_path_in_manifest_rejected(self) -> None:
        """Manifest içinde mutlak yol varsa ValueError fırlatılmalı."""
        manifest = self._create_manifest({"/etc/passwd": "abcdef1234567890"})

        with self.assertRaises(ValueError) as ctx:
            self.updater._validate_update_integrity(self.update_root, manifest)
        self.assertIn("absolute", str(ctx.exception).lower())

    def test_path_escaping_update_root_rejected(self) -> None:
        """Sub dizinde escape symlink varsa ValueError fırlatılmalı."""
        # Sub dizin oluştur ve içine escape symlink koy
        sub = self.update_root / "sub"
        sub.mkdir()
        (sub / "file.txt").write_text("ok")

        # Sub altında üst dizine symlink
        escape_link = sub / "escape"
        escape_link.symlink_to(Path(self.tmpdir))

        manifest = self._create_manifest({})

        with self.assertRaises(ValueError) as ctx:
            self.updater._validate_update_integrity(self.update_root, manifest)
        self.assertIn("symlink", str(ctx.exception).lower())

    # ── Temiz Güncelleme ──

    def test_clean_update_accepted(self) -> None:
        """Temiz güncelleme dizini doğrulamadan geçmeli."""
        # Normal dosyalar oluştur
        yara_dir = self.update_root / "yara"
        yara_dir.mkdir()
        yara_file = yara_dir / "test.yar"
        yara_file.write_text("rule test { condition: false }")

        manifest = self._create_manifest({
            "yara/test.yar": "dummy_hash_for_test"
        })

        # ValueError fırlatılmamalı
        self.updater._validate_update_integrity(self.update_root, manifest)

    def test_empty_manifest_accepted(self) -> None:
        """Boş manifest ile temiz dizin geçmeli."""
        manifest = self._create_manifest({})
        # ValueError fırlatılmamalı
        self.updater._validate_update_integrity(self.update_root, manifest)


# ═══════════════════════════════════════════════
# Ed25519 Manifest İmza Doğrulama Testleri
# ═══════════════════════════════════════════════

try:
    from nacl.signing import SigningKey  # noqa: PLC0415
    HAS_NACL = True
except ImportError:
    HAS_NACL = False


@unittest.skipUnless(HAS_NACL, "PyNaCl required for signature tests")
class TestManifestSignatureVerification(unittest.TestCase):
    """Ed25519 manifest imza doğrulama testleri.

    Gerçek Ed25519 keypair üretir (PyNaCl) — harici dosya gerektirmez.
    """

    def setUp(self) -> None:
        """Test ortamı: geçici dizin + UPDATE/ + Ed25519 keypair."""
        import base64
        from nacl.signing import SigningKey as _SK

        self.tmpdir = tempfile.mkdtemp(prefix="airlock_sig_test_")
        self.usb_root = Path(self.tmpdir) / "usb"
        self.usb_root.mkdir()
        self.update_dir = self.usb_root / "UPDATE"
        self.update_dir.mkdir()

        # Anahtar dizini
        self.keys_dir = Path(self.tmpdir) / "keys"
        self.keys_dir.mkdir()

        # Ed25519 keypair üret
        self.signing_key = _SK.generate()
        self.verify_key = self.signing_key.verify_key

        # Public key dosyasına yaz (Base64)
        self.pub_key_path = self.keys_dir / "update_verify.pub"
        self.pub_key_path.write_text(
            base64.b64encode(bytes(self.verify_key)).decode("ascii") + "\n",
            encoding="ascii",
        )

    def tearDown(self) -> None:
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _create_signed_manifest(
        self, manifest_data: dict, signing_key: object | None = None
    ) -> str:
        """Manifest oluştur ve Ed25519 ile imzala."""
        import base64

        sk = signing_key or self.signing_key
        manifest_text = json.dumps(manifest_data)
        manifest_bytes = manifest_text.encode("utf-8")

        # manifest.json yaz
        manifest_path = self.update_dir / "manifest.json"
        manifest_path.write_text(manifest_text, encoding="utf-8")

        # İmzala
        signed = sk.sign(manifest_bytes)
        sig_b64 = base64.b64encode(signed.signature).decode("ascii")

        # manifest.json.sig yaz
        sig_path = self.update_dir / "manifest.json.sig"
        sig_path.write_text(sig_b64, encoding="ascii")

        return manifest_text

    def _make_updater(self, require_sig: bool = True) -> OfflineUpdater:
        """Test config ile OfflineUpdater oluştur."""
        cfg = AirlockConfig(
            require_update_signature=require_sig,
            update_public_key_path=self.pub_key_path,
        )
        return OfflineUpdater(config=cfg)

    def test_valid_signature_accepted(self) -> None:
        """Geçerli Ed25519 imza → is_valid=True."""
        # Manifest + bir bileşen oluştur
        clamav_dir = self.update_dir / "clamav"
        clamav_dir.mkdir()
        # ClamAV dosyası oluştur (boyut limitleri dahilinde)
        cvd_file = clamav_dir / "daily.cvd"
        cvd_file.write_bytes(b"\x00" * (200 * 1024))  # 200 KB

        self._create_signed_manifest({
            "version": "test",
            "files": {},
        })

        updater = self._make_updater(require_sig=True)
        result = updater.verify_update_package(self.usb_root)

        self.assertTrue(result.is_valid)

    def test_invalid_signature_rejected(self) -> None:
        """Farklı anahtar ile imzalanmış → is_valid=False."""
        from nacl.signing import SigningKey as _SK

        # Farklı bir anahtarla imzala
        wrong_key = _SK.generate()
        self._create_signed_manifest(
            {"version": "test", "files": {}},
            signing_key=wrong_key,
        )

        # Bir bileşen oluştur
        clamav_dir = self.update_dir / "clamav"
        clamav_dir.mkdir()
        (clamav_dir / "daily.cvd").write_bytes(b"\x00" * (200 * 1024))

        updater = self._make_updater(require_sig=True)
        result = updater.verify_update_package(self.usb_root)

        self.assertFalse(result.is_valid)
        self.assertIsNotNone(result.rejection_reason)
        # İmza doğrulama başarısız mesajı olmalı
        reason_lower = result.rejection_reason.lower()
        self.assertTrue(
            "imza" in reason_lower or "signature" in reason_lower
            or "başarısız" in reason_lower
        )

    def test_missing_signature_rejected(self) -> None:
        """İmza dosyası yok + require_update_signature=True → is_valid=False."""
        # manifest.json yaz AMA .sig yok
        manifest_data = {"version": "test", "files": {}}
        manifest_path = self.update_dir / "manifest.json"
        manifest_path.write_text(json.dumps(manifest_data), encoding="utf-8")

        # Bileşen oluştur
        clamav_dir = self.update_dir / "clamav"
        clamav_dir.mkdir()
        (clamav_dir / "daily.cvd").write_bytes(b"\x00" * (200 * 1024))

        updater = self._make_updater(require_sig=True)
        result = updater.verify_update_package(self.usb_root)

        self.assertFalse(result.is_valid)
        self.assertIn("sig", result.rejection_reason.lower())

    def test_tampered_manifest_rejected(self) -> None:
        """İmza geçerli ama manifest sonradan değiştirilmiş → is_valid=False."""
        # Orijinal manifest'i imzala
        self._create_signed_manifest({
            "version": "original",
            "files": {},
        })

        # Manifest'i değiştir (imza eski kalacak)
        manifest_path = self.update_dir / "manifest.json"
        manifest_path.write_text(
            json.dumps({"version": "TAMPERED", "files": {}}),
            encoding="utf-8",
        )

        # Bileşen oluştur
        clamav_dir = self.update_dir / "clamav"
        clamav_dir.mkdir()
        (clamav_dir / "daily.cvd").write_bytes(b"\x00" * (200 * 1024))

        updater = self._make_updater(require_sig=True)
        result = updater.verify_update_package(self.usb_root)

        self.assertFalse(result.is_valid)


if __name__ == "__main__":
    unittest.main()

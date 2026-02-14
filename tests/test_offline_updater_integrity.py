"""
THE AIRLOCK v5.0.8 FORTRESS-HARDENED — Offline Updater Integrity Tests

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


if __name__ == "__main__":
    unittest.main()

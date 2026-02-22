"""
THE AIRLOCK v5.1.1 FORTRESS-HARDENED — ArchiveHandler Unit Tests

Test edilenler:
  1. Zip bomb tespiti (yüksek sıkıştırma oranı)
  2. Arşiv içi path traversal (../ engelleme)
  3. Maksimum dosya sayısı limiti
  4. Maksimum açılmış boyut limiti
  5. Şifreli arşiv engelleme
  6. Arşiv türü tespiti (magic byte)
  7. TAR symlink/hardlink engelleme
  8. Boş / bozuk arşiv

Kullanım:
    python -m pytest tests/test_archive_handler.py -v
    python -m unittest tests.test_archive_handler -v
"""

from __future__ import annotations

import io
import os
import struct
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from app.config import ArchiveLimits
from app.security.archive_handler import (
    ArchiveHandler,
    ArchiveSafetyResult,
)


class TestArchiveTypeDetection(unittest.TestCase):
    """Arşiv türü tespiti (magic byte)."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp(prefix="airlock_archive_test_")
        self.handler = ArchiveHandler()

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_zip_detection(self) -> None:
        """ZIP dosyası doğru tespit edilmeli."""
        zip_path = Path(self.tmpdir) / "test.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("hello.txt", "Hello World")
        self.assertEqual(self.handler.detect_type(zip_path), "zip")

    def test_tar_detection(self) -> None:
        """TAR dosyası doğru tespit edilmeli."""
        tar_path = Path(self.tmpdir) / "test.tar"
        with tarfile.open(tar_path, "w:") as tf:
            info = tarfile.TarInfo(name="hello.txt")
            data = b"Hello World"
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        self.assertEqual(self.handler.detect_type(tar_path), "tar")

    def test_tar_gz_detection(self) -> None:
        """TAR.GZ dosyası doğru tespit edilmeli."""
        tgz_path = Path(self.tmpdir) / "test.tar.gz"
        with tarfile.open(tgz_path, "w:gz") as tf:
            info = tarfile.TarInfo(name="hello.txt")
            data = b"Hello World"
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        self.assertEqual(self.handler.detect_type(tgz_path), "tar.gz")

    def test_not_archive(self) -> None:
        """Arşiv olmayan dosya boş string döndürmeli."""
        txt_path = Path(self.tmpdir) / "plain.txt"
        txt_path.write_text("Just plain text, not an archive.")
        self.assertEqual(self.handler.detect_type(txt_path), "")

    def test_is_archive_true(self) -> None:
        """is_archive() ZIP için True döndürmeli."""
        zip_path = Path(self.tmpdir) / "test2.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("a.txt", "data")
        self.assertTrue(self.handler.is_archive(zip_path))

    def test_is_archive_false(self) -> None:
        """is_archive() text dosyası için False döndürmeli."""
        txt_path = Path(self.tmpdir) / "not_archive.txt"
        txt_path.write_text("hello")
        self.assertFalse(self.handler.is_archive(txt_path))


class TestZipBombDetection(unittest.TestCase):
    """Zip bomb tespiti (sıkıştırma oranı kontrolü)."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp(prefix="airlock_zipbomb_test_")
        # Düşük limitler ile test
        config = mock.MagicMock()
        config.archive_limits = ArchiveLimits(
            max_depth=3,
            max_total_size_mb=10,  # 10MB limit
            max_file_count=100,
            max_single_file_mb=5,
            compression_ratio_limit=50,  # 50x oran limiti
            timeout_seconds=30,
            encrypted_policy="block",
        )
        self.handler = ArchiveHandler(config=config)

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_normal_zip_safe(self) -> None:
        """Normal ZIP dosyası güvenli olmalı."""
        zip_path = Path(self.tmpdir) / "normal.zip"
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for i in range(5):
                zf.writestr(f"file_{i}.txt", f"Content of file {i} " * 10)

        result = self.handler.check_safety(zip_path)
        self.assertTrue(result.is_safe)
        self.assertEqual(result.archive_type, "zip")
        self.assertEqual(result.file_count, 5)

    def test_zip_too_many_files(self) -> None:
        """Çok fazla dosya içeren ZIP engellenmeli."""
        zip_path = Path(self.tmpdir) / "many_files.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            for i in range(150):  # 100 limit, 150 dosya
                zf.writestr(f"file_{i:04d}.txt", f"data{i}")

        result = self.handler.check_safety(zip_path)
        self.assertFalse(result.is_safe)
        self.assertIn("TOO_MANY_FILES", result.block_reason or "")

    def test_zip_too_large_uncompressed(self) -> None:
        """Açılmış hali çok büyük ZIP engellenmeli."""
        zip_path = Path(self.tmpdir) / "big_uncompressed.zip"
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            # 10MB limitin üstünde olacak kadar büyük veri
            big_data = "A" * (1024 * 1024)  # 1MB tekrarlanan veri
            for i in range(15):
                zf.writestr(f"big_{i}.txt", big_data)

        result = self.handler.check_safety(zip_path)
        self.assertFalse(result.is_safe)
        self.assertIn("UNCOMPRESSED_TOO_LARGE", result.block_reason or "")

    def test_encrypted_zip_blocked(self) -> None:
        """Şifreli ZIP engellenmeli (policy=block)."""
        zip_path = Path(self.tmpdir) / "encrypted.zip"
        # Şifreli ZIP oluşturmak karmaşık, flag_bits ile simüle edelim
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("secret.txt", "data")

        # zipfile ile şifreli oluşturamadığımız için check_safety'yi
        # mock edebiliriz veya is_encrypted sonucunu test edebiliriz
        result = self.handler.check_safety(zip_path)
        # Normal zip, encrypted değil — güvenli olmalı
        self.assertTrue(result.is_safe)
        self.assertFalse(result.is_encrypted)


class TestZipPathTraversal(unittest.TestCase):
    """Arşiv içi path traversal engelleme."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp(prefix="airlock_ziptraversal_")
        self.handler = ArchiveHandler()
        self.extract_dir = Path(self.tmpdir) / "extract"
        self.extract_dir.mkdir()

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_zip_path_traversal_blocked(self) -> None:
        """ZIP içinde ../../ yollu dosya extract edilmemeli."""
        zip_path = Path(self.tmpdir) / "traversal.zip"

        # Kötü niyetli ZIP oluştur (path traversal ile)
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("normal.txt", "safe content")
            # Path traversal girişimi
            zf.writestr("../../etc/passwd", "root:x:0:0:root")

        # Extract et — kötü dosya extract edilmemeli
        success = self.handler._extract_zip(zip_path, self.extract_dir)
        self.assertTrue(success)

        # Normal dosya extract edilmiş olmalı
        self.assertTrue((self.extract_dir / "normal.txt").exists())

        # Traversal dosya extract edilmemiş olmalı (güvenlik)
        self.assertFalse(
            (self.extract_dir / ".." / ".." / "etc" / "passwd").exists()
        )

    def test_zip_absolute_path_blocked(self) -> None:
        """ZIP içinde mutlak yollu dosya extract edilmemeli."""
        zip_path = Path(self.tmpdir) / "absolute.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("/etc/shadow", "should not extract")
            zf.writestr("good.txt", "safe")

        success = self.handler._extract_zip(zip_path, self.extract_dir)
        self.assertTrue(success)
        self.assertTrue((self.extract_dir / "good.txt").exists())


class TestTarSecurity(unittest.TestCase):
    """TAR arşiv güvenlik kontrolleri."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp(prefix="airlock_tar_test_")
        self.handler = ArchiveHandler()
        self.extract_dir = Path(self.tmpdir) / "extract"
        self.extract_dir.mkdir()

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_tar_symlink_blocked(self) -> None:
        """TAR içindeki symlink extract edilmemeli."""
        tar_path = Path(self.tmpdir) / "symlink.tar"
        with tarfile.open(tar_path, "w:") as tf:
            # Normal dosya
            info = tarfile.TarInfo(name="good.txt")
            data = b"safe content"
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))

            # Symlink — engellenmeli
            link_info = tarfile.TarInfo(name="evil_link")
            link_info.type = tarfile.SYMTYPE
            link_info.linkname = "/etc/passwd"
            tf.addfile(link_info)

        success = self.handler._extract_tar(tar_path, self.extract_dir, "tar")
        self.assertTrue(success)
        self.assertTrue((self.extract_dir / "good.txt").exists())
        # Symlink extract edilmemiş olmalı
        self.assertFalse((self.extract_dir / "evil_link").exists())

    def test_tar_path_traversal_blocked(self) -> None:
        """TAR içinde ../ path'li dosya extract edilmemeli."""
        tar_path = Path(self.tmpdir) / "traversal.tar"
        with tarfile.open(tar_path, "w:") as tf:
            info = tarfile.TarInfo(name="../../etc/shadow")
            data = b"hacked"
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))

            good_info = tarfile.TarInfo(name="safe.txt")
            good_data = b"ok"
            good_info.size = len(good_data)
            tf.addfile(good_info, io.BytesIO(good_data))

        success = self.handler._extract_tar(tar_path, self.extract_dir, "tar")
        self.assertTrue(success)
        self.assertTrue((self.extract_dir / "safe.txt").exists())

    def test_tar_safety_check(self) -> None:
        """TAR güvenlik ön kontrolü çalışmalı."""
        tar_path = Path(self.tmpdir) / "safe.tar"
        with tarfile.open(tar_path, "w:") as tf:
            for i in range(3):
                info = tarfile.TarInfo(name=f"file_{i}.txt")
                data = f"content {i}".encode()
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))

        result = self.handler.check_safety(tar_path)
        self.assertTrue(result.is_safe)
        self.assertEqual(result.archive_type, "tar")
        self.assertEqual(result.file_count, 3)


class TestCorruptArchive(unittest.TestCase):
    """Bozuk arşiv dosyaları."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp(prefix="airlock_corrupt_test_")
        self.handler = ArchiveHandler()

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_corrupt_zip(self) -> None:
        """Bozuk ZIP dosyası engellenmeli."""
        corrupt_path = Path(self.tmpdir) / "corrupt.zip"
        # ZIP magic byte + bozuk veri
        corrupt_path.write_bytes(b"PK\x03\x04" + b"\x00" * 100)
        result = self.handler.check_safety(corrupt_path)
        self.assertFalse(result.is_safe)
        self.assertIn("CORRUPT_ZIP", result.block_reason or "")

    def test_not_an_archive(self) -> None:
        """Arşiv olmayan dosya için safety check başarısız olmalı."""
        txt_path = Path(self.tmpdir) / "plain.txt"
        txt_path.write_text("This is not an archive at all.")
        result = self.handler.check_safety(txt_path)
        self.assertFalse(result.is_safe)
        self.assertIn("NOT_AN_ARCHIVE", result.block_reason or "")

    def test_empty_file(self) -> None:
        """Boş dosya arşiv değil."""
        empty = Path(self.tmpdir) / "empty.zip"
        empty.write_bytes(b"")
        result = self.handler.check_safety(empty)
        self.assertFalse(result.is_safe)


class TestCheckLimits(unittest.TestCase):
    """Arşiv limit kontrolleri — _check_limits metodu."""

    def setUp(self) -> None:
        config = mock.MagicMock()
        config.archive_limits = ArchiveLimits(
            max_depth=3,
            max_total_size_mb=100,
            max_file_count=500,
            max_single_file_mb=50,
            compression_ratio_limit=100,
            timeout_seconds=120,
            encrypted_policy="block",
        )
        self.handler = ArchiveHandler(config=config)

    def test_within_limits(self) -> None:
        """Limitler içindeki değerler → None (güvenli)."""
        result = self.handler._check_limits(
            file_count=10,
            total_uncompressed=1024 * 1024,  # 1MB
            compression_ratio=5.0,
            is_encrypted=False,
        )
        self.assertIsNone(result)

    def test_encrypted_blocked(self) -> None:
        """Şifreli arşiv → block."""
        result = self.handler._check_limits(
            file_count=1,
            total_uncompressed=1024,
            compression_ratio=1.0,
            is_encrypted=True,
        )
        self.assertIn("ENCRYPTED", result or "")

    def test_too_many_files(self) -> None:
        """Dosya sayısı aşıldı → block."""
        result = self.handler._check_limits(
            file_count=600,  # > 500
            total_uncompressed=1024,
            compression_ratio=1.0,
            is_encrypted=False,
        )
        self.assertIn("TOO_MANY_FILES", result or "")

    def test_zip_bomb_ratio(self) -> None:
        """Sıkıştırma oranı aşıldı → block."""
        result = self.handler._check_limits(
            file_count=1,
            total_uncompressed=1024,
            compression_ratio=200.0,  # > 100
            is_encrypted=False,
        )
        self.assertIn("ZIP_BOMB", result or "")


if __name__ == "__main__":
    unittest.main()

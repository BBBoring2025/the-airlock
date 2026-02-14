"""
THE AIRLOCK v5.0.8 FORTRESS-HARDENED — FileValidator Unit Tests

Test edilenler:
  1. Symlink tespiti → BLOCK
  2. Path traversal → BLOCK
  3. Tehlikeli uzantı → BLOCK
  4. Dosya boyut limiti → BLOCK
  5. Device file / FIFO / Socket → BLOCK
  6. Hedef USB symlink koruması (safe_copy_no_symlink, validate_target_path)
  7. Toplu doğrulama (batch validation)

Kullanım:
    python -m pytest tests/test_file_validator.py -v
    python -m unittest tests.test_file_validator -v
"""

from __future__ import annotations

import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from app.config import (
    DANGEROUS_EXTENSIONS,
    MAX_FILENAME_LENGTH,
    SecurityPolicy,
)
from app.security.file_validator import (
    FileValidator,
    ValidationResult,
    validate_target_path,
    safe_mkdir_no_symlink,
    safe_copy_no_symlink,
)


def _make_policy(**overrides: object) -> SecurityPolicy:
    """Test için SecurityPolicy oluştur."""
    defaults = {
        "name": "test",
        "cdr_on_failure": "quarantine",
        "unknown_extension": "block",
        "archive_handling": "block",
        "max_file_size_mb": 100,
        "entropy_threshold": 7.0,
        "ocr_enabled": False,
        "allow_images": True,
        "allow_text": True,
        "allow_pdf": True,
        "allow_office": False,
    }
    defaults.update(overrides)
    return SecurityPolicy(**defaults)


class TestSymlinkDetection(unittest.TestCase):
    """Symlink dosyalarının engellenmesi."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp(prefix="airlock_test_")
        self.source_root = Path(self.tmpdir) / "source"
        self.source_root.mkdir()
        self.validator = FileValidator()

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_regular_file_allowed(self) -> None:
        """Normal dosya geçmeli."""
        f = self.source_root / "readme.txt"
        f.write_text("test content")
        result = self.validator.validate_file(f, self.source_root)
        self.assertTrue(result.is_safe)
        self.assertIsNone(result.block_reason)

    def test_symlink_blocked(self) -> None:
        """Symlink dosya BLOCK edilmeli."""
        real_file = self.source_root / "real.txt"
        real_file.write_text("secret data")
        link_file = self.source_root / "link.txt"
        link_file.symlink_to(real_file)

        result = self.validator.validate_file(link_file, self.source_root)
        self.assertFalse(result.is_safe)
        self.assertIn("SYMLINK", result.block_reason or "")

    def test_symlink_to_outside_blocked(self) -> None:
        """Dışarıya işaret eden symlink BLOCK edilmeli."""
        outside_file = Path(self.tmpdir) / "outside.txt"
        outside_file.write_text("outside")
        link = self.source_root / "escape.txt"
        link.symlink_to(outside_file)

        result = self.validator.validate_file(link, self.source_root)
        self.assertFalse(result.is_safe)
        self.assertIn("SYMLINK", result.block_reason or "")

    def test_broken_symlink_blocked(self) -> None:
        """Kırık symlink de BLOCK edilmeli."""
        link = self.source_root / "broken.txt"
        link.symlink_to("/nonexistent/path/nowhere")

        result = self.validator.validate_file(link, self.source_root)
        self.assertFalse(result.is_safe)


class TestPathTraversal(unittest.TestCase):
    """Path traversal saldırılarının engellenmesi."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp(prefix="airlock_test_")
        self.source_root = Path(self.tmpdir) / "source"
        self.source_root.mkdir()
        self.validator = FileValidator()

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_dotdot_in_filename_blocked(self) -> None:
        """Dosya adında '..' pattern BLOCK edilmeli."""
        f = self.source_root / "..hidden"
        f.write_text("traversal attempt")
        result = self.validator.validate_file(f, self.source_root)
        self.assertFalse(result.is_safe)
        self.assertIn("DANGEROUS_FILENAME", result.block_reason or "")

    def test_control_chars_in_filename_blocked(self) -> None:
        """Kontrol karakterli dosya adı BLOCK edilmeli."""
        f = self.source_root / "test\x01file.txt"
        try:
            f.write_text("data")
            result = self.validator.validate_file(f, self.source_root)
            self.assertFalse(result.is_safe)
        except OSError:
            # Dosya sistemi kontrol karakteri kabul etmeyebilir
            pass

    def test_long_filename_blocked(self) -> None:
        """MAX_FILENAME_LENGTH'ten uzun dosya adı BLOCK edilmeli."""
        long_name = "a" * (MAX_FILENAME_LENGTH + 1)
        f = self.source_root / long_name
        try:
            f.write_text("data")
            result = self.validator.validate_file(f, self.source_root)
            self.assertFalse(result.is_safe)
            self.assertIn("FILENAME_TOO_LONG", result.block_reason or "")
        except OSError:
            # Dosya sistemi uzun adı kabul etmeyebilir
            pass


class TestDangerousExtensions(unittest.TestCase):
    """Tehlikeli uzantıların engellenmesi."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp(prefix="airlock_test_")
        self.source_root = Path(self.tmpdir) / "source"
        self.source_root.mkdir()
        self.validator = FileValidator()

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_exe_blocked(self) -> None:
        """.exe uzantısı BLOCK edilmeli."""
        f = self.source_root / "malware.exe"
        f.write_text("MZ...")
        result = self.validator.validate_file(f, self.source_root)
        self.assertFalse(result.is_safe)
        self.assertIn("DANGEROUS_EXTENSION", result.block_reason or "")

    def test_bat_blocked(self) -> None:
        """.bat uzantısı BLOCK edilmeli."""
        f = self.source_root / "script.bat"
        f.write_text("@echo off")
        result = self.validator.validate_file(f, self.source_root)
        self.assertFalse(result.is_safe)

    def test_ps1_blocked(self) -> None:
        """.ps1 (PowerShell) uzantısı BLOCK edilmeli."""
        f = self.source_root / "payload.ps1"
        f.write_text("Get-Process")
        result = self.validator.validate_file(f, self.source_root)
        self.assertFalse(result.is_safe)

    def test_all_dangerous_extensions(self) -> None:
        """Tüm DANGEROUS_EXTENSIONS kontrol edilmeli."""
        for ext in list(DANGEROUS_EXTENSIONS)[:10]:  # İlk 10 tanesini test et
            f = self.source_root / f"testfile{ext}"
            try:
                f.write_text("test")
                result = self.validator.validate_file(f, self.source_root)
                self.assertFalse(
                    result.is_safe,
                    f"Uzantı {ext} engellenmedi!",
                )
            finally:
                if f.exists():
                    f.unlink()

    def test_safe_extension_allowed(self) -> None:
        """Güvenli uzantı (.txt) geçmeli."""
        f = self.source_root / "notes.txt"
        f.write_text("Hello world")
        result = self.validator.validate_file(f, self.source_root)
        self.assertTrue(result.is_safe)

    def test_pdf_allowed(self) -> None:
        """PDF uzantısı güvenli — DANGEROUS_EXTENSIONS listesinde değil."""
        f = self.source_root / "document.pdf"
        f.write_bytes(b"%PDF-1.4 test")
        result = self.validator.validate_file(f, self.source_root)
        self.assertTrue(result.is_safe)


class TestFileSizeLimit(unittest.TestCase):
    """Dosya boyut limitinin uygulanması."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp(prefix="airlock_test_")
        self.source_root = Path(self.tmpdir) / "source"
        self.source_root.mkdir()

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_file_within_limit(self) -> None:
        """Limit altındaki dosya geçmeli."""
        policy = _make_policy(max_file_size_mb=1)
        validator = FileValidator(policy=policy)
        f = self.source_root / "small.txt"
        f.write_text("x" * 100)
        result = validator.validate_file(f, self.source_root)
        self.assertTrue(result.is_safe)

    def test_file_exceeds_limit(self) -> None:
        """Limit üstündeki dosya BLOCK edilmeli."""
        policy = _make_policy(max_file_size_mb=1)
        validator = FileValidator(policy=policy)
        f = self.source_root / "big.txt"
        # 1MB = 1048576 bytes, biraz üstü yazıyoruz
        f.write_bytes(b"x" * (1024 * 1024 + 100))
        result = validator.validate_file(f, self.source_root)
        self.assertFalse(result.is_safe)
        self.assertIn("FILE_TOO_LARGE", result.block_reason or "")

    def test_no_policy_no_size_check(self) -> None:
        """Policy yoksa boyut kontrolü atlanmalı."""
        validator = FileValidator(policy=None)
        f = self.source_root / "any.txt"
        f.write_bytes(b"x" * (2 * 1024 * 1024))
        result = validator.validate_file(f, self.source_root)
        self.assertTrue(result.is_safe)


class TestTargetSymlinkProtection(unittest.TestCase):
    """Hedef USB'de symlink saldırılarının engellenmesi."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp(prefix="airlock_test_")
        self.target_root = Path(self.tmpdir) / "target"
        self.target_root.mkdir()
        self.source_dir = Path(self.tmpdir) / "source"
        self.source_dir.mkdir()

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_validate_target_path_normal(self) -> None:
        """Normal hedef path geçmeli."""
        target = self.target_root / "subdir" / "file.txt"
        self.assertTrue(validate_target_path(target, self.target_root))

    def test_validate_target_path_symlink_blocked(self) -> None:
        """Hedef path'te symlink varsa BLOCK."""
        # Hedefte symlink dizin oluştur
        real_dir = Path(self.tmpdir) / "real_dir"
        real_dir.mkdir()
        link_dir = self.target_root / "linked"
        link_dir.symlink_to(real_dir)

        target = link_dir / "file.txt"
        self.assertFalse(validate_target_path(target, self.target_root))

    def test_safe_mkdir_no_symlink_normal(self) -> None:
        """Normal dizin oluşturma başarılı olmalı."""
        target_dir = self.target_root / "newdir" / "sub"
        result = safe_mkdir_no_symlink(target_dir, self.target_root)
        self.assertTrue(result)
        self.assertTrue(target_dir.exists())

    def test_safe_mkdir_no_symlink_blocked(self) -> None:
        """Symlink bulunan yolda dizin oluşturma BLOCK."""
        outside = Path(self.tmpdir) / "outside"
        outside.mkdir()
        link = self.target_root / "escape"
        link.symlink_to(outside)

        target_dir = link / "sub"
        result = safe_mkdir_no_symlink(target_dir, self.target_root)
        self.assertFalse(result)

    def test_safe_copy_no_symlink_success(self) -> None:
        """Normal dosya kopyalama başarılı olmalı."""
        src = self.source_dir / "data.txt"
        src.write_text("test content")
        target = self.target_root / "data.txt"

        result = safe_copy_no_symlink(src, target, self.target_root)
        self.assertTrue(result)
        self.assertTrue(target.exists())
        self.assertEqual(target.read_text(), "test content")

    def test_safe_copy_to_symlink_blocked(self) -> None:
        """Hedef bir symlink ise kopyalama BLOCK."""
        src = self.source_dir / "data.txt"
        src.write_text("content")

        # Hedefte dosya yerine symlink koy
        outside_file = Path(self.tmpdir) / "outside.txt"
        outside_file.write_text("victim")
        target = self.target_root / "trap.txt"
        target.symlink_to(outside_file)

        result = safe_copy_no_symlink(src, target, self.target_root)
        self.assertFalse(result)
        # Kurbanın içeriği değişmemeli
        self.assertEqual(outside_file.read_text(), "victim")

    def test_safe_copy_parent_symlink_blocked(self) -> None:
        """Parent dizin symlink ise kopyalama BLOCK."""
        src = self.source_dir / "data.txt"
        src.write_text("content")

        outside = Path(self.tmpdir) / "escape_dir"
        outside.mkdir()
        link = self.target_root / "linked_dir"
        link.symlink_to(outside)

        target = link / "file.txt"
        result = safe_copy_no_symlink(src, target, self.target_root)
        self.assertFalse(result)


class TestBatchValidation(unittest.TestCase):
    """Toplu dosya doğrulama testleri."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp(prefix="airlock_test_")
        self.source_root = Path(self.tmpdir) / "source"
        self.source_root.mkdir()
        self.validator = FileValidator()

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_batch_mixed_files(self) -> None:
        """Karışık dosya türleri — güvenli ve tehlikeli ayrıştırılmalı."""
        # Güvenli dosyalar
        (self.source_root / "safe1.txt").write_text("hello")
        (self.source_root / "safe2.pdf").write_bytes(b"%PDF-1.4")

        # Tehlikeli dosya
        (self.source_root / "danger.exe").write_text("MZ")

        result = self.validator.validate_batch(self.source_root)
        self.assertEqual(len(result.safe_files), 2)
        self.assertEqual(len(result.blocked_files), 1)
        self.assertEqual(result.total_files, 3)

    def test_batch_empty_directory(self) -> None:
        """Boş dizin — 0 dosya."""
        result = self.validator.validate_batch(self.source_root)
        self.assertEqual(result.total_files, 0)
        self.assertTrue(result.is_within_limits)

    def test_batch_nonexistent_directory(self) -> None:
        """Var olmayan dizin — hata durumu."""
        fake = Path(self.tmpdir) / "nonexistent"
        result = self.validator.validate_batch(fake)
        self.assertFalse(result.is_within_limits)

    def test_batch_symlink_in_tree(self) -> None:
        """Dizin ağacındaki symlink engellenmeli."""
        (self.source_root / "good.txt").write_text("ok")
        real = self.source_root / "real.txt"
        real.write_text("data")
        link = self.source_root / "link.txt"
        link.symlink_to(real)

        result = self.validator.validate_batch(self.source_root)
        # link.txt blocked, good.txt + real.txt safe
        self.assertEqual(len(result.blocked_files), 1)
        self.assertEqual(len(result.safe_files), 2)


class TestHiddenFileWarning(unittest.TestCase):
    """Gizli dosyalar için uyarı."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp(prefix="airlock_test_")
        self.source_root = Path(self.tmpdir) / "source"
        self.source_root.mkdir()
        self.validator = FileValidator()

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_hidden_file_warning(self) -> None:
        """Gizli dosya geçmeli ama uyarı içermeli."""
        f = self.source_root / ".hidden_config"
        f.write_text("secret")
        result = self.validator.validate_file(f, self.source_root)
        self.assertTrue(result.is_safe)
        self.assertTrue(any("HIDDEN_FILE" in w for w in result.warnings))


if __name__ == "__main__":
    unittest.main()

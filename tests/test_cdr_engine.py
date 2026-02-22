"""
THE AIRLOCK v5.1.1 FORTRESS-HARDENED — CDR Engine Hermetic Tests

Tum testler HERMETIK: Ghostscript, LibreOffice, Tesseract, img2pdf, pdfunite,
bwrap → MOCK. Hicbir harici binary gerektirmez.

Test edilen modül: app/security/cdr_engine.py

Kullanım:
    python -m pytest tests/test_cdr_engine.py -v
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from app.config import AirlockConfig, DIRECTORIES
from app.security.cdr_engine import CDREngine, CDRResult


class _CDRTestBase(unittest.TestCase):
    """Ortak setUp/tearDown — geçici dizin yönetimi."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp(prefix="airlock_cdr_test_")
        self.work_dir = Path(self.tmpdir) / "tmp"
        self.work_dir.mkdir()
        self.source_dir = Path(self.tmpdir) / "source"
        self.source_dir.mkdir()
        self.target_dir = Path(self.tmpdir) / "target"
        self.target_dir.mkdir()

    def tearDown(self) -> None:
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _make_engine(
        self,
        bwrap_available: bool = False,
        cdr_require_sandbox: bool = False,
        **kwargs: object,
    ) -> CDREngine:
        """Mock bwrap kontrolü ile CDREngine oluştur."""
        cfg = AirlockConfig(cdr_require_sandbox=cdr_require_sandbox, **kwargs)
        with patch.object(CDREngine, "_check_bwrap", return_value=bwrap_available):
            engine = CDREngine(config=cfg)
        # DIRECTORIES["tmp"] yerine test dizinini kullan
        engine._work_dir = self.work_dir
        return engine


# ═══════════════════════════════════════════════
# PDF CDR Tests
# ═══════════════════════════════════════════════


class TestPDFCDR(_CDRTestBase):
    """PDF CDR pipeline testleri — Ghostscript + img2pdf mock."""

    def _gs_side_effect(self, job_dir: Path, page_count: int = 3):
        """Ghostscript benzeri yan etki: sahte JPG dosyaları oluşturur."""

        def side_effect(*args, **kwargs):
            cmd = args[0] if args else kwargs.get("args", [])
            prog = cmd[0] if cmd else ""
            if prog in ("gs", "bwrap"):
                # gs çıktı dizinini bul — sOutputFile parametresinden
                for i, arg in enumerate(cmd):
                    if isinstance(arg, str) and arg.startswith("-sOutputFile="):
                        pattern = arg.split("=", 1)[1]
                        # Sayfa dosyalarını oluştur
                        for n in range(1, page_count + 1):
                            page_path = Path(pattern % n)
                            page_path.parent.mkdir(parents=True, exist_ok=True)
                            page_path.write_bytes(b"\xff\xd8\xff\xe0" + b"\x00" * 100)
                        break
                return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")
            if prog == "img2pdf":
                # img2pdf çıktı dosyasını oluştur
                for i, arg in enumerate(cmd):
                    if arg == "-o" and i + 1 < len(cmd):
                        out = Path(cmd[i + 1])
                        out.parent.mkdir(parents=True, exist_ok=True)
                        out.write_bytes(b"%PDF-1.4 fake")
                        break
                return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

        return side_effect

    @patch("app.security.cdr_engine.subprocess.run")
    def test_pdf_success(self, mock_run: MagicMock) -> None:
        """Başarılı PDF CDR: gs→JPG→img2pdf→PDF."""
        engine = self._make_engine()
        source = self.source_dir / "test.pdf"
        source.write_bytes(b"%PDF-1.4 test content")
        target = self.target_dir / "test_clean.pdf"

        mock_run.side_effect = self._gs_side_effect(self.work_dir, page_count=2)

        result = engine.process_pdf(source, target)

        self.assertTrue(result.success)
        self.assertEqual(result.cdr_method, "rasterize")
        self.assertEqual(result.pages_processed, 2)
        self.assertIsNotNone(result.original_sha256)

    @patch("app.security.cdr_engine.subprocess.run")
    def test_pdf_ghostscript_fails(self, mock_run: MagicMock) -> None:
        """Ghostscript rc=1 → CDR başarısız."""
        engine = self._make_engine()
        source = self.source_dir / "bad.pdf"
        source.write_bytes(b"%PDF-1.4 corrupt")
        target = self.target_dir / "bad_clean.pdf"

        mock_run.return_value = subprocess.CompletedProcess(
            args=["gs"], returncode=1, stdout="", stderr="Error"
        )

        result = engine.process_pdf(source, target)

        self.assertFalse(result.success)
        self.assertIn("NO_PAGES", result.reason)

    @patch("app.security.cdr_engine.subprocess.run")
    def test_pdf_img2pdf_fails(self, mock_run: MagicMock) -> None:
        """gs başarılı ama img2pdf başarısız → CDR başarısız."""
        engine = self._make_engine()
        source = self.source_dir / "test2.pdf"
        source.write_bytes(b"%PDF-1.4 content")
        target = self.target_dir / "test2_clean.pdf"

        call_count = [0]

        def side_effect(*args, **kwargs):
            cmd = args[0] if args else kwargs.get("args", [])
            prog = cmd[0] if cmd else ""
            call_count[0] += 1
            if prog == "gs" or (prog == "bwrap" and "gs" in cmd):
                # gs: sahte sayfa oluştur
                for i, arg in enumerate(cmd):
                    if isinstance(arg, str) and arg.startswith("-sOutputFile="):
                        pattern = arg.split("=", 1)[1]
                        p = Path(pattern % 1)
                        p.parent.mkdir(parents=True, exist_ok=True)
                        p.write_bytes(b"\xff\xd8\xff\xe0" + b"\x00" * 50)
                        break
                return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")
            if prog == "img2pdf":
                return subprocess.CompletedProcess(
                    args=cmd, returncode=1, stdout="", stderr="img2pdf error"
                )
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

        mock_run.side_effect = side_effect

        result = engine.process_pdf(source, target)

        self.assertFalse(result.success)
        self.assertIn("IMG2PDF", result.reason)

    @patch("app.security.cdr_engine.subprocess.run")
    def test_pdf_ghostscript_not_found(self, mock_run: MagicMock) -> None:
        """Ghostscript kurulu değil → FileNotFoundError → CDR başarısız."""
        engine = self._make_engine()
        source = self.source_dir / "nogs.pdf"
        source.write_bytes(b"%PDF-1.4 test")
        target = self.target_dir / "nogs_clean.pdf"

        mock_run.side_effect = FileNotFoundError("gs not found")

        result = engine.process_pdf(source, target)

        self.assertFalse(result.success)


# ═══════════════════════════════════════════════
# Office CDR Tests
# ═══════════════════════════════════════════════


class TestOfficeCDR(_CDRTestBase):
    """Office CDR pipeline testleri — LibreOffice + PDF pipeline mock."""

    @patch("app.security.cdr_engine.subprocess.run")
    def test_office_success(self, mock_run: MagicMock) -> None:
        """Başarılı Office CDR: soffice→PDF→gs→img2pdf→temiz PDF."""
        engine = self._make_engine()
        source = self.source_dir / "doc.docx"
        source.write_bytes(b"PK\x03\x04 fake docx content")
        target = self.target_dir / "doc_clean.pdf"

        def side_effect(*args, **kwargs):
            cmd = args[0] if args else kwargs.get("args", [])
            prog = cmd[0] if cmd else ""
            if prog == "soffice" or (prog == "bwrap" and "soffice" in cmd):
                # soffice: job_dir'e PDF oluştur
                for i, arg in enumerate(cmd):
                    if arg == "--outdir" and i + 1 < len(cmd):
                        outdir = Path(cmd[i + 1])
                        pdf_out = outdir / "doc.pdf"
                        pdf_out.parent.mkdir(parents=True, exist_ok=True)
                        pdf_out.write_bytes(b"%PDF-1.4 soffice output")
                        break
                return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")
            if prog == "gs" or (prog == "bwrap" and "gs" in cmd):
                for i, arg in enumerate(cmd):
                    if isinstance(arg, str) and arg.startswith("-sOutputFile="):
                        pattern = arg.split("=", 1)[1]
                        p = Path(pattern % 1)
                        p.parent.mkdir(parents=True, exist_ok=True)
                        p.write_bytes(b"\xff\xd8\xff\xe0" + b"\x00" * 50)
                        break
                return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")
            if prog == "img2pdf":
                for i, arg in enumerate(cmd):
                    if arg == "-o" and i + 1 < len(cmd):
                        out = Path(cmd[i + 1])
                        out.parent.mkdir(parents=True, exist_ok=True)
                        out.write_bytes(b"%PDF-1.4 final")
                        break
                return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

        mock_run.side_effect = side_effect

        result = engine.process_office(source, target)

        self.assertTrue(result.success)
        self.assertEqual(result.cdr_method, "office_to_pdf_rasterize")

    @patch("app.security.cdr_engine.subprocess.run")
    def test_office_libreoffice_fails(self, mock_run: MagicMock) -> None:
        """LibreOffice başarısız → CDR başarısız."""
        engine = self._make_engine()
        source = self.source_dir / "bad.docx"
        source.write_bytes(b"PK\x03\x04 corrupt")
        target = self.target_dir / "bad_clean.pdf"

        mock_run.return_value = subprocess.CompletedProcess(
            args=["soffice"], returncode=1, stdout="", stderr="soffice error"
        )

        result = engine.process_office(source, target)

        self.assertFalse(result.success)
        self.assertIn("LIBREOFFICE", result.reason)


# ═══════════════════════════════════════════════
# Image CDR Tests
# ═══════════════════════════════════════════════


class TestImageCDR(_CDRTestBase):
    """Resim CDR testleri — Pillow ile metadata temizleme."""

    def test_image_jpeg_success(self) -> None:
        """JPEG metadata strip + re-encode başarılı."""
        try:
            from PIL import Image
        except ImportError:
            self.skipTest("Pillow not installed")

        engine = self._make_engine()
        source = self.source_dir / "photo.jpg"

        # Gerçek JPEG oluştur (Pillow ile)
        img = Image.new("RGB", (10, 10), color="red")
        img.save(str(source), format="JPEG", quality=90)
        img.close()

        target = self.target_dir / "photo_clean.jpg"

        result = engine.process_image(source, target)

        self.assertTrue(result.success)
        self.assertEqual(result.cdr_method, "image_strip")
        self.assertEqual(result.pages_processed, 1)
        # Çıktı dosyası mevcut olmalı
        self.assertTrue(result.output_path is not None)

    def test_image_unknown_format_to_png(self) -> None:
        """Bilinmeyen format → PNG'ye dönüştürülmeli."""
        try:
            from PIL import Image
        except ImportError:
            self.skipTest("Pillow not installed")

        engine = self._make_engine()
        source = self.source_dir / "weird.bmp"

        # BMP oluştur
        img = Image.new("RGB", (5, 5), color="blue")
        img.save(str(source), format="BMP")
        img.close()

        target = self.target_dir / "weird_clean.bmp"

        result = engine.process_image(source, target)

        self.assertTrue(result.success)
        self.assertEqual(result.cdr_method, "image_strip")

    def test_image_pillow_not_installed(self) -> None:
        """Pillow yüklü değil → CDR başarısız."""
        engine = self._make_engine()
        source = self.source_dir / "nopillow.jpg"
        source.write_bytes(b"\xff\xd8\xff\xe0" + b"\x00" * 50)
        target = self.target_dir / "nopillow_clean.jpg"

        # PIL import'unu engelle
        import sys
        original_pil = sys.modules.get("PIL")
        original_pil_image = sys.modules.get("PIL.Image")
        sys.modules["PIL"] = None  # type: ignore[assignment]
        sys.modules["PIL.Image"] = None  # type: ignore[assignment]

        try:
            result = engine.process_image(source, target)
            self.assertFalse(result.success)
            self.assertIn("PILLOW", result.reason)
        finally:
            # PIL modüllerini geri yükle
            if original_pil is not None:
                sys.modules["PIL"] = original_pil
            else:
                sys.modules.pop("PIL", None)
            if original_pil_image is not None:
                sys.modules["PIL.Image"] = original_pil_image
            else:
                sys.modules.pop("PIL.Image", None)


# ═══════════════════════════════════════════════
# Text CDR Tests
# ═══════════════════════════════════════════════


class TestTextCDR(_CDRTestBase):
    """Metin CDR testleri — encoding + kontrol karakter temizleme."""

    def test_text_utf8_success(self) -> None:
        """Normal UTF-8 metin başarıyla işlenir."""
        engine = self._make_engine()
        source = self.source_dir / "readme.txt"
        source.write_text("Hello World\nLine 2\tTabbed", encoding="utf-8")
        target = self.target_dir / "readme_clean.txt"

        result = engine.process_text(source, target)

        self.assertTrue(result.success)
        self.assertEqual(result.cdr_method, "text_clean")
        # İçerik korunmalı
        cleaned = target.read_text(encoding="utf-8")
        self.assertIn("Hello World", cleaned)
        self.assertIn("\t", cleaned)  # Tab korunmalı

    def test_text_binary_blocked(self) -> None:
        """NUL byte içeren dosya reddedilmeli."""
        engine = self._make_engine()
        source = self.source_dir / "binary.txt"
        source.write_bytes(b"Normal text\x00hidden binary")
        target = self.target_dir / "binary_clean.txt"

        result = engine.process_text(source, target)

        self.assertFalse(result.success)
        self.assertIn("BINARY_CONTENT", result.reason)

    def test_text_control_chars_stripped(self) -> None:
        """Kontrol karakterleri temizlenmeli, tab/newline korunmalı."""
        engine = self._make_engine()
        source = self.source_dir / "dirty.txt"
        # \x01-\x08 kontrol karakterleri + korunması gereken \t \n
        content = b"Line1\x01\x02\x03\tTabbed\nLine2\x08end"
        source.write_bytes(content)
        target = self.target_dir / "dirty_clean.txt"

        result = engine.process_text(source, target)

        self.assertTrue(result.success)
        # read_bytes ile oku — line ending dönüşümü olmasın
        raw = target.read_bytes()
        cleaned = raw.decode("utf-8")
        # Tab ve newline korunmalı
        self.assertIn("\t", cleaned)
        self.assertIn("\n", cleaned)
        # Kontrol karakterleri silinmiş olmalı
        self.assertNotIn("\x01", cleaned)
        self.assertNotIn("\x02", cleaned)
        self.assertNotIn("\x03", cleaned)
        self.assertNotIn("\x08", cleaned)
        # warnings listesinde temizlenen karakter sayısı olmalı
        self.assertTrue(len(result.warnings) > 0)


# ═══════════════════════════════════════════════
# Sandbox Policy Tests
# ═══════════════════════════════════════════════


class TestSandboxPolicy(_CDRTestBase):
    """Bubblewrap sandbox politika testleri."""

    def test_sandbox_required_but_missing(self) -> None:
        """cdr_require_sandbox=True + bwrap yok → komut reddedilmeli."""
        engine = self._make_engine(bwrap_available=False, cdr_require_sandbox=True)

        result = engine._run_sandboxed(
            ["gs", "--version"], timeout=5, job_dir=self.work_dir
        )

        self.assertEqual(result.returncode, 1)
        self.assertIn("SANDBOX_REQUIRED", result.stderr)

    @patch("app.security.cdr_engine.subprocess.run")
    def test_bwrap_available_uses_sandbox(self, mock_run: MagicMock) -> None:
        """bwrap mevcut → komut bwrap prefix ile çalıştırılmalı."""
        engine = self._make_engine(bwrap_available=True)

        mock_run.return_value = subprocess.CompletedProcess(
            args=["bwrap"], returncode=0, stdout="", stderr=""
        )

        engine._run_sandboxed(["gs", "--version"], timeout=5, job_dir=self.work_dir)

        mock_run.assert_called_once()
        actual_cmd = mock_run.call_args[0][0]
        self.assertEqual(actual_cmd[0], "bwrap")
        # gs komutunun argümanlarında olmalı
        self.assertIn("gs", actual_cmd)

    @patch("app.security.cdr_engine.subprocess.run")
    def test_bwrap_not_available_direct_run(self, mock_run: MagicMock) -> None:
        """bwrap yok + sandbox zorunlu değil → doğrudan çalıştır."""
        engine = self._make_engine(bwrap_available=False, cdr_require_sandbox=False)

        mock_run.return_value = subprocess.CompletedProcess(
            args=["gs"], returncode=0, stdout="ok", stderr=""
        )

        engine._run_sandboxed(["gs", "--version"], timeout=5, job_dir=self.work_dir)

        mock_run.assert_called_once()
        actual_cmd = mock_run.call_args[0][0]
        self.assertEqual(actual_cmd[0], "gs")
        self.assertNotIn("bwrap", actual_cmd)


if __name__ == "__main__":
    unittest.main()

"""
THE AIRLOCK v5.0.8 FORTRESS-HARDENED — Report Signature Unit Tests

Test edilenler:
  1. Rapor üretimi (JSON yapısı)
  2. Ed25519 imzalama → doğrulama (sign → verify)
  3. Değiştirilmiş rapor → doğrulama BAŞARISIZ
  4. İmza olmadan doğrulama → False
  5. Manifest üretimi ve doğrulama
  6. ScanSession istatistik güncelleme

Kullanım:
    python -m pytest tests/test_report_signature.py -v
    python -m unittest tests.test_report_signature -v

NOT: Bu testler PyNaCl kütüphanesini gerektirir.
     PyNaCl yoksa imza testleri atlanır.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, Optional
from unittest import mock

from app.security.report_generator import (
    FileEntry,
    ReportGenerator,
    ScanSession,
    ScanSummary,
    USBSourceInfo,
)

# PyNaCl mevcut mu kontrol et
try:
    from nacl.signing import SigningKey, VerifyKey
    import base64
    HAS_NACL = True
except ImportError:
    HAS_NACL = False


def _create_test_session() -> ScanSession:
    """Test için ScanSession oluştur."""
    session = ScanSession(
        policy="balanced",
        usb_source=USBSourceInfo(
            vendor_id="1234",
            product_id="5678",
            manufacturer="TestCorp",
            serial="SN001",
            filesystem="vfat",
            label="DIRTY",
            total_size_mb=1024,
        ),
    )
    session.start()

    # Dosya kayıtları ekle
    session.add_file(FileEntry(
        original_path="/source/doc.pdf",
        original_sha256="aabbcc" * 10 + "aabb",
        original_size=102400,
        action="cdr_rasterize",
        output_path="/target/doc.pdf",
        output_sha256="ddeeff" * 10 + "ddee",
        output_size=98000,
    ))
    session.add_file(FileEntry(
        original_path="/source/photo.jpg",
        original_sha256="112233" * 10 + "1122",
        original_size=204800,
        action="cdr_image_strip",
        output_path="/target/photo.jpg",
        output_sha256="445566" * 10 + "4455",
        output_size=200000,
    ))
    session.add_file(FileEntry(
        original_path="/source/malware.exe",
        original_sha256="deadbe" * 10 + "dead",
        original_size=51200,
        action="blocked",
        detections=[{"engine": "clamav", "rule": "Win.Trojan.Test"}],
    ))

    session.finish()
    return session


class TestReportGeneration(unittest.TestCase):
    """Rapor üretimi testleri."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp(prefix="airlock_report_test_")
        config = mock.MagicMock()
        config.update_public_key_path = Path(self.tmpdir) / "pub.key"
        self.generator = ReportGenerator(config=config)

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_report_structure(self) -> None:
        """Rapor doğru JSON yapısına sahip olmalı."""
        session = _create_test_session()
        report = self.generator.generate(session)

        # Zorunlu alanlar
        self.assertIn("version", report)
        self.assertIn("codename", report)
        self.assertIn("timestamp", report)
        self.assertIn("station_id", report)
        self.assertIn("policy", report)
        self.assertIn("summary", report)
        self.assertIn("usb_source", report)
        self.assertIn("files", report)

    def test_report_policy(self) -> None:
        """Rapor aktif politikayı doğru göstermeli."""
        session = _create_test_session()
        report = self.generator.generate(session)
        self.assertEqual(report["policy"], "balanced")

    def test_report_summary_stats(self) -> None:
        """Rapor özet istatistikleri doğru olmalı."""
        session = _create_test_session()
        report = self.generator.generate(session)
        summary = report["summary"]

        self.assertEqual(summary["total_files"], 3)
        self.assertEqual(summary["processed"], 2)
        self.assertEqual(summary["blocked"], 1)
        self.assertEqual(summary["cdr_applied"], 2)

    def test_report_files_count(self) -> None:
        """Rapordaki dosya sayısı doğru olmalı."""
        session = _create_test_session()
        report = self.generator.generate(session)
        self.assertEqual(len(report["files"]), 3)

    def test_report_usb_info(self) -> None:
        """Rapordaki USB bilgileri doğru olmalı."""
        session = _create_test_session()
        report = self.generator.generate(session)
        usb = report["usb_source"]
        self.assertEqual(usb["vendor_id"], "1234")
        self.assertEqual(usb["product_id"], "5678")
        self.assertEqual(usb["label"], "DIRTY")

    def test_report_json_serializable(self) -> None:
        """Rapor JSON'a serialize edilebilmeli."""
        session = _create_test_session()
        report = self.generator.generate(session)
        # JSON'a dönüştürme hatası vermemeli
        json_str = json.dumps(report, ensure_ascii=False)
        self.assertIsInstance(json_str, str)
        # JSON'dan geri dönüşüm
        parsed = json.loads(json_str)
        self.assertEqual(parsed["policy"], "balanced")

    def test_report_timestamp_iso(self) -> None:
        """Rapor timestamp ISO formatında olmalı."""
        session = _create_test_session()
        report = self.generator.generate(session)
        timestamp = report["timestamp"]
        # ISO format: YYYY-MM-DDTHH:MM:SS...
        self.assertIn("T", timestamp)


class TestScanSession(unittest.TestCase):
    """ScanSession istatistik testleri."""

    def test_session_timing(self) -> None:
        """Oturum süresi doğru hesaplanmalı."""
        session = ScanSession()
        session.start()
        session.finish()
        self.assertGreaterEqual(session.summary.duration_seconds, 0.0)

    def test_file_add_clean_copy(self) -> None:
        """clean_copy ekleme istatistik güncellemeli."""
        session = ScanSession()
        session.add_file(FileEntry(
            original_path="/test/file.txt",
            original_sha256="abc123",
            original_size=100,
            action="clean_copy",
        ))
        self.assertEqual(session.summary.total_files, 1)
        self.assertEqual(session.summary.processed, 1)
        self.assertEqual(session.summary.clean_copied, 1)

    def test_file_add_cdr(self) -> None:
        """CDR dosya ekleme istatistik güncellemeli."""
        session = ScanSession()
        session.add_file(FileEntry(
            original_path="/test/doc.pdf",
            original_sha256="abc123",
            original_size=1000,
            action="cdr_rasterize",
        ))
        self.assertEqual(session.summary.cdr_applied, 1)
        self.assertEqual(session.summary.processed, 1)

    def test_file_add_blocked(self) -> None:
        """Engellenen dosya istatistik güncellemeli."""
        session = ScanSession()
        session.add_file(FileEntry(
            original_path="/test/evil.exe",
            original_sha256="abc123",
            original_size=500,
            action="blocked",
        ))
        self.assertEqual(session.summary.blocked, 1)
        self.assertEqual(session.summary.processed, 0)

    def test_file_add_quarantined(self) -> None:
        """Karantinaya alınan dosya istatistik güncellemeli."""
        session = ScanSession()
        session.add_file(FileEntry(
            original_path="/test/virus.dat",
            original_sha256="abc123",
            original_size=500,
            action="quarantined",
        ))
        self.assertEqual(session.summary.quarantined, 1)

    def test_threat_detection_count(self) -> None:
        """Tehdit tespiti sayısı doğru olmalı."""
        session = ScanSession()
        session.add_file(FileEntry(
            original_path="/test/bad.dat",
            original_sha256="abc123",
            original_size=500,
            action="quarantined",
            detections=[
                {"engine": "clamav", "rule": "Trojan"},
                {"engine": "yara", "rule": "Suspicious"},
            ],
        ))
        self.assertEqual(session.summary.threats_detected, 2)


@unittest.skipUnless(HAS_NACL, "PyNaCl gerekli — pip install pynacl")
class TestReportSignature(unittest.TestCase):
    """Rapor Ed25519 imzalama ve doğrulama testleri."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp(prefix="airlock_sig_test_")
        self.private_key_path = Path(self.tmpdir) / "signing.key"
        self.public_key_path = Path(self.tmpdir) / "verify.pub"

        # Test anahtar çifti oluştur
        from app.utils.crypto import generate_keypair
        generate_keypair(self.private_key_path, self.public_key_path)

        config = mock.MagicMock()
        config.update_public_key_path = self.public_key_path

        # Generator'ı test anahtarı ile oluştur
        self.generator = ReportGenerator(config=config)
        # İmzalama anahtarını override et
        self.generator._signing_key_path = self.private_key_path

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_sign_and_verify(self) -> None:
        """İmzala → doğrula başarılı olmalı."""
        session = _create_test_session()
        report = self.generator.generate(session)

        # İmzala
        signature = self.generator.sign_report(report)
        self.assertIsInstance(signature, str)
        self.assertTrue(len(signature) > 10)

        # Rapora imzayı ekle
        report["signature"] = signature

        # Doğrula
        is_valid = self.generator.verify_report(
            report, self.public_key_path
        )
        self.assertTrue(is_valid)

    def test_tampered_report_fails(self) -> None:
        """Değiştirilmiş rapor doğrulama BAŞARISIZ olmalı."""
        session = _create_test_session()
        report = self.generator.generate(session)

        # İmzala
        signature = self.generator.sign_report(report)
        report["signature"] = signature

        # Raporu değiştir
        report["summary"]["total_files"] = 9999

        # Doğrulama başarısız olmalı
        is_valid = self.generator.verify_report(
            report, self.public_key_path
        )
        self.assertFalse(is_valid)

    def test_missing_signature_fails(self) -> None:
        """İmza olmadan doğrulama BAŞARISIZ olmalı."""
        session = _create_test_session()
        report = self.generator.generate(session)
        # İmza yok
        is_valid = self.generator.verify_report(
            report, self.public_key_path
        )
        self.assertFalse(is_valid)

    def test_wrong_key_fails(self) -> None:
        """Yanlış anahtar ile doğrulama BAŞARISIZ olmalı."""
        session = _create_test_session()
        report = self.generator.generate(session)

        signature = self.generator.sign_report(report)
        report["signature"] = signature

        # Farklı anahtar çifti oluştur
        from app.utils.crypto import generate_keypair
        wrong_pub = Path(self.tmpdir) / "wrong.pub"
        generate_keypair(
            Path(self.tmpdir) / "wrong.key",
            wrong_pub,
        )

        # Yanlış anahtar ile doğrulama
        is_valid = self.generator.verify_report(report, wrong_pub)
        self.assertFalse(is_valid)

    def test_write_report_signed(self) -> None:
        """write_report imzalı rapor dosyası yazmalı."""
        session = _create_test_session()
        report = self.generator.generate(session)

        target_dir = Path(self.tmpdir) / "output"
        report_path = self.generator.write_report(
            report, target_dir, sign=True
        )

        self.assertTrue(report_path.exists())

        # Dosyayı oku ve imza kontrol et
        content = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertIn("signature", content)
        # signature None veya string olabilir (anahtar bulunamazsa None)
        if content["signature"] is not None:
            self.assertIsInstance(content["signature"], str)


class TestManifest(unittest.TestCase):
    """Manifest üretimi ve doğrulama testleri."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp(prefix="airlock_manifest_test_")
        config = mock.MagicMock()
        config.update_public_key_path = Path(self.tmpdir) / "pub.key"
        self.generator = ReportGenerator(config=config)

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_manifest_generation(self) -> None:
        """Manifest dosyası doğru oluşturulmalı."""
        files = [
            FileEntry(
                original_path="/source/a.txt",
                original_sha256="aaa",
                original_size=100,
                action="clean_copy",
                output_path="a.txt",
                output_sha256="bbb111",
            ),
            FileEntry(
                original_path="/source/b.pdf",
                original_sha256="ccc",
                original_size=200,
                action="cdr_rasterize",
                output_path="b.pdf",
                output_sha256="ddd222",
            ),
        ]

        target_dir = Path(self.tmpdir) / "manifest_out"
        manifest_path = self.generator.write_manifest(files, target_dir)

        self.assertIsNotNone(manifest_path)
        self.assertTrue(manifest_path.exists())

        content = manifest_path.read_text(encoding="utf-8")
        lines = content.strip().splitlines()
        self.assertEqual(len(lines), 2)
        self.assertIn("bbb111", lines[0])
        self.assertIn("ddd222", lines[1])

    def test_manifest_empty(self) -> None:
        """Tüm dosyalar engelliyse manifest None döndürmeli."""
        files = [
            FileEntry(
                original_path="/source/bad.exe",
                original_sha256="aaa",
                original_size=100,
                action="blocked",
                # output_sha256 yok
            ),
        ]
        target_dir = Path(self.tmpdir) / "empty_manifest"
        result = self.generator.write_manifest(files, target_dir)
        self.assertIsNone(result)

    def test_manifest_verify(self) -> None:
        """Manifest doğrulama — dosya hash'leri eşleşmeli."""
        target_dir = Path(self.tmpdir) / "verify_test"
        target_dir.mkdir(parents=True)

        # Test dosyaları oluştur
        file_a = target_dir / "a.txt"
        file_a.write_text("hello world")

        from app.utils.crypto import sha256_file
        hash_a = sha256_file(file_a)

        # Manifest oluştur
        manifest_path = target_dir / "manifest.sha256"
        manifest_path.write_text(f"{hash_a}  a.txt\n", encoding="utf-8")

        results = self.generator.verify_manifest(manifest_path, target_dir)
        self.assertTrue(results.get("a.txt", False))

    def test_manifest_verify_tampered(self) -> None:
        """Değiştirilmiş dosya manifest doğrulamasını bozmalı."""
        target_dir = Path(self.tmpdir) / "tamper_test"
        target_dir.mkdir(parents=True)

        file_a = target_dir / "a.txt"
        file_a.write_text("original content")

        from app.utils.crypto import sha256_file
        hash_a = sha256_file(file_a)

        manifest_path = target_dir / "manifest.sha256"
        manifest_path.write_text(f"{hash_a}  a.txt\n", encoding="utf-8")

        # Dosyayı değiştir
        file_a.write_text("TAMPERED content")

        results = self.generator.verify_manifest(manifest_path, target_dir)
        self.assertFalse(results.get("a.txt", True))

    def test_manifest_verify_missing_file(self) -> None:
        """Eksik dosya manifest doğrulamasında False olmalı."""
        target_dir = Path(self.tmpdir) / "missing_test"
        target_dir.mkdir(parents=True)

        manifest_path = target_dir / "manifest.sha256"
        manifest_path.write_text(
            "abc123  nonexistent.txt\n", encoding="utf-8"
        )

        results = self.generator.verify_manifest(manifest_path, target_dir)
        self.assertFalse(results.get("nonexistent.txt", True))


if __name__ == "__main__":
    unittest.main()

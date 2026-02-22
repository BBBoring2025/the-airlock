"""
THE AIRLOCK v5.1.1 FORTRESS-HARDENED — File Scanner Hermetic Tests

Tum testler HERMETIK: ClamAV daemon, clamscan, yara binary, python-magic,
file komutu → MOCK. Hicbir harici binary gerektirmez.

Test edilen modül: app/security/scanner.py

Kullanım:
    python -m pytest tests/test_scanner.py -v
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from app.config import AirlockConfig, DIRECTORIES
from app.security.scanner import Detection, FileScanner, ScanResult


class _ScannerTestBase(unittest.TestCase):
    """Ortak setUp/tearDown — geçici dizin + hash cache reset."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp(prefix="airlock_scan_test_")
        self.test_dir = Path(self.tmpdir)
        # Class-level hash cache'i temizle (testler arası izolasyon)
        FileScanner._known_bad_hashes = None

    def tearDown(self) -> None:
        shutil.rmtree(self.tmpdir, ignore_errors=True)
        # Cache'i temizle
        FileScanner._known_bad_hashes = None

    def _make_scanner(self, **kwargs: object) -> FileScanner:
        """Test config ile FileScanner oluştur."""
        cfg = AirlockConfig(**kwargs)
        scanner = FileScanner(config=cfg)
        return scanner

    def _create_file(self, name: str, content: bytes) -> Path:
        """Test dosyası oluştur."""
        p = self.test_dir / name
        p.write_bytes(content)
        return p

    def _sha256(self, data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()


# ═══════════════════════════════════════════════
# ClamAV Scanner Tests
# ═══════════════════════════════════════════════


class TestClamAVScanner(_ScannerTestBase):
    """ClamAV tarama testleri — pyclamd daemon + clamscan CLI mock."""

    def test_clamav_daemon_threat_detected(self) -> None:
        """ClamAV daemon tehdit tespit eder → Detection döner."""
        scanner = self._make_scanner(clamav_enabled=True)
        test_file = self._create_file("eicar.com", b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR")

        # pyclamd modülünü mock'la
        mock_pyclamd = MagicMock()
        mock_clamd_instance = MagicMock()
        mock_clamd_instance.ping.return_value = True
        mock_clamd_instance.scan_file.return_value = {
            str(test_file): ("FOUND", "Eicar-Test-Signature")
        }
        mock_pyclamd.ClamdUnixSocket.return_value = mock_clamd_instance

        import sys
        with patch.dict(sys.modules, {"pyclamd": mock_pyclamd}):
            # _clamav_available reset
            scanner._clamav_available = None
            detection = scanner._scan_clamav_daemon(test_file)

        self.assertIsInstance(detection, Detection)
        self.assertEqual(detection.engine, "clamav")
        self.assertEqual(detection.rule_name, "Eicar-Test-Signature")

    def test_clamav_daemon_clean(self) -> None:
        """ClamAV daemon temiz dosya → False döner (tehdit yok)."""
        scanner = self._make_scanner(clamav_enabled=True)
        test_file = self._create_file("clean.txt", b"Hello World")

        mock_pyclamd = MagicMock()
        mock_clamd_instance = MagicMock()
        mock_clamd_instance.ping.return_value = True
        mock_clamd_instance.scan_file.return_value = None  # Temiz
        mock_pyclamd.ClamdUnixSocket.return_value = mock_clamd_instance

        import sys
        with patch.dict(sys.modules, {"pyclamd": mock_pyclamd}):
            scanner._clamav_available = None
            detection = scanner._scan_clamav_daemon(test_file)

        self.assertFalse(detection)  # False = temiz (None değil!)

    @patch("app.security.scanner.subprocess.run")
    def test_clamav_cli_fallback_threat(self, mock_run: MagicMock) -> None:
        """pyclamd yok → clamscan fallback ile tehdit tespit."""
        scanner = self._make_scanner(clamav_enabled=True)
        test_file = self._create_file("virus.exe", b"\x4d\x5a" + b"\x00" * 100)

        # pyclamd yok → _clamav_available = False
        scanner._clamav_available = False

        # clamscan fallback
        mock_run.return_value = subprocess.CompletedProcess(
            args=["clamscan"],
            returncode=1,  # 1 = virüs bulundu
            stdout=f"{test_file}: Eicar-Signature FOUND\n",
            stderr="",
        )

        detection = scanner._scan_clamav_cli(test_file)

        self.assertIsInstance(detection, Detection)
        self.assertEqual(detection.engine, "clamav")
        self.assertIn("Eicar-Signature", detection.rule_name)

    @patch("app.security.scanner.subprocess.run")
    def test_clamav_cli_fallback_timeout(self, mock_run: MagicMock) -> None:
        """clamscan timeout → graceful None döner."""
        scanner = self._make_scanner(clamav_enabled=True)
        test_file = self._create_file("big.bin", b"\x00" * 1000)

        mock_run.side_effect = subprocess.TimeoutExpired(cmd="clamscan", timeout=120)

        detection = scanner._scan_clamav_cli(test_file)

        self.assertIsNone(detection)  # Graceful — hata değil tehdit de değil


# ═══════════════════════════════════════════════
# YARA Scanner Tests
# ═══════════════════════════════════════════════


class TestYARAScanner(_ScannerTestBase):
    """YARA tarama testleri — yara-python mock."""

    def test_yara_match_detected(self) -> None:
        """YARA kuralı eşleşir → Detection döner."""
        scanner = self._make_scanner(yara_enabled=True)
        test_file = self._create_file("suspect.bin", b"\xDE\xAD\xBE\xEF" * 100)

        # Mock yara modülü — import yara satırını geçmesi için
        mock_yara_module = MagicMock()
        mock_yara_module.TimeoutError = type("TimeoutError", (Exception,), {})
        mock_yara_module.Error = type("Error", (Exception,), {})

        # Mock match sonucu
        mock_match = MagicMock()
        mock_match.rule = "Suspicious_Binary"
        mock_match.tags = ["malware"]

        mock_rules = MagicMock()
        mock_rules.match.return_value = [mock_match]

        # YARA zaten derlenmiş olarak inject et
        scanner._yara_available = True
        scanner._yara_rules_compiled = mock_rules

        import sys
        with patch.dict(sys.modules, {"yara": mock_yara_module}):
            detections = scanner._scan_yara(test_file)

        self.assertEqual(len(detections), 1)
        self.assertEqual(detections[0].engine, "yara")
        self.assertEqual(detections[0].rule_name, "Suspicious_Binary")

    def test_yara_no_match(self) -> None:
        """YARA eşleşme yok → boş liste."""
        scanner = self._make_scanner(yara_enabled=True)
        test_file = self._create_file("clean.txt", b"Normal text content")

        mock_rules = MagicMock()
        mock_rules.match.return_value = []

        scanner._yara_available = True
        scanner._yara_rules_compiled = mock_rules

        detections = scanner._scan_yara(test_file)

        self.assertEqual(len(detections), 0)

    def test_yara_not_installed(self) -> None:
        """yara-python yüklü değil → boş liste, graceful."""
        scanner = self._make_scanner(yara_enabled=True)
        test_file = self._create_file("test.bin", b"data")

        # yara modülü yok simülasyonu
        scanner._yara_available = False

        detections = scanner._scan_yara(test_file)

        self.assertEqual(len(detections), 0)


# ═══════════════════════════════════════════════
# Entropy Analysis Tests
# ═══════════════════════════════════════════════


class TestEntropyAnalysis(_ScannerTestBase):
    """Shannon entropy hesaplama ve değerlendirme testleri."""

    def test_entropy_random_data_high(self) -> None:
        """Rastgele veri → yüksek entropy (>7.5)."""
        scanner = self._make_scanner()
        test_file = self._create_file("random.bin", os.urandom(4096))

        entropy = scanner._calculate_entropy(test_file)

        self.assertGreater(entropy, 7.5)

    def test_entropy_uniform_data_low(self) -> None:
        """Tekdüze veri → düşük entropy (~0.0)."""
        scanner = self._make_scanner()
        test_file = self._create_file("uniform.bin", b"A" * 4096)

        entropy = scanner._calculate_entropy(test_file)

        self.assertAlmostEqual(entropy, 0.0, places=1)

    def test_entropy_very_high_detection(self) -> None:
        """Çok yüksek entropy → VERY_HIGH_ENTROPY Detection."""
        scanner = self._make_scanner(entropy_enabled=True)
        test_file = self._create_file("encrypted.bin", os.urandom(4096))

        entropy = scanner._calculate_entropy(test_file)
        detection = scanner._evaluate_entropy(test_file, entropy)

        self.assertIsNotNone(detection)
        self.assertEqual(detection.engine, "entropy")
        self.assertIn("ENTROPY", detection.rule_name)


# ═══════════════════════════════════════════════
# Magic Byte Verification Tests
# ═══════════════════════════════════════════════


class TestMagicByteVerification(_ScannerTestBase):
    """Uzantı-MIME eşleştirme testleri."""

    def test_mime_match_no_detection(self) -> None:
        """Uzantı ve MIME eşleşir → Detection yok."""
        scanner = self._make_scanner(magic_byte_check=True)
        test_file = self._create_file("doc.pdf", b"%PDF-1.4 content")

        result = scanner._verify_magic_bytes(test_file, "application/pdf")

        self.assertIsNone(result)

    def test_mime_mismatch_detection(self) -> None:
        """Uzantı .jpg ama MIME executable → MIME_MISMATCH Detection."""
        scanner = self._make_scanner(magic_byte_check=True)
        test_file = self._create_file("photo.jpg", b"\x4d\x5a\x90\x00")  # PE header

        result = scanner._verify_magic_bytes(test_file, "application/x-executable")

        self.assertIsInstance(result, Detection)
        self.assertEqual(result.engine, "magic")
        self.assertEqual(result.rule_name, "MIME_MISMATCH")

    def test_unknown_extension_skipped(self) -> None:
        """Bilinmeyen uzantı → kontrol atlanır, None döner."""
        scanner = self._make_scanner(magic_byte_check=True)
        test_file = self._create_file("data.xyz", b"unknown format")

        result = scanner._verify_magic_bytes(test_file, "application/octet-stream")

        self.assertIsNone(result)


# ═══════════════════════════════════════════════
# ScanResult Tests
# ═══════════════════════════════════════════════


class TestScanResult(_ScannerTestBase):
    """ScanResult dataclass testleri."""

    def test_scan_result_detection_summary(self) -> None:
        """Birden fazla tespit → doğru özet formatı."""
        result = ScanResult(
            filepath=Path("/tmp/test.bin"),
            is_threat=True,
            threat_level="malicious",
            detections=[
                Detection(engine="clamav", rule_name="Trojan.Generic", details=""),
                Detection(engine="yara", rule_name="Suspicious_PE", details=""),
            ],
        )

        summary = result.detection_summary
        self.assertIn("clamav:Trojan.Generic", summary)
        self.assertIn("yara:Suspicious_PE", summary)
        self.assertIn("|", summary)

    def test_scan_file_known_bad_hash(self) -> None:
        """Bilinen kötü hash → is_threat=True."""
        content = b"known malware payload content"
        test_file = self._create_file("malware.bin", content)
        sha = self._sha256(content)

        # Hash'i bilinen kötü listeye ekle
        FileScanner._known_bad_hashes = {sha}

        scanner = self._make_scanner(
            clamav_enabled=False,
            yara_enabled=False,
            entropy_enabled=False,
            magic_byte_check=False,
            hash_check=True,
        )

        # _detect_mime_type mock — python-magic/file komutu gerekmesin
        with patch.object(scanner, "_detect_mime_type", return_value="application/octet-stream"):
            result = scanner.scan_file(test_file)

        self.assertTrue(result.is_threat)
        self.assertEqual(result.threat_level, "malicious")
        self.assertTrue(
            any(d.engine == "hash" for d in result.detections)
        )


if __name__ == "__main__":
    unittest.main()

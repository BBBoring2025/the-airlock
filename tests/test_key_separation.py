"""
THE AIRLOCK v5.1.1 FORTRESS-HARDENED — Key Separation Tests

İki bağımsız Ed25519 keypair'in birbirinden izole olduğunu doğrular.
Temel güvenlik prensibi: cihaz ele geçirilmesi ≠ filo ele geçirilmesi.

Test edilenler:
  1. Rapor ve güncelleme anahtarları FARKLI olmalı
  2. Rapor anahtarı ile güncelleme imzası DOĞRULANAMAMALI
  3. Güncelleme anahtarı ile rapor imzası DOĞRULANAMAMALI
  4. Doğru rapor imzalama çalışmalı
  5. Doğru güncelleme imzalama çalışmalı

Kullanım:
    python -m pytest tests/test_key_separation.py -v
"""

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

try:
    from nacl.signing import SigningKey  # noqa: PLC0415,F401
    HAS_NACL = True
except ImportError:
    HAS_NACL = False

from app.utils.crypto import generate_keypair, sign_data, verify_signature


@unittest.skipUnless(HAS_NACL, "PyNaCl required for key separation tests")
class TestKeySeparation(unittest.TestCase):
    """Ed25519 anahtar ayrımı testleri — iki bağımsız keypair."""

    def setUp(self) -> None:
        """İki ayrı keypair üret — tempdir'de."""
        self.tmpdir = tempfile.mkdtemp(prefix="airlock_keysep_test_")
        self.keys_dir = Path(self.tmpdir)

        # Rapor keypair
        self.report_private_path = self.keys_dir / "report_signing.key"
        self.report_public_path = self.keys_dir / "report_verify.pub"
        self.report_priv_bytes, self.report_pub_bytes = generate_keypair(
            private_key_path=self.report_private_path,
            public_key_path=self.report_public_path,
        )

        # Güncelleme keypair
        self.update_private_path = self.keys_dir / "update_signing.key"
        self.update_public_path = self.keys_dir / "update_verify.pub"
        self.update_priv_bytes, self.update_pub_bytes = generate_keypair(
            private_key_path=self.update_private_path,
            public_key_path=self.update_public_path,
        )

        # Test verisi
        self.test_data = b'{"session": "test", "files_processed": 42}'

    def tearDown(self) -> None:
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_report_and_update_keys_are_different(self) -> None:
        """İki keypair'in açık anahtarları FARKLI olmalı."""
        self.assertNotEqual(
            self.report_pub_bytes,
            self.update_pub_bytes,
            "Rapor ve güncelleme açık anahtarları AYNI — ayrım yok!",
        )
        self.assertNotEqual(
            self.report_priv_bytes,
            self.update_priv_bytes,
            "Rapor ve güncelleme özel anahtarları AYNI — ayrım yok!",
        )

    def test_report_key_cannot_forge_update(self) -> None:
        """Rapor anahtarı ile imzalanan veri, güncelleme anahtarı ile DOĞRULANAMAMALI."""
        # Rapor anahtarıyla imzala
        signature = sign_data(self.test_data, self.report_private_path)

        # Güncelleme açık anahtarıyla doğrulamaya çalış → BAŞARISIZ olmalı
        result = verify_signature(
            self.test_data, signature, self.update_public_path
        )
        self.assertFalse(
            result,
            "Rapor anahtarı ile güncelleme imzası doğrulandı — KRİTİK GÜVENLİK AÇIĞI!",
        )

    def test_update_key_cannot_forge_report(self) -> None:
        """Güncelleme anahtarı ile imzalanan veri, rapor anahtarı ile DOĞRULANAMAMALI."""
        # Güncelleme anahtarıyla imzala
        signature = sign_data(self.test_data, self.update_private_path)

        # Rapor açık anahtarıyla doğrulamaya çalış → BAŞARISIZ olmalı
        result = verify_signature(
            self.test_data, signature, self.report_public_path
        )
        self.assertFalse(
            result,
            "Güncelleme anahtarı ile rapor imzası doğrulandı — KRİTİK GÜVENLİK AÇIĞI!",
        )

    def test_correct_report_signing_works(self) -> None:
        """Rapor anahtarı ile imzala → rapor açık anahtarı ile doğrula → True."""
        signature = sign_data(self.test_data, self.report_private_path)

        result = verify_signature(
            self.test_data, signature, self.report_public_path
        )
        self.assertTrue(
            result,
            "Doğru rapor imzalama/doğrulama çalışmıyor!",
        )

    def test_correct_update_signing_works(self) -> None:
        """Güncelleme anahtarı ile imzala → güncelleme açık anahtarı ile doğrula → True."""
        signature = sign_data(self.test_data, self.update_private_path)

        result = verify_signature(
            self.test_data, signature, self.update_public_path
        )
        self.assertTrue(
            result,
            "Doğru güncelleme imzalama/doğrulama çalışmıyor!",
        )


if __name__ == "__main__":
    unittest.main()

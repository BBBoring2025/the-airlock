"""
THE AIRLOCK v5.0.8 FORTRESS-HARDENED — PolicyEngine Unit Tests

Test edilenler:
  1. Tehdit → her zaman QUARANTINE
  2. Arşiv → policy.archive_handling'e göre BLOCK/COPY
  3. Tehlikeli uzantı → BLOCK
  4. PDF/Office CDR desteği → CDR_DOCUMENT (izin varsa)
  5. PDF/Office engelli → BLOCK
  6. Resim → CDR_IMAGE / BLOCK
  7. Metin → CDR_TEXT / BLOCK
  8. Bilinmeyen tür → policy.unknown_extension'a göre
  9. 3 politika modu: paranoid, balanced, convenient
  10. CDR kullanılamaz durum → cdr_on_failure politikası

Kullanım:
    python -m pytest tests/test_policy_engine.py -v
    python -m unittest tests.test_policy_engine -v
"""

from __future__ import annotations

import unittest

from app.config import SecurityPolicy
from app.security.policy_engine import FileAction, decide_file_action


def _policy(**overrides: object) -> SecurityPolicy:
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
        "allow_office": True,
    }
    defaults.update(overrides)
    return SecurityPolicy(**defaults)


class TestThreatAlwaysQuarantine(unittest.TestCase):
    """Kural 1: Tehdit → her zaman QUARANTINE."""

    def test_threat_pdf(self) -> None:
        """PDF tehdit → QUARANTINE."""
        action = decide_file_action(
            is_threat=True,
            mime_type="application/pdf",
            extension=".pdf",
            policy=_policy(),
        )
        self.assertEqual(action, FileAction.QUARANTINE)

    def test_threat_image(self) -> None:
        """Resim tehdit → QUARANTINE."""
        action = decide_file_action(
            is_threat=True,
            mime_type="image/jpeg",
            extension=".jpg",
            policy=_policy(),
        )
        self.assertEqual(action, FileAction.QUARANTINE)

    def test_threat_text(self) -> None:
        """Metin tehdit → QUARANTINE."""
        action = decide_file_action(
            is_threat=True,
            mime_type="text/plain",
            extension=".txt",
            policy=_policy(),
        )
        self.assertEqual(action, FileAction.QUARANTINE)

    def test_threat_unknown(self) -> None:
        """Bilinmeyen tür tehdit → QUARANTINE."""
        action = decide_file_action(
            is_threat=True,
            mime_type="application/octet-stream",
            extension=".bin",
            policy=_policy(),
        )
        self.assertEqual(action, FileAction.QUARANTINE)


class TestArchiveHandling(unittest.TestCase):
    """Kural 2: Arşiv → policy.archive_handling'e göre."""

    def test_archive_block(self) -> None:
        """archive_handling=block → BLOCK."""
        action = decide_file_action(
            is_threat=False,
            mime_type="application/zip",
            extension=".zip",
            policy=_policy(archive_handling="block"),
            is_archive=True,
        )
        self.assertEqual(action, FileAction.BLOCK)

    def test_archive_extract(self) -> None:
        """archive_handling=extract → COPY (daemon açıp işleyecek)."""
        action = decide_file_action(
            is_threat=False,
            mime_type="application/zip",
            extension=".zip",
            policy=_policy(archive_handling="extract"),
            is_archive=True,
        )
        self.assertEqual(action, FileAction.COPY)

    def test_archive_not_flagged_but_mime_detected(self) -> None:
        """is_archive=False olsa bile arşiv MIME türü arşiv politikasına tabi."""
        action = decide_file_action(
            is_threat=False,
            mime_type="application/zip",
            extension=".zip",
            policy=_policy(archive_handling="block"),
            is_archive=False,
        )
        # Arşiv MIME tespit edildi → archive_handling politikası uygulanır
        self.assertEqual(action, FileAction.BLOCK)

    def test_archive_mime_extract_policy(self) -> None:
        """Arşiv MIME + archive_handling=extract → COPY."""
        action = decide_file_action(
            is_threat=False,
            mime_type="application/zip",
            extension=".zip",
            policy=_policy(archive_handling="extract"),
            is_archive=False,
        )
        self.assertEqual(action, FileAction.COPY)


class TestDangerousExtension(unittest.TestCase):
    """Kural 3: Tehlikeli uzantı → BLOCK."""

    def test_exe_blocked(self) -> None:
        """.exe → BLOCK."""
        action = decide_file_action(
            is_threat=False,
            mime_type="application/x-executable",
            extension=".exe",
            policy=_policy(),
        )
        self.assertEqual(action, FileAction.BLOCK)

    def test_bat_blocked(self) -> None:
        """.bat → BLOCK."""
        action = decide_file_action(
            is_threat=False,
            mime_type="text/plain",
            extension=".bat",
            policy=_policy(),
        )
        self.assertEqual(action, FileAction.BLOCK)

    def test_ps1_blocked(self) -> None:
        """.ps1 → BLOCK."""
        action = decide_file_action(
            is_threat=False,
            mime_type="text/plain",
            extension=".ps1",
            policy=_policy(),
        )
        self.assertEqual(action, FileAction.BLOCK)

    def test_docm_blocked(self) -> None:
        """.docm (macro Office) → BLOCK."""
        action = decide_file_action(
            is_threat=False,
            mime_type="application/vnd.ms-word.document.macroEnabled.12",
            extension=".docm",
            policy=_policy(),
        )
        self.assertEqual(action, FileAction.BLOCK)

    def test_iso_blocked(self) -> None:
        """.iso (disk image) → BLOCK."""
        action = decide_file_action(
            is_threat=False,
            mime_type="application/x-iso9660-image",
            extension=".iso",
            policy=_policy(),
        )
        self.assertEqual(action, FileAction.BLOCK)


class TestCDRDocument(unittest.TestCase):
    """Kural 4: CDR desteklenen doküman (PDF/Office)."""

    def test_pdf_cdr(self) -> None:
        """PDF + allow_pdf=True + cdr_available → CDR_DOCUMENT."""
        action = decide_file_action(
            is_threat=False,
            mime_type="application/pdf",
            extension=".pdf",
            policy=_policy(allow_pdf=True),
            cdr_available=True,
        )
        self.assertEqual(action, FileAction.CDR_DOCUMENT)

    def test_pdf_blocked_by_policy(self) -> None:
        """PDF + allow_pdf=False → BLOCK."""
        action = decide_file_action(
            is_threat=False,
            mime_type="application/pdf",
            extension=".pdf",
            policy=_policy(allow_pdf=False),
        )
        self.assertEqual(action, FileAction.BLOCK)

    def test_office_docx_cdr(self) -> None:
        """DOCX + allow_office=True → CDR_DOCUMENT."""
        action = decide_file_action(
            is_threat=False,
            mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            extension=".docx",
            policy=_policy(allow_office=True),
            cdr_available=True,
        )
        self.assertEqual(action, FileAction.CDR_DOCUMENT)

    def test_office_blocked_by_policy(self) -> None:
        """Office + allow_office=False → BLOCK."""
        action = decide_file_action(
            is_threat=False,
            mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            extension=".docx",
            policy=_policy(allow_office=False),
        )
        self.assertEqual(action, FileAction.BLOCK)

    def test_pdf_no_cdr_quarantine(self) -> None:
        """PDF + cdr_available=False + cdr_on_failure=quarantine → QUARANTINE."""
        action = decide_file_action(
            is_threat=False,
            mime_type="application/pdf",
            extension=".pdf",
            policy=_policy(allow_pdf=True, cdr_on_failure="quarantine"),
            cdr_available=False,
        )
        self.assertEqual(action, FileAction.QUARANTINE)

    def test_pdf_no_cdr_block(self) -> None:
        """PDF + cdr_available=False + cdr_on_failure=block → BLOCK."""
        action = decide_file_action(
            is_threat=False,
            mime_type="application/pdf",
            extension=".pdf",
            policy=_policy(allow_pdf=True, cdr_on_failure="block"),
            cdr_available=False,
        )
        self.assertEqual(action, FileAction.BLOCK)

    def test_pdf_no_cdr_copy(self) -> None:
        """PDF + cdr_available=False + cdr_on_failure=copy → COPY."""
        action = decide_file_action(
            is_threat=False,
            mime_type="application/pdf",
            extension=".pdf",
            policy=_policy(allow_pdf=True, cdr_on_failure="copy"),
            cdr_available=False,
        )
        self.assertEqual(action, FileAction.COPY)


class TestCDRImage(unittest.TestCase):
    """Kural 5: Resim → CDR_IMAGE / BLOCK."""

    def test_jpeg_cdr(self) -> None:
        """JPEG + allow_images=True → CDR_IMAGE."""
        action = decide_file_action(
            is_threat=False,
            mime_type="image/jpeg",
            extension=".jpg",
            policy=_policy(allow_images=True),
            cdr_available=True,
        )
        self.assertEqual(action, FileAction.CDR_IMAGE)

    def test_png_cdr(self) -> None:
        """PNG + allow_images=True → CDR_IMAGE."""
        action = decide_file_action(
            is_threat=False,
            mime_type="image/png",
            extension=".png",
            policy=_policy(allow_images=True),
            cdr_available=True,
        )
        self.assertEqual(action, FileAction.CDR_IMAGE)

    def test_image_blocked(self) -> None:
        """Resim + allow_images=False → BLOCK."""
        action = decide_file_action(
            is_threat=False,
            mime_type="image/jpeg",
            extension=".jpg",
            policy=_policy(allow_images=False),
        )
        self.assertEqual(action, FileAction.BLOCK)

    def test_image_no_cdr_copy(self) -> None:
        """Resim + cdr_available=False → COPY (graceful degrade)."""
        action = decide_file_action(
            is_threat=False,
            mime_type="image/jpeg",
            extension=".jpg",
            policy=_policy(allow_images=True),
            cdr_available=False,
        )
        self.assertEqual(action, FileAction.COPY)


class TestCDRText(unittest.TestCase):
    """Kural 6: Metin → CDR_TEXT / BLOCK."""

    def test_plain_text_cdr(self) -> None:
        """text/plain → CDR_TEXT."""
        action = decide_file_action(
            is_threat=False,
            mime_type="text/plain",
            extension=".txt",
            policy=_policy(allow_text=True),
        )
        self.assertEqual(action, FileAction.CDR_TEXT)

    def test_csv_cdr(self) -> None:
        """text/csv → CDR_TEXT."""
        action = decide_file_action(
            is_threat=False,
            mime_type="text/csv",
            extension=".csv",
            policy=_policy(allow_text=True),
        )
        self.assertEqual(action, FileAction.CDR_TEXT)

    def test_json_cdr(self) -> None:
        """application/json → CDR_TEXT."""
        action = decide_file_action(
            is_threat=False,
            mime_type="application/json",
            extension=".json",
            policy=_policy(allow_text=True),
        )
        self.assertEqual(action, FileAction.CDR_TEXT)

    def test_xml_cdr(self) -> None:
        """text/xml → CDR_TEXT."""
        action = decide_file_action(
            is_threat=False,
            mime_type="text/xml",
            extension=".xml",
            policy=_policy(allow_text=True),
        )
        self.assertEqual(action, FileAction.CDR_TEXT)

    def test_text_blocked(self) -> None:
        """Metin + allow_text=False → BLOCK."""
        action = decide_file_action(
            is_threat=False,
            mime_type="text/plain",
            extension=".txt",
            policy=_policy(allow_text=False),
        )
        self.assertEqual(action, FileAction.BLOCK)


class TestUnknownType(unittest.TestCase):
    """Kural 7: Bilinmeyen tür → policy.unknown_extension'a göre."""

    def test_unknown_block(self) -> None:
        """unknown_extension=block → BLOCK."""
        action = decide_file_action(
            is_threat=False,
            mime_type="application/octet-stream",
            extension=".xyz",
            policy=_policy(unknown_extension="block"),
        )
        self.assertEqual(action, FileAction.BLOCK)

    def test_unknown_quarantine(self) -> None:
        """unknown_extension=quarantine → QUARANTINE."""
        action = decide_file_action(
            is_threat=False,
            mime_type="application/octet-stream",
            extension=".xyz",
            policy=_policy(unknown_extension="quarantine"),
        )
        self.assertEqual(action, FileAction.QUARANTINE)

    def test_unknown_allow(self) -> None:
        """unknown_extension=allow → COPY."""
        action = decide_file_action(
            is_threat=False,
            mime_type="application/octet-stream",
            extension=".xyz",
            policy=_policy(unknown_extension="allow"),
        )
        self.assertEqual(action, FileAction.COPY)

    def test_unknown_copy_with_warning(self) -> None:
        """unknown_extension=copy_with_warning → COPY (allow gibi davranır)."""
        action = decide_file_action(
            is_threat=False,
            mime_type="application/octet-stream",
            extension=".xyz",
            policy=_policy(unknown_extension="copy_with_warning"),
        )
        self.assertEqual(action, FileAction.COPY)


class TestParanoidPolicy(unittest.TestCase):
    """PARANOID politikası senaryoları."""

    def _paranoid_policy(self) -> SecurityPolicy:
        return SecurityPolicy(
            name="paranoid",
            cdr_on_failure="quarantine",
            unknown_extension="block",
            archive_handling="block",
            max_file_size_mb=100,
            entropy_threshold=7.0,
            ocr_enabled=False,
            allow_images=True,
            allow_text=True,
            allow_pdf=True,
            allow_office=False,  # Office kapalı
        )

    def test_office_blocked_in_paranoid(self) -> None:
        """PARANOID modda Office dosyaları BLOCK."""
        policy = self._paranoid_policy()
        action = decide_file_action(
            is_threat=False,
            mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            extension=".docx",
            policy=policy,
        )
        self.assertEqual(action, FileAction.BLOCK)

    def test_archive_blocked_in_paranoid(self) -> None:
        """PARANOID modda arşivler BLOCK."""
        policy = self._paranoid_policy()
        action = decide_file_action(
            is_threat=False,
            mime_type="application/zip",
            extension=".zip",
            policy=policy,
            is_archive=True,
        )
        self.assertEqual(action, FileAction.BLOCK)

    def test_unknown_blocked_in_paranoid(self) -> None:
        """PARANOID modda bilinmeyen türler BLOCK."""
        policy = self._paranoid_policy()
        action = decide_file_action(
            is_threat=False,
            mime_type="application/octet-stream",
            extension=".strange",
            policy=policy,
        )
        self.assertEqual(action, FileAction.BLOCK)

    def test_pdf_cdr_in_paranoid(self) -> None:
        """PARANOID modda PDF CDR uygulanmalı (izin var)."""
        policy = self._paranoid_policy()
        action = decide_file_action(
            is_threat=False,
            mime_type="application/pdf",
            extension=".pdf",
            policy=policy,
            cdr_available=True,
        )
        self.assertEqual(action, FileAction.CDR_DOCUMENT)


class TestBalancedPolicy(unittest.TestCase):
    """BALANCED politikası senaryoları."""

    def _balanced_policy(self) -> SecurityPolicy:
        return SecurityPolicy(
            name="balanced",
            cdr_on_failure="quarantine",
            unknown_extension="copy_with_warning",
            archive_handling="scan_and_extract",
            max_file_size_mb=500,
            entropy_threshold=7.5,
            ocr_enabled=True,
            allow_images=True,
            allow_text=True,
            allow_pdf=True,
            allow_office=True,
        )

    def test_office_allowed_in_balanced(self) -> None:
        """BALANCED modda Office CDR uygulanmalı."""
        policy = self._balanced_policy()
        action = decide_file_action(
            is_threat=False,
            mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            extension=".docx",
            policy=policy,
            cdr_available=True,
        )
        self.assertEqual(action, FileAction.CDR_DOCUMENT)

    def test_unknown_copy_in_balanced(self) -> None:
        """BALANCED modda bilinmeyen türler COPY."""
        policy = self._balanced_policy()
        action = decide_file_action(
            is_threat=False,
            mime_type="application/octet-stream",
            extension=".custom",
            policy=policy,
        )
        self.assertEqual(action, FileAction.COPY)


class TestConvenientPolicy(unittest.TestCase):
    """CONVENIENT politikası senaryoları."""

    def _convenient_policy(self) -> SecurityPolicy:
        return SecurityPolicy(
            name="convenient",
            cdr_on_failure="copy_unsanitized_folder",
            unknown_extension="copy_with_warning",
            archive_handling="scan_and_extract",
            max_file_size_mb=2048,
            entropy_threshold=7.9,
            ocr_enabled=True,
            allow_images=True,
            allow_text=True,
            allow_pdf=True,
            allow_office=True,
        )

    def test_cdr_failure_copy_in_convenient(self) -> None:
        """CONVENIENT modda CDR başarısız → COPY (cdr_on_failure=copy_unsanitized_folder)."""
        policy = self._convenient_policy()
        action = decide_file_action(
            is_threat=False,
            mime_type="application/pdf",
            extension=".pdf",
            policy=policy,
            cdr_available=False,
        )
        self.assertEqual(action, FileAction.COPY)

    def test_threat_still_quarantine_in_convenient(self) -> None:
        """CONVENIENT modda bile tehdit → QUARANTINE."""
        policy = self._convenient_policy()
        action = decide_file_action(
            is_threat=True,
            mime_type="application/pdf",
            extension=".pdf",
            policy=policy,
        )
        self.assertEqual(action, FileAction.QUARANTINE)

    def test_dangerous_ext_still_blocked(self) -> None:
        """CONVENIENT modda bile tehlikeli uzantı → BLOCK."""
        policy = self._convenient_policy()
        action = decide_file_action(
            is_threat=False,
            mime_type="application/x-executable",
            extension=".exe",
            policy=policy,
        )
        self.assertEqual(action, FileAction.BLOCK)


class TestRulePriority(unittest.TestCase):
    """Kural öncelik sırası testleri."""

    def test_threat_overrides_cdr(self) -> None:
        """Tehdit CDR'dan önce gelir."""
        action = decide_file_action(
            is_threat=True,
            mime_type="application/pdf",
            extension=".pdf",
            policy=_policy(allow_pdf=True),
            cdr_available=True,
        )
        # PDF CDR yerine QUARANTINE olmalı
        self.assertEqual(action, FileAction.QUARANTINE)

    def test_archive_before_dangerous_ext(self) -> None:
        """Arşiv kuralı tehlikeli uzantıdan önce gelir."""
        action = decide_file_action(
            is_threat=False,
            mime_type="application/zip",
            extension=".zip",
            policy=_policy(archive_handling="extract"),
            is_archive=True,
        )
        # .zip tehlikeli uzantıda değil ama arşiv kuralından COPY olmalı
        self.assertEqual(action, FileAction.COPY)

    def test_dangerous_ext_before_cdr(self) -> None:
        """Tehlikeli uzantı CDR'dan önce gelir."""
        # .docm hem Office MIME'a benzeyebilir hem tehlikeli uzantı
        action = decide_file_action(
            is_threat=False,
            mime_type="application/vnd.ms-word.document.macroEnabled.12",
            extension=".docm",
            policy=_policy(allow_office=True),
            cdr_available=True,
        )
        self.assertEqual(action, FileAction.BLOCK)


if __name__ == "__main__":
    unittest.main()

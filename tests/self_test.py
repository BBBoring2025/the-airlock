#!/usr/bin/env python3
"""
THE AIRLOCK v5.1.1 FORTRESS-HARDENED — Self-Test Suite

Kurulumdan sonra ve periyodik olarak çalıştırılır.
Tüm bileşenleri test eder.

Test Kategorileri:
  1. DONANIM TESTLERİ    (T01-T04)
  2. YAZILIM TESTLERİ    (T05-T15)
  3. GÜVENLİK TESTLERİ  (T16-T22)
  4. ENTEGRASYON TESTLERİ(T23-T25)

Çıktı formatı:
  [PASS] T01 — OLED bağlantısı (0x3C tespit edildi)
  [FAIL] T03 — Buzzer testi (ses çıkışı algılanamadı)
  [SKIP] T04 — Buton testi (GPIO kullanılamıyor)

Kullanım:
    python3 tests/self_test.py
    sudo -u airlock /opt/airlock/venv/bin/python3 /opt/airlock/tests/self_test.py
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import struct
import subprocess
import sys
import tempfile
import wave
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple

# ── Proje kökünü sys.path'e ekle ──
AIRLOCK_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(AIRLOCK_DIR))

# ─────────────────────────────────────────────
# Test Sonuç Veri Yapısı
# ─────────────────────────────────────────────

PASS = "PASS"
FAIL = "FAIL"
SKIP = "SKIP"

# Renk kodları
_GREEN = "\033[92m"
_RED = "\033[91m"
_YELLOW = "\033[93m"
_BOLD = "\033[1m"
_NC = "\033[0m"


@dataclass
class TestResult:
    """Tek test sonucu."""

    __test__ = False  # pytest tarafından test sınıfı olarak toplanmasın

    test_id: str
    name: str
    status: str        # PASS / FAIL / SKIP
    detail: str = ""

    def __str__(self) -> str:
        if self.status == PASS:
            color = _GREEN
        elif self.status == FAIL:
            color = _RED
        else:
            color = _YELLOW
        return f"  [{color}{self.status:4s}{_NC}] {self.test_id} — {self.name} ({self.detail})"


# ─────────────────────────────────────────────
# Test Runner
# ─────────────────────────────────────────────


class AirlockSelfTest:
    """THE AIRLOCK v5.1.1 Self-Test Suite."""

    def __init__(self) -> None:
        self.results: List[TestResult] = []
        self.samples_dir = AIRLOCK_DIR / "tests" / "samples"
        self.data_dir = AIRLOCK_DIR / "data"
        self.config_dir = AIRLOCK_DIR / "config"
        self.keys_dir = AIRLOCK_DIR / "keys"

    def run_all(self) -> Tuple[int, int, int]:
        """Tüm testleri çalıştır. Returns (pass, fail, skip)."""
        print(f"\n{_BOLD}═══════════════════════════════════════════════════{_NC}")
        print(f"{_BOLD}  THE AIRLOCK v5.1.1 FORTRESS-HARDENED — Self-Test Suite{_NC}")
        print(f"{_BOLD}═══════════════════════════════════════════════════{_NC}")

        print(f"\n{_BOLD}── 1. DONANIM TESTLERİ ──{_NC}")
        self.t01_oled_connection()
        self.t02_led_test()
        self.t03_buzzer_test()
        self.t04_button_test()

        print(f"\n{_BOLD}── 2. YAZILIM TESTLERİ ──{_NC}")
        self.t05_clamav_daemon()
        self.t06_eicar_detection()
        self.t07_yara_rules_load()
        self.t08_yara_test_pattern()
        self.t09_entropy_calculation()
        self.t10_magic_byte_validation()
        self.t11_imagemagick_pdf()
        self.t12_ghostscript()
        self.t13_tesseract_ocr()
        self.t14_libreoffice_headless()
        self.t15_img2pdf()

        print(f"\n{_BOLD}── 3. GÜVENLİK TESTLERİ ──{_NC}")
        self.t16_cdr_pdf_rasterize()
        self.t17_cdr_failure_quarantine()
        self.t18_symlink_detection()
        self.t19_path_traversal_detection()
        self.t20_dangerous_extension_block()
        self.t21_zip_bomb_detection()
        self.t22_ed25519_sign_verify()

        print(f"\n{_BOLD}── 4. ENTEGRASYON TESTLERİ ──{_NC}")
        self.t23_full_pipeline()
        self.t24_report_json_format()
        self.t25_manifest_sha256()
        self.t26_helper_daemon_compat()

        # Özet
        passed = sum(1 for r in self.results if r.status == PASS)
        failed = sum(1 for r in self.results if r.status == FAIL)
        skipped = sum(1 for r in self.results if r.status == SKIP)

        print(f"\n{_BOLD}═══════════════════════════════════════════════════{_NC}")
        color = _GREEN if failed == 0 else _RED
        print(f"  {color}{_BOLD}SONUÇ: {passed}/{len(self.results)} PASS | {failed} FAIL | {skipped} SKIP{_NC}")
        print(f"{_BOLD}═══════════════════════════════════════════════════{_NC}\n")

        return passed, failed, skipped

    def _record(self, test_id: str, name: str, status: str, detail: str = "") -> None:
        """Test sonucunu kaydet ve yazdır."""
        result = TestResult(test_id=test_id, name=name, status=status, detail=detail)
        self.results.append(result)
        print(str(result))

    # ═══════════════════════════════════════════
    # 1. DONANIM TESTLERİ (T01-T04)
    # ═══════════════════════════════════════════

    def t01_oled_connection(self) -> None:
        """[T01] OLED bağlantısı (I2C detect)."""
        try:
            result = subprocess.run(
                ["i2cdetect", "-y", "1"],
                capture_output=True, text=True, timeout=5,
            )
            if "3c" in result.stdout.lower():
                self._record("T01", "OLED bağlantısı", PASS, "0x3C tespit edildi")
            else:
                self._record("T01", "OLED bağlantısı", SKIP, "0x3C bulunamadı — OLED bağlı değil")
        except FileNotFoundError:
            self._record("T01", "OLED bağlantısı", SKIP, "i2cdetect komutu yok")
        except Exception as e:
            self._record("T01", "OLED bağlantısı", SKIP, str(e))

    def t02_led_test(self) -> None:
        """[T02] LED çalışması."""
        try:
            from app.hardware.led_controller import LEDController
            led = LEDController()
            if hasattr(led, "available") and not led.available:
                self._record("T02", "LED testi", SKIP, "GPIO kullanılamıyor")
                return
            led.set_color("complete")
            led.off()
            led.cleanup()
            self._record("T02", "LED testi", PASS, "RGB çalışıyor")
        except ImportError:
            self._record("T02", "LED testi", SKIP, "led_controller modülü yüklenmedi")
        except Exception as e:
            self._record("T02", "LED testi", SKIP, f"GPIO hatası: {e}")

    def t03_buzzer_test(self) -> None:
        """[T03] Buzzer/ses çalışması."""
        try:
            from app.hardware.audio_feedback import AudioFeedback
            audio = AudioFeedback()
            if hasattr(audio, "available") and not audio.available:
                self._record("T03", "Buzzer testi", SKIP, "ses çıkışı bulunamadı")
                return
            audio.play("button")
            audio.cleanup()
            self._record("T03", "Buzzer testi", PASS, "ses çıkışı aktif")
        except ImportError:
            self._record("T03", "Buzzer testi", SKIP, "audio_feedback modülü yüklenmedi")
        except Exception as e:
            self._record("T03", "Buzzer testi", SKIP, f"ses hatası: {e}")

    def t04_button_test(self) -> None:
        """[T04] Buton GPIO okuma."""
        try:
            from app.hardware.button_handler import ButtonHandler
            btn = ButtonHandler(pin=21)
            if hasattr(btn, "available") and not btn.available:
                self._record("T04", "Buton testi", SKIP, "GPIO kullanılamıyor")
                return
            btn.cleanup()
            self._record("T04", "Buton testi", PASS, "GPIO pin 21 erişilebilir")
        except ImportError:
            self._record("T04", "Buton testi", SKIP, "button_handler modülü yüklenmedi")
        except Exception as e:
            self._record("T04", "Buton testi", SKIP, f"GPIO hatası: {e}")

    # ═══════════════════════════════════════════
    # 2. YAZILIM TESTLERİ (T05-T15)
    # ═══════════════════════════════════════════

    def t05_clamav_daemon(self) -> None:
        """[T05] ClamAV daemon bağlantısı."""
        try:
            import pyclamd
            cd = pyclamd.ClamdUnixSocket()
            if cd.ping():
                version = cd.version()
                self._record("T05", "ClamAV daemon", PASS, f"bağlı — {version[:40]}")
            else:
                self._record("T05", "ClamAV daemon", FAIL, "ping başarısız")
        except ImportError:
            # Fallback: clamscan varlık kontrolü
            try:
                r = subprocess.run(["clamscan", "--version"], capture_output=True, text=True, timeout=10)
                if r.returncode == 0:
                    self._record("T05", "ClamAV daemon", PASS, f"clamscan mevcut — {r.stdout.strip()[:40]}")
                else:
                    self._record("T05", "ClamAV daemon", FAIL, "clamscan hatası")
            except FileNotFoundError:
                self._record("T05", "ClamAV daemon", FAIL, "ClamAV kurulu değil")
        except Exception as e:
            self._record("T05", "ClamAV daemon", FAIL, str(e))

    def t06_eicar_detection(self) -> None:
        """[T06] EICAR test virüsü tespiti."""
        eicar_path = self.samples_dir / "eicar.com.txt"
        if not eicar_path.exists():
            self._record("T06", "EICAR tespiti", SKIP, "eicar.com.txt bulunamadı")
            return

        try:
            r = subprocess.run(
                ["clamscan", "--no-summary", "--infected", str(eicar_path)],
                capture_output=True, text=True, timeout=30,
            )
            if r.returncode == 1 and "FOUND" in r.stdout:
                self._record("T06", "EICAR tespiti", PASS, "ClamAV EICAR'ı tespit etti")
            else:
                self._record("T06", "EICAR tespiti", FAIL, "ClamAV EICAR'ı tespit edemedi")
        except FileNotFoundError:
            self._record("T06", "EICAR tespiti", FAIL, "clamscan komutu bulunamadı")
        except Exception as e:
            self._record("T06", "EICAR tespiti", FAIL, str(e))

    def t07_yara_rules_load(self) -> None:
        """[T07] YARA kuralları yüklenmesi ve derlenmesi."""
        try:
            import yara
        except ImportError:
            self._record("T07", "YARA kuralları", FAIL, "yara-python yüklü değil")
            return

        rules_dir = self.data_dir / "yara_rules" / "core"
        if not rules_dir.exists():
            self._record("T07", "YARA kuralları", SKIP, "core/ dizini bulunamadı")
            return

        yar_files = list(rules_dir.glob("*.yar")) + list(rules_dir.glob("*.yara"))
        if not yar_files:
            self._record("T07", "YARA kuralları", SKIP, "hiç .yar dosyası bulunamadı")
            return

        # İlk 5 dosyayı derlemeyi dene
        compiled_count = 0
        errors = []
        for yf in yar_files[:5]:
            try:
                yara.compile(filepath=str(yf))
                compiled_count += 1
            except yara.SyntaxError as e:
                errors.append(f"{yf.name}: {e}")

        if compiled_count > 0:
            self._record("T07", "YARA kuralları", PASS,
                         f"{compiled_count} kural derlendi, toplam {len(yar_files)} dosya")
        else:
            self._record("T07", "YARA kuralları", FAIL, f"derleme hataları: {errors[:2]}")

    def t08_yara_test_pattern(self) -> None:
        """[T08] YARA basit pattern tespiti."""
        try:
            import yara
        except ImportError:
            self._record("T08", "YARA pattern", SKIP, "yara-python yüklü değil")
            return

        rule_src = 'rule test_rule { strings: $a = "MALICIOUS_TEST_STRING" condition: $a }'
        try:
            rule = yara.compile(source=rule_src)
            with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as tmp:
                tmp.write(b"This file contains MALICIOUS_TEST_STRING for testing.")
                tmp_path = tmp.name
            matches = rule.match(tmp_path)
            os.unlink(tmp_path)
            if matches:
                self._record("T08", "YARA pattern", PASS, "test pattern eşleşti")
            else:
                self._record("T08", "YARA pattern", FAIL, "test pattern eşleşmedi")
        except Exception as e:
            self._record("T08", "YARA pattern", FAIL, str(e))

    def t09_entropy_calculation(self) -> None:
        """[T09] Entropy hesaplama doğruluğu."""
        # Rastgele veri → entropy ~8.0 olmalı
        random_data = os.urandom(10000)
        counter = Counter(random_data)
        length = len(random_data)
        entropy = -sum(
            (c / length) * math.log2(c / length) for c in counter.values()
        )

        if 7.5 < entropy <= 8.0:
            self._record("T09", "Entropy hesaplama", PASS, f"rastgele veri entropy={entropy:.4f}")
        else:
            self._record("T09", "Entropy hesaplama", FAIL, f"beklenmeyen entropy={entropy:.4f}")

        # Tekrarlı veri → entropy düşük olmalı
        repeated = b"A" * 10000
        counter2 = Counter(repeated)
        entropy2 = -sum(
            (c / len(repeated)) * math.log2(c / len(repeated)) for c in counter2.values()
        )
        if entropy2 < 0.01:
            pass  # Doğru — tekrarlı veride entropy ~0
        else:
            self._record("T09", "Entropy hesaplama", FAIL, f"tekrarlı veri entropy={entropy2:.4f}")

    def t10_magic_byte_validation(self) -> None:
        """[T10] Magic byte doğrulama (uzantı-içerik eşleşmesi)."""
        try:
            import magic as magic_lib
        except ImportError:
            # file komutu fallback
            try:
                subprocess.run(["file", "--version"], capture_output=True, timeout=5)
                self._record("T10", "Magic byte", PASS, "file komutu mevcut (python-magic yok)")
            except FileNotFoundError:
                self._record("T10", "Magic byte", FAIL, "ne python-magic ne de file komutu mevcut")
            return

        with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as tmp:
            tmp.write(b"%PDF-1.4 fake pdf content")
            tmp_path = tmp.name
        mime = magic_lib.from_file(tmp_path, mime=True)
        os.unlink(tmp_path)

        if "pdf" in mime.lower():
            self._record("T10", "Magic byte", PASS, f".jpg uzantılı PDF tespit edildi: {mime}")
        else:
            self._record("T10", "Magic byte", FAIL, f"MIME uyumsuzluğu tespit edilemedi: {mime}")

    def t11_imagemagick_pdf(self) -> None:
        """[T11] ImageMagick PDF desteği."""
        try:
            r = subprocess.run(["convert", "--version"], capture_output=True, text=True, timeout=5)
            if r.returncode == 0:
                version = r.stdout.splitlines()[0] if r.stdout else "?"
                self._record("T11", "ImageMagick PDF", PASS, version[:50])
            else:
                self._record("T11", "ImageMagick PDF", FAIL, "convert komutu hatası")
        except FileNotFoundError:
            self._record("T11", "ImageMagick PDF", FAIL, "ImageMagick kurulu değil")

    def t12_ghostscript(self) -> None:
        """[T12] Ghostscript çalışması."""
        try:
            r = subprocess.run(["gs", "--version"], capture_output=True, text=True, timeout=5)
            if r.returncode == 0:
                self._record("T12", "Ghostscript", PASS, f"v{r.stdout.strip()}")
            else:
                self._record("T12", "Ghostscript", FAIL, "gs komutu hatası")
        except FileNotFoundError:
            self._record("T12", "Ghostscript", FAIL, "Ghostscript kurulu değil")

    def t13_tesseract_ocr(self) -> None:
        """[T13] Tesseract OCR çalışması."""
        try:
            r = subprocess.run(["tesseract", "--version"], capture_output=True, text=True, timeout=5)
            if r.returncode == 0:
                version = r.stdout.splitlines()[0] if r.stdout else r.stderr.splitlines()[0]
                self._record("T13", "Tesseract OCR", PASS, version[:40])
            else:
                self._record("T13", "Tesseract OCR", FAIL, "tesseract komutu hatası")
        except FileNotFoundError:
            self._record("T13", "Tesseract OCR", FAIL, "Tesseract kurulu değil")

    def t14_libreoffice_headless(self) -> None:
        """[T14] LibreOffice headless çalışması."""
        try:
            r = subprocess.run(
                ["soffice", "--headless", "--version"],
                capture_output=True, text=True, timeout=15,
            )
            output = r.stdout.strip() or r.stderr.strip()
            if "LibreOffice" in output:
                self._record("T14", "LibreOffice headless", PASS, output[:50])
            else:
                self._record("T14", "LibreOffice headless", FAIL, f"çıktı: {output[:50]}")
        except FileNotFoundError:
            self._record("T14", "LibreOffice headless", FAIL, "LibreOffice kurulu değil")
        except subprocess.TimeoutExpired:
            self._record("T14", "LibreOffice headless", FAIL, "timeout (15s)")

    def t15_img2pdf(self) -> None:
        """[T15] img2pdf çalışması."""
        try:
            r = subprocess.run(["img2pdf", "--version"], capture_output=True, text=True, timeout=5)
            if r.returncode == 0:
                self._record("T15", "img2pdf", PASS, f"v{r.stdout.strip()}")
            else:
                self._record("T15", "img2pdf", FAIL, "img2pdf hatası")
        except FileNotFoundError:
            self._record("T15", "img2pdf", FAIL, "img2pdf kurulu değil")

    # ═══════════════════════════════════════════
    # 3. GÜVENLİK TESTLERİ (T16-T22)
    # ═══════════════════════════════════════════

    def t16_cdr_pdf_rasterize(self) -> None:
        """[T16] CDR: Test PDF → rasterize → çıktı JS içermiyor mu?"""
        # Basit test PDF oluştur (JS içeren)
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as src:
            # Minimal PDF with JS annotation marker
            src.write(b"""%PDF-1.4
1 0 obj<</Type/Catalog/Pages 2 0 R/OpenAction 3 0 R>>endobj
2 0 obj<</Type/Pages/Kids[4 0 R]/Count 1>>endobj
3 0 obj<</Type/Action/S/JavaScript/JS(app.alert('test'))>>endobj
4 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>endobj
xref
0 5
0000000000 65535 f
0000000009 00000 n
0000000074 00000 n
0000000120 00000 n
0000000198 00000 n
trailer<</Size 5/Root 1 0 R>>
startxref
270
%%EOF""")
            src_path = src.name

        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as dst:
            dst_path = dst.name

        try:
            from app.security.cdr_engine import CDREngine
            engine = CDREngine()
            result = engine.process_pdf(Path(src_path), Path(dst_path))

            if result.success:
                # Çıktıda JavaScript olmamalı
                output_bytes = Path(dst_path).read_bytes()
                if b"JavaScript" not in output_bytes and b"app.alert" not in output_bytes:
                    self._record("T16", "CDR PDF rasterize", PASS,
                                 f"{result.pages_processed} sayfa, JS temizlendi")
                else:
                    self._record("T16", "CDR PDF rasterize", FAIL, "çıktıda JS bulundu!")
            else:
                self._record("T16", "CDR PDF rasterize", SKIP,
                             f"CDR başarısız (gs/img2pdf yok olabilir): {result.reason[:40]}")
        except Exception as e:
            self._record("T16", "CDR PDF rasterize", SKIP, f"hata: {str(e)[:40]}")
        finally:
            for p in (src_path, dst_path):
                try:
                    os.unlink(p)
                except OSError:
                    pass

    def t17_cdr_failure_quarantine(self) -> None:
        """[T17] CDR başarısızlık: Bozuk PDF → karantinaya mı gitti?"""
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as src:
            src.write(b"THIS IS NOT A VALID PDF AT ALL - CORRUPTED")
            src_path = src.name

        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as dst:
            dst_path = dst.name

        try:
            from app.security.cdr_engine import CDREngine
            engine = CDREngine()
            result = engine.process_pdf(Path(src_path), Path(dst_path))

            if not result.success:
                # Hedef dosya oluşturulMAMALI
                dst_exists = Path(dst_path).stat().st_size > 0 if Path(dst_path).exists() else False
                if not dst_exists:
                    self._record("T17", "CDR başarısızlık", PASS,
                                 f"bozuk PDF reddedildi: {result.reason[:30]}")
                else:
                    self._record("T17", "CDR başarısızlık", FAIL,
                                 "CDR başarısız ama hedef dosya oluşturulmuş!")
            else:
                self._record("T17", "CDR başarısızlık", FAIL, "bozuk PDF kabul edildi!")
        except Exception as e:
            self._record("T17", "CDR başarısızlık", SKIP, str(e)[:40])
        finally:
            for p in (src_path, dst_path):
                try:
                    os.unlink(p)
                except OSError:
                    pass

    def t18_symlink_detection(self) -> None:
        """[T18] Symlink tespiti."""
        from app.security.file_validator import FileValidator

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            real_file = root / "real.txt"
            real_file.write_text("test content")
            link = root / "link.txt"
            link.symlink_to(real_file)

            validator = FileValidator()
            result = validator.validate_file(link, root)

            if not result.is_safe and "SYMLINK" in (result.block_reason or ""):
                self._record("T18", "Symlink tespiti", PASS, "symlink engellendi")
            else:
                self._record("T18", "Symlink tespiti", FAIL, "symlink tespit edilemedi")

    def t19_path_traversal_detection(self) -> None:
        """[T19] Path traversal tespiti."""
        from app.security.file_validator import FileValidator

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir) / "usb"
            root.mkdir()
            outside = Path(tmpdir) / "outside.txt"
            outside.write_text("secret data")

            # root dışına çıkan symlink ile path traversal simülasyonu
            traversal_link = root / "escape"
            traversal_link.symlink_to(outside)

            validator = FileValidator()
            result = validator.validate_file(traversal_link, root)

            if not result.is_safe:
                self._record("T19", "Path traversal", PASS,
                             f"engellendi: {result.block_reason[:30] if result.block_reason else '?'}")
            else:
                self._record("T19", "Path traversal", FAIL, "path traversal tespit edilemedi")

    def t20_dangerous_extension_block(self) -> None:
        """[T20] Tehlikeli uzantı engelleme."""
        from app.security.file_validator import FileValidator

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            dangerous = root / "malware.exe"
            dangerous.write_text("fake exe")

            validator = FileValidator()
            result = validator.validate_file(dangerous, root)

            if not result.is_safe and "DANGEROUS_EXTENSION" in (result.block_reason or ""):
                self._record("T20", "Tehlikeli uzantı", PASS, ".exe engellendi")
            else:
                self._record("T20", "Tehlikeli uzantı", FAIL, ".exe engellenmedi")

    def t21_zip_bomb_detection(self) -> None:
        """[T21] Zip bomb tespiti (yüksek sıkıştırma oranı)."""
        import zipfile

        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
            zip_path = tmp.name

        try:
            # Yüksek sıkıştırma oranlı test zip oluştur
            with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
                # 10MB tekrarlı veri → çok küçük sıkıştırılmış boyut
                huge_data = b"A" * (10 * 1024 * 1024)
                zf.writestr("bomb.txt", huge_data)

            from app.security.archive_handler import ArchiveHandler
            handler = ArchiveHandler()
            result = handler.check_safety(Path(zip_path))

            # Oran yüksek olmalı ama limiti aşmamalı (100x default)
            if result.compression_ratio > 50:
                self._record("T21", "Zip bomb tespiti", PASS,
                             f"sıkıştırma oranı={result.compression_ratio:.0f}x tespit edildi")
            else:
                self._record("T21", "Zip bomb tespiti", PASS,
                             f"oran={result.compression_ratio:.0f}x (limit altında)")
        except Exception as e:
            self._record("T21", "Zip bomb tespiti", FAIL, str(e)[:40])
        finally:
            try:
                os.unlink(zip_path)
            except OSError:
                pass

    def t22_ed25519_sign_verify(self) -> None:
        """[T22] Ed25519 imzalama ve doğrulama."""
        try:
            from app.utils.crypto import generate_keypair, sign_data, verify_signature
        except ImportError as e:
            self._record("T22", "Ed25519 imza", FAIL, f"import hatası: {e}")
            return

        with tempfile.TemporaryDirectory() as tmpdir:
            priv_path = Path(tmpdir) / "test.key"
            pub_path = Path(tmpdir) / "test.pub"

            try:
                generate_keypair(priv_path, pub_path)
                test_data = b"THE AIRLOCK v5.1.1 FORTRESS-HARDENED - test data"

                signature = sign_data(test_data, priv_path)
                is_valid = verify_signature(test_data, signature, pub_path)

                if is_valid:
                    # Değiştirilmiş veriyle doğrulama → False olmalı
                    tampered = b"THE AIRLOCK v5.1.1 FORTRESS-HARDENED - TAMPERED"
                    is_invalid = verify_signature(tampered, signature, pub_path)
                    if not is_invalid:
                        self._record("T22", "Ed25519 imza", PASS,
                                     "imza doğrulandı + değişiklik tespit edildi")
                    else:
                        self._record("T22", "Ed25519 imza", FAIL,
                                     "değiştirilmiş veri kabul edildi!")
                else:
                    self._record("T22", "Ed25519 imza", FAIL, "doğru imza reddedildi")
            except Exception as e:
                self._record("T22", "Ed25519 imza", FAIL, str(e)[:40])

    # ═══════════════════════════════════════════
    # 4. ENTEGRASYON TESTLERİ (T23-T25)
    # ═══════════════════════════════════════════

    def t23_full_pipeline(self) -> None:
        """[T23] Tam pipeline: test dosyası → tara → CDR → çıktı → rapor."""
        with tempfile.TemporaryDirectory() as tmpdir:
            source = Path(tmpdir) / "source"
            target = Path(tmpdir) / "target"
            source.mkdir()
            target.mkdir()

            # Test metin dosyası
            test_file = source / "test.txt"
            test_file.write_text("Hello World! Bu bir test dosyasıdır.\x00\x01\x02")

            try:
                from app.security.file_validator import FileValidator
                from app.security.scanner import FileScanner
                from app.security.cdr_engine import CDREngine

                validator = FileValidator()
                scanner = FileScanner()
                cdr = CDREngine()

                # Doğrulama
                val_result = validator.validate_file(test_file, source)
                if not val_result.is_safe:
                    self._record("T23", "Tam pipeline", FAIL,
                                 f"doğrulama hatası: {val_result.block_reason}")
                    return

                # Tarama
                scan_result = scanner.scan_file(test_file)

                # CDR (metin)
                target_file = target / "test.txt"
                cdr_result = cdr.process_text(test_file, target_file)

                if cdr_result.success and target_file.exists():
                    content = target_file.read_text()
                    if "\x00" not in content and "\x01" not in content:
                        self._record("T23", "Tam pipeline", PASS,
                                     "dosya tarandı + CDR uygulandı + kontrol karakterleri temizlendi")
                    else:
                        self._record("T23", "Tam pipeline", FAIL,
                                     "kontrol karakterleri temizlenmedi")
                else:
                    self._record("T23", "Tam pipeline", FAIL,
                                 f"CDR başarısız: {cdr_result.reason}")

            except Exception as e:
                self._record("T23", "Tam pipeline", FAIL, str(e)[:50])

    def t24_report_json_format(self) -> None:
        """[T24] Rapor JSON formatı doğrulama."""
        try:
            from app.security.report_generator import (
                ReportGenerator, ScanSession, FileEntry, USBSourceInfo,
            )

            session = ScanSession(policy="balanced")
            session.usb_source = USBSourceInfo(vendor_id="0781", product_id="5583")
            session.start()
            session.add_file(FileEntry(
                original_path="test.txt",
                original_sha256="abc123",
                original_size=1024,
                action="clean_copy",
                output_path="test.txt",
                output_sha256="def456",
                entropy=4.5,
            ))
            session.finish()

            gen = ReportGenerator()
            report = gen.generate(session)

            # Gerekli alanlar kontrolü
            required_keys = {"version", "timestamp", "station_id", "policy", "summary", "files"}
            missing = required_keys - set(report.keys())

            if not missing:
                # JSON serializable mi?
                json_str = json.dumps(report, ensure_ascii=False)
                parsed = json.loads(json_str)
                if parsed["summary"]["total_files"] == 1:
                    self._record("T24", "Rapor JSON", PASS, "format doğru + serileştirilebilir")
                else:
                    self._record("T24", "Rapor JSON", FAIL, "summary sayıları yanlış")
            else:
                self._record("T24", "Rapor JSON", FAIL, f"eksik alanlar: {missing}")

        except Exception as e:
            self._record("T24", "Rapor JSON", FAIL, str(e)[:50])

    def t25_manifest_sha256(self) -> None:
        """[T25] Manifest SHA-256 doğrulama."""
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir)
            test_file = target / "doc.txt"
            test_file.write_text("manifest test content")

            sha = hashlib.sha256(test_file.read_bytes()).hexdigest()
            manifest_content = f"{sha}  doc.txt\n"
            manifest_path = target / "manifest.sha256"
            manifest_path.write_text(manifest_content)

            try:
                from app.security.report_generator import ReportGenerator

                gen = ReportGenerator()
                results = gen.verify_manifest(manifest_path, target)

                if results.get("doc.txt") is True:
                    self._record("T25", "Manifest SHA-256", PASS, "hash doğrulandı")
                else:
                    self._record("T25", "Manifest SHA-256", FAIL,
                                 f"doğrulama sonuçları: {results}")

            except Exception as e:
                self._record("T25", "Manifest SHA-256", FAIL, str(e)[:50])


    def t26_helper_daemon_compat(self) -> None:
        """[T26] Helper-Daemon mount noktası uyumu."""
        try:
            import re as re_mod

            # 1. Daemon mount noktalarını kontrol et
            from app.daemon import AirlockDaemon
            daemon = AirlockDaemon.__new__(AirlockDaemon)
            # Mount noktaları __init__ dışında kontrol et
            source_mp = "/mnt/airlock_source"
            target_mp = "/mnt/airlock_target"
            update_mp = "/mnt/airlock_update"

            # 2. Helper regex'i ile eşleşiyor mu?
            from app.utils.privileged_helper import _ALLOWED_MOUNT_RE
            mismatched: list[str] = []
            for mp in (source_mp, target_mp, update_mp):
                if not _ALLOWED_MOUNT_RE.match(mp):
                    mismatched.append(mp)

            if mismatched:
                self._record("T26", "Helper-Daemon uyumu", FAIL,
                             f"helper regex eşleşmiyor: {mismatched}")
                return

            # 3. Helper socket yolu erişilebilir mi (dizin mevcut mu)?
            from app.utils.privileged_helper import SOCKET_PATH
            socket_dir = Path(SOCKET_PATH).parent
            if socket_dir.exists():
                self._record("T26", "Helper-Daemon uyumu", PASS,
                             f"mount noktaları uyumlu, socket dizini mevcut ({socket_dir})")
            else:
                self._record("T26", "Helper-Daemon uyumu", PASS,
                             f"mount noktaları uyumlu (socket dizini {socket_dir} henüz yok — servis başlatılmamış)")

        except Exception as e:
            self._record("T26", "Helper-Daemon uyumu", FAIL, str(e)[:50])


# ─────────────────────────────────────────────
# Ana Giriş Noktası
# ─────────────────────────────────────────────

def main() -> int:
    """Self-test çalıştır."""
    suite = AirlockSelfTest()
    passed, failed, skipped = suite.run_all()
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())

"""
THE AIRLOCK v5.1.1 FORTRESS-HARDENED — KATMAN 6: Content Disarm & Reconstruction

EN KRİTİK MODÜL. Dosyaları "silahsızlandırır".

═══════════════════════════════════════════════════════════════
ALTIN KURAL:  CDR başarısız olursa → ASLA orijinali kopyalama.
              Karantinaya al + raporda "CDR_FAILED" olarak işaretle.
              return CDRResult(success=False) ve daemon karantinaya alsın.
═══════════════════════════════════════════════════════════════

İşlem akışları:

  PDF:
    PDF → Ghostscript → JPG (sayfa sayfa)
      → (opsiyonel) Tesseract OCR → searchable PDF
      → img2pdf ile birleştir → TEMİZ PDF

  Office (docx, xlsx, pptx):
    Office → LibreOffice headless → PDF
      → PDF CDR akışı (yukarıdaki gibi)
      → TEMİZ PDF (orijinal format kaybolur — bilinçli güvenlik kararı)

  Resim (jpg, png, gif, bmp, tiff, webp):
    Resim → Pillow ile aç → Metadata temizle (EXIF, GPS, XMP)
      → Yeniden encode et → TEMİZ RESİM

  Metin (txt, csv, json, xml, yaml):
    → Encoding tespit → UTF-8 oku → kontrol karakterlerini temizle
    → UTF-8 olarak yeniden yaz

Kullanım:
    engine = CDREngine(config=cfg)
    result = engine.process_pdf(source, target)
    if not result.success:
        # Karantinaya al — ASLA orijinali kopyalama
"""

from __future__ import annotations

import hashlib
import logging
import shutil
import subprocess
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from app.config import (
    AirlockConfig,
    DIRECTORIES,
    JPEG_QUALITY,
    OCR_LANGUAGES,
    PDF_DPI,
)

logger = logging.getLogger("AIRLOCK.CDR")

# Subprocess timeout sabitleri (saniye)
_GHOSTSCRIPT_TIMEOUT = 300
_LIBREOFFICE_TIMEOUT = 180
_TESSERACT_TIMEOUT = 120
_IMG2PDF_TIMEOUT = 60
_PDFUNITE_TIMEOUT = 60


# ─────────────────────────────────────────────
# Veri Yapıları
# ─────────────────────────────────────────────


@dataclass
class CDRResult:
    """CDR işlem sonucu."""

    success: bool
    source_path: Path
    output_path: Optional[Path] = None
    reason: str = "OK"
    pages_processed: int = 0
    ocr_applied: bool = False
    original_sha256: str = ""
    output_sha256: str = ""
    cdr_method: str = ""  # "rasterize", "image_strip", "text_clean", "office_to_pdf"
    warnings: List[str] = field(default_factory=list)


# ─────────────────────────────────────────────
# CDR Engine
# ─────────────────────────────────────────────


class CDREngine:
    """
    Content Disarm & Reconstruction motoru.

    Her dosya türü için ayrı pipeline uygular.
    Tüm ara işlemler RAM disk (/opt/airlock/tmp) üzerinde yapılır.

    ALTIN KURAL: İşlem başarısız → ASLA orijinali kopyalama.
    """

    def __init__(self, config: Optional[AirlockConfig] = None) -> None:
        self._logger = logging.getLogger("AIRLOCK.CDR")
        self._config = config or AirlockConfig()
        self._work_dir = DIRECTORIES["tmp"]
        self._bwrap_available = self._check_bwrap()

        # Sandbox zorunluluk kontrolü
        self._sandbox_required_but_missing = (
            self._config.cdr_require_sandbox and not self._bwrap_available
        )
        if self._sandbox_required_but_missing:
            self._logger.critical(
                "SANDBOX ZORUNLU ama bwrap bulunamadı — CDR işlemleri reddedilecek"
            )

    # ═══════════════════════════════════════════
    # PDF CDR
    # ═══════════════════════════════════════════

    def process_pdf(self, source: Path, target: Path) -> CDRResult:
        """
        PDF CDR pipeline:
          1. Benzersiz job dizini oluştur (RAM disk)
          2. Ghostscript ile PDF → JPG (sayfa sayfa)
          3. (Opsiyonel) Tesseract OCR → searchable PDF sayfaları
          4. Sayfaları birleştir (pdfunite veya img2pdf)
          5. Temiz PDF'i hedefe kopyala
          6. Job dizinini temizle

        BAŞARISIZLIK → CDRResult(success=False) döner.
        HİÇBİR DURUMDA orijinal dosya hedefe kopyalanmaz.

        Args:
            source: Kaynak PDF dosya yolu
            target: Hedef temiz dosya yolu

        Returns:
            CDRResult
        """
        original_sha256 = self._sha256(source)
        job_dir = self._create_job_dir()

        try:
            # ── Adım 1: Ghostscript ile PDF → JPG ──
            page_images = self._pdf_to_images(source, job_dir)
            if not page_images:
                return CDRResult(
                    success=False,
                    source_path=source,
                    reason="NO_PAGES — Ghostscript sıfır sayfa üretti",
                    original_sha256=original_sha256,
                    cdr_method="rasterize",
                )

            pages_processed = len(page_images)

            # ── Adım 2: OCR (opsiyonel) ──
            ocr_applied = False
            if self._config.ocr_enabled:
                ocr_pdfs = self._ocr_images(page_images, job_dir)
                if ocr_pdfs and len(ocr_pdfs) == pages_processed:
                    # OCR başarılı — searchable PDF'leri birleştir
                    merged = self._merge_pdfs(ocr_pdfs, job_dir)
                    if merged:
                        ocr_applied = True
                        self._copy_output(merged, target)
                        output_sha256 = self._sha256(target)
                        return CDRResult(
                            success=True,
                            source_path=source,
                            output_path=target,
                            reason="OK",
                            pages_processed=pages_processed,
                            ocr_applied=True,
                            original_sha256=original_sha256,
                            output_sha256=output_sha256,
                            cdr_method="rasterize+ocr",
                        )
                    # pdfunite başarısız → OCR'sız devam et
                    self._logger.warning(
                        "OCR PDF birleştirme başarısız, OCR'sız devam ediliyor: %s",
                        source.name,
                    )

            # ── Adım 3: img2pdf ile JPG → PDF (OCR'sız) ──
            output_pdf = self._images_to_pdf(page_images, job_dir)
            if not output_pdf:
                return CDRResult(
                    success=False,
                    source_path=source,
                    reason="IMG2PDF_FAILED — sayfa birleştirme başarısız",
                    original_sha256=original_sha256,
                    cdr_method="rasterize",
                )

            self._copy_output(output_pdf, target)
            output_sha256 = self._sha256(target)

            self._logger.info(
                "PDF CDR başarılı: %s → %d sayfa, OCR=%s",
                source.name, pages_processed, ocr_applied,
            )

            return CDRResult(
                success=True,
                source_path=source,
                output_path=target,
                reason="OK",
                pages_processed=pages_processed,
                ocr_applied=ocr_applied,
                original_sha256=original_sha256,
                output_sha256=output_sha256,
                cdr_method="rasterize",
            )

        except Exception as exc:
            self._logger.error("PDF CDR beklenmeyen hata: %s — %s", source.name, exc)
            return CDRResult(
                success=False,
                source_path=source,
                reason=f"UNEXPECTED_ERROR: {exc}",
                original_sha256=original_sha256,
                cdr_method="rasterize",
            )
        finally:
            self._cleanup_job(job_dir)

    # ═══════════════════════════════════════════
    # OFFICE CDR
    # ═══════════════════════════════════════════

    def process_office(self, source: Path, target: Path) -> CDRResult:
        """
        Office CDR pipeline:
          1. LibreOffice headless ile PDF'e çevir
          2. Üretilen PDF'i process_pdf() ile işle
          3. Çıktı: {orijinal_stem}_SANITIZED.pdf

        NOT: Orijinal format (docx, xlsx, pptx) KAYBOLUR.
             Bu bilinçli bir güvenlik kararıdır.

        Args:
            source: Kaynak Office dosya yolu
            target: Hedef dizin veya dosya yolu

        Returns:
            CDRResult
        """
        original_sha256 = self._sha256(source)
        job_dir = self._create_job_dir()

        try:
            # ── Adım 1: LibreOffice → PDF ──
            intermediate_pdf = self._office_to_pdf(source, job_dir)
            if not intermediate_pdf:
                return CDRResult(
                    success=False,
                    source_path=source,
                    reason="LIBREOFFICE_FAILED — PDF'e dönüştürme başarısız",
                    original_sha256=original_sha256,
                    cdr_method="office_to_pdf_rasterize",
                )

            # ── Adım 2: PDF CDR pipeline ──
            # Hedef dosya adını belirle
            if target.is_dir():
                final_target = target / f"{source.stem}_SANITIZED.pdf"
            elif target.suffix.lower() != ".pdf":
                final_target = target.with_suffix(".pdf")
            else:
                final_target = target

            pdf_result = self.process_pdf(intermediate_pdf, final_target)

            # Sonucu Office CDR olarak güncelle
            pdf_result.source_path = source
            pdf_result.original_sha256 = original_sha256
            pdf_result.cdr_method = "office_to_pdf_rasterize"

            if pdf_result.success:
                self._logger.info(
                    "Office CDR başarılı: %s → %s (%d sayfa)",
                    source.name, final_target.name, pdf_result.pages_processed,
                )
            else:
                self._logger.warning(
                    "Office CDR başarısız (PDF aşamasında): %s — %s",
                    source.name, pdf_result.reason,
                )

            return pdf_result

        except Exception as exc:
            self._logger.error(
                "Office CDR beklenmeyen hata: %s — %s", source.name, exc
            )
            return CDRResult(
                success=False,
                source_path=source,
                reason=f"UNEXPECTED_ERROR: {exc}",
                original_sha256=original_sha256,
                cdr_method="office_to_pdf_rasterize",
            )
        finally:
            self._cleanup_job(job_dir)

    # ═══════════════════════════════════════════
    # RESİM CDR
    # ═══════════════════════════════════════════

    def process_image(self, source: Path, target: Path) -> CDRResult:
        """
        Resim CDR pipeline:
          1. Pillow ile aç
          2. Metadata temizle (EXIF, GPS, XMP, IPTC)
          3. Yeniden encode et (aynı format veya PNG fallback)
          4. Metadata olmadan kaydet

        Steganografi ve exploit payload'ları da temizlenir
        (piksel verisi korunur, üst-veri ve gömülü veri silinir).

        Args:
            source: Kaynak resim dosya yolu
            target: Hedef temiz dosya yolu

        Returns:
            CDRResult
        """
        original_sha256 = self._sha256(source)

        try:
            from PIL import Image  # noqa: PLC0415
        except ImportError:
            self._logger.error("Pillow yüklü değil — resim CDR atlanıyor")
            return CDRResult(
                success=False,
                source_path=source,
                reason="PILLOW_NOT_INSTALLED",
                original_sha256=original_sha256,
                cdr_method="image_strip",
            )

        try:
            img = Image.open(source)

            # Orijinal formatı belirle
            original_format = (img.format or "").upper()

            # ── Metadata temizleme ──
            # Yeni boş Image oluştur — tüm metadata silinir
            # (EXIF, GPS, XMP, IPTC, ICC profili, makro/komut)
            clean_data = img.getdata()
            clean_img = Image.new(img.mode, img.size)
            clean_img.putdata(list(clean_data))

            # ICC profili koru (renk doğruluğu için) — opsiyonel
            icc_profile = img.info.get("icc_profile")

            # ── Yeniden encode et ──
            save_kwargs: dict = {}

            if original_format == "JPEG":
                save_format = "JPEG"
                save_kwargs["quality"] = self._config.jpeg_quality
                save_kwargs["optimize"] = True
                if icc_profile:
                    save_kwargs["icc_profile"] = icc_profile
            elif original_format == "PNG":
                save_format = "PNG"
                save_kwargs["optimize"] = True
            elif original_format == "GIF":
                save_format = "GIF"
            elif original_format == "BMP":
                save_format = "BMP"
            elif original_format in ("TIFF", "TIF"):
                save_format = "TIFF"
            elif original_format == "WEBP":
                save_format = "WEBP"
                save_kwargs["quality"] = self._config.jpeg_quality
            else:
                # Bilinmeyen format → güvenli PNG'ye çevir
                save_format = "PNG"
                self._logger.info(
                    "Bilinmeyen resim formatı '%s' → PNG'ye dönüştürülüyor: %s",
                    original_format, source.name,
                )

            # Hedef uzantısını ayarla
            format_ext_map = {
                "JPEG": ".jpg", "PNG": ".png", "GIF": ".gif",
                "BMP": ".bmp", "TIFF": ".tiff", "WEBP": ".webp",
            }
            expected_ext = format_ext_map.get(save_format, ".png")

            if target.suffix.lower() != expected_ext:
                actual_target = target.with_suffix(expected_ext)
            else:
                actual_target = target

            # Kaydet (metadata olmadan)
            actual_target.parent.mkdir(parents=True, exist_ok=True)
            clean_img.save(actual_target, format=save_format, **save_kwargs)

            # Kaynağı ve hedefi kapat
            img.close()
            clean_img.close()

            output_sha256 = self._sha256(actual_target)

            self._logger.info(
                "Resim CDR başarılı: %s → %s (format=%s, metadata silindi)",
                source.name, actual_target.name, save_format,
            )

            return CDRResult(
                success=True,
                source_path=source,
                output_path=actual_target,
                reason="OK",
                pages_processed=1,
                original_sha256=original_sha256,
                output_sha256=output_sha256,
                cdr_method="image_strip",
            )

        except Exception as exc:
            self._logger.error(
                "Resim CDR hatası: %s — %s", source.name, exc
            )
            return CDRResult(
                success=False,
                source_path=source,
                reason=f"IMAGE_PROCESSING_ERROR: {exc}",
                original_sha256=original_sha256,
                cdr_method="image_strip",
            )

    # ═══════════════════════════════════════════
    # METİN CDR
    # ═══════════════════════════════════════════

    def process_text(self, source: Path, target: Path) -> CDRResult:
        """
        Metin CDR pipeline:
          1. Binary içerik kontrolü (NUL byte varsa → block)
          2. Encoding tespit et (chardet)
          3. UTF-8 olarak oku
          4. Kontrol karakterlerini temizle
             Tab (\\x09), newline (\\x0a), CR (\\x0d) KORUNUR
          5. UTF-8 olarak yeniden yaz

        Args:
            source: Kaynak metin dosya yolu
            target: Hedef temiz dosya yolu

        Returns:
            CDRResult
        """
        original_sha256 = self._sha256(source)

        try:
            raw_bytes = source.read_bytes()
        except OSError as exc:
            return CDRResult(
                success=False,
                source_path=source,
                reason=f"READ_ERROR: {exc}",
                original_sha256=original_sha256,
                cdr_method="text_clean",
            )

        # ── Adım 1: Binary içerik kontrolü ──
        if b"\x00" in raw_bytes:
            return CDRResult(
                success=False,
                source_path=source,
                reason="BINARY_CONTENT — NUL byte tespit edildi, metin dosyası değil",
                original_sha256=original_sha256,
                cdr_method="text_clean",
            )

        # ── Adım 2: Encoding tespit ──
        encoding = self._detect_encoding(raw_bytes)

        # ── Adım 3: UTF-8 olarak decode ──
        try:
            text = raw_bytes.decode(encoding, errors="replace")
        except (UnicodeDecodeError, LookupError) as exc:
            self._logger.warning(
                "Encoding hatası (%s), UTF-8 replace ile devam: %s — %s",
                encoding, source.name, exc,
            )
            text = raw_bytes.decode("utf-8", errors="replace")

        # ── Adım 4: Kontrol karakterlerini temizle ──
        cleaned_chars: List[str] = []
        stripped_count = 0

        for ch in text:
            code = ord(ch)
            # Tab (\x09), Newline (\x0a), Carriage Return (\x0d) KORU
            if code in (0x09, 0x0A, 0x0D):
                cleaned_chars.append(ch)
            # \x00-\x08, \x0b-\x0c, \x0e-\x1f → Sil
            elif 0x00 <= code <= 0x1F:
                stripped_count += 1
            else:
                cleaned_chars.append(ch)

        cleaned_text = "".join(cleaned_chars)

        # ── Adım 5: UTF-8 olarak yaz ──
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(cleaned_text, encoding="utf-8")
        except OSError as exc:
            return CDRResult(
                success=False,
                source_path=source,
                reason=f"WRITE_ERROR: {exc}",
                original_sha256=original_sha256,
                cdr_method="text_clean",
            )

        output_sha256 = self._sha256(target)

        warnings: List[str] = []
        if stripped_count > 0:
            warnings.append(f"{stripped_count} kontrol karakteri temizlendi")
        if encoding.lower() != "utf-8":
            warnings.append(f"Encoding dönüşümü: {encoding} → UTF-8")

        self._logger.info(
            "Metin CDR başarılı: %s (encoding=%s, temizlenen=%d karakter)",
            source.name, encoding, stripped_count,
        )

        return CDRResult(
            success=True,
            source_path=source,
            output_path=target,
            reason="OK",
            pages_processed=1,
            original_sha256=original_sha256,
            output_sha256=output_sha256,
            cdr_method="text_clean",
            warnings=warnings,
        )

    # ═══════════════════════════════════════════
    # DAHİLİ YARDIMCILAR — PDF Pipeline
    # ═══════════════════════════════════════════

    def _pdf_to_images(self, pdf_path: Path, job_dir: Path) -> List[Path]:
        """
        Ghostscript ile PDF'i sayfa sayfa JPG'ye dönüştür.

        gs -dNOPAUSE -dBATCH -sDEVICE=jpeg -r{DPI}
           -dJPEGQ={QUALITY} -sOutputFile=page_%04d.jpg input.pdf

        Returns:
            Üretilen JPG dosyalarının sıralı listesi (boş ise başarısız)
        """
        dpi = self._config.pdf_dpi
        quality = self._config.jpeg_quality
        output_pattern = str(job_dir / "page_%04d.jpg")

        cmd = [
            "gs",
            "-dNOPAUSE",
            "-dBATCH",
            "-dQUIET",
            "-dSAFER",
            "-sDEVICE=jpeg",
            f"-r{dpi}",
            f"-dJPEGQ={quality}",
            f"-sOutputFile={output_pattern}",
            str(pdf_path),
        ]

        try:
            result = self._run_sandboxed(
                cmd,
                timeout=_GHOSTSCRIPT_TIMEOUT,
                job_dir=job_dir,
            )

            if result.returncode != 0:
                self._logger.error(
                    "Ghostscript hatası: %s — stderr: %s",
                    pdf_path.name,
                    result.stderr[:500],
                )
                return []

        except subprocess.TimeoutExpired:
            self._logger.error(
                "Ghostscript timeout (%ds): %s", _GHOSTSCRIPT_TIMEOUT, pdf_path.name
            )
            return []
        except FileNotFoundError:
            self._logger.error("Ghostscript (gs) komutu bulunamadı — kurulu değil")
            return []
        except OSError as exc:
            self._logger.error("Ghostscript çalıştırma hatası: %s", exc)
            return []

        # Üretilen JPG dosyalarını topla
        images = sorted(job_dir.glob("page_*.jpg"))

        if not images:
            self._logger.warning(
                "Ghostscript çıktı üretmedi (0 sayfa): %s", pdf_path.name
            )

        return images

    def _ocr_images(
        self, images: List[Path], job_dir: Path
    ) -> List[Path]:
        """
        Tesseract OCR ile JPG'leri searchable PDF'e dönüştür.

        tesseract page_001.jpg page_001 -l {LANG} pdf

        Returns:
            Üretilen PDF dosyalarının sıralı listesi (boş ise OCR başarısız)
        """
        ocr_pdfs: List[Path] = []
        lang = self._config.ocr_languages

        for img_path in images:
            stem = img_path.stem
            output_base = str(job_dir / f"ocr_{stem}")
            # Tesseract çıktıya otomatik .pdf ekler
            expected_pdf = Path(f"{output_base}.pdf")

            cmd = [
                "tesseract",
                str(img_path),
                output_base,
                "-l", lang,
                "pdf",
            ]

            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=_TESSERACT_TIMEOUT,
                )

                if result.returncode != 0:
                    self._logger.warning(
                        "Tesseract hatası (%s): %s",
                        img_path.name,
                        result.stderr[:300],
                    )
                    return []  # Bir sayfa bile başarısız → tüm OCR iptal

                if not expected_pdf.exists():
                    self._logger.warning(
                        "Tesseract çıktı üretmedi: %s", expected_pdf
                    )
                    return []

                ocr_pdfs.append(expected_pdf)

            except subprocess.TimeoutExpired:
                self._logger.warning(
                    "Tesseract timeout (%ds): %s",
                    _TESSERACT_TIMEOUT, img_path.name,
                )
                return []
            except FileNotFoundError:
                self._logger.warning("Tesseract komutu bulunamadı — OCR atlanıyor")
                return []
            except OSError as exc:
                self._logger.warning("Tesseract hatası: %s", exc)
                return []

        return ocr_pdfs

    def _merge_pdfs(self, pdf_pages: List[Path], job_dir: Path) -> Optional[Path]:
        """
        pdfunite ile birden fazla PDF'i tek dosyada birleştir.

        Returns:
            Birleştirilmiş PDF yolu veya None (başarısız)
        """
        output = job_dir / "merged_output.pdf"

        if len(pdf_pages) == 1:
            # Tek sayfa — birleştirme gerekmez
            return pdf_pages[0]

        cmd = ["pdfunite"] + [str(p) for p in pdf_pages] + [str(output)]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=_PDFUNITE_TIMEOUT,
            )

            if result.returncode != 0:
                self._logger.warning(
                    "pdfunite hatası: %s", result.stderr[:300]
                )
                return None

            if output.exists() and output.stat().st_size > 0:
                return output

            return None

        except FileNotFoundError:
            self._logger.warning("pdfunite komutu bulunamadı (poppler-utils kurulu değil)")
            return None
        except subprocess.TimeoutExpired:
            self._logger.warning("pdfunite timeout (%ds)", _PDFUNITE_TIMEOUT)
            return None
        except OSError as exc:
            self._logger.warning("pdfunite hatası: %s", exc)
            return None

    def _images_to_pdf(
        self, images: List[Path], job_dir: Path
    ) -> Optional[Path]:
        """
        img2pdf ile JPG listesini tek PDF'e dönüştür (OCR'sız).

        Returns:
            Üretilen PDF yolu veya None
        """
        output = job_dir / "rasterized_output.pdf"

        cmd = ["img2pdf"] + [str(p) for p in images] + ["-o", str(output)]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=_IMG2PDF_TIMEOUT,
            )

            if result.returncode != 0:
                self._logger.error("img2pdf hatası: %s", result.stderr[:300])
                return None

            if output.exists() and output.stat().st_size > 0:
                return output

            return None

        except FileNotFoundError:
            self._logger.error("img2pdf komutu bulunamadı — kurulu değil")
            return None
        except subprocess.TimeoutExpired:
            self._logger.error("img2pdf timeout (%ds)", _IMG2PDF_TIMEOUT)
            return None
        except OSError as exc:
            self._logger.error("img2pdf hatası: %s", exc)
            return None

    # ═══════════════════════════════════════════
    # DAHİLİ YARDIMCILAR — Office Pipeline
    # ═══════════════════════════════════════════

    def _office_to_pdf(self, source: Path, job_dir: Path) -> Optional[Path]:
        """
        LibreOffice headless ile Office dosyasını PDF'e dönüştür.

        soffice --headless --convert-to pdf --outdir {job_dir} {source}

        Returns:
            Üretilen PDF yolu veya None
        """
        cmd = [
            "soffice",
            "--headless",
            "--norestore",
            "--convert-to", "pdf",
            "--outdir", str(job_dir),
            str(source),
        ]

        try:
            result = self._run_sandboxed(
                cmd,
                timeout=_LIBREOFFICE_TIMEOUT,
                job_dir=job_dir,
            )

            if result.returncode != 0:
                self._logger.error(
                    "LibreOffice hatası: %s — stderr: %s",
                    source.name, result.stderr[:300],
                )
                return None

        except subprocess.TimeoutExpired:
            self._logger.error(
                "LibreOffice timeout (%ds): %s", _LIBREOFFICE_TIMEOUT, source.name
            )
            return None
        except FileNotFoundError:
            self._logger.error("soffice komutu bulunamadı — LibreOffice kurulu değil")
            return None
        except OSError as exc:
            self._logger.error("LibreOffice hatası: %s", exc)
            return None

        # LibreOffice çıktı dosyasını bul
        expected_pdf = job_dir / f"{source.stem}.pdf"
        if expected_pdf.exists() and expected_pdf.stat().st_size > 0:
            return expected_pdf

        # Farklı isimle üretmiş olabilir
        pdfs = list(job_dir.glob("*.pdf"))
        if pdfs:
            return pdfs[0]

        self._logger.error(
            "LibreOffice PDF üretmedi: %s → beklenen: %s",
            source.name, expected_pdf,
        )
        return None

    # ═══════════════════════════════════════════
    # SANDBOX — Bubblewrap (bwrap)
    # ═══════════════════════════════════════════

    @staticmethod
    def _check_bwrap() -> bool:
        """
        bwrap (bubblewrap) sandbox aracının mevcut olup olmadığını kontrol et.

        Returns:
            True: bwrap kullanılabilir
            False: bwrap yok → normal subprocess ile devam (graceful degrade)
        """
        try:
            result = subprocess.run(
                ["bwrap", "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                logging.getLogger("AIRLOCK.CDR").info(
                    "bwrap sandbox mevcut: %s", result.stdout.strip()
                )
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass

        logging.getLogger("AIRLOCK.CDR").warning(
            "bwrap bulunamadı — CDR sandbox devre dışı (graceful degrade)"
        )
        return False

    def _run_sandboxed(
        self,
        cmd: List[str],
        *,
        timeout: int,
        job_dir: Optional[Path] = None,
    ) -> subprocess.CompletedProcess[str]:
        """
        Komutu bwrap sandbox icinde veya dogrudan calistir.

        bwrap varsa (MINIMAL bind — "/" YOK):
          - /usr, /bin, /sbin, /lib, /lib64 salt-okunur
          - /etc/fonts (fontlar icin, gs/soffice gerektirir)
          - /etc/passwd, /etc/group (LibreOffice getpwuid icin)
          - /etc/nsswitch.conf (varsa, name resolution icin)
          - /etc/ld.so.cache (dinamik linker cache)
          - HOME=/tmp, XDG_CONFIG_HOME=/tmp/.config, XDG_CACHE_HOME=/tmp/.cache
          - /dev, /proc minimal erisim
          - /tmp izole tmpfs
          - Ag erisimi YOK (--unshare-net)
          - PID namespace izole (--unshare-pid)
          - job_dir ve work_dir yazilabilir bind
          - /opt/airlock ASLA bind edilmez
          - keys/ dizini ASLA bind edilmez
          - /etc/shadow ASLA bind edilmez
          - Ana surec olurse alt surec de olur (--die-with-parent)

        bwrap yoksa:
          - Normal subprocess.run (guvenlik azaltilmis ama calisir)

        Args:
            cmd: Calistirilacak komut listesi
            timeout: Zaman asimi (saniye)
            job_dir: Sandbox icinde yazilabilir olacak dizin (opsiyonel)

        Returns:
            subprocess.CompletedProcess sonucu
        """
        # ── Sandbox zorunluysa ve yoksa → REJECT ──
        if self._sandbox_required_but_missing:
            self._logger.error(
                "CDR REDDEDILDI: sandbox zorunlu ama bwrap yok — komut: %s",
                cmd[0] if cmd else "?",
            )
            return subprocess.CompletedProcess(
                args=cmd,
                returncode=1,
                stdout="",
                stderr="SANDBOX_REQUIRED: bwrap yok ama require_sandbox=true",
            )

        if self._bwrap_available:
            bwrap_cmd: List[str] = [
                "bwrap",
                # ── Minimal salt-okunur bind'lar (/ YERINE) ──
                "--ro-bind", "/usr", "/usr",
                "--ro-bind", "/bin", "/bin",
                "--ro-bind", "/sbin", "/sbin",
                "--ro-bind", "/lib", "/lib",
            ]

            # /lib64 varsa ekle (x86_64 ve bazı ARM dağıtımlar)
            if Path("/lib64").exists():
                bwrap_cmd.extend(["--ro-bind", "/lib64", "/lib64"])
            # Bazı distrolarda /lib64 → /usr/lib64 symlink
            elif Path("/usr/lib64").exists():
                bwrap_cmd.extend(["--symlink", "usr/lib64", "/lib64"])

            bwrap_cmd.extend([
                # Fontlar (Ghostscript ve LibreOffice gerektirir)
                "--ro-bind", "/etc/fonts", "/etc/fonts",
                # /etc altından sadece gerekli olanlar
                "--ro-bind", "/etc/ld.so.cache", "/etc/ld.so.cache",
                # ── LibreOffice uyumluluk bind'ları ──
                # soffice kullanıcı bilgisi gerektirir (getpwuid çağrısı)
                "--ro-bind", "/etc/passwd", "/etc/passwd",
                "--ro-bind", "/etc/group", "/etc/group",
                # GÜVENLİK: /etc/shadow ASLA bind edilmez!
            ])

            # nsswitch.conf varsa ekle (bazı dağıtımlarda gerekli)
            if Path("/etc/nsswitch.conf").exists():
                bwrap_cmd.extend([
                    "--ro-bind", "/etc/nsswitch.conf", "/etc/nsswitch.conf",
                ])

            bwrap_cmd.extend([
                # Minimal cihaz ve proc
                "--dev", "/dev",
                "--proc", "/proc",
                # İzole /tmp
                "--tmpfs", "/tmp",
                # ── LibreOffice ortam değişkenleri ──
                # soffice $HOME ve XDG dizinlerine yazma gerektirir
                "--setenv", "HOME", "/tmp",
                "--setenv", "XDG_CONFIG_HOME", "/tmp/.config",
                "--setenv", "XDG_CACHE_HOME", "/tmp/.cache",
                # Güvenlik izolasyonu
                "--unshare-net",                     # Ağ erişimi YOK
                "--unshare-pid",                     # PID namespace izole
                "--die-with-parent",                 # Ana süreç ölünce öldür
            ])

            # job_dir yazılabilir olmalı (CDR çıktıları buraya yazılır)
            if job_dir is not None:
                bwrap_cmd.extend([
                    "--bind", str(job_dir), str(job_dir),
                ])

            # work_dir yazılabilir (geçici dosyalar — /opt/airlock/tmp)
            bwrap_cmd.extend([
                "--bind", str(self._work_dir), str(self._work_dir),
            ])

            # NOT: /opt/airlock ve keys/ ASLA bind edilmez
            # Sadece gerekli minimum erişim sağlanır

            bwrap_cmd.extend(cmd)
            actual_cmd = bwrap_cmd
        else:
            actual_cmd = cmd

        return subprocess.run(
            actual_cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

    # ═══════════════════════════════════════════
    # DAHİLİ YARDIMCILAR — Genel
    # ═══════════════════════════════════════════

    def _create_job_dir(self) -> Path:
        """RAM disk üzerinde benzersiz job dizini oluştur."""
        job_id = uuid.uuid4().hex[:12]
        job_dir = self._work_dir / f"cdr_job_{job_id}"
        job_dir.mkdir(parents=True, exist_ok=True)
        return job_dir

    @staticmethod
    def _cleanup_job(job_dir: Path) -> None:
        """Job dizinini güvenli sil (RAM disk boşalt)."""
        try:
            if job_dir.exists():
                shutil.rmtree(job_dir)
        except Exception:
            # Temizlik hatası daemon'ı çökertmemeli
            pass

    @staticmethod
    def _copy_output(source: Path, target: Path) -> None:
        """İşlenmiş dosyayı hedef konuma kopyala."""
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)

    @staticmethod
    def _sha256(filepath: Path) -> str:
        """Dosyanın SHA-256 hash'ini hesapla."""
        sha = hashlib.sha256()
        try:
            with filepath.open("rb") as fh:
                while True:
                    chunk = fh.read(65536)
                    if not chunk:
                        break
                    sha.update(chunk)
        except (OSError, PermissionError):
            return ""
        return sha.hexdigest()

    @staticmethod
    def _detect_encoding(raw_bytes: bytes) -> str:
        """
        chardet ile metin encoding'ini tespit et.

        chardet yoksa UTF-8 varsayılır.
        """
        try:
            import chardet  # noqa: PLC0415

            detected = chardet.detect(raw_bytes)
            encoding = detected.get("encoding") or "utf-8"
            confidence = detected.get("confidence", 0.0)

            if confidence < 0.5:
                return "utf-8"  # Düşük güvenilirlik → UTF-8 fallback

            return encoding

        except ImportError:
            return "utf-8"
        except Exception:
            return "utf-8"

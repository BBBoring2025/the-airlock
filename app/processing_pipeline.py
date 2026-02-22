"""
THE AIRLOCK v5.1.1 FORTRESS-HARDENED — Dosya İşleme Pipeline

daemon.py'den ayrılmış dosya işleme mantığı. Tek dosyanın
tarama → karar → CDR → kopyalama/karantina akışını yönetir.

GÜVENLİK KURALLARI:
  - CDR başarısız → ASLA kopyalama → Karantinaya al
  - Symlink → ASLA takip etme
  - Hata durumunda → ASLA sessizce geçme → Logla
"""

from __future__ import annotations

import logging
import shutil
from pathlib import Path
from typing import Callable, Optional

from app.config import AirlockConfig, CDR_SUPPORTED, DIRECTORIES
from app.security.scanner import FileScanner, ScanResult
from app.security.cdr_engine import CDREngine
from app.security.archive_handler import ArchiveHandler
from app.security.file_validator import (
    FileValidator,
    safe_copy_no_symlink,
    safe_mkdir_no_symlink,
    validate_target_path,
)
from app.security.policy_engine import decide_file_action, FileAction
from app.security.report_generator import FileEntry, ScanSession
from app.utils.crypto import sha256_file


class FileProcessor:
    """
    Tek dosyanın tarama → karar → CDR → kopyalama akışını yönetir.

    daemon.py'den ayrılmış dosya işleme pipeline'ı.
    Tüm bağımlılıklar dependency injection ile sağlanır.
    """

    def __init__(
        self,
        config: AirlockConfig,
        cdr_engine: CDREngine,
        archive_handler: ArchiveHandler,
        scanner: FileScanner,
        file_validator: FileValidator,
        logger: logging.Logger,
        hw_event_callback: Optional[Callable[[str], None]] = None,
        oled: Optional[object] = None,
    ) -> None:
        """
        FileProcessor başlat.

        Args:
            config: Airlock yapılandırması
            cdr_engine: CDR motoru (PDF/Office/Image/Text)
            archive_handler: Arşiv işleyici
            scanner: Dosya tarayıcı (ClamAV + YARA + entropy + magic)
            file_validator: Dosya doğrulayıcı
            logger: Logger instance
            hw_event_callback: Donanım olay callback'i (LED/ses)
            oled: OLED ekran instance'ı (opsiyonel)
        """
        self._config = config
        self._cdr_engine = cdr_engine
        self._archive_handler = archive_handler
        self._scanner = scanner
        self._file_validator = file_validator
        self._logger = logger
        self._hw_event = hw_event_callback
        self._oled = oled

    # ═══════════════════════════════════════════
    # ANA PIPELINE
    # ═══════════════════════════════════════════

    def process_file(
        self,
        filepath: Path,
        relative: Path,
        source_root: Path,
        target_root: Path,
        session: ScanSession,
    ) -> None:
        """
        Tek dosyayı işle: tara → karar ver → CDR/kopya/karantina.

        Args:
            filepath: İşlenecek dosyanın mutlak yolu
            relative: Kaynak kök'e göre göreceli yol
            source_root: Kaynak USB mount noktası
            target_root: Hedef USB mount noktası
            session: Mevcut tarama oturumu (sonuçlar eklenir)
        """
        # ── Tarama ──
        scan_result = self._scanner.scan_file(filepath)
        mime = scan_result.mime_type
        extension = filepath.suffix
        is_archive = self._archive_handler.is_archive(filepath)

        # ── Merkezi politika kararı ──
        policy = self._config.active_policy_settings
        action = decide_file_action(
            is_threat=scan_result.is_threat,
            mime_type=mime,
            extension=extension,
            policy=policy,
            is_archive=is_archive,
        )

        target_path = target_root / relative

        # ── Kararı uygula ──
        if action == FileAction.QUARANTINE:
            self._logger.warning(
                "TEHDİT: %s — %s",
                filepath.name, scan_result.detection_summary,
            )
            self._quarantine_file(filepath, source_root)

            entry = FileEntry(
                original_path=str(relative),
                original_sha256=scan_result.sha256,
                original_size=scan_result.file_size,
                action="quarantined",
                entropy=scan_result.entropy,
                detections=[
                    {"engine": d.engine, "rule": d.rule_name, "detail": d.details}
                    for d in scan_result.detections
                ],
            )
            session.add_file(entry)

            if self._hw_event:
                self._hw_event("threat")
            if self._oled:
                try:
                    self._oled.show_threat(filepath.name[:20], scan_result.detection_summary[:30])
                except Exception:
                    pass

        elif action == FileAction.BLOCK:
            entry = FileEntry(
                original_path=str(relative),
                original_sha256=scan_result.sha256,
                original_size=scan_result.file_size,
                action="blocked",
                entropy=scan_result.entropy,
                detections=[{
                    "engine": "policy",
                    "rule": "POLICY_BLOCKED",
                    "detail": f"Politika engeli: {policy.name} (mime={mime}, ext={extension})",
                }],
            )
            session.add_file(entry)

        elif is_archive and action == FileAction.COPY:
            # Arşiv → aç ve işle (decide_file_action COPY döner çünkü arşivler extract edilir)
            self._process_archive(
                filepath, source_root, target_root, relative, scan_result, session
            )

        elif action == FileAction.CDR_DOCUMENT:
            self._apply_document_cdr(
                filepath, target_path, mime, relative, scan_result, session,
                target_root, source_root,
            )

        elif action == FileAction.CDR_IMAGE:
            self._apply_image_cdr(
                filepath, target_path, relative, scan_result, session,
                target_root, source_root,
            )

        elif action == FileAction.CDR_TEXT:
            self._apply_text_cdr(
                filepath, target_path, relative, scan_result, session,
                target_root, source_root,
            )

        elif action == FileAction.COPY:
            self._copy_clean_file(
                filepath, target_path, relative, scan_result, session,
                target_root,
            )

    # ═══════════════════════════════════════════
    # CDR İŞLEM YARDIMCILARI
    # ═══════════════════════════════════════════

    def _apply_document_cdr(
        self,
        filepath: Path,
        target_path: Path,
        mime: str,
        relative: Path,
        scan_result: ScanResult,
        session: ScanSession,
        target_root: Path,
        source_root: Path,
    ) -> bool:
        """PDF/Office CDR uygula. True dönerse dosya işlendi."""
        # Hedef path güvenlik kontrolü
        if not safe_mkdir_no_symlink(target_path.parent, target_root):
            self._logger.warning(
                "CDR HEDEF SYMLINK/TRAVERSAL ENGELLENDİ: %s", target_path,
            )
            return False

        if not validate_target_path(target_path, target_root):
            self._logger.warning(
                "CDR HEDEF PATH TRAVERSAL ENGELLENDİ: %s", target_path,
            )
            return False

        cdr_strategy = CDR_SUPPORTED.get(mime, "")

        if self._oled:
            try:
                self._oled.show_cdr(filepath.name[:20], cdr_strategy)
            except Exception:
                pass

        if self._hw_event:
            self._hw_event("cdr")

        if "office" in cdr_strategy:
            cdr_result = self._cdr_engine.process_office(filepath, target_path)
        else:
            cdr_result = self._cdr_engine.process_pdf(filepath, target_path)

        if cdr_result.success:
            entry = FileEntry(
                original_path=str(relative),
                original_sha256=cdr_result.original_sha256,
                original_size=scan_result.file_size,
                action=f"cdr_{cdr_strategy}",
                output_path=str(cdr_result.output_path.relative_to(
                    target_root
                )) if cdr_result.output_path else None,
                output_sha256=cdr_result.output_sha256,
                output_size=cdr_result.output_path.stat().st_size if cdr_result.output_path and cdr_result.output_path.exists() else None,
                ocr_applied=cdr_result.ocr_applied,
                entropy=scan_result.entropy,
            )
            session.add_file(entry)
            return True
        else:
            # CDR BAŞARISIZ → ASLA kopyalama → karantina
            self._logger.warning(
                "CDR BAŞARISIZ: %s — %s — karantinaya alınıyor",
                filepath.name, cdr_result.reason,
            )
            self._quarantine_file(filepath, source_root)

            entry = FileEntry(
                original_path=str(relative),
                original_sha256=cdr_result.original_sha256,
                original_size=scan_result.file_size,
                action="quarantined",
                entropy=scan_result.entropy,
                detections=[{
                    "engine": "cdr",
                    "rule": "CDR_FAILED",
                    "detail": cdr_result.reason,
                }],
            )
            session.add_file(entry)
            session.summary.cdr_failed += 1
            return True  # İşlendi (karantina)

    def _apply_image_cdr(
        self,
        filepath: Path,
        target_path: Path,
        relative: Path,
        scan_result: ScanResult,
        session: ScanSession,
        target_root: Path,
        source_root: Path,
    ) -> bool:
        """Resim CDR uygula."""
        # Hedef path güvenlik kontrolü
        if not safe_mkdir_no_symlink(target_path.parent, target_root):
            self._logger.warning(
                "IMAGE CDR HEDEF SYMLINK ENGELLENDİ: %s", target_path,
            )
            return False

        if not validate_target_path(target_path, target_root):
            return False

        if self._hw_event:
            self._hw_event("cdr")
        cdr_result = self._cdr_engine.process_image(filepath, target_path)

        if cdr_result.success:
            out_rel = None
            out_size = None
            if cdr_result.output_path and cdr_result.output_path.exists():
                try:
                    out_rel = str(cdr_result.output_path.relative_to(
                        target_root
                    ))
                except ValueError:
                    out_rel = str(cdr_result.output_path.name)
                out_size = cdr_result.output_path.stat().st_size

            entry = FileEntry(
                original_path=str(relative),
                original_sha256=cdr_result.original_sha256,
                original_size=scan_result.file_size,
                action="cdr_image_strip",
                output_path=out_rel,
                output_sha256=cdr_result.output_sha256,
                output_size=out_size,
                entropy=scan_result.entropy,
            )
            session.add_file(entry)
            return True
        else:
            self._quarantine_file(filepath, source_root)
            entry = FileEntry(
                original_path=str(relative),
                original_sha256=cdr_result.original_sha256,
                original_size=scan_result.file_size,
                action="quarantined",
                entropy=scan_result.entropy,
                detections=[{
                    "engine": "cdr",
                    "rule": "CDR_FAILED",
                    "detail": cdr_result.reason,
                }],
            )
            session.add_file(entry)
            session.summary.cdr_failed += 1
            return True

    def _apply_text_cdr(
        self,
        filepath: Path,
        target_path: Path,
        relative: Path,
        scan_result: ScanResult,
        session: ScanSession,
        target_root: Path,
        source_root: Path,
    ) -> bool:
        """Metin CDR uygula."""
        # Hedef path güvenlik kontrolü
        if not safe_mkdir_no_symlink(target_path.parent, target_root):
            self._logger.warning(
                "TEXT CDR HEDEF SYMLINK ENGELLENDİ: %s", target_path,
            )
            return False

        if not validate_target_path(target_path, target_root):
            return False

        cdr_result = self._cdr_engine.process_text(filepath, target_path)

        if cdr_result.success:
            out_rel = None
            out_size = None
            if cdr_result.output_path and cdr_result.output_path.exists():
                try:
                    out_rel = str(cdr_result.output_path.relative_to(
                        target_root
                    ))
                except ValueError:
                    out_rel = str(cdr_result.output_path.name)
                out_size = cdr_result.output_path.stat().st_size

            entry = FileEntry(
                original_path=str(relative),
                original_sha256=cdr_result.original_sha256,
                original_size=scan_result.file_size,
                action="cdr_text_clean",
                output_path=out_rel,
                output_sha256=cdr_result.output_sha256,
                output_size=out_size,
                entropy=scan_result.entropy,
            )
            session.add_file(entry)
            return True
        else:
            self._quarantine_file(filepath, source_root)
            entry = FileEntry(
                original_path=str(relative),
                original_sha256=cdr_result.original_sha256,
                original_size=scan_result.file_size,
                action="quarantined",
                detections=[{
                    "engine": "cdr",
                    "rule": "CDR_FAILED",
                    "detail": cdr_result.reason,
                }],
            )
            session.add_file(entry)
            session.summary.cdr_failed += 1
            return True

    def _copy_clean_file(
        self,
        filepath: Path,
        target_path: Path,
        relative: Path,
        scan_result: ScanResult,
        session: ScanSession,
        target_root: Path,
    ) -> None:
        """Temiz dosyayı doğrudan hedefe kopyala — symlink koruması ile."""
        # Güvenli kopyalama: hedef USB'deki symlink/traversal kontrolü
        if not safe_copy_no_symlink(filepath, target_path, target_root):
            self._logger.warning(
                "HEDEF SYMLINK/TRAVERSAL ENGELLENDİ: %s → %s", filepath.name, target_path,
            )
            entry = FileEntry(
                original_path=str(relative),
                original_sha256=scan_result.sha256,
                original_size=scan_result.file_size,
                action="blocked",
                entropy=scan_result.entropy,
                detections=[{
                    "engine": "target_validator",
                    "rule": "TARGET_SYMLINK_TRAVERSAL",
                    "detail": f"Hedef path güvenlik ihlali: {target_path}",
                }],
            )
            session.add_file(entry)
            return

        try:
            entry = FileEntry(
                original_path=str(relative),
                original_sha256=scan_result.sha256,
                original_size=scan_result.file_size,
                action="clean_copy",
                output_path=str(relative),
                output_sha256=sha256_file(target_path),
                output_size=target_path.stat().st_size,
                entropy=scan_result.entropy,
            )
            session.add_file(entry)

        except OSError as exc:
            self._logger.error("Dosya kopyalama hatası: %s — %s", filepath.name, exc)

    def _process_archive(
        self,
        filepath: Path,
        source_root: Path,
        target_root: Path,
        relative: Path,
        scan_result: ScanResult,
        session: ScanSession,
    ) -> None:
        """Arşiv dosyasını aç, tara ve CDR uygula."""
        policy = self._config.active_policy_settings

        if policy.archive_handling == "block":
            entry = FileEntry(
                original_path=str(relative),
                original_sha256=scan_result.sha256,
                original_size=scan_result.file_size,
                action="blocked",
                entropy=scan_result.entropy,
                detections=[{
                    "engine": "policy",
                    "rule": "ARCHIVE_BLOCKED",
                    "detail": f"Arşivler engellenmiş (politika: {policy.name})",
                }],
            )
            session.add_file(entry)
            return

        # Hedef dizin: arşiv adıyla alt klasör
        archive_target_dir = target_root / relative.stem

        archive_result = self._archive_handler.extract_and_process(
            filepath=filepath,
            target_dir=archive_target_dir,
            scanner=self._scanner,
            cdr_engine=self._cdr_engine,
            file_validator=self._file_validator,
        )

        # Arşiv sonuçlarını session'a ekle
        for af in archive_result.files:
            entry = FileEntry(
                original_path=f"{relative}/{af.relative_path}",
                original_sha256="",
                original_size=0,
                action=af.action,
                output_path=str(af.output_path.relative_to(target_root)) if af.output_path else None,
                output_sha256=sha256_file(af.output_path) if af.output_path and af.output_path.exists() else None,
                detections=[{"engine": "archive", "rule": af.action, "detail": af.detail}] if af.action in ("blocked", "quarantined") else [],
            )
            session.add_file(entry)

    # ═══════════════════════════════════════════
    # KARANTİNA
    # ═══════════════════════════════════════════

    def _quarantine_file(self, filepath: Path, source_root: Path) -> None:
        """Dosyayı karantina dizinine kopyala."""
        quarantine_dir = DIRECTORIES["quarantine"]
        try:
            relative = filepath.relative_to(source_root)
            dest = quarantine_dir / relative
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(filepath, dest)
            self._logger.info("Karantinaya alındı: %s → %s", filepath.name, dest)
        except (OSError, ValueError) as exc:
            self._logger.error("Karantina kopyalama hatası: %s — %s", filepath.name, exc)

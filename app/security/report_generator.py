"""
THE AIRLOCK v5.0.8 FORTRESS-HARDENED — KATMAN 7: İmzalı Rapor ve Manifest Üretimi

Her tarama oturumu sonunda:
  1. JSON rapor dosyası üretilir (yapılandırılmış format)
  2. Tüm temiz dosyaların SHA-256 manifest'i oluşturulur
  3. Rapor Ed25519 anahtarıyla imzalanır
  4. Rapor hem log dizinine hem temiz USB'ye kopyalanır

Rapor imzası, raporun bütünlüğünü ve kaynağını doğrular.
Herhangi bir değişiklik imzayı geçersiz kılar.

GÜVENLİK KURALI: Rapor → ASLA imzasız bırakma.
                  İmzalama anahtarı yoksa uyar ama rapor üret.

Kullanım:
    gen = ReportGenerator(config=cfg)
    report = gen.generate(session)
    gen.write_report(report, target_usb_dir)
    gen.write_manifest(report, target_usb_dir)
"""

from __future__ import annotations

import json
import logging
import platform
import shutil
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.config import (
    AirlockConfig,
    DIRECTORIES,
    VERSION,
    CODENAME,
)
from app.utils.crypto import sha256_bytes, sha256_file, sign_data, verify_signature

logger = logging.getLogger("AIRLOCK.REPORT")


# ─────────────────────────────────────────────
# Veri Yapıları
# ─────────────────────────────────────────────


@dataclass
class FileEntry:
    """Rapordaki tek dosya kaydı."""

    original_path: str
    original_sha256: str
    original_size: int
    action: str           # "clean_copy", "cdr_rasterize", "cdr_image_strip",
                          # "cdr_text_clean", "cdr_office", "blocked", "quarantined"
    output_path: Optional[str] = None
    output_sha256: Optional[str] = None
    output_size: Optional[int] = None
    detections: List[Dict[str, str]] = field(default_factory=list)
    ocr_applied: bool = False
    entropy: float = 0.0


@dataclass
class USBSourceInfo:
    """Kaynak USB bilgileri."""

    vendor_id: str = ""
    product_id: str = ""
    manufacturer: str = ""
    serial: str = ""
    filesystem: str = ""
    label: str = ""
    total_size_mb: int = 0


@dataclass
class ScanSummary:
    """Tarama oturumu özet istatistikleri."""

    total_files: int = 0
    processed: int = 0
    blocked: int = 0
    quarantined: int = 0
    cdr_applied: int = 0
    cdr_failed: int = 0
    threats_detected: int = 0
    clean_copied: int = 0
    duration_seconds: float = 0.0


@dataclass
class ScanSession:
    """Bir tarama oturumunun tüm verileri."""

    policy: str = "balanced"
    usb_source: USBSourceInfo = field(default_factory=USBSourceInfo)
    summary: ScanSummary = field(default_factory=ScanSummary)
    files: List[FileEntry] = field(default_factory=list)
    start_time: Optional[float] = None
    end_time: Optional[float] = None

    def start(self) -> None:
        """Oturumu başlat — zamanlayıcıyı başlat."""
        self.start_time = time.monotonic()

    def finish(self) -> None:
        """Oturumu bitir — süreyi hesapla."""
        self.end_time = time.monotonic()
        if self.start_time is not None:
            self.summary.duration_seconds = round(
                self.end_time - self.start_time, 2
            )

    def add_file(self, entry: FileEntry) -> None:
        """Dosya kaydı ekle ve istatistikleri güncelle."""
        self.files.append(entry)
        self.summary.total_files += 1

        if entry.action == "clean_copy":
            self.summary.processed += 1
            self.summary.clean_copied += 1
        elif entry.action.startswith("cdr_"):
            self.summary.processed += 1
            self.summary.cdr_applied += 1
        elif entry.action == "blocked":
            self.summary.blocked += 1
        elif entry.action == "quarantined":
            self.summary.quarantined += 1

        if entry.detections:
            self.summary.threats_detected += len(entry.detections)


# ─────────────────────────────────────────────
# Report Generator
# ─────────────────────────────────────────────


class ReportGenerator:
    """
    İmzalı JSON rapor ve SHA-256 manifest üreticisi.

    Her tarama sonunda çağrılır.
    Rapor Ed25519 ile imzalanır, manifest dosya hash'lerini içerir.
    """

    def __init__(self, config: Optional[AirlockConfig] = None) -> None:
        self._logger = logging.getLogger("AIRLOCK.REPORT")
        self._config = config or AirlockConfig()
        self._signing_key_path = DIRECTORIES["keys"] / "report_signing.key"
        self._station_id = self._get_station_id()

    # ── Rapor Üretimi ──

    def generate(self, session: ScanSession) -> Dict[str, Any]:
        """
        Tarama oturumundan JSON rapor üret.

        Rapor yapısı:
          - version, codename, timestamp, station_id
          - policy
          - summary (istatistikler)
          - usb_source (kaynak USB bilgileri)
          - files (dosya kayıtları listesi)
          - signature (Ed25519 imza — ayrı eklenir)

        Args:
            session: Tamamlanmış ScanSession

        Returns:
            Rapor sözlüğü (JSON-serializable)
        """
        now = datetime.now(timezone.utc)

        report: Dict[str, Any] = {
            "version": VERSION,
            "codename": CODENAME,
            "timestamp": now.isoformat(),
            "station_id": self._station_id,
            "policy": session.policy,
            "summary": {
                "total_files": session.summary.total_files,
                "processed": session.summary.processed,
                "blocked": session.summary.blocked,
                "quarantined": session.summary.quarantined,
                "cdr_applied": session.summary.cdr_applied,
                "cdr_failed": session.summary.cdr_failed,
                "threats_detected": session.summary.threats_detected,
                "clean_copied": session.summary.clean_copied,
                "duration_seconds": session.summary.duration_seconds,
            },
            "usb_source": {
                "vendor_id": session.usb_source.vendor_id,
                "product_id": session.usb_source.product_id,
                "manufacturer": session.usb_source.manufacturer,
                "serial": session.usb_source.serial,
                "filesystem": session.usb_source.filesystem,
                "label": session.usb_source.label,
                "total_size_mb": session.usb_source.total_size_mb,
            },
            "files": [
                {
                    "original_path": f.original_path,
                    "original_sha256": f.original_sha256,
                    "original_size": f.original_size,
                    "action": f.action,
                    "output_path": f.output_path,
                    "output_sha256": f.output_sha256,
                    "output_size": f.output_size,
                    "detections": f.detections,
                    "ocr_applied": f.ocr_applied,
                    "entropy": f.entropy,
                }
                for f in session.files
            ],
        }

        self._logger.info(
            "Rapor üretildi: %d dosya, %d tehdit, %.1f saniye",
            session.summary.total_files,
            session.summary.threats_detected,
            session.summary.duration_seconds,
        )

        return report

    # ── İmzalama ──

    def sign_report(self, report: Dict[str, Any]) -> str:
        """
        Rapor JSON'ını Ed25519 ile imzala.

        İmza, "signature" alanı HARİÇ tüm rapor üzerinden hesaplanır.
        Böylece imza eklenmiş rapor doğrulanabilir.

        Args:
            report: Rapor sözlüğü ("signature" alanı olmadan)

        Returns:
            Base64-encoded Ed25519 imza

        Raises:
            FileNotFoundError: İmzalama anahtarı bulunamazsa
        """
        # İmzalanacak veri: JSON (deterministic sort)
        report_copy = {k: v for k, v in report.items() if k != "signature"}
        report_json = json.dumps(
            report_copy, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")

        signature = sign_data(report_json, self._signing_key_path)

        self._logger.info("Rapor imzalandı (Ed25519)")
        return signature

    def verify_report(
        self, report: Dict[str, Any], public_key_path: Optional[Path] = None
    ) -> bool:
        """
        Raporun Ed25519 imzasını doğrula.

        Args:
            report: İmzalı rapor sözlüğü ("signature" alanı dahil)
            public_key_path: Açık anahtar dosyası. None ise varsayılan.

        Returns:
            True: imza geçerli
            False: imza geçersiz veya eksik
        """
        signature_b64 = report.get("signature")
        if not signature_b64:
            self._logger.warning("Raporda imza alanı bulunamadı")
            return False

        if public_key_path is None:
            public_key_path = self._config.update_public_key_path

        report_copy = {k: v for k, v in report.items() if k != "signature"}
        report_json = json.dumps(
            report_copy, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")

        return verify_signature(report_json, signature_b64, public_key_path)

    # ── Rapor Yazma ──

    def write_report(
        self,
        report: Dict[str, Any],
        *target_dirs: Path,
        sign: bool = True,
    ) -> Path:
        """
        Raporu JSON dosyası olarak yaz.

        İmzala (opsiyonel) ve belirtilen dizinlere kopyala.

        Args:
            report: Rapor sözlüğü
            *target_dirs: Raporun yazılacağı dizinler (log + USB)
            sign: True ise imzala (varsayılan)

        Returns:
            İlk hedef dizindeki rapor dosya yolu
        """
        # İmzala
        if sign:
            try:
                signature = self.sign_report(report)
                report["signature"] = signature
            except (FileNotFoundError, ImportError, Exception) as exc:
                self._logger.warning(
                    "Rapor imzalanamadı: %s — imzasız devam ediliyor", exc
                )
                report["signature"] = None

        # JSON oluştur
        timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"airlock_report_{timestamp_str}.json"

        report_json = json.dumps(
            report, ensure_ascii=False, indent=2, sort_keys=False
        )

        first_path: Optional[Path] = None

        # Her hedef dizine yaz
        for target_dir in target_dirs:
            try:
                target_dir.mkdir(parents=True, exist_ok=True)
                report_path = target_dir / filename
                report_path.write_text(report_json, encoding="utf-8")

                if first_path is None:
                    first_path = report_path

                self._logger.info("Rapor yazıldı: %s", report_path)
            except OSError as exc:
                self._logger.error(
                    "Rapor yazılamadı (%s): %s", target_dir, exc
                )

        # Log dizinine her zaman yaz
        log_dir = DIRECTORIES["logs"]
        log_report_path = log_dir / filename
        if first_path is None or first_path.parent != log_dir:
            try:
                log_dir.mkdir(parents=True, exist_ok=True)
                log_report_path.write_text(report_json, encoding="utf-8")
                self._logger.info("Rapor log dizinine yazıldı: %s", log_report_path)
                if first_path is None:
                    first_path = log_report_path
            except OSError as exc:
                self._logger.error("Rapor log dizinine yazılamadı: %s", exc)

        return first_path or Path("/dev/null")

    # ── Manifest Yazma ──

    def write_manifest(
        self,
        files: List[FileEntry],
        target_dir: Path,
        filename: str = "manifest.sha256",
    ) -> Optional[Path]:
        """
        Temiz USB'ye SHA-256 manifest dosyası yaz.

        Format:
          sha256_hash  dosya/yolu.ext
          sha256_hash  başka/dosya.pdf

        Sadece başarıyla işlenmiş (output_sha256 olan) dosyalar dahil edilir.

        Args:
            files: Dosya kayıtları listesi
            target_dir: Manifest'in yazılacağı dizin
            filename: Manifest dosya adı

        Returns:
            Manifest dosya yolu veya None (hata)
        """
        lines: List[str] = []

        for entry in files:
            if entry.output_sha256 and entry.output_path:
                lines.append(f"{entry.output_sha256}  {entry.output_path}")

        if not lines:
            self._logger.info("Manifest: yazılacak dosya yok (tümü engellendi/karantinada)")
            return None

        manifest_content = "\n".join(lines) + "\n"

        try:
            target_dir.mkdir(parents=True, exist_ok=True)
            manifest_path = target_dir / filename
            manifest_path.write_text(manifest_content, encoding="utf-8")

            self._logger.info(
                "Manifest yazıldı: %s (%d dosya)", manifest_path, len(lines)
            )
            return manifest_path

        except OSError as exc:
            self._logger.error("Manifest yazılamadı: %s", exc)
            return None

    def verify_manifest(
        self, manifest_path: Path, base_dir: Path
    ) -> Dict[str, bool]:
        """
        Manifest dosyasındaki hash'leri doğrula.

        Args:
            manifest_path: Manifest dosya yolu
            base_dir: Dosyaların bulunduğu kök dizin

        Returns:
            {dosya_yolu: doğrulama_sonucu} sözlüğü
        """
        results: Dict[str, bool] = {}

        try:
            content = manifest_path.read_text(encoding="utf-8")
        except OSError as exc:
            self._logger.error("Manifest okunamadı: %s", exc)
            return results

        for line in content.strip().splitlines():
            line = line.strip()
            if not line:
                continue

            parts = line.split("  ", 1)
            if len(parts) != 2:
                continue

            expected_hash, file_path_str = parts
            file_path = base_dir / file_path_str

            if not file_path.exists():
                results[file_path_str] = False
                continue

            actual_hash = sha256_file(file_path)
            results[file_path_str] = (actual_hash == expected_hash)

        valid = sum(1 for v in results.values() if v)
        total = len(results)
        self._logger.info(
            "Manifest doğrulama: %d/%d dosya geçerli", valid, total
        )

        return results

    # ── Dahili Yardımcılar ──

    @staticmethod
    def _get_station_id() -> str:
        """
        Cihaz benzersiz kimliği oluştur.

        Raspberry Pi'de /proc/cpuinfo'dan seri numarası okunur.
        Bulunamazsa hostname kullanılır.

        Returns:
            "AIRLOCK-xxxx" formatında station ID
        """
        # Raspberry Pi seri numarası
        try:
            cpuinfo = Path("/proc/cpuinfo").read_text(encoding="utf-8")
            for line in cpuinfo.splitlines():
                if line.strip().startswith("Serial"):
                    serial = line.split(":")[-1].strip()
                    short = serial[-8:]  # Son 8 karakter
                    return f"AIRLOCK-{short}"
        except (FileNotFoundError, OSError):
            pass

        # Fallback: hostname
        hostname = platform.node() or "unknown"
        return f"AIRLOCK-{hostname[:12]}"

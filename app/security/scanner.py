"""
THE AIRLOCK v5.1.1 FORTRESS-HARDENED — KATMAN 5: Çok Motorlu Dosya Tarama

4 tarama motoru:
  1. ClamAV — 8M+ malware imzası (pyclamd daemon veya clamscan fallback)
  2. YARA — Pattern matching (core + custom kurallar)
  3. Entropy Analizi — Shannon entropy (packed/encrypted payload tespiti)
  4. Magic Byte Doğrulama — Uzantı-içerik MIME eşleşmesi

Ek:
  5. Bilinen kötü hash kontrolü (SHA-256)

Kullanım:
    scanner = FileScanner(config=config)
    result = scanner.scan_file(filepath)
    if result.is_threat:
        # karantinaya al
"""

from __future__ import annotations

import hashlib
import logging
import math
import subprocess
import shutil
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, FrozenSet, List, Optional, Set

from app.config import (
    AirlockConfig,
    CLAMAV_SOCKET,
    DIRECTORIES,
    ENTROPY_SUSPICIOUS_THRESHOLD,
    ENTROPY_VERY_HIGH_THRESHOLD,
    YARA_TIMEOUT_SECONDS,
)

logger = logging.getLogger("AIRLOCK.SCANNER")


# ─────────────────────────────────────────────
# Veri Yapıları
# ─────────────────────────────────────────────


@dataclass
class Detection:
    """Tek bir tarama motoru tarafından bulunan tespit."""

    engine: str       # "clamav" | "yara" | "entropy" | "magic" | "hash"
    rule_name: str    # Kural/imza adı
    details: str      # Ek detay


@dataclass
class ScanResult:
    """Dosya tarama sonucu."""

    filepath: Path
    is_threat: bool
    threat_level: str  # "clean" | "suspicious" | "malicious"
    detections: List[Detection] = field(default_factory=list)
    mime_type: str = ""
    sha256: str = ""
    entropy: float = 0.0
    file_size: int = 0

    @property
    def detection_summary(self) -> str:
        """Tespitlerin tek satırlık özeti."""
        if not self.detections:
            return "clean"
        parts = [f"{d.engine}:{d.rule_name}" for d in self.detections]
        return " | ".join(parts)


# ─────────────────────────────────────────────
# Uzantı → Beklenen MIME Eşlemesi
# ─────────────────────────────────────────────

# Magic byte doğrulama için uzantı-MIME eşleştirmesi
_EXTENSION_MIME_MAP: Dict[str, FrozenSet[str]] = {
    ".pdf": frozenset({"application/pdf"}),
    ".doc": frozenset({"application/msword", "application/vnd.ms-word"}),
    ".docx": frozenset({
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/zip",
    }),
    ".xls": frozenset({"application/vnd.ms-excel"}),
    ".xlsx": frozenset({
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/zip",
    }),
    ".ppt": frozenset({"application/vnd.ms-powerpoint"}),
    ".pptx": frozenset({
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "application/zip",
    }),
    ".jpg": frozenset({"image/jpeg"}),
    ".jpeg": frozenset({"image/jpeg"}),
    ".png": frozenset({"image/png"}),
    ".gif": frozenset({"image/gif"}),
    ".bmp": frozenset({"image/bmp", "image/x-ms-bmp"}),
    ".tiff": frozenset({"image/tiff"}),
    ".tif": frozenset({"image/tiff"}),
    ".webp": frozenset({"image/webp"}),
    ".svg": frozenset({"image/svg+xml", "text/xml", "application/xml"}),
    ".zip": frozenset({"application/zip", "application/x-zip-compressed"}),
    ".rar": frozenset({"application/x-rar-compressed", "application/vnd.rar"}),
    ".7z": frozenset({"application/x-7z-compressed"}),
    ".tar": frozenset({"application/x-tar"}),
    ".gz": frozenset({"application/gzip", "application/x-gzip"}),
    ".bz2": frozenset({"application/x-bzip2"}),
    ".xz": frozenset({"application/x-xz"}),
    ".mp3": frozenset({"audio/mpeg"}),
    ".mp4": frozenset({"video/mp4"}),
    ".avi": frozenset({"video/x-msvideo", "video/avi"}),
    ".mkv": frozenset({"video/x-matroska"}),
    ".txt": frozenset({"text/plain"}),
    ".csv": frozenset({"text/csv", "text/plain", "application/csv"}),
    ".json": frozenset({"application/json", "text/plain"}),
    ".xml": frozenset({"text/xml", "application/xml"}),
    ".html": frozenset({"text/html"}),
    ".htm": frozenset({"text/html"}),
}


# ─────────────────────────────────────────────
# File Scanner
# ─────────────────────────────────────────────


class FileScanner:
    """
    Çok motorlu dosya tarayıcı.

    Her dosya 4 motor + hash kontrolünden geçer.
    Herhangi biri "malicious" dönerse → is_threat = True.
    """

    # Hash dosyasını okurken cache'le
    _known_bad_hashes: Optional[Set[str]] = None

    def __init__(self, config: Optional[AirlockConfig] = None) -> None:
        """
        Args:
            config: Uygulama yapılandırması. None ise varsayılan kullanılır.
        """
        self._logger = logging.getLogger("AIRLOCK.SCANNER")
        self._config = config or AirlockConfig()

        # Motor durumları
        self._clamav_available: Optional[bool] = None
        self._yara_available: Optional[bool] = None
        self._yara_rules_compiled: Optional[object] = None  # yara.Rules

    # ── Ana Tarama ──

    def scan_file(self, filepath: Path) -> ScanResult:
        """
        Dosyayı tüm motorlarla tara.

        Args:
            filepath: Taranacak dosya yolu

        Returns:
            ScanResult: Tarama sonucu (is_threat, detections, entropy, sha256, …)
        """
        detections: List[Detection] = []
        threat_level = "clean"

        # Dosya boyutu
        try:
            file_size = filepath.stat().st_size
        except OSError as exc:
            self._logger.error("Dosya erişim hatası: %s — %s", filepath, exc)
            return ScanResult(
                filepath=filepath,
                is_threat=False,
                threat_level="error",
                file_size=0,
            )

        # SHA-256 hesapla (tüm motorlar için ortak)
        sha256 = self._calculate_sha256(filepath)

        # MIME type tespit et (magic byte doğrulama için)
        mime_type = self._detect_mime_type(filepath)

        # Entropy hesapla
        entropy = self._calculate_entropy(filepath)

        # ── Motor 1: ClamAV ──
        if self._config.clamav_enabled:
            clamav_detection = self._scan_clamav(filepath)
            if clamav_detection:
                detections.append(clamav_detection)

        # ── Motor 2: YARA ──
        if self._config.yara_enabled:
            yara_detections = self._scan_yara(filepath)
            detections.extend(yara_detections)

        # ── Motor 3: Entropy Analizi ──
        if self._config.entropy_enabled:
            entropy_detection = self._evaluate_entropy(filepath, entropy)
            if entropy_detection:
                detections.append(entropy_detection)

        # ── Motor 4: Magic Byte Doğrulama ──
        if self._config.magic_byte_check:
            magic_detection = self._verify_magic_bytes(filepath, mime_type)
            if magic_detection:
                detections.append(magic_detection)

        # ── Motor 5: Bilinen Kötü Hash ──
        if self._config.hash_check:
            hash_detection = self._check_known_hashes(sha256)
            if hash_detection:
                detections.append(hash_detection)

        # ── Tehdit Seviyesi Hesapla ──
        if detections:
            # Herhangi biri malicious → dosya tehlikeli
            has_malicious = any(
                d.engine in ("clamav", "hash") or
                (d.engine == "yara" and "suspicious" not in d.rule_name.lower())
                for d in detections
            )

            if has_malicious:
                threat_level = "malicious"
            else:
                threat_level = "suspicious"

        result = ScanResult(
            filepath=filepath,
            is_threat=(threat_level == "malicious"),
            threat_level=threat_level,
            detections=detections,
            mime_type=mime_type,
            sha256=sha256,
            entropy=entropy,
            file_size=file_size,
        )

        # Sonucu logla
        if result.is_threat:
            self._logger.warning(
                "TEHDİT TESPİT EDİLDİ: %s — %s [sha256=%s, entropy=%.2f]",
                filepath.name,
                result.detection_summary,
                sha256[:16],
                entropy,
            )
        elif detections:
            self._logger.info(
                "ŞÜPHELİ: %s — %s [entropy=%.2f]",
                filepath.name,
                result.detection_summary,
                entropy,
            )
        else:
            self._logger.debug(
                "TEMİZ: %s [sha256=%s, entropy=%.2f, mime=%s]",
                filepath.name,
                sha256[:16],
                entropy,
                mime_type,
            )

        return result

    # ── Motor 1: ClamAV ──

    def _scan_clamav(self, filepath: Path) -> Optional[Detection]:
        """
        ClamAV ile dosyayı tara.

        Önce pyclamd daemon'a bağlanmayı dener.
        Daemon yoksa clamscan komut satırı aracına fallback yapar.

        Returns:
            Detection: Tespit varsa, None: temiz
        """
        # Yöntem A: pyclamd ile daemon bağlantısı
        detection = self._scan_clamav_daemon(filepath)
        if detection is not None:
            return detection if detection else None

        # Yöntem B: clamscan fallback
        return self._scan_clamav_cli(filepath)

    def _scan_clamav_daemon(self, filepath: Path) -> Optional[Detection | bool]:
        """
        pyclamd ile ClamAV daemon'a bağlan.

        Returns:
            Detection: tehdit bulundu
            False: temiz (daemon erişildi, tehdit yok)
            None: daemon erişilemedi (fallback gerekli)
        """
        if self._clamav_available is False:
            return None

        try:
            import pyclamd  # noqa: PLC0415
        except ImportError:
            self._logger.debug("pyclamd yüklü değil — clamscan fallback kullanılacak")
            self._clamav_available = False
            return None

        try:
            clamd = pyclamd.ClamdUnixSocket(filename=str(self._config.clamav_socket))
            if not clamd.ping():
                self._logger.warning("ClamAV daemon'a ping başarısız")
                self._clamav_available = False
                return None

            self._clamav_available = True
            scan_result = clamd.scan_file(str(filepath))

            if scan_result is None:
                return False  # Temiz

            # scan_result formatı: {'/path/to/file': ('FOUND', 'Eicar-Signature')}
            for _path, (status, signature) in scan_result.items():
                if status == "FOUND":
                    return Detection(
                        engine="clamav",
                        rule_name=signature,
                        details=f"ClamAV tespit: {signature}",
                    )

            return False  # Temiz

        except Exception as exc:
            self._logger.warning("ClamAV daemon hatası: %s", exc)
            self._clamav_available = False
            return None

    def _scan_clamav_cli(self, filepath: Path) -> Optional[Detection]:
        """
        clamscan komut satırı aracı ile tara (fallback).

        shell=False ZORUNLU, timeout uygulanır.
        """
        try:
            result = subprocess.run(
                [
                    "clamscan",
                    "--no-summary",
                    "--infected",
                    str(filepath),
                ],
                capture_output=True,
                text=True,
                timeout=120,
            )

            # clamscan return code: 0=temiz, 1=virüs bulundu, 2=hata
            if result.returncode == 1:
                # Çıktı formatı: /path/to/file: Eicar-Signature FOUND
                output = result.stdout.strip()
                signature = "Unknown"
                if "FOUND" in output:
                    parts = output.rsplit(":", 1)
                    if len(parts) == 2:
                        signature = parts[1].replace("FOUND", "").strip()

                return Detection(
                    engine="clamav",
                    rule_name=signature,
                    details=f"ClamAV (cli) tespit: {signature}",
                )

            if result.returncode == 2:
                self._logger.warning(
                    "ClamAV cli hatası: %s", result.stderr.strip()
                )

            return None  # Temiz veya hata

        except FileNotFoundError:
            self._logger.warning("clamscan komutu bulunamadı — ClamAV kurulu değil")
            return None
        except subprocess.TimeoutExpired:
            self._logger.error(
                "ClamAV cli timeout: %s (120s aşıldı)", filepath.name
            )
            return None
        except OSError as exc:
            self._logger.error("ClamAV cli hatası: %s", exc)
            return None

    # ── Motor 2: YARA ──

    def _scan_yara(self, filepath: Path) -> List[Detection]:
        """
        YARA kuralları ile tara.

        core/ ve custom/ dizinlerindeki tüm .yar dosyalarını derler (ilk çağrıda).
        Sonraki çağrılarda derlenmiş kuralları kullanır.

        Returns:
            Tespit listesi (boş olabilir)
        """
        if self._yara_available is False:
            return []

        try:
            import yara  # noqa: PLC0415
        except ImportError:
            self._logger.debug("yara-python yüklü değil — YARA tarama atlanıyor")
            self._yara_available = False
            return []

        # Kuralları derle (ilk çağrıda)
        if self._yara_rules_compiled is None:
            self._yara_rules_compiled = self._compile_yara_rules(yara)
            if self._yara_rules_compiled is None:
                self._yara_available = False
                return []

        self._yara_available = True
        detections: List[Detection] = []

        try:
            matches = self._yara_rules_compiled.match(
                str(filepath),
                timeout=self._config.yara_timeout,
            )

            for match in matches:
                detections.append(
                    Detection(
                        engine="yara",
                        rule_name=match.rule,
                        details=f"YARA eşleşme: {match.rule} (tags: {match.tags})",
                    )
                )

        except yara.TimeoutError:
            self._logger.warning(
                "YARA timeout: %s (%ds aşıldı)",
                filepath.name,
                self._config.yara_timeout,
            )
        except yara.Error as exc:
            self._logger.error("YARA tarama hatası: %s — %s", filepath.name, exc)

        return detections

    def _compile_yara_rules(self, yara_module: object) -> Optional[object]:
        """
        Tüm YARA kural dosyalarını derle.

        core/ ve custom/ dizinlerindeki tüm .yar dosyalarını toplar ve derler.
        """
        rule_files: Dict[str, str] = {}

        for rules_dir_key in ("yara_core", "yara_custom"):
            rules_dir = DIRECTORIES.get(rules_dir_key)
            if rules_dir is None or not rules_dir.exists():
                continue

            for yar_file in sorted(rules_dir.glob("*.yar")):
                namespace = yar_file.stem
                rule_files[namespace] = str(yar_file)

            # .yara uzantılı dosyalar da
            for yar_file in sorted(rules_dir.glob("*.yara")):
                namespace = yar_file.stem
                rule_files[namespace] = str(yar_file)

        if not rule_files:
            self._logger.warning(
                "YARA kural dosyası bulunamadı: %s",
                [str(DIRECTORIES.get(k, "?")) for k in ("yara_core", "yara_custom")],
            )
            return None

        try:
            compiled = yara_module.compile(filepaths=rule_files)
            self._logger.info(
                "YARA kuralları derlendi: %d dosya", len(rule_files)
            )
            return compiled
        except Exception as exc:
            self._logger.error("YARA derleme hatası: %s", exc)
            return None

    # ── Motor 3: Entropy Analizi ──

    def _calculate_entropy(self, filepath: Path) -> float:
        """
        Shannon entropy hesapla.

        H = -Σ p(x) * log2(p(x))

        Referans değerler:
          Normal metin: ~4.0-5.0
          Sıkıştırılmış dosya: ~7.5-8.0
          Şifrelenmiş payload: ~7.9-8.0
          Rastgele veri: ~8.0

        Performans: Sadece ilk 1MB üzerinden hesaplar.

        Args:
            filepath: Dosya yolu

        Returns:
            Entropy değeri (0.0 — 8.0)
        """
        try:
            data = filepath.read_bytes()[:1024 * 1024]  # İlk 1MB
        except (OSError, PermissionError):
            return 0.0

        if not data:
            return 0.0

        counter = Counter(data)
        length = len(data)

        entropy = -sum(
            (count / length) * math.log2(count / length)
            for count in counter.values()
        )
        return round(entropy, 4)

    def _evaluate_entropy(
        self, filepath: Path, entropy: float
    ) -> Optional[Detection]:
        """
        Entropy değerini politika eşiğine göre değerlendir.

        Returns:
            Detection: Eşik aşıldıysa
            None: Normal aralıkta
        """
        policy = self._config.active_policy_settings

        if entropy >= ENTROPY_VERY_HIGH_THRESHOLD:
            return Detection(
                engine="entropy",
                rule_name="VERY_HIGH_ENTROPY",
                details=(
                    f"Çok yüksek entropy: {entropy:.4f} >= {ENTROPY_VERY_HIGH_THRESHOLD} "
                    f"— olası encrypted/packed payload"
                ),
            )

        if entropy >= policy.entropy_threshold:
            return Detection(
                engine="entropy",
                rule_name="HIGH_ENTROPY",
                details=(
                    f"Yüksek entropy: {entropy:.4f} >= {policy.entropy_threshold} "
                    f"(politika: {policy.name})"
                ),
            )

        return None

    # ── Motor 4: Magic Byte Doğrulama ──

    def _detect_mime_type(self, filepath: Path) -> str:
        """
        python-magic veya file komutu ile gerçek MIME type tespit et.

        Returns:
            MIME type string (ör: "application/pdf")
        """
        # Yöntem A: python-magic kütüphanesi
        try:
            import magic as magic_lib  # noqa: PLC0415

            mime = magic_lib.from_file(str(filepath), mime=True)
            if mime:
                return mime
        except ImportError:
            pass
        except Exception as exc:
            self._logger.debug("python-magic hatası: %s", exc)

        # Yöntem B: file komutu (shell=False ZORUNLU)
        try:
            result = subprocess.run(
                ["file", "--mime-type", "--brief", str(filepath)],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
            self._logger.debug("file komutu hatası: %s", exc)

        return "application/octet-stream"

    def _verify_magic_bytes(
        self, filepath: Path, detected_mime: str
    ) -> Optional[Detection]:
        """
        Dosyanın uzantısı ile gerçek MIME türünü karşılaştır.

        Uyumsuzluk varsa → Detection döndür.
        Örnek: .jpg uzantılı ama içerik PE executable → TEHLİKELİ
        """
        extension = filepath.suffix.lower()

        if not extension or extension not in _EXTENSION_MIME_MAP:
            return None  # Bilinmeyen uzantı — bu kontrol atlanır

        expected_mimes = _EXTENSION_MIME_MAP[extension]

        if detected_mime not in expected_mimes:
            # application/octet-stream → bilinmeyen, zorunlu engelleme yok
            if detected_mime == "application/octet-stream":
                return None

            return Detection(
                engine="magic",
                rule_name="MIME_MISMATCH",
                details=(
                    f"Uzantı-içerik uyumsuzluğu: uzantı={extension} "
                    f"beklenen={sorted(expected_mimes)} "
                    f"gerçek={detected_mime}"
                ),
            )

        return None

    # ── Motor 5: Bilinen Kötü Hash ──

    def _check_known_hashes(self, sha256: str) -> Optional[Detection]:
        """
        SHA-256 hash'ini bilinen kötü hash listesiyle karşılaştır.

        Hash listesi /opt/airlock/data/known_bad_hashes.txt dosyasından okunur.
        İlk çağrıda yüklenir, sonrakilerde cache'ten kontrol edilir (O(1)).

        Returns:
            Detection: Hash listede bulunduysa
            None: Temiz
        """
        if FileScanner._known_bad_hashes is None:
            FileScanner._known_bad_hashes = self._load_known_hashes()

        if sha256.lower() in FileScanner._known_bad_hashes:
            return Detection(
                engine="hash",
                rule_name="KNOWN_BAD_HASH",
                details=f"Bilinen kötü hash: {sha256}",
            )

        return None

    def _load_known_hashes(self) -> Set[str]:
        """
        Bilinen kötü hash listesini dosyadan yükle.

        Dosya formatı: her satırda bir SHA-256 hash (küçük harf, 64 hex karakter).
        # ile başlayan satırlar yorum satırı.
        """
        hashes: Set[str] = set()
        hash_file = DIRECTORIES["data"] / "known_bad_hashes.txt"
        legacy_hash_file = DIRECTORIES["config"] / "known_bad_hashes.txt"

        # Geriye dönük uyumluluk: legacy konumu bir kez migrate et (v5.1.0 → v5.1.1)
        if not hash_file.exists() and legacy_hash_file.exists():
            try:
                shutil.copy2(legacy_hash_file, hash_file)
                self._logger.warning(
                    "Legacy hash list migrated: %s → %s",
                    legacy_hash_file,
                    hash_file,
                )
            except OSError as exc:
                self._logger.warning(
                    "Legacy hash list bulundu ama taşınamadı (%s). Legacy dosya okunacak: %s",
                    exc,
                    legacy_hash_file,
                )
                hash_file = legacy_hash_file

        if not hash_file.exists():
            self._logger.info(
                "Kötü hash listesi bulunamadı: %s — hash kontrolü boş liste ile çalışacak",
                hash_file,
            )
            return hashes

        try:
            for line in hash_file.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # Sadece geçerli SHA-256 hash'leri kabul et (64 hex karakter)
                cleaned = line.split()[0].lower()  # Satırda ek bilgi varsa ilk kelimeyi al
                if len(cleaned) == 64 and all(c in "0123456789abcdef" for c in cleaned):
                    hashes.add(cleaned)

            self._logger.info(
                "Kötü hash listesi yüklendi: %d hash — %s", len(hashes), hash_file
            )

        except (OSError, PermissionError) as exc:
            self._logger.error("Hash listesi okunamadı: %s — %s", hash_file, exc)

        return hashes

    # ── Ortak Yardımcılar ──

    @staticmethod
    def _calculate_sha256(filepath: Path) -> str:
        """
        Dosyanın SHA-256 hash'ini hesapla.

        Büyük dosyalar için 64KB bloklar halinde okur.
        """
        sha = hashlib.sha256()
        try:
            with filepath.open("rb") as fh:
                while True:
                    chunk = fh.read(65536)  # 64KB
                    if not chunk:
                        break
                    sha.update(chunk)
        except (OSError, PermissionError):
            return ""

        return sha.hexdigest()

    def reload_yara_rules(self) -> bool:
        """
        YARA kurallarını yeniden derle.

        Güncelleme sonrası veya kural değişikliğinde çağrılır.

        Returns:
            True: başarılı
            False: derleme hatası
        """
        self._yara_rules_compiled = None
        self._yara_available = None

        try:
            import yara  # noqa: PLC0415
        except ImportError:
            self._logger.error("yara-python yüklü değil")
            return False

        compiled = self._compile_yara_rules(yara)
        if compiled is None:
            return False

        self._yara_rules_compiled = compiled
        self._yara_available = True
        return True

    def reload_known_hashes(self) -> int:
        """
        Bilinen kötü hash listesini yeniden yükle.

        Returns:
            Yüklenen hash sayısı
        """
        FileScanner._known_bad_hashes = self._load_known_hashes()
        return len(FileScanner._known_bad_hashes)

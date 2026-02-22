#!/usr/bin/env python3
"""
Ses Efektleri Modülü.

THE AIRLOCK v5.1.1 FORTRESS-HARDENED — Sesli Geri Bildirim

Olaylar ve sesleri:
    startup          — Kısa melodi (sistem açıldı)
    usb_detect       — Tek tık (USB algılandı)
    usb_blocked      — Alarm (BadUSB engellendi)
    file_done        — Kısa tık (dosya işlendi)
    threat           — Uyarı sesi (tehdit bulundu)
    complete         — Başarı melodisi (işlem tamamlandı)
    error            — Düşük ton (hata oluştu)
    button           — Tık sesi (buton basıldı)
    shutdown         — Kapanış sesi
    update_complete  — Güncelleme tamamlandı melodisi

Ses dosyaları: /opt/airlock/data/sounds/ dizinindeki WAV dosyaları.
``generate_sounds.py`` scripti tarafından kurulumda oluşturulur.

Çalma: pygame.mixer tercih edilir. Yoksa ``aplay`` fallback.
Ses yoksa (hoparlör bağlı değil veya pygame yok) ``available = False``.
"""

from __future__ import annotations

import logging
import subprocess
import threading
from pathlib import Path
from typing import Dict, Optional

# ── pygame (opsiyonel) ──
try:
    import pygame  # type: ignore[import-untyped]
    import pygame.mixer  # type: ignore[import-untyped]
    _PYGAME_AVAILABLE = True
except ImportError:
    _PYGAME_AVAILABLE = False


logger = logging.getLogger("AIRLOCK.AUDIO")

# ── Sabitler ──
_DEFAULT_SOUNDS_DIR = Path("/opt/airlock/data/sounds")
_APLAY_TIMEOUT = 10  # saniye

# ── Olay → WAV dosya adı eşlemesi ──
_EVENT_FILES: Dict[str, str] = {
    "startup":          "startup.wav",
    "usb_detect":       "usb_detect.wav",
    "usb_blocked":      "usb_blocked.wav",
    "file_done":        "file_done.wav",
    "threat":           "threat.wav",
    "complete":         "complete.wav",
    "error":            "error.wav",
    "button":           "button.wav",
    "shutdown":         "shutdown.wav",
    "update_complete":  "update_complete.wav",
}


class AudioFeedback:
    """
    Ses efektleri kontrolcüsü.

    pygame.mixer ile WAV dosyalarını çalar. pygame yoksa ``aplay``
    komutu fallback olarak kullanılır. Hiçbiri çalışmazsa
    ``available = False``.
    """

    def __init__(
        self,
        sounds_dir: str | Path = _DEFAULT_SOUNDS_DIR,
        volume: int = 80,
    ) -> None:
        """
        Ses sistemini başlat.

        Args:
            sounds_dir: WAV dosyalarının bulunduğu dizin.
            volume: Ses seviyesi (0-100).
        """
        self.available: bool = False
        self._sounds_dir: Path = Path(sounds_dir)
        self._volume: float = max(0.0, min(1.0, volume / 100.0))
        self._use_pygame: bool = False
        self._lock: threading.Lock = threading.Lock()
        self._play_thread: Optional[threading.Thread] = None

        # Ses dizini kontrolü
        if not self._sounds_dir.is_dir():
            logger.info("Ses dizini bulunamadi: %s", self._sounds_dir)
            # Yerel geliştirme ortamı desteği
            local_sounds = Path(__file__).resolve().parent.parent.parent / "data" / "sounds"
            if local_sounds.is_dir():
                self._sounds_dir = local_sounds
                logger.info("Yerel ses dizini kullaniliyor: %s", local_sounds)
            else:
                logger.info("Ses dosyalari bulunamadi - ses devre disi")
                return

        # WAV dosya varlığını kontrol et
        wav_count = sum(1 for f in _EVENT_FILES.values() if (self._sounds_dir / f).is_file())
        if wav_count == 0:
            logger.info("Hicbir WAV dosyasi bulunamadi - ses devre disi")
            return

        # pygame.mixer başlat
        if _PYGAME_AVAILABLE:
            try:
                if not pygame.mixer.get_init():
                    pygame.mixer.init(frequency=22050, size=-16, channels=1, buffer=1024)
                pygame.mixer.music.set_volume(self._volume)
                self._use_pygame = True
                self.available = True
                logger.info(
                    "Ses sistemi baslatildi (pygame, volume=%d%%, %d/%d WAV)",
                    int(self._volume * 100), wav_count, len(_EVENT_FILES),
                )
                return
            except Exception as exc:
                logger.info("pygame.mixer baslatma hatasi: %s", exc)

        # aplay fallback kontrolü
        if self._check_aplay():
            self.available = True
            logger.info(
                "Ses sistemi baslatildi (aplay fallback, %d/%d WAV)",
                wav_count, len(_EVENT_FILES),
            )
        else:
            logger.info("Ses sistemi kullanilamiyor - devre disi")

    # ─────────────────────────────────────────────
    # Genel API
    # ─────────────────────────────────────────────

    def play(self, event_name: str, blocking: bool = False) -> None:
        """
        Olay sesini çal.

        Args:
            event_name: ``_EVENT_FILES`` sözlüğündeki olay adı.
            blocking: ``True`` ise sesin bitmesini bekle.
                      ``False`` (varsayılan) ise ayrı thread'de çal.
        """
        if not self.available:
            return

        wav_file = _EVENT_FILES.get(event_name)
        if wav_file is None:
            logger.debug("Bilinmeyen ses olayi: %s", event_name)
            return

        wav_path = self._sounds_dir / wav_file
        if not wav_path.is_file():
            logger.debug("WAV dosyasi bulunamadi: %s", wav_path)
            return

        if blocking:
            self._play_sound(wav_path)
        else:
            # Non-blocking: thread'de çal
            self._play_thread = threading.Thread(
                target=self._play_sound,
                args=(wav_path,),
                name=f"audio-{event_name}",
                daemon=True,
            )
            self._play_thread.start()

    def set_volume(self, volume: int) -> None:
        """
        Ses seviyesini ayarla.

        Args:
            volume: 0-100 arası ses seviyesi.
        """
        self._volume = max(0.0, min(1.0, volume / 100.0))
        if self._use_pygame and _PYGAME_AVAILABLE:
            try:
                pygame.mixer.music.set_volume(self._volume)
            except Exception:
                pass

    def cleanup(self) -> None:
        """pygame.mixer'ı kapat ve kaynakları serbest bırak."""
        if self._use_pygame and _PYGAME_AVAILABLE:
            try:
                pygame.mixer.music.stop()
                pygame.mixer.quit()
            except Exception as exc:
                logger.debug("pygame cleanup hatasi: %s", exc)

        self.available = False
        logger.info("Ses sistemi kapatildi")

    # ─────────────────────────────────────────────
    # Düşük Seviye Çalma
    # ─────────────────────────────────────────────

    def _play_sound(self, wav_path: Path) -> None:
        """
        WAV dosyasını çal (blocking).

        pygame varsa mixer ile, yoksa aplay ile çalar.
        """
        with self._lock:
            if self._use_pygame:
                self._play_pygame(wav_path)
            else:
                self._play_aplay(wav_path)

    def _play_pygame(self, wav_path: Path) -> None:
        """pygame.mixer ile WAV çal."""
        try:
            sound = pygame.mixer.Sound(str(wav_path))
            sound.set_volume(self._volume)
            channel = sound.play()
            if channel is not None:
                while channel.get_busy():
                    pygame.time.wait(50)
        except Exception as exc:
            logger.debug("pygame ses calisma hatasi (%s): %s", wav_path.name, exc)

    def _play_aplay(self, wav_path: Path) -> None:
        """aplay komutu ile WAV çal (fallback)."""
        try:
            subprocess.run(
                ["aplay", "-q", str(wav_path)],
                timeout=_APLAY_TIMEOUT,
                check=False,
                shell=False,  # Güvenlik: ASLA shell=True
                capture_output=True,
            )
        except subprocess.TimeoutExpired:
            logger.debug("aplay timeout: %s", wav_path.name)
        except FileNotFoundError:
            logger.debug("aplay komutu bulunamadi")
        except Exception as exc:
            logger.debug("aplay hatasi (%s): %s", wav_path.name, exc)

    # ─────────────────────────────────────────────
    # Yardımcı
    # ─────────────────────────────────────────────

    @staticmethod
    def _check_aplay() -> bool:
        """aplay komutunun sistemde mevcut olup olmadığını kontrol et."""
        try:
            result = subprocess.run(
                ["which", "aplay"],
                timeout=5,
                check=False,
                shell=False,
                capture_output=True,
            )
            return result.returncode == 0
        except Exception:
            return False

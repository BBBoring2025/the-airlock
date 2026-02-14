#!/usr/bin/env python3
"""
Fiziksel Buton Kontrolcüsü (GPIO 21).

THE AIRLOCK v5.0.8 FORTRESS-HARDENED — Kullanıcı Etkileşimi

Davranışlar:
    Kısa basış  (< 3 saniye) — Güvenli çıkar (safe eject callback)
    Uzun basış  (>= 3 saniye) — Sistemi kapat (shutdown callback)

Debounce: 50ms (yazılımsal, bouncetime parametresi)
Pull-up: Dahili GPIO pull-up resistor (GPIO.PUD_UP)
Bağlantı: Buton → GPIO 21 ↔ GND (aktif LOW)

GPIO kullanılamıyorsa ``available = False``, tüm metodlar sessizce geçer.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Callable, Optional

# ── GPIO (opsiyonel) ──
try:
    import RPi.GPIO as GPIO  # type: ignore[import-untyped]
    _GPIO_AVAILABLE = True
except ImportError:
    _GPIO_AVAILABLE = False


logger = logging.getLogger("AIRLOCK.BUTTON")

# ── Sabitler ──
_DEFAULT_PIN = 21
_DEBOUNCE_MS = 50
_LONG_PRESS_THRESHOLD = 3.0  # saniye


class ButtonHandler:
    """
    Fiziksel buton kontrolcüsü.

    GPIO üzerinden buton basma olaylarını dinler.
    Kısa ve uzun basış ayrımı yapar.
    GPIO yoksa ``available = False``.
    """

    LONG_PRESS_THRESHOLD: float = _LONG_PRESS_THRESHOLD

    def __init__(
        self,
        pin: int = _DEFAULT_PIN,
        on_short_press: Optional[Callable[[], None]] = None,
        on_long_press: Optional[Callable[[], None]] = None,
        long_press_threshold: float = _LONG_PRESS_THRESHOLD,
    ) -> None:
        """
        GPIO event detect kur.

        BOTH edge (basıldı + bırakıldı) dinler ve basılma süresini ölçer.

        Args:
            pin: GPIO pin numarası (BCM).
            on_short_press: Kısa basış callback fonksiyonu.
            on_long_press: Uzun basış callback fonksiyonu.
            long_press_threshold: Uzun basış eşiği (saniye).
        """
        self.available: bool = False
        self._pin: int = pin
        self._on_short_press: Optional[Callable[[], None]] = on_short_press
        self._on_long_press: Optional[Callable[[], None]] = on_long_press
        self._long_press_threshold: float = long_press_threshold
        self._press_start_time: float = 0.0
        self._is_pressed: bool = False
        self._lock: threading.Lock = threading.Lock()
        self._callback_thread: Optional[threading.Thread] = None

        if not _GPIO_AVAILABLE:
            logger.info("RPi.GPIO bulunamadi - buton devre disi")
            return

        try:
            GPIO.setmode(GPIO.BCM)
            GPIO.setwarnings(False)

            # Dahili pull-up: buton basılınca LOW (GND'ye çeker)
            GPIO.setup(self._pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)

            # BOTH edge: hem FALLING (basıldı) hem RISING (bırakıldı)
            GPIO.add_event_detect(
                self._pin,
                GPIO.BOTH,
                callback=self._gpio_callback,
                bouncetime=_DEBOUNCE_MS,
            )

            self.available = True
            logger.info(
                "Buton handler baslatildi (pin=%d, debounce=%dms, long=%.1fs)",
                pin, _DEBOUNCE_MS, long_press_threshold,
            )
        except Exception as exc:
            logger.info("Buton baslatma hatasi: %s", exc)
            self.available = False

    # ─────────────────────────────────────────────
    # GPIO Callback
    # ─────────────────────────────────────────────

    def _gpio_callback(self, channel: int) -> None:
        """
        GPIO edge callback.

        FALLING (buton basıldı) → zamanı kaydet.
        RISING (buton bırakıldı) → süreyi hesapla → callback çağır.

        Args:
            channel: GPIO kanal numarası (pin).
        """
        with self._lock:
            current_state = GPIO.input(self._pin)

            if current_state == GPIO.LOW:
                # ── Buton basıldı (FALLING edge) ──
                self._press_start_time = time.monotonic()
                self._is_pressed = True
                logger.debug("Buton basildi (pin=%d)", self._pin)

            elif self._is_pressed:
                # ── Buton bırakıldı (RISING edge) ──
                self._is_pressed = False
                press_duration = time.monotonic() - self._press_start_time

                logger.debug(
                    "Buton birakildi (pin=%d, sure=%.2fs)",
                    self._pin, press_duration,
                )

                # Callback'i ayrı thread'de çağır (GPIO callback'i bloklamama)
                if press_duration >= self._long_press_threshold:
                    self._fire_callback(self._on_long_press, "uzun_basis")
                else:
                    self._fire_callback(self._on_short_press, "kisa_basis")

    def _fire_callback(
        self,
        callback: Optional[Callable[[], None]],
        event_name: str,
    ) -> None:
        """
        Callback fonksiyonunu ayrı thread'de çalıştır.

        GPIO interrupt context'inden hızlıca çıkmak için
        callback ayrı thread'e atanır.

        Args:
            callback: Çağrılacak fonksiyon.
            event_name: Log için olay adı.
        """
        if callback is None:
            logger.debug("Buton olayi: %s (callback yok)", event_name)
            return

        logger.info("Buton olayi: %s", event_name)

        self._callback_thread = threading.Thread(
            target=self._safe_callback,
            args=(callback, event_name),
            name=f"button-{event_name}",
            daemon=True,
        )
        self._callback_thread.start()

    @staticmethod
    def _safe_callback(callback: Callable[[], None], event_name: str) -> None:
        """
        Callback'i güvenli şekilde çalıştır.

        Hata oluşursa loglar, daemon'ı çökertmez.

        Args:
            callback: Çağrılacak fonksiyon.
            event_name: Log için olay adı.
        """
        try:
            callback()
        except Exception as exc:
            logger.error(
                "Buton callback hatasi (%s): %s",
                event_name, exc,
            )

    # ─────────────────────────────────────────────
    # Callback Güncelleme
    # ─────────────────────────────────────────────

    def set_short_press_callback(self, callback: Optional[Callable[[], None]]) -> None:
        """
        Kısa basış callback fonksiyonunu güncelle.

        Args:
            callback: Yeni callback fonksiyonu veya None.
        """
        with self._lock:
            self._on_short_press = callback

    def set_long_press_callback(self, callback: Optional[Callable[[], None]]) -> None:
        """
        Uzun basış callback fonksiyonunu güncelle.

        Args:
            callback: Yeni callback fonksiyonu veya None.
        """
        with self._lock:
            self._on_long_press = callback

    # ─────────────────────────────────────────────
    # Durum Sorgulama
    # ─────────────────────────────────────────────

    def is_pressed(self) -> bool:
        """
        Butonun şu an basılı olup olmadığını kontrol et.

        Returns:
            True ise buton basılı.
        """
        if not self.available:
            return False
        try:
            return GPIO.input(self._pin) == GPIO.LOW
        except Exception:
            return False

    # ─────────────────────────────────────────────
    # Temizlik
    # ─────────────────────────────────────────────

    def cleanup(self) -> None:
        """
        GPIO event detect kaldır ve kaynakları serbest bırak.

        NOT: GPIO.cleanup() burada çağrılmaz — diğer modüller
        de GPIO kullanıyor olabilir. Genel cleanup daemon seviyesinde yapılır.
        """
        if self.available and _GPIO_AVAILABLE:
            try:
                GPIO.remove_event_detect(self._pin)
            except Exception as exc:
                logger.debug("GPIO event detect kaldirma hatasi: %s", exc)

        # Callback thread'inin bitmesini bekle
        if self._callback_thread is not None and self._callback_thread.is_alive():
            self._callback_thread.join(timeout=2.0)

        self.available = False
        logger.info("Buton handler kapatildi (pin=%d)", self._pin)

#!/usr/bin/env python3
"""
RGB LED Kontrolcüsü.

THE AIRLOCK v5.1.1 FORTRESS-HARDENED — Görsel Durum Göstergesi

Renk Kodları:
    idle     — Mavi (sabit): Bekleme modu
    scanning — Sarı (yanıp sönen): Tarama/işlem devam
    complete — Yeşil (sabit): Tamamlandı, temiz
    threat   — Kırmızı (yanıp sönen): Tehdit tespit edildi
    blocked  — Kırmızı (sabit): BadUSB engellendi
    update   — Mor (sabit): Güncelleme modu
    cdr      — Turuncu (hızlı yanıp sönen): CDR işlemi
    startup  — Beyaz (pulse): Sistem açılış/kapanış

İki mod desteklenir:
    1. ``rgb``      — Ayrı RGB LED'ler (GPIO PWM, 3 pin)
    2. ``neopixel`` — WS2812B tek pin (rpi_ws281x kütüphanesi)

GPIO kullanılamıyorsa ``available = False``, tüm metodlar sessizce geçer.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Dict, Optional, Tuple

# ── GPIO (opsiyonel) ──
try:
    import RPi.GPIO as GPIO  # type: ignore[import-untyped]
    _GPIO_AVAILABLE = True
except ImportError:
    _GPIO_AVAILABLE = False

# ── NeoPixel (opsiyonel) ──
try:
    from rpi_ws281x import PixelStrip, Color  # type: ignore[import-untyped]
    _NEOPIXEL_AVAILABLE = True
except ImportError:
    _NEOPIXEL_AVAILABLE = False


logger = logging.getLogger("AIRLOCK.LED")

# ── Pin Sabitleri (config.py GPIOConfig'den) ──
_DEFAULT_RED_PIN = 17
_DEFAULT_GREEN_PIN = 27
_DEFAULT_BLUE_PIN = 22
_DEFAULT_NEOPIXEL_PIN = 18  # PWM0 — NeoPixel için
_DEFAULT_NEOPIXEL_COUNT = 1
_DEFAULT_NEOPIXEL_BRIGHTNESS = 128  # 0-255
_PWM_FREQUENCY = 1000  # Hz


class LEDController:
    """
    RGB LED kontrolcüsü.

    ``rgb`` modunda 3 ayrı GPIO pin (PWM), ``neopixel`` modunda
    tek WS2812B LED kullanır. Donanım yoksa ``available = False``.
    """

    COLORS: Dict[str, Tuple[int, int, int]] = {
        "idle":     (0, 0, 255),        # Mavi
        "scanning": (255, 200, 0),      # Sarı
        "complete": (0, 255, 0),        # Yeşil
        "threat":   (255, 0, 0),        # Kırmızı
        "blocked":  (255, 0, 0),        # Kırmızı
        "update":   (128, 0, 255),      # Mor
        "cdr":      (255, 128, 0),      # Turuncu
        "startup":  (255, 255, 255),    # Beyaz
        "error":    (255, 50, 0),       # Koyu kırmızı-turuncu
        "shutdown": (255, 255, 255),    # Beyaz
        "off":      (0, 0, 0),          # Kapalı
    }

    def __init__(
        self,
        mode: str = "rgb",
        red_pin: int = _DEFAULT_RED_PIN,
        green_pin: int = _DEFAULT_GREEN_PIN,
        blue_pin: int = _DEFAULT_BLUE_PIN,
        neopixel_pin: int = _DEFAULT_NEOPIXEL_PIN,
        neopixel_count: int = _DEFAULT_NEOPIXEL_COUNT,
        neopixel_brightness: int = _DEFAULT_NEOPIXEL_BRIGHTNESS,
    ) -> None:
        """
        LED kontrolcüsünü başlat.

        Args:
            mode: 'rgb' (3 ayrı GPIO PWM) veya 'neopixel' (WS2812B).
            red_pin: Kırmızı LED GPIO pin numarası (BCM).
            green_pin: Yeşil LED GPIO pin numarası (BCM).
            blue_pin: Mavi LED GPIO pin numarası (BCM).
            neopixel_pin: NeoPixel data pin numarası (BCM).
            neopixel_count: NeoPixel LED sayısı.
            neopixel_brightness: NeoPixel parlaklık (0-255).
        """
        self.available: bool = False
        self._mode: str = mode
        self._lock: threading.Lock = threading.Lock()
        self._effect_thread: Optional[threading.Thread] = None
        self._effect_running: bool = False

        # RGB PWM nesneleri
        self._pwm_r: Optional[object] = None
        self._pwm_g: Optional[object] = None
        self._pwm_b: Optional[object] = None

        # NeoPixel nesnesi
        self._strip: Optional[object] = None

        if mode == "neopixel":
            self._init_neopixel(neopixel_pin, neopixel_count, neopixel_brightness)
        else:
            self._init_rgb(red_pin, green_pin, blue_pin)

    # ─────────────────────────────────────────────
    # Başlatma
    # ─────────────────────────────────────────────

    def _init_rgb(self, red_pin: int, green_pin: int, blue_pin: int) -> None:
        """3 ayrı GPIO PWM ile RGB LED başlat."""
        if not _GPIO_AVAILABLE:
            logger.info("RPi.GPIO bulunamadi - LED devre disi")
            return

        try:
            GPIO.setmode(GPIO.BCM)
            GPIO.setwarnings(False)

            GPIO.setup(red_pin, GPIO.OUT)
            GPIO.setup(green_pin, GPIO.OUT)
            GPIO.setup(blue_pin, GPIO.OUT)

            self._pwm_r = GPIO.PWM(red_pin, _PWM_FREQUENCY)
            self._pwm_g = GPIO.PWM(green_pin, _PWM_FREQUENCY)
            self._pwm_b = GPIO.PWM(blue_pin, _PWM_FREQUENCY)

            self._pwm_r.start(0)  # type: ignore[union-attr]
            self._pwm_g.start(0)  # type: ignore[union-attr]
            self._pwm_b.start(0)  # type: ignore[union-attr]

            self.available = True
            logger.info("RGB LED baslatildi (R=%d, G=%d, B=%d)", red_pin, green_pin, blue_pin)
        except Exception as exc:
            logger.info("RGB LED baslatma hatasi: %s", exc)
            self.available = False

    def _init_neopixel(self, pin: int, count: int, brightness: int) -> None:
        """WS2812B NeoPixel başlat."""
        if not _NEOPIXEL_AVAILABLE:
            logger.info("rpi_ws281x bulunamadi - NeoPixel devre disi")
            return

        try:
            strip = PixelStrip(
                num=count,
                pin=pin,
                freq_hz=800000,
                dma=10,
                invert=False,
                brightness=brightness,
                channel=0,
            )
            strip.begin()
            self._strip = strip
            self.available = True
            logger.info("NeoPixel baslatildi (pin=%d, count=%d)", pin, count)
        except Exception as exc:
            logger.info("NeoPixel baslatma hatasi: %s", exc)
            self.available = False

    # ─────────────────────────────────────────────
    # Efekt Thread Yönetimi
    # ─────────────────────────────────────────────

    def _stop_effect(self) -> None:
        """Çalışan blink/pulse efektini durdur."""
        self._effect_running = False
        if self._effect_thread is not None and self._effect_thread.is_alive():
            self._effect_thread.join(timeout=3.0)
        self._effect_thread = None

    def _start_effect(self, target: object, name: str) -> None:
        """Yeni efekt thread'i başlat."""
        self._stop_effect()
        self._effect_running = True
        self._effect_thread = threading.Thread(
            target=target,  # type: ignore[arg-type]
            name=f"led-{name}",
            daemon=True,
        )
        self._effect_thread.start()

    # ─────────────────────────────────────────────
    # Renk Ayarlama (düşük seviye)
    # ─────────────────────────────────────────────

    def _set_rgb(self, r: int, g: int, b: int) -> None:
        """
        Ham RGB değerlerini ayarla (0-255).

        Thread lock olmadan çağrılır — çağıran lock tutar.
        """
        if not self.available:
            return

        if self._mode == "neopixel" and self._strip is not None:
            try:
                self._strip.setPixelColor(0, Color(r, g, b))  # type: ignore[union-attr]
                self._strip.show()  # type: ignore[union-attr]
            except Exception as exc:
                logger.debug("NeoPixel renk hatasi: %s", exc)
        elif self._pwm_r is not None:
            try:
                # PWM duty cycle: 0-100 (0-255 → 0-100)
                self._pwm_r.ChangeDutyCycle(r * 100 / 255)  # type: ignore[union-attr]
                self._pwm_g.ChangeDutyCycle(g * 100 / 255)  # type: ignore[union-attr]
                self._pwm_b.ChangeDutyCycle(b * 100 / 255)  # type: ignore[union-attr]
            except Exception as exc:
                logger.debug("PWM renk hatasi: %s", exc)

    # ─────────────────────────────────────────────
    # Genel API
    # ─────────────────────────────────────────────

    def set_color(self, color_name: str) -> None:
        """
        Sabit renk ayarla.

        Çalışan blink/pulse efektini durdurur.

        Args:
            color_name: COLORS sözlüğündeki renk adı.
        """
        if not self.available:
            return

        self._stop_effect()
        rgb = self.COLORS.get(color_name, (0, 0, 0))

        with self._lock:
            self._set_rgb(*rgb)

    def blink(
        self,
        color_name: str,
        count: int = 3,
        interval: float = 0.3,
    ) -> None:
        """
        LED'i yanıp söndür (non-blocking).

        Ayrı thread'de çalışır. Önceki efekti durdurur.

        Args:
            color_name: Yanıp sönecek renk adı.
            count: Yanıp sönme sayısı (0 = sonsuz).
            interval: Yanıp sönme aralığı (saniye).
        """
        if not self.available:
            return

        rgb = self.COLORS.get(color_name, (255, 0, 0))

        def _blink_loop() -> None:
            iteration = 0
            while self._effect_running:
                if count > 0 and iteration >= count:
                    break
                # Aç
                with self._lock:
                    self._set_rgb(*rgb)
                self._interruptible_sleep(interval)
                if not self._effect_running:
                    break
                # Kapat
                with self._lock:
                    self._set_rgb(0, 0, 0)
                self._interruptible_sleep(interval)
                iteration += 1

        self._start_effect(_blink_loop, "blink")

    def pulse(self, color_name: str, duration: float = 2.0) -> None:
        """
        Yavaşça parla ve sön — breathing effect (non-blocking).

        Parlaklık 0 → max → 0 arası sinüzoidal geçiş yapar.

        Args:
            color_name: Pulse yapılacak renk adı.
            duration: Bir tam döngü süresi (saniye).
        """
        if not self.available:
            return

        rgb = self.COLORS.get(color_name, (255, 255, 255))

        def _pulse_loop() -> None:
            import math
            steps = 100
            step_time = duration / steps

            while self._effect_running:
                for step in range(steps):
                    if not self._effect_running:
                        return
                    # Sinüzoidal parlaklık: 0 → 1 → 0
                    brightness = (math.sin(math.pi * step / steps)) ** 2
                    r = int(rgb[0] * brightness)
                    g = int(rgb[1] * brightness)
                    b = int(rgb[2] * brightness)
                    with self._lock:
                        self._set_rgb(r, g, b)
                    time.sleep(step_time)

        self._start_effect(_pulse_loop, "pulse")

    def off(self) -> None:
        """LED'i kapat. Çalışan efekti durdurur."""
        if not self.available:
            return
        self._stop_effect()
        with self._lock:
            self._set_rgb(0, 0, 0)

    def cleanup(self) -> None:
        """
        GPIO/NeoPixel temizliği.

        LED'i kapatır, PWM durdurur, GPIO serbest bırakır.
        """
        self._stop_effect()

        if self.available:
            with self._lock:
                self._set_rgb(0, 0, 0)

            if self._mode != "neopixel" and _GPIO_AVAILABLE:
                try:
                    if self._pwm_r is not None:
                        self._pwm_r.stop()  # type: ignore[union-attr]
                    if self._pwm_g is not None:
                        self._pwm_g.stop()  # type: ignore[union-attr]
                    if self._pwm_b is not None:
                        self._pwm_b.stop()  # type: ignore[union-attr]
                    # NOT: GPIO.cleanup() burada çağrılmaz —
                    # diğer modüller de GPIO kullanıyor olabilir.
                    # Genel cleanup daemon tarafından yapılır.
                except Exception as exc:
                    logger.debug("PWM cleanup hatasi: %s", exc)

        self.available = False
        logger.info("LED kontrolcusu kapatildi")

    # ─────────────────────────────────────────────
    # Yardımcı
    # ─────────────────────────────────────────────

    def _interruptible_sleep(self, seconds: float) -> None:
        """
        Kesintiye uğrayabilir uyku.

        ``_effect_running`` False olursa erken uyanır.
        """
        steps = int(seconds / 0.05)
        for _ in range(max(steps, 1)):
            if not self._effect_running:
                return
            time.sleep(0.05)

#!/usr/bin/env python3
"""
SSD1306 OLED Ekran Kontrolü (128x64 pixel, I2C).

THE AIRLOCK v5.0.8 FORTRESS-HARDENED — Katman: Kullanıcı Arayüzü

Ekran Durumları:
    SPLASH      — Açılış logosu + versiyon
    IDLE        — "USB bekleniyor..." + animasyon
    USB_DETECTED— Kaynak/Hedef/Update USB tespit edildi
    USB_BLOCKED — BadUSB engelleme uyarısı
    SCANNING    — Progress bar + dosya adı + tehdit sayısı
    THREAT      — Tehdit uyarısı + detay
    CDR         — CDR işlem durumu
    COMPLETE    — Özet (dosya sayısı, tehdit, süre)
    UPDATE      — Güncelleme ilerlemesi
    ERROR       — Hata detayı
    SHUTDOWN    — Kapanış mesajı

Kütüphane: luma.oled (luma.core)
Font: PIL.ImageFont (bitmap fallback)

ÖNEMLİ: OLED yoksa (I2C cihaz bulunamadı) self.available = False.
Tüm metodlar try/except ile sarılır. Donanım hatası daemon'ı çökertmemeli.
"""

from __future__ import annotations

import logging
import threading
import time
from pathlib import Path
from typing import Optional

# ── luma.oled + PIL (opsiyonel) ──
try:
    from luma.core.interface.serial import i2c  # type: ignore[import-untyped]
    from luma.oled.device import ssd1306  # type: ignore[import-untyped]
    _LUMA_AVAILABLE = True
except ImportError:
    _LUMA_AVAILABLE = False

try:
    from PIL import Image, ImageDraw, ImageFont  # type: ignore[import-untyped]
    _PIL_AVAILABLE = True
except ImportError:
    _PIL_AVAILABLE = False


logger = logging.getLogger("AIRLOCK.OLED")

# ── Sabitler ──
_VERSION_FILE = Path(__file__).resolve().parent.parent.parent / "VERSION"
_DEFAULT_FONT_SIZE = 10
_DISPLAY_WIDTH = 128
_DISPLAY_HEIGHT = 64
_IDLE_ANIMATION_INTERVAL = 0.8  # saniye


def _load_version() -> str:
    """VERSION dosyasından versiyon bilgisini oku."""
    try:
        return _VERSION_FILE.read_text(encoding="utf-8").strip()
    except (OSError, ValueError):
        return "5.0.8"


def _get_font(size: int = _DEFAULT_FONT_SIZE) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    """
    Truetype font yükle. Bulunamazsa bitmap fallback.

    Raspberry Pi OS'te DejaVuSans genellikle mevcut.
    """
    truetype_paths = [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf",
        "/usr/share/fonts/truetype/noto/NotoSansMono-Regular.ttf",
    ]
    for font_path in truetype_paths:
        try:
            return ImageFont.truetype(font_path, size)
        except (OSError, IOError):
            continue
    return ImageFont.load_default()


class OLEDDisplay:
    """
    SSD1306 OLED ekran kontrolcüsü.

    128x64 pixel, I2C bağlantılı.
    OLED donanımı yoksa ``available = False`` olur ve
    tüm metodlar sessizce geçer (no-op).
    """

    def __init__(self, address: int = 0x3C, width: int = 128, height: int = 64) -> None:
        """
        I2C üzerinden OLED cihazını başlat.

        Args:
            address: I2C adresi (varsayılan 0x3C).
            width: Ekran genişliği (pixel).
            height: Ekran yüksekliği (pixel).
        """
        self.available: bool = False
        self._device: Optional[object] = None
        self._width: int = width
        self._height: int = height
        self._lock: threading.Lock = threading.Lock()
        self._idle_thread: Optional[threading.Thread] = None
        self._idle_running: bool = False
        self._font: Optional[object] = None
        self._font_small: Optional[object] = None
        self._font_large: Optional[object] = None

        if not _LUMA_AVAILABLE or not _PIL_AVAILABLE:
            logger.info("luma.oled veya PIL bulunamadi - OLED devre disi")
            return

        try:
            serial = i2c(port=1, address=address)
            self._device = ssd1306(serial, width=width, height=height)
            self._font = _get_font(10)
            self._font_small = _get_font(8)
            self._font_large = _get_font(14)
            self.available = True
            logger.info("OLED ekran baslatildi (adres=0x%02X, %dx%d)", address, width, height)
        except Exception as exc:
            logger.info("OLED ekran bulunamadi: %s", exc)
            self.available = False

    # ─────────────────────────────────────────────
    # Yardımcı: Çizim
    # ─────────────────────────────────────────────

    def _safe_draw(self, draw_func: object) -> None:
        """
        Thread-safe ekran çizimi.

        Idle animasyonunu durdurur, çizim fonksiyonunu çağırır,
        hata durumunda sessizce geçer.
        """
        if not self.available or self._device is None:
            return
        self._stop_idle_animation()
        with self._lock:
            try:
                img = Image.new("1", (self._width, self._height), 0)
                draw = ImageDraw.Draw(img)
                draw_func(draw, img)  # type: ignore[operator]
                self._device.display(img)  # type: ignore[union-attr]
            except Exception as exc:
                logger.debug("OLED cizim hatasi: %s", exc)

    def _draw_header(self, draw: ImageDraw.ImageDraw, text: str) -> None:
        """Üst başlık çiz (ters renk çubuğu)."""
        draw.rectangle([0, 0, self._width - 1, 12], fill=1)
        draw.text((2, 1), text, font=self._font_small, fill=0)

    def _draw_progress_bar(
        self,
        draw: ImageDraw.ImageDraw,
        x: int,
        y: int,
        width: int,
        height: int,
        progress: int,
    ) -> None:
        """Progress bar çiz (0-100%)."""
        progress = max(0, min(100, progress))
        # Çerçeve
        draw.rectangle([x, y, x + width - 1, y + height - 1], outline=1, fill=0)
        # Dolgu
        fill_width = int((width - 2) * progress / 100)
        if fill_width > 0:
            draw.rectangle([x + 1, y + 1, x + fill_width, y + height - 2], fill=1)

    def _truncate(self, text: str, max_chars: int = 20) -> str:
        """Uzun metinleri kırp."""
        if len(text) <= max_chars:
            return text
        return text[: max_chars - 2] + ".."

    # ─────────────────────────────────────────────
    # Idle Animasyonu (non-blocking thread)
    # ─────────────────────────────────────────────

    def _stop_idle_animation(self) -> None:
        """Idle animasyon thread'ini durdur."""
        self._idle_running = False
        if self._idle_thread is not None and self._idle_thread.is_alive():
            self._idle_thread.join(timeout=2.0)
        self._idle_thread = None

    def _idle_animation_loop(self) -> None:
        """Idle ekranında dönen nokta animasyonu."""
        dots = 0
        while self._idle_running and self.available and self._device is not None:
            with self._lock:
                try:
                    img = Image.new("1", (self._width, self._height), 0)
                    draw = ImageDraw.Draw(img)

                    # Başlık
                    self._draw_header(draw, "THE AIRLOCK v5.0.8")

                    # USB bekleniyor mesajı
                    dot_str = "." * (dots % 4)
                    draw.text((10, 26), f"USB bekleniyor{dot_str}", font=self._font, fill=1)

                    # Alt bilgi
                    draw.text((20, 50), "FORTRESS", font=self._font_small, fill=1)

                    self._device.display(img)  # type: ignore[union-attr]
                except Exception:
                    break

            dots += 1
            # Uyku sırasında durdurulabilir olsun
            for _ in range(int(_IDLE_ANIMATION_INTERVAL * 10)):
                if not self._idle_running:
                    return
                time.sleep(0.1)

    # ─────────────────────────────────────────────
    # Ekran Durumları
    # ─────────────────────────────────────────────

    def show_splash(self) -> None:
        """
        Açılış ekranı.

        THE AIRLOCK v5.0.8
        ═══════════════════
         FORTRESS-HARDENED
          versiyon x.y.z
        """
        version = _load_version()

        def _draw(draw: ImageDraw.ImageDraw, img: Image.Image) -> None:
            # Üst başlık
            draw.rectangle([0, 0, self._width - 1, 15], fill=1)
            draw.text((8, 1), "THE AIRLOCK v5.0.8", font=self._font, fill=0)

            # Ayırıcı çizgi
            draw.line([(0, 18), (self._width - 1, 18)], fill=1)

            # FORTRESS
            draw.text((28, 25), "FORTRESS", font=self._font_large, fill=1)

            # Versiyon
            draw.text((38, 48), f"v{version}", font=self._font_small, fill=1)

        self._safe_draw(_draw)

    def show_idle(self) -> None:
        """
        Bekleme ekranı.

        'USB bekleniyor...' + dönen nokta animasyonu.
        Non-blocking: ayrı thread'de çalışır.
        """
        if not self.available:
            return
        self._stop_idle_animation()
        self._idle_running = True
        self._idle_thread = threading.Thread(
            target=self._idle_animation_loop,
            name="oled-idle",
            daemon=True,
        )
        self._idle_thread.start()

    def show_usb_detected(self, usb_type: str) -> None:
        """
        USB tespit edildi ekranı.

        Args:
            usb_type: USB tipi açıklaması (ör. 'KAYNAK (Kirli)').
        """
        label = self._truncate(usb_type, 18)

        def _draw(draw: ImageDraw.ImageDraw, img: Image.Image) -> None:
            self._draw_header(draw, "USB TESPIT EDILDI")
            draw.text((10, 20), label, font=self._font, fill=1)
            draw.text((10, 40), "Takmaya devam edin", font=self._font_small, fill=1)
            draw.text((10, 52), "veya bekleyin...", font=self._font_small, fill=1)

        self._safe_draw(_draw)

    def show_usb_blocked(self, reason: str) -> None:
        """
        BadUSB engelleme uyarısı.

        Args:
            reason: Engelleme sebebi.
        """
        reason_short = self._truncate(reason, 20)

        def _draw(draw: ImageDraw.ImageDraw, img: Image.Image) -> None:
            # Uyarı başlık
            draw.rectangle([0, 0, self._width - 1, 14], fill=1)
            draw.text((4, 1), "!! USB ENGELLENDI !!", font=self._font, fill=0)

            # Uyarı ikonu ve mesaj
            draw.text((4, 20), "BadUSB Tespit!", font=self._font, fill=1)
            draw.text((4, 36), reason_short, font=self._font_small, fill=1)
            draw.text((4, 52), "Cihazi cikarin!", font=self._font_small, fill=1)

        self._safe_draw(_draw)

    def show_scanning(
        self,
        filename: str,
        progress: int,
        current: int,
        total: int,
        threats: int,
    ) -> None:
        """
        Tarama ilerleme ekranı.

        Args:
            filename: İşlenen dosya adı.
            progress: İlerleme yüzdesi (0-100).
            current: İşlenen dosya numarası.
            total: Toplam dosya sayısı.
            threats: Tespit edilen tehdit sayısı.
        """
        name = self._truncate(filename, 20)

        def _draw(draw: ImageDraw.ImageDraw, img: Image.Image) -> None:
            self._draw_header(draw, "TARAMA")

            # Dosya adı
            draw.text((2, 16), name, font=self._font_small, fill=1)

            # Progress bar
            self._draw_progress_bar(draw, 2, 28, 124, 10, progress)

            # Sayaçlar
            draw.text((2, 42), f"{current}/{total}", font=self._font_small, fill=1)
            draw.text((60, 42), f"%{progress}", font=self._font_small, fill=1)

            # Tehdit sayısı
            if threats > 0:
                draw.text((2, 54), f"Tehdit: {threats}", font=self._font_small, fill=1)
            else:
                draw.text((2, 54), "Temiz", font=self._font_small, fill=1)

        self._safe_draw(_draw)

    def show_threat(self, filename: str, threat_name: str) -> None:
        """
        Tehdit uyarı ekranı.

        Args:
            filename: Tehditli dosya adı.
            threat_name: Tehdit adı/türü.
        """
        name = self._truncate(filename, 20)
        threat = self._truncate(threat_name, 20)

        def _draw(draw: ImageDraw.ImageDraw, img: Image.Image) -> None:
            draw.rectangle([0, 0, self._width - 1, 14], fill=1)
            draw.text((8, 1), "TEHDIT TESPIT!", font=self._font, fill=0)

            draw.text((2, 20), name, font=self._font_small, fill=1)
            draw.line([(0, 32), (self._width - 1, 32)], fill=1)
            draw.text((2, 36), threat, font=self._font_small, fill=1)
            draw.text((2, 52), "Karantinaya alindi", font=self._font_small, fill=1)

        self._safe_draw(_draw)

    def show_cdr(self, filename: str, cdr_type: str) -> None:
        """
        CDR (Content Disarm & Reconstruction) işlem ekranı.

        Args:
            filename: İşlenen dosya adı.
            cdr_type: CDR stratejisi (ör. 'pdf_rasterize').
        """
        name = self._truncate(filename, 20)
        strategy = self._truncate(cdr_type, 20)

        def _draw(draw: ImageDraw.ImageDraw, img: Image.Image) -> None:
            self._draw_header(draw, "CDR ISLEMI")

            draw.text((2, 18), name, font=self._font_small, fill=1)
            draw.line([(0, 30), (self._width - 1, 30)], fill=1)
            draw.text((2, 34), f"Strateji: {strategy}", font=self._font_small, fill=1)
            draw.text((2, 50), "Dosya temizleniyor..", font=self._font_small, fill=1)

        self._safe_draw(_draw)

    def show_complete(
        self,
        total: int,
        clean: int,
        threats: int,
        duration: float,
    ) -> None:
        """
        Tamamlandı özet ekranı.

        Args:
            total: Toplam dosya sayısı.
            clean: Temiz aktarılan dosya sayısı.
            threats: Tehdit sayısı.
            duration: Toplam süre (saniye).
        """
        duration_str = f"{duration:.1f}s" if duration < 60 else f"{duration / 60:.1f}dk"

        def _draw(draw: ImageDraw.ImageDraw, img: Image.Image) -> None:
            self._draw_header(draw, "TAMAMLANDI")

            draw.text((2, 16), f"Toplam : {total} dosya", font=self._font_small, fill=1)
            draw.text((2, 28), f"Temiz  : {clean}", font=self._font_small, fill=1)
            draw.text((2, 40), f"Tehdit : {threats}", font=self._font_small, fill=1)
            draw.text((2, 52), f"Sure   : {duration_str}", font=self._font_small, fill=1)

        self._safe_draw(_draw)

    def show_update(self, component: str, progress: int) -> None:
        """
        Güncelleme ilerleme ekranı.

        Args:
            component: Güncellenen bileşen adı (ör. 'ClamAV').
            progress: İlerleme yüzdesi (0-100).
        """
        comp = self._truncate(component, 18)

        def _draw(draw: ImageDraw.ImageDraw, img: Image.Image) -> None:
            self._draw_header(draw, "GUNCELLEME")

            draw.text((2, 18), comp, font=self._font, fill=1)

            # Progress bar
            self._draw_progress_bar(draw, 2, 34, 124, 10, progress)

            draw.text((50, 50), f"%{progress}", font=self._font_small, fill=1)

        self._safe_draw(_draw)

    def show_error(self, message: str) -> None:
        """
        Hata ekranı.

        Args:
            message: Hata mesajı.
        """
        # İki satıra böl
        line1 = self._truncate(message, 20)
        line2 = ""
        if len(message) > 20:
            line2 = self._truncate(message[20:], 20)

        def _draw(draw: ImageDraw.ImageDraw, img: Image.Image) -> None:
            draw.rectangle([0, 0, self._width - 1, 14], fill=1)
            draw.text((20, 1), "!! HATA !!", font=self._font, fill=0)

            draw.text((2, 22), line1, font=self._font_small, fill=1)
            if line2:
                draw.text((2, 36), line2, font=self._font_small, fill=1)

        self._safe_draw(_draw)

    def show_shutdown(self) -> None:
        """Kapanış mesajı ekranı."""

        def _draw(draw: ImageDraw.ImageDraw, img: Image.Image) -> None:
            draw.text((10, 10), "THE AIRLOCK v5.0.8", font=self._font, fill=1)
            draw.line([(10, 24), (118, 24)], fill=1)
            draw.text((20, 30), "Kapatiliyor...", font=self._font, fill=1)
            draw.text((25, 48), "Gule gule!", font=self._font_small, fill=1)

        self._safe_draw(_draw)

    # ─────────────────────────────────────────────
    # Yardımcı: Temizlik
    # ─────────────────────────────────────────────

    def clear(self) -> None:
        """Ekranı temizle (siyah)."""
        if not self.available or self._device is None:
            return
        self._stop_idle_animation()
        with self._lock:
            try:
                self._device.hide()  # type: ignore[union-attr]
            except Exception as exc:
                logger.debug("OLED temizleme hatasi: %s", exc)

    def cleanup(self) -> None:
        """Ekranı kapat ve kaynakları serbest bırak."""
        self._stop_idle_animation()
        self.clear()
        self.available = False
        logger.info("OLED ekran kapatildi")

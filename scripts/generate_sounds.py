#!/usr/bin/env python3
"""
THE AIRLOCK v5.0.8 FORTRESS-HARDENED — Ses Dosyası Üretici

numpy ile sine wave tabanlı WAV ses dosyaları üretir.
Kurulumda çalıştırılır, /opt/airlock/data/sounds/ dizinine yazar.

Ses Olayları:
  startup          — Kısa melodi (sistem açıldı)
  usb_detect       — Tek tık (USB algılandı)
  usb_blocked      — Alarm (BadUSB engellendi) — 3 kısa yüksek bip
  file_done        — Kısa tık (dosya işlendi)
  threat           — Uyarı sesi (tehdit bulundu) — düşük tonlu uzun bip
  complete         — Başarı melodisi (işlem tamamlandı)
  error            — Düşük ton (hata oluştu)
  button           — Tık sesi (buton basıldı)
  shutdown         — Kapanış sesi
  update_complete  — Güncelleme tamamlandı

Kullanım:
    python3 scripts/generate_sounds.py
    python3 scripts/generate_sounds.py --output /custom/sounds/dir
"""

from __future__ import annotations

import argparse
import struct
import sys
import wave
from pathlib import Path
from typing import List, Tuple

# numpy opsiyonel — yoksa math ile fallback
try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    import math
    HAS_NUMPY = False

# ── Sabitler ──
SAMPLE_RATE = 44100
DEFAULT_OUTPUT_DIR = Path("/opt/airlock/data/sounds")


# ─────────────────────────────────────────────
# Ses Üretim Fonksiyonları
# ─────────────────────────────────────────────


def generate_tone(
    frequency: float,
    duration: float,
    volume: float = 0.5,
    fade_ms: float = 10.0,
) -> List[int]:
    """
    Tek frekanslı sine wave üret.

    Args:
        frequency: Frekans (Hz)
        duration: Süre (saniye)
        volume: Ses seviyesi (0.0-1.0)
        fade_ms: Fade in/out süresi (milisaniye)

    Returns:
        16-bit PCM sample listesi
    """
    num_samples = int(SAMPLE_RATE * duration)
    fade_samples = int(SAMPLE_RATE * fade_ms / 1000.0)

    if HAS_NUMPY:
        t = np.linspace(0, duration, num_samples, endpoint=False)
        samples = np.sin(2.0 * np.pi * frequency * t) * volume

        # Fade in/out
        if fade_samples > 0 and fade_samples < num_samples // 2:
            fade_in = np.linspace(0, 1, fade_samples)
            fade_out = np.linspace(1, 0, fade_samples)
            samples[:fade_samples] *= fade_in
            samples[-fade_samples:] *= fade_out

        # 16-bit PCM
        pcm = (samples * 32767).astype(np.int16)
        return pcm.tolist()
    else:
        samples = []
        for i in range(num_samples):
            t = i / SAMPLE_RATE
            sample = math.sin(2.0 * math.pi * frequency * t) * volume

            # Fade in/out
            if fade_samples > 0:
                if i < fade_samples:
                    sample *= i / fade_samples
                elif i > num_samples - fade_samples:
                    sample *= (num_samples - i) / fade_samples

            samples.append(int(sample * 32767))
        return samples


def generate_silence(duration: float) -> List[int]:
    """Sessizlik üret."""
    return [0] * int(SAMPLE_RATE * duration)


def concatenate(*segments: List[int]) -> List[int]:
    """Birden fazla ses segmentini birleştir."""
    result: List[int] = []
    for seg in segments:
        result.extend(seg)
    return result


def write_wav(filepath: Path, samples: List[int]) -> None:
    """16-bit mono WAV dosyası yaz."""
    filepath.parent.mkdir(parents=True, exist_ok=True)

    with wave.open(str(filepath), "w") as wf:
        wf.setnchannels(1)       # Mono
        wf.setsampwidth(2)       # 16-bit
        wf.setframerate(SAMPLE_RATE)

        # Clamp to int16 range
        data = b""
        for s in samples:
            s = max(-32768, min(32767, s))
            data += struct.pack("<h", s)

        wf.writeframes(data)


# ─────────────────────────────────────────────
# Ses Tanımları
# ─────────────────────────────────────────────


def sound_startup() -> List[int]:
    """Açılış melodisi: C5 → E5 → G5 (yükselen üçlü)."""
    return concatenate(
        generate_tone(523.25, 0.15, 0.4),   # C5
        generate_silence(0.03),
        generate_tone(659.25, 0.15, 0.45),  # E5
        generate_silence(0.03),
        generate_tone(783.99, 0.25, 0.5),   # G5
    )


def sound_usb_detect() -> List[int]:
    """USB algılandı: tek kısa tık (1000 Hz)."""
    return generate_tone(1000, 0.08, 0.3)


def sound_usb_blocked() -> List[int]:
    """BadUSB alarm: 3 kısa yüksek bip (2500 Hz)."""
    return concatenate(
        generate_tone(2500, 0.1, 0.7),
        generate_silence(0.05),
        generate_tone(2500, 0.1, 0.7),
        generate_silence(0.05),
        generate_tone(2500, 0.15, 0.7),
    )


def sound_file_done() -> List[int]:
    """Dosya işlendi: çok kısa hafif tık (800 Hz)."""
    return generate_tone(800, 0.04, 0.15)


def sound_threat() -> List[int]:
    """Tehdit tespit: düşük tonlu uzun uyarı bip (300 Hz → 200 Hz)."""
    return concatenate(
        generate_tone(300, 0.3, 0.6),
        generate_tone(200, 0.4, 0.6),
    )


def sound_complete() -> List[int]:
    """Başarı melodisi: G4 → C5 → E5 → G5 (parlak yükselen)."""
    return concatenate(
        generate_tone(392.00, 0.12, 0.35),  # G4
        generate_silence(0.02),
        generate_tone(523.25, 0.12, 0.40),  # C5
        generate_silence(0.02),
        generate_tone(659.25, 0.12, 0.45),  # E5
        generate_silence(0.02),
        generate_tone(783.99, 0.30, 0.5),   # G5
    )


def sound_error() -> List[int]:
    """Hata: düşük iki nota (200 Hz → 150 Hz)."""
    return concatenate(
        generate_tone(200, 0.2, 0.5),
        generate_silence(0.05),
        generate_tone(150, 0.3, 0.5),
    )


def sound_button() -> List[int]:
    """Buton basıldı: hafif tık (600 Hz)."""
    return generate_tone(600, 0.05, 0.2)


def sound_shutdown() -> List[int]:
    """Kapanış: G5 → E5 → C5 (inen üçlü, yavaş)."""
    return concatenate(
        generate_tone(783.99, 0.2, 0.4),   # G5
        generate_silence(0.05),
        generate_tone(659.25, 0.2, 0.35),  # E5
        generate_silence(0.05),
        generate_tone(523.25, 0.3, 0.3),   # C5
    )


def sound_update_complete() -> List[int]:
    """Güncelleme tamamlandı: C5 → G5 → C6 (oktav atlama)."""
    return concatenate(
        generate_tone(523.25, 0.15, 0.35),   # C5
        generate_silence(0.03),
        generate_tone(783.99, 0.15, 0.40),   # G5
        generate_silence(0.03),
        generate_tone(1046.50, 0.25, 0.45),  # C6
    )


# ─────────────────────────────────────────────
# Ana Üretim
# ─────────────────────────────────────────────

SOUND_MAP = {
    "startup":         sound_startup,
    "usb_detect":      sound_usb_detect,
    "usb_blocked":     sound_usb_blocked,
    "file_done":       sound_file_done,
    "threat":          sound_threat,
    "complete":        sound_complete,
    "error":           sound_error,
    "button":          sound_button,
    "shutdown":        sound_shutdown,
    "update_complete": sound_update_complete,
}


def generate_all(output_dir: Path) -> int:
    """
    Tüm ses dosyalarını üret.

    Args:
        output_dir: Çıktı dizini

    Returns:
        Üretilen dosya sayısı
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    count = 0

    for name, generator in SOUND_MAP.items():
        filepath = output_dir / f"{name}.wav"
        try:
            samples = generator()
            write_wav(filepath, samples)
            print(f"  [OK] {filepath.name} ({len(samples)} sample, {len(samples)/SAMPLE_RATE:.2f}s)")
            count += 1
        except Exception as exc:
            print(f"  [FAIL] {name}: {exc}", file=sys.stderr)

    return count


def main() -> int:
    """Ana giriş noktası."""
    parser = argparse.ArgumentParser(
        description="THE AIRLOCK v5.0.8 — Ses Dosyası Üretici",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help=f"Çıktı dizini (varsayılan: {DEFAULT_OUTPUT_DIR})",
    )
    args = parser.parse_args()

    print(f"Ses dosyaları üretiliyor: {args.output}")
    count = generate_all(args.output)
    print(f"\nToplam: {count}/{len(SOUND_MAP)} ses dosyası üretildi")

    return 0 if count == len(SOUND_MAP) else 1


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
THE AIRLOCK v5.1.1 — Performans Benchmark

Pi 5 (8GB) üzerinde çalıştırılmak üzere tasarlanmış performans testi.
CI'da değil, hedef donanım üzerinde çalıştırılmalıdır.

Testler:
  1. SHA-256 hashing: 100 × 1MB dosya
  2. Entropy hesaplama: 100 × 1MB dosya
  3. Dosya kopyalama (safe_copy): 50 × 5MB dosya
  4. Magic byte detection: 100 dosya
  5. CDR/ClamAV: Sadece araçlar mevcutsa (yoksa skip)

Kullanım:
    python scripts/benchmark.py
    python scripts/benchmark.py --json  # Sadece JSON çıktı
"""

from __future__ import annotations

import json
import math
import os
import shutil
import statistics
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

# ── Proje root'unu sys.path'e ekle ──
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# ─────────────────────────────────────────────
# Yardımcı Fonksiyonlar
# ─────────────────────────────────────────────


def _create_random_file(path: Path, size_bytes: int) -> None:
    """Belirtilen boyutta rastgele veri dosyası oluştur."""
    path.write_bytes(os.urandom(size_bytes))


def _create_typed_file(path: Path, extension: str, size_bytes: int = 1024) -> None:
    """Magic byte'lı test dosyası oluştur."""
    magic_headers = {
        ".pdf": b"%PDF-1.4\n",
        ".png": b"\x89PNG\r\n\x1a\n",
        ".jpg": b"\xff\xd8\xff\xe0",
        ".zip": b"PK\x03\x04",
        ".gz": b"\x1f\x8b\x08",
        ".txt": b"Hello World\n",
        ".html": b"<!DOCTYPE html>",
        ".xml": b"<?xml version=",
    }
    header = magic_headers.get(extension, b"\x00")
    remaining = max(0, size_bytes - len(header))
    path.write_bytes(header + os.urandom(remaining))


def _run_benchmark(
    name: str,
    func: Callable[[], None],
    iterations: int,
) -> Dict[str, Any]:
    """Benchmark çalıştır ve istatistikler döndür."""
    times_ms: List[float] = []

    for _ in range(iterations):
        start = time.perf_counter()
        func()
        elapsed_ms = (time.perf_counter() - start) * 1000
        times_ms.append(elapsed_ms)

    return {
        "name": name,
        "iterations": iterations,
        "min_ms": round(min(times_ms), 3),
        "max_ms": round(max(times_ms), 3),
        "mean_ms": round(statistics.mean(times_ms), 3),
        "median_ms": round(statistics.median(times_ms), 3),
        "stddev_ms": round(statistics.stdev(times_ms), 3) if len(times_ms) > 1 else 0.0,
    }


def _print_table(results: List[Dict[str, Any]]) -> None:
    """Sonuçları insan-okunabilir tablo formatında yazdır."""
    print("\n" + "=" * 80)
    print("THE AIRLOCK v5.1.1 — Performans Benchmark Sonuçları")
    print("=" * 80)
    print(
        f"{'Test':<35} {'N':>5} {'Min':>10} {'Max':>10} "
        f"{'Ort':>10} {'Med':>10} {'StdDev':>10}"
    )
    print("-" * 80)
    for r in results:
        if r.get("skipped"):
            print(f"  {r['name']:<33} {'SKIPPED':>5}   {r.get('reason', '')}")
        else:
            print(
                f"  {r['name']:<33} {r['iterations']:>5} "
                f"{r['min_ms']:>9.3f} {r['max_ms']:>9.3f} "
                f"{r['mean_ms']:>9.3f} {r['median_ms']:>9.3f} "
                f"{r['stddev_ms']:>9.3f}"
            )
    print("-" * 80)
    print("  Süre birimi: milisaniye (ms/dosya)")
    print("=" * 80 + "\n")


# ─────────────────────────────────────────────
# Benchmark Testleri
# ─────────────────────────────────────────────


def bench_sha256(tmpdir: Path) -> Dict[str, Any]:
    """SHA-256 hashing: 100 × 1MB dosya."""
    from app.utils.crypto import sha256_file

    files: List[Path] = []
    for i in range(100):
        f = tmpdir / f"sha256_test_{i}.bin"
        _create_random_file(f, 1 * 1024 * 1024)  # 1MB
        files.append(f)

    idx = [0]

    def _hash_one() -> None:
        sha256_file(files[idx[0] % len(files)])
        idx[0] += 1

    return _run_benchmark("SHA-256 hashing (1MB)", _hash_one, 100)


def bench_entropy(tmpdir: Path) -> Dict[str, Any]:
    """Entropy hesaplama: 100 × 1MB dosya."""
    files: List[Path] = []
    for i in range(100):
        f = tmpdir / f"entropy_test_{i}.bin"
        _create_random_file(f, 1 * 1024 * 1024)  # 1MB
        files.append(f)

    idx = [0]

    def _calc_entropy() -> None:
        """Scanner'ın entropy hesaplamasını simüle et."""
        filepath = files[idx[0] % len(files)]
        data = filepath.read_bytes()
        if not data:
            return
        counter = Counter(data)
        length = len(data)
        entropy = -sum(
            (count / length) * math.log2(count / length)
            for count in counter.values()
            if count > 0
        )
        _ = entropy  # Sonucu kullan (optimize edilmesin)
        idx[0] += 1

    return _run_benchmark("Entropy hesaplama (1MB)", _calc_entropy, 100)


def bench_safe_copy(tmpdir: Path) -> Dict[str, Any]:
    """Dosya kopyalama (safe_copy): 50 × 5MB dosya."""
    try:
        from app.security.file_validator import safe_copy_no_symlink
    except ImportError:
        return {"name": "Safe copy (5MB)", "skipped": True, "reason": "file_validator import hatası"}

    src_dir = tmpdir / "src"
    dst_dir = tmpdir / "dst"
    src_dir.mkdir()
    dst_dir.mkdir()

    files: List[Path] = []
    for i in range(50):
        f = src_dir / f"copy_test_{i}.bin"
        _create_random_file(f, 5 * 1024 * 1024)  # 5MB
        files.append(f)

    idx = [0]

    def _copy_one() -> None:
        i = idx[0] % len(files)
        src = files[i]
        dst = dst_dir / f"copy_out_{idx[0]}.bin"
        safe_copy_no_symlink(src, dst, dst_dir)
        idx[0] += 1

    return _run_benchmark("Safe copy (5MB)", _copy_one, 50)


def bench_magic_byte(tmpdir: Path) -> Dict[str, Any]:
    """Magic byte detection: 100 dosya."""
    extensions = [".pdf", ".png", ".jpg", ".zip", ".gz", ".txt", ".html", ".xml"]
    files: List[Path] = []
    for i in range(100):
        ext = extensions[i % len(extensions)]
        f = tmpdir / f"magic_test_{i}{ext}"
        _create_typed_file(f, ext, 4096)
        files.append(f)

    # Magic byte kontrolü — basit MIME tespiti
    try:
        import mimetypes
    except ImportError:
        return {"name": "Magic byte detection", "skipped": True, "reason": "mimetypes yok"}

    idx = [0]

    def _detect_one() -> None:
        filepath = files[idx[0] % len(files)]
        # Uzantı bazlı MIME
        _ = mimetypes.guess_type(str(filepath))[0]
        # İlk 16 byte oku (magic byte)
        with filepath.open("rb") as fh:
            _ = fh.read(16)
        idx[0] += 1

    return _run_benchmark("Magic byte detection", _detect_one, 100)


def bench_cdr_pdf(tmpdir: Path) -> Optional[Dict[str, Any]]:
    """PDF CDR (Ghostscript): Sadece gs mevcutsa."""
    if shutil.which("gs") is None:
        return {"name": "CDR PDF (Ghostscript)", "skipped": True, "reason": "gs bulunamadı"}

    try:
        from app.security.cdr_engine import CDREngine
        from app.config import AirlockConfig

        config = AirlockConfig()
        engine = CDREngine(config=config)
    except Exception:
        return {"name": "CDR PDF (Ghostscript)", "skipped": True, "reason": "CDREngine init hatası"}

    # Basit PDF oluştur
    pdf_content = (
        b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
        b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
        b"3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R>>endobj\n"
        b"xref\n0 4\ntrailer<</Size 4/Root 1 0 R>>\nstartxref\n0\n%%EOF"
    )

    src = tmpdir / "bench_test.pdf"
    src.write_bytes(pdf_content)

    idx = [0]

    def _cdr_one() -> None:
        dst = tmpdir / f"bench_cdr_out_{idx[0]}.pdf"
        engine.process_pdf(src, dst)
        idx[0] += 1

    return _run_benchmark("CDR PDF (Ghostscript)", _cdr_one, 10)


def bench_clamav(tmpdir: Path) -> Optional[Dict[str, Any]]:
    """ClamAV tarama: Sadece clamdscan mevcutsa."""
    if shutil.which("clamdscan") is None and shutil.which("clamscan") is None:
        return {"name": "ClamAV scan (1MB)", "skipped": True, "reason": "clamdscan/clamscan bulunamadı"}

    files: List[Path] = []
    for i in range(10):
        f = tmpdir / f"clam_test_{i}.bin"
        _create_random_file(f, 1 * 1024 * 1024)  # 1MB
        files.append(f)

    scanner_cmd = "clamdscan" if shutil.which("clamdscan") else "clamscan"
    idx = [0]

    def _scan_one() -> None:
        import subprocess
        filepath = files[idx[0] % len(files)]
        try:
            subprocess.run(
                [scanner_cmd, "--no-summary", str(filepath)],
                capture_output=True,
                timeout=30,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        idx[0] += 1

    return _run_benchmark(f"ClamAV scan ({scanner_cmd})", _scan_one, 10)


# ─────────────────────────────────────────────
# Ana Çalıştırma
# ─────────────────────────────────────────────


def main() -> None:
    """Tüm benchmark'ları çalıştır."""
    json_only = "--json" in sys.argv

    if not json_only:
        print("THE AIRLOCK v5.1.1 — Performans Benchmark başlıyor...")
        print(f"  Platform: {sys.platform}")
        print(f"  Python: {sys.version.split()[0]}")
        print()

    results: List[Dict[str, Any]] = []

    with tempfile.TemporaryDirectory(prefix="airlock_bench_") as tmpdir_str:
        tmpdir = Path(tmpdir_str)

        # ── Temel testler (her yerde çalışır) ──
        if not json_only:
            print("[1/6] SHA-256 hashing (100 × 1MB)...")
        results.append(bench_sha256(tmpdir))

        if not json_only:
            print("[2/6] Entropy hesaplama (100 × 1MB)...")
        results.append(bench_entropy(tmpdir))

        if not json_only:
            print("[3/6] Safe copy (50 × 5MB)...")
        results.append(bench_safe_copy(tmpdir))

        if not json_only:
            print("[4/6] Magic byte detection (100 dosya)...")
        results.append(bench_magic_byte(tmpdir))

        # ── Harici araç testleri (Pi'de çalışır, CI'da skip) ──
        if not json_only:
            print("[5/6] CDR PDF (Ghostscript)...")
        results.append(bench_cdr_pdf(tmpdir))

        if not json_only:
            print("[6/6] ClamAV scan...")
        results.append(bench_clamav(tmpdir))

    # ── Sonuçları yazdır ──
    if not json_only:
        _print_table(results)

    # ── JSON çıktı ──
    output = {
        "version": "5.1.1",
        "platform": sys.platform,
        "python": sys.version.split()[0],
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "benchmarks": results,
    }

    json_path = PROJECT_ROOT / "benchmark_results.json"
    json_path.write_text(
        json.dumps(output, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    if json_only:
        print(json.dumps(output, indent=2, ensure_ascii=False))
    else:
        print(f"JSON sonuçlar: {json_path}")


if __name__ == "__main__":
    main()

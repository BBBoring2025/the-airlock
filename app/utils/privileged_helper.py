"""
THE AIRLOCK v5.1.1 FORTRESS-HARDENED — Ayricalikli Yardimci Sunucu

Root olarak calisan ayri bir systemd servisi.
Unix socket uzerinden SADECE 4 komut kabul eder:
  1. mount        — Belirli path pattern ile USB mount
  2. umount       — Belirli path pattern ile USB unmount
  3. deauth       — sysfs authorized dosyasina 0 yazma
  4. update_clamav — ClamAV veritabani guncelle + daemon kontrol

Diger HER SEY → REJECT.

Guvenlik:
  - Socket izinleri: srw-rw---- root:airlock (0660)
  - Komut argumanlari dogrulanir (path traversal, shell injection)
  - Sadece /mnt/airlock_* mount noktalarina izin
  - Sadece /dev/sd* cihazlarina izin
  - Sadece /sys/bus/usb/devices/*/authorized sysfs yollarina izin
  - Timeout: her komut max 15 saniye

Mount kural sikilasmasi:
  - /mnt/airlock_source → "ro" ZORUNLU, "rw" yasak
  - /mnt/airlock_target → "rw" ZORUNLU
  - Her iki hedef icin: noexec,nosuid,nodev ZORUNLU (eksikse otomatik eklenir)
  - FAT/exFAT/NTFS: uid,gid,umask=0077 otomatik eklenir (POSIX izni yok)

Kullanim:
  Bu modul dogrudan calistirilir (airlock-helper.service):
    python3 -m app.utils.privileged_helper

Protokol (JSON over Unix socket):
  Istek:  {"cmd": "mount", "device": "/dev/sda1", "target": "/mnt/airlock_source", ...}
  Yanit:  {"ok": true}  veya  {"ok": false, "error": "REJECTED: ..."}
"""

from __future__ import annotations

import concurrent.futures
import json
import logging
import os
import re
import shutil
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("AIRLOCK.HELPER")

# ─────────────────────────────────────────────
# Sabitler
# ─────────────────────────────────────────────

SOCKET_PATH = "/run/airlock/helper.sock"
_CMD_TIMEOUT = 15
_MAX_MSG_SIZE = 4096

# Izin verilen pattern'lar (REGEX — siki esleme)
_ALLOWED_DEVICE_RE = re.compile(r"^/dev/sd[a-z][0-9]{0,3}$")
_ALLOWED_MOUNT_RE = re.compile(r"^/mnt/airlock_(source|target|update)$")
_ALLOWED_SYSFS_RE = re.compile(
    r"^/sys/bus/usb/devices/[0-9]+-[0-9]+(\.[0-9]+)*/authorized$"
)

# Izin verilen mount secenekleri (whitelist)
_ALLOWED_MOUNT_OPTIONS = frozenset({
    "ro", "rw", "noexec", "nosuid", "nodev", "noatime",
    "sync", "dirsync", "relatime",
    "uid", "gid", "umask", "dmask", "fmask",  # FAT/exFAT/NTFS sahiplik
})

# ZORUNLU guvenlik mount secenekleri — eksikse otomatik eklenir
_REQUIRED_SECURITY_OPTIONS = {"noexec", "nosuid", "nodev"}

# Izin verilen filesystem turleri
_ALLOWED_FSTYPES = frozenset({
    "vfat", "exfat", "ntfs", "ext4", "ext3",
})

# ClamAV guncelleme sabitleri
_CLAMAV_DB_PATH = Path("/var/lib/clamav")
_ALLOWED_CLAMAV_ACTIONS = frozenset({"copy_file", "service_stop", "service_start"})
_ALLOWED_CVD_EXTENSIONS = frozenset({".cvd", ".cld"})  # eski — artik filename whitelist kullanilir
# ClamAV dosya boyut araliklari (byte) — cok kucuk/buyuk → suphe
_CLAMAV_SIZE_LIMITS = {
    "main.cvd":     (50 * 1024 * 1024,   500 * 1024 * 1024),
    "daily.cvd":    (100 * 1024,          200 * 1024 * 1024),
    "bytecode.cvd": (10 * 1024,           50 * 1024 * 1024),
    "main.cld":     (50 * 1024 * 1024,    500 * 1024 * 1024),
    "daily.cld":    (100 * 1024,          200 * 1024 * 1024),
    "bytecode.cld": (10 * 1024,           50 * 1024 * 1024),
}
# Izin verilen ClamAV dosya adlari — _CLAMAV_SIZE_LIMITS key'lerinden turetilir (DRY)
_ALLOWED_CLAMAV_FILENAMES = frozenset(_CLAMAV_SIZE_LIMITS.keys())


# ─────────────────────────────────────────────
# Dogrulama Fonksiyonlari
# ─────────────────────────────────────────────


def _validate_device(device: str) -> Optional[str]:
    """Cihaz yolunu dogrula. Hata varsa mesaj dondur."""
    if not _ALLOWED_DEVICE_RE.match(device):
        return f"REJECTED_DEVICE: '{device}' — sadece /dev/sd[a-z][0-9]{{0,3}} izinli"
    real = os.path.realpath(device)
    if real != device:
        return f"REJECTED_SYMLINK: '{device}' -> '{real}'"
    return None


def _validate_mountpoint(target: str) -> Optional[str]:
    """Mount noktasini dogrula. Hata varsa mesaj dondur."""
    if not _ALLOWED_MOUNT_RE.match(target):
        return f"REJECTED_MOUNTPOINT: '{target}' — sadece /mnt/airlock_(source|target|update) izinli"
    return None


def _validate_mount_options(options: str) -> Optional[str]:
    """Mount seceneklerini dogrula. Hata varsa mesaj dondur."""
    parts = options.split(",")
    for opt in parts:
        opt_key = opt.split("=")[0].strip()
        if opt_key not in _ALLOWED_MOUNT_OPTIONS:
            return f"REJECTED_OPTION: '{opt_key}' — izinli degil"
    return None


def _validate_fstype(fstype: str) -> Optional[str]:
    """Filesystem turunu dogrula. Hata varsa mesaj dondur."""
    if fstype not in _ALLOWED_FSTYPES:
        return f"REJECTED_FSTYPE: '{fstype}' — izinli: {sorted(_ALLOWED_FSTYPES)}"
    return None


def _validate_sysfs_path(sysfs_path: str) -> Optional[str]:
    """sysfs authorized yolunu dogrula. Hata varsa mesaj dondur."""
    if not _ALLOWED_SYSFS_RE.match(sysfs_path):
        return (
            f"REJECTED_SYSFS: '{sysfs_path}' — "
            "sadece /sys/bus/usb/devices/<bus>/authorized izinli"
        )
    real = os.path.realpath(sysfs_path)
    if not real.startswith("/sys/bus/usb/devices/"):
        return f"REJECTED_SYSFS_SYMLINK: '{sysfs_path}' -> '{real}'"
    return None


def _enforce_mount_policy(target: str, options: str, fstype: str = "") -> tuple[str, Optional[str]]:
    """
    Mount hedefine gore ro/rw politikasini zorla ve guvenlik seceneklerini ekle.

    Kurallar:
      - /mnt/airlock_source → "ro" ZORUNLU, "rw" YASAK (kaynak USB ASLA yazilmaz)
      - /mnt/airlock_target → "rw" ZORUNLU (hedef USB yazilabilir olmali)
      - Her iki hedef icin: noexec, nosuid, nodev ZORUNLU
        (eksik olanlar otomatik eklenir)
      - FAT/exFAT/NTFS: uid, gid, umask otomatik eklenir
        (POSIX izin sistemi olmayan FS'lerde airlock erisimi icin)

    Args:
        target: Mount noktasi
        options: Istenen mount secenekleri
        fstype: Filesystem turu (vfat, ext4 vb.) — FS-specific secenek icin

    Returns:
        (duzeltilmis_options, error_message) tuple
        error varsa options bos string doner
    """
    opt_set = set(options.split(",")) if options else set()

    # ── Kaynak / Update USB: read-only ZORUNLU ──
    if target in ("/mnt/airlock_source", "/mnt/airlock_update"):
        # "rw" varsa → REJECT (kaynak/update USB ASLA yazilmaz)
        if "rw" in opt_set:
            return "", f"REJECTED_SOURCE_RW: {target} icin 'rw' YASAK — sadece 'ro' izinli"
        # "ro" yoksa ekle
        if "ro" not in opt_set:
            opt_set.add("ro")
            logger.info("MOUNT POLICY: %s icin 'ro' otomatik eklendi", target)

    # ── Hedef USB: read-write ZORUNLU ──
    elif target == "/mnt/airlock_target":
        # "rw" yoksa ekle
        if "rw" not in opt_set:
            opt_set.add("rw")
            logger.info("MOUNT POLICY: hedef USB icin 'rw' otomatik eklendi")
        # Hedef icin "ro" mantikli degil — cikar
        if "ro" in opt_set:
            opt_set.discard("ro")
            logger.warning("MOUNT POLICY: hedef USB icin 'ro' cikarildi, 'rw' zorunlu")

    # ── Guvenlik secenekleri: noexec, nosuid, nodev ZORUNLU ──
    for required in _REQUIRED_SECURITY_OPTIONS:
        if required not in opt_set:
            opt_set.add(required)
            logger.info("MOUNT POLICY: '%s' otomatik eklendi", required)

    # ── FAT/exFAT/NTFS: uid/gid/umask otomatik ekle ──
    # Bu FS'ler POSIX izin sistemi desteklemez — uid/gid olmadan
    # dosyalar root:root olur ve airlock kullanicisi erisemez
    _NON_POSIX_FS = frozenset({"vfat", "exfat", "ntfs"})
    if fstype in _NON_POSIX_FS:
        try:
            import pwd  # noqa: PLC0415 — sadece non-POSIX FS'te gerekli
            pw = pwd.getpwnam("airlock")
            _uid, _gid = pw.pw_uid, pw.pw_gid
        except (KeyError, ImportError):
            _uid, _gid = 1000, 1000  # fallback

        has_uid = any(o.startswith("uid=") for o in opt_set)
        has_gid = any(o.startswith("gid=") for o in opt_set)
        has_umask = any(o.startswith("umask=") for o in opt_set)

        if not has_uid:
            opt_set.add(f"uid={_uid}")
        if not has_gid:
            opt_set.add(f"gid={_gid}")
        if not has_umask:
            opt_set.add("umask=0077")

        logger.info(
            "MOUNT POLICY: %s FS icin uid=%d,gid=%d,umask=0077 eklendi",
            fstype, _uid, _gid,
        )

    return ",".join(sorted(opt_set)), None


# ─────────────────────────────────────────────
# Komut Isleyiciler
# ─────────────────────────────────────────────


def _handle_mount(request: Dict[str, Any]) -> Dict[str, Any]:
    """mount komutu isle."""
    device = request.get("device", "")
    target = request.get("target", "")
    fstype = request.get("fstype", "")
    options = request.get("options", "")

    # Temel dogrulamalar
    for validator, value in [
        (_validate_device, device),
        (_validate_mountpoint, target),
        (_validate_fstype, fstype),
        (_validate_mount_options, options),
    ]:
        error = validator(value)
        if error:
            logger.warning("MOUNT RED: %s", error)
            return {"ok": False, "error": error}

    # ── Hedefe gore ro/rw politikasi zorla + guvenlik secenekleri ekle ──
    enforced_options, policy_error = _enforce_mount_policy(target, options, fstype)
    if policy_error:
        logger.warning("MOUNT POLICY RED: %s", policy_error)
        return {"ok": False, "error": policy_error}
    options = enforced_options

    # Mount noktasini hazirla
    mp = Path(target)
    try:
        mp.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return {"ok": False, "error": f"MKDIR_FAILED: {exc}"}

    # Mount komutu (shell=False ZORUNLU)
    cmd = ["mount", "-t", fstype, "-o", options, device, target]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=_CMD_TIMEOUT,
        )
        if result.returncode != 0:
            logger.error("MOUNT BASARISIZ: %s -> %s", device, result.stderr.strip())
            return {"ok": False, "error": f"MOUNT_FAILED: {result.stderr.strip()[:200]}"}
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "MOUNT_TIMEOUT"}
    except (FileNotFoundError, OSError) as exc:
        return {"ok": False, "error": f"MOUNT_ERROR: {exc}"}

    logger.info("MOUNT OK: %s -> %s (%s, %s)", device, target, fstype, options)
    return {"ok": True}


def _handle_umount(request: Dict[str, Any]) -> Dict[str, Any]:
    """umount komutu isle."""
    target = request.get("target", "")

    error = _validate_mountpoint(target)
    if error:
        logger.warning("UMOUNT RED: %s", error)
        return {"ok": False, "error": error}

    # sync
    try:
        subprocess.run(["sync"], capture_output=True, timeout=_CMD_TIMEOUT)
    except (subprocess.TimeoutExpired, OSError):
        pass

    # Normal unmount
    try:
        result = subprocess.run(
            ["umount", target],
            capture_output=True,
            text=True,
            timeout=_CMD_TIMEOUT,
        )
        if result.returncode == 0:
            logger.info("UMOUNT OK: %s", target)
            return {"ok": True}
    except (subprocess.TimeoutExpired, OSError):
        pass

    # Lazy unmount fallback
    try:
        result = subprocess.run(
            ["umount", "-l", target],
            capture_output=True,
            text=True,
            timeout=_CMD_TIMEOUT,
        )
        if result.returncode == 0:
            logger.warning("UMOUNT LAZY OK: %s", target)
            return {"ok": True}
    except (subprocess.TimeoutExpired, OSError) as exc:
        return {"ok": False, "error": f"UMOUNT_FAILED: {exc}"}

    return {"ok": False, "error": "UMOUNT_FAILED: tum yontemler basarisiz"}


def _handle_deauth(request: Dict[str, Any]) -> Dict[str, Any]:
    """USB deauthorize komutu isle."""
    sysfs_path = request.get("sysfs_path", "")

    error = _validate_sysfs_path(sysfs_path)
    if error:
        logger.warning("DEAUTH RED: %s", error)
        return {"ok": False, "error": error}

    try:
        Path(sysfs_path).write_text("0")
        logger.warning("DEAUTH OK: %s", sysfs_path)
        return {"ok": True}
    except (PermissionError, FileNotFoundError, OSError) as exc:
        logger.error("DEAUTH BASARISIZ: %s — %s", sysfs_path, exc)
        return {"ok": False, "error": f"DEAUTH_FAILED: {exc}"}


def _handle_update_clamav(request: Dict[str, Any]) -> Dict[str, Any]:
    """
    ClamAV veritabani guncelleme komutu isle.

    3 alt-aksiyon:
      - "service_stop"  → systemctl stop clamav-daemon
      - "service_start" → systemctl start clamav-daemon
      - "copy_file"     → CVD/CLD dosyasini /var/lib/clamav/ altina kopyala

    Guvenlik:
      - Sadece .cvd/.cld uzantili dosyalara izin
      - Dosya boyut araligi kontrolu
      - Hedef SADECE /var/lib/clamav/
      - Kaynak dosyada symlink kontrolu
      - Diger her sey → REJECT
    """
    action = request.get("action", "")

    if action not in _ALLOWED_CLAMAV_ACTIONS:
        return {
            "ok": False,
            "error": f"REJECTED_CLAMAV_ACTION: '{action}' — "
                     f"izinli: {sorted(_ALLOWED_CLAMAV_ACTIONS)}",
        }

    # ── Servis kontrol ──
    if action in ("service_stop", "service_start"):
        systemctl_action = "stop" if action == "service_stop" else "start"
        try:
            result = subprocess.run(
                ["systemctl", systemctl_action, "clamav-daemon"],
                capture_output=True,
                text=True,
                timeout=_CMD_TIMEOUT,
            )
            if result.returncode == 0:
                logger.info("CLAMAV %s OK", systemctl_action.upper())
                return {"ok": True}
            else:
                logger.warning(
                    "CLAMAV %s BASARISIZ: %s",
                    systemctl_action.upper(), result.stderr.strip()[:200],
                )
                return {"ok": False, "error": f"CLAMAV_SERVICE_FAILED: {result.stderr.strip()[:200]}"}
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
            return {"ok": False, "error": f"CLAMAV_SERVICE_ERROR: {exc}"}

    # ── Dosya kopyalama ──
    # action == "copy_file"
    source = request.get("source", "")
    filename = request.get("filename", "")

    # Dosya adi dogrulamasi — SADECE bilinen ClamAV dosya adlari
    if not filename:
        return {"ok": False, "error": "REJECTED_CLAMAV: filename bos"}

    if filename not in _ALLOWED_CLAMAV_FILENAMES:
        return {
            "ok": False,
            "error": f"REJECTED_CLAMAV_FILENAME: '{filename}' — "
                     f"sadece {sorted(_ALLOWED_CLAMAV_FILENAMES)} izinli",
        }

    src_path = Path(source)
    dest_path = _CLAMAV_DB_PATH / filename

    # Path traversal kontrolu — hedef /var/lib/clamav/ icinde kalmali
    try:
        dest_resolved = dest_path.resolve()
        if not str(dest_resolved).startswith(str(_CLAMAV_DB_PATH)):
            return {
                "ok": False,
                "error": f"REJECTED_CLAMAV_TRAVERSAL: hedef /var/lib/clamav/ disinda",
            }
    except (OSError, ValueError):
        return {"ok": False, "error": "REJECTED_CLAMAV_PATH: hedef yol cozulemedi"}

    # Kaynak dosya dogrulamalari
    if not src_path.exists():
        return {"ok": False, "error": f"REJECTED_CLAMAV_SOURCE: '{source}' bulunamadi"}
    if src_path.is_symlink():
        return {"ok": False, "error": f"REJECTED_CLAMAV_SYMLINK: '{source}' bir symlink"}

    # Kaynak yol sinirlamasi — SADECE UPDATE USB'den dosya kabul et
    try:
        src_resolved = src_path.resolve()
        if not str(src_resolved).startswith("/mnt/airlock_update/"):
            return {
                "ok": False,
                "error": f"REJECTED_CLAMAV_SOURCE_PATH: kaynak /mnt/airlock_update/ disinda: "
                         f"'{src_resolved}'",
            }
    except (OSError, ValueError):
        return {"ok": False, "error": "REJECTED_CLAMAV_SOURCE_RESOLVE: kaynak yol cozulemedi"}

    # Boyut araligi kontrolu
    file_size = src_path.stat().st_size
    limits = _CLAMAV_SIZE_LIMITS.get(filename)
    if limits:
        min_size, max_size = limits
        if file_size < min_size or file_size > max_size:
            return {
                "ok": False,
                "error": f"REJECTED_CLAMAV_SIZE: '{filename}' {file_size} bytes — "
                         f"beklenen: {min_size}-{max_size} bytes",
            }

    # Kopyala
    try:
        shutil.copy2(str(src_path), str(dest_path))
        logger.info("CLAMAV COPY OK: %s -> %s (%d bytes)", source, dest_path, file_size)
        return {"ok": True}
    except (PermissionError, OSError) as exc:
        logger.error("CLAMAV COPY BASARISIZ: %s", exc)
        return {"ok": False, "error": f"CLAMAV_COPY_FAILED: {exc}"}


# Komut dispatch tablosu
_HANDLERS = {
    "mount": _handle_mount,
    "umount": _handle_umount,
    "deauth": _handle_deauth,
    "update_clamav": _handle_update_clamav,
}


# ─────────────────────────────────────────────
# Sunucu Sinifi
# ─────────────────────────────────────────────


class HelperServer:
    """
    Ayricalikli yardimci Unix socket sunucusu.

    Root olarak calisir, sadece 4 komutu kabul eder.
    Her istek JSON, her yanit JSON.
    """

    # Rate limit sabitleri
    _RATE_LIMIT: int = 2         # Pencere basina max istek
    _RATE_WINDOW: float = 1.0    # Saniye cinsinden pencere suresi

    def __init__(self, socket_path: str = SOCKET_PATH) -> None:
        self._socket_path = socket_path
        self._server: Optional[socket.socket] = None
        self._running = False
        self._logger = logging.getLogger("AIRLOCK.HELPER")

        # ThreadPoolExecutor — sinirli thread sayisi (DoS onlemi)
        self._executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=4, thread_name_prefix="helper"
        )

        # Thread-safe rate limiter
        self._rate_lock = threading.Lock()
        self._request_timestamps: Dict[str, List[float]] = {}

    def start(self) -> None:
        """Sunucuyu baslat ve baglantilari dinle."""
        self._setup_socket()
        self._running = True

        # Graceful shutdown
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)

        self._logger.info(
            "Privileged helper baslatildi: %s (PID=%d)",
            self._socket_path, os.getpid(),
        )

        try:
            while self._running:
                try:
                    self._server.settimeout(1.0)
                    conn, _ = self._server.accept()
                except socket.timeout:
                    continue
                except OSError:
                    if self._running:
                        self._logger.error("Socket accept hatasi")
                    break

                # Her baglantiyi ThreadPool'da isle (max 4 worker)
                self._executor.submit(self._handle_connection, conn)

        finally:
            self.stop()

    def stop(self) -> None:
        """Sunucuyu durdur ve temizle."""
        self._running = False
        # ThreadPool'u kapat (beklemeden — islemdeki isler tamamlanir)
        self._executor.shutdown(wait=False)
        if self._server:
            try:
                self._server.close()
            except OSError:
                pass
        # Socket dosyasini temizle
        try:
            os.unlink(self._socket_path)
        except OSError:
            pass
        self._logger.info("Privileged helper durduruldu")

    def _setup_socket(self) -> None:
        """Unix socket olustur ve dinlemeye basla."""
        sock_dir = Path(self._socket_path).parent
        sock_dir.mkdir(parents=True, exist_ok=True)

        # Eski socket varsa temizle
        try:
            os.unlink(self._socket_path)
        except OSError:
            pass

        self._server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server.bind(self._socket_path)

        # Socket izinleri: root:airlock, 0660
        os.chmod(self._socket_path, 0o660)
        # airlock grubuna ata (GID lookup)
        try:
            import grp
            gid = grp.getgrnam("airlock").gr_gid
            os.chown(self._socket_path, 0, gid)
        except (KeyError, ImportError, OSError):
            self._logger.warning(
                "airlock grubu bulunamadi — socket izinleri varsayilan kalacak"
            )

        self._server.listen(5)

    def _check_peer_credentials(self, conn: socket.socket) -> bool:
        """SO_PEERCRED ile baglanti sahibinin UID'sini dogrula (Linux only).

        Sadece root (0) ve airlock kullanicisina izin verilir.
        SO_PEERCRED mevcut degilse (macOS/BSD) uyari loglanir ve izin verilir.
        """
        if not hasattr(socket, "SO_PEERCRED"):
            self._logger.warning(
                "SO_PEERCRED desteklenmiyor (non-Linux?) — peer dogrulama atlanacak"
            )
            return True

        try:
            cred = conn.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
            )
            peer_pid, peer_uid, peer_gid = struct.unpack("3i", cred)

            # airlock kullanici UID'sini bul
            try:
                import pwd  # noqa: PLC0415
                expected_uid = pwd.getpwnam("airlock").pw_uid
            except (KeyError, ImportError):
                expected_uid = -1   # airlock kullanicisi yok — sadece root'a izin ver

            if peer_uid != 0 and peer_uid != expected_uid:
                self._logger.warning(
                    "REJECTED: yetkisiz UID=%d (PID=%d, GID=%d)",
                    peer_uid, peer_pid, peer_gid,
                )
                conn.sendall(json.dumps(
                    {"ok": False, "error": "REJECTED: yetkisiz kullanici"}
                ).encode("utf-8"))
                return False

            return True
        except (OSError, struct.error) as exc:
            self._logger.warning("SO_PEERCRED okunamadi: %s — baglanti reddediliyor", exc)
            return False

    def _check_rate_limit(self, cmd: str) -> bool:
        """Thread-safe rate limit kontrolu.

        Her komut tipi icin pencere basina max _RATE_LIMIT istek.
        """
        with self._rate_lock:
            now = time.monotonic()
            timestamps = self._request_timestamps.get(cmd, [])
            # Pencere disindaki kayitlari temizle
            timestamps = [t for t in timestamps if now - t < self._RATE_WINDOW]
            if len(timestamps) >= self._RATE_LIMIT:
                return False
            timestamps.append(now)
            self._request_timestamps[cmd] = timestamps
            return True

    def _handle_connection(self, conn: socket.socket) -> None:
        """Tek baglantiyi isle: peer dogrula -> oku -> parse -> rate limit -> calistir -> yanitla."""
        try:
            conn.settimeout(_CMD_TIMEOUT)

            # SO_PEERCRED peer credential kontrolu
            if not self._check_peer_credentials(conn):
                return

            raw = conn.recv(_MAX_MSG_SIZE)
            if not raw:
                return

            # JSON parse
            try:
                request = json.loads(raw.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                response = {"ok": False, "error": f"INVALID_JSON: {exc}"}
                conn.sendall(json.dumps(response).encode("utf-8"))
                return

            # Komut dispatch
            cmd = request.get("cmd", "")

            # Rate limit kontrolu
            if not self._check_rate_limit(cmd):
                self._logger.warning("RATE_LIMITED: '%s' komutu cok sik", cmd)
                response = {"ok": False, "error": "RATE_LIMITED"}
                conn.sendall(json.dumps(response).encode("utf-8"))
                return

            handler = _HANDLERS.get(cmd)

            if handler is None:
                self._logger.warning("BILINMEYEN KOMUT RED: '%s'", cmd)
                response = {
                    "ok": False,
                    "error": f"REJECTED: bilinmeyen komut '{cmd}' — "
                             f"izinli: {sorted(_HANDLERS.keys())}",
                }
            else:
                response = handler(request)

            conn.sendall(json.dumps(response).encode("utf-8"))

        except socket.timeout:
            self._logger.warning("Baglanti timeout")
        except OSError as exc:
            self._logger.error("Baglanti hatasi: %s", exc)
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _signal_handler(self, signum: int, frame: object) -> None:
        """SIGTERM/SIGINT yakalandiginda graceful shutdown."""
        self._logger.info("Sinyal alindi (%d) — durduruluyor", signum)
        self._running = False


# ─────────────────────────────────────────────
# Dogrudan Calistirma
# ─────────────────────────────────────────────

def main() -> None:
    """Privileged helper'i baslat."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    if os.geteuid() != 0:
        logger.error("Privileged helper root olarak calistirilmali!")
        sys.exit(1)

    server = HelperServer()
    server.start()


if __name__ == "__main__":
    main()

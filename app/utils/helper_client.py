"""
THE AIRLOCK v5.0.8 FORTRESS-HARDENED — Privileged Helper Istemci

airlock (non-root) servisinden privileged helper'a Unix socket
uzerinden komut gonderir.

4 fonksiyon:
  - request_mount(device, target, fstype, options) → (ok, error)
  - request_umount(target)                         → (ok, error)
  - request_deauthorize(sysfs_path)                → (ok, error)
  - request_update_clamav(action, source, filename) → (ok, error)

Protokol: JSON over Unix socket (tek mesaj gönder → tek yanıt al)

Kullanım:
    from app.utils.helper_client import request_mount, request_umount
    ok, err = request_mount("/dev/sda1", "/mnt/airlock_source", "vfat", "ro,noexec,nosuid,nodev")
    if not ok:
        logger.error("Mount başarısız: %s", err)
"""

from __future__ import annotations

import json
import logging
import socket
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger("AIRLOCK.HELPER_CLIENT")

# Privileged helper socket yolu
SOCKET_PATH = "/run/airlock/helper.sock"
_TIMEOUT = 15
_MAX_RESPONSE_SIZE = 4096


def _send_request(request: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    """
    Privileged helper'a JSON istek gönder ve yanıt al.

    Args:
        request: Gönderilecek JSON istek

    Returns:
        (ok, error_message) tuple
        ok=True → başarılı, error=None
        ok=False → başarısız, error=açıklama
    """
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(_TIMEOUT)

        try:
            sock.connect(SOCKET_PATH)
        except (FileNotFoundError, ConnectionRefusedError) as exc:
            logger.error(
                "Helper socket bağlantısı başarısız (%s): %s",
                SOCKET_PATH, exc,
            )
            return False, f"HELPER_UNAVAILABLE: {exc}"

        # İstek gönder
        payload = json.dumps(request).encode("utf-8")
        sock.sendall(payload)

        # Yanıt al
        raw = sock.recv(_MAX_RESPONSE_SIZE)
        if not raw:
            return False, "HELPER_EMPTY_RESPONSE"

        response = json.loads(raw.decode("utf-8"))
        ok = response.get("ok", False)
        error = response.get("error")

        if not ok:
            logger.warning("Helper red: %s — %s", request.get("cmd"), error)

        return ok, error

    except socket.timeout:
        logger.error("Helper timeout (%ds)", _TIMEOUT)
        return False, "HELPER_TIMEOUT"
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        logger.error("Helper yanıt parse hatası: %s", exc)
        return False, f"HELPER_PARSE_ERROR: {exc}"
    except OSError as exc:
        logger.error("Helper iletişim hatası: %s", exc)
        return False, f"HELPER_IO_ERROR: {exc}"
    finally:
        try:
            sock.close()
        except OSError:
            pass


def request_mount(
    device: str,
    target: str,
    fstype: str,
    options: str,
) -> Tuple[bool, Optional[str]]:
    """
    Privileged helper üzerinden mount isteği gönder.

    Args:
        device: Blok cihaz yolu (ör: /dev/sda1)
        target: Mount noktası (ör: /mnt/airlock_source)
        fstype: Filesystem türü (vfat, exfat, ntfs, ext4, ext3)
        options: Mount seçenekleri (ro,noexec,nosuid,nodev)

    Returns:
        (ok, error) tuple
    """
    return _send_request({
        "cmd": "mount",
        "device": device,
        "target": target,
        "fstype": fstype,
        "options": options,
    })


def request_umount(target: str) -> Tuple[bool, Optional[str]]:
    """
    Privileged helper üzerinden umount isteği gönder.

    Args:
        target: Unmount edilecek mount noktası

    Returns:
        (ok, error) tuple
    """
    return _send_request({
        "cmd": "umount",
        "target": target,
    })


def request_deauthorize(sysfs_path: str) -> Tuple[bool, Optional[str]]:
    """
    Privileged helper uzerinden USB deauthorize istegi gonder.

    Args:
        sysfs_path: /sys/bus/usb/devices/<device>/authorized yolu

    Returns:
        (ok, error) tuple
    """
    return _send_request({
        "cmd": "deauth",
        "sysfs_path": sysfs_path,
    })


def request_update_clamav(
    action: str,
    source: str = "",
    filename: str = "",
) -> Tuple[bool, Optional[str]]:
    """
    Privileged helper uzerinden ClamAV guncelleme istegi gonder.

    3 aksiyon desteklenir:
      - "service_stop"  → ClamAV daemon durdur
      - "service_start" → ClamAV daemon baslat
      - "copy_file"     → CVD/CLD dosyasini /var/lib/clamav/ altina kopyala

    Args:
        action: Gerceklestirilecek aksiyon
        source: Kaynak dosya yolu (copy_file icin)
        filename: Hedef dosya adi (copy_file icin, or: main.cvd)

    Returns:
        (ok, error) tuple
    """
    request: Dict[str, Any] = {
        "cmd": "update_clamav",
        "action": action,
    }
    if source:
        request["source"] = source
    if filename:
        request["filename"] = filename

    return _send_request(request)

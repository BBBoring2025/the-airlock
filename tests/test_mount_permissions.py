"""
THE AIRLOCK v5.0.8 FORTRESS-HARDENED — Mount İzin Testleri

FAT/exFAT/NTFS gibi POSIX izin sistemi olmayan filesystem'lerde
uid/gid/umask otomatik eklenmesini ve ext4 gibi POSIX FS'lerde
eklenmemesini doğrular.

Test edilen fonksiyon:
    app.utils.privileged_helper._enforce_mount_policy()
"""

from __future__ import annotations

import unittest
from unittest import mock

from app.utils.privileged_helper import _enforce_mount_policy


def _parse_options(options_str: str) -> dict[str, str]:
    """Mount option string'ini key=value dict'ine çevir."""
    result: dict[str, str] = {}
    for opt in options_str.split(","):
        if "=" in opt:
            key, val = opt.split("=", 1)
            result[key] = val
        else:
            result[opt] = ""
    return result


class TestVfatMountOptions(unittest.TestCase):
    """vfat filesystem için uid/gid/umask eklenmesini doğrula."""

    def test_vfat_source_gets_uid_gid_umask(self) -> None:
        """vfat + source → uid, gid, umask=0077 eklenmeli."""
        options, error = _enforce_mount_policy(
            "/mnt/airlock_source", "ro,noexec,nosuid,nodev", "vfat",
        )
        self.assertIsNone(error)
        parsed = _parse_options(options)
        self.assertIn("uid", parsed)
        self.assertIn("gid", parsed)
        self.assertEqual(parsed["umask"], "0077")

    def test_vfat_target_gets_uid_gid_umask(self) -> None:
        """vfat + target → uid, gid, umask=0077 eklenmeli."""
        options, error = _enforce_mount_policy(
            "/mnt/airlock_target", "rw,noexec,nosuid,nodev", "vfat",
        )
        self.assertIsNone(error)
        parsed = _parse_options(options)
        self.assertIn("uid", parsed)
        self.assertIn("gid", parsed)
        self.assertEqual(parsed["umask"], "0077")

    def test_vfat_preserves_existing_uid(self) -> None:
        """Kullanıcı uid= belirtmişse üzerine yazılmamalı."""
        options, error = _enforce_mount_policy(
            "/mnt/airlock_source", "ro,noexec,nosuid,nodev,uid=500", "vfat",
        )
        self.assertIsNone(error)
        parsed = _parse_options(options)
        self.assertEqual(parsed["uid"], "500")

    def test_exfat_also_gets_uid_gid(self) -> None:
        """exFAT da non-POSIX — uid/gid eklenmeli."""
        options, error = _enforce_mount_policy(
            "/mnt/airlock_source", "ro", "exfat",
        )
        self.assertIsNone(error)
        parsed = _parse_options(options)
        self.assertIn("uid", parsed)
        self.assertIn("gid", parsed)
        self.assertIn("umask", parsed)

    def test_ntfs_gets_uid_gid(self) -> None:
        """NTFS de non-POSIX — uid/gid eklenmeli."""
        options, error = _enforce_mount_policy(
            "/mnt/airlock_target", "rw", "ntfs",
        )
        self.assertIsNone(error)
        parsed = _parse_options(options)
        self.assertIn("uid", parsed)
        self.assertIn("gid", parsed)
        self.assertEqual(parsed["umask"], "0077")


class TestExt4MountOptions(unittest.TestCase):
    """ext4 (POSIX) filesystem için uid/gid EKLENMEMESİNİ doğrula."""

    def test_ext4_no_uid_gid(self) -> None:
        """ext4 POSIX FS — uid/gid eklenmemeli."""
        options, error = _enforce_mount_policy(
            "/mnt/airlock_source", "ro,noexec,nosuid,nodev", "ext4",
        )
        self.assertIsNone(error)
        parsed = _parse_options(options)
        self.assertNotIn("uid", parsed)
        self.assertNotIn("gid", parsed)
        self.assertNotIn("umask", parsed)

    def test_ext3_no_uid_gid(self) -> None:
        """ext3 POSIX FS — uid/gid eklenmemeli."""
        options, error = _enforce_mount_policy(
            "/mnt/airlock_target", "rw,noexec,nosuid,nodev", "ext3",
        )
        self.assertIsNone(error)
        parsed = _parse_options(options)
        self.assertNotIn("uid", parsed)
        self.assertNotIn("gid", parsed)
        self.assertNotIn("umask", parsed)


class TestUnknownFstype(unittest.TestCase):
    """Bilinmeyen veya boş fstype güvenli davranış."""

    def test_empty_fstype_no_uid_gid(self) -> None:
        """Boş fstype → uid/gid eklenmemeli (güvenli varsayılan)."""
        options, error = _enforce_mount_policy(
            "/mnt/airlock_source", "ro,noexec,nosuid,nodev", "",
        )
        self.assertIsNone(error)
        parsed = _parse_options(options)
        self.assertNotIn("uid", parsed)
        self.assertNotIn("gid", parsed)

    def test_security_options_always_enforced(self) -> None:
        """Tüm FS türlerinde noexec,nosuid,nodev zorunlu."""
        for fstype in ("vfat", "ext4", "ntfs", ""):
            options, error = _enforce_mount_policy(
                "/mnt/airlock_source", "ro", fstype,
            )
            self.assertIsNone(error, f"fstype={fstype} için hata: {error}")
            parsed = _parse_options(options)
            self.assertIn("noexec", parsed, f"fstype={fstype}: noexec eksik")
            self.assertIn("nosuid", parsed, f"fstype={fstype}: nosuid eksik")
            self.assertIn("nodev", parsed, f"fstype={fstype}: nodev eksik")

    def test_source_always_ro(self) -> None:
        """Tüm FS türlerinde source → ro zorunlu."""
        for fstype in ("vfat", "ext4", "ntfs"):
            options, error = _enforce_mount_policy(
                "/mnt/airlock_source", "", fstype,
            )
            self.assertIsNone(error)
            parsed = _parse_options(options)
            self.assertIn("ro", parsed, f"fstype={fstype}: ro eksik")

    def test_target_always_rw(self) -> None:
        """Tüm FS türlerinde target → rw zorunlu."""
        for fstype in ("vfat", "ext4", "ntfs"):
            options, error = _enforce_mount_policy(
                "/mnt/airlock_target", "", fstype,
            )
            self.assertIsNone(error)
            parsed = _parse_options(options)
            self.assertIn("rw", parsed, f"fstype={fstype}: rw eksik")


if __name__ == "__main__":
    unittest.main()

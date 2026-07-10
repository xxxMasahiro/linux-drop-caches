from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from linux_cache_guard.config import load_policy
from linux_cache_guard.models import GIB


class ConfigTests(unittest.TestCase):
    def test_missing_config_uses_safe_auto_cleanup_default(self) -> None:
        with TemporaryDirectory() as temporary:
            policy = load_policy(Path(temporary) / "missing.toml")
        self.assertTrue(policy.enabled)
        self.assertFalse(policy.auto_cleanup)
        self.assertEqual(policy.threshold_bytes(11 * GIB), int(11 * GIB * 0.35))

    def test_invalid_boolean_is_rejected(self) -> None:
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "config.toml"
            path.write_text("[policy]\nauto_cleanup = 'yes'\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "auto_cleanup"):
                load_policy(path)

    def test_noncanonical_helper_path_is_rejected(self) -> None:
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "config.toml"
            path.write_text("[policy]\nhelper_path = '/usr/bin/sh'\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "helper_path is fixed"):
                load_policy(path)

    def test_unknown_setting_is_rejected(self) -> None:
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "config.toml"
            path.write_text("[policy]\nauto_cleanp = false\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "unknown policy setting: auto_cleanp"):
                load_policy(path)

    def test_missing_system_configuration_fails_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "required system configuration"):
            load_policy(Path("/etc/linux-cache-guard/does-not-exist.toml"))

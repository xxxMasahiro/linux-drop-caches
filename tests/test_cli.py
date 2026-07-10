from __future__ import annotations

import unittest

from linux_cache_guard.cli import _schedule_override_contents, _validate_interval


class ScheduleTests(unittest.TestCase):
    def test_accepts_supported_intervals(self) -> None:
        self.assertEqual(_validate_interval("30s"), "30s")
        self.assertEqual(_validate_interval("15min"), "15min")
        self.assertEqual(_validate_interval("1h"), "1h")
        self.assertEqual(_validate_interval("2d"), "2d")

    def test_rejects_invalid_intervals(self) -> None:
        for interval in ("0min", "10 minutes", "-1h", "weekly"):
            with self.subTest(interval=interval):
                with self.assertRaisesRegex(ValueError, "interval must look like"):
                    _validate_interval(interval)

    def test_timer_override_replaces_both_default_triggers(self) -> None:
        contents = _schedule_override_contents("30min")
        self.assertIn("OnBootSec=\n", contents)
        self.assertIn("OnUnitActiveSec=\n", contents)
        self.assertIn("OnBootSec=30min\n", contents)
        self.assertIn("OnUnitActiveSec=30min\n", contents)

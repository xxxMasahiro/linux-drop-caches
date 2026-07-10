from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from linux_cache_guard.models import GIB, MIB
from linux_cache_guard.system import check_helper, parse_meminfo


class SystemTests(unittest.TestCase):
    def test_parse_meminfo_calculates_reclaimable_cache(self) -> None:
        parsed = parse_meminfo(
            """MemTotal:       11534336 kB
MemAvailable:    7340032 kB
Buffers:            1024 kB
Cached:          2097152 kB
KReclaimable:    1048576 kB
SwapTotal:      16777216 kB
SwapFree:       16711680 kB
"""
        )
        self.assertEqual(parsed.total_bytes, 11 * GIB)
        self.assertEqual(parsed.available_bytes, 7 * GIB)
        self.assertEqual(parsed.reclaimable_cache_bytes, 3 * GIB + MIB)
        self.assertEqual(parsed.swap_used_bytes, 64 * MIB)

    def test_helper_symlink_is_rejected(self) -> None:
        with TemporaryDirectory() as temporary:
            directory = Path(temporary)
            target = directory / "target"
            target.write_text("#!/bin/sh\n", encoding="utf-8")
            target.chmod(0o755)
            link = directory / "helper"
            link.symlink_to(target)
            status = check_helper(link)
        self.assertFalse(status.ok)
        self.assertIn("helper must not be a symbolic link", status.reasons)

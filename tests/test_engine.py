from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import subprocess
import unittest
from unittest.mock import patch

from linux_cache_guard.engine import cleanup, evaluate_cleanup, load_history, load_state, pending_file, recover_pending
from linux_cache_guard.models import GIB, MIB, CleanupState, HelperStatus, MemorySnapshot, Policy


def snapshot(*, cache_gib: int = 4, dirty_mib: int = 0, writeback_mib: int = 0) -> MemorySnapshot:
    return MemorySnapshot(
        values={
            "MemTotal": 11 * GIB,
            "MemAvailable": 6 * GIB,
            "Buffers": 0,
            "Cached": cache_gib * GIB,
            "KReclaimable": 0,
            "Dirty": dirty_mib * MIB,
            "Writeback": writeback_mib * MIB,
            "SwapTotal": 0,
            "SwapFree": 0,
        }
    )


def helper() -> HelperStatus:
    return HelperStatus(path=Path("/helper"), exists=True, ok=True, owner_uid=0, mode="0o755")


class EngineTests(unittest.TestCase):
    def test_cleanup_is_recommended_when_all_gates_pass(self) -> None:
        policy = Policy(min_reclaimable_cache_bytes=3 * GIB, cooldown_seconds=0, min_cache_growth_bytes=0)
        decision = evaluate_cleanup(snapshot(), policy, helper(), CleanupState(), (), now=100)
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.status, "cleanup_recommended")

    def test_writeback_blocks_cleanup(self) -> None:
        policy = Policy(min_reclaimable_cache_bytes=3 * GIB, cooldown_seconds=0, min_cache_growth_bytes=0)
        decision = evaluate_cleanup(snapshot(writeback_mib=1), policy, helper(), CleanupState(), (), now=100)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.status, "blocked")
        self.assertIn("writeback is active", decision.reasons)

    def test_active_build_blocks_cleanup(self) -> None:
        policy = Policy(min_reclaimable_cache_bytes=3 * GIB, cooldown_seconds=0, min_cache_growth_bytes=0)
        decision = evaluate_cleanup(snapshot(), policy, helper(), CleanupState(), ("cargo",), now=100)
        self.assertFalse(decision.allowed)
        self.assertIn("active build process detected: cargo", decision.reasons)

    def test_missing_helper_is_reported_as_unavailable(self) -> None:
        policy = Policy(min_reclaimable_cache_bytes=3 * GIB, cooldown_seconds=0, min_cache_growth_bytes=0)
        unavailable_helper = HelperStatus(path=Path("/missing"), exists=False, ok=False, reasons=("helper unavailable",))
        decision = evaluate_cleanup(snapshot(), policy, unavailable_helper, CleanupState(), (), now=100)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.status, "unavailable")

    def test_dry_run_records_a_receipt_without_running_helper(self) -> None:
        with TemporaryDirectory() as temporary:
            policy = Policy(
                helper_path=Path(temporary) / "missing-helper",
                state_dir=Path(temporary) / "state",
            )
            result = cleanup(policy, dry_run=True, automatic=False)
            self.assertEqual(result.result, "skipped")
            self.assertIsNotNone(result.receipt_path)
            assert result.receipt_path is not None
            self.assertTrue(result.receipt_path.exists())

    def test_successful_cleanup_records_post_cleanup_state(self) -> None:
        with TemporaryDirectory() as temporary:
            policy = Policy(
                min_reclaimable_cache_bytes=3 * GIB,
                cooldown_seconds=0,
                min_cache_growth_bytes=0,
                state_dir=Path(temporary) / "state",
            )
            snapshots = iter((snapshot(cache_gib=4), snapshot(cache_gib=1)))
            result = cleanup(
                policy,
                dry_run=False,
                automatic=False,
                runner=lambda _, __: subprocess.CompletedProcess(("helper",), 0, "", ""),
                snapshot_loader=lambda: next(snapshots),
                process_loader=lambda: (),
                helper_loader=lambda _: helper(),
            )
            self.assertEqual(result.result, "completed")
            self.assertTrue(result.executed)
            self.assertEqual(result.as_dict()["estimated_reclaimable_cache_delta_bytes"], 3 * GIB)
            self.assertEqual(load_state(policy).last_success_cache_bytes, 1 * GIB)
            assert result.receipt_path is not None
            self.assertIn(str(result.receipt_path), result.receipt_path.read_text(encoding="utf-8"))

    def test_automatic_cleanup_requires_an_explicit_pressure_limit(self) -> None:
        with TemporaryDirectory() as temporary:
            policy = Policy(
                auto_cleanup=True,
                min_reclaimable_cache_bytes=3 * GIB,
                cooldown_seconds=0,
                min_cache_growth_bytes=0,
                state_dir=Path(temporary) / "state",
            )
            result = cleanup(
                policy,
                dry_run=False,
                automatic=True,
                snapshot_loader=lambda: snapshot(),
                process_loader=lambda: (),
                helper_loader=lambda _: helper(),
            )
            self.assertEqual(result.result, "skipped")
            self.assertIn("automatic cleanup requires max_available_memory_bytes", result.decision.reasons)

    def test_corrupt_state_fails_closed_before_automatic_cleanup(self) -> None:
        with TemporaryDirectory() as temporary:
            state_dir = Path(temporary) / "state"
            state_dir.mkdir(mode=0o700)
            (state_dir / "cleanup-state.json").write_text("not json", encoding="utf-8")
            policy = Policy(
                auto_cleanup=True,
                max_available_memory_bytes=8 * GIB,
                min_reclaimable_cache_bytes=3 * GIB,
                cooldown_seconds=0,
                min_cache_growth_bytes=0,
                state_dir=state_dir,
            )
            result = cleanup(
                policy,
                dry_run=False,
                automatic=True,
                runner=lambda _, __: self.fail("helper must not run"),
                snapshot_loader=lambda: snapshot(),
                process_loader=lambda: (),
                helper_loader=lambda _: helper(),
            )
            self.assertEqual(result.result, "skipped")
            self.assertIn("cleanup state store is unavailable", result.decision.reasons[0])

    def test_successful_helper_with_state_failure_remains_fail_closed(self) -> None:
        with TemporaryDirectory() as temporary:
            policy = Policy(
                min_reclaimable_cache_bytes=3 * GIB,
                cooldown_seconds=0,
                min_cache_growth_bytes=0,
                state_dir=Path(temporary) / "state",
            )
            snapshots = iter((snapshot(cache_gib=4), snapshot(cache_gib=1)))
            with patch("linux_cache_guard.engine.save_state", side_effect=OSError("disk full")):
                result = cleanup(
                    policy,
                    dry_run=False,
                    automatic=False,
                    runner=lambda _, __: subprocess.CompletedProcess(("helper",), 0, "", ""),
                    snapshot_loader=lambda: next(snapshots),
                    process_loader=lambda: (),
                    helper_loader=lambda _: helper(),
                )
            self.assertTrue(result.executed)
            self.assertEqual(result.result, "completed_with_recording_error")
            self.assertTrue(pending_file(policy).exists())

    def test_pending_recovery_requires_confirmation_and_writes_receipt(self) -> None:
        with TemporaryDirectory() as temporary:
            policy = Policy(state_dir=Path(temporary) / "state")
            policy.state_dir.mkdir(mode=0o700)
            pending_file(policy).write_text("{}", encoding="utf-8")
            self.assertEqual(recover_pending(policy, confirmed=False)["status"], "confirmation_required")
            result = recover_pending(policy, confirmed=True)
            self.assertEqual(result["status"], "recovered")
            self.assertFalse(pending_file(policy).exists())
            self.assertTrue((policy.state_dir / "cleanup-receipts.jsonl").exists())
            self.assertEqual(load_history(policy, limit=1)[0]["receipt_type"], "pending_cleanup_recovery")

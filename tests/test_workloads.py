from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch
from contextlib import redirect_stdout

from linux_cache_guard.cli import build_parser, main
from linux_cache_guard.workloads.admission import evaluate_admission
from linux_cache_guard.workloads.capabilities import detect_capabilities
from linux_cache_guard.workloads.cgroup_v2 import load_cgroup_snapshot, read_memory_high
from linux_cache_guard.workloads.config import load_workload_policy
from linux_cache_guard.workloads.contracts import (
    HostSnapshot,
    ManagedWorkload,
    PsiSample,
    WorkloadPolicy,
    WorkloadProfile,
)
from linux_cache_guard.workloads.procfs import parse_psi
from linux_cache_guard.workloads.runner import workload_run, workload_status
from linux_cache_guard.workloads.state import append_event, load_events, load_workloads, save_workloads
from linux_cache_guard.workloads.systemd_user import ScopeResult, SystemdUserError, SystemdUserRunner


def policy(*, state_dir: str, enabled: bool = True, mode: str = "admit") -> WorkloadPolicy:
    return WorkloadPolicy(
        enabled=enabled,
        mode=mode,
        min_host_available_bytes=2 * 1024 * 1024 * 1024,
        max_managed_workloads=2,
        event_max_bytes=65536,
        event_retention_days=14,
        sample_interval_seconds=60,
        profiles={"coding": WorkloadProfile("coding", 1024 * 1024 * 1024, 2 * 1024 * 1024 * 1024)},
        state_dir=state_dir,
    )


def host(*, available: int = 8 * 1024 * 1024 * 1024) -> HostSnapshot:
    return HostSnapshot(
        total_bytes=12 * 1024 * 1024 * 1024,
        available_bytes=available,
        swap_used_bytes=0,
        psi=PsiSample(some={"avg10": 0.0}, full={"avg10": 0.0}),
        collected_at="2026-07-11T00:00:00Z",
        scope="linux_host",
    )


class WorkloadConfigTests(unittest.TestCase):
    def test_strict_versioned_config_loads_profiles(self) -> None:
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "workload.toml"
            path.write_text(
                """format_version = 1
[workload_guard]
enabled = true
mode = "admit"
min_host_available_bytes = 1
max_managed_workloads = 2
event_max_bytes = 65536
event_retention_days = 2
sample_interval_seconds = 60
[workload_guard.profiles.coding]
admission_bytes = 10
memory_high_bytes = 20
""",
                encoding="utf-8",
            )
            loaded = load_workload_policy(path)
        self.assertTrue(loaded.enabled)
        self.assertEqual(loaded.profiles["coding"].memory_high_bytes, 20)

    def test_unknown_root_setting_is_rejected(self) -> None:
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "workload.toml"
            path.write_text("format_version = 1\nunknown = true\n[workload_guard]\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "unknown workload configuration"):
                load_workload_policy(path)

    def test_memory_high_must_cover_admission(self) -> None:
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "workload.toml"
            path.write_text(
                """format_version = 1
[workload_guard]
[workload_guard.profiles.coding]
admission_bytes = 20
memory_high_bytes = 10
""",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "must not exceed"):
                load_workload_policy(path)


class WorkloadObservationTests(unittest.TestCase):
    def test_psi_parser_keeps_some_and_full(self) -> None:
        sample = parse_psi("some avg10=1.00 avg60=0.50 avg300=0.25 total=10\nfull avg10=0.10 avg60=0.05 avg300=0.01 total=2\n", source="fixture")
        self.assertEqual(sample.some, {"avg10": 1.0, "avg60": 0.5, "avg300": 0.25, "total": 10.0})
        self.assertEqual(sample.full, {"avg10": 0.1, "avg60": 0.05, "avg300": 0.01, "total": 2.0})

    def test_cgroup_snapshot_reads_only_known_metrics(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = root / "user.slice" / "demo.scope"
            directory.mkdir(parents=True)
            (directory / "memory.current").write_text("100\n", encoding="utf-8")
            (directory / "memory.peak").write_text("120\n", encoding="utf-8")
            (directory / "memory.swap.current").write_text("2\n", encoding="utf-8")
            (directory / "memory.stat").write_text("anon 30\nfile 40\nslab 20\nfuture_key 99\n", encoding="utf-8")
            (directory / "memory.events").write_text("high 2\nmax 0\noom 0\noom_kill 0\n", encoding="utf-8")
            (directory / "cgroup.events").write_text("populated 1\n", encoding="utf-8")
            (directory / "pids.current").write_text("3\n", encoding="utf-8")
            (directory / "memory.pressure").write_text("some avg10=0.00\nfull avg10=0.00\n", encoding="utf-8")
            snapshot = load_cgroup_snapshot("/user.slice/demo.scope", root=root)
        self.assertEqual(snapshot.current_bytes, 100)
        self.assertEqual(snapshot.events["high"], 2)
        self.assertTrue(snapshot.populated)

    def test_memory_high_rejects_unlimited_or_missing_values(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = root / "user.slice" / "demo.scope"
            directory.mkdir(parents=True)
            (directory / "memory.high").write_text("max\n", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "unlimited"):
                read_memory_high("/user.slice/demo.scope", root=root)
            (directory / "memory.high").unlink()
            with self.assertRaisesRegex(RuntimeError, "cannot read"):
                read_memory_high("/user.slice/demo.scope", root=root)

    def test_status_does_not_create_state_directory(self) -> None:
        with TemporaryDirectory() as temporary:
            selected = policy(state_dir=str(Path(temporary) / "state"))
            with patch("linux_cache_guard.workloads.runner.load_host_snapshot", return_value=host()):
                workload_status(selected)
            self.assertFalse((Path(temporary) / "state").exists())


class WorkloadAdmissionTests(unittest.TestCase):
    def test_admission_defers_when_reserve_would_be_breached(self) -> None:
        selected = policy(state_dir="/tmp/unused")
        decision = evaluate_admission(selected, "coding", host(available=2 * 1024 * 1024 * 1024), ())
        self.assertEqual(decision.status, "defer")

    def test_admission_is_limited_by_active_workloads(self) -> None:
        selected = replace(policy(state_dir="/tmp/unused"), max_managed_workloads=1)
        active = ManagedWorkload("id", "coding", "unit", None, 1024, "2026-07-11T00:00:00Z")
        decision = evaluate_admission(selected, "coding", host(), (active,))
        self.assertEqual(decision.status, "defer")


class FakeRunner:
    state = "inactive"

    def unit_name(self, prefix: str = "linux-cache-guard-workload") -> str:
        return f"{prefix}-fixture.service"

    def unit_state(self, unit_name: str) -> str:
        return self.state

    def run(self, unit_name: str, memory_high_bytes: int, argv: tuple[str, ...], *, on_started):
        self.last_memory_high = memory_high_bytes
        on_started("/user.slice/fixture.scope")
        return ScopeResult(unit_name, "/user.slice/fixture.scope", 0, True)


class WorkloadRunnerTests(unittest.TestCase):
    def test_run_releases_reservation_and_never_uses_memory_max(self) -> None:
        with TemporaryDirectory() as temporary:
            selected = policy(state_dir=str(Path(temporary) / "state"))
            fake = FakeRunner()
            with patch("linux_cache_guard.workloads.runner._control_available", return_value=(True, ())):
                with patch("linux_cache_guard.workloads.runner.load_host_snapshot", return_value=host()):
                    decision, result = workload_run(selected, "coding", ("/usr/bin/true",), adapter=fake)  # type: ignore[arg-type]
            self.assertEqual(decision.status, "allow")
            self.assertIsNotNone(result)
            self.assertEqual(fake.last_memory_high, selected.profiles["coding"].memory_high_bytes)
            self.assertEqual(load_workloads(selected, strict=True), ())
            events = load_events(selected, limit=10)
        self.assertTrue(any(event.get("kind") == "workload_finished" for event in events))
        self.assertNotIn("/usr/bin/true", str(events))

    def test_fresh_starting_reservation_blocks_a_concurrent_run(self) -> None:
        with TemporaryDirectory() as temporary:
            selected = replace(policy(state_dir=str(Path(temporary) / "state")), max_managed_workloads=1)
            reservation = ManagedWorkload(
                "first",
                "coding",
                "linux-cache-guard-workload-first.service",
                None,
                selected.profiles["coding"].admission_bytes,
                datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
                status="starting",
            )
            save_workloads(selected, (reservation,))
            fake = FakeRunner()
            with patch("linux_cache_guard.workloads.runner._control_available", return_value=(True, ())):
                with patch("linux_cache_guard.workloads.runner.load_host_snapshot", return_value=host()):
                    decision, result = workload_run(selected, "coding", ("/usr/bin/true",), adapter=fake)  # type: ignore[arg-type]
            self.assertEqual(decision.status, "defer")
            self.assertIsNone(result)
            self.assertEqual(len(load_workloads(selected, strict=True)), 1)

    def test_stale_missing_reservation_is_reclaimed(self) -> None:
        with TemporaryDirectory() as temporary:
            selected = replace(policy(state_dir=str(Path(temporary) / "state")), max_managed_workloads=1)
            stale = ManagedWorkload(
                "stale",
                "coding",
                "linux-cache-guard-workload-stale.service",
                None,
                selected.profiles["coding"].admission_bytes,
                "2020-01-01T00:00:00Z",
                status="starting",
            )
            save_workloads(selected, (stale,))
            fake = FakeRunner()
            fake.state = "missing"
            with patch("linux_cache_guard.workloads.runner._control_available", return_value=(True, ())):
                with patch("linux_cache_guard.workloads.runner.load_host_snapshot", return_value=host()):
                    decision, result = workload_run(selected, "coding", ("/usr/bin/true",), adapter=fake)  # type: ignore[arg-type]
            self.assertEqual(decision.status, "allow")
            self.assertIsNotNone(result)


class SystemdUserRunnerTests(unittest.TestCase):
    def test_missing_unit_state_is_distinct_from_connection_failure(self) -> None:
        runner = SystemdUserRunner()
        with patch("linux_cache_guard.workloads.systemd_user.subprocess.run", return_value=Mock(returncode=4)):
            self.assertEqual(runner.unit_state("missing.service"), "missing")
        with patch("linux_cache_guard.workloads.systemd_user.subprocess.run", return_value=Mock(returncode=1)):
            self.assertEqual(runner.unit_state("broken.service"), "unknown")

    def test_root_or_unreadable_cgroup_is_not_verified(self) -> None:
        process = Mock()
        process.poll.return_value = 0
        process.wait.return_value = 0
        runner = SystemdUserRunner()
        runner._show = Mock(return_value={"ControlGroup": "/", "MemoryHigh": "10"})  # type: ignore[method-assign]
        runner._stop = Mock()  # type: ignore[method-assign]
        with patch("linux_cache_guard.workloads.systemd_user.subprocess.Popen", return_value=process):
            with self.assertRaisesRegex(SystemdUserError, "did not verify"):
                runner.run("fixture.service", 10, ("/usr/bin/true",))
        runner._stop.assert_called_once_with("fixture.service")

        process = Mock()
        process.poll.return_value = 0
        process.wait.return_value = 0
        runner = SystemdUserRunner()
        runner._show = Mock(return_value={"ControlGroup": "/user.slice/fixture.service", "MemoryHigh": "10"})  # type: ignore[method-assign]
        runner._stop = Mock()  # type: ignore[method-assign]
        with patch("linux_cache_guard.workloads.systemd_user.subprocess.Popen", return_value=process):
            with patch("linux_cache_guard.workloads.systemd_user.read_memory_high", side_effect=RuntimeError("unreadable")):
                with self.assertRaisesRegex(SystemdUserError, "did not verify"):
                    runner.run("fixture.service", 10, ("/usr/bin/true",))
        runner._stop.assert_called_once_with("fixture.service")


class WorkloadCliTests(unittest.TestCase):
    def test_run_arguments_do_not_replace_the_top_level_command(self) -> None:
        args = build_parser().parse_args(["workload", "run", "--profile", "coding", "--", "/usr/bin/true"])
        self.assertEqual(args.command, "workload")
        self.assertEqual(args.argv, ["--", "/usr/bin/true"])

    def test_status_accepts_json_after_subcommand_without_state_writes(self) -> None:
        output = StringIO()
        with TemporaryDirectory() as temporary:
            missing_system_config = Path(temporary) / "missing-system-workload.toml"
            with patch.dict("os.environ", {"XDG_CONFIG_HOME": temporary, "XDG_STATE_HOME": temporary}, clear=False), patch(
                "linux_cache_guard.workloads.config.SYSTEM_WORKLOAD_CONFIG_PATH", missing_system_config
            ):
                with redirect_stdout(output):
                    code = main(["workload", "status", "--json"])
            self.assertFalse((Path(temporary) / "linux-cache-guard" / "workloads").exists())
        self.assertEqual(code, 0)
        self.assertIn('"kind": "workload_status"', output.getvalue())

    def test_global_json_is_applied_to_workload_status(self) -> None:
        output = StringIO()
        with TemporaryDirectory() as temporary:
            missing_system_config = Path(temporary) / "missing-system-workload.toml"
            with patch.dict("os.environ", {"XDG_CONFIG_HOME": temporary, "XDG_STATE_HOME": temporary}, clear=False), patch(
                "linux_cache_guard.workloads.config.SYSTEM_WORKLOAD_CONFIG_PATH", missing_system_config
            ):
                with redirect_stdout(output):
                    code = main(["--json", "workload", "status"])
        self.assertEqual(code, 0)
        self.assertIn('"kind": "workload_status"', output.getvalue())

    def test_run_and_metrics_reject_json(self) -> None:
        with TemporaryDirectory() as temporary:
            missing_system_config = Path(temporary) / "missing-system-workload.toml"
            with patch.dict("os.environ", {"XDG_CONFIG_HOME": temporary, "XDG_STATE_HOME": temporary}, clear=False), patch(
                "linux_cache_guard.workloads.config.SYSTEM_WORKLOAD_CONFIG_PATH", missing_system_config
            ):
                self.assertEqual(main(["workload", "run", "--profile", "coding", "--json", "--", "/usr/bin/true"]), 2)
                self.assertEqual(main(["workload", "metrics", "--json"]), 2)

    def test_check_uses_documented_defer_exit_code(self) -> None:
        with TemporaryDirectory() as temporary:
            config_path = Path(temporary) / "workload.toml"
            config_path.write_text(
                """format_version = 1
[workload_guard]
enabled = true
mode = "admit"
min_host_available_bytes = 1
max_managed_workloads = 1
event_max_bytes = 65536
event_retention_days = 2
sample_interval_seconds = 60
[workload_guard.profiles.coding]
admission_bytes = 10
memory_high_bytes = 20
""",
                encoding="utf-8",
            )
            with patch("linux_cache_guard.workloads.runner.load_host_snapshot", return_value=host(available=1)):
                code = main(["workload", "--config", str(config_path), "check", "--profile", "coding"])
        self.assertEqual(code, 3)

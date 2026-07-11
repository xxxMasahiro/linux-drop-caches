from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import subprocess
import time
from collections.abc import Callable
from typing import Sequence
from uuid import uuid4

from .cgroup_v2 import read_memory_high


class SystemdUserError(RuntimeError):
    """A user-systemd scope could not be created or verified."""


@dataclass(frozen=True)
class ScopeResult:
    unit_name: str
    cgroup_path: str | None
    exit_code: int
    memory_high_verified: bool


class SystemdUserRunner:
    def __init__(self, *, systemd_run_path: str = "/usr/bin/systemd-run", systemctl_path: str = "/usr/bin/systemctl") -> None:
        self.systemd_run_path = systemd_run_path
        self.systemctl_path = systemctl_path

    def available(self) -> bool:
        return Path(self.systemd_run_path).is_file() and Path(self.systemctl_path).is_file()

    @staticmethod
    def unit_name(prefix: str = "linux-cache-guard-workload") -> str:
        return f"{prefix}-{uuid4().hex}.service"

    def unit_state(self, unit_name: str) -> str:
        result = subprocess.run(
            [self.systemctl_path, "--user", "is-active", "--quiet", unit_name],
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            return "active"
        if result.returncode == 3:
            return "inactive"
        if result.returncode == 4:
            return "missing"
        return "unknown"

    def _show(self, unit_name: str) -> dict[str, str]:
        result = subprocess.run(
            [
                self.systemctl_path,
                "--user",
                "show",
                unit_name,
                "--property=ControlGroup",
                "--property=MemoryHigh",
                "--property=LoadState",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            return {}
        properties: dict[str, str] = {}
        for line in result.stdout.splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                properties[key] = value
        return properties

    def _stop(self, unit_name: str) -> None:
        subprocess.run(
            [self.systemctl_path, "--user", "stop", unit_name],
            check=False,
            capture_output=True,
            text=True,
        )

    def _command(self, unit_name: str, memory_high_bytes: int, argv: Sequence[str], *, quiet: bool = False) -> list[str]:
        if not argv:
            raise SystemdUserError("workload command must not be empty")
        if not self.available():
            raise SystemdUserError("systemd-run or systemctl is unavailable")
        command = [
            self.systemd_run_path,
            "--user",
            "--wait",
            "--pipe",
            f"--unit={unit_name}",
            "--service-type=exec",
            f"--property=MemoryHigh={memory_high_bytes}",
            "--property=CollectMode=inactive-or-failed",
            "--",
            *argv,
        ]
        if quiet:
            command.insert(2, "--quiet")
        return command

    def run(
        self,
        unit_name: str,
        memory_high_bytes: int,
        argv: Sequence[str],
        *,
        on_started: Callable[[str | None], None] | None = None,
        quiet: bool = False,
    ) -> ScopeResult:
        process = subprocess.Popen(self._command(unit_name, memory_high_bytes, argv, quiet=quiet))
        cgroup_path: str | None = None
        verified = False
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            properties = self._show(unit_name)
            candidate = properties.get("ControlGroup")
            high = properties.get("MemoryHigh")
            if candidate and candidate != "/" and high == str(memory_high_bytes):
                cgroup_path = candidate
                try:
                    actual_high = read_memory_high(candidate)
                except (RuntimeError, ValueError):
                    actual_high = None
                if actual_high == memory_high_bytes:
                    verified = True
                    break
            if process.poll() is not None:
                break
            time.sleep(0.05)
        if not verified:
            self._stop(unit_name)
            process.wait()
            raise SystemdUserError("systemd did not verify the requested MemoryHigh property")
        if on_started is not None:
            try:
                on_started(cgroup_path)
            except BaseException:
                self._stop(unit_name)
                process.wait()
                raise
        exit_code = process.wait()
        return ScopeResult(
            unit_name=unit_name,
            cgroup_path=cgroup_path,
            exit_code=exit_code,
            memory_high_verified=True,
        )

    def verify_control(self, *, memory_high_bytes: int = 128 * 1024 * 1024) -> ScopeResult:
        sleep = "/usr/bin/sleep"
        if not Path(sleep).is_file():
            raise SystemdUserError("sleep is required for the explicit control verification")
        return self.run(self.unit_name("linux-cache-guard-verify"), memory_high_bytes, (sleep, "1"), quiet=True)

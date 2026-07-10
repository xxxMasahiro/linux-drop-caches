from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Mapping


GIB = 1024 * 1024 * 1024
MIB = 1024 * 1024
DEFAULT_HELPER_PATH = Path("/usr/local/sbin/linux-drop-caches")


def format_bytes(value: int) -> str:
    if value >= GIB:
        return f"{value / GIB:.2f} GiB"
    if value >= MIB:
        return f"{value / MIB:.1f} MiB"
    if value >= 1024:
        return f"{value / 1024:.1f} KiB"
    return f"{value} B"


@dataclass(frozen=True)
class MemorySnapshot:
    values: Mapping[str, int]
    source: str = "/proc/meminfo"

    def value(self, key: str) -> int:
        return int(self.values.get(key, 0))

    @property
    def total_bytes(self) -> int:
        return self.value("MemTotal")

    @property
    def available_bytes(self) -> int:
        return self.value("MemAvailable")

    @property
    def swap_used_bytes(self) -> int:
        return max(0, self.value("SwapTotal") - self.value("SwapFree"))

    @property
    def reclaimable_cache_bytes(self) -> int:
        # `Cached` is page cache; `KReclaimable` is reclaimable kernel cache.
        return self.value("Buffers") + self.value("Cached") + self.value("KReclaimable")

    def as_dict(self) -> dict[str, object]:
        return {
            "source": self.source,
            "values": dict(self.values),
            "total_bytes": self.total_bytes,
            "available_bytes": self.available_bytes,
            "swap_used_bytes": self.swap_used_bytes,
            "reclaimable_cache_bytes": self.reclaimable_cache_bytes,
            "human": {
                "total": format_bytes(self.total_bytes),
                "available": format_bytes(self.available_bytes),
                "swap_used": format_bytes(self.swap_used_bytes),
                "reclaimable_cache": format_bytes(self.reclaimable_cache_bytes),
            },
        }


@dataclass(frozen=True)
class HelperStatus:
    path: Path
    exists: bool
    ok: bool
    owner_uid: int | None = None
    mode: str | None = None
    reasons: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, object]:
        return {
            "path": str(self.path),
            "exists": self.exists,
            "ok": self.ok,
            "owner_uid": self.owner_uid,
            "mode": self.mode,
            "reasons": list(self.reasons),
        }


@dataclass(frozen=True)
class Policy:
    enabled: bool = True
    auto_cleanup: bool = False
    min_reclaimable_cache_bytes: int | None = None
    max_available_memory_bytes: int | None = None
    max_dirty_bytes: int = 64 * MIB
    require_writeback_zero: bool = True
    require_no_build_processes: bool = True
    cooldown_seconds: int = 3600
    min_cache_growth_bytes: int = 512 * MIB
    helper_path: Path = DEFAULT_HELPER_PATH
    state_dir: Path = Path("~/.local/state/linux-cache-guard")
    build_blockers: tuple[str, ...] = ("cargo", "rustc")

    def threshold_bytes(self, total_memory_bytes: int) -> int:
        if self.min_reclaimable_cache_bytes is not None:
            return self.min_reclaimable_cache_bytes
        return max(2 * GIB, int(total_memory_bytes * 0.35))

    def as_dict(self, *, total_memory_bytes: int) -> dict[str, object]:
        return {
            "enabled": self.enabled,
            "auto_cleanup": self.auto_cleanup,
            "min_reclaimable_cache_bytes": self.threshold_bytes(total_memory_bytes),
            "min_reclaimable_cache_human": format_bytes(self.threshold_bytes(total_memory_bytes)),
            "max_available_memory_bytes": self.max_available_memory_bytes,
            "max_available_memory_human": (
                format_bytes(self.max_available_memory_bytes)
                if self.max_available_memory_bytes is not None
                else None
            ),
            "max_dirty_bytes": self.max_dirty_bytes,
            "max_dirty_human": format_bytes(self.max_dirty_bytes),
            "require_writeback_zero": self.require_writeback_zero,
            "require_no_build_processes": self.require_no_build_processes,
            "cooldown_seconds": self.cooldown_seconds,
            "min_cache_growth_bytes": self.min_cache_growth_bytes,
            "min_cache_growth_human": format_bytes(self.min_cache_growth_bytes),
            "helper_path": str(self.helper_path),
            "state_dir": str(self.state_dir),
            "build_blockers": list(self.build_blockers),
        }


@dataclass(frozen=True)
class CleanupState:
    last_success_at: float | None = None
    last_success_cache_bytes: int | None = None

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class SafetyDecision:
    allowed: bool
    status: str
    reasons: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    threshold_bytes: int = 0
    active_build_processes: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, object]:
        return {
            "allowed": self.allowed,
            "status": self.status,
            "reasons": list(self.reasons),
            "warnings": list(self.warnings),
            "threshold_bytes": self.threshold_bytes,
            "threshold_human": format_bytes(self.threshold_bytes),
            "active_build_processes": list(self.active_build_processes),
        }


@dataclass(frozen=True)
class CleanupResult:
    action: str
    result: str
    executed: bool
    exit_code: int | None
    snapshot_before: MemorySnapshot
    snapshot_after: MemorySnapshot | None
    decision: SafetyDecision
    helper_status: HelperStatus
    errors: tuple[str, ...] = ()
    helper_stderr: str = ""
    receipt_path: Path | None = None

    def as_dict(self) -> dict[str, object]:
        estimated_delta_bytes = None
        if self.snapshot_after is not None:
            estimated_delta_bytes = max(
                0,
                self.snapshot_before.reclaimable_cache_bytes - self.snapshot_after.reclaimable_cache_bytes,
            )
        return {
            "action": self.action,
            "result": self.result,
            "executed": self.executed,
            "exit_code": self.exit_code,
            "snapshot_before": self.snapshot_before.as_dict(),
            "snapshot_after": self.snapshot_after.as_dict() if self.snapshot_after else None,
            "estimated_reclaimable_cache_delta_bytes": estimated_delta_bytes,
            "estimated_reclaimable_cache_delta_human": (
                format_bytes(estimated_delta_bytes) if estimated_delta_bytes is not None else None
            ),
            "decision": self.decision.as_dict(),
            "helper_status": self.helper_status.as_dict(),
            "errors": list(self.errors),
            "helper_stderr": self.helper_stderr,
            "receipt_path": str(self.receipt_path) if self.receipt_path else None,
        }

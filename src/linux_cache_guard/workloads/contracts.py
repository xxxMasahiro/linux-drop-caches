from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Mapping


WORKLOAD_SCHEMA_VERSION = 1

EXIT_ALLOW = 0
EXIT_INVALID = 2
EXIT_DEFER = 3
EXIT_DENY = 4
EXIT_UNSUPPORTED = 5
EXIT_INTERNAL = 70


@dataclass(frozen=True)
class Capability:
    name: str
    state: str
    reasons: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, object]:
        return {"name": self.name, "state": self.state, "reasons": list(self.reasons)}


@dataclass(frozen=True)
class CapabilityReport:
    capabilities: tuple[Capability, ...]

    def state_for(self, name: str) -> str:
        for capability in self.capabilities:
            if capability.name == name:
                return capability.state
        return "unavailable"

    def as_dict(self) -> dict[str, object]:
        return {"capabilities": [capability.as_dict() for capability in self.capabilities]}


@dataclass(frozen=True)
class PsiSample:
    some: Mapping[str, float] | None = None
    full: Mapping[str, float] | None = None
    source: str = "/proc/pressure/memory"
    reason: str | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "source": self.source,
            "some": dict(self.some) if self.some is not None else None,
            "full": dict(self.full) if self.full is not None else None,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class HostSnapshot:
    total_bytes: int | None
    available_bytes: int | None
    swap_used_bytes: int | None
    psi: PsiSample
    collected_at: str
    scope: str
    reason: str | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "total_bytes": self.total_bytes,
            "available_bytes": self.available_bytes,
            "swap_used_bytes": self.swap_used_bytes,
            "psi": self.psi.as_dict(),
            "collected_at": self.collected_at,
            "scope": self.scope,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class ManagedWorkload:
    workload_id: str
    profile: str
    unit_name: str
    cgroup_path: str | None
    admission_bytes: int
    created_at: str
    status: str = "starting"

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class CgroupSnapshot:
    cgroup_path: str
    current_bytes: int | None
    peak_bytes: int | None
    swap_current_bytes: int | None
    anon_bytes: int | None
    file_bytes: int | None
    slab_bytes: int | None
    pids_current: int | None
    populated: bool | None
    events: Mapping[str, int] = field(default_factory=dict)
    psi: PsiSample | None = None
    reason: str | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "cgroup_path": self.cgroup_path,
            "current_bytes": self.current_bytes,
            "peak_bytes": self.peak_bytes,
            "swap_current_bytes": self.swap_current_bytes,
            "anon_bytes": self.anon_bytes,
            "file_bytes": self.file_bytes,
            "slab_bytes": self.slab_bytes,
            "pids_current": self.pids_current,
            "populated": self.populated,
            "events": dict(self.events),
            "psi": self.psi.as_dict() if self.psi else None,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class WorkloadProfile:
    name: str
    admission_bytes: int
    memory_high_bytes: int

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class WorkloadPolicy:
    enabled: bool
    mode: str
    min_host_available_bytes: int
    max_managed_workloads: int
    event_max_bytes: int
    event_retention_days: int
    sample_interval_seconds: int
    profiles: Mapping[str, WorkloadProfile]
    state_dir: str

    def as_dict(self) -> dict[str, object]:
        return {
            "enabled": self.enabled,
            "mode": self.mode,
            "min_host_available_bytes": self.min_host_available_bytes,
            "max_managed_workloads": self.max_managed_workloads,
            "event_max_bytes": self.event_max_bytes,
            "event_retention_days": self.event_retention_days,
            "sample_interval_seconds": self.sample_interval_seconds,
            "profiles": {name: profile.as_dict() for name, profile in self.profiles.items()},
            "state_dir": self.state_dir,
        }


@dataclass(frozen=True)
class AdmissionDecision:
    status: str
    reasons: tuple[str, ...] = ()
    retry_after_seconds: int | None = None
    active_workload_count: int = 0
    reserved_bytes: int = 0

    @property
    def exit_code(self) -> int:
        return {
            "allow": EXIT_ALLOW,
            "defer": EXIT_DEFER,
            "deny": EXIT_DENY,
            "unsupported": EXIT_UNSUPPORTED,
        }.get(self.status, EXIT_INTERNAL)

    def as_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "reasons": list(self.reasons),
            "retry_after_seconds": self.retry_after_seconds,
            "active_workload_count": self.active_workload_count,
            "reserved_bytes": self.reserved_bytes,
        }


def envelope(kind: str, data: Mapping[str, object]) -> dict[str, object]:
    return {"schema_version": WORKLOAD_SCHEMA_VERSION, "kind": kind, "data": dict(data)}

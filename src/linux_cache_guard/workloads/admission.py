from __future__ import annotations

from collections.abc import Iterable

from .contracts import AdmissionDecision, HostSnapshot, ManagedWorkload, WorkloadPolicy


def _psi_full_avg10(snapshot: HostSnapshot) -> float | None:
    if snapshot.psi.full is None:
        return None
    value = snapshot.psi.full.get("avg10")
    return float(value) if value is not None else None


def evaluate_admission(
    policy: WorkloadPolicy,
    profile_name: str,
    host: HostSnapshot,
    managed_workloads: Iterable[ManagedWorkload],
) -> AdmissionDecision:
    active = tuple(managed_workloads)
    reserved_bytes = sum(workload.admission_bytes for workload in active)
    profile = policy.profiles.get(profile_name)
    if profile is None:
        return AdmissionDecision("deny", (f"unknown workload profile: {profile_name}",), active_workload_count=len(active), reserved_bytes=reserved_bytes)
    if not policy.enabled:
        return AdmissionDecision("deny", ("workload guard is disabled in configuration",), active_workload_count=len(active), reserved_bytes=reserved_bytes)
    if policy.mode != "admit":
        return AdmissionDecision("deny", ("workload guard mode is observe; admission is disabled",), active_workload_count=len(active), reserved_bytes=reserved_bytes)
    if host.total_bytes is None or host.available_bytes is None:
        return AdmissionDecision("unsupported", (host.reason or "host memory observation is unavailable",), active_workload_count=len(active), reserved_bytes=reserved_bytes)
    if len(active) >= policy.max_managed_workloads:
        return AdmissionDecision(
            "defer",
            (f"managed workload limit reached: {len(active)} of {policy.max_managed_workloads}",),
            retry_after_seconds=60,
            active_workload_count=len(active),
            reserved_bytes=reserved_bytes,
        )
    required_available = policy.min_host_available_bytes + profile.admission_bytes
    if host.available_bytes < required_available:
        return AdmissionDecision(
            "defer",
            (f"available memory is below the required reserve of {required_available} bytes",),
            retry_after_seconds=60,
            active_workload_count=len(active),
            reserved_bytes=reserved_bytes,
        )
    allocatable = max(0, host.total_bytes - policy.min_host_available_bytes)
    if reserved_bytes + profile.admission_bytes > allocatable:
        return AdmissionDecision(
            "defer",
            ("managed workload reservations would exceed the configured host budget",),
            retry_after_seconds=60,
            active_workload_count=len(active),
            reserved_bytes=reserved_bytes,
        )
    full_avg10 = _psi_full_avg10(host)
    if full_avg10 is not None and full_avg10 > 0.10:
        return AdmissionDecision(
            "defer",
            (f"memory PSI full avg10 is elevated ({full_avg10:.2f}%)",),
            retry_after_seconds=60,
            active_workload_count=len(active),
            reserved_bytes=reserved_bytes,
        )
    return AdmissionDecision("allow", active_workload_count=len(active), reserved_bytes=reserved_bytes)

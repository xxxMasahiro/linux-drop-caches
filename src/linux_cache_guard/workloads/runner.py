from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from typing import Sequence
from uuid import uuid4

from .admission import evaluate_admission
from .capabilities import detect_capabilities
from .cgroup_v2 import load_cgroup_snapshot
from .contracts import AdmissionDecision, ManagedWorkload, WorkloadPolicy, envelope
from .procfs import load_host_snapshot
from .state import (
    WorkloadStateError,
    append_event,
    load_events,
    load_monitor_state,
    load_workloads,
    save_monitor_state,
    save_workloads,
    workload_lock,
)
from .systemd_user import ScopeResult, SystemdUserError, SystemdUserRunner


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _event(kind: str, **data: object) -> dict[str, object]:
    return {
        **envelope(kind, data),
        "created_at": _now(),
    }


def _starting_record_is_fresh(workload: ManagedWorkload) -> bool:
    try:
        started_at = datetime.fromisoformat(workload.created_at.replace("Z", "+00:00"))
    except ValueError:
        return False
    return (datetime.now(UTC) - started_at).total_seconds() < 30


def _reconcile_locked(policy: WorkloadPolicy, adapter: SystemdUserRunner) -> tuple[ManagedWorkload, ...]:
    workloads = load_workloads(policy, strict=True)
    retained: list[ManagedWorkload] = []
    changed = False
    for workload in workloads:
        state = adapter.unit_state(workload.unit_name)
        if workload.status == "starting" and state in {"inactive", "missing"} and _starting_record_is_fresh(workload):
            retained.append(workload)
            continue
        if state in {"inactive", "missing"}:
            changed = True
            continue
        retained.append(workload)
    result = tuple(retained)
    if changed:
        save_workloads(policy, result)
    return result


def workload_status(policy: WorkloadPolicy) -> dict[str, object]:
    host = load_host_snapshot()
    capabilities = detect_capabilities()
    state_error: str | None = None
    try:
        workloads = load_workloads(policy, strict=True)
    except WorkloadStateError as exc:
        workloads = ()
        state_error = str(exc)
    observed: list[dict[str, object]] = []
    for workload in workloads:
        snapshot = load_cgroup_snapshot(workload.cgroup_path) if workload.cgroup_path else None
        observed.append(
            {
                "workload": workload.as_dict(),
                "cgroup": snapshot.as_dict() if snapshot else None,
            }
        )
    return {
        "host": host.as_dict(),
        "capabilities": capabilities.as_dict(),
        "workloads": observed,
        "state_error": state_error,
        "policy": policy.as_dict(),
    }


def workload_check(policy: WorkloadPolicy, profile_name: str) -> AdmissionDecision:
    try:
        workloads = load_workloads(policy, strict=True)
    except WorkloadStateError as exc:
        return AdmissionDecision("unsupported", (str(exc),))
    return evaluate_admission(policy, profile_name, load_host_snapshot(), workloads)


def _control_available() -> tuple[bool, tuple[str, ...]]:
    report = detect_capabilities()
    missing = [
        capability.name
        for capability in report.capabilities
        if capability.name in {"cgroup_memory", "systemd_user"} and capability.state != "ready"
    ]
    if missing:
        return False, ("workload control is unavailable: " + ", ".join(missing),)
    return True, ()


def verify_control(adapter: SystemdUserRunner) -> ScopeResult:
    available, reasons = _control_available()
    if not available:
        raise SystemdUserError("; ".join(reasons))
    return adapter.verify_control()


def workload_run(
    policy: WorkloadPolicy,
    profile_name: str,
    argv: Sequence[str],
    *,
    adapter: SystemdUserRunner | None = None,
) -> tuple[AdmissionDecision, ScopeResult | None]:
    if not argv:
        return AdmissionDecision("deny", ("workload command must not be empty",)), None
    adapter = adapter or SystemdUserRunner()
    available, reasons = _control_available()
    if not available:
        return AdmissionDecision("unsupported", reasons), None
    workload_id = uuid4().hex
    unit_name = adapter.unit_name()
    profile = policy.profiles.get(profile_name)
    if profile is None:
        return AdmissionDecision("deny", (f"unknown workload profile: {profile_name}",)), None
    with workload_lock(policy):
        workloads = _reconcile_locked(policy, adapter)
        decision = evaluate_admission(policy, profile_name, load_host_snapshot(), workloads)
        if decision.status != "allow":
            append_event(policy, _event("workload_admission", profile=profile_name, decision=decision.as_dict()))
            return decision, None
        reservation = ManagedWorkload(
            workload_id=workload_id,
            profile=profile_name,
            unit_name=unit_name,
            cgroup_path=None,
            admission_bytes=profile.admission_bytes,
            created_at=_now(),
        )
        save_workloads(policy, (*workloads, reservation))
        append_event(policy, _event("workload_reserved", workload=reservation.as_dict()))

    def started(cgroup_path: str | None) -> None:
        with workload_lock(policy):
            workloads = load_workloads(policy, strict=True)
            updated = tuple(
                replace(item, cgroup_path=cgroup_path, status="running") if item.workload_id == workload_id else item
                for item in workloads
            )
            save_workloads(policy, updated)
            append_event(
                policy,
                _event(
                    "workload_started",
                    workload_id=workload_id,
                    profile=profile_name,
                    unit_name=unit_name,
                    cgroup_path=cgroup_path,
                ),
            )

    try:
        result = adapter.run(unit_name, profile.memory_high_bytes, argv, on_started=started)
    except (OSError, SystemdUserError, WorkloadStateError) as exc:
        try:
            with workload_lock(policy):
                workloads = load_workloads(policy, strict=True)
                save_workloads(policy, tuple(item for item in workloads if item.workload_id != workload_id))
                append_event(policy, _event("workload_start_failed", workload_id=workload_id, profile=profile_name, error=str(exc)))
        except WorkloadStateError as state_exc:
            return AdmissionDecision(
                "unsupported",
                (f"managed workload failed and state was left unchanged: {state_exc}",),
            ), None
        return AdmissionDecision("unsupported", (f"managed workload could not start: {exc}",)), None
    with workload_lock(policy):
        workloads = load_workloads(policy, strict=True)
        save_workloads(policy, tuple(item for item in workloads if item.workload_id != workload_id))
        append_event(
            policy,
            _event(
                "workload_finished",
                workload_id=workload_id,
                profile=profile_name,
                unit_name=result.unit_name,
                cgroup_path=result.cgroup_path,
                exit_code=result.exit_code,
                memory_high_verified=result.memory_high_verified,
            ),
        )
    return AdmissionDecision("allow"), result


def workload_history(policy: WorkloadPolicy, *, limit: int) -> tuple[dict[str, object], ...]:
    return load_events(policy, limit=limit)


def workload_monitor(policy: WorkloadPolicy) -> dict[str, object]:
    if not policy.enabled:
        return {"level": "disabled"}
    status = workload_status(policy)
    host = status["host"]
    assert isinstance(host, dict)
    available = host.get("available_bytes")
    psi = host.get("psi")
    full_avg10 = None
    if isinstance(psi, dict) and isinstance(psi.get("full"), dict):
        full_avg10 = psi["full"].get("avg10")
    level = "pressure" if isinstance(available, int) and available < policy.min_host_available_bytes else "healthy"
    if isinstance(full_avg10, (int, float)) and full_avg10 > 0.10:
        level = "pressure"
    with workload_lock(policy):
        previous = load_monitor_state(policy)
        if previous is not None and isinstance(previous.get("sampled_at"), str):
            try:
                previous_time = datetime.fromisoformat(previous["sampled_at"].replace("Z", "+00:00"))
            except ValueError:
                previous_time = None
            if previous_time is not None:
                elapsed = (datetime.now(UTC) - previous_time).total_seconds()
                if elapsed < policy.sample_interval_seconds:
                    return {"level": "skipped", "host": host}
        if previous is None or previous.get("level") != level:
            append_event(policy, _event("workload_observation_changed", level=level, host=host))
        save_monitor_state(policy, {"level": level, "host": host, "sampled_at": _now()})
    return {"level": level, "host": host}

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import replace
import fcntl
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
from typing import Callable

from .models import CleanupResult, CleanupState, HelperStatus, MemorySnapshot, Policy, SafetyDecision
from .system import check_helper, load_meminfo, process_names


class StateError(RuntimeError):
    """The local receipt/state store cannot safely enforce cleanup policy."""


SUDO_PATH = "/usr/bin/sudo"


def state_file(policy: Policy) -> Path:
    return policy.state_dir / "cleanup-state.json"


def receipts_file(policy: Policy) -> Path:
    return policy.state_dir / "cleanup-receipts.jsonl"


def latest_receipt_file(policy: Policy) -> Path:
    return policy.state_dir / "latest-cleanup-receipt.json"


def pending_file(policy: Policy) -> Path:
    return policy.state_dir / "cleanup-pending.json"


def load_state(policy: Policy, *, strict: bool = False) -> CleanupState:
    if strict and pending_file(policy).exists():
        raise StateError("a previous cleanup did not record durable completion")
    path = state_file(policy)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return CleanupState()
    except (OSError, json.JSONDecodeError) as exc:
        if strict:
            raise StateError(f"cleanup state is unreadable: {exc}") from exc
        return CleanupState()
    last_success_at = payload.get("last_success_at")
    last_success_cache_bytes = payload.get("last_success_cache_bytes")
    if not isinstance(last_success_at, (int, float)):
        last_success_at = None
    if not isinstance(last_success_cache_bytes, int) or last_success_cache_bytes < 0:
        last_success_cache_bytes = None
    return CleanupState(last_success_at=last_success_at, last_success_cache_bytes=last_success_cache_bytes)


def save_state(policy: Policy, state: CleanupState) -> None:
    _ensure_state_dir(policy)
    _atomic_json_write(state_file(policy), state.as_dict())


def _mark_pending(policy: Policy, snapshot: MemorySnapshot) -> None:
    _atomic_json_write(
        pending_file(policy),
        {
            "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "reclaimable_cache_bytes_before": snapshot.reclaimable_cache_bytes,
        },
    )


def _clear_pending(policy: Policy) -> None:
    pending_file(policy).unlink(missing_ok=True)
    _fsync_directory(policy.state_dir)


def _atomic_json_write(path: Path, payload: dict[str, object]) -> None:
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, sort_keys=True, indent=2) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
        _fsync_directory(path.parent)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _ensure_state_dir(policy: Policy) -> None:
    policy.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    metadata = policy.state_dir.lstat()
    if not policy.state_dir.is_dir() or policy.state_dir.is_symlink():
        raise StateError(f"state path is not a directory: {policy.state_dir}")
    if metadata.st_mode & 0o022:
        raise StateError(f"state directory is writable by another user: {policy.state_dir}")


@contextmanager
def _cleanup_lock(policy: Policy):
    _ensure_state_dir(policy)
    lock_path = policy.state_dir / "cleanup.lock"
    descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def evaluate_cleanup(
    snapshot: MemorySnapshot,
    policy: Policy,
    helper: HelperStatus,
    state: CleanupState,
    active_processes: tuple[str, ...],
    *,
    now: float | None = None,
) -> SafetyDecision:
    now = time.time() if now is None else now
    threshold = policy.threshold_bytes(snapshot.total_bytes)
    reasons: list[str] = []
    warnings: list[str] = []
    active_builds = tuple(name for name in active_processes if name in policy.build_blockers)

    if not policy.enabled:
        reasons.append("cleanup is disabled in configuration")
    if snapshot.reclaimable_cache_bytes < threshold:
        reasons.append("reclaimable cache is below the cleanup threshold")
    if snapshot.value("Dirty") > policy.max_dirty_bytes:
        reasons.append("dirty memory exceeds the configured safety limit")
    if policy.require_writeback_zero and snapshot.value("Writeback") != 0:
        reasons.append("writeback is active")
    if policy.require_no_build_processes and active_builds:
        reasons.append("active build process detected: " + ", ".join(active_builds))
    if not helper.ok:
        reasons.extend(helper.reasons)
    if state.last_success_at is not None and now - state.last_success_at < policy.cooldown_seconds:
        remaining = int(policy.cooldown_seconds - (now - state.last_success_at))
        reasons.append(f"cleanup cooldown is active for another {remaining} seconds")
    if state.last_success_cache_bytes is not None:
        growth = snapshot.reclaimable_cache_bytes - state.last_success_cache_bytes
        if growth < policy.min_cache_growth_bytes:
            reasons.append("reclaimable cache has not grown enough since the last cleanup")
    if snapshot.swap_used_bytes:
        warnings.append("Swap is in use; dropping cache may not reduce application memory")
    if snapshot.available_bytes < snapshot.total_bytes // 10:
        warnings.append("available memory is below 10%; investigate application memory as well")

    if reasons:
        if any("dirty" in reason or "writeback" in reason or "active build" in reason for reason in reasons):
            status = "blocked"
        elif not helper.ok:
            status = "unavailable"
        else:
            status = "not_needed"
        return SafetyDecision(
            allowed=False,
            status=status,
            reasons=tuple(reasons),
            warnings=tuple(warnings),
            threshold_bytes=threshold,
            active_build_processes=active_builds,
        )
    return SafetyDecision(
        allowed=True,
        status="cleanup_recommended",
        warnings=tuple(warnings),
        threshold_bytes=threshold,
        active_build_processes=active_builds,
    )


def apply_automatic_policy(
    decision: SafetyDecision,
    snapshot: MemorySnapshot,
    policy: Policy,
) -> SafetyDecision:
    if not policy.auto_cleanup:
        return SafetyDecision(
            allowed=False,
            status="not_needed",
            reasons=("automatic cleanup is disabled in configuration",),
            warnings=decision.warnings,
            threshold_bytes=decision.threshold_bytes,
            active_build_processes=decision.active_build_processes,
        )
    if policy.max_available_memory_bytes is None:
        return SafetyDecision(
            allowed=False,
            status="not_needed",
            reasons=("automatic cleanup requires max_available_memory_bytes",),
            warnings=decision.warnings,
            threshold_bytes=decision.threshold_bytes,
            active_build_processes=decision.active_build_processes,
        )
    if snapshot.available_bytes > policy.max_available_memory_bytes:
        return SafetyDecision(
            allowed=False,
            status="not_needed",
            reasons=("available memory is above the automatic pressure limit",),
            warnings=decision.warnings,
            threshold_bytes=decision.threshold_bytes,
            active_build_processes=decision.active_build_processes,
        )
    return decision


def inspect(policy: Policy, *, automatic: bool = False) -> tuple[MemorySnapshot, HelperStatus, CleanupState, SafetyDecision]:
    snapshot = load_meminfo()
    helper = check_helper(policy.helper_path)
    state = load_state(policy)
    decision = evaluate_cleanup(snapshot, policy, helper, state, process_names())
    if pending_file(policy).exists():
        decision = SafetyDecision(
            allowed=False,
            status="unavailable",
            reasons=("a previous cleanup requires explicit recovery",),
            warnings=decision.warnings,
            threshold_bytes=decision.threshold_bytes,
            active_build_processes=decision.active_build_processes,
        )
    elif automatic:
        decision = apply_automatic_policy(decision, snapshot, policy)
    return snapshot, helper, state, decision


def _run_helper(path: Path, *, automatic: bool) -> subprocess.CompletedProcess[str]:
    if os.geteuid() == 0:
        command = [str(path)]
    elif automatic:
        command = [SUDO_PATH, "-n", str(path)]
    else:
        command = [SUDO_PATH, str(path)]
    return subprocess.run(command, check=False, capture_output=True, text=True)


def _write_receipt(policy: Policy, result: CleanupResult) -> CleanupResult:
    _ensure_state_dir(policy)
    receipt_path = receipts_file(policy)
    finalized = replace(result, receipt_path=receipt_path)
    payload = finalized.as_dict()
    payload["created_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    _append_receipt_payload(policy, payload)
    _atomic_json_write(latest_receipt_file(policy), payload)
    return finalized


def _append_receipt_payload(policy: Policy, payload: dict[str, object]) -> None:
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    receipt_path = receipts_file(policy)
    descriptor = os.open(receipt_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(descriptor, "a", encoding="utf-8") as handle:
        handle.write(serialized + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def recover_pending(policy: Policy, *, confirmed: bool) -> dict[str, object]:
    try:
        with _cleanup_lock(policy):
            path = pending_file(policy)
            if not path.exists():
                return {"status": "no_pending_cleanup", "recovered": False}
            if not confirmed:
                return {
                    "status": "confirmation_required",
                    "recovered": False,
                    "pending_path": str(path),
                }
            payload: dict[str, object] = {
                "receipt_type": "pending_cleanup_recovery",
                "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "pending_path": str(path),
                "action": "operator_acknowledged_pending_cleanup",
            }
            _append_receipt_payload(policy, payload)
            _clear_pending(policy)
            return {"status": "recovered", "recovered": True, "receipt_path": str(receipts_file(policy))}
    except (OSError, StateError) as exc:
        return {"status": "unavailable", "recovered": False, "error": str(exc)}


def load_history(policy: Policy, *, limit: int) -> tuple[dict[str, object], ...]:
    if limit < 1:
        raise ValueError("history limit must be at least 1")
    try:
        lines = receipts_file(policy).read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return ()
    except OSError as exc:
        raise StateError(f"cannot read receipt history: {exc}") from exc
    entries: list[dict[str, object]] = []
    for line in lines:
        try:
            entry = json.loads(line)
        except json.JSONDecodeError as exc:
            raise StateError(f"receipt history is corrupt: {exc}") from exc
        if not isinstance(entry, dict):
            raise StateError("receipt history contains a non-object entry")
        entries.append(entry)
    return tuple(entries[-limit:])


def cleanup(
    policy: Policy,
    *,
    dry_run: bool,
    automatic: bool,
    runner: Callable[[Path, bool], subprocess.CompletedProcess[str]] | None = None,
    snapshot_loader: Callable[[], MemorySnapshot] = load_meminfo,
    process_loader: Callable[[], tuple[str, ...]] = process_names,
    helper_loader: Callable[[Path], HelperStatus] = check_helper,
) -> CleanupResult:
    snapshot_before = snapshot_loader()
    helper = helper_loader(policy.helper_path)
    try:
        with _cleanup_lock(policy):
            return _cleanup_locked(
                policy,
                snapshot_before=snapshot_before,
                helper=helper,
                dry_run=dry_run,
                automatic=automatic,
                runner=runner,
                snapshot_loader=snapshot_loader,
                process_loader=process_loader,
            )
    except (OSError, StateError) as exc:
        decision = SafetyDecision(
            allowed=False,
            status="unavailable",
            reasons=(f"cleanup state store is unavailable: {exc}",),
            threshold_bytes=policy.threshold_bytes(snapshot_before.total_bytes),
        )
        return CleanupResult(
            action="automatic" if automatic else "interactive",
            result="skipped",
            executed=False,
            exit_code=None,
            snapshot_before=snapshot_before,
            snapshot_after=None,
            decision=decision,
            helper_status=helper,
            errors=("no helper was executed because the state store was unavailable",),
        )


def _cleanup_locked(
    policy: Policy,
    *,
    snapshot_before: MemorySnapshot,
    helper: HelperStatus,
    dry_run: bool,
    automatic: bool,
    runner: Callable[[Path, bool], subprocess.CompletedProcess[str]] | None,
    snapshot_loader: Callable[[], MemorySnapshot],
    process_loader: Callable[[], tuple[str, ...]],
) -> CleanupResult:
    decision = evaluate_cleanup(snapshot_before, policy, helper, load_state(policy, strict=True), process_loader())

    if automatic:
        decision = apply_automatic_policy(decision, snapshot_before, policy)
    if not decision.allowed:
        result = CleanupResult(
            action="automatic" if automatic else "interactive",
            result="skipped",
            executed=False,
            exit_code=None,
            snapshot_before=snapshot_before,
            snapshot_after=None,
            decision=decision,
            helper_status=helper,
        )
        return _write_receipt(policy, result)
    if dry_run:
        result = CleanupResult(
            action="automatic" if automatic else "interactive",
            result="would_run",
            executed=False,
            exit_code=None,
            snapshot_before=snapshot_before,
            snapshot_after=None,
            decision=decision,
            helper_status=helper,
        )
        return _write_receipt(policy, result)

    _mark_pending(policy, snapshot_before)
    completed = (runner or (lambda path, automatic: _run_helper(path, automatic=automatic)))(
        policy.helper_path,
        automatic,
    )
    snapshot_after = snapshot_loader()
    errors: tuple[str, ...] = ()
    if completed.returncode != 0:
        errors = ("root helper returned a non-zero exit code",)
    result = CleanupResult(
        action="automatic" if automatic else "interactive",
        result="completed" if completed.returncode == 0 else "failed",
        executed=completed.returncode == 0,
        exit_code=completed.returncode,
        snapshot_before=snapshot_before,
        snapshot_after=snapshot_after,
        decision=decision,
        helper_status=helper,
        errors=errors,
        helper_stderr=completed.stderr.strip(),
    )
    if not result.executed:
        return _write_receipt(policy, result)
    try:
        save_state(
            policy,
            CleanupState(
                last_success_at=time.time(),
                last_success_cache_bytes=snapshot_after.reclaimable_cache_bytes,
            ),
        )
        _clear_pending(policy)
    except (OSError, StateError) as exc:
        return replace(
            result,
            result="completed_with_recording_error",
            errors=(f"helper completed but state recording failed: {exc}",),
        )
    try:
        return _write_receipt(policy, result)
    except (OSError, StateError) as exc:
        return replace(
            result,
            result="completed_with_recording_error",
            errors=(f"helper completed but receipt recording failed: {exc}",),
        )

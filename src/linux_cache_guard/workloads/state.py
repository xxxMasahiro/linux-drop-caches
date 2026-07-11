from __future__ import annotations

from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
import fcntl
import json
import os
from pathlib import Path
import stat
import tempfile
from typing import Iterator

from .contracts import ManagedWorkload, WorkloadPolicy


class WorkloadStateError(RuntimeError):
    """The workload state store cannot safely coordinate managed launches."""


STATE_SCHEMA_VERSION = 1


def state_directory(policy: WorkloadPolicy) -> Path:
    return Path(policy.state_dir).expanduser()


def state_file(policy: WorkloadPolicy) -> Path:
    return state_directory(policy) / "workload-state.json"


def monitor_file(policy: WorkloadPolicy) -> Path:
    return state_directory(policy) / "workload-monitor.json"


def event_file(policy: WorkloadPolicy) -> Path:
    return state_directory(policy) / "workload-events.jsonl"


def _validate_owned_path(path: Path, *, directory: bool | None = None) -> None:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode):
        raise WorkloadStateError(f"state path must not be a symbolic link: {path}")
    if directory is True and not stat.S_ISDIR(metadata.st_mode):
        raise WorkloadStateError(f"state path must be a directory: {path}")
    if directory is False and not stat.S_ISREG(metadata.st_mode):
        raise WorkloadStateError(f"state path must be a regular file: {path}")
    if metadata.st_uid != os.geteuid():
        raise WorkloadStateError(f"state path is not owned by the current user: {path}")
    if metadata.st_mode & 0o022:
        raise WorkloadStateError(f"state path is writable by another user: {path}")


def _validate_state_parents(path: Path) -> None:
    current = path.parent
    while True:
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise WorkloadStateError(f"cannot inspect state parent {current}: {exc}") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise WorkloadStateError(f"state parent must not be a symbolic link: {current}")
        if current == current.parent:
            return
        writable_by_others = metadata.st_mode & 0o022
        sticky = metadata.st_mode & stat.S_ISVTX
        if metadata.st_uid not in {0, os.geteuid()} and not sticky:
            raise WorkloadStateError(f"state parent has an unexpected owner: {current}")
        if writable_by_others and not sticky:
            raise WorkloadStateError(f"state parent is writable by another user: {current}")
        current = current.parent


def ensure_state_directory(policy: WorkloadPolicy) -> Path:
    directory = state_directory(policy)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        os.chmod(directory, 0o700)
    except OSError as exc:
        raise WorkloadStateError(f"cannot secure workload state directory {directory}: {exc}") from exc
    _validate_owned_path(directory, directory=True)
    _validate_state_parents(directory)
    return directory


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


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


@contextmanager
def workload_lock(policy: WorkloadPolicy) -> Iterator[None]:
    directory = ensure_state_directory(policy)
    lock_path = directory / "workload.lock"
    try:
        descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except OSError as exc:
        raise WorkloadStateError(f"cannot open workload lock safely: {exc}") from exc
    try:
        os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _parse_workload(raw: object) -> ManagedWorkload:
    if not isinstance(raw, dict):
        raise WorkloadStateError("workload state contains a non-object entry")
    required_strings = ("workload_id", "profile", "unit_name", "created_at", "status")
    if any(not isinstance(raw.get(name), str) for name in required_strings):
        raise WorkloadStateError("workload state contains an invalid workload entry")
    cgroup_path = raw.get("cgroup_path")
    admission_bytes = raw.get("admission_bytes")
    if cgroup_path is not None and not isinstance(cgroup_path, str):
        raise WorkloadStateError("workload state contains an invalid cgroup path")
    if not isinstance(admission_bytes, int) or isinstance(admission_bytes, bool) or admission_bytes <= 0:
        raise WorkloadStateError("workload state contains an invalid admission byte count")
    return ManagedWorkload(
        workload_id=raw["workload_id"],
        profile=raw["profile"],
        unit_name=raw["unit_name"],
        cgroup_path=cgroup_path,
        admission_bytes=admission_bytes,
        created_at=raw["created_at"],
        status=raw["status"],
    )


def load_workloads(policy: WorkloadPolicy, *, strict: bool = False) -> tuple[ManagedWorkload, ...]:
    path = state_file(policy)
    try:
        _validate_owned_path(path, directory=False)
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return ()
    except (OSError, json.JSONDecodeError, WorkloadStateError) as exc:
        if strict:
            raise WorkloadStateError(f"workload state is unreadable: {exc}") from exc
        return ()
    if not isinstance(payload, dict) or payload.get("schema_version") != STATE_SCHEMA_VERSION:
        if strict:
            raise WorkloadStateError("workload state schema is unsupported")
        return ()
    raw_workloads = payload.get("workloads")
    if not isinstance(raw_workloads, list):
        if strict:
            raise WorkloadStateError("workload state has no workloads list")
        return ()
    try:
        return tuple(_parse_workload(item) for item in raw_workloads)
    except WorkloadStateError:
        if strict:
            raise
        return ()


def save_workloads(policy: WorkloadPolicy, workloads: tuple[ManagedWorkload, ...]) -> None:
    directory = ensure_state_directory(policy)
    _atomic_json_write(
        directory / "workload-state.json",
        {"schema_version": STATE_SCHEMA_VERSION, "workloads": [workload.as_dict() for workload in workloads]},
    )


def save_monitor_state(policy: WorkloadPolicy, payload: dict[str, object]) -> None:
    directory = ensure_state_directory(policy)
    _atomic_json_write(directory / "workload-monitor.json", {"schema_version": STATE_SCHEMA_VERSION, **payload})


def load_monitor_state(policy: WorkloadPolicy) -> dict[str, object] | None:
    path = monitor_file(policy)
    try:
        _validate_owned_path(path, directory=False)
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError, WorkloadStateError):
        return None
    if not isinstance(payload, dict) or payload.get("schema_version") != STATE_SCHEMA_VERSION:
        return None
    return payload


def _event_paths(policy: WorkloadPolicy) -> list[Path]:
    directory = state_directory(policy)
    paths = [event_file(policy)]
    paths.extend(sorted(directory.glob("workload-events.*.jsonl"), reverse=True))
    return paths


def _prune_rotated_events(policy: WorkloadPolicy, *, now: datetime) -> None:
    cutoff = now - timedelta(days=policy.event_retention_days)
    for path in state_directory(policy).glob("workload-events.*.jsonl"):
        try:
            _validate_owned_path(path, directory=False)
            modified = datetime.fromtimestamp(path.stat().st_mtime, tz=UTC)
        except (OSError, WorkloadStateError):
            continue
        if modified < cutoff:
            path.unlink(missing_ok=True)


def append_event(policy: WorkloadPolicy, event: dict[str, object]) -> None:
    directory = ensure_state_directory(policy)
    path = event_file(policy)
    now = datetime.now(UTC)
    encoded = (json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    if len(encoded) > policy.event_max_bytes:
        raise WorkloadStateError("workload event exceeds the configured event size limit")
    if path.exists():
        _validate_owned_path(path, directory=False)
        if path.stat().st_size + len(encoded) > policy.event_max_bytes:
            stem = f"workload-events.{now.strftime('%Y%m%dT%H%M%SZ')}"
            rotated = directory / f"{stem}.jsonl"
            suffix = 1
            while rotated.exists():
                rotated = directory / f"{stem}.{suffix}.jsonl"
                suffix += 1
            path.replace(rotated)
            _fsync_directory(directory)
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
    except OSError as exc:
        raise WorkloadStateError(f"cannot append workload event safely: {exc}") from exc
    try:
        os.fchmod(descriptor, 0o600)
        os.write(descriptor, encoded)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _prune_rotated_events(policy, now=now)
    _fsync_directory(directory)


def load_events(policy: WorkloadPolicy, *, limit: int) -> tuple[dict[str, object], ...]:
    if limit < 1:
        raise ValueError("history limit must be at least 1")
    events: list[dict[str, object]] = []
    cutoff = datetime.now(UTC) - timedelta(days=policy.event_retention_days)
    for path in _event_paths(policy):
        if len(events) >= limit:
            break
        try:
            _validate_owned_path(path, directory=False)
            data = path.read_bytes()[-policy.event_max_bytes :]
        except (FileNotFoundError, OSError, WorkloadStateError):
            continue
        lines = data.decode("utf-8", errors="replace").splitlines()
        if data and not data.startswith(b"{") and lines:
            lines = lines[1:]
        for line in reversed(lines):
            if len(events) >= limit:
                break
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(item, dict):
                continue
            created_at = item.get("created_at")
            if isinstance(created_at, str):
                try:
                    if datetime.fromisoformat(created_at.replace("Z", "+00:00")) < cutoff:
                        continue
                except ValueError:
                    continue
            events.append(item)
    return tuple(events)

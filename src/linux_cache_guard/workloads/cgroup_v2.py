from __future__ import annotations

from pathlib import Path, PurePosixPath

from .contracts import CgroupSnapshot
from .procfs import load_psi


def _relative_cgroup_path(value: str) -> PurePosixPath:
    path = PurePosixPath(value.lstrip("/"))
    if not path.parts or path == PurePosixPath(".") or ".." in path.parts:
        raise ValueError("cgroup path must be a non-root relative path")
    return path


def _read_int(path: Path) -> int | None:
    try:
        raw_value = path.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if raw_value == "max":
        return None
    try:
        return int(raw_value)
    except ValueError:
        return None


def _read_key_values(path: Path) -> dict[str, int]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return {}
    values: dict[str, int] = {}
    for line in lines:
        fields = line.split()
        if len(fields) != 2:
            continue
        try:
            values[fields[0]] = int(fields[1])
        except ValueError:
            continue
    return values


def load_cgroup_snapshot(cgroup_path: str, *, root: Path = Path("/sys/fs/cgroup")) -> CgroupSnapshot:
    try:
        relative = _relative_cgroup_path(cgroup_path)
    except ValueError as exc:
        return CgroupSnapshot(
            cgroup_path=cgroup_path,
            current_bytes=None,
            peak_bytes=None,
            swap_current_bytes=None,
            anon_bytes=None,
            file_bytes=None,
            slab_bytes=None,
            pids_current=None,
            populated=None,
            reason=str(exc),
        )
    directory = root.joinpath(*relative.parts)
    if not directory.is_dir():
        return CgroupSnapshot(
            cgroup_path=cgroup_path,
            current_bytes=None,
            peak_bytes=None,
            swap_current_bytes=None,
            anon_bytes=None,
            file_bytes=None,
            slab_bytes=None,
            pids_current=None,
            populated=None,
            reason="managed cgroup no longer exists",
        )
    memory_stat = _read_key_values(directory / "memory.stat")
    events = _read_key_values(directory / "memory.events")
    cgroup_events = _read_key_values(directory / "cgroup.events")
    return CgroupSnapshot(
        cgroup_path=cgroup_path,
        current_bytes=_read_int(directory / "memory.current"),
        peak_bytes=_read_int(directory / "memory.peak"),
        swap_current_bytes=_read_int(directory / "memory.swap.current"),
        anon_bytes=memory_stat.get("anon"),
        file_bytes=memory_stat.get("file"),
        slab_bytes=memory_stat.get("slab"),
        pids_current=_read_int(directory / "pids.current"),
        populated=bool(cgroup_events["populated"]) if "populated" in cgroup_events else None,
        events=events,
        psi=load_psi(directory / "memory.pressure"),
    )


def read_memory_high(cgroup_path: str, *, root: Path = Path("/sys/fs/cgroup")) -> int:
    relative = _relative_cgroup_path(cgroup_path)
    path = root.joinpath(*relative.parts) / "memory.high"
    try:
        raw_value = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise RuntimeError(f"cannot read cgroup MemoryHigh: {exc}") from exc
    if raw_value == "max":
        raise RuntimeError("cgroup MemoryHigh is unlimited")
    try:
        return int(raw_value)
    except ValueError as exc:
        raise RuntimeError("cgroup MemoryHigh is invalid") from exc

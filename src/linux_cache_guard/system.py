from __future__ import annotations

from pathlib import Path
import stat

from .models import HelperStatus, MemorySnapshot


MEMINFO_KEYS = (
    "MemTotal",
    "MemAvailable",
    "Buffers",
    "Cached",
    "Dirty",
    "Writeback",
    "KReclaimable",
    "SwapTotal",
    "SwapFree",
)


def parse_meminfo(text: str, *, source: str = "/proc/meminfo") -> MemorySnapshot:
    values: dict[str, int] = {key: 0 for key in MEMINFO_KEYS}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, raw_value = line.split(":", 1)
        if key not in values:
            continue
        fields = raw_value.split()
        if not fields:
            continue
        try:
            value = int(fields[0])
        except ValueError:
            continue
        values[key] = value * 1024 if len(fields) > 1 and fields[1].lower() == "kb" else value
    return MemorySnapshot(values=values, source=source)


def load_meminfo(path: Path = Path("/proc/meminfo")) -> MemorySnapshot:
    text = path.read_text(encoding="utf-8")
    required_keys = ("MemTotal", "MemAvailable", "Cached", "Dirty", "Writeback", "KReclaimable")
    missing = tuple(key for key in required_keys if f"{key}:" not in text)
    if missing:
        raise RuntimeError("missing required /proc/meminfo fields: " + ", ".join(missing))
    return parse_meminfo(text, source=str(path))


def process_names(proc_path: Path = Path("/proc")) -> tuple[str, ...]:
    if not proc_path.is_dir():
        return ()
    names: set[str] = set()
    for entry in proc_path.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            name = (entry / "comm").read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if name:
            names.add(Path(name).name)
    return tuple(sorted(names))


def check_helper(path: Path) -> HelperStatus:
    expanded = path.expanduser()
    try:
        metadata = expanded.lstat()
    except OSError as exc:
        return HelperStatus(path=expanded, exists=False, ok=False, reasons=(f"helper unavailable: {exc}",))

    reasons: list[str] = []
    if expanded.is_symlink():
        reasons.append("helper must not be a symbolic link")
    if not stat.S_ISREG(metadata.st_mode):
        reasons.append("helper is not a regular file")
    if metadata.st_uid != 0:
        reasons.append("helper is not root-owned")
    if metadata.st_mode & stat.S_IWGRP:
        reasons.append("helper is group-writable")
    if metadata.st_mode & stat.S_IWOTH:
        reasons.append("helper is world-writable")
    if not metadata.st_mode & stat.S_IXUSR:
        reasons.append("helper is not executable")
    parent = expanded.parent
    while True:
        try:
            parent_metadata = parent.lstat()
        except OSError as exc:
            reasons.append(f"cannot inspect helper parent {parent}: {exc}")
            break
        if stat.S_ISLNK(parent_metadata.st_mode):
            reasons.append(f"helper parent is a symbolic link: {parent}")
            break
        if parent_metadata.st_uid != 0:
            reasons.append(f"helper parent is not root-owned: {parent}")
        if parent_metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            reasons.append(f"helper parent is writable by a non-root user: {parent}")
        if parent == parent.parent:
            break
        parent = parent.parent
    return HelperStatus(
        path=expanded,
        exists=True,
        ok=not reasons,
        owner_uid=metadata.st_uid,
        mode=oct(stat.S_IMODE(metadata.st_mode)),
        reasons=tuple(reasons),
    )

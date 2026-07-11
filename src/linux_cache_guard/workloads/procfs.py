from __future__ import annotations

from datetime import UTC, datetime
import os
from pathlib import Path

from ..system import load_meminfo
from .contracts import HostSnapshot, PsiSample


def parse_psi(text: str, *, source: str) -> PsiSample:
    samples: dict[str, dict[str, float]] = {}
    for line in text.splitlines():
        fields = line.split()
        if not fields or fields[0] not in {"some", "full"}:
            continue
        values: dict[str, float] = {}
        for field in fields[1:]:
            if "=" not in field:
                continue
            key, raw_value = field.split("=", 1)
            try:
                values[key] = float(raw_value)
            except ValueError:
                continue
        samples[fields[0]] = values
    if not samples:
        return PsiSample(source=source, reason="memory PSI did not contain some or full samples")
    return PsiSample(some=samples.get("some"), full=samples.get("full"), source=source)


def load_psi(path: Path = Path("/proc/pressure/memory")) -> PsiSample:
    try:
        return parse_psi(path.read_text(encoding="utf-8"), source=str(path))
    except OSError as exc:
        return PsiSample(source=str(path), reason=f"memory PSI is unavailable: {exc}")


def _host_scope(version_path: Path) -> str:
    try:
        version = version_path.read_text(encoding="utf-8").lower()
    except OSError:
        return "linux_guest"
    return "wsl_guest" if "microsoft" in version or "wsl" in version else "linux_host"


def load_host_snapshot(
    *,
    meminfo_path: Path = Path("/proc/meminfo"),
    psi_path: Path = Path("/proc/pressure/memory"),
    version_path: Path = Path("/proc/version"),
) -> HostSnapshot:
    collected_at = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    psi = load_psi(psi_path)
    try:
        snapshot = load_meminfo(meminfo_path)
    except (OSError, RuntimeError) as exc:
        return HostSnapshot(
            total_bytes=None,
            available_bytes=None,
            swap_used_bytes=None,
            psi=psi,
            collected_at=collected_at,
            scope=_host_scope(version_path),
            reason=f"host memory snapshot is unavailable: {exc}",
        )
    return HostSnapshot(
        total_bytes=snapshot.total_bytes,
        available_bytes=snapshot.available_bytes,
        swap_used_bytes=snapshot.swap_used_bytes,
        psi=psi,
        collected_at=collected_at,
        scope=_host_scope(version_path),
    )


def user_systemd_socket() -> Path | None:
    runtime = os.environ.get("XDG_RUNTIME_DIR")
    if not runtime:
        return None
    candidate = Path(runtime) / "systemd" / "private"
    return candidate if candidate.exists() else None

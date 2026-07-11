from __future__ import annotations

from pathlib import Path

from .contracts import Capability, CapabilityReport
from .procfs import user_systemd_socket


def detect_capabilities(
    *,
    proc_root: Path = Path("/proc"),
    cgroup_root: Path = Path("/sys/fs/cgroup"),
) -> CapabilityReport:
    capabilities: list[Capability] = []
    meminfo = proc_root / "meminfo"
    capabilities.append(
        Capability("host_memory", "ready" if meminfo.is_file() else "unavailable", () if meminfo.is_file() else ("/proc/meminfo is unavailable",))
    )
    psi = proc_root / "pressure" / "memory"
    capabilities.append(
        Capability("memory_psi", "ready" if psi.is_file() else "unavailable", () if psi.is_file() else ("/proc/pressure/memory is unavailable",))
    )
    controllers_path = cgroup_root / "cgroup.controllers"
    if not controllers_path.is_file():
        capabilities.append(Capability("cgroup_v2", "unavailable", ("cgroup v2 controllers file is unavailable",)))
        capabilities.append(Capability("cgroup_memory", "unavailable", ("cgroup v2 is unavailable",)))
    else:
        capabilities.append(Capability("cgroup_v2", "ready"))
        try:
            controllers = controllers_path.read_text(encoding="utf-8").split()
        except OSError as exc:
            capabilities.append(Capability("cgroup_memory", "unavailable", (f"cannot read cgroup controllers: {exc}",)))
        else:
            if "memory" in controllers:
                capabilities.append(Capability("cgroup_memory", "ready"))
            else:
                capabilities.append(Capability("cgroup_memory", "unavailable", ("memory controller is unavailable",)))
    socket = user_systemd_socket()
    if socket is None:
        capabilities.append(Capability("systemd_user", "unavailable", ("user systemd manager socket is unavailable",)))
    else:
        capabilities.append(Capability("systemd_user", "ready"))
    memory_state = next(item.state for item in capabilities if item.name == "cgroup_memory")
    if socket is not None and memory_state == "ready":
        capabilities.append(
            Capability(
                "memory_high_control",
                "unverified",
                ("verify-control is an immediate diagnostic; workload run verifies each managed scope",),
            )
        )
    else:
        capabilities.append(Capability("memory_high_control", "unavailable", ("cgroup memory control or user systemd is unavailable",)))
    return CapabilityReport(capabilities=tuple(capabilities))

from __future__ import annotations

import os
from pathlib import Path
import re
import stat
import tomllib
from typing import Any

from .contracts import WorkloadPolicy, WorkloadProfile


SYSTEM_WORKLOAD_CONFIG_PATH = Path("/etc/linux-cache-guard/workload-guard.toml")
PROFILE_PATTERN = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
ROOT_KEYS = frozenset({"format_version", "workload_guard"})
GUARD_KEYS = frozenset(
    {
        "enabled",
        "mode",
        "min_host_available_bytes",
        "max_managed_workloads",
        "event_max_bytes",
        "event_retention_days",
        "sample_interval_seconds",
        "profiles",
    }
)
PROFILE_KEYS = frozenset({"admission_bytes", "memory_high_bytes"})


def default_user_workload_config_path() -> Path:
    config_home = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return config_home / "linux-cache-guard" / "workload-guard.toml"


def default_workload_config_path() -> Path:
    """Prefer the installed policy without merging it with a user policy."""
    return SYSTEM_WORKLOAD_CONFIG_PATH if SYSTEM_WORKLOAD_CONFIG_PATH.exists() else default_user_workload_config_path()


def default_workload_state_dir() -> Path:
    state_home = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))
    return state_home / "linux-cache-guard" / "workloads"


def _expect_bool(data: dict[str, Any], name: str, default: bool) -> bool:
    value = data.get(name, default)
    if not isinstance(value, bool):
        raise ValueError(f"workload_guard.{name} must be true or false")
    return value


def _expect_int(data: dict[str, Any], name: str, default: int, *, minimum: int, maximum: int | None = None) -> int:
    value = data.get(name, default)
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise ValueError(f"workload_guard.{name} must be an integer of at least {minimum}")
    if maximum is not None and value > maximum:
        raise ValueError(f"workload_guard.{name} must be no greater than {maximum}")
    return value


def _validate_system_config(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ValueError(f"cannot inspect system workload configuration {path}: {exc}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ValueError("system workload configuration must be a regular non-symbolic-link file")
    if metadata.st_uid != 0:
        raise ValueError("system workload configuration must be root-owned")
    if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ValueError("system workload configuration must not be group- or world-writable")
    parent = path.parent
    while True:
        parent_metadata = parent.lstat()
        if stat.S_ISLNK(parent_metadata.st_mode) or parent_metadata.st_uid != 0:
            raise ValueError(f"system workload configuration parent must be root-owned: {parent}")
        if parent_metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise ValueError(f"system workload configuration parent must not be writable: {parent}")
        if parent == parent.parent:
            return
        parent = parent.parent


def _disabled_policy() -> WorkloadPolicy:
    return WorkloadPolicy(
        enabled=False,
        mode="observe",
        min_host_available_bytes=2 * 1024 * 1024 * 1024,
        max_managed_workloads=1,
        event_max_bytes=1024 * 1024,
        event_retention_days=14,
        sample_interval_seconds=300,
        profiles={},
        state_dir=str(default_workload_state_dir()),
    )


def load_workload_policy(path: Path | None = None) -> WorkloadPolicy:
    config_path = path or default_workload_config_path()
    if not config_path.exists():
        if path is not None and config_path.is_relative_to(Path("/etc")):
            raise ValueError(f"required system workload configuration is missing: {config_path}")
        return _disabled_policy()
    if config_path.is_relative_to(Path("/etc")):
        _validate_system_config(config_path)
    try:
        raw = tomllib.loads(config_path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise ValueError(f"invalid workload TOML in {config_path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ValueError("workload configuration must be a TOML object")
    unknown_root = set(raw) - ROOT_KEYS
    if unknown_root:
        raise ValueError("unknown workload configuration setting: " + ", ".join(sorted(unknown_root)))
    if raw.get("format_version") != 1:
        raise ValueError("workload configuration format_version must be 1")
    guard = raw.get("workload_guard")
    if not isinstance(guard, dict):
        raise ValueError("workload_guard must be a TOML table")
    unknown_guard = set(guard) - GUARD_KEYS
    if unknown_guard:
        raise ValueError("unknown workload_guard setting: " + ", ".join(sorted(unknown_guard)))
    mode = guard.get("mode", "observe")
    if mode not in {"observe", "admit"}:
        raise ValueError("workload_guard.mode must be observe or admit")
    profiles_raw = guard.get("profiles", {})
    if not isinstance(profiles_raw, dict):
        raise ValueError("workload_guard.profiles must be a TOML table")
    profiles: dict[str, WorkloadProfile] = {}
    for name, profile_raw in profiles_raw.items():
        if not isinstance(name, str) or not PROFILE_PATTERN.fullmatch(name):
            raise ValueError("workload profile names must use lowercase letters, digits, _ or -")
        if not isinstance(profile_raw, dict):
            raise ValueError(f"workload profile {name} must be a TOML table")
        unknown_profile = set(profile_raw) - PROFILE_KEYS
        if unknown_profile:
            raise ValueError(f"unknown workload profile setting for {name}: " + ", ".join(sorted(unknown_profile)))
        admission = profile_raw.get("admission_bytes")
        high = profile_raw.get("memory_high_bytes")
        if not isinstance(admission, int) or isinstance(admission, bool) or admission <= 0:
            raise ValueError(f"workload profile {name}.admission_bytes must be a positive integer")
        if not isinstance(high, int) or isinstance(high, bool) or high <= 0:
            raise ValueError(f"workload profile {name}.memory_high_bytes must be a positive integer")
        if admission > high:
            raise ValueError(f"workload profile {name}.admission_bytes must not exceed memory_high_bytes")
        profiles[name] = WorkloadProfile(name=name, admission_bytes=admission, memory_high_bytes=high)
    return WorkloadPolicy(
        enabled=_expect_bool(guard, "enabled", False),
        mode=mode,
        min_host_available_bytes=_expect_int(
            guard, "min_host_available_bytes", 2 * 1024 * 1024 * 1024, minimum=0
        ),
        max_managed_workloads=_expect_int(guard, "max_managed_workloads", 1, minimum=1, maximum=128),
        event_max_bytes=_expect_int(guard, "event_max_bytes", 1024 * 1024, minimum=65536, maximum=64 * 1024 * 1024),
        event_retention_days=_expect_int(guard, "event_retention_days", 14, minimum=1, maximum=3650),
        sample_interval_seconds=_expect_int(guard, "sample_interval_seconds", 300, minimum=60, maximum=86400),
        profiles=profiles,
        state_dir=str(default_workload_state_dir()),
    )


def workload_sample_config() -> str:
    return """# This file is separate from config.toml and does not control cache cleanup.\nformat_version = 1\n\n[workload_guard]\n# Observation is safe by default. Change to admit only after reviewing status.\nenabled = false\nmode = \"observe\"\nmin_host_available_bytes = 2147483648\nmax_managed_workloads = 3\nevent_max_bytes = 1048576\nevent_retention_days = 14\n# The optional user timer wakes every minute; this is the minimum record interval.\nsample_interval_seconds = 300\n\n[workload_guard.profiles.coding]\nadmission_bytes = 2147483648\nmemory_high_bytes = 3221225472\n"""

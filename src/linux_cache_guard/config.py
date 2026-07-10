from __future__ import annotations

import os
from pathlib import Path
import stat
import tomllib
from typing import Any

from .models import DEFAULT_HELPER_PATH, Policy


POLICY_KEYS = frozenset(
    {
        "enabled",
        "auto_cleanup",
        "min_reclaimable_cache_bytes",
        "max_available_memory_bytes",
        "max_dirty_bytes",
        "require_writeback_zero",
        "require_no_build_processes",
        "cooldown_seconds",
        "min_cache_growth_bytes",
        "helper_path",
    }
)
STORAGE_KEYS = frozenset({"state_dir"})


def default_config_path() -> Path:
    config_home = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return config_home / "linux-cache-guard" / "config.toml"


def default_state_dir(config_path: Path | None = None) -> Path:
    if config_path is not None and config_path.is_relative_to(Path("/etc")):
        return Path("/var/lib/linux-cache-guard")
    state_home = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))
    return state_home / "linux-cache-guard"


def _expect_bool(data: dict[str, Any], name: str, default: bool) -> bool:
    value = data.get(name, default)
    if not isinstance(value, bool):
        raise ValueError(f"policy.{name} must be true or false")
    return value


def _expect_non_negative_int(data: dict[str, Any], name: str, default: int | None) -> int | None:
    value = data.get(name, default)
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"policy.{name} must be a non-negative integer")
    return value


def _validate_system_config(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ValueError(f"cannot inspect system configuration {path}: {exc}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ValueError("system configuration must be a regular non-symbolic-link file")
    if metadata.st_uid != 0:
        raise ValueError("system configuration must be root-owned")
    if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ValueError("system configuration must not be group- or world-writable")
    parent = path.parent
    while True:
        parent_metadata = parent.lstat()
        if stat.S_ISLNK(parent_metadata.st_mode) or parent_metadata.st_uid != 0:
            raise ValueError(f"system configuration parent must be root-owned: {parent}")
        if parent_metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise ValueError(f"system configuration parent must not be writable: {parent}")
        if parent == parent.parent:
            return
        parent = parent.parent


def load_policy(path: Path | None = None) -> Policy:
    config_path = path or default_config_path()
    if not config_path.exists():
        if path is not None and config_path.is_relative_to(Path("/etc")):
            raise ValueError(f"required system configuration is missing: {config_path}")
        return Policy(state_dir=default_state_dir(config_path))
    if config_path.is_relative_to(Path("/etc")):
        _validate_system_config(config_path)
    try:
        raw = tomllib.loads(config_path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise ValueError(f"invalid TOML in {config_path}: {exc}") from exc
    policy_raw = raw.get("policy", {})
    storage_raw = raw.get("storage", {})
    if not isinstance(policy_raw, dict) or not isinstance(storage_raw, dict):
        raise ValueError("policy and storage must be TOML tables")
    unknown_policy_keys = set(policy_raw) - POLICY_KEYS
    unknown_storage_keys = set(storage_raw) - STORAGE_KEYS
    if unknown_policy_keys:
        raise ValueError("unknown policy setting: " + ", ".join(sorted(unknown_policy_keys)))
    if unknown_storage_keys:
        raise ValueError("unknown storage setting: " + ", ".join(sorted(unknown_storage_keys)))

    helper_path = policy_raw.get("helper_path", str(DEFAULT_HELPER_PATH))
    configured_state_dir = storage_raw.get("state_dir")
    if not isinstance(helper_path, str):
        raise ValueError("helper_path must be a string")
    if Path(helper_path) != DEFAULT_HELPER_PATH:
        raise ValueError(f"helper_path is fixed to {DEFAULT_HELPER_PATH}")
    if configured_state_dir is not None and not isinstance(configured_state_dir, str):
        raise ValueError("state_dir must be a string")
    return Policy(
        enabled=_expect_bool(policy_raw, "enabled", True),
        auto_cleanup=_expect_bool(policy_raw, "auto_cleanup", False),
        min_reclaimable_cache_bytes=_expect_non_negative_int(policy_raw, "min_reclaimable_cache_bytes", None),
        max_available_memory_bytes=_expect_non_negative_int(policy_raw, "max_available_memory_bytes", None),
        max_dirty_bytes=_expect_non_negative_int(policy_raw, "max_dirty_bytes", 64 * 1024 * 1024) or 0,
        require_writeback_zero=_expect_bool(policy_raw, "require_writeback_zero", True),
        require_no_build_processes=_expect_bool(policy_raw, "require_no_build_processes", True),
        cooldown_seconds=_expect_non_negative_int(policy_raw, "cooldown_seconds", 3600) or 0,
        min_cache_growth_bytes=_expect_non_negative_int(policy_raw, "min_cache_growth_bytes", 512 * 1024 * 1024) or 0,
        helper_path=DEFAULT_HELPER_PATH,
        state_dir=(
            Path(configured_state_dir).expanduser()
            if configured_state_dir
            else default_state_dir(config_path)
        ),
    )


def sample_config() -> str:
    return """[policy]\nenabled = true\nauto_cleanup = false\n# min_reclaimable_cache_bytes = 4294967296\n# Automatic cleanup also needs an explicit memory-pressure limit.\n# max_available_memory_bytes = 2147483648\nmax_dirty_bytes = 67108864\nrequire_writeback_zero = true\nrequire_no_build_processes = true\ncooldown_seconds = 3600\nmin_cache_growth_bytes = 536870912\n\n[storage]\n# state_dir = \"/var/lib/linux-cache-guard\"\n"""

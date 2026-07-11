from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import sys
import re
import subprocess
import tempfile
from importlib import resources

from . import __version__
from .config import default_config_path, load_policy, sample_config
from .engine import StateError, cleanup, inspect, load_history, recover_pending
from .models import DEFAULT_HELPER_PATH
from .workloads.cli import configure_parser as configure_workload_parser
from .workloads.cli import execute as execute_workload


SYSTEM_CONFIG_PATH = Path("/etc/linux-cache-guard/config.toml")
TIMER_OVERRIDE_DIRECTORY = Path("/etc/systemd/system/linux-cache-guard.timer.d")
TIMER_OVERRIDE_PATH = TIMER_OVERRIDE_DIRECTORY / "override.conf"
DEFAULT_CHECK_INTERVAL = "10min"
INTERVAL_PATTERN = re.compile(r"^[1-9][0-9]*(s|min|h|d)$")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="linux-cache-guard",
        description="Inspect Linux reclaimable cache and run policy-gated cleanup.",
    )
    parser.add_argument("--version", action="version", version=f"linux-drop-caches {__version__}")
    parser.add_argument("--config", type=Path, help="TOML configuration file")
    parser.add_argument("--json", action="store_true", dest="as_json", help="write JSON to standard output")
    commands = parser.add_subparsers(dest="command", required=True)
    status_parser = commands.add_parser("status", help="show memory and interactive cleanup status")
    status_parser.add_argument("--json", action="store_true", dest="as_json", default=argparse.SUPPRESS)
    check_parser = commands.add_parser("check", help="show whether a cleanup would be allowed")
    check_parser.add_argument("--auto", action="store_true", help="evaluate the additional automatic-cleanup rules")
    check_parser.add_argument("--json", action="store_true", dest="as_json", default=argparse.SUPPRESS)

    cleanup_parser = commands.add_parser("cleanup", help="run a checked cleanup or a dry run")
    cleanup_mode = cleanup_parser.add_mutually_exclusive_group()
    cleanup_mode.add_argument("--dry-run", action="store_true", help="record what would happen without changing cache")
    cleanup_mode.add_argument("--yes", action="store_true", help="perform an interactive cleanup after checks")
    cleanup_mode.add_argument("--auto", action="store_true", help="run only when auto_cleanup is enabled in configuration")
    cleanup_parser.add_argument("--json", action="store_true", dest="as_json", default=argparse.SUPPRESS)

    init_parser = commands.add_parser("init-config", help="write a conservative configuration template")
    init_parser.add_argument("--path", type=Path, default=default_config_path())
    init_parser.add_argument("--force", action="store_true", help="replace an existing configuration file")

    helper_parser = commands.add_parser("install-helper", help="install the fixed root cache-drop helper")
    helper_parser.add_argument("--force", action="store_true", help="replace an existing helper")

    recovery_parser = commands.add_parser("recover-pending", help="acknowledge a failed cleanup record after review")
    recovery_parser.add_argument("--yes", action="store_true", help="confirm that the pending cleanup was reviewed")
    recovery_parser.add_argument("--json", action="store_true", dest="as_json", default=argparse.SUPPRESS)

    history_parser = commands.add_parser("history", help="show recent cleanup receipts")
    history_parser.add_argument("--limit", type=int, default=10, help="number of recent receipts to show")
    history_parser.add_argument("--json", action="store_true", dest="as_json", default=argparse.SUPPRESS)

    schedule_parser = commands.add_parser("schedule", help="view or change the systemd check interval")
    schedule_commands = schedule_parser.add_subparsers(dest="schedule_command", required=True)
    schedule_commands.add_parser("show", help="show the configured check interval")
    schedule_set_parser = schedule_commands.add_parser("set", help="set the interval, for example 30min or 1h")
    schedule_set_parser.add_argument("interval", help="positive duration ending in s, min, h, or d")
    workload_parser = commands.add_parser("workload", help="inspect and cooperatively manage opt-in user workloads")
    configure_workload_parser(workload_parser)
    return parser


def _emit(payload: dict[str, object], *, as_json: bool) -> None:
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return
    if "snapshot" in payload:
        snapshot = payload["snapshot"]
        assert isinstance(snapshot, dict)
        human = snapshot["human"]
        assert isinstance(human, dict)
        print(f"Memory: {human['total']} total, {human['available']} available")
        print(f"Reclaimable cache: {human['reclaimable_cache']}")
        print(f"Swap in use: {human['swap_used']}")
    decision = payload.get("decision")
    if isinstance(decision, dict):
        print(f"Cleanup status: {decision['status']}")
        for reason in decision.get("reasons", []):
            print(f"  - {reason}")
        for warning in decision.get("warnings", []):
            print(f"  warning: {warning}")
        print(f"Cleanup threshold: {decision['threshold_human']}")
    helper = payload.get("helper")
    if isinstance(helper, dict):
        print(f"Helper: {'ready' if helper['ok'] else 'not ready'} ({helper['path']})")
        for reason in helper.get("reasons", []):
            print(f"  - {reason}")
    result = payload.get("result")
    if isinstance(result, dict):
        print(f"Result: {result['result']}")
        estimated_delta = result.get("estimated_reclaimable_cache_delta_human")
        if estimated_delta is not None:
            print(f"Estimated reclaimable-cache change: {estimated_delta}")
        receipt = result.get("receipt_path")
        if receipt:
            print(f"Receipt: {receipt}")
        for error in result.get("errors", []):
            print(f"  error: {error}", file=sys.stderr)
    recovery = payload.get("recovery")
    if isinstance(recovery, dict):
        print(f"Pending cleanup recovery: {recovery['status']}")
        if recovery.get("pending_path"):
            print(f"Pending marker: {recovery['pending_path']}")
        if recovery.get("receipt_path"):
            print(f"Receipt: {recovery['receipt_path']}")
        if recovery.get("error"):
            print(f"  error: {recovery['error']}", file=sys.stderr)
    history = payload.get("history")
    if isinstance(history, list):
        if not history:
            print("No cleanup receipts recorded.")
        for entry in history:
            if isinstance(entry, dict):
                timestamp = entry.get("created_at", "unknown time")
                result = entry.get("result", entry.get("receipt_type", "unknown result"))
                print(f"{timestamp}: {result}")
    schedule = payload.get("schedule")
    if isinstance(schedule, dict):
        print(f"Check interval: {schedule['interval']}")
        print(f"Source: {schedule['source']}")
        if schedule.get("message"):
            print(schedule["message"])


def _secure_root_directory(path: Path) -> bool:
    current = path
    while True:
        try:
            metadata = current.lstat()
        except OSError:
            return False
        if stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0:
            return False
        if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            return False
        if current == current.parent:
            return True
        current = current.parent


def _install_helper(*, force: bool) -> int:
    if os.geteuid() != 0:
        print("install-helper must run as root, for example: sudo linux-cache-guard install-helper", file=sys.stderr)
        return 2
    destination = DEFAULT_HELPER_PATH
    if not _secure_root_directory(destination.parent):
        print(f"refusing insecure helper parent directory: {destination.parent}", file=sys.stderr)
        return 2
    if destination.exists() and not force:
        print(f"refusing to overwrite existing helper: {destination}; use --force after review", file=sys.stderr)
        return 2
    with resources.as_file(resources.files("linux_cache_guard.resources").joinpath("linux-drop-caches")) as source:
        temporary = destination.with_name(f".{destination.name}.tmp")
        try:
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o700)
        except FileExistsError:
            print(f"refusing existing temporary helper path: {temporary}", file=sys.stderr)
            return 2
        try:
            with source.open("rb") as input_handle, os.fdopen(descriptor, "wb") as output_handle:
                output_handle.write(input_handle.read())
                output_handle.flush()
                os.fsync(output_handle.fileno())
            os.chmod(temporary, 0o755)
            os.chown(temporary, 0, 0)
            temporary.replace(destination)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
    print(f"installed root helper at {destination}")
    return 0


def _validate_interval(value: str) -> str:
    if not INTERVAL_PATTERN.fullmatch(value):
        raise ValueError("interval must look like 30s, 15min, 1h, or 1d")
    return value


def _schedule_override_contents(interval: str) -> str:
    return f"[Timer]\nOnBootSec=\nOnUnitActiveSec=\nOnBootSec={interval}\nOnUnitActiveSec={interval}\n"


def _show_schedule() -> dict[str, object]:
    if not TIMER_OVERRIDE_PATH.exists():
        return {"interval": DEFAULT_CHECK_INTERVAL, "source": "package default"}
    if TIMER_OVERRIDE_PATH.is_symlink():
        raise ValueError(f"refusing symbolic-link timer override: {TIMER_OVERRIDE_PATH}")
    contents = TIMER_OVERRIDE_PATH.read_text(encoding="utf-8")
    intervals = [
        line.split("=", 1)[1]
        for line in contents.splitlines()
        if line.startswith("OnUnitActiveSec=") and line != "OnUnitActiveSec="
    ]
    if not intervals:
        raise ValueError(f"timer override does not define OnUnitActiveSec: {TIMER_OVERRIDE_PATH}")
    return {"interval": intervals[-1], "source": str(TIMER_OVERRIDE_PATH)}


def _set_schedule(interval: str) -> dict[str, object]:
    if os.geteuid() != 0:
        raise PermissionError("run schedule set as root: sudo linux-cache-guard schedule set <interval>")
    TIMER_OVERRIDE_DIRECTORY.mkdir(mode=0o755, parents=True, exist_ok=True)
    if not _secure_root_directory(TIMER_OVERRIDE_DIRECTORY):
        raise PermissionError(f"refusing insecure timer override directory: {TIMER_OVERRIDE_DIRECTORY}")
    if TIMER_OVERRIDE_PATH.is_symlink():
        raise PermissionError(f"refusing symbolic-link timer override: {TIMER_OVERRIDE_PATH}")
    descriptor, temporary_name = tempfile.mkstemp(prefix=".override.", dir=TIMER_OVERRIDE_DIRECTORY)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o644)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(_schedule_override_contents(interval))
            handle.flush()
            os.fsync(handle.fileno())
        os.chown(temporary, 0, 0)
        temporary.replace(TIMER_OVERRIDE_PATH)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise

    message = "Timer override saved."
    if Path("/run/systemd/system").is_dir():
        reload_result = subprocess.run(["/usr/bin/systemctl", "daemon-reload"], check=False, capture_output=True, text=True)
        if reload_result.returncode != 0:
            raise RuntimeError(reload_result.stderr.strip() or "systemctl daemon-reload failed")
        restart_result = subprocess.run(
            ["/usr/bin/systemctl", "try-restart", "linux-cache-guard.timer"],
            check=False,
            capture_output=True,
            text=True,
        )
        if restart_result.returncode != 0:
            raise RuntimeError(restart_result.stderr.strip() or "systemctl try-restart failed")
        message = "Timer override saved and active timer reloaded."
    else:
        message = "Timer override saved; systemd is not active, so no timer was restarted."
    return {"interval": interval, "source": str(TIMER_OVERRIDE_PATH), "message": message}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "init-config":
        if os.geteuid() == 0 and args.path != SYSTEM_CONFIG_PATH:
            print(f"root may write configuration only at {SYSTEM_CONFIG_PATH}", file=sys.stderr)
            return 2
        if args.path.is_symlink():
            print(f"refusing symbolic-link configuration path: {args.path}", file=sys.stderr)
            return 2
        if args.path.exists() and not args.force:
            print(f"refusing to overwrite existing configuration: {args.path}", file=sys.stderr)
            return 2
        args.path.parent.mkdir(parents=True, exist_ok=True)
        args.path.write_text(sample_config(), encoding="utf-8")
        print(f"wrote configuration template to {args.path}")
        return 0
    if args.command == "install-helper":
        return _install_helper(force=args.force)
    if args.command == "schedule":
        try:
            schedule = _show_schedule() if args.schedule_command == "show" else _set_schedule(_validate_interval(args.interval))
        except (OSError, PermissionError, RuntimeError, ValueError) as exc:
            print(f"schedule error: {exc}", file=sys.stderr)
            return 2
        _emit({"schedule": schedule}, as_json=args.as_json)
        return 0
    if args.command == "workload":
        return execute_workload(args)

    try:
        policy = load_policy(args.config)
    except (OSError, ValueError) as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2
    if args.command == "recover-pending":
        recovery = recover_pending(policy, confirmed=args.yes)
        _emit({"recovery": recovery}, as_json=args.as_json)
        return 0 if recovery["status"] in {"recovered", "no_pending_cleanup", "confirmation_required"} else 1
    if args.command == "history":
        try:
            history = list(load_history(policy, limit=args.limit))
        except (StateError, ValueError) as exc:
            print(f"history error: {exc}", file=sys.stderr)
            return 1
        _emit({"history": history}, as_json=args.as_json)
        return 0
    try:
        if args.command in {"status", "check"}:
            snapshot, helper, state, decision = inspect(
                policy,
                automatic=args.command == "check" and args.auto,
            )
            payload: dict[str, object] = {
                "snapshot": snapshot.as_dict(),
                "helper": helper.as_dict(),
                "state": state.as_dict(),
                "decision": decision.as_dict(),
                "policy": policy.as_dict(total_memory_bytes=snapshot.total_bytes),
            }
            _emit(payload, as_json=args.as_json)
            return 0

        dry_run = args.dry_run or not (args.yes or args.auto)
        result = cleanup(policy, dry_run=dry_run, automatic=args.auto)
        payload = {"result": result.as_dict(), "decision": result.decision.as_dict()}
        _emit(payload, as_json=args.as_json)
        return 0 if result.result in {"completed", "would_run", "skipped"} else 1
    except (OSError, RuntimeError) as exc:
        print(f"system inspection error: {exc}", file=sys.stderr)
        return 1

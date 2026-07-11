from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

from ..models import format_bytes
from .config import (
    SYSTEM_WORKLOAD_CONFIG_PATH,
    default_user_workload_config_path,
    load_workload_policy,
    workload_sample_config,
)
from .contracts import EXIT_INVALID, envelope
from .runner import (
    verify_control,
    workload_check,
    workload_history,
    workload_monitor,
    workload_run,
    workload_status,
)
from .state import WorkloadStateError
from .systemd_user import SystemdUserError, SystemdUserRunner


def configure_parser(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--config", dest="workload_config", type=Path, help="workload TOML configuration file")
    parser.add_argument("--json", dest="workload_json", action="store_true", help="write JSON to standard output")
    commands = parser.add_subparsers(dest="workload_command", required=True)
    capabilities = commands.add_parser("capabilities", help="show read-only workload control capabilities")
    capabilities.add_argument("--json", dest="workload_json", action="store_true", default=argparse.SUPPRESS)
    status = commands.add_parser("status", help="show host and managed workload memory state")
    status.add_argument("--json", dest="workload_json", action="store_true", default=argparse.SUPPRESS)
    check = commands.add_parser("check", help="advise whether a workload profile may start")
    check.add_argument("--profile", required=True, help="configured workload profile")
    check.add_argument("--json", dest="workload_json", action="store_true", default=argparse.SUPPRESS)
    verify = commands.add_parser("verify-control", help="explicitly verify a user-systemd MemoryHigh scope")
    verify.add_argument("--json", dest="workload_json", action="store_true", default=argparse.SUPPRESS)
    run = commands.add_parser("run", help="run a command inside a verified user-systemd MemoryHigh scope")
    run.add_argument("--profile", required=True, help="configured workload profile")
    run.add_argument("--json", dest="workload_json", action="store_true", default=argparse.SUPPRESS)
    run.add_argument("argv", nargs=argparse.REMAINDER, help="command after --")
    history = commands.add_parser("history", help="show recent workload events")
    history.add_argument("--limit", type=int, default=20, help="number of recent events")
    history.add_argument("--json", dest="workload_json", action="store_true", default=argparse.SUPPRESS)
    monitor = commands.add_parser("monitor", help="record a workload observation when its state changes")
    monitor.add_argument("--json", dest="workload_json", action="store_true", default=argparse.SUPPRESS)
    metrics = commands.add_parser("metrics", help="write workload metrics to standard output")
    metrics.add_argument("--format", choices=("prometheus",), default="prometheus")
    metrics.add_argument("--json", dest="workload_json", action="store_true", default=argparse.SUPPRESS)
    init_config = commands.add_parser("init-config", help="write a disabled workload configuration template")
    init_config.add_argument("--path", type=Path, default=default_user_workload_config_path())
    init_config.add_argument("--force", action="store_true", help="replace an existing configuration after review")


def _emit(payload: dict[str, object], *, as_json: bool) -> None:
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return
    kind = payload.get("kind")
    data = payload.get("data")
    if not isinstance(data, dict):
        print("invalid workload output", file=sys.stderr)
        return
    if kind == "workload_capabilities":
        for capability in data.get("capabilities", []):
            if isinstance(capability, dict):
                print(f"{capability.get('name')}: {capability.get('state')}")
                for reason in capability.get("reasons", []):
                    print(f"  - {reason}")
    elif kind == "workload_status":
        host = data.get("host")
        if isinstance(host, dict):
            available = host.get("available_bytes")
            total = host.get("total_bytes")
            print(
                "Host memory: "
                + (format_bytes(total) if isinstance(total, int) else "unknown")
                + " total, "
                + (format_bytes(available) if isinstance(available, int) else "unknown")
                + " available"
            )
            print(f"Scope: {host.get('scope')}")
        workloads = data.get("workloads")
        if isinstance(workloads, list):
            print(f"Managed workloads: {len(workloads)}")
            for entry in workloads:
                if not isinstance(entry, dict):
                    continue
                workload = entry.get("workload")
                cgroup = entry.get("cgroup")
                if isinstance(workload, dict):
                    print(f"  - {workload.get('profile')}: {workload.get('status')}")
                if isinstance(cgroup, dict) and isinstance(cgroup.get("current_bytes"), int):
                    print(f"    memory: {format_bytes(cgroup['current_bytes'])}")
        if data.get("state_error"):
            print(f"State warning: {data['state_error']}")
    elif kind == "workload_admission":
        decision = data.get("decision")
        if isinstance(decision, dict):
            print(f"Workload admission: {decision.get('status')}")
            for reason in decision.get("reasons", []):
                print(f"  - {reason}")
    elif kind == "workload_history":
        events = data.get("events")
        if not isinstance(events, list) or not events:
            print("No workload events recorded.")
        elif isinstance(events, list):
            for event in events:
                if isinstance(event, dict):
                    print(f"{event.get('created_at', 'unknown time')}: {event.get('kind', 'unknown event')}")
    elif kind == "workload_monitor":
        print(f"Workload monitor: {data.get('level')}")
    elif kind == "workload_control_verification":
        print("Workload MemoryHigh control: verified")
    elif kind == "workload_run":
        print(f"Workload run: exit code {data.get('exit_code')}")


def _write_config(path: Path, *, force: bool) -> int:
    if os.geteuid() == 0 and path != SYSTEM_WORKLOAD_CONFIG_PATH:
        print(f"root may write workload configuration only at {SYSTEM_WORKLOAD_CONFIG_PATH}", file=sys.stderr)
        return EXIT_INVALID
    if path.is_symlink():
        print(f"refusing symbolic-link workload configuration path: {path}", file=sys.stderr)
        return EXIT_INVALID
    if path.exists() and not force:
        print(f"refusing to overwrite existing workload configuration: {path}; use --force after review", file=sys.stderr)
        return EXIT_INVALID
    path.parent.mkdir(mode=0o755 if os.geteuid() == 0 else 0o700, parents=True, exist_ok=True)
    path.write_text(workload_sample_config(), encoding="utf-8")
    if os.geteuid() == 0:
        os.chmod(path, 0o644)
        os.chown(path, 0, 0)
    print(f"wrote disabled workload configuration template to {path}")
    return 0


def _metrics(policy_data: dict[str, object]) -> str:
    host = policy_data.get("host")
    lines = ["# HELP linux_cache_guard_workload_managed_workloads Number of managed workloads.", "# TYPE linux_cache_guard_workload_managed_workloads gauge"]
    workloads = policy_data.get("workloads")
    lines.append(f"linux_cache_guard_workload_managed_workloads {len(workloads) if isinstance(workloads, list) else 0}")
    if isinstance(host, dict):
        for name, key in (("available_bytes", "available_bytes"), ("swap_used_bytes", "swap_used_bytes")):
            value = host.get(key)
            if isinstance(value, int):
                lines.append(f"linux_cache_guard_workload_host_{name} {value}")
        psi = host.get("psi")
        if isinstance(psi, dict) and isinstance(psi.get("full"), dict):
            value = psi["full"].get("avg10")
            if isinstance(value, (int, float)):
                lines.append(f"linux_cache_guard_workload_memory_psi_full_avg10 {value}")
    return "\n".join(lines) + "\n"


def execute(args: argparse.Namespace) -> int:
    if getattr(args, "config", None) is not None:
        print("use workload --config for workload configuration; the global --config belongs to cache cleanup", file=sys.stderr)
        return EXIT_INVALID
    if args.workload_command == "init-config":
        return _write_config(args.path, force=args.force)
    try:
        policy = load_workload_policy(args.workload_config)
    except (OSError, ValueError) as exc:
        print(f"workload configuration error: {exc}", file=sys.stderr)
        return EXIT_INVALID
    as_json = bool(getattr(args, "workload_json", False) or getattr(args, "as_json", False))
    if args.workload_command == "capabilities":
        payload = workload_status(policy)
        _emit(envelope("workload_capabilities", payload["capabilities"]), as_json=as_json)
        return 0
    if args.workload_command == "status":
        _emit(envelope("workload_status", workload_status(policy)), as_json=as_json)
        return 0
    if args.workload_command == "check":
        decision = workload_check(policy, args.profile)
        _emit(envelope("workload_admission", {"decision": decision.as_dict()}), as_json=as_json)
        return decision.exit_code
    if args.workload_command == "verify-control":
        try:
            result = verify_control(SystemdUserRunner())
        except SystemdUserError as exc:
            _emit(envelope("workload_admission", {"decision": {"status": "unsupported", "reasons": [str(exc)]}}), as_json=as_json)
            return 5
        _emit(envelope("workload_control_verification", {"unit_name": result.unit_name, "cgroup_path": result.cgroup_path}), as_json=as_json)
        return 0
    if args.workload_command == "run":
        if as_json:
            print("workload run does not support --json because the managed command owns standard output", file=sys.stderr)
            return EXIT_INVALID
        command = tuple(args.argv)
        if command and command[0] == "--":
            command = command[1:]
        decision, result = workload_run(policy, args.profile, command)
        if result is None:
            _emit(envelope("workload_admission", {"decision": decision.as_dict()}), as_json=as_json)
            return decision.exit_code
        _emit(
            envelope(
                "workload_run",
                {
                    "unit_name": result.unit_name,
                    "cgroup_path": result.cgroup_path,
                    "exit_code": result.exit_code,
                    "memory_high_verified": result.memory_high_verified,
                },
            ),
            as_json=as_json,
        )
        return result.exit_code
    if args.workload_command == "history":
        try:
            events = list(workload_history(policy, limit=args.limit))
        except (ValueError, OSError) as exc:
            print(f"workload history error: {exc}", file=sys.stderr)
            return EXIT_INVALID
        _emit(envelope("workload_history", {"events": events}), as_json=as_json)
        return 0
    if args.workload_command == "monitor":
        try:
            result = workload_monitor(policy)
        except (OSError, WorkloadStateError) as exc:
            print(f"workload monitor error: {exc}", file=sys.stderr)
            return 70
        _emit(envelope("workload_monitor", result), as_json=as_json)
        return 0
    if args.workload_command == "metrics":
        if as_json:
            print("workload metrics emits Prometheus text and does not support --json", file=sys.stderr)
            return EXIT_INVALID
        print(_metrics(workload_status(policy)), end="")
        return 0
    print("unknown workload command", file=sys.stderr)
    return EXIT_INVALID

# Workload Guard

## Purpose and boundary

`linux-cache-guard workload` is an opt-in resource-management layer for
commands a user deliberately starts through the guard. It can be used for AI
agents, browser automation, builds, tests, or any other local command. It is
not a cache-drop scheduler and never invokes the root helper.

The guard observes Linux guest memory. On WSL it does not observe or control
Windows-host processes, Vmmem reclaim, or `.wslconfig` settings.

The first implementation is cooperative. A process running with the same Linux
user ID can bypass `workload run`, so it is not a hostile-process sandbox. A
future enforced runner would require a distinct non-login account and a separate
security review; it is intentionally out of scope.

## Commands

```bash
linux-cache-guard workload capabilities
linux-cache-guard workload status
linux-cache-guard workload check --profile coding
linux-cache-guard workload verify-control
linux-cache-guard workload run --profile coding -- your-agent-command
linux-cache-guard workload history --limit 20
linux-cache-guard workload metrics --format prometheus
```

`capabilities` and `status` are read-only. They do not create state, change a
cgroup, enable a timer, run sudo, or change cache state.

`check` is advisory. It evaluates the configured reserve, parallel-workload
limit, reservations, and memory PSI. A different process may change the host
after a successful check. `run` therefore repeats the decision under a lock
before creating a managed scope.

`verify-control` explicitly creates a short-lived user systemd service to prove
that `MemoryHigh` can be applied at that time. It is the only diagnostic command
that creates a temporary scope. The result is not cached because delegation can
change after a reboot; every `run` reads the live cgroup value and refuses to
continue if it cannot verify the requested limit.

The workload `check` exit codes are stable: `0` for `allow`, `3` for temporary
`defer`, `4` for policy `deny`, `5` for `unsupported`, and `2` for invalid input
or configuration. A successful `run` returns the started command's exit code.
`run` rejects `--json`, because the managed command owns standard output; use
`history --json` for machine-readable execution records. `metrics` emits only
Prometheus text and also rejects `--json`.

## Configuration

The workload policy is intentionally separate from the cache policy.

| Use | Path |
| --- | --- |
| System-managed policy | `/etc/linux-cache-guard/workload-guard.toml` |
| Standalone user policy | `~/.config/linux-cache-guard/workload-guard.toml` |
| Per-user state and events | `~/.local/state/linux-cache-guard/workloads/` |

When the installed system policy exists, it is the default. Otherwise the user
policy is the default. There is no automatic merge between the two files; pass
`workload --config PATH` when selecting the other policy. System policy is
root-owned and is suitable when an AI agent must not edit profiles. The user
policy is for standalone cooperative use.

The installed system template is disabled:

```toml
format_version = 1

[workload_guard]
enabled = false
mode = "observe"
min_host_available_bytes = 2147483648
max_managed_workloads = 3
event_max_bytes = 1048576
event_retention_days = 14
sample_interval_seconds = 300

[workload_guard.profiles.coding]
admission_bytes = 2147483648
memory_high_bytes = 3221225472
```

Change `enabled` to `true` and `mode` to `admit` only after observing normal
work sessions. `admission_bytes` reserves launch capacity. `memory_high_bytes`
is the soft cgroup limit applied to a command launched by `workload run`.
`admission_bytes` cannot exceed `memory_high_bytes`.

`MemoryMax` is deliberately unsupported. A cgroup hard memory limit can cause
an OOM kill inside that cgroup when reclaim cannot reduce usage. The Linux
kernel documents `memory.high` as the throttling control and `memory.max` as a
hard limit. [Linux cgroup v2 documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html)

## Optional observation timer

The installer ships, but never enables, a user timer. It wakes once per minute,
while `sample_interval_seconds` sets the minimum interval at which it records a
new observation. It does not start workloads, drop cache, stop processes, or
alter settings.

```bash
systemctl --user daemon-reload
systemctl --user enable --now linux-cache-guard-workload.timer
```

The user systemd manager must be active. The tool never enables linger on the
user's behalf. If WSL or the user manager stops, the timer stops too and resumes
only when that manager starts again.

## Data handling

Events contain timestamps, profile names, generated unit IDs, decisions, and
aggregate memory values. They never store the command line, environment,
prompt, working directory, or project path. Event files have a size limit and
retention period from the workload policy.

## Compatibility levels

- Observation: `/proc/meminfo` is available.
- Pressure observation: `/proc/pressure/memory` is available.
- Managed memory control: cgroup v2 memory support, a reachable user systemd
  manager, and a successful live `MemoryHigh` readback during each `run` are all
  required.

When a control capability is unavailable, the guard reports `unsupported`; it
does not silently start an unlimited command through `workload run`.

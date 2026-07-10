# linux-drop-caches

`linux-drop-caches` is an opt-in Linux cache-maintenance tool. It separates a
tiny root-owned helper from a normal user-facing command that checks memory,
writeback activity, build processes, and cooldown rules before requesting a
cache drop.

Linux normally reclaims file cache automatically. This project is intended for
operators who have a specific reason to return reclaimable cache to the host,
such as an observed WSL memory-footprint problem. It does not reduce the memory
used by applications, fix a memory leak, or guarantee better performance.

The source installer requires Python 3.11 or later. On WSL distributions that
ship an older Python, install a supported Python version before running it.

## Release scope

Version 0.1 is a source-install alpha for Ubuntu and WSL environments with
Python 3.11+; it is not yet a distribution-managed package. A stable release
must add a Debian package, upgrade and uninstall behavior that preserves user
configuration and receipts by default, a changelog, and CI validation.

## What it does

- Shows memory, Swap, and reclaimable cache status.
- Recommends a cleanup threshold based on installed memory.
- Refuses cleanup during writeback, excessive dirty memory, or an active Cargo
  or Rust compiler process.
- Supports a dry run before every real cleanup.
- Records JSON receipts for attempted and completed cleanups.
- Provides a systemd timer template that checks every ten minutes but is
  disabled for automatic cleanup by default.

## Quick start

For a source checkout, install the fixed system locations and leave automatic
cleanup disabled:

```bash
sudo ./scripts/install-system.sh
```

Then inspect the machine without changing anything:

```bash
linux-cache-guard status
linux-cache-guard cleanup --dry-run
```

For a real, interactive cleanup, review the dry-run result and then run:

```bash
linux-cache-guard cleanup --yes
```

The command executes only `/usr/local/sbin/linux-drop-caches` with no
arguments. See [docs/operations.md](docs/operations.md) before enabling an
automatic timer. A future distribution package should install the same files
without requiring a source checkout.

To change the check interval after installation, run for example:

```bash
sudo /usr/local/bin/linux-cache-guard schedule set 30min
```

This changes only how often the timer checks conditions. It does not enable
automatic cleanup.

For a constrained AI-agent sudo policy, see
[docs/agent-administration.md](docs/agent-administration.md). The agent policy
is intentionally separate from release deployment; it never grants root access
to a mutable source checkout.

## Project layout

- `linux-cache-guard`: normal user-facing command for status and policy checks.
- `linux-drop-caches`: fixed root helper installed in `/usr/local/sbin`.
- `config/linux-cache-guard.toml`: safe default configuration.
- `packaging/systemd`: optional timer templates.

## Safety model

Automatic cleanup is off by default. Enabling it requires an explicit
configuration change, an available-memory pressure limit, and a systemd timer
installation. Every automatic run checks the configured cache threshold,
pressure limit, dirty/writeback memory, active build processes, helper
ownership and permissions, cooldown, and cache growth since the last successful
cleanup.

The helper deliberately remains small. Scheduling, policy, logging, and
receipts belong in `linux-cache-guard`, not in the privileged script.

The before/after cache difference in a receipt is an estimate of reclaimable
cache change, not a measurement of bytes freed by the kernel. Other activity
can change memory between the two snapshots.

## Development

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -B -m unittest discover -s tests -v
PYTHONPATH=src python3 -m linux_cache_guard status
```

The test suite never writes to `/proc/sys/vm/drop_caches` and never invokes
`sudo`.

## Security

Report security issues privately as described in [SECURITY.md](SECURITY.md).
Do not file a public issue containing credentials, private machine data, or an
active exploit path.

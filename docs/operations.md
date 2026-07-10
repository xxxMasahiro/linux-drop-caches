# Operations guide

## Before enabling cleanup

Run these commands for several normal work sessions first:

```bash
linux-cache-guard status
linux-cache-guard cleanup --dry-run
```

The tool should report `cleanup_recommended` only when reclaimable cache meets
the configured threshold and all safety checks pass. A large cache is not an
error by itself; Linux uses it to make future file reads faster.

## Installation model

The source repository stays in a normal user directory. Installation places
each component where Linux expects it:

| Component | Installed location | Purpose |
| --- | --- | --- |
| User command | `/usr/local/bin/linux-cache-guard` | Status, dry run, policy checks, and receipts |
| Root helper | `/usr/local/sbin/linux-drop-caches` | The only privileged cache-drop operation |
| System configuration | `/etc/linux-cache-guard/config.toml` | Shared automatic-cleanup policy |
| Receipts | `/var/lib/linux-cache-guard/` | Cleanup history for the system timer |
| Timer | systemd unit directory | Optional ten-minute policy checks |

For an early source installation, install the fixed helper, system command,
configuration, service account, limited sudo rule, and systemd units together:

```bash
sudo ./scripts/install-system.sh
```

The source installer requires Python 3.11 or later and checks this before it
changes system files. It detects whether systemd is actually running; on WSL
without systemd it installs the manual command but does not attempt to reload
or enable the timer.

A distribution package should install the same files with the OS package
manager. Interactive cleanup uses normal `sudo` confirmation. The systemd
service runs as a dedicated `linux-cache-guard` account, which may use sudo
only for `/usr/local/sbin/linux-drop-caches` with no arguments. Do not grant
passwordless sudo access to a shell, Python interpreter, or an
argument-taking wrapper.

## Changing the check interval

The package default is a ten-minute check. An administrator can choose a
different interval without editing a systemd file manually:

```bash
sudo /usr/local/bin/linux-cache-guard schedule show
sudo /usr/local/bin/linux-cache-guard schedule set 30min
```

Supported units are `s`, `min`, `h`, and `d`, for example `15min`, `1h`, or
`2d`. The command writes a fixed systemd timer override and reloads an already
active timer. It does not enable the timer and does not change
`auto_cleanup`.

## Interactive cleanup

Without a system installation, the normal command uses the calling user's
configuration and state directory:

After reviewing a dry run, run:

```bash
linux-cache-guard cleanup --yes
```

The command refuses to continue when the cache is below the threshold, a
writeback is active, dirty memory is too high, a Cargo or Rust compiler process
is active, the helper permissions are unsafe, or a cooldown is in effect.

After `install-system.sh`, use the system policy through the same dedicated
account as the timer. This keeps manual checks and automatic checks on the
same lock, cooldown, receipts, and `/var/lib` state store:

```bash
sudo -u linux-cache-guard /usr/local/bin/linux-cache-guard \
  --config /etc/linux-cache-guard/config.toml check --auto
sudo -u linux-cache-guard /usr/local/bin/linux-cache-guard \
  --config /etc/linux-cache-guard/config.toml cleanup --dry-run
```

Only after reviewing that dry run should an operator use `cleanup --yes` with
the same command prefix. The dedicated account has a sudo rule for the fixed
helper only; the rest of the policy process remains unprivileged.

## Optional ten-minute checks

1. Review `/etc/linux-cache-guard/config.toml`, which the source installer
   creates without enabling automatic cleanup.

2. Keep `auto_cleanup = false` while checking dry-run receipts with the
   service-account command above.
3. When an operator explicitly accepts the policy, set `auto_cleanup = true`
   and set `max_available_memory_bytes` to a host-appropriate pressure limit.
   Automatic cleanup remains disabled until both values are present.
4. Install the packaged systemd service and timer, then enable the timer:

   ```bash
   sudo systemctl enable --now linux-cache-guard.timer
   ```

The timer runs every ten minutes, but the default cooldown prevents repeated
cleanup. The configured cache-growth rule and the explicit available-memory
pressure limit must also be satisfied after the last successful cleanup.
The service timeout is ten minutes because the helper runs `sync`; slow or
network-backed storage can make that operation take longer than a short timer
interval.

WSL requires systemd to be enabled for this timer. Without systemd, keep the
tool manual; do not replace the policy-gated command with a direct cron call
to the root helper.

## Recovering a pending cleanup

If the helper exits unsuccessfully, or if the process is interrupted after it
starts, the guard leaves a pending marker and refuses subsequent cleanup. This
is intentional. Inspect the latest receipt and host state first, then use the
same service-account command to see the pending marker:

```bash
sudo -u linux-cache-guard /usr/local/bin/linux-cache-guard \
  --config /etc/linux-cache-guard/config.toml recover-pending
```

After an operator confirms that another cleanup is safe, acknowledge it with
`recover-pending --yes`. The acknowledgement is added to the JSONL receipt
history before the pending marker is cleared.

## Viewing history

Use the same policy account to view the most recent receipts:

```bash
sudo -u linux-cache-guard /usr/local/bin/linux-cache-guard \
  --config /etc/linux-cache-guard/config.toml history --limit 20
```

The displayed cache difference is an estimate based on before/after snapshots;
it is not a measurement of bytes freed by the kernel.

## Receipts

Each cleanup attempt writes one JSON line and updates a latest-receipt JSON
file. Receipts include the decision, before/after memory snapshots when a
helper was executed, and the helper exit code. They are operational records,
not a claim that a cache drop solved an application-memory problem.

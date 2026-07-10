# Changelog

## 0.1.3-alpha - 2026-07-11

- Added a root-owned `linux-cache-guard-admin` command and optional,
  user-specific agent sudo policy for status, dry-run, and interval changes.
- Documented the boundary between constrained administration and a future
  signed-release deployment workflow.

## 0.1.2-alpha - 2026-07-11

- Fixed source-installer permission validation so a secure `0644` system
  configuration is accepted rather than mistaken for group-writable.

## 0.1.1-alpha - 2026-07-11

- Added `schedule show` and `schedule set` so an operator can set the systemd
  check interval to values such as `15min`, `30min`, or `1h` without manually
  editing a unit override.

## 0.1.0-alpha - 2026-07-11

- Initial source-install alpha for Ubuntu and WSL systems with Python 3.11+.
- Added a fixed root helper, policy-gated CLI, receipts, pending-cleanup
  recovery, history display, and optional ten-minute systemd timer.
- Automatic cleanup remains disabled until an operator sets both the automatic
  flag and an explicit available-memory pressure limit.

## Compatibility policy

The source installer is not a distribution package. Stable releases will add
explicit upgrade, uninstall, configuration-preservation, and receipt-retention
policies before claiming package-manager support.

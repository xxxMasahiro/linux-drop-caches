# Changelog

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

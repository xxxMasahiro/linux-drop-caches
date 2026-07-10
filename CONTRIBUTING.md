# Contributing

Keep the privileged helper minimal and POSIX-shell compatible. New policy,
logging, scheduling, and user-interface behavior belongs in the unprivileged
Python command.

All changes that affect cleanup decisions require tests for both the allowed
and refused paths. Tests must not call `sudo` or write to `/proc/sys`.

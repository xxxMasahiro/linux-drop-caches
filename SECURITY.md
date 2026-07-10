# Security policy

`linux-drop-caches` contains an optional privileged helper. Please report a
suspected security issue privately to the maintainers before opening a public
issue. Include the installed version, Linux distribution, and a minimal,
sanitized reproduction.

Do not include credentials, private logs, or personally identifiable data.

The intended privilege boundary is narrow: the helper is root-owned, is not
group- or world-writable, accepts no arguments, runs `sync`, and writes `3` to
`/proc/sys/vm/drop_caches`. The user-facing CLI must not be granted broader
passwordless sudo access.

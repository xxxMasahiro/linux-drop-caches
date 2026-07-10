# Agent administration

## Purpose

`linux-cache-guard-admin` is a root-owned command with a deliberately small
interface for an AI agent. It is not a general root shell and it does not run
files from a mutable Git checkout.

The available commands are:

```text
linux-cache-guard-admin status
linux-cache-guard-admin dry-run
linux-cache-guard-admin set-interval <duration>
```

`set-interval` accepts only the duration syntax already validated by
`linux-cache-guard`: for example `30s`, `15min`, `1h`, or `2d`.

## Installing an agent policy

An administrator can install the fixed policy for one existing local user:

```bash
sudo ./scripts/install-system.sh --agent-user AGENT_USER
```

For example, an agent running as `masahiro` can use:

```bash
sudo -n /usr/local/sbin/linux-cache-guard-admin status
sudo -n /usr/local/sbin/linux-cache-guard-admin dry-run
sudo -n /usr/local/sbin/linux-cache-guard-admin set-interval 20min
```

The policy does not permit the agent to enable automatic cleanup, run a real
cleanup, recover a pending cleanup, modify arbitrary systemd units, or execute
an arbitrary command as root.

## Release update boundary

Do not grant an agent passwordless sudo access to `install-system.sh`, a Git
checkout, a package manager, a shell, Python, or `linux-cache-guard` without
fixed arguments. A mutable source tree is not a trusted root deployment
artifact.

The next update layer must accept only a root-owned, integrity-verified release
bundle that has an explicit approval record. Until that signed-release trust
chain is configured, an administrator must perform the source-install update.

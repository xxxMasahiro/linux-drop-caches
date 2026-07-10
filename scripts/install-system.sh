#!/bin/sh
# Install the source checkout into the standard Linux system locations.
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

if [ "$(id -u)" -ne 0 ]; then
  echo "run as root: sudo ./scripts/install-system.sh" >&2
  exit 1
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project_dir=$(dirname "$script_dir")
service_user=linux-cache-guard
helper_path=/usr/local/sbin/linux-drop-caches
library_dir=/usr/local/lib/linux-cache-guard
config_path=/etc/linux-cache-guard/config.toml
python_bin=

for candidate in /usr/bin/python3.13 /usr/bin/python3.12 /usr/bin/python3.11; do
  if [ -x "$candidate" ] && "$candidate" -c 'import sys; raise SystemExit(sys.version_info < (3, 11))'; then
    python_bin=$candidate
    break
  fi
done

if [ -z "$python_bin" ]; then
  echo "Python 3.11 or later is required; install it before linux-drop-caches" >&2
  exit 1
fi

if ! command -v useradd >/dev/null 2>&1; then
  echo "useradd is required for the systemd service account" >&2
  exit 1
fi
if ! command -v getent >/dev/null 2>&1 || ! command -v sudo >/dev/null 2>&1; then
  echo "getent and sudo are required for the systemd service account" >&2
  exit 1
fi
if ! command -v stat >/dev/null 2>&1; then
  echo "stat is required to validate an existing system configuration" >&2
  exit 1
fi

if [ -L "$config_path" ] || { [ -e "$config_path" ] && [ ! -f "$config_path" ]; }; then
  echo "refusing non-regular system configuration: $config_path" >&2
  exit 1
fi
if [ -f "$config_path" ]; then
  config_owner=$(stat -c %u "$config_path")
  config_mode=$(stat -c %a "$config_path")
  config_group_digit=$(( (config_mode / 10) % 10 ))
  config_other_digit=$(( config_mode % 10 ))
  if [ "$config_owner" -ne 0 ] || [ $((config_group_digit & 2)) -ne 0 ] || [ $((config_other_digit & 2)) -ne 0 ]; then
    echo "refusing unsafe system configuration permissions: $config_path" >&2
    exit 1
  fi
fi

if id -u "$service_user" >/dev/null 2>&1; then
  account_line=$(getent passwd "$service_user")
  account_uid=$(printf '%s\n' "$account_line" | awk -F: '{print $3}')
  account_gid=$(printf '%s\n' "$account_line" | awk -F: '{print $4}')
  account_home=$(printf '%s\n' "$account_line" | awk -F: '{print $6}')
  account_shell=$(printf '%s\n' "$account_line" | awk -F: '{print $7}')
  group_gid=$(getent group "$service_user" | awk -F: '{print $3}')
  system_uid_max=$(awk '/^[[:space:]]*SYS_UID_MAX[[:space:]]+/ {print $2; exit}' /etc/login.defs 2>/dev/null || true)
  system_uid_max=${system_uid_max:-999}
  case "$account_shell" in
    /usr/sbin/nologin|/sbin/nologin) ;;
    *)
      echo "refusing existing account with a login shell: $service_user" >&2
      exit 1
      ;;
  esac
  if [ "$account_uid" -gt "$system_uid_max" ] || [ "$account_gid" != "$group_gid" ] || [ "$account_home" != "/var/lib/linux-cache-guard" ]; then
    echo "refusing incompatible existing service account: $service_user" >&2
    exit 1
  fi
else
  useradd --system --user-group --home-dir /var/lib/linux-cache-guard \
    --shell /usr/sbin/nologin "$service_user"
fi

install -d -m 0755 /usr/local/bin "$library_dir" /usr/local/sbin /etc/linux-cache-guard
install -d -m 0750 -o "$service_user" -g "$service_user" /var/lib/linux-cache-guard
rm -rf "$library_dir/linux_cache_guard"
cp -R "$project_dir/src/linux_cache_guard" "$library_dir/"
chown -R root:root "$library_dir/linux_cache_guard"
chmod -R go-w "$library_dir/linux_cache_guard"
sed "s|@PYTHON_BIN@|$python_bin|" "$project_dir/packaging/launcher/linux-cache-guard" \
  >/usr/local/bin/linux-cache-guard
chmod 0755 /usr/local/bin/linux-cache-guard
chown root:root /usr/local/bin/linux-cache-guard
install -m 0755 "$project_dir/src/linux_cache_guard/resources/linux-drop-caches" "$helper_path"
chown root:root "$helper_path"

if [ ! -e "$config_path" ]; then
  install -m 0644 "$project_dir/config/linux-cache-guard.toml" "$config_path"
else
  echo "preserving existing configuration: $config_path"
fi

install -m 0644 "$project_dir/packaging/systemd/linux-cache-guard.service" /etc/systemd/system/linux-cache-guard.service
install -m 0644 "$project_dir/packaging/systemd/linux-cache-guard.timer" /etc/systemd/system/linux-cache-guard.timer
install -m 0440 "$project_dir/packaging/sudoers/linux-cache-guard" /etc/sudoers.d/linux-cache-guard

if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload
else
  echo "systemd is not active; timer installation is deferred"
fi

echo "installed linux-drop-caches; automatic cleanup remains disabled in $config_path"

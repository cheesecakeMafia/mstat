#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_SCRIPT="${SCRIPT_DIR}/mstat"
BIN_DIR="${HOME}/.local/bin"
TARGET_LINK="${BIN_DIR}/mstat"
CONFIG_DIR="${HOME}/.config/mstat"
ALLOWLIST_FILE="${CONFIG_DIR}/allowed-ips.conf"
MACHINES_CONF="${CONFIG_DIR}/machines.conf"

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    printf 'Missing required command: %s\n' "$cmd" >&2
    exit 1
  fi
}

detect_machine() {
  local ip name
  ip="$(tailscale ip -4 2>/dev/null | head -1 | tr -d '\r\n')"
  name="$(hostname -s 2>/dev/null || echo unknown)"
  if [[ -z "$ip" ]]; then
    printf 'Cannot detect Tailscale IPv4 address\n' >&2
    exit 1
  fi
  printf '%s %s' "$ip" "$name"
}

write_machines_conf() {
  local ip="$1"
  local name="$2"
  mkdir -p "$CONFIG_DIR"

  if [[ -f "$MACHINES_CONF" ]]; then
    if grep -q "^${ip}[[:space:]]" "$MACHINES_CONF" 2>/dev/null; then
      printf 'Machine already registered in %s (kept as-is)\n' "$MACHINES_CONF"
      return
    fi
    printf '%s  %s\n' "$ip" "$name" >>"$MACHINES_CONF"
    printf 'Appended %s (%s) to %s\n' "$name" "$ip" "$MACHINES_CONF"
  else
    cat >"$MACHINES_CONF" <<EOF
# machines.conf — maps Tailscale IPs to machine names
# Format: <tailscale_ip> <machine_name>
# Run install.sh on each machine to auto-register it.
${ip}  ${name}
EOF
    chmod 600 "$MACHINES_CONF"
    printf 'Created %s\n' "$MACHINES_CONF"
  fi
}

write_default_allowlist() {
  mkdir -p "$CONFIG_DIR"

  if [[ -f "$ALLOWLIST_FILE" ]]; then
    printf 'Allowlist exists: %s (kept as-is)\n' "$ALLOWLIST_FILE"
    return
  fi

  cat >"$ALLOWLIST_FILE" <<'EOF'
# allowed-ips.conf — Tailscale IPs allowed to SSH into this machine
# One IPv4 address per line. Lines starting with # are comments.
# Example:
# 100.64.0.1  # my-other-machine
EOF
  chmod 600 "$ALLOWLIST_FILE"
  printf 'Created template allowlist: %s\n' "$ALLOWLIST_FILE"
  printf 'Edit %s to add the Tailscale IPs of machines allowed to SSH here.\n' "$ALLOWLIST_FILE"
}

warn_optional_dependency() {
  local cmd="$1"
  local note="$2"
  local pkg="${3:-$cmd}"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    printf 'Warning: optional dependency missing: %s (%s). Install with: sudo apt install %s\n' "$cmd" "$note" "$pkg"
  fi
}

main() {
  require_cmd tailscale

  if [[ ! -f "$SOURCE_SCRIPT" ]]; then
    printf 'Cannot find mstat script at %s\n' "$SOURCE_SCRIPT" >&2
    exit 1
  fi

  mkdir -p "$BIN_DIR"
  ln -snf "$SOURCE_SCRIPT" "$TARGET_LINK"
  chmod +x "$SOURCE_SCRIPT"

  if ! grep -qE '(^|:)\$HOME/\.local/bin($|:)' <<<"${PATH}"; then
    if [[ -f "${HOME}/.bashrc" ]] && ! grep -q 'export PATH="$HOME/.local/bin:$PATH"' "${HOME}/.bashrc"; then
      printf '\nexport PATH="$HOME/.local/bin:$PATH"\n' >>"${HOME}/.bashrc"
      printf 'Updated ~/.bashrc with ~/.local/bin in PATH\n'
    fi
  fi

  local machine_info ip name
  machine_info="$(detect_machine)"
  read -r ip name <<<"$machine_info"

  write_machines_conf "$ip" "$name"
  write_default_allowlist

  warn_optional_dependency speedtest-cli "--full mode speed test"
  warn_optional_dependency fail2ban-client "remediation command integration" fail2ban
  warn_optional_dependency jq "JSON pipeline convenience"

  printf 'Installed mstat -> %s\n' "$TARGET_LINK"
  printf 'Run: mstat --help\n'
}

main "$@"

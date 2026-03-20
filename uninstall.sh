#!/usr/bin/env bash

set -euo pipefail

BIN_LINK="${HOME}/.local/bin/mstat"
CONFIG_DIR="${HOME}/.config/mstat"
ALLOWLIST_FILE="${CONFIG_DIR}/allowed-ips.conf"
PURGE_CONFIG=0

usage() {
  cat <<'EOF'
Usage:
  uninstall.sh [--purge-config]

Options:
  --purge-config   Remove ~/.config/mstat/allowed-ips.conf and empty config dir
  --help           Show help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --purge-config) PURGE_CONFIG=1 ;;
    --help|-h) usage; exit 0 ;;
    *) printf 'Unknown option: %s\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

if [[ -L "$BIN_LINK" || -f "$BIN_LINK" ]]; then
  rm -f "$BIN_LINK"
  printf 'Removed %s\n' "$BIN_LINK"
else
  printf 'No installed mstat found at %s\n' "$BIN_LINK"
fi

if [[ "$PURGE_CONFIG" -eq 1 ]]; then
  if [[ -f "$ALLOWLIST_FILE" ]]; then
    rm -f "$ALLOWLIST_FILE"
    printf 'Removed %s\n' "$ALLOWLIST_FILE"
  fi
  if [[ -d "$CONFIG_DIR" ]] && [[ -z "$(ls -A "$CONFIG_DIR" 2>/dev/null)" ]]; then
    rmdir "$CONFIG_DIR"
    printf 'Removed empty directory %s\n' "$CONFIG_DIR"
  fi
fi

printf 'Uninstall complete.\n'

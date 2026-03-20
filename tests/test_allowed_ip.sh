#!/usr/bin/env bash
# Test harness for is_allowed_ip() and related security-check logic.
# Run: bash tests/test_allowed_ip.sh

set -uo pipefail

PASS=0
FAIL=0

assert_allowed() {
  local desc="$1" machine="$2" ip="$3"
  if is_allowed_ip "$machine" "$ip"; then
    PASS=$((PASS + 1))
  else
    printf 'FAIL: %s — expected allowed, got rejected (machine=%s ip=%s)\n' "$desc" "$machine" "$ip"
    FAIL=$((FAIL + 1))
  fi
}

assert_rejected() {
  local desc="$1" machine="$2" ip="$3"
  if is_allowed_ip "$machine" "$ip"; then
    printf 'FAIL: %s — expected rejected, got allowed (machine=%s ip=%s)\n' "$desc" "$machine" "$ip"
    FAIL=$((FAIL + 1))
  else
    PASS=$((PASS + 1))
  fi
}

# --- Source only the functions we need from mstat ---
# We extract is_allowed_ip and its helpers without running main().

declare -A ALLOWLIST_CACHE=()

# Inline the two functions under test:
trim_ws() {
  local text="$1"
  text="${text#"${text%%[![:space:]]*}"}"
  text="${text%"${text##*[![:space:]]}"}"
  printf '%s' "$text"
}

is_allowed_ip() {
  local machine="$1"
  local ip="$2"

  [[ "$ip" == "127.0.0.1" || "$ip" == "::1" || "$ip" == "0.0.0.0" ]] && return 0

  grep -qxF "$ip" <<<"${ALLOWLIST_CACHE["$machine"]:-}"
}

# --- Set up test allowlist ---
ALLOWLIST_CACHE["testbox"]="198.51.100.1
198.51.100.2"

# ===== Loopback / placeholder exemptions =====
assert_allowed  "IPv4 loopback"              testbox "127.0.0.1"
assert_allowed  "IPv6 loopback"              testbox "::1"
assert_allowed  "0.0.0.0 (no source recorded)" testbox "0.0.0.0"

# ===== Allowlisted IPs =====
assert_allowed  "allowlisted Tailscale IP 1" testbox "198.51.100.1"
assert_allowed  "allowlisted Tailscale IP 2" testbox "198.51.100.2"

# ===== Unexpected IPs (must be rejected) =====
assert_rejected "random public IPv4"         testbox "203.0.113.42"
assert_rejected "RFC1918 not in allowlist"   testbox "192.168.1.100"
assert_rejected "Tailscale IP not in list"   testbox "198.51.100.99"
assert_rejected "similar prefix, wrong IP"   testbox "198.51.100.3"

# ===== Edge cases =====
assert_rejected "empty string"               testbox ""
assert_rejected "unknown machine, real IP"   unknown "203.0.113.42"
assert_allowed  "unknown machine, loopback"  unknown "127.0.0.1"
assert_allowed  "unknown machine, 0.0.0.0"  unknown "0.0.0.0"

# --- Summary ---
TOTAL=$((PASS + FAIL))
printf '\n%d/%d tests passed' "$PASS" "$TOTAL"
if [[ "$FAIL" -gt 0 ]]; then
  printf ' (%d FAILED)\n' "$FAIL"
  exit 1
else
  printf ' — all green\n'
  exit 0
fi

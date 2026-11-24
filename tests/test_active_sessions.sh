#!/usr/bin/env bash
# Test harness for collect_active_sessions().
# Run: bash tests/test_active_sessions.sh

set -uo pipefail

PASS=0
FAIL=0

assert_eq() {
  local desc="$1" expected="$2" actual="$3"
  if [[ "$expected" == "$actual" ]]; then
    PASS=$((PASS + 1))
  else
    printf 'FAIL: %s\n  expected: %s\n  actual:   %s\n' "$desc" "$expected" "$actual"
    FAIL=$((FAIL + 1))
  fi
}

source <(sed '/^main "\$@"/d' "$(dirname "${BASH_SOURCE[0]}")/../mstat")

# Run the real commands against a PATH that holds only stubs and these tools.
STUBS="$(mktemp -d)"
trap 'rm -rf "$STUBS"' EXIT
for tool in awk sed cat; do
  ln -s "$(command -v "$tool")" "$STUBS/$tool"
done
printf '#!%s\ncat "%s/who.out"\n' "$BASH" "$STUBS" >"$STUBS/who"
printf '#!%s\ncat "%s/ss.out"\n' "$BASH" "$STUBS" >"$STUBS/ss"
chmod +x "$STUBS/who" "$STUBS/ss"

run_cmd() {
  PATH="$STUBS" "$BASH" -c "$2"
}

ALLOWLIST_CACHE["testbox"]="100.104.111.13
fd7a:115c:a1e0::1
fe80::1%eth0"

run_sessions_test() {
  METRICS=()
  ALERTS=()
  HEALTH_ISSUE=0
  printf '%s\n' "$1" >"$STUBS/who.out"
  printf '%s\n' "$2" >"$STUBS/ss.out"
  collect_active_sessions testbox
}

# Real line from Ubuntu 26.04: no process column
run_sessions_test "" "0      36     100.85.85.79:22 100.104.111.13:48598"
assert_eq "ss peer without process column is counted" "1" "$(get_metric testbox active_ssh_sessions)"
assert_eq "ss peer on the allowlist is not suspicious" "none" "$(get_metric testbox suspicious_active_ips)"

run_sessions_test "" '0 0 100.85.85.79:22 203.0.113.42:48598 users:(("sshd-session",pid=10,fd=4))'
assert_eq "ss peer with process column is read" "203.0.113.42" "$(get_metric testbox suspicious_active_ips)"
assert_eq "unexpected ss peer raises CRITICAL" "CRITICAL|testbox|Active SSH session from unexpected IP 203.0.113.42 on testbox" "${ALERTS[*]:-}"

run_sessions_test "" "0 0 [fd7a:115c:a1e0::9]:22 [fd7a:115c:a1e0::1]:48598
0 0 [2001:db8::9]:22 [2001:db8::1]:48598"
assert_eq "IPv6 ss peers are counted" "2" "$(get_metric testbox active_ssh_sessions)"
assert_eq "only the IPv6 ss peer off the allowlist is suspicious" "2001:db8::1" "$(get_metric testbox suspicious_active_ips)"

run_sessions_test "" "0 0 [::ffff:100.85.85.79]:22 [::ffff:100.104.111.13]:48598"
assert_eq "IPv4-mapped ss peer is counted" "1" "$(get_metric testbox active_ssh_sessions)"
assert_eq "IPv4-mapped ss peer matches its IPv4 allowlist entry" "none" "$(get_metric testbox suspicious_active_ips)"

run_sessions_test "cheese   pts/0   2026-11-24 12:00   .   1234 (100.104.111.13)" "0 36 100.85.85.79:22 100.104.111.13:48598"
assert_eq "same IP from who and ss is counted once" "1" "$(get_metric testbox active_ssh_sessions)"

# who prints IPv6 without brackets or port
run_sessions_test "cheese   pts/0   2026-11-24 12:00   .   1234 (fd7a:115c:a1e0::1)" "0 0 [fd7a:115c:a1e0::9]:22 [fd7a:115c:a1e0::1]:48598"
assert_eq "same IPv6 from who and ss is counted once" "1" "$(get_metric testbox active_ssh_sessions)"
assert_eq "allowlisted IPv6 from who is not suspicious" "none" "$(get_metric testbox suspicious_active_ips)"

run_sessions_test "cheese   pts/0   2026-11-24 12:00   .   1234 (::1)" ""
assert_eq "IPv6 loopback from who is counted" "1" "$(get_metric testbox active_ssh_sessions)"

# Link-local: ss prints the zone on the local address only, who prints it on the peer
run_sessions_test "cheese   pts/0   2026-11-24 12:00   .   1234 (fe80::1%eth0)" "0 0 [fe80::9]%eth0:22 [fe80::1]:48598"
assert_eq "same link-local peer from who and ss is counted once" "1" "$(get_metric testbox active_ssh_sessions)"
assert_eq "link-local peer with the zone of its entry is not suspicious" "none" "$(get_metric testbox suspicious_active_ips)"

run_sessions_test "" "0 0 [fe80::9]%eth1:22 [fe80::1]:48598
0 0 [fe80::9]:22 [fe80::1]:48599"
assert_eq "link-local peer in another zone or no zone is suspicious" "fe80::1%eth1, fe80::1" "$(get_metric testbox suspicious_active_ips)"

run_sessions_test "" "0 0 [fd7a:115c:a1e0::9]%eth0:22 [fd7a:115c:a1e0::1]:48598"
assert_eq "zone of the local address is not added to a global peer" "none" "$(get_metric testbox suspicious_active_ips)"

# The address forms of ss
assert_eq "normalize IPv4 with port" "1.2.3.4" "$(normalize_ip "1.2.3.4:5")"
assert_eq "normalize IPv6 with port" "fd7a:115c:a1e0::1" "$(normalize_ip "[fd7a:115c:a1e0::1]:5")"
assert_eq "normalize IPv4-mapped IPv6 with port" "1.2.3.4" "$(normalize_ip "[::ffff:1.2.3.4]:5")"
assert_eq "normalize link-local with zone and port" "fe80::1%eth0" "$(normalize_ip "[fe80::1]%eth0:5")"
assert_eq "normalize link-local, zone in brackets" "fe80::1%eth0" "$(normalize_ip "[fe80::1%eth0]:5")"
assert_eq "normalize bare link-local with zone" "fe80::1%eth0" "$(normalize_ip "FE80:0::1%eth0")"
assert_eq "normalize bare IPv6" "fd7a:115c:a1e0::1" "$(normalize_ip "fd7a:115c:a1e0::1")"
assert_eq "normalize bare IPv6 loopback" "::1" "$(normalize_ip "::1")"
assert_eq "normalize IPv6 unspecified" "::" "$(normalize_ip "0:0:0:0:0:0:0:0")"
assert_eq "normalize compresses the first longest zero run" "1::2:3:0:0:4" "$(normalize_ip "1:0:0:2:3:0:0:4")"
assert_eq "normalize keeps a single zero group" "1:0:2:3:4:5:6:7" "$(normalize_ip "1:0:2:3:4:5:6:7")"

TOTAL=$((PASS + FAIL))
printf '\n%d/%d tests passed' "$PASS" "$TOTAL"
if [[ "$FAIL" -gt 0 ]]; then
  printf ' (%d FAILED)\n' "$FAIL"
  exit 1
else
  printf ' — all green\n'
  exit 0
fi

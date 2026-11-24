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

source <(sed '/^main "\$@"/d' "$(dirname "${BASH_SOURCE[0]}")/../mstat")

# --- Set up test allowlist ---
ALLOWLIST_CACHE["testbox"]="198.51.100.1
198.51.100.2
fd7a:115c:a1e0::1
2001:DB8:0000:0:0:0:0:2
::ffff:198.51.100.5
::ffff:1.300.1.1
fe80::1
fe80::2%eth0
FE80:0::3%eth0
not-an-ip"

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

# ===== IPv6: every spelling of an allowlisted address =====
assert_allowed  "IPv6 as written"            testbox "fd7a:115c:a1e0::1"
assert_allowed  "IPv6 uppercase"             testbox "FD7A:115C:A1E0::1"
assert_allowed  "IPv6 expanded"              testbox "fd7a:115c:a1e0:0000:0000:0000:0000:0001"
assert_allowed  "IPv6 entry expanded and uppercase" testbox "2001:db8::2"
assert_allowed  "IPv4-mapped IPv6 of an allowlisted IPv4" testbox "::ffff:198.51.100.1"
assert_allowed  "IPv4-mapped IPv6 in hex"    testbox "::ffff:c633:6401"
assert_allowed  "IPv4 of an IPv4-mapped entry" testbox "198.51.100.5"
assert_allowed  "IPv6 loopback expanded"     testbox "0:0:0:0:0:0:0:1"
assert_rejected "IPv4-mapped entry with an octet above 255" testbox "2.44.1.1"
assert_rejected "other IPv6 in the same prefix" testbox "fd7a:115c:a1e0::2"
assert_rejected "longer IPv6 that starts the same" testbox "fd7a:115c:a1e0::1:1"
assert_rejected "cut IPv6"                   testbox "fd7a:115c:a1e0::"
assert_rejected "IPv6 with two ::"           testbox "fd7a::a1e0::1"
assert_rejected "IPv6 with nine groups"      testbox "fd7a:115c:a1e0:0:0:0:0:0:1"
assert_rejected "IPv6 with a trailing colon"  testbox "fd7a:115c:a1e0:0:0:0:0:1:"
assert_rejected ":: in place of no group"    testbox "fd7a:115c:a1e0:0::0:0:0:1"
assert_rejected "IPv6 unspecified"           testbox "::"
assert_rejected "allowlisted IPv6 with a zone" testbox "fd7a:115c:a1e0::1%eth0"
assert_rejected "IPv4-mapped IPv6 with a zone" testbox "::ffff:198.51.100.1%eth0"
assert_rejected "loopback with a zone"       testbox "::1%eth0"

# A group that is not hex must not reach shell arithmetic
marker="/tmp/mstat-test-marker-$$"
assert_rejected "command in an IPv6 group"   testbox "0:0:0:0:0:0:0:0,x[\$(touch $marker)]=1"
if [[ -e "$marker" ]]; then
  printf 'FAIL: command in an IPv6 group was executed\n'
  FAIL=$((FAIL + 1))
  rm -f "$marker"
else
  PASS=$((PASS + 1))
fi

# ===== Link-local: the zone must be known and must match =====
assert_allowed  "link-local, same zone"      testbox "fe80::2%eth0"
assert_allowed  "link-local, same zone, other spelling" testbox "fe80::3%eth0"
assert_rejected "link-local, other zone"     testbox "fe80::2%eth1"
assert_rejected "link-local, zone in other case" testbox "fe80::2%ETH0"
assert_rejected "link-local without zone, entry with zone" testbox "fe80::2"
assert_rejected "link-local with zone, entry without zone" testbox "fe80::1%eth0"
assert_rejected "link-local without zone, entry without zone" testbox "fe80::1"

# ===== Edge cases =====
assert_rejected "empty string"               testbox ""
assert_rejected "unknown machine, empty string" unknown ""
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

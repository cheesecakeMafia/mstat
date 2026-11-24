#!/usr/bin/env bash
# Test harness for collect_security_metrics().
# Run: bash tests/test_security_metrics.sh

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
for tool in awk sed cat grep head wc find; do
  ln -s "$(command -v "$tool")" "$STUBS/$tool"
done

cat >"$STUBS/systemctl" <<EOF
#!$BASH
cat "$STUBS/units"
EOF

# Like journalctl: -o cat prints the message only, and no output still exits 0.
# The sudo caller sees journal.out, the plain user sees journal.user.
# A line marked "~" is not from root, a line marked "<" is older than any --since.
cat >"$STUBS/journalctl" <<EOF
#!$BASH
printf '%s\n' "\$*" >>"$STUBS/journal.args"
if [[ "\$*" == *"short-unix"* ]]; then
  # The user journal reaches further back than the system journal
  [[ "\$*" == *"_UID=0"* ]] || echo "1000000000.000000 testbox app[1]: x"
  sed 's/\$/.123456 testbox kernel: x/' "$STUBS/journal.oldest"
  exit 0
fi
if [[ "\$AS_ROOT" -eq 1 ]]; then
  src="$STUBS/journal.out"
  [[ -f "\$src" ]] || exit 1
else
  src="$STUBS/journal.user"
  [[ -f "\$src" ]] || exit 0
fi
filter=()
[[ "\$*" == *"_UID=0"* ]] && filter+=(-e '/^~/d')
[[ "\$*" == *"--since"* ]] && filter+=(-e '/^</d')
filter+=(-e 's/^[~<]//')
[[ "\$*" == *"-o cat"* ]] && filter+=(-e 's/^[^]]*\]: //')
if [[ "\$*" == *"-n 1 "* ]]; then
  sed -E "\${filter[@]}" "\$src" | sed -n '\$p'
else
  sed -E "\${filter[@]}" "\$src"
fi
exit "\$(cat "$STUBS/journal.rc")"
EOF

# The clock stands still. A date without a year is of the current year, as with the real date.
NOW="$(date -d '2026-11-24 12:00:00' +%s)"
cat >"$STUBS/date" <<EOF
#!$BASH
now="\$(cat "$STUBS/now")"
if [[ "\$1" != "-d" ]]; then
  exec "$(command -v date)" -d "@\$now" "\$@"
elif [[ "\$2" == *" days ago" ]]; then
  exec "$(command -v date)" -d "\$("$(command -v date)" -d "@\$now" '+%F %T') \$2" "\$3"
elif [[ "\$2" == [A-Z]* ]]; then
  exec "$(command -v date)" -d "\$2 \$("$(command -v date)" -d "@\$now" +%Y)" "\$3"
fi
exec "$(command -v date)" "\$@"
EOF

# stat -c %W / and stat -Lc %Y /etc/machine-id
cat >"$STUBS/stat" <<EOF
#!$BASH
if [[ "\$*" == *"%W /" ]]; then cat "$STUBS/root.birth"; else cat "$STUBS/machine-id.time"; fi
EOF
chmod +x "$STUBS/systemctl" "$STUBS/journalctl" "$STUBS/date" "$STUBS/stat"

# Days before the standing clock
days_ago() {
  echo $((NOW - $1 * 86400))
}
echo "$NOW" >"$STUBS/now"
# The date of last for some days before the standing clock
iso_days_ago() {
  date -d "@$(days_ago "$1")" +%Y-%m-%dT%H:%M:%S%:z
}
days_ago 60 >"$STUBS/journal.oldest"
days_ago 300 >"$STUBS/root.birth"
days_ago 300 >"$STUBS/machine-id.time"
printf '\nwtmp begins %s\n' "$(iso_days_ago 60)" >"$STUBS/last.begins"

SUDO_OK=1
echo 0 >"$STUBS/journal.rc"

mkdir -p "$STUBS/var/id" "$STUBS/run"
: >"$STUBS/var/id/system.journal"

run_cmd() {
  local cmd="${2//\{\/var,\/run\}\/log\/journal/$STUBS/\{var,run\}}"
  AS_ROOT=0 PATH="$STUBS" "$BASH" -c "${cmd//\/var\/log\/auth.log/$STUBS/user.auth.log}"
}

run_privileged_cmd() {
  echo "$2" >>"$STUBS/sudo.calls"
  [[ "$SUDO_OK" -eq 1 ]] || return 1
  AS_ROOT=1 PATH="$STUBS" "$BASH" -c "${2//\/var\/log\/auth.log/$STUBS/auth.log}"
}

# Arguments: output of last ("-" = last is not installed, "FAIL" = last exits 1), journal lines ("-" = journalctl fails),
# auth.log lines (not given = no file), auth.log.1 lines (not given = one old line, "-" = no file).
# USER_AUTH=1 lets the user read auth.log without sudo. USER_JOURNAL holds the journal lines that the user sees without sudo.
USER_AUTH=0
USER_JOURNAL=""
run_security_test() {
  METRICS=()
  ALERTS=()
  WARNINGS=()
  HEALTH_ISSUE=0
  RUNTIME_ERROR=0
  INCOMPLETE=0
  rm -f "$STUBS/last" "$STUBS/journal.out" "$STUBS/journal.args" "$STUBS/journal.user" "$STUBS/sudo.calls" "$STUBS/"{,user.}auth.log{,.1}
  if [[ "$1" != "-" ]]; then
    printf '%s\n' "$1" >"$STUBS/last.out"
    printf '#!%s\nprintf "%%s" "$*" >"%s/last.args"\ncat "%s/last.out" "%s/last.begins"\n[[ "$(cat "%s/last.out")" != FAIL ]]\n' "$BASH" "$STUBS" "$STUBS" "$STUBS" "$STUBS" >"$STUBS/last"
    chmod +x "$STUBS/last"
  fi
  if [[ "$2" != "-" ]]; then
    printf '%s' "${2:+$2$'\n'}" >"$STUBS/journal.out"
  fi
  if [[ -n "$USER_JOURNAL" ]]; then
    printf '%s\n' "$USER_JOURNAL" >"$STUBS/journal.user"
  fi
  if [[ $# -ge 3 ]]; then
    printf '%s' "${3:+$3$'\n'}" >"$STUBS/auth.log"
    [[ "${4:-}" == "-" ]] || printf '%s\n' "${4:-Nov 10 10:00:00 testbox CRON[1]: x}" >"$STUBS/auth.log.1"
    [[ "$USER_AUTH" -eq 0 ]] || for f in "$STUBS"/auth.log*; do ln -s "$f" "$STUBS/user.${f##*/}"; done
  fi
  collect_security_metrics testbox 2>/dev/null
}

ALLOWLIST_CACHE["testbox"]="100.104.111.13
fd7a:115c:a1e0::1"
printf 'ssh.service enabled enabled\n' >"$STUBS/units"

# ===== Failed logins =====
P="Nov 24 10:00:00 testbox sshd[123]:"
run_security_test "" "$P Failed password for invalid user x from 1.2.3.4 port 5 ssh2
$P Failed password for root from 1.2.3.4 port 6 ssh2"
assert_eq "failed logins from IPv4 are counted" "1.2.3.4:2" "$(get_metric testbox failed_ssh_attempts_7d)"

run_security_test "" "$P Invalid user x from fd7a:115c:a1e0::1 port 5
$P Failed password for invalid user x from fd7a:115c:a1e0::1 port 5 ssh2
$P Failed password for root from fe80::1%eth0 port 22 ssh2
$P Failed password for root from 2001:db8::1 port 22 ssh2"
assert_eq "failed logins from IPv6 are counted in brackets" "[2001:db8::1]:1, [fd7a:115c:a1e0::1]:2, [fe80::1%eth0]:1" "$(get_metric testbox failed_ssh_attempts_7d)"

run_security_test "" "$P Invalid user x from 9.9.9.9 from 1.2.3.4 port 5
$P Failed password for invalid user x from 9.9.9.9 port 7 ssh2 from 1.2.3.4 port 5 ssh2
$P Invalid user x from 2001:db8::9 port 7 from 1.2.3.4 port 5"
assert_eq "address inside a hostile username is not counted" "1.2.3.4:3" "$(get_metric testbox failed_ssh_attempts_7d)"

run_security_test "" "$P Connection closed by invalid user Failed password for x from 9.9.9.9 port 7 1.2.3.4 port 5 [preauth]
$P Connection closed by invalid user Invalid user x from 1.2.3.4 port 5 [preauth]
$P Disconnecting invalid user x from 9.9.9.9 port 7 1.2.3.4 port 5: Too many authentication failures [preauth]"
assert_eq "hostile username in another message is not counted" "none" "$(get_metric testbox failed_ssh_attempts_7d)"

run_security_test "" "2026-11-24T10:00:00.123456+05:30 testbox sshd-session[123]: message repeated 2 times: [ Failed password for root from 1.2.3.4 port 5 ssh2]"
assert_eq "repeated-message line is counted once" "1.2.3.4:1" "$(get_metric testbox failed_ssh_attempts_7d)"

run_security_test "" "$P Server listening on 0.0.0.0 port 22."
assert_eq "failed: readable journal without failed logins means none" "none" "$(get_metric testbox failed_ssh_attempts_7d)"

run_security_test "" "-" "$P Failed password for root from 1.2.3.4 port 5 ssh2"
assert_eq "failed: journal failure falls back to auth.log" "1.2.3.4:1 (auth.log)" "$(get_metric testbox failed_ssh_attempts_7d)"

run_security_test "" "" "$P Failed password for root from 1.2.3.4 port 5 ssh2"
assert_eq "failed: empty journal falls back to auth.log" "1.2.3.4:1 (auth.log)" "$(get_metric testbox failed_ssh_attempts_7d)"

run_security_test "" "-" "$P Server listening on 0.0.0.0 port 22."
assert_eq "failed: auth.log without failed logins means none" "none (auth.log)" "$(get_metric testbox failed_ssh_attempts_7d)"

run_security_test "" "-"
assert_eq "failed: no journal and no auth.log is unavailable" "[unavailable]" "$(get_metric testbox failed_ssh_attempts_7d)"

run_security_test "" ""
assert_eq "failed: empty journal and no auth.log is unavailable" "[unavailable]" "$(get_metric testbox failed_ssh_attempts_7d)"

run_security_test "" "$P Failed password for root from 1.2.3.4 port 5 ssh2" "$P Failed password for root from 5.6.7.8 port 5 ssh2"
assert_eq "failed: journal and auth.log are not added together" "1.2.3.4:1" "$(get_metric testbox failed_ssh_attempts_7d)"

echo 1 >"$STUBS/journal.rc"
run_security_test "" "$P Failed password for root from 1.2.3.4 port 5 ssh2" "$P Failed password for root from 5.6.7.8 port 5 ssh2"
assert_eq "failed: partial journal output is replaced by auth.log" "5.6.7.8:1 (auth.log)" "$(get_metric testbox failed_ssh_attempts_7d)"
echo 0 >"$STUBS/journal.rc"

SUDO_OK=0
run_security_test "" "$P Failed password for root from 1.2.3.4 port 5 ssh2" ""
assert_eq "failed: no sudo requires sudo" "[requires sudo]" "$(get_metric testbox failed_ssh_attempts_7d)"
SUDO_OK=1

# ===== Login history with last =====
run_security_test "cheese   pts/0        203.0.113.42     Mon Nov 23 15:06   still logged in
cheese   seat0        198.51.100.7     Mon Nov 23 15:06   still logged in
cheese   pts/1        100.104.111.13   Mon Nov 23 15:06   still logged in" "-"
assert_eq "last: only the unexpected pts/ IP is reported" "203.0.113.42" "$(get_metric testbox suspicious_login_history_ips)"

# last cuts an address at 16 characters without -w
run_security_test "cheese   pts/0        2001:db8:1:2:3:4:5:6 Mon Nov 23 15:06   still logged in
cheese   pts/1        fd7a:115c:a1e0::1 Mon Nov 23 15:06 - 15:07  (00:01)
cheese   pts/2        ::1              Mon Nov 23 15:06 - 15:07  (00:01)" "-"
assert_eq "last: only the unexpected IPv6 is reported" "2001:db8:1:2:3:4:5:6" "$(get_metric testbox suspicious_login_history_ips)"
assert_eq "last: full addresses are requested" "-i -w -n 100 --time-format iso" "$(cat "$STUBS/last.args")"

run_security_test "reboot   system boot  0.0.0.0          Mon Nov 23 15:06   still running" "-"
assert_eq "last: no pts/ lines means none" "none" "$(get_metric testbox suspicious_login_history_ips)"
assert_eq "last: the journal is not used for history" "0" "$(grep -c -- '30 days ago' "$STUBS/journal.args")"

# ===== Login history without last =====
P="Nov 24 10:00:00 testbox sshd-session[123]:"
run_security_test "-" "$P Accepted publickey for cheese from 100.104.111.13 port 60700 ssh2: ED25519 SHA256:abc
$P Accepted publickey for cheese from fd7a:115c:a1e0::1 port 60700 ssh2: ED25519 SHA256:abc"
assert_eq "journal: allowlisted IPv4 and IPv6 logins mean none" "none" "$(get_metric testbox suspicious_login_history_ips)"
assert_eq "journal: reads the ssh unit for 30 days" "1" "$(grep -c -- "-u ssh --since 30 days ago" "$STUBS/journal.args")"

run_security_test "-" "$P Accepted publickey for cheese from 100.104.111.13 port 60700 ssh2: ED25519 SHA256:abc
$P Accepted publickey for cheese from 203.0.113.42 port 60700 ssh2: ED25519 SHA256:abc
$P Accepted password for cheese from 203.0.113.42 port 60701 ssh2
$P Accepted keyboard-interactive/pam for cheese from 203.0.113.43 port 60702 ssh2
$P Accepted password for cheese from 2001:db8::1 port 60703 ssh2
$P Invalid user Accepted password for x from 9.9.9.9 port 1 ssh2 from 1.2.3.4 port 5"
assert_eq "journal: unexpected IPv4 and IPv6 logins are reported once each" "2001:db8::1, 203.0.113.42, 203.0.113.43" "$(get_metric testbox suspicious_login_history_ips)"
assert_eq "journal: one alert for each unexpected IP" "3" "${#ALERTS[@]}"

run_security_test "-" "$P Server listening on 0.0.0.0 port 22."
assert_eq "journal: readable without logins means none" "none" "$(get_metric testbox suspicious_login_history_ips)"

run_security_test "-" "-"
assert_eq "journal: journalctl failure is unavailable" "[unavailable]" "$(get_metric testbox suspicious_login_history_ips)"

run_security_test "-" ""
assert_eq "journal: empty journal is unavailable" "[unavailable]" "$(get_metric testbox suspicious_login_history_ips)"

echo 1 >"$STUBS/journal.rc"
run_security_test "-" "$P Server listening on 0.0.0.0 port 22."
assert_eq "journal: failure after partial output is unavailable" "[unavailable]" "$(get_metric testbox suspicious_login_history_ips)"
echo 0 >"$STUBS/journal.rc"

SUDO_OK=0
run_security_test "-" "$P Accepted password for cheese from 203.0.113.42 port 60701 ssh2"
assert_eq "journal: no sudo requires sudo" "[requires sudo]" "$(get_metric testbox suspicious_login_history_ips)"
SUDO_OK=1

: >"$STUBS/units"
run_security_test "-" "$P Accepted password for cheese from 203.0.113.42 port 60701 ssh2"
assert_eq "journal: no ssh unit is unavailable" "[unavailable]" "$(get_metric testbox suspicious_login_history_ips)"

# ===== last is installed but fails (no wtmp) =====
printf 'ssh.service enabled enabled\n' >"$STUBS/units"
run_security_test "FAIL" "-"
assert_eq "last: failure with no journal is unavailable" "[unavailable]" "$(get_metric testbox suspicious_login_history_ips)"

# ===== Any line of the unit makes the journal readable, from any date =====
printf 'ssh.service enabled enabled\n' >"$STUBS/units"
run_security_test "-" "<$P Server listening on 0.0.0.0 port 22."
assert_eq "old line: history without recent lines means none" "none" "$(get_metric testbox suspicious_login_history_ips)"
assert_eq "old line: failed without recent lines means none" "none" "$(get_metric testbox failed_ssh_attempts_7d)"

run_security_test "-" "<$P Accepted password for cheese from 203.0.113.42 port 60701 ssh2
<$P Failed password for root from 1.2.3.4 port 5 ssh2"
assert_eq "old line: login before the window is not reported" "none" "$(get_metric testbox suspicious_login_history_ips)"
assert_eq "old line: failure before the window is not counted" "none" "$(get_metric testbox failed_ssh_attempts_7d)"

# ===== Journal without sudo =====
LINES_SEEN="$P Accepted password for cheese from 203.0.113.42 port 60701 ssh2
$P Failed password for root from 1.2.3.4 port 5 ssh2"
SUDO_OK=0
USER_JOURNAL="$LINES_SEEN"
run_security_test "-" "-"
assert_eq "no sudo: history from the user's own journal access" "203.0.113.42" "$(get_metric testbox suspicious_login_history_ips)"
assert_eq "no sudo: failed logins from the user's own journal access" "1.2.3.4:1" "$(get_metric testbox failed_ssh_attempts_7d)"
assert_eq "no sudo: sudo is not called" "no" "$([[ -e "$STUBS/sudo.calls" ]] && echo yes || echo no)"

USER_JOURNAL="$P Server listening on 0.0.0.0 port 22."
run_security_test "-" "-"
assert_eq "no sudo: readable without logins means none" "none" "$(get_metric testbox suspicious_login_history_ips)"
assert_eq "no sudo: readable without failed logins means none" "none" "$(get_metric testbox failed_ssh_attempts_7d)"

# The user sees lines of the unit, but none from root
USER_JOURNAL="~$P Accepted password for cheese from 100.104.111.13 port 60701 ssh2
~$P Failed password for root from 9.9.9.9 port 5 ssh2"
run_security_test "-" "-"
assert_eq "own lines only: history requires sudo" "[requires sudo]" "$(get_metric testbox suspicious_login_history_ips)"
assert_eq "own lines only: failed logins require sudo" "[requires sudo]" "$(get_metric testbox failed_ssh_attempts_7d)"

SUDO_OK=1
run_security_test "-" "$LINES_SEEN"
assert_eq "own lines only: history comes from sudo" "203.0.113.42" "$(get_metric testbox suspicious_login_history_ips)"
assert_eq "own lines only: failed logins come from sudo" "1.2.3.4:1" "$(get_metric testbox failed_ssh_attempts_7d)"

USER_JOURNAL=""
run_security_test "-" "$LINES_SEEN"
assert_eq "no lines without sudo: history comes from sudo" "203.0.113.42" "$(get_metric testbox suspicious_login_history_ips)"
assert_eq "no lines without sudo: failed logins come from sudo" "1.2.3.4:1" "$(get_metric testbox failed_ssh_attempts_7d)"

SUDO_OK=0
USER_JOURNAL="$P Server listening on 0.0.0.0 port 22."
echo 1 >"$STUBS/journal.rc"
run_security_test "-" "-"
assert_eq "no sudo: journalctl failure requires sudo" "[requires sudo] [requires sudo]" "$(get_metric testbox suspicious_login_history_ips) $(get_metric testbox failed_ssh_attempts_7d)"
echo 0 >"$STUBS/journal.rc"

# root can read every file, so this case needs a plain user
if [[ "$EUID" -ne 0 ]]; then
  for closed in "$STUBS/var/id/system@old.journal" "$STUBS/run/id"; do
    mkdir -p "$STUBS/run/id"
    [[ -d "$closed" ]] || : >"$closed"
    chmod 000 "$closed"
    run_security_test "-" "-"
    assert_eq "closed system journal ${closed#"$STUBS"}: history and failed logins require sudo" "[requires sudo] [requires sudo]" "$(get_metric testbox suspicious_login_history_ips) $(get_metric testbox failed_ssh_attempts_7d)"
    chmod 700 "$closed"
  done
fi
SUDO_OK=1
USER_JOURNAL=""

# ===== Journal that does not cover the window =====
WARN_HISTORY="suspicious_login_history_ips on testbox: journal covers 4h, the window is 30d"
WARN_FAILED="failed_ssh_attempts_7d on testbox: journal covers 4h, the window is 7d"
echo $((NOW - 4 * 3600 - 1800)) >"$STUBS/journal.oldest"
run_security_test "-" "$P Server listening on 0.0.0.0 port 22."
assert_eq "short journal: history none shows the coverage" "none (journal covers 4h)" "$(get_metric testbox suspicious_login_history_ips)"
assert_eq "short journal: failed none shows the coverage" "none (journal covers 4h)" "$(get_metric testbox failed_ssh_attempts_7d)"
assert_eq "short journal: one warning for each metric" "$WARN_HISTORY $WARN_FAILED" "${WARNINGS[*]:-}"
assert_eq "short journal: incomplete on an older system" "1" "$INCOMPLETE"

run_security_test "-" "$LINES_SEEN"
assert_eq "short journal: history value shows the coverage" "203.0.113.42 (journal covers 4h)" "$(get_metric testbox suspicious_login_history_ips)"
assert_eq "short journal: failed value shows the coverage" "1.2.3.4:2 (journal covers 4h)" "$(run_security_test "-" "$LINES_SEEN
$P Failed password for root from 1.2.3.4 port 6 ssh2"; get_metric testbox failed_ssh_attempts_7d)"

run_security_test "cheese   pts/0        100.104.111.13   Mon Nov 23 15:06   still logged in" "$LINES_SEEN"
assert_eq "short journal: history from last has no journal coverage" "none" "$(get_metric testbox suspicious_login_history_ips)"

days_ago 10 >"$STUBS/journal.oldest"
run_security_test "-" "$P Server listening on 0.0.0.0 port 22."
assert_eq "10 days of journal: short for the history only" "none (journal covers 10d) none" "$(get_metric testbox suspicious_login_history_ips) $(get_metric testbox failed_ssh_attempts_7d)"

for oldest in "" "$((NOW + 3600))" "garbage"; do
  echo "$oldest" >"$STUBS/journal.oldest"
  run_security_test "-" "$P Server listening on 0.0.0.0 port 22."
  assert_eq "oldest entry '$oldest': coverage is unknown and incomplete" "none (journal coverage unknown) 1" "$(get_metric testbox failed_ssh_attempts_7d) $INCOMPLETE"
done

assert_eq "no coverage line: coverage is unknown" "none (journal coverage unknown)" "$(set_log_metric testbox no_coverage_line none 7 "__SOURCE__ journal"; get_metric testbox no_coverage_line)"

assert_eq "age in minutes" "59m" "$(format_age 3599)"
assert_eq "age in hours" "47h" "$(format_age 172799)"
assert_eq "age in days" "2d" "$(format_age 259199)"

# The result stays complete only if / and the machine ID are both known to be younger than the window
echo $((NOW - 4 * 3600)) >"$STUBS/journal.oldest"
while read -r root_birth id_time expected; do
  echo "$root_birth" >"$STUBS/root.birth"
  echo "$id_time" >"$STUBS/machine-id.time"
  run_security_test "-" "$P Server listening on 0.0.0.0 port 22."
  assert_eq "install dates '$root_birth' '$id_time'" "$expected none (journal covers 4h)" "$INCOMPLETE $(get_metric testbox failed_ssh_attempts_7d)"
done <<EOF
$(days_ago 2) $(days_ago 2) 0
$(days_ago 6) $(days_ago 6) 0
$(days_ago 8) $(days_ago 2) 1
$(days_ago 2) $(days_ago 8) 1
0 $(days_ago 2) 1
- $(days_ago 2) 1
$(days_ago 2) ? 1
$(days_ago -2) $(days_ago 2) 1
EOF
: >"$STUBS/root.birth"
: >"$STUBS/machine-id.time"
run_security_test "-" "$P Server listening on 0.0.0.0 port 22."
assert_eq "install dates empty" "1" "$INCOMPLETE"

days_ago 2 >"$STUBS/root.birth"
days_ago 2 >"$STUBS/machine-id.time"
run_security_test "-" "$P Server listening on 0.0.0.0 port 22."
assert_eq "new system: still warns" "$WARN_HISTORY $WARN_FAILED" "${WARNINGS[*]:-}"
days_ago 300 >"$STUBS/root.birth"
days_ago 300 >"$STUBS/machine-id.time"
days_ago 60 >"$STUBS/journal.oldest"

# ===== auth.log without sudo, and its window =====
SUDO_OK=0
USER_AUTH=1
A="2026-11-24T10:00:00.123456+00:00 testbox sshd[123]:"
run_security_test "" "-" "$A Failed password for root from 1.2.3.4 port 5 ssh2"
assert_eq "auth.log: read without sudo" "1.2.3.4:1 (auth.log)" "$(get_metric testbox failed_ssh_attempts_7d)"

run_security_test "" "-" "$A Server listening on 0.0.0.0 port 22." "2026-11-10T10:00:00.123456+00:00 testbox CRON[1]: x"
assert_eq "auth.log: covered window without failed logins means none" "none (auth.log) 0" "$(get_metric testbox failed_ssh_attempts_7d) $INCOMPLETE"

run_security_test "" "-" "$A Failed password for root from 1.2.3.4 port 5 ssh2" "2026-11-10T10:00:00.123456+00:00 testbox sshd[1]: Failed password for root from 9.9.9.9 port 5 ssh2
2026-11-18T10:00:00.123456+00:00 testbox sshd[1]: Failed password for root from 5.6.7.8 port 5 ssh2"
assert_eq "auth.log: auth.log.1 is read, lines before the window are not counted" "1.2.3.4:1, 5.6.7.8:1 (auth.log)" "$(get_metric testbox failed_ssh_attempts_7d)"

run_security_test "" "-" "$P Failed password for root from 1.2.3.4 port 5 ssh2" "Nov 10 10:00:00 testbox sshd[1]: Failed password for root from 9.9.9.9 port 5 ssh2
Nov 18 10:00:00 testbox sshd[1]: Failed password for root from 5.6.7.8 port 5 ssh2"
assert_eq "auth.log: the same for dates without a year" "1.2.3.4:1, 5.6.7.8:1 (auth.log)" "$(get_metric testbox failed_ssh_attempts_7d)"

run_security_test "" "-" "$P Server listening on 0.0.0.0 port 22.
?? testbox sshd[1]: Failed password for root from 1.2.3.4 port 5 ssh2"
assert_eq "auth.log: a line without a usable date is counted" "1.2.3.4:1 (auth.log)" "$(get_metric testbox failed_ssh_attempts_7d)"

run_security_test "" "-" "Nov 23 11:00:00 testbox CRON[1]: x
$P Server listening on 0.0.0.0 port 22." "-"
assert_eq "auth.log: short coverage is shown (no year)" "none (auth.log covers 25h) 1" "$(get_metric testbox failed_ssh_attempts_7d) $INCOMPLETE"
assert_eq "auth.log: short coverage warns" "failed_ssh_attempts_7d on testbox: auth.log covers 25h, the window is 7d" "${WARNINGS[*]:-}"

run_security_test "" "-" "$(date -d "@$(days_ago 3)" +%Y-%m-%dT%H:%M:%S.123456%:z) testbox CRON[1]: x
$A Failed password for root from 1.2.3.4 port 5 ssh2" "-"
assert_eq "auth.log: short coverage is shown" "1.2.3.4:1 (auth.log covers 3d)" "$(get_metric testbox failed_ssh_attempts_7d)"

run_security_test "" "-" "$A Server listening on 0.0.0.0 port 22." "?? testbox CRON[1]: x"
assert_eq "auth.log: unknown coverage is shown" "none (auth.log coverage unknown) 1" "$(get_metric testbox failed_ssh_attempts_7d) $INCOMPLETE"

run_security_test "" "-" "$A Server listening on 0.0.0.0 port 22." "Nov 25 10:00:00 testbox CRON[1]: x"
assert_eq "auth.log: oldest line in the near future is unknown coverage" "none (auth.log coverage unknown)" "$(get_metric testbox failed_ssh_attempts_7d)"

# Over the new year, without a year in the dates
date -d '2027-01-03 12:00:00' +%s >"$STUBS/now"
run_security_test "" "-" "Jan  2 10:00:00 testbox sshd[1]: Failed password for root from 1.2.3.4 port 5 ssh2" "Dec 20 10:00:00 testbox sshd[1]: Failed password for root from 9.9.9.9 port 5 ssh2
Dec 29 10:00:00 testbox sshd[1]: Failed password for root from 5.6.7.8 port 5 ssh2"
assert_eq "auth.log: window over the new year" "1.2.3.4:1, 5.6.7.8:1 (auth.log)" "$(get_metric testbox failed_ssh_attempts_7d)"
echo "$NOW" >"$STUBS/now"

run_security_test "" "-" "2026-11-24T10:00:00.123456+00:00 testbox sudo[1]: COMMAND=/bin/grep sshd[1]: x"
assert_eq "auth.log: no line of sshd requires sudo" "[requires sudo]" "$(get_metric testbox failed_ssh_attempts_7d)"
SUDO_OK=1
run_security_test "" "-" "2026-11-24T10:00:00.123456+00:00 testbox sudo[1]: COMMAND=/bin/grep sshd[1]: x"
assert_eq "auth.log: no line of sshd with sudo is unavailable" "[unavailable]" "$(get_metric testbox failed_ssh_attempts_7d)"
run_security_test "" "-" "2026-11-24T10:00:00.123456+00:00 testbox sshd-session[1]: x"
assert_eq "auth.log: sshd-session is a line of sshd" "none (auth.log)" "$(get_metric testbox failed_ssh_attempts_7d)"
run_security_test "" "-" "" "$A x"
assert_eq "auth.log: empty after rotation is unavailable" "[unavailable]" "$(get_metric testbox failed_ssh_attempts_7d)"

# A log that nothing writes to any more
run_security_test "" "-" "$A Server listening on 0.0.0.0 port 22."
touch -d '2 days ago' "$STUBS/auth.log"
collect_security_metrics testbox 2>/dev/null
assert_eq "auth.log: not written for two days is unavailable" "[unavailable]" "$(get_metric testbox failed_ssh_attempts_7d)"

# ===== The source with the longer coverage =====
SUDO_OK=0
USER_AUTH=1
CRON_25H="$(date -d "@$((NOW - 25 * 3600))" +%Y-%m-%dT%H:%M:%S.123456%:z) testbox CRON[1]: x"
A_FAILED="$A Failed password for root from 1.2.3.4 port 5 ssh2"
J_FAILED="$P Failed password for root from 1.2.3.4 port 5 ssh2"
OLD_LINE="$(date -d "@$((NOW - 14 * 86400 - 3600))" +%Y-%m-%dT%H:%M:%S.123456%:z) testbox CRON[1]: x"

echo $((NOW - 4 * 3600)) >"$STUBS/journal.oldest"
USER_JOURNAL="$P Server listening on 0.0.0.0 port 22."
run_security_test "" "-" "$A_FAILED" "$OLD_LINE"
assert_eq "sources: auth.log covers the window, the journal does not" "1.2.3.4:1 (auth.log) 0" "$(get_metric testbox failed_ssh_attempts_7d) $INCOMPLETE"
assert_eq "sources: no warning when auth.log covers the window" "" "${WARNINGS[*]:-}"

run_security_test "" "-" "$CRON_25H
$A_FAILED" "-"
assert_eq "sources: auth.log is short but longer than the journal" "1.2.3.4:1 (auth.log covers 25h) 1" "$(get_metric testbox failed_ssh_attempts_7d) $INCOMPLETE"
assert_eq "sources: the warning names auth.log" "failed_ssh_attempts_7d on testbox: auth.log covers 25h, the window is 7d" "${WARNINGS[*]:-}"

days_ago 3 >"$STUBS/journal.oldest"
run_security_test "" "-" "$CRON_25H
$A Server listening on 0.0.0.0 port 22." "-"
assert_eq "sources: the journal is short but longer than auth.log" "none (journal covers 3d)" "$(get_metric testbox failed_ssh_attempts_7d)"

run_security_test "" "-" "$CRON_25H
$A_FAILED" "-"
assert_eq "sources: a failure only in the shorter source is not lost" "1.2.3.4:1 (journal covers 3d)" "$(get_metric testbox failed_ssh_attempts_7d)"

: >"$STUBS/journal.oldest"
run_security_test "" "-" "$CRON_25H
$A Server listening on 0.0.0.0 port 22." "-"
assert_eq "sources: known coverage goes before unknown" "none (auth.log covers 25h)" "$(get_metric testbox failed_ssh_attempts_7d)"
run_security_test "" "-" "?? testbox CRON[1]: x
$A Server listening on 0.0.0.0 port 22." "-"
assert_eq "sources: both unknown" "none (journal coverage unknown)" "$(get_metric testbox failed_ssh_attempts_7d)"

# The same lines in both sources are not added together
echo $((NOW - 4 * 3600)) >"$STUBS/journal.oldest"
USER_JOURNAL="$J_FAILED
$P Failed password for root from 1.2.3.4 port 6 ssh2
$P Failed password for root from 5.6.7.8 port 6 ssh2
$P Failed password for root from 5.6.7.8 port 7 ssh2"
run_security_test "" "-" "$A_FAILED
$A Failed password for root from 5.6.7.8 port 6 ssh2
$A Failed password for root from 1.2.3.4 port 6 ssh2
$A Failed password for root from 1.2.3.4 port 7 ssh2
$A Failed password for root from 2001:db8::1 port 7 ssh2" "$OLD_LINE"
assert_eq "sources: the higher count of each address" "1.2.3.4:3, [2001:db8::1]:1, 5.6.7.8:2 (auth.log)" "$(get_metric testbox failed_ssh_attempts_7d)"

days_ago 60 >"$STUBS/journal.oldest"
USER_JOURNAL="$J_FAILED"
run_security_test "" "-" "$A Failed password for root from 5.6.7.8 port 5 ssh2" "$OLD_LINE"
assert_eq "sources: a journal that covers the window is enough" "1.2.3.4:1" "$(get_metric testbox failed_ssh_attempts_7d)"

# Login history without last
echo $((NOW - 4 * 3600)) >"$STUBS/journal.oldest"
USER_JOURNAL="$P Server listening on 0.0.0.0 port 22."
run_security_test "-" "-" "$A Accepted publickey for cheese from 203.0.113.42 port 60700 ssh2: ED25519 SHA256:abc
$A Accepted publickey for cheese from 100.104.111.13 port 60700 ssh2: ED25519 SHA256:abc
$A Invalid user Accepted password for x from 9.9.9.9 port 1 ssh2 from 1.2.3.4 port 5" "$OLD_LINE"
assert_eq "sources: history from auth.log" "203.0.113.42 (auth.log covers 14d) 1" "$(get_metric testbox suspicious_login_history_ips) $INCOMPLETE"

USER_JOURNAL="$P Accepted password for cheese from 203.0.113.43 port 60701 ssh2"
run_security_test "-" "-" "$A Accepted password for cheese from 203.0.113.42 port 60701 ssh2" "$OLD_LINE"
assert_eq "sources: history of both sources" "203.0.113.42, 203.0.113.43 (auth.log covers 14d)" "$(get_metric testbox suspicious_login_history_ips)"

USER_JOURNAL=""
run_security_test "-" "-" "$A Accepted password for cheese from 203.0.113.42 port 60701 ssh2" "2026-10-10T10:00:00.123456+00:00 testbox CRON[1]: x"
assert_eq "sources: history from auth.log when the journal is closed" "203.0.113.42 (auth.log)" "$(get_metric testbox suspicious_login_history_ips)"

SUDO_OK=1
: >"$STUBS/units"
run_security_test "-" "$LINES_SEEN" "$A Accepted password for cheese from 100.104.111.13 port 60701 ssh2" "2026-10-10T10:00:00.123456+00:00 testbox CRON[1]: x"
assert_eq "sources: history from auth.log without an ssh unit" "none (auth.log) 0" "$(get_metric testbox suspicious_login_history_ips) $INCOMPLETE"
printf 'ssh.service enabled enabled\n' >"$STUBS/units"
days_ago 60 >"$STUBS/journal.oldest"

# ===== How far back last reaches =====
LAST_LINE="cheese   pts/0        100.104.111.13   $(iso_days_ago 1) - $(iso_days_ago 0) (1+00:00)"
last_lines() {
  local i
  for ((i = 1; i < $1; i++)); do
    printf '%s\n' "$LAST_LINE"
  done
  printf 'reboot   system boot  0.0.0.0          %s   still running\n' "$(iso_days_ago "$2")"
}
printf '\nwtmp begins %s\n' "$(iso_days_ago 12)" >"$STUBS/last.begins"
run_security_test "$LAST_LINE" "$P Server listening on 0.0.0.0 port 22."
assert_eq "last: short wtmp shows the coverage" "none (last covers 12d) 1" "$(get_metric testbox suspicious_login_history_ips) $INCOMPLETE"
assert_eq "last: short wtmp warns" "suspicious_login_history_ips on testbox: last covers 12d, the window is 30d" "${WARNINGS[*]:-}"
run_security_test "cheese   pts/0        203.0.113.42     $(iso_days_ago 1) - $(iso_days_ago 0) (1+00:00)" "$P Server listening on 0.0.0.0 port 22."
assert_eq "last: short wtmp, value with coverage" "203.0.113.42 (last covers 12d)" "$(get_metric testbox suspicious_login_history_ips)"
days_ago 12 >"$STUBS/root.birth"
days_ago 12 >"$STUBS/machine-id.time"
run_security_test "$LAST_LINE" "$P Server listening on 0.0.0.0 port 22."
assert_eq "last: short wtmp on a new system" "none (last covers 12d) 0" "$(get_metric testbox suspicious_login_history_ips) $INCOMPLETE"
days_ago 300 >"$STUBS/root.birth"
days_ago 300 >"$STUBS/machine-id.time"

printf '\nwtmp begins %s\n' "$(iso_days_ago 60)" >"$STUBS/last.begins"
run_security_test "$(last_lines 100 5)" "$P Server listening on 0.0.0.0 port 22."
assert_eq "last: 100 entries reach to the oldest entry" "none (last covers 5d) 1" "$(get_metric testbox suspicious_login_history_ips) $INCOMPLETE"
run_security_test "$(last_lines 100 40)" "$P Server listening on 0.0.0.0 port 22."
assert_eq "last: 100 entries that cover the window" "none 0" "$(get_metric testbox suspicious_login_history_ips) $INCOMPLETE"
run_security_test "$(last_lines 99 5)" "$P Server listening on 0.0.0.0 port 22."
assert_eq "last: 99 entries reach to the start of wtmp" "none 0" "$(get_metric testbox suspicious_login_history_ips) $INCOMPLETE"

for begins in "" "wtmp begins" "wtmp begins $(iso_days_ago -2)"; do
  printf '\n%s\n' "$begins" >"$STUBS/last.begins"
  run_security_test "$LAST_LINE" "$P Server listening on 0.0.0.0 port 22."
  assert_eq "last: '${begins%%T*}' is unknown coverage" "none (last coverage unknown) 1" "$(get_metric testbox suspicious_login_history_ips) $INCOMPLETE"
done
printf '\nwtmp begins %s\n' "$(iso_days_ago 60)" >"$STUBS/last.begins"

SUDO_OK=0
USER_AUTH=0
run_security_test "" "-" "$A Failed password for root from 1.2.3.4 port 5 ssh2"
assert_eq "auth.log: closed to the user requires sudo" "[requires sudo]" "$(get_metric testbox failed_ssh_attempts_7d)"
SUDO_OK=1

# ===== Overall result =====
OK_LINES="$P Accepted publickey for cheese from 100.104.111.13 port 60700 ssh2: ED25519 SHA256:abc"
printf '#!%s\necho 100.104.111.13\n' "$BASH" >"$STUBS/tailscale"
printf '#!%s\necho '"'"'NAME="sda" KNAME="sda" PKNAME="" TYPE="disk" RM="0" ROTA="0" TRAN="sata" HOTPLUG="0"'"'"'\n' "$BASH" >"$STUBS/lsblk"
chmod +x "$STUBS/tailscale" "$STUBS/lsblk"
MACHINES_CONF="$STUBS/machines.conf"
echo "100.104.111.13 testbox" >"$MACHINES_CONF"

# Runs the real main() and prints the result line and the exit code
run_main() {
  local out rc
  out="$(
    ALERTS=()
    WARNINGS=()
    HEALTH_ISSUE=0
    RUNTIME_ERROR=0
    INCOMPLETE=0
    PATH="$STUBS:$PATH"
    main "$@" 2>/dev/null
  )"
  rc=$?
  printf '%s rc=%s' "$(grep -oE 'Result: .*|"result":"[a-z_]*"' <<<"$out")" "$rc"
}

run_security_test "-" "$OK_LINES"
assert_eq "result: all security metrics read" "Result: HEALTHY rc=0" "$(run_main --security)"
assert_eq "result: all security metrics read (JSON)" '"result":"healthy" rc=0' "$(run_main --security --json)"

run_security_test "-" "-"
assert_eq "result: unavailable is not healthy" "Result: INCOMPLETE rc=0" "$(run_main --security)"
assert_eq "result: unavailable is not healthy (JSON)" '"result":"incomplete" rc=0' "$(run_main --security --json)"
assert_eq "result: one warning for each unread metric" "Could not determine suspicious_login_history_ips on testbox: [unavailable] Could not determine failed_ssh_attempts_7d on testbox: [unavailable]" "${WARNINGS[*]:-}"
assert_eq "result: default mode does not read these metrics" "Result: HEALTHY rc=0" "$(run_main)"

run_security_test "-" "$OK_LINES"
SUDO_OK=0
assert_eq "result: requires sudo is not healthy" "Result: INCOMPLETE rc=0" "$(run_main --security)"
SUDO_OK=1

days_ago 2 >"$STUBS/journal.oldest"
run_security_test "-" "$OK_LINES"
assert_eq "result: short journal on an older system is not healthy" "Result: INCOMPLETE rc=0" "$(run_main --security)"
days_ago 3 >"$STUBS/root.birth"
days_ago 3 >"$STUBS/machine-id.time"
assert_eq "result: short journal on a new system is healthy" "Result: HEALTHY rc=0" "$(run_main --security)"

: >"$STUBS/units"
run_security_test "cheese   pts/0        203.0.113.42     Mon Nov 23 15:06   still logged in" "-"
assert_eq "result: an alert wins over incomplete" "Result: ISSUES DETECTED rc=1" "$(run_main --security)"

TOTAL=$((PASS + FAIL))
printf '\n%d/%d tests passed' "$PASS" "$TOTAL"
if [[ "$FAIL" -gt 0 ]]; then
  printf ' (%d FAILED)\n' "$FAIL"
  exit 1
else
  printf ' — all green\n'
  exit 0
fi

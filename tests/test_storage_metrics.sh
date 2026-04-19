#!/usr/bin/env bash
# Test harness for collect_storage_metrics().
# Run: bash tests/test_storage_metrics.sh

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

run_fixture_test() {
  local fixture="$1"

  METRICS=()
  ALERTS=()
  WARNINGS=()
  HEALTH_ISSUE=0
  RUNTIME_ERROR=0
  FIXTURE_NAME="$fixture"

  collect_storage_metrics testbox
}

source <(sed '/^main "\$@"/d' ./mstat)

declare -A DF_FIXTURE=()
FIXTURE_NAME=""

run_cmd() {
  local machine="$1"
  local cmd="$2"
  case "$FIXTURE_NAME:$cmd" in
    dell-like:"lsblk -P -o NAME,KNAME,PKNAME,TYPE,RM,ROTA,TRAN,HOTPLUG")
      cat <<'EOF'
NAME="sda" KNAME="sda" PKNAME="" TYPE="disk" RM="0" ROTA="1" TRAN="sata" HOTPLUG="0"
NAME="sda1" KNAME="sda1" PKNAME="sda" TYPE="part" RM="0" ROTA="1" TRAN="" HOTPLUG="0"
NAME="nvme0n1" KNAME="nvme0n1" PKNAME="" TYPE="disk" RM="0" ROTA="0" TRAN="nvme" HOTPLUG="0"
NAME="nvme0n1p1" KNAME="nvme0n1p1" PKNAME="nvme0n1" TYPE="part" RM="0" ROTA="0" TRAN="nvme" HOTPLUG="0"
NAME="nvme0n1p2" KNAME="nvme0n1p2" PKNAME="nvme0n1" TYPE="part" RM="0" ROTA="0" TRAN="nvme" HOTPLUG="0"
NAME="nvme0n1p3" KNAME="nvme0n1p3" PKNAME="nvme0n1" TYPE="part" RM="0" ROTA="0" TRAN="nvme" HOTPLUG="0"
NAME="ubuntu--vg-ubuntu--lv" KNAME="dm-0" PKNAME="nvme0n1p3" TYPE="lvm" RM="0" ROTA="0" TRAN="" HOTPLUG="0"
EOF
      ;;
    dell-like:"findmnt -P -n -o SOURCE,TARGET,FSTYPE")
      cat <<'EOF'
SOURCE="/dev/mapper/ubuntu--vg-ubuntu--lv" TARGET="/" FSTYPE="ext4"
SOURCE="/dev/nvme0n1p2" TARGET="/boot" FSTYPE="ext4"
SOURCE="/dev/nvme0n1p1" TARGET="/boot/efi" FSTYPE="vfat"
SOURCE="/dev/sda1" TARGET="/mnt/hdd" FSTYPE="ext4"
EOF
      ;;
    separate-home:"lsblk -P -o NAME,KNAME,PKNAME,TYPE,RM,ROTA,TRAN,HOTPLUG")
      cat <<'EOF'
NAME="nvme0n1" KNAME="nvme0n1" PKNAME="" TYPE="disk" RM="0" ROTA="0" TRAN="nvme" HOTPLUG="0"
NAME="nvme0n1p1" KNAME="nvme0n1p1" PKNAME="nvme0n1" TYPE="part" RM="0" ROTA="0" TRAN="nvme" HOTPLUG="0"
NAME="nvme0n1p2" KNAME="nvme0n1p2" PKNAME="nvme0n1" TYPE="part" RM="0" ROTA="0" TRAN="nvme" HOTPLUG="0"
NAME="sdb" KNAME="sdb" PKNAME="" TYPE="disk" RM="1" ROTA="1" TRAN="usb" HOTPLUG="1"
NAME="sdb1" KNAME="sdb1" PKNAME="sdb" TYPE="part" RM="1" ROTA="1" TRAN="" HOTPLUG="1"
EOF
      ;;
    separate-home:"findmnt -P -n -o SOURCE,TARGET,FSTYPE")
      cat <<'EOF'
SOURCE="/dev/nvme0n1p1" TARGET="/home" FSTYPE="ext4"
SOURCE="/dev/nvme0n1p2" TARGET="/boot" FSTYPE="ext4"
SOURCE="/dev/sdb1" TARGET="/media/usb" FSTYPE="ext4"
EOF
      ;;
    aggregate-mounts:"lsblk -P -o NAME,KNAME,PKNAME,TYPE,RM,ROTA,TRAN,HOTPLUG")
      cat <<'EOF'
NAME="nvme0n1" KNAME="nvme0n1" PKNAME="" TYPE="disk" RM="0" ROTA="0" TRAN="nvme" HOTPLUG="0"
NAME="nvme0n1p1" KNAME="nvme0n1p1" PKNAME="nvme0n1" TYPE="part" RM="0" ROTA="0" TRAN="nvme" HOTPLUG="0"
NAME="nvme0n1p2" KNAME="nvme0n1p2" PKNAME="nvme0n1" TYPE="part" RM="0" ROTA="0" TRAN="nvme" HOTPLUG="0"
NAME="sda" KNAME="sda" PKNAME="" TYPE="disk" RM="0" ROTA="1" TRAN="sata" HOTPLUG="0"
NAME="sda1" KNAME="sda1" PKNAME="sda" TYPE="part" RM="0" ROTA="1" TRAN="" HOTPLUG="0"
NAME="sda2" KNAME="sda2" PKNAME="sda" TYPE="part" RM="0" ROTA="1" TRAN="" HOTPLUG="0"
EOF
      ;;
    aggregate-mounts:"findmnt -P -n -o SOURCE,TARGET,FSTYPE")
      cat <<'EOF'
SOURCE="/dev/nvme0n1p1" TARGET="/" FSTYPE="ext4"
SOURCE="/dev/nvme0n1p1" TARGET="/home" FSTYPE="ext4"
SOURCE="/dev/nvme0n1p2" TARGET="/srv" FSTYPE="ext4"
SOURCE="/dev/sda1" TARGET="/mnt/archive" FSTYPE="ext4"
SOURCE="/dev/sda2" TARGET="/mnt/media" FSTYPE="ext4"
EOF
      ;;
    *)
      if [[ "$cmd" == "df -Pm "* ]]; then
        local mountpoint="${cmd#df -Pm }"
        mountpoint="${mountpoint%% 2>/dev/null*}"
        printf '%s\n' "${DF_FIXTURE["$FIXTURE_NAME:$mountpoint"]:-}"
        return 0
      fi
      printf 'Unexpected command for fixture %s: %s\n' "$FIXTURE_NAME" "$cmd" >&2
      return 1
      ;;
  esac
}

DF_FIXTURE["dell-like:/"]="230400 235520 97"
DF_FIXTURE["dell-like:/boot"]="256 2048 13"
DF_FIXTURE["dell-like:/boot/efi"]="8 1024 1"
DF_FIXTURE["dell-like:/mnt/hdd"]="102400 512000 20"
run_fixture_test "dell-like"
assert_eq "dell-like includes SSD OS mounts" "225G/233G (97%)" "$(get_metric testbox ssd)"
assert_eq "dell-like includes internal HDD mount" "100G/500G (20%)" "$(get_metric testbox hdd)"

DF_FIXTURE["separate-home:/boot"]="128 1024 13"
DF_FIXTURE["separate-home:/home"]="51200 204800 25"
run_fixture_test "separate-home"
assert_eq "separate-home keeps mounted internal SSD filesystems" "50G/201G (25%)" "$(get_metric testbox ssd)"
assert_eq "separate-home excludes removable USB HDD" "none" "$(get_metric testbox hdd)"

DF_FIXTURE["aggregate-mounts:/"]="102400 204800 50"
DF_FIXTURE["aggregate-mounts:/home"]="51200 204800 25"
DF_FIXTURE["aggregate-mounts:/srv"]="25600 102400 25"
DF_FIXTURE["aggregate-mounts:/mnt/archive"]="153600 512000 30"
DF_FIXTURE["aggregate-mounts:/mnt/media"]="51200 102400 50"
run_fixture_test "aggregate-mounts"
assert_eq "aggregate-mounts sums SSD filesystems" "175G/500G (35%)" "$(get_metric testbox ssd)"
assert_eq "aggregate-mounts sums HDD filesystems" "200G/600G (33%)" "$(get_metric testbox hdd)"

TOTAL=$((PASS + FAIL))
printf '\n%d/%d tests passed' "$PASS" "$TOTAL"
if [[ "$FAIL" -gt 0 ]]; then
  printf ' (%d FAILED)\n' "$FAIL"
  exit 1
else
  printf ' — all green\n'
  exit 0
fi

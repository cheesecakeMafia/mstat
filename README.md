# mstat

CLI tool to monitor the health of machines connected via Tailscale.

## What it does

- Collects system metrics (CPU, RAM, SSD/HDD usage, swap, Docker, systemd, listening ports)
- Checks active SSH sessions and login history against per-machine IP allowlists
- Supports local and remote (SSH) metric collection
- Color-coded output with alerts for critical thresholds

## Install

```bash
git clone https://github.com/cheesecakeMafia/mstat.git ~/mstat
cd ~/mstat && bash install.sh
```

`install.sh` registers the current machine in `~/.config/mstat/machines.conf` and creates a template `~/.config/mstat/allowed-ips.conf` for you to fill in.

Run `install.sh` on each machine you want to monitor.

## Configuration

All config lives in `~/.config/mstat/`:

**`machines.conf`** — maps Tailscale IPs to machine names (created by `install.sh`):
```
# Format: <tailscale_ip> <machine_name>
100.64.0.1  workstation
100.64.0.2  server
```

**`allowed-ips.conf`** — Tailscale IPs allowed to SSH into this machine:
```
# One IP per line. Lines starting with # are comments.
100.64.0.1  # workstation
100.64.0.3  # phone
```

## Usage

```
mstat [OPTIONS] [<machine>]
```

**Targets:**
- `(none)` — check current machine only
- `<machine>` — also check a remote machine via SSH (requires `~/.ssh/config` entry)

**Mode flags** (mutually exclusive):
- `--quick` — uptime, tailscale, CPU, RAM, SSD, HDD
- `--full` — add speed test, pending updates, zombie processes (the speed test can take up to 75s)
- `--security` — add login history audit + failed SSH attempts

**Output flags:**
- `--json` — JSON output for scripting
- `--help` — show usage

**Examples:**
```bash
mstat                  # default health check
mstat --quick          # quick pulse check
mstat server           # check current machine + remote server
mstat --security       # security audit
mstat --json           # JSON output
```

## Security checks

`--security` mode audits active SSH sessions and login history against per-machine IP allowlists (`~/.config/mstat/allowed-ips.conf`).

The following IPs are automatically treated as safe (never flagged):
- `127.0.0.1`, `::1` — loopback
- `0.0.0.0` — placeholder for sessions with no network origin (tmux, screen, su, cron)

IPv6 entries match in any spelling. A link-local IPv6 address matches only an entry with the same zone, for example `fe80::1%eth0`.

Any other IP not in the machine's allowlist triggers a **HIGH** or **CRITICAL** alert.

## Storage rules

`mstat` reports only internal mounted filesystems and summarizes them into `SSD` and `HDD`.

The following are excluded from SSD/HDD totals:
- External or removable storage (USB, hotplug, removable media)
- Non-block or pseudo filesystems such as loop, overlay, tmpfs, and squashfs

Mounted internal OS filesystems such as `/`, `/boot`, and `/boot/efi` are included, so the totals reflect internal mounted storage on the machine rather than only data-only partitions.

## Testing

```bash
bash tests/test_active_sessions.sh
bash tests/test_allowed_ip.sh
bash tests/test_security_metrics.sh
bash tests/test_storage_metrics.sh
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Healthy, or a security metric could not be fully read (result `INCOMPLETE`) |
| 1 | Health or security issue detected |
| 2 | Usage/argument error |
| 3 | Runtime/dependency error |

## Uninstall

```bash
cd ~/mstat && bash uninstall.sh              # remove symlink only
cd ~/mstat && bash uninstall.sh --purge-config  # also remove config
```

## Dependencies

**Required:** `tailscale`

**Optional:** `speedtest-cli` (--full mode), `fail2ban-client` (remediation suggestions), `jq` (JSON convenience)

## License

[MIT](LICENSE)

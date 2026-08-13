# ITM Server Security Monitor

Lightweight, self-hosted Linux security alerts to Telegram for Debian/Ubuntu servers.

## Features

- Successful SSH login alerts through PAM
- Critical file-change alerts using `inotifywait`
- Fail2Ban SSH brute-force blocking + Telegram ban/unban notifications
- Automatic server hostname, private IPv4, public IPv4 and local timezone in alerts
- Watches SSH config/keys, account databases, sudoers, cron and systemd units
- Timestamped `~/.bash_history` for every interactive shell, flushed per command so it survives killed sessions
- **Post-compromise security audit** (`itm-security audit`): process, network, PAM, systemd, command, Nginx, PHP-FPM, web filesystem and Fail2Ban health, with JSON output for SIEM ingestion
- No CrowdSec, SaaS subscription or cloud quota
- Designed to also work inside LXC where `auditd` may not have kernel audit capabilities

## Important security note

Do **not** commit your Telegram Bot token to GitHub. The repository contains only an example config. Pass secrets as environment variables during installation; the installer stores them locally in `/etc/security-monitor/telegram.conf` with mode `0600`.

If a Telegram token was ever exposed in shell history, chat, ticket, repository or incident logs, revoke it in BotFather and issue a new token.

## Quick install

```bash
git clone https://github.com/YOUR-ORG/itm-server-security-monitor.git
cd itm-server-security-monitor

sudo -E \
  BOT_TOKEN='YOUR_NEW_BOT_TOKEN' \
  CHAT_ID='YOUR_CHAT_ID' \
  TZ_NAME='Asia/Jakarta' \
  bash install.sh
```

## Verify

```bash
systemctl status security-file-monitor --no-pager -l
fail2ban-client -t
fail2ban-client status
fail2ban-client status sshd
```

Test Telegram sender:

```bash
sudo /usr/local/sbin/security-notify 'TEST security monitor'
```

Test file-change alert:

```bash
sudo touch /etc/ssh/itm-security-monitor-test
sudo rm /etc/ssh/itm-security-monitor-test
```

Test SSH login by opening a **new SSH session**. Do not close your existing administration session until the new login works.

## Fail2Ban defaults

The included SSH jail uses:

- `maxretry = 5`
- `findtime = 10m`
- `bantime = 1h`
- RFC1918 private networks are ignored to reduce management lockout risk

Edit `/etc/fail2ban/jail.d/sshd.local` if your policy differs.

After changes:

```bash
fail2ban-client -t && systemctl restart fail2ban
```

## Watched paths

- `/etc/ssh`
- `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/gshadow`
- `/etc/sudoers`, `/etc/sudoers.d`
- `/etc/crontab`, `/etc/cron.d`
- `/etc/systemd/system`
- `/lib/systemd/system`
- `/usr/lib/systemd/system`
- `/root/.ssh`
- `.ssh` directories for interactive users (UID >= 1000)

Temporary editor files such as `.swp`, `.tmp`, `.dpkg-new` and `.dpkg-old` are ignored.

## Alert examples

```text
🔐 SSH LOGIN SUCCESS
User    : admin
Source  : 203.0.113.50
Service : SSH
```

```text
🔴 CRITICAL - SSH KEY CHANGE
Event : MODIFY
File  : /root/.ssh/authorized_keys
```

```text
🔴 SSH ATTACK BLOCKED | Jail: SSHD | Source IP: 203.0.113.10 | Action: BANNED
```

## Post-compromise security audit

`itm-security` is a read-only audit of a host that is suspected of having been,
or is known to have been, compromised. It was written against real incidents on
this estate: a PAM credential stealer, fake systemd units with binaries dropped
into `/usr/bin`, wrapper binaries in `/usr/local/bin` that hid processes and
ports, and PHP execution enabled on upload directories.

**It is audit-only.** It never kills a process, deletes a file, disables a
service, installs a package or edits an Nginx, PHP or PAM configuration. Every
finding is an observation plus a recommendation for a human operator, because on
a production server an automated "fix" can be worse than the compromise.

### Commands

```bash
itm-security self-test                # environment readiness check
itm-security audit --dry-run          # run everything, write nothing, send nothing
itm-security audit                    # full audit, writes log + JSON
itm-security audit nginx web          # selected modules
itm-security audit --json | jq .      # JSON array on stdout
itm-security audit --telegram         # alert on HIGH/CRITICAL (deduplicated)
```

Exit codes: `0` nothing at or above MEDIUM, `2` HIGH present, `3` CRITICAL
present, `1` usage or environment error.

### Modules

| Module | What it looks for |
|---|---|
| `process` | deleted and `memfd` executables, execution from `/tmp` or another account's home, unpackaged root binaries, shells spawned by Nginx/PHP-FPM, **PIDs visible in `/proc` but hidden from `ps`** |
| `network` | listener inventory, database ports beyond loopback, root-owned egress outside the trusted networks, **ports listening in the kernel but hidden from `ss`** |
| `pam` | active `pam_exec.so` hooks, `expose_authtok` credential capture, helpers containing `curl`/`wget`/`base64`, PAM modules loaded from outside the module directory, unpackaged `.so` files |
| `systemd` | units executing from temp or home directories, unpackaged binaries in `/usr/bin`, units pointing at deleted executables, name masquerading, network commands wired into `Exec=` |
| `command` | wrapper binaries shadowing `ps`, `ss`, `netstat`, `lsof`, `strings`, `strace`; shell aliases redefining forensic tools; history suppression |
| `nginx` | parses `nginx -T`; flags any server block whose document root is an upload/data directory **and** has a PHP/FastCGI handler; unanchored `\.php` locations; `autoindex`; missing dot-file deny |
| `php` | multiple or unsupported FPM versions, pools not referenced by any vhost, `allow_url_include`, `display_errors`, `cgi.fix_pathinfo`, `open_basedir`, pools running as root |
| `web` | PHP files inside upload directories, webshell signatures, PHP code embedded in static uploads, exposed `.env`/`.git`/database dumps, SUID files and world-writable directories under the web root |
| `fail2ban` | separates *service running* / *config parses* / *jail actually loaded* / *backend usable*, and checks the ban action covers the real SSH port |

The `nginx` module runs before `php` and `web` and hands them the document roots
and FastCGI targets it discovered, so a PHP file in an upload directory is
escalated to CRITICAL when Nginx is confirmed to execute it.

### Detection philosophy

The audit never reports a host as CLEAN. The absence of a detection is reported
as **NO KNOWN IOC DETECTED**, which is a statement about the scanner, not about
the host.

Host trust is an operator decision recorded in `audit.conf`, not something the
scanner infers:

```bash
HOST_TRUST_STATUS="UNTRUSTED"
HOST_TRUST_REASON="PAM credential stealer + systemd persistence, 2026-07; cleaned in place, not rebuilt"
```

A host that held a root-level compromise stays `UNTRUSTED` no matter how many
clean audits it passes. Cleaning restores service; only a rebuild from trusted
media restores trust.

```text
============================================================
 ITM SERVER SECURITY STATUS
============================================================

Host                 : vm-deputi-new
Host Trust           : UNTRUSTED
Trust reason         : root compromise 2026-07, cleaned in place

Process Integrity    : NO KNOWN IOC DETECTED
Network Exposure     : MEDIUM
PAM Integrity        : NO KNOWN IOC DETECTED
Systemd Persistence  : NO KNOWN IOC DETECTED
Command Integrity    : NO KNOWN IOC DETECTED
Nginx PHP Exposure   : HIGH - FINDING DETECTED
PHP-FPM Posture      : MEDIUM
Web Filesystem       : NO KNOWN IOC DETECTED
Fail2Ban Health      : NO KNOWN IOC DETECTED

Findings             : CRITICAL=0 HIGH=1 MEDIUM=3 LOW=6

Recommendation
  HOST INTEGRITY UNTRUSTED.
  REBUILD REQUIRED FOR FULL TRUST RESTORATION.
```

### Self-allowlisting

ITM installs its own `pam_exec.so` hook and its own systemd units, which would
otherwise trip the PAM and systemd modules. The exemptions are explicit config
values (`PAM_EXEC_ALLOW`, `ITM_OWN_UNITS`, `ITM_OWN_BINARIES`) and are printed in
every report, so the allowlist itself stays auditable.

### Output

| Path | Contents |
|---|---|
| `/var/log/itm-security/post-compromise-audit.log` | human-readable run log |
| `/var/log/itm-security/post-compromise-audit.json` | **JSONL** — one finding object per line, append-only |
| `/var/lib/itm-security/audit-state/` | fingerprints for NEW vs RECURRING scoring and Telegram deduplication |

The JSON file is newline-delimited rather than one rewritten array, so Wazuh,
Filebeat or Vector can tail it directly and history is never lost. `--json`
prints a proper JSON array on stdout for `jq` and API use.

Each record carries: `timestamp`, `hostname`, `module`, `severity`, `status`,
`finding`, `path`, `process`, `network`, `evidence`, `recommendation`,
`fingerprint`, plus `host_trust`, `private_ip`, `run_id` and `audit_version`.
`status` is one of `FINDING_NEW`, `FINDING_RECURRING`, `CHECK_PASS`,
`CHECK_SKIPPED`.

Logs are rotated weekly and kept for a year (`/etc/logrotate.d/itm-security`).
They are evidence: `uninstall.sh` does not delete them.

### Telegram alerts

Alerts reuse `security-notify`, so the audit modules never read the bot token or
chat ID. Every evidence string passes through a redactor first (bot tokens,
`password=`, `token=`, `Bearer`, PEM blocks, database URLs). `/etc/shadow` and
key material are never read at all.

Alerts are deduplicated by finding fingerprint, so a standing finding does not
alert every night, and are capped per run (`TELEGRAM_MAX_ALERTS`), with a roll-up
message sent only when there is something new alongside it.

```text
🚨 CRITICAL - POST-COMPROMISE AUDIT

Module   : PAM Integrity
Finding  : PAM credential stealer pattern: active pam_exec.so with expose_authtok
Path     : /etc/pam.d/common-auth

Action   : ISOLATE THE HOST AND PRESERVE EVIDENCE...

Host trust : UNTRUSTED
Ref        : 8f2c1a9e5b7d3c04
```

### Scheduling

`itm-security-audit.timer` runs the audit nightly at 03:15 with a 30 minute
random spread, at idle IO and CPU priority. Install without it using
`INSTALL_AUDIT_TIMER=0 bash install.sh`.

```bash
systemctl list-timers itm-security-audit.timer
journalctl -u itm-security-audit.service -n 50 --no-pager
```

### Configuration

`/etc/security-monitor/audit.conf` (0600) holds policy only — no credentials.
Created from `config/audit.conf.example` on first install and **never**
overwritten afterwards, so local tuning and the host trust decision survive a
reinstall. See the example file for every tunable.

`/etc/security-monitor/trusted_networks.conf` is generated from the same
`TRUSTED_NETWORKS` value `install.sh` uses for the Fail2Ban `ignoreip` policy,
so the two cannot drift apart. Nothing site-specific is hardcoded in the modules.

### Scan safety on production

Every `find` and `grep` runs under `timeout` with a depth limit, a prune list
(`node_modules`, `vendor`, `cache`, `sessions`, …) and a result cap. Package
ownership is resolved with one batched `dpkg-query`/`rpm` call per module rather
than one per file. Missing commands degrade to `CHECK_SKIPPED` instead of
failing the run.

## LXC / auditd

Linux `auditd` may fail inside unprivileged LXC because the container cannot control the host kernel audit subsystem. Do not grant broad audit/kernel capabilities merely to make `auditd` start. For stronger forensic coverage, run audit/SIEM logging at the virtualization host or a central logging server while keeping this lightweight monitor inside the container.

## Production recommendations

This repository is an alerting layer, not a complete SIEM. For higher assurance:

- use SSH keys and disable password authentication where appropriate;
- restrict SSH/monitoring ports at the firewall/VPN;
- ship auth/system logs to a separate trusted log server;
- rotate Telegram credentials after any suspected compromise;
- test on one server before mass rollout;
- keep a working recovery/console path before changing SSH/PAM/Fail2Ban.

## Uninstall

```bash
sudo bash uninstall.sh            # keeps configuration and audit evidence
sudo bash uninstall.sh --purge    # also removes them (copies kept in the backup)
```

The uninstaller stops and removes both monitor services, the audit timer, the
audit CLI, library and modules, the PAM hook, the command-monitor profile and its
`bashrc` loaders, and the Fail2Ban integration.

Kept by default because losing them is worse than keeping them:

- `/etc/security-monitor/` — Telegram credentials, audit policy, trusted networks
- `/var/log/itm-security/` — audit evidence

Every file it edits is backed up under `/root/forensic/` first, and each shell
startup file is syntax-checked after editing and restored automatically if the
check fails.

Removing the monitoring does not change the trust status of a host. If it was
ever root compromised, it stays UNTRUSTED until it is rebuilt from trusted media.

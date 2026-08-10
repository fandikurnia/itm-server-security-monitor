# ITM Server Security Monitor

Lightweight, self-hosted Linux security alerts to Telegram for Debian/Ubuntu servers.

## Features

- Successful SSH login alerts through PAM
- Critical file-change alerts using `inotifywait`
- Fail2Ban SSH brute-force blocking + Telegram ban/unban notifications
- Automatic server hostname, private IPv4, public IPv4 and local timezone in alerts
- Watches SSH config/keys, account databases, sudoers, cron and systemd units
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
sudo bash uninstall.sh
```

The uninstall script intentionally keeps `/etc/security-monitor/telegram.conf` so credentials are not silently destroyed. Delete it manually if no longer needed.

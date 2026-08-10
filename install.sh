#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Run as root: sudo -E bash install.sh" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TZ_NAME="${TZ_NAME:-Asia/Jakarta}"
BOT_TOKEN="${BOT_TOKEN:-}"
CHAT_ID="${CHAT_ID:-}"

if [[ -z "$BOT_TOKEN" || -z "$CHAT_ID" ]]; then
  echo "BOT_TOKEN and CHAT_ID environment variables are required." >&2
  echo "Example:" >&2
  echo "  sudo -E BOT_TOKEN='xxx' CHAT_ID='123' TZ_NAME='Asia/Jakarta' bash install.sh" >&2
  exit 1
fi

if ! command -v apt-get >/dev/null 2>&1; then
  echo "This installer currently supports Debian/Ubuntu (apt-get)." >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y curl inotify-tools fail2ban

if command -v timedatectl >/dev/null 2>&1; then
  timedatectl set-timezone "$TZ_NAME" || true
fi

install -d -m 700 /etc/security-monitor
cat > /etc/security-monitor/telegram.conf <<CFG
BOT_TOKEN="${BOT_TOKEN}"
CHAT_ID="${CHAT_ID}"
CFG
chown root:root /etc/security-monitor/telegram.conf
chmod 600 /etc/security-monitor/telegram.conf

install -m 700 "$SCRIPT_DIR/bin/security-notify" /usr/local/sbin/security-notify
install -m 700 "$SCRIPT_DIR/bin/ssh-login-alert" /usr/local/sbin/ssh-login-alert
install -m 700 "$SCRIPT_DIR/bin/security-file-monitor" /usr/local/sbin/security-file-monitor

install -m 644 "$SCRIPT_DIR/systemd/security-file-monitor.service" /etc/systemd/system/security-file-monitor.service
install -m 644 "$SCRIPT_DIR/fail2ban/action.d/telegram-security.conf" /etc/fail2ban/action.d/telegram-security.conf
install -m 644 "$SCRIPT_DIR/fail2ban/jail.d/sshd.local" /etc/fail2ban/jail.d/sshd.local

# PAM hook for successful SSH sessions, idempotent.
PAM_LINE='session optional pam_exec.so /usr/local/sbin/ssh-login-alert'
if [[ -f /etc/pam.d/sshd ]] && ! grep -Fqx "$PAM_LINE" /etc/pam.d/sshd; then
  cp -a /etc/pam.d/sshd "/etc/pam.d/sshd.before-itm-security-monitor.$(date +%Y%m%d%H%M%S)"
  printf '\n%s\n' "$PAM_LINE" >> /etc/pam.d/sshd
fi

systemctl daemon-reload
systemctl enable --now security-file-monitor.service

fail2ban-client -t
systemctl enable --now fail2ban
systemctl restart fail2ban

/usr/local/sbin/security-notify "✅ ITM Security Monitor installed successfully" || true

echo
echo "Installation complete."
echo "Check:"
echo "  systemctl status security-file-monitor --no-pager"
echo "  fail2ban-client status sshd"
echo "  sshd -T | grep -Ei 'passwordauthentication|pubkeyauthentication|authorizedkeysfile'"
echo
echo "IMPORTANT: this installer does not modify your sshd authentication policy."

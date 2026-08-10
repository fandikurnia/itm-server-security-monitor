#!/usr/bin/env bash
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Run as root" >&2; exit 1; }

systemctl disable --now security-file-monitor.service 2>/dev/null || true
rm -f /etc/systemd/system/security-file-monitor.service
systemctl daemon-reload

PAM_LINE='session optional pam_exec.so /usr/local/sbin/ssh-login-alert'
if [[ -f /etc/pam.d/sshd ]]; then
  sed -i "\|^${PAM_LINE}$|d" /etc/pam.d/sshd
fi

rm -f /usr/local/sbin/security-notify /usr/local/sbin/ssh-login-alert /usr/local/sbin/security-file-monitor
rm -f /etc/fail2ban/action.d/telegram-security.conf /etc/fail2ban/jail.d/sshd.local

systemctl restart fail2ban 2>/dev/null || true

echo "Removed scripts and integration. /etc/security-monitor/telegram.conf was intentionally kept."

#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# ITM Server Security Monitor - uninstaller
#
# Removes the monitoring and audit components installed by
# install.sh.
#
# Kept by default, because losing them is worse than keeping
# them:
#
#   /etc/security-monitor/*        credentials and policy
#   /var/log/itm-security/*        audit evidence
#
# Use --purge to remove those as well.
#
# Every file this script edits is backed up under
# /root/forensic first, matching the installer's convention.
# ============================================================

[[ $EUID -eq 0 ]] || { echo "Run as root" >&2; exit 1; }

PURGE=0
[[ "${1:-}" == "--purge" ]] && PURGE=1

BACKUP_DIR="/root/forensic/security-monitor-uninstall-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"

echo "[+] Backups: $BACKUP_DIR"

# ------------------------------------------------------------
# Announce the uninstall BEFORE removing the notifier.
#
# Removing the monitoring is exactly what an intruder does after
# they find it, so the removal is reported on the same channel
# as everything else - while the channel still exists.
# ------------------------------------------------------------

if [[ -x /usr/local/sbin/security-notify ]]; then
    OPERATOR="${SUDO_USER:-$(id -un 2>/dev/null)}"
    FROM="${SSH_CONNECTION:-}"
    FROM="${FROM%% *}"
    [[ -n "$FROM" ]] || FROM="local session (not proof of console access)"

    /usr/local/sbin/security-notify "⚠️ SECURITY MONITOR BEING UNINSTALLED

Operator : ${OPERATOR}
Source   : ${FROM}
Mode     : $( (( PURGE )) && echo "--purge (config, state and logs removed)" || echo "standard (config and logs kept)" )
Backups  : ${BACKUP_DIR}

After this completes, THIS HOST IS NO LONGER MONITORED.
File changes, SSH logins, command execution and scheduled audits
stop being reported. No further alert will arrive from this server.

If you did not start this, treat it as an intrusion in progress." \
        >/dev/null 2>&1 || true

    echo "[+] Uninstall announced to Telegram."
fi

# ------------------------------------------------------------
# Remove a block the installer appended, identified by its
# marker comment, after backing the file up.
# ------------------------------------------------------------

remove_marker_block() {

    local file="$1" marker="$2"

    [[ -f "$file" ]] || return 0
    grep -Fq "$marker" "$file" || return 0

    cp -a "$file" "$BACKUP_DIR/$(basename "$file").ORIGINAL"

    awk -v marker="$marker" '
        index($0, marker) { skip = 1; next }
        skip && /^fi[[:space:]]*$/ { skip = 0; next }
        skip { next }
        { print }
    ' "$file" > "$file.itm-tmp"

    mv -f "$file.itm-tmp" "$file"

    # A broken shell startup file locks every login out.
    if ! bash -n "$file"; then
        echo "[ERROR] $file failed syntax check after edit."
        echo "        Restoring from $BACKUP_DIR"
        cp -a "$BACKUP_DIR/$(basename "$file").ORIGINAL" "$file"
        return 1
    fi

    echo "[+] Removed ITM block from $file"
}

# ------------------------------------------------------------
# Services
# ------------------------------------------------------------

echo "[+] Stopping services..."

for unit in \
    itm-web-realtime.service \
    itm-web-scan.timer \
    itm-web-scan.service \
    itm-security-audit.timer \
    itm-security-audit.service \
    itm-command-monitor.service \
    security-file-monitor.service
do
    systemctl disable --now "$unit" 2>/dev/null || true
    rm -f "/etc/systemd/system/$unit"
done

systemctl daemon-reload 2>/dev/null || true

# ------------------------------------------------------------
# PAM hook
# ------------------------------------------------------------

PAM_LINE='session optional pam_exec.so /usr/local/sbin/ssh-login-alert'

if [[ -f /etc/pam.d/sshd ]] && grep -Fqx "$PAM_LINE" /etc/pam.d/sshd; then
    cp -a /etc/pam.d/sshd "$BACKUP_DIR/pam.d.sshd.ORIGINAL"
    sed -i "\|^${PAM_LINE}$|d" /etc/pam.d/sshd
    echo "[+] Removed SSH login PAM hook."
fi

# ------------------------------------------------------------
# Command monitoring
# ------------------------------------------------------------

if [[ -f /etc/profile.d/sysadmin.sh ]]; then
    cp -a /etc/profile.d/sysadmin.sh "$BACKUP_DIR/sysadmin.sh.ORIGINAL"
    rm -f /etc/profile.d/sysadmin.sh
    echo "[+] Removed /etc/profile.d/sysadmin.sh"
fi

remove_marker_block /etc/bash.bashrc "# ITM Server Security Monitor - command profile loader" || true
remove_marker_block /etc/bashrc      "# ITM Server Security Monitor - command profile loader" || true
remove_marker_block /root/.bashrc    "# ITM Server Security Monitor - root command loader" || true

# ------------------------------------------------------------
# Scripts, library and modules
# ------------------------------------------------------------

cp -a /usr/local/sbin/security-notify "$BACKUP_DIR/" 2>/dev/null || true

rm -f \
    /usr/local/sbin/security-notify \
    /usr/local/sbin/ssh-login-alert \
    /usr/local/sbin/security-file-monitor \
    /usr/local/sbin/itm-command-relay \
    /usr/local/sbin/itm-security \
    /usr/local/sbin/itm-web-realtime

rm -rf /usr/local/lib/itm-security

rm -f /etc/logrotate.d/itm-security

echo "[+] Removed scripts, audit library and modules."

# ------------------------------------------------------------
# Fail2Ban integration
# ------------------------------------------------------------

for f in /etc/fail2ban/action.d/telegram-security.conf /etc/fail2ban/jail.d/sshd.local; do
    [[ -f "$f" ]] && cp -a "$f" "$BACKUP_DIR/$(basename "$f").ORIGINAL"
    rm -f "$f"
done

if systemctl is-active --quiet fail2ban 2>/dev/null; then
    systemctl restart fail2ban 2>/dev/null || true
fi

echo "[+] Removed Fail2Ban integration."

# ------------------------------------------------------------
# Configuration, state and evidence
# ------------------------------------------------------------

if (( PURGE )); then

    echo
    echo "[!] --purge: removing configuration, audit state and audit logs."
    echo "[!] Audit logs are incident evidence. A copy is kept in the backup directory."

    for f in /etc/security-monitor/telegram.conf \
             /etc/security-monitor/audit.conf \
             /etc/security-monitor/trusted_networks.conf
    do
        [[ -f "$f" ]] && cp -a "$f" "$BACKUP_DIR/$(basename "$f").ORIGINAL"
    done

    # Tuned IOC lists and the integrity baseline represent real
    # operator work; keep a copy even when purging.
    [[ -d /etc/security-monitor/ioc ]] \
        && cp -a /etc/security-monitor/ioc "$BACKUP_DIR/ioc"

    [[ -d /var/lib/itm-security/web-baseline ]] \
        && cp -a /var/lib/itm-security/web-baseline "$BACKUP_DIR/web-baseline"

    # Evidence copies of suspected malicious files are forensic
    # material and are preserved in the backup directory.
    [[ -d /var/lib/itm-security/evidence ]] \
        && cp -a /var/lib/itm-security/evidence "$BACKUP_DIR/evidence"

    if [[ -d /var/log/itm-security ]]; then
        cp -a /var/log/itm-security "$BACKUP_DIR/itm-security-logs"
    fi

    rm -rf \
        /etc/security-monitor \
        /var/lib/itm-security \
        /var/log/itm-security

    echo "[+] Configuration, state and logs removed (copies in $BACKUP_DIR)."

else

    rm -rf /var/lib/itm-security/audit-state /var/lib/itm-security/scan-state
    rm -f  /var/lib/itm-security/host-role.conf

    echo
    echo "[+] Kept intentionally:"
    echo "      /etc/security-monitor/telegram.conf"
    echo "      /etc/security-monitor/audit.conf"
    echo "      /etc/security-monitor/trusted_networks.conf"
    echo "      /etc/security-monitor/ioc/          (tuned IOC lists)"
    echo "      /var/lib/itm-security/web-baseline/ (integrity baseline)"
    echo "      /var/lib/itm-security/evidence/     (captured suspect files)"
    echo "      /var/log/itm-security/              (audit evidence)"
    echo
    echo "    Remove them with: bash uninstall.sh --purge"

fi

# Final notice, sent from the backup copy while it still exists.
if [[ -x "$BACKUP_DIR/security-notify" ]] || command -v curl >/dev/null 2>&1; then
    if [[ -r /etc/security-monitor/telegram.conf ]]; then
        # shellcheck disable=SC1091
        . /etc/security-monitor/telegram.conf 2>/dev/null || true
        if [[ -n "${BOT_TOKEN:-}" && -n "${CHAT_ID:-}" ]]; then
            curl -fsS --max-time 10 -X POST \
                "https://api.telegram.org/bot${BOT_TOKEN}/sendMessage" \
                -d "chat_id=${CHAT_ID}" \
                --data-urlencode "text=🔕 SECURITY MONITOR REMOVED

Host    : $(hostname -f 2>/dev/null || hostname)
Time    : $(date '+%Y-%m-%d %H:%M:%S %Z')

Monitoring has stopped on this host. This is the last message
you will receive from it." >/dev/null 2>&1 || true
        fi
    fi
fi

echo
echo "Uninstall complete."
echo "Backups: $BACKUP_DIR"
echo
echo "NOTE: removing the monitoring does not change the trust status of this"
echo "      host. If it was ever root compromised, it stays UNTRUSTED until it"
echo "      is rebuilt from trusted media."

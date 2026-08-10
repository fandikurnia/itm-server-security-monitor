#!/usr/bin/env bash

set -euo pipefail

# ============================================================
# ITM Server Security Monitor Installer
# Debian / Ubuntu
# ============================================================

if [[ $EUID -ne 0 ]]; then
    echo "Run as root: sudo -E bash install.sh" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

TZ_NAME="${TZ_NAME:-Asia/Jakarta}"
BOT_TOKEN="${BOT_TOKEN:-}"
CHAT_ID="${CHAT_ID:-}"

TELEGRAM_CONF="/etc/security-monitor/telegram.conf"


# ============================================================
# OS CHECK
# ============================================================

if ! command -v apt-get >/dev/null 2>&1; then
    echo "[ERROR] This installer currently supports Debian/Ubuntu." >&2
    exit 1
fi


# ============================================================
# PACKAGES
# ============================================================

echo "[+] Installing required packages..."

export DEBIAN_FRONTEND=noninteractive

apt-get update

apt-get install -y \
    curl \
    inotify-tools \
    fail2ban


# ============================================================
# TIMEZONE
# ============================================================

if command -v timedatectl >/dev/null 2>&1; then
    echo "[+] Setting timezone: $TZ_NAME"
    timedatectl set-timezone "$TZ_NAME" || true
fi


# ============================================================
# TELEGRAM CONFIG
# ============================================================

echo "[+] Checking Telegram configuration..."

install -d -o root -g root -m 700 /etc/security-monitor

if [[ -f "$TELEGRAM_CONF" ]]; then

    echo "[+] Existing Telegram configuration found:"
    echo "    $TELEGRAM_CONF"
    echo "[+] Existing BOT_TOKEN / CHAT_ID will be preserved."

else

    if [[ -z "$BOT_TOKEN" || -z "$CHAT_ID" ]]; then
        echo
        echo "[ERROR] Telegram configuration does not exist."
        echo
        echo "First installation requires:"
        echo
        echo "BOT_TOKEN='xxx' CHAT_ID='123' TZ_NAME='Asia/Jakarta' bash install.sh"
        echo
        exit 1
    fi

    cat > "$TELEGRAM_CONF" <<EOF
BOT_TOKEN="${BOT_TOKEN}"
CHAT_ID="${CHAT_ID}"
EOF

    chown root:root "$TELEGRAM_CONF"
    chmod 600 "$TELEGRAM_CONF"

    echo "[+] Telegram configuration created."
fi


# Always enforce correct permissions
chown root:root "$TELEGRAM_CONF"
chmod 600 "$TELEGRAM_CONF"


# ============================================================
# SECURITY NOTIFICATION SCRIPTS
# ============================================================

echo "[+] Installing notification scripts..."

install \
    -o root \
    -g root \
    -m 0700 \
    "$SCRIPT_DIR/bin/security-notify" \
    /usr/local/sbin/security-notify

install \
    -o root \
    -g root \
    -m 0700 \
    "$SCRIPT_DIR/bin/ssh-login-alert" \
    /usr/local/sbin/ssh-login-alert

install \
    -o root \
    -g root \
    -m 0700 \
    "$SCRIPT_DIR/bin/security-file-monitor" \
    /usr/local/sbin/security-file-monitor


# ============================================================
# FILE MONITOR SYSTEMD
# ============================================================

echo "[+] Installing security file monitor..."

install \
    -o root \
    -g root \
    -m 0644 \
    "$SCRIPT_DIR/systemd/security-file-monitor.service" \
    /etc/systemd/system/security-file-monitor.service


# ============================================================
# FAIL2BAN
# ============================================================

echo "[+] Installing Fail2Ban configuration..."

install \
    -o root \
    -g root \
    -m 0644 \
    "$SCRIPT_DIR/fail2ban/action.d/telegram-security.conf" \
    /etc/fail2ban/action.d/telegram-security.conf

install \
    -o root \
    -g root \
    -m 0644 \
    "$SCRIPT_DIR/fail2ban/jail.d/sshd.local" \
    /etc/fail2ban/jail.d/sshd.local


# ============================================================
# PAM SSH LOGIN ALERT
# ============================================================

echo "[+] Installing SSH login alert..."

PAM_LINE='session optional pam_exec.so /usr/local/sbin/ssh-login-alert'

if [[ -f /etc/pam.d/sshd ]]; then

    if ! grep -Fqx "$PAM_LINE" /etc/pam.d/sshd; then

        PAM_BACKUP="/etc/pam.d/sshd.before-itm-security-monitor.$(date +%Y%m%d%H%M%S)"

        cp -a /etc/pam.d/sshd "$PAM_BACKUP"

        printf '\n%s\n' "$PAM_LINE" >> /etc/pam.d/sshd

        echo "[+] PAM sshd backup:"
        echo "    $PAM_BACKUP"

    else

        echo "[+] SSH login PAM hook already installed."

    fi

fi


# ============================================================
# COMMAND MONITOR FORENSIC PRESERVATION
# ============================================================

echo "[+] Installing ITM command monitoring..."

if [[ -f /etc/profile.d/sysadmin.sh ]]; then

    # Only make a forensic copy if installed file differs
    # from the repository version.

    if ! cmp -s \
        /etc/profile.d/sysadmin.sh \
        "$SCRIPT_DIR/bin/itm-command-profile"; then

        BACKUP_DIR="/root/forensic/security-monitor-install-$(date +%Y%m%d-%H%M%S)"

        mkdir -p "$BACKUP_DIR"

        cp -a \
            /etc/profile.d/sysadmin.sh \
            "$BACKUP_DIR/sysadmin.sh.ORIGINAL"

        stat \
            /etc/profile.d/sysadmin.sh \
            > "$BACKUP_DIR/sysadmin.sh.stat.txt"

        sha256sum \
            /etc/profile.d/sysadmin.sh \
            > "$BACKUP_DIR/sysadmin.sh.sha256.txt"

        chmod 700 "$BACKUP_DIR"

        echo "[+] Existing sysadmin.sh preserved:"
        echo "    $BACKUP_DIR"

    else

        echo "[+] Existing command monitor already matches repository."

    fi

fi


# ============================================================
# INSTALL GLOBAL COMMAND PROFILE
# ============================================================

install \
    -o root \
    -g root \
    -m 0644 \
    "$SCRIPT_DIR/bin/itm-command-profile" \
    /etc/profile.d/sysadmin.sh


# ============================================================
# VALIDATE COMMAND PROFILE
# ============================================================

echo "[+] Validating command monitor syntax..."

if ! bash -n /etc/profile.d/sysadmin.sh; then

    echo "[ERROR] /etc/profile.d/sysadmin.sh syntax validation failed."
    exit 1

fi

echo "[+] Command profile syntax OK."


# ============================================================
# COMMAND RELAY
# ============================================================

install \
    -o root \
    -g root \
    -m 0700 \
    "$SCRIPT_DIR/bin/itm-command-relay" \
    /usr/local/sbin/itm-command-relay


# ============================================================
# COMMAND MONITOR SYSTEMD SERVICE
# ============================================================

install \
    -o root \
    -g root \
    -m 0644 \
    "$SCRIPT_DIR/systemd/itm-command-monitor.service" \
    /etc/systemd/system/itm-command-monitor.service


# ============================================================
# SYSTEMD
# ============================================================

echo "[+] Reloading systemd..."

systemctl daemon-reload

systemctl enable --now security-file-monitor.service

systemctl enable itm-command-monitor.service
systemctl restart itm-command-monitor.service


# ============================================================
# FAIL2BAN VALIDATION
# ============================================================

echo "[+] Validating Fail2Ban..."

fail2ban-client -t

systemctl enable --now fail2ban
systemctl restart fail2ban


# ============================================================
# VERIFICATION
# ============================================================

echo
echo "============================================================"
echo " ITM Server Security Monitor - Verification"
echo "============================================================"

echo
echo "[*] Telegram config:"
if [[ -f "$TELEGRAM_CONF" ]]; then
    echo "    OK"
else
    echo "    MISSING"
fi


echo
echo "[*] security-notify:"
if [[ -x /usr/local/sbin/security-notify ]]; then
    echo "    OK"
else
    echo "    MISSING"
fi


echo
echo "[*] Command profile:"
if bash -n /etc/profile.d/sysadmin.sh >/dev/null 2>&1; then
    echo "    OK"
else
    echo "    ERROR"
fi


echo
echo "[*] Command relay:"
if systemctl is-active --quiet itm-command-monitor.service; then
    echo "    ACTIVE"
else
    echo "    FAILED"
fi


echo
echo "[*] File monitor:"
if systemctl is-active --quiet security-file-monitor.service; then
    echo "    ACTIVE"
else
    echo "    FAILED"
fi


echo
echo "[*] Fail2Ban:"
if systemctl is-active --quiet fail2ban; then
    echo "    ACTIVE"
else
    echo "    FAILED"
fi


echo
echo "============================================================"


# ============================================================
# TELEGRAM INSTALL TEST
# ============================================================

/usr/local/sbin/security-notify \
    "✅ ITM Security Monitor installed/updated successfully" \
    || true


echo
echo "Installation complete."
echo
echo "Useful checks:"
echo
echo "  systemctl status security-file-monitor --no-pager"
echo "  systemctl status itm-command-monitor --no-pager"
echo "  fail2ban-client status sshd"
echo "  journalctl -t itm-command-monitor -n 20 --no-pager"
echo
echo "IMPORTANT:"
echo "  Existing SSH authentication policy was NOT modified."
echo "  Open a NEW login shell before testing command monitoring."
echo
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
# REQUIRED REPOSITORY FILES
# ============================================================

REQUIRED_FILES=(
    "$SCRIPT_DIR/bin/security-notify"
    "$SCRIPT_DIR/bin/ssh-login-alert"
    "$SCRIPT_DIR/bin/security-file-monitor"
    "$SCRIPT_DIR/bin/itm-command-profile"
    "$SCRIPT_DIR/bin/itm-command-relay"
    "$SCRIPT_DIR/systemd/security-file-monitor.service"
    "$SCRIPT_DIR/systemd/itm-command-monitor.service"
    "$SCRIPT_DIR/fail2ban/action.d/telegram-security.conf"
    "$SCRIPT_DIR/fail2ban/jail.d/sshd.local"
)

for file in "${REQUIRED_FILES[@]}"; do
    if [[ ! -f "$file" ]]; then
        echo "[ERROR] Required repository file missing:"
        echo "        $file"
        exit 1
    fi
done

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

apt-get update --allow-releaseinfo-change

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

install -d -o root -g root -m 0700 /etc/security-monitor

if [[ -f "$TELEGRAM_CONF" ]]; then

    echo "[+] Existing Telegram configuration found:"
    echo "    $TELEGRAM_CONF"
    echo "[+] Existing BOT_TOKEN / CHAT_ID preserved."

else

    if [[ -z "$BOT_TOKEN" || -z "$CHAT_ID" ]]; then
        echo
        echo "[ERROR] Telegram configuration does not exist."
        echo
        echo "First installation:"
        echo
        echo "BOT_TOKEN='xxx' CHAT_ID='123' TZ_NAME='Asia/Jakarta' bash install.sh"
        echo
        exit 1
    fi

    cat > "$TELEGRAM_CONF" <<CFG
BOT_TOKEN="${BOT_TOKEN}"
CHAT_ID="${CHAT_ID}"
CFG

    echo "[+] Telegram configuration created."
fi

chown root:root "$TELEGRAM_CONF"
chmod 600 "$TELEGRAM_CONF"

# ============================================================
# INSTALL NOTIFICATION COMPONENTS
# ============================================================

echo "[+] Installing notification scripts..."

install -o root -g root -m 0700 \
    "$SCRIPT_DIR/bin/security-notify" \
    /usr/local/sbin/security-notify

install -o root -g root -m 0700 \
    "$SCRIPT_DIR/bin/ssh-login-alert" \
    /usr/local/sbin/ssh-login-alert

install -o root -g root -m 0700 \
    "$SCRIPT_DIR/bin/security-file-monitor" \
    /usr/local/sbin/security-file-monitor

# ============================================================
# FILE MONITOR SERVICE
# ============================================================

install -o root -g root -m 0644 \
    "$SCRIPT_DIR/systemd/security-file-monitor.service" \
    /etc/systemd/system/security-file-monitor.service

# ============================================================
# FAIL2BAN
# ============================================================

echo "[+] Installing Fail2Ban configuration..."

install -o root -g root -m 0644 \
    "$SCRIPT_DIR/fail2ban/action.d/telegram-security.conf" \
    /etc/fail2ban/action.d/telegram-security.conf

install -o root -g root -m 0644 \
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
# PRESERVE OLD COMMAND MONITOR
# ============================================================

echo "[+] Installing ITM command monitor..."

if [[ -f /etc/profile.d/sysadmin.sh ]]; then

    if ! cmp -s \
        /etc/profile.d/sysadmin.sh \
        "$SCRIPT_DIR/bin/itm-command-profile"; then

        BACKUP_DIR="/root/forensic/security-monitor-install-$(date +%Y%m%d-%H%M%S)"

        mkdir -p "$BACKUP_DIR"
        chmod 700 "$BACKUP_DIR"

        cp -a \
            /etc/profile.d/sysadmin.sh \
            "$BACKUP_DIR/sysadmin.sh.ORIGINAL"

        stat /etc/profile.d/sysadmin.sh \
            > "$BACKUP_DIR/sysadmin.sh.stat.txt"

        sha256sum /etc/profile.d/sysadmin.sh \
            > "$BACKUP_DIR/sysadmin.sh.sha256.txt"

        echo "[+] Existing sysadmin.sh preserved:"
        echo "    $BACKUP_DIR"
    else
        echo "[+] Existing command profile already matches repository."
    fi
fi

# ============================================================
# GLOBAL LOGIN SHELL COMMAND MONITOR
# ============================================================

install -o root -g root -m 0644 \
    "$SCRIPT_DIR/bin/itm-command-profile" \
    /etc/profile.d/sysadmin.sh

echo "[+] Validating command profile..."

bash -n /etc/profile.d/sysadmin.sh

echo "[+] Command profile syntax OK."

# ============================================================
# NON-LOGIN BASH SHELL SUPPORT
#
# Required for:
#   sudo su
#   bash
#   interactive non-login root shells
# ============================================================

echo "[+] Enabling monitoring for non-login Bash shells..."

BASHRC_FILE="/etc/bash.bashrc"
BASHRC_MARKER="# ITM Server Security Monitor - command profile loader"
BASHRC_SOURCE='source /etc/profile.d/sysadmin.sh'

if [[ -f "$BASHRC_FILE" ]]; then

    if ! grep -Fq "$BASHRC_MARKER" "$BASHRC_FILE"; then

        BASHRC_BACKUP_DIR="/root/forensic/bashrc-monitor-$(date +%Y%m%d-%H%M%S)"

        mkdir -p "$BASHRC_BACKUP_DIR"
        chmod 700 "$BASHRC_BACKUP_DIR"

        cp -a \
            "$BASHRC_FILE" \
            "$BASHRC_BACKUP_DIR/bash.bashrc.ORIGINAL"

        stat "$BASHRC_FILE" \
            > "$BASHRC_BACKUP_DIR/bash.bashrc.stat.txt"

        sha256sum "$BASHRC_FILE" \
            > "$BASHRC_BACKUP_DIR/bash.bashrc.sha256.txt"

        cat >> "$BASHRC_FILE" <<'BASHRC'

# ITM Server Security Monitor - command profile loader
if [ -r /etc/profile.d/sysadmin.sh ]; then
    source /etc/profile.d/sysadmin.sh
fi
BASHRC

        echo "[+] /etc/bash.bashrc loader installed."
        echo "[+] Original preserved:"
        echo "    $BASHRC_BACKUP_DIR"

    else
        echo "[+] /etc/bash.bashrc loader already installed."
    fi

    bash -n "$BASHRC_FILE"
fi

# ============================================================
# COMMAND RELAY
# ============================================================

install -o root -g root -m 0700 \
    "$SCRIPT_DIR/bin/itm-command-relay" \
    /usr/local/sbin/itm-command-relay

# ============================================================
# COMMAND MONITOR SYSTEMD SERVICE
# ============================================================

install -o root -g root -m 0644 \
    "$SCRIPT_DIR/systemd/itm-command-monitor.service" \
    /etc/systemd/system/itm-command-monitor.service

# ============================================================
# SYSTEMD
# ============================================================

echo "[+] Reloading systemd..."

systemctl daemon-reload

systemctl enable --now security-file-monitor.service
systemctl enable --now itm-command-monitor.service

# ============================================================
# FAIL2BAN
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

check_result() {
    local label="$1"
    local result="$2"

    printf "%-28s %s\n" "$label" "$result"
}

if [[ -f "$TELEGRAM_CONF" ]]; then
    check_result "Telegram config:" "OK"
else
    check_result "Telegram config:" "MISSING"
fi

if [[ -x /usr/local/sbin/security-notify ]]; then
    check_result "security-notify:" "OK"
else
    check_result "security-notify:" "MISSING"
fi

if bash -n /etc/profile.d/sysadmin.sh >/dev/null 2>&1; then
    check_result "Command profile:" "OK"
else
    check_result "Command profile:" "ERROR"
fi

if systemctl is-active --quiet itm-command-monitor.service; then
    check_result "Command relay:" "ACTIVE"
else
    check_result "Command relay:" "FAILED"
fi

if systemctl is-active --quiet security-file-monitor.service; then
    check_result "File monitor:" "ACTIVE"
else
    check_result "File monitor:" "FAILED"
fi

if systemctl is-active --quiet fail2ban; then
    check_result "Fail2Ban:" "ACTIVE"
else
    check_result "Fail2Ban:" "FAILED"
fi

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
echo "  systemctl status security-file-monitor --no-pager"
echo "  systemctl status itm-command-monitor --no-pager"
echo "  fail2ban-client status sshd"
echo "  journalctl -t itm-command-monitor -n 20 --no-pager"
echo
echo "Command monitor tests:"
echo "  Open a NEW SSH/login shell."
echo "  Test: whoami"
echo "  Test root: sudo su"
echo "  Then run: whoami ; hostname ; uptime"
echo
echo "IMPORTANT:"
echo "  Existing SSH authentication policy was NOT modified."
echo "  Telegram credentials remain local in:"
echo "  $TELEGRAM_CONF"

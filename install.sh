#!/usr/bin/env bash

set -euo pipefail

# ============================================================
# ITM Server Security Monitor
# Multi-Distro Installer
#
# Supported:
#   Debian / Ubuntu
#   AlmaLinux / Rocky Linux / RHEL compatible
# ============================================================

if [[ $EUID -ne 0 ]]; then
    echo "[ERROR] Run installer as root." >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

TZ_NAME="${TZ_NAME:-Asia/Jakarta}"
BOT_TOKEN="${BOT_TOKEN:-}"
CHAT_ID="${CHAT_ID:-}"

TELEGRAM_CONF="/etc/security-monitor/telegram.conf"

# ITM trusted networks
TRUSTED_NETWORKS="127.0.0.1/8 ::1 192.168.100.0/24 192.168.111.0/24 103.166.224.0/24"

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
)

for file in "${REQUIRED_FILES[@]}"; do
    if [[ ! -f "$file" ]]; then
        echo "[ERROR] Required repository file missing:"
        echo "        $file"
        exit 1
    fi
done

# ============================================================
# OS DETECTION
# ============================================================

if [[ ! -r /etc/os-release ]]; then
    echo "[ERROR] Cannot detect Linux distribution."
    exit 1
fi

# shellcheck disable=SC1091
source /etc/os-release

OS_ID="${ID:-unknown}"
OS_LIKE="${ID_LIKE:-}"
OS_VERSION="${VERSION_ID:-unknown}"
OS_FAMILY="unknown"

case "$OS_ID" in
    ubuntu|debian)
        OS_FAMILY="debian"
        ;;
    almalinux|rocky|rhel|centos|ol)
        OS_FAMILY="rhel"
        ;;
    *)
        if [[ "$OS_LIKE" == *debian* ]]; then
            OS_FAMILY="debian"
        elif [[ "$OS_LIKE" == *rhel* || "$OS_LIKE" == *fedora* ]]; then
            OS_FAMILY="rhel"
        fi
        ;;
esac

if [[ "$OS_FAMILY" == "unknown" ]]; then
    echo "[ERROR] Unsupported Linux distribution:"
    echo "        ID=$OS_ID VERSION=$OS_VERSION ID_LIKE=$OS_LIKE"
    exit 1
fi

echo
echo "============================================================"
echo " ITM Server Security Monitor"
echo "============================================================"
echo "OS          : $OS_ID"
echo "Version     : $OS_VERSION"
echo "Family      : $OS_FAMILY"
echo "Timezone    : $TZ_NAME"
echo "============================================================"
echo

# ============================================================
# PACKAGE CHECK
#
# Do not update package repositories when everything already
# exists. This prevents broken legacy repositories from
# blocking the security monitor installation.
# ============================================================

echo "[+] Checking required packages..."

MISSING_PACKAGES=()

command -v curl >/dev/null 2>&1 \
    || MISSING_PACKAGES+=("curl")

command -v inotifywait >/dev/null 2>&1 \
    || MISSING_PACKAGES+=("inotify-tools")

command -v fail2ban-client >/dev/null 2>&1 \
    || MISSING_PACKAGES+=("fail2ban")

if (( ${#MISSING_PACKAGES[@]} > 0 )); then

    echo "[+] Missing packages:"
    printf '    %s\n' "${MISSING_PACKAGES[@]}"

    case "$OS_FAMILY" in

        debian)

            export DEBIAN_FRONTEND=noninteractive

            echo "[+] Running apt-get update..."

            if ! apt-get update --allow-releaseinfo-change; then
                echo
                echo "[ERROR] apt-get update failed."
                echo "Fix broken APT repositories and run installer again."
                exit 1
            fi

            apt-get install -y "${MISSING_PACKAGES[@]}"
            ;;

        rhel)

            if command -v dnf >/dev/null 2>&1; then
                PKG_MGR="dnf"
            elif command -v yum >/dev/null 2>&1; then
                PKG_MGR="yum"
            else
                echo "[ERROR] dnf/yum not found."
                exit 1
            fi

            #
            # Fail2Ban is provided through EPEL on
            # Enterprise Linux compatible distributions.
            #
            if ! rpm -q epel-release >/dev/null 2>&1; then

                echo "[+] Installing EPEL repository..."

                "$PKG_MGR" install -y epel-release

            else

                echo "[+] EPEL repository already installed."

            fi

            "$PKG_MGR" install -y "${MISSING_PACKAGES[@]}"
            ;;

    esac

else

    echo "[+] All required packages already installed."
    echo "[+] Package repository update skipped."

fi

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

install -d \
    -o root \
    -g root \
    -m 0700 \
    /etc/security-monitor

if [[ -f "$TELEGRAM_CONF" ]]; then

    echo "[+] Existing Telegram configuration found."
    echo "[+] Existing BOT_TOKEN / CHAT_ID preserved."

else

    if [[ -z "$BOT_TOKEN" || -z "$CHAT_ID" ]]; then

        echo
        echo "[ERROR] Telegram configuration does not exist."
        echo
        echo "For first installation use:"
        echo
        echo 'read -rsp "BOT_TOKEN: " BOT_TOKEN'
        echo 'echo'
        echo 'read -rp "CHAT_ID: " CHAT_ID'
        echo 'export BOT_TOKEN CHAT_ID'
        echo 'bash install.sh'
        echo 'unset BOT_TOKEN CHAT_ID'
        echo
        exit 1

    fi

    cat > "$TELEGRAM_CONF" <<EOF
BOT_TOKEN="${BOT_TOKEN}"
CHAT_ID="${CHAT_ID}"
EOF

    echo "[+] Telegram configuration created."

fi

chown root:root "$TELEGRAM_CONF"
chmod 600 "$TELEGRAM_CONF"

# ============================================================
# INSTALL SECURITY SCRIPTS
# ============================================================

echo "[+] Installing security scripts..."

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

install \
    -o root \
    -g root \
    -m 0700 \
    "$SCRIPT_DIR/bin/itm-command-relay" \
    /usr/local/sbin/itm-command-relay

# ============================================================
# INSTALL SYSTEMD SERVICES
# ============================================================

echo "[+] Installing systemd services..."

install \
    -o root \
    -g root \
    -m 0644 \
    "$SCRIPT_DIR/systemd/security-file-monitor.service" \
    /etc/systemd/system/security-file-monitor.service

install \
    -o root \
    -g root \
    -m 0644 \
    "$SCRIPT_DIR/systemd/itm-command-monitor.service" \
    /etc/systemd/system/itm-command-monitor.service

# ============================================================
# SSH LOGIN PAM ALERT
# ============================================================

echo "[+] Configuring SSH login alert..."

PAM_LINE='session optional pam_exec.so /usr/local/sbin/ssh-login-alert'

if [[ -f /etc/pam.d/sshd ]]; then

    if ! grep -Fqx "$PAM_LINE" /etc/pam.d/sshd; then

        PAM_BACKUP="/etc/pam.d/sshd.before-itm-security-monitor.$(date +%Y%m%d%H%M%S)"

        cp -a \
            /etc/pam.d/sshd \
            "$PAM_BACKUP"

        printf '\n%s\n' \
            "$PAM_LINE" \
            >> /etc/pam.d/sshd

        echo "[+] PAM backup:"
        echo "    $PAM_BACKUP"

    else

        echo "[+] SSH PAM hook already installed."

    fi

fi

# ============================================================
# PRESERVE EXISTING / LEGACY SYSADMIN.SH
# ============================================================

echo "[+] Installing command monitor..."

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

        stat \
            /etc/profile.d/sysadmin.sh \
            > "$BACKUP_DIR/sysadmin.sh.stat.txt"

        sha256sum \
            /etc/profile.d/sysadmin.sh \
            > "$BACKUP_DIR/sysadmin.sh.sha256.txt"

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

bash -n /etc/profile.d/sysadmin.sh

echo "[+] Command profile syntax OK."

# ============================================================
# GLOBAL NON-LOGIN BASH SUPPORT
#
# Debian / Ubuntu:
#   /etc/bash.bashrc
#
# Alma / Rocky / RHEL:
#   /etc/bashrc
# ============================================================

if [[ "$OS_FAMILY" == "debian" ]]; then
    GLOBAL_BASHRC="/etc/bash.bashrc"
else
    GLOBAL_BASHRC="/etc/bashrc"
fi

echo "[+] Configuring global Bash monitor:"
echo "    $GLOBAL_BASHRC"

BASHRC_MARKER="# ITM Server Security Monitor - command profile loader"

if [[ -f "$GLOBAL_BASHRC" ]]; then

    if ! grep -Fq "$BASHRC_MARKER" "$GLOBAL_BASHRC"; then

        BASHRC_BACKUP_DIR="/root/forensic/bashrc-monitor-$(date +%Y%m%d-%H%M%S)"

        mkdir -p "$BASHRC_BACKUP_DIR"
        chmod 700 "$BASHRC_BACKUP_DIR"

        cp -a \
            "$GLOBAL_BASHRC" \
            "$BASHRC_BACKUP_DIR/bashrc.ORIGINAL"

        stat \
            "$GLOBAL_BASHRC" \
            > "$BASHRC_BACKUP_DIR/bashrc.stat.txt"

        sha256sum \
            "$GLOBAL_BASHRC" \
            > "$BASHRC_BACKUP_DIR/bashrc.sha256.txt"

        cat >> "$GLOBAL_BASHRC" <<'EOF'

# ITM Server Security Monitor - command profile loader
if [ -r /etc/profile.d/sysadmin.sh ]; then
    source /etc/profile.d/sysadmin.sh
fi
EOF

        echo "[+] Global Bash loader installed."

    else

        echo "[+] Global Bash loader already installed."

    fi

    bash -n "$GLOBAL_BASHRC"

fi

# ============================================================
# ROOT INTERACTIVE SHELL SUPPORT
#
# Required because sudo su / root shells may not always load
# /etc/profile.d automatically.
# ============================================================

echo "[+] Configuring root command monitoring..."

ROOT_BASHRC="/root/.bashrc"
ROOT_MARKER="# ITM Server Security Monitor - root command loader"

touch "$ROOT_BASHRC"

if ! grep -Fq "$ROOT_MARKER" "$ROOT_BASHRC"; then

    ROOT_BACKUP_DIR="/root/forensic/root-bashrc-$(date +%Y%m%d-%H%M%S)"

    mkdir -p "$ROOT_BACKUP_DIR"
    chmod 700 "$ROOT_BACKUP_DIR"

    cp -a \
        "$ROOT_BASHRC" \
        "$ROOT_BACKUP_DIR/root.bashrc.ORIGINAL"

    stat \
        "$ROOT_BASHRC" \
        > "$ROOT_BACKUP_DIR/root.bashrc.stat.txt"

    sha256sum \
        "$ROOT_BASHRC" \
        > "$ROOT_BACKUP_DIR/root.bashrc.sha256.txt"

    cat >> "$ROOT_BASHRC" <<'EOF'

# ITM Server Security Monitor - root command loader
if [ -r /etc/profile.d/sysadmin.sh ]; then
    source /etc/profile.d/sysadmin.sh
fi
EOF

    echo "[+] Root command monitoring enabled."

else

    echo "[+] Root command monitoring already enabled."

fi

bash -n "$ROOT_BASHRC"

# ============================================================
# FAIL2BAN TELEGRAM ACTION
# ============================================================

echo "[+] Installing Fail2Ban Telegram action..."

install \
    -o root \
    -g root \
    -m 0644 \
    "$SCRIPT_DIR/fail2ban/action.d/telegram-security.conf" \
    /etc/fail2ban/action.d/telegram-security.conf

# ============================================================
# FAIL2BAN BACKEND
#
# Prefer systemd journal for portability between:
#
# Debian/Ubuntu:
#   /var/log/auth.log
#
# RHEL family:
#   /var/log/secure
#
# With systemd backend no log path needs to be hardcoded.
# ============================================================

FAIL2BAN_BACKEND="systemd"

# ============================================================
# FAIL2BAN BAN ACTION
# ============================================================

if systemctl is-active --quiet firewalld 2>/dev/null \
    && [[ -f /etc/fail2ban/action.d/firewallcmd-rich-rules.conf ]]; then

    F2B_BAN_ACTION="firewallcmd-rich-rules"

elif [[ -f /etc/fail2ban/action.d/nftables-multiport.conf ]] \
    && command -v nft >/dev/null 2>&1; then

    F2B_BAN_ACTION="nftables-multiport"

else

    F2B_BAN_ACTION="iptables-multiport"

fi

echo "[+] Fail2Ban firewall action:"
echo "    $F2B_BAN_ACTION"

# ============================================================
# GENERATE FAIL2BAN SSH CONFIG
#
# Generated here intentionally so one install.sh works across
# both Linux families.
# ============================================================

cat > /etc/fail2ban/jail.d/sshd.local <<EOF
[sshd]

enabled = true
port = ssh
filter = sshd

backend = ${FAIL2BAN_BACKEND}

maxretry = 5
findtime = 10m
bantime = 1h

# ITM trusted management networks
ignoreip = ${TRUSTED_NETWORKS}

action = ${F2B_BAN_ACTION}[name=SSHD, port="22", protocol=tcp]
         telegram-security[name=SSHD]
EOF

chown root:root /etc/fail2ban/jail.d/sshd.local
chmod 644 /etc/fail2ban/jail.d/sshd.local

# ============================================================
# SYSTEMD
# ============================================================

echo "[+] Reloading systemd..."

systemctl daemon-reload

systemctl enable --now \
    security-file-monitor.service

systemctl enable --now \
    itm-command-monitor.service

# ============================================================
# FAIL2BAN VALIDATION
# ============================================================

echo "[+] Validating Fail2Ban..."

if ! fail2ban-client -t; then

    echo
    echo "[ERROR] Fail2Ban configuration validation failed."
    echo
    echo "Check:"
    echo "    /etc/fail2ban/jail.d/sshd.local"
    echo
    exit 1

fi

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
    local value="$2"

    printf "%-30s %s\n" \
        "$label" \
        "$value"
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

check_result "OS family:" "$OS_FAMILY"
check_result "Global Bash RC:" "$GLOBAL_BASHRC"
check_result "Fail2Ban backend:" "$FAIL2BAN_BACKEND"
check_result "Fail2Ban action:" "$F2B_BAN_ACTION"

echo "============================================================"

# ============================================================
# TELEGRAM INSTALL TEST
# ============================================================

/usr/local/sbin/security-notify \
    "✅ ITM Security Monitor installed/updated successfully

OS      : ${OS_ID} ${OS_VERSION}
Family  : ${OS_FAMILY}" \
    || true

# ============================================================
# FINAL INFORMATION
# ============================================================

echo
echo "Installation complete."
echo

echo "Trusted Fail2Ban networks:"
for net in $TRUSTED_NETWORKS; do
    echo "  - $net"
done

echo
echo "Useful checks:"
echo
echo "  systemctl status security-file-monitor --no-pager"
echo "  systemctl status itm-command-monitor --no-pager"
echo "  systemctl status fail2ban --no-pager"
echo "  fail2ban-client status sshd"
echo "  fail2ban-client get sshd ignoreip"
echo "  journalctl -t itm-command-monitor -n 20 --no-pager"
echo

echo "Command monitoring test:"
echo
echo "  Open a NEW login shell."
echo "  whoami"
echo "  hostname"
echo "  uptime"
echo
echo "  sudo su"
echo "  whoami"
echo "  hostname"
echo "  uptime"
echo

echo "IMPORTANT:"
echo "  Existing SSH authentication policy was NOT modified."
echo "  Telegram credentials remain local in:"
echo "  $TELEGRAM_CONF"
echo
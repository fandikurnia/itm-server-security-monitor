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
#
# Single source of truth for both the Fail2Ban ignoreip policy
# and the post-compromise audit's trusted network policy.
TRUSTED_NETWORKS="127.0.0.1/8 ::1 192.168.100.0/24 192.168.111.0/24 103.166.224.0/24"

# ============================================================
# POST-COMPROMISE AUDIT
# ============================================================

AUDIT_CONF="/etc/security-monitor/audit.conf"
TRUSTED_NET_CONF="/etc/security-monitor/trusted_networks.conf"

AUDIT_LIB_DIR="/usr/local/lib/itm-security"
AUDIT_MODULE_DIR="$AUDIT_LIB_DIR/modules"

AUDIT_LOG_DIR="/var/log/itm-security"
AUDIT_STATE_DIR="/var/lib/itm-security/audit-state"

AUDIT_IOC_DIR="/etc/security-monitor/ioc"
WEB_BASELINE_DIR="/var/lib/itm-security/web-baseline"
WEB_SCAN_STATE_DIR="/var/lib/itm-security/scan-state"
WEB_EVIDENCE_DIR="/var/lib/itm-security/evidence"

AUDIT_MODULES=(
    audit_role.sh
    audit_health.sh
    audit_process.sh
    audit_network.sh
    audit_pam.sh
    audit_systemd.sh
    audit_cron.sh
    audit_command.sh
    audit_ioc.sh
    audit_sshd.sh
    audit_ssh_session.sh
    audit_nginx.sh
    audit_apache.sh
    audit_php.sh
    audit_web.sh
    audit_webshell.sh
    audit_gambling.sh
    audit_seo.sh
    audit_integrity.sh
    audit_fail2ban.sh
)

# IOC databases. Installed only when absent, so operator tuning
# and site specific allowlists are never overwritten.
AUDIT_IOC_FILES=(
    gambling-keywords.conf
    webshell-patterns.conf
    seo-poisoning-patterns.conf
    suspicious-filenames.conf
    web-exclusions.conf
    known-iocs.conf
)

# Set to 0 to install the web monitoring without enabling the
# three hourly scan or the realtime watcher.
INSTALL_WEB_MONITOR="${INSTALL_WEB_MONITOR:-1}"

# Set INSTALL_AUDIT_TIMER=0 to install the audit tooling without
# enabling the nightly run.
INSTALL_AUDIT_TIMER="${INSTALL_AUDIT_TIMER:-1}"

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
    "$SCRIPT_DIR/bin/itm-security"
    "$SCRIPT_DIR/lib/itm-audit-common.sh"
    "$SCRIPT_DIR/config/audit.conf.example"
    "$SCRIPT_DIR/systemd/itm-security-audit.service"
    "$SCRIPT_DIR/systemd/itm-security-audit.timer"
    "$SCRIPT_DIR/logrotate/itm-security"
    "$SCRIPT_DIR/lib/itm-web-common.sh"
    "$SCRIPT_DIR/lib/itm-remediate.sh"
    "$SCRIPT_DIR/bin/itm-web-realtime"
    "$SCRIPT_DIR/systemd/itm-web-scan.service"
    "$SCRIPT_DIR/systemd/itm-web-scan.timer"
    "$SCRIPT_DIR/systemd/itm-web-realtime.service"
)

for ioc in "${AUDIT_IOC_FILES[@]}"; do
    REQUIRED_FILES+=("$SCRIPT_DIR/config/${ioc}.example")
done

for module in "${AUDIT_MODULES[@]}"; do
    REQUIRED_FILES+=("$SCRIPT_DIR/modules/$module")
done

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
# INSTALL POST-COMPROMISE AUDIT
#
# The audit is read only. It reports and alerts; it never
# kills a process, deletes a file, disables a service or edits
# an Nginx, PHP or PAM configuration.
# ============================================================

echo "[+] Installing post-compromise audit..."

install \
    -o root \
    -g root \
    -m 0700 \
    -d "$AUDIT_LIB_DIR" "$AUDIT_MODULE_DIR"

install \
    -o root \
    -g root \
    -m 0600 \
    "$SCRIPT_DIR/lib/itm-audit-common.sh" \
    "$AUDIT_LIB_DIR/itm-audit-common.sh"

for module in "${AUDIT_MODULES[@]}"; do

    install \
        -o root \
        -g root \
        -m 0600 \
        "$SCRIPT_DIR/modules/$module" \
        "$AUDIT_MODULE_DIR/$module"

    bash -n "$AUDIT_MODULE_DIR/$module"

done

install \
    -o root \
    -g root \
    -m 0600 \
    "$SCRIPT_DIR/lib/itm-web-common.sh"
    "$SCRIPT_DIR/lib/itm-remediate.sh" \
    "$AUDIT_LIB_DIR/itm-web-common.sh"

install \
    -o root \
    -g root \
    -m 0700 \
    "$SCRIPT_DIR/bin/itm-security" \
    /usr/local/sbin/itm-security

install \
    -o root \
    -g root \
    -m 0700 \
    "$SCRIPT_DIR/bin/itm-web-realtime" \
    /usr/local/sbin/itm-web-realtime

bash -n /usr/local/sbin/itm-security
bash -n /usr/local/sbin/itm-web-realtime

echo "[+] Audit modules installed: ${#AUDIT_MODULES[@]}"

# ------------------------------------------------------------
# Audit output directories
#
# Logs are evidence: keep them root readable only, and never
# remove them on upgrade or uninstall.
# ------------------------------------------------------------

install -o root -g root -m 0750 -d "$AUDIT_LOG_DIR"
install -o root -g root -m 0700 -d "$AUDIT_STATE_DIR"
install -o root -g root -m 0700 -d "$WEB_BASELINE_DIR"
install -o root -g root -m 0700 -d "$WEB_SCAN_STATE_DIR"
install -o root -g root -m 0700 -d "$WEB_EVIDENCE_DIR"

# ------------------------------------------------------------
# IOC databases
#
# Keyword and pattern lists live outside the modules so they can
# be tuned per site. Existing files are never overwritten: an
# operator's allowlist is not the installer's to discard.
# ------------------------------------------------------------

install -o root -g root -m 0700 -d "$AUDIT_IOC_DIR"

for ioc in "${AUDIT_IOC_FILES[@]}"; do

    if [[ -f "$AUDIT_IOC_DIR/$ioc" ]]; then
        echo "[+] Existing IOC list preserved: $ioc"
    else
        install \
            -o root \
            -g root \
            -m 0600 \
            "$SCRIPT_DIR/config/${ioc}.example" \
            "$AUDIT_IOC_DIR/$ioc"
        echo "[+] IOC list installed: $ioc"
    fi

done

# ------------------------------------------------------------
# Audit configuration
#
# Existing files are never overwritten, so local tuning and the
# operator's host trust decision survive a reinstall.
# ------------------------------------------------------------

if [[ -f "$AUDIT_CONF" ]]; then

    echo "[+] Existing audit.conf preserved."

else

    install \
        -o root \
        -g root \
        -m 0600 \
        "$SCRIPT_DIR/config/audit.conf.example" \
        "$AUDIT_CONF"

    echo "[+] audit.conf created from example."

fi

if [[ -f "$TRUSTED_NET_CONF" ]]; then

    echo "[+] Existing trusted_networks.conf preserved."

else

    #
    # Generated from TRUSTED_NETWORKS so the audit policy and
    # the Fail2Ban ignoreip policy cannot drift apart.
    #
    {
        echo "# ITM Server Security Monitor"
        echo "# Trusted network policy - generated by install.sh on $(date '+%Y-%m-%d %H:%M:%S %Z')"
        echo "#"
        echo "# Edit freely: the installer will not overwrite this file again."
        echo
        for net in $TRUSTED_NETWORKS; do
            echo "$net"
        done
    } > "$TRUSTED_NET_CONF"

    chown root:root "$TRUSTED_NET_CONF"
    chmod 600 "$TRUSTED_NET_CONF"

    echo "[+] trusted_networks.conf created."

fi

# ------------------------------------------------------------
# Log rotation
# ------------------------------------------------------------

if [[ -d /etc/logrotate.d ]]; then

    install \
        -o root \
        -g root \
        -m 0644 \
        "$SCRIPT_DIR/logrotate/itm-security" \
        /etc/logrotate.d/itm-security

    echo "[+] Log rotation installed."

fi

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

install \
    -o root \
    -g root \
    -m 0644 \
    "$SCRIPT_DIR/systemd/itm-security-audit.service" \
    /etc/systemd/system/itm-security-audit.service

install \
    -o root \
    -g root \
    -m 0644 \
    "$SCRIPT_DIR/systemd/itm-security-audit.timer" \
    /etc/systemd/system/itm-security-audit.timer

install \
    -o root \
    -g root \
    -m 0644 \
    "$SCRIPT_DIR/systemd/itm-web-scan.service" \
    /etc/systemd/system/itm-web-scan.service

install \
    -o root \
    -g root \
    -m 0644 \
    "$SCRIPT_DIR/systemd/itm-web-scan.timer" \
    /etc/systemd/system/itm-web-scan.timer

install \
    -o root \
    -g root \
    -m 0644 \
    "$SCRIPT_DIR/systemd/itm-web-realtime.service" \
    /etc/systemd/system/itm-web-realtime.service

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

F2B_JAIL="/etc/fail2ban/jail.d/sshd.local"
F2B_GENERATED="$(mktemp)"

cat > "$F2B_GENERATED" <<EOF
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

#
# An existing jail is treated as operator configuration, not as
# something the installer owns. Ban times, ignoreip and maxretry
# get tuned per site, and silently resetting them on every
# upgrade would undo that tuning without anyone noticing.
#
if [[ -f "$F2B_JAIL" ]]; then

    if cmp -s "$F2B_JAIL" "$F2B_GENERATED"; then
        echo "[+] Fail2Ban sshd jail already matches the generated policy."
        rm -f "$F2B_GENERATED"
    else
        install -o root -g root -m 0644 "$F2B_GENERATED" "${F2B_JAIL}.itm-new"
        rm -f "$F2B_GENERATED"
        echo "[!] Existing Fail2Ban sshd jail PRESERVED (it differs from the generated policy)."
        echo "    Proposed version written to: ${F2B_JAIL}.itm-new"
        echo "    Compare with: diff -u ${F2B_JAIL} ${F2B_JAIL}.itm-new"
    fi

else
    install -o root -g root -m 0644 "$F2B_GENERATED" "$F2B_JAIL"
    rm -f "$F2B_GENERATED"
    echo "[+] Fail2Ban sshd jail created."
fi



# ============================================================
# INTEGRITY MANIFEST
#
# Hashes of everything just installed, so "itm-security health"
# can tell an upgrade apart from tampering. Paths are relative
# to / so the manifest verifies with: cd / && sha256sum -c
# ============================================================

ITM_MANIFEST="/var/lib/itm-security/manifest.sha256"

install -o root -g root -m 0700 -d /var/lib/itm-security

{
    cd / || exit 1
    for f in \
        usr/local/sbin/security-notify \
        usr/local/sbin/ssh-login-alert \
        usr/local/sbin/security-file-monitor \
        usr/local/sbin/itm-command-relay \
        usr/local/sbin/itm-security \
        usr/local/sbin/itm-web-realtime \
        etc/profile.d/sysadmin.sh \
        etc/fail2ban/action.d/telegram-security.conf
    do
        [[ -f "$f" ]] && sha256sum "$f"
    done
    find usr/local/lib/itm-security -type f -name '*.sh' -exec sha256sum {} + 2>/dev/null
    find etc/systemd/system -maxdepth 1 -type f \( -name 'itm-*' -o -name 'security-file-monitor.service' \) \
        -exec sha256sum {} + 2>/dev/null
} > "$ITM_MANIFEST" 2>/dev/null

chmod 600 "$ITM_MANIFEST"

echo "[+] Integrity manifest written ($(wc -l < "$ITM_MANIFEST") files)."

# ============================================================
# SYSTEMD
# ============================================================

echo "[+] Reloading systemd..."

systemctl daemon-reload

systemctl enable --now \
    security-file-monitor.service

systemctl enable --now \
    itm-command-monitor.service

# ------------------------------------------------------------
# Nightly audit
#
# The timer runs the audit, not a remediation. Set
# INSTALL_AUDIT_TIMER=0 to install the tooling without the
# scheduled run.
# ------------------------------------------------------------

if [[ "$INSTALL_AUDIT_TIMER" == "1" ]]; then

    systemctl enable --now \
        itm-security-audit.timer

    echo "[+] Nightly audit timer enabled."

else

    echo "[+] Audit timer NOT enabled (INSTALL_AUDIT_TIMER=0)."
    echo "    Run manually: itm-security audit"

fi

# ------------------------------------------------------------
# Web content monitoring
#
# Two layers:
#   itm-web-scan.timer      reconciliation every three hours
#   itm-web-realtime        inotify, catches a file that exists
#                           for only a few minutes
#
# Both are role aware: on a host with no web application
# workload the scan exits after a lightweight classification and
# the realtime watcher exits 0 without watching anything.
# ------------------------------------------------------------

if [[ "$INSTALL_WEB_MONITOR" == "1" ]]; then

    systemctl enable --now itm-web-scan.timer

    if command -v inotifywait >/dev/null 2>&1; then
        systemctl enable --now itm-web-realtime.service
        echo "[+] Web scan timer and realtime monitor enabled."
    else
        echo "[!] inotify-tools missing - realtime web monitor NOT started."
        echo "    Scheduled scanning still runs every three hours."
    fi

else

    echo "[+] Web monitoring NOT enabled (INSTALL_WEB_MONITOR=0)."

fi

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

if [[ -x /usr/local/sbin/itm-security ]]; then
    check_result "Audit CLI:" "OK"
else
    check_result "Audit CLI:" "MISSING"
fi

AUDIT_MODULES_FOUND="$(find "$AUDIT_MODULE_DIR" -maxdepth 1 -name 'audit_*.sh' 2>/dev/null | wc -l)"
check_result "Audit modules:" "$AUDIT_MODULES_FOUND / ${#AUDIT_MODULES[@]}"

if [[ "$INSTALL_AUDIT_TIMER" == "1" ]]; then
    if systemctl is-active --quiet itm-security-audit.timer; then
        check_result "Audit timer:" "ACTIVE"
    else
        check_result "Audit timer:" "FAILED"
    fi
else
    check_result "Audit timer:" "DISABLED BY OPERATOR"
fi

if [[ -f "$AUDIT_CONF" ]]; then
    check_result "Audit config:" "OK"
else
    check_result "Audit config:" "MISSING"
fi

if [[ "$INSTALL_WEB_MONITOR" == "1" ]]; then
    if systemctl is-active --quiet itm-web-scan.timer; then
        check_result "Web scan timer:" "ACTIVE (00,03,06,09,12,15,18,21)"
    else
        check_result "Web scan timer:" "FAILED"
    fi

    if systemctl is-active --quiet itm-web-realtime.service; then
        check_result "Realtime web monitor:" "ACTIVE"
    elif command -v inotifywait >/dev/null 2>&1; then
        check_result "Realtime web monitor:" "NOT APPLICABLE (no web workload)"
    else
        check_result "Realtime web monitor:" "inotify-tools MISSING"
    fi
else
    check_result "Web monitoring:" "DISABLED BY OPERATOR"
fi

IOC_FOUND="$(find "$AUDIT_IOC_DIR" -maxdepth 1 -name '*.conf' 2>/dev/null | wc -l)"
check_result "IOC lists:" "$IOC_FOUND / ${#AUDIT_IOC_FILES[@]}"

HOST_ROLE_LINE="$(/usr/local/sbin/itm-security audit role --dry-run --quiet 2>/dev/null | grep -m1 'host role:' || true)"
check_result "Host role:" "${HOST_ROLE_LINE#*host role: }"

check_result "Host trust status:" \
    "$(grep -E '^HOST_TRUST_STATUS=' "$AUDIT_CONF" 2>/dev/null | cut -d'"' -f2 || echo UNVERIFIED)"

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

echo "Post-compromise audit (read only, never modifies the host):"
echo
echo "  itm-security self-test"
echo "  itm-security audit --dry-run     # writes nothing, sends nothing"
echo "  itm-security audit"
echo "  itm-security audit nginx web     # single modules"
echo "  itm-security audit --json | jq ."
echo
echo "  itm-security remediate            # generate response scripts in /root/forensic"
echo "  itm-security web status"
echo "  itm-security web baseline        # after a verified clean deployment"
echo "  systemctl status itm-web-realtime --no-pager"
echo "  systemctl list-timers itm-web-scan.timer"
echo "  systemctl list-timers itm-security-audit.timer"
echo "  less $AUDIT_LOG_DIR/post-compromise-audit.log"
echo

echo "IMPORTANT - host trust:"
echo
echo "  If this host was ever root compromised, record it in:"
echo "  $AUDIT_CONF"
echo
echo '      HOST_TRUST_STATUS="UNTRUSTED"'
echo '      HOST_TRUST_REASON="<incident reference>"'
echo
echo "  The audit never reports a host as CLEAN. A host that held a"
echo "  root level compromise stays UNTRUSTED until it is rebuilt"
echo "  from trusted media."
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
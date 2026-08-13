#!/usr/bin/env bash
# shellcheck shell=bash

# ============================================================
# ITM Server Security Monitor
# Post-Compromise Audit - Module I: Fail2Ban health
#
# Read only. Fail2Ban is never restarted or reconfigured here:
# a restart drops every active ban.
#
# "fail2ban-client -t" only proves the configuration parses. It
# does NOT prove the jail is running. The failure seen on this
# estate looked exactly like that:
#
#   fail2ban-client -t          -> OK
#   fail2ban-client status sshd -> jail not found
#   journal                     -> Failed to initialize any
#                                  backend for Jail 'sshd'
#
# caused by the systemd backend being selected while the
# python3-systemd binding was missing. This module therefore
# separates four independent states:
#
#   service running / config valid / jail loaded / backend usable
# ============================================================

# Listed in Fail2Ban's own precedence order: later files win.
f2b_jail_configs() {
    local f
    for f in /etc/fail2ban/jail.conf /etc/fail2ban/jail.local; do
        [[ -r "$f" ]] && printf '%s\n' "$f"
    done
    find /etc/fail2ban/jail.d -maxdepth 1 -type f \( -name '*.conf' -o -name '*.local' \) 2>/dev/null | sort
}

f2b_effective_backend() {

    local file backend=""

    while IFS= read -r file; do
        [[ -r "$file" ]] || continue
        local v
        v="$(grep -E '^[[:space:]]*backend[[:space:]]*=' "$file" 2>/dev/null | tail -1 | cut -d= -f2- | xargs 2>/dev/null)"
        [[ -n "$v" ]] && backend="$v"
    done < <(f2b_jail_configs)

    printf '%s' "${backend:-auto}"
}

sshd_effective_ports() {

    local ports=""

    if have_cmd sshd; then
        ports="$(run_timeout 10 sshd -T 2>/dev/null | awk '/^port /{print $2}' | tr '\n' ' ')"
    fi

    if [[ -z "$ports" && -r /etc/ssh/sshd_config ]]; then
        ports="$(grep -hiE '^[[:space:]]*Port[[:space:]]+[0-9]+' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null \
            | awk '{print $2}' | sort -u | tr '\n' ' ')"
    fi

    printf '%s' "${ports:-22}"
}

# ------------------------------------------------------------
# Service and configuration state
# ------------------------------------------------------------

check_f2b_service() {

    if ! have_cmd fail2ban-client; then
        add_finding HIGH \
            "Fail2Ban is not installed" \
            id="f2b-missing" \
            evidence="fail2ban-client not found in PATH. SSH brute force attempts on this host are neither rate limited nor alerted." \
            action="Install fail2ban and run the ITM installer again so the SSH jail and the Telegram action are restored."
        return 1
    fi

    if have_cmd systemctl; then
        if run_timeout 10 systemctl is-active --quiet fail2ban 2>/dev/null; then
            add_pass "fail2ban service is running ($(run_timeout 10 systemctl is-enabled fail2ban 2>/dev/null || echo unknown))"
        else
            add_finding HIGH \
                "Fail2Ban service is not running" \
                id="f2b-inactive" \
                process="fail2ban.service state=$(run_timeout 10 systemctl is-active fail2ban 2>/dev/null || echo unknown)" \
                evidence="$(truncate_text "$(run_timeout 10 systemctl status fail2ban --no-pager 2>&1 | head -12)" 600)" \
                action="Start it and read the journal for the reason: systemctl start fail2ban ; journalctl -u fail2ban -n 50 --no-pager"
        fi
    fi

    if run_timeout "$CMD_TIMEOUT" fail2ban-client -t >/dev/null 2>&1; then
        add_pass "fail2ban configuration parses (fail2ban-client -t)"
    else
        add_finding HIGH \
            "Fail2Ban configuration fails validation" \
            id="f2b-config-invalid" \
            evidence="$(truncate_text "$(run_timeout "$CMD_TIMEOUT" fail2ban-client -t 2>&1 | tail -12)" 600)" \
            action="Fix the reported jail file. Until it parses, Fail2Ban runs with whatever it loaded last, or not at all."
    fi

    return 0
}

# ------------------------------------------------------------
# Jails that are actually loaded
# ------------------------------------------------------------

check_f2b_jails() {

    local status jails jail_count sshd_status

    status="$(run_timeout "$CMD_TIMEOUT" fail2ban-client status 2>&1)"

    if ! printf '%s' "$status" | grep -q 'Jail list'; then
        add_finding HIGH \
            "Fail2Ban server is not answering status queries" \
            id="f2b-no-status" \
            evidence="$(truncate_text "$status" 400)" \
            action="The configuration may parse while the server is down. Check: systemctl status fail2ban ; journalctl -u fail2ban -n 50 --no-pager"
        return 0
    fi

    jails="$(printf '%s' "$status" | sed -nE 's/.*Jail list:[[:space:]]*(.*)/\1/p' | tr -d ' ')"
    jail_count="$(printf '%s' "$jails" | tr ',' '\n' | grep -c . || true)"

    if [[ -z "$jails" ]]; then
        add_finding HIGH \
            "Fail2Ban is running with no jail loaded" \
            id="f2b-no-jails" \
            evidence="Jail list is empty. The service is up but enforces nothing." \
            action="Check the jail files in /etc/fail2ban/jail.d and read the journal for backend initialisation errors."
        return 0
    fi

    add_pass "fail2ban jails loaded ($jail_count): $jails"

    # ---- the sshd jail specifically ----------------------------
    if ! printf '%s' "$jails" | tr ',' '\n' | grep -qx 'sshd'; then
        add_finding HIGH \
            "The sshd jail is configured but not loaded" \
            id="f2b-sshd-not-loaded" \
            path="/etc/fail2ban/jail.d/sshd.local" \
            evidence="Loaded jails: $jails
A configuration that passes 'fail2ban-client -t' can still fail to start a jail, most often because the log backend could not be initialised." \
            action="Read the reason: journalctl -u fail2ban -n 100 --no-pager | grep -i jail"
        return 0
    fi

    sshd_status="$(run_timeout "$CMD_TIMEOUT" fail2ban-client status sshd 2>&1)"

    if printf '%s' "$sshd_status" | grep -qi 'currently banned\|Total banned'; then
        add_pass "sshd jail active - $(printf '%s' "$sshd_status" | grep -iE 'currently failed|currently banned|total banned' | tr '\n' ' ' | tr -s ' ')"
    else
        add_finding HIGH \
            "The sshd jail does not report a working status" \
            id="f2b-sshd-status" \
            evidence="$(truncate_text "$sshd_status" 400)" \
            action="Investigate with: journalctl -u fail2ban -n 100 --no-pager"
    fi
}

# ------------------------------------------------------------
# Backend initialisation
# ------------------------------------------------------------

check_f2b_backend() {

    local backend journal py_ok=0

    backend="$(f2b_effective_backend)"
    add_pass "fail2ban backend configured: $backend"

    # The exact failure previously seen on this estate.
    if have_cmd journalctl; then
        journal="$(run_timeout "$CMD_TIMEOUT" journalctl -u fail2ban -n 300 --no-pager 2>/dev/null \
            | grep -iE 'Failed to initialize any backend|Failed during configure|ERROR.*Jail' | tail -5)"

        if [[ -n "$journal" ]]; then
            add_finding HIGH \
                "Fail2Ban reported a backend initialisation failure" \
                id="f2b-backend-failure" \
                evidence="$(truncate_text "$journal" 500)" \
                action="With backend=systemd install the Python binding (Debian/Ubuntu: python3-systemd, RHEL family: python3-systemd) and restart fail2ban. With backend=auto point logpath at the file that actually exists on this distribution (/var/log/auth.log or /var/log/secure)."
        else
            add_pass "no backend initialisation error in the recent fail2ban journal"
        fi
    else
        add_skip "journalctl not available - fail2ban journal not inspected"
    fi

    # The systemd backend needs the python3-systemd binding.
    if [[ "$backend" == "systemd" ]]; then

        if have_cmd python3 && run_timeout 10 python3 -c "import systemd.journal" >/dev/null 2>&1; then
            py_ok=1
        fi

        if (( py_ok )); then
            add_pass "python3 systemd binding available (backend=systemd usable)"
        else
            add_finding HIGH \
                "Fail2Ban uses the systemd backend but the python3 systemd binding is missing" \
                id="f2b-missing-python-systemd" \
                evidence="python3 -c 'import systemd.journal' failed. This is the direct cause of \"Failed to initialize any backend for Jail 'sshd'\"." \
                action="Install the binding: apt-get install python3-systemd (Debian/Ubuntu) or dnf install python3-systemd (AlmaLinux/Rocky), then: systemctl restart fail2ban ; fail2ban-client status sshd"
        fi
    fi
}

# ------------------------------------------------------------
# Does the ban action cover the real SSH port?
# ------------------------------------------------------------

check_f2b_ssh_port() {

    local ssh_ports jail_text port covered=1

    ssh_ports="$(sshd_effective_ports)"
    [[ -n "$ssh_ports" ]] || return 0

    jail_text="$(cat /etc/fail2ban/jail.d/*.local /etc/fail2ban/jail.local 2>/dev/null || true)"
    [[ -n "$jail_text" ]] || return 0

    for port in $ssh_ports; do

        [[ "$port" == "22" ]] && continue

        # "port = ssh" resolves to 22 through /etc/services, so a
        # custom SSH port needs to be named explicitly.
        if ! printf '%s' "$jail_text" | grep -q "$port"; then
            covered=0
            add_finding MEDIUM \
                "Fail2Ban ban action may not cover the SSH port in use" \
                id="f2b-port-mismatch:$port" \
                path="/etc/fail2ban/jail.d/sshd.local" \
                network="sshd listening on port(s): $ssh_ports" \
                evidence="Port $port does not appear anywhere in the jail configuration. With 'port = ssh' the firewall rule is written for port 22 only, so attempts against $port are detected but never blocked." \
                action="Set port = $port in /etc/fail2ban/jail.d/sshd.local and in the action, then: fail2ban-client -t && systemctl restart fail2ban"
        fi
    done

    (( covered )) && add_pass "fail2ban jail references the SSH port(s) in use: $ssh_ports"
}

# ------------------------------------------------------------
# The ITM Telegram action
# ------------------------------------------------------------

check_f2b_telegram_action() {

    local action="/etc/fail2ban/action.d/telegram-security.conf"

    if [[ -r "$action" ]]; then
        if grep -q "$ITM_NOTIFY_BIN" "$action" 2>/dev/null; then
            add_pass "ITM Telegram ban action installed and pointing at $ITM_NOTIFY_BIN"
        else
            add_finding LOW \
                "ITM Telegram ban action exists but does not reference the notifier" \
                id="f2b-telegram-action-modified" \
                path="$action" \
                evidence="$(truncate_text "$(head -8 "$action")" 300)" \
                action="Reinstall it from the repository: install -m 0644 fail2ban/action.d/telegram-security.conf /etc/fail2ban/action.d/"
        fi
    else
        add_finding LOW \
            "ITM Telegram ban action is not installed" \
            id="f2b-telegram-action-missing" \
            path="$action" \
            evidence="Bans will still happen but no Telegram alert will be sent for them." \
            action="Run the ITM installer again to restore the action file."
    fi
}

# ============================================================
# ENTRY POINT
# ============================================================

run_audit_fail2ban() {

    module_begin "fail2ban" "Fail2Ban Health"

    if check_f2b_service; then
        check_f2b_jails
        check_f2b_backend
        check_f2b_ssh_port
        check_f2b_telegram_action
    fi

    module_end
}

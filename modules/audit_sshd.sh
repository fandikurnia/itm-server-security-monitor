#!/usr/bin/env bash
# shellcheck shell=bash

# ============================================================
# ITM Server Security Monitor
# Module S2: SSH server configuration
#
# Read only, and deliberately separate from the session module.
#
# Session enforcement is an operational control that can act on
# a running system. Changing sshd_config is not: a wrong edit
# there locks every administrator out of the host, including
# the person running this tool. This module therefore only ever
# reports and recommends - it never writes sshd_config and
# never reloads sshd.
#
# The effective configuration comes from "sshd -T", which
# resolves Include directives, Match blocks and defaults the
# way sshd actually sees them. Reading sshd_config by hand
# misses all three.
# ============================================================

SSHD_MAX_AUTH_TRIES_LIMIT="${SSHD_MAX_AUTH_TRIES_LIMIT:-3}"

# Test seam.
SSHD_CONFIG_FIXTURE="${SSHD_CONFIG_FIXTURE:-}"

sshd_effective_config() {

    if [[ -n "$SSHD_CONFIG_FIXTURE" && -r "$SSHD_CONFIG_FIXTURE" ]]; then
        cat "$SSHD_CONFIG_FIXTURE"
        return 0
    fi

    have_cmd sshd || return 1
    run_timeout "$CMD_TIMEOUT" sshd -T 2>/dev/null
}

sshd_value() {
    local key="$1"
    awk -v k="${key,,}" 'tolower($1) == k { $1=""; sub(/^ /, ""); print; exit }' \
        "$ITM_RUN_TMP/sshd-effective.txt" 2>/dev/null
}

# ============================================================

check_sshd_config() {

    if ! sshd_effective_config > "$ITM_RUN_TMP/sshd-effective.txt" 2>/dev/null \
        || [[ ! -s "$ITM_RUN_TMP/sshd-effective.txt" ]]; then
        add_skip "could not read the effective SSH configuration (sshd -T)"
        return 0
    fi

    local permit_root password_auth pubkey_auth max_auth alive_interval alive_count ports

    permit_root="$(sshd_value permitrootlogin)"
    password_auth="$(sshd_value passwordauthentication)"
    pubkey_auth="$(sshd_value pubkeyauthentication)"
    max_auth="$(sshd_value maxauthtries)"
    alive_interval="$(sshd_value clientaliveinterval)"
    alive_count="$(sshd_value clientalivecountmax)"
    ports="$(awk 'tolower($1)=="port" {print $2}' "$ITM_RUN_TMP/sshd-effective.txt" 2>/dev/null | tr '\n' ' ')"

    add_pass "sshd effective config: port(s)=${ports:-22} PermitRootLogin=${permit_root:-?} PasswordAuthentication=${password_auth:-?} PubkeyAuthentication=${pubkey_auth:-?} MaxAuthTries=${max_auth:-?} ClientAliveInterval=${alive_interval:-?} ClientAliveCountMax=${alive_count:-?}"

    # ---- root login -----------------------------------------
    case "$permit_root" in
        yes)
            add_finding HIGH \
                "SSH permits direct root login" \
                id="sshd-permitrootlogin" \
                event=SSH_ROOT_LOGIN_ENABLED \
                path="/etc/ssh/sshd_config" \
                confidence=99 \
                reasons="PermitRootLogin=yes in the effective configuration
A root login is attributable to nobody: the audit trail stops at 'root'
Brute force against root needs no username discovery" \
                evidence="PermitRootLogin ${permit_root}" \
                action="RECOMMENDATION ONLY - this module changes nothing. Move to 'prohibit-password' (keys only) or 'no', after confirming an unprivileged account with sudo can log in. Edit /etc/ssh/sshd_config, then: sshd -t && systemctl reload sshd. Keep a second session open while you do it." ;;
        prohibit-password|without-password)
            add_pass "PermitRootLogin=${permit_root} (key-based root login only)" ;;
        no)
            add_pass "PermitRootLogin=no" ;;
        *)
            [[ -n "$permit_root" ]] && add_pass "PermitRootLogin=${permit_root}" ;;
    esac

    # ---- password authentication ----------------------------
    if [[ "$password_auth" == "yes" ]]; then
        local sev=MEDIUM
        local extra="Fail2Ban is present, which limits but does not remove brute force exposure."
        if ! have_cmd fail2ban-client; then
            sev=HIGH
            extra="Fail2Ban is NOT installed on this host, so there is no rate limiting on password attempts."
        fi
        add_finding "$sev" \
            "SSH accepts password authentication" \
            id="sshd-passwordauth" \
            event=SSH_PASSWORD_AUTH_ENABLED \
            path="/etc/ssh/sshd_config" \
            confidence=95 \
            reasons="PasswordAuthentication=yes in the effective configuration
Passwords are guessable, reusable and phishable; keys are not
$extra" \
            evidence="PasswordAuthentication ${password_auth} PubkeyAuthentication ${pubkey_auth:-?}" \
            action="RECOMMENDATION ONLY. Confirm every account that needs access has a working key first, then set PasswordAuthentication no and reload sshd. Verify with a second session before closing the current one."
    else
        add_pass "PasswordAuthentication=${password_auth:-no}"
    fi

    # ---- public key authentication --------------------------
    if [[ "$pubkey_auth" == "no" ]]; then
        add_finding MEDIUM \
            "SSH public key authentication is disabled" \
            id="sshd-pubkeyauth-off" \
            path="/etc/ssh/sshd_config" \
            confidence=90 \
            reasons="PubkeyAuthentication=no leaves passwords as the only way in
Disabling passwords later becomes impossible without re-enabling this first" \
            evidence="PubkeyAuthentication ${pubkey_auth}" \
            action="RECOMMENDATION ONLY. Set PubkeyAuthentication yes and deploy keys before restricting password authentication."
    fi

    # ---- brute force surface --------------------------------
    if [[ "$max_auth" =~ ^[0-9]+$ ]] && (( max_auth > SSHD_MAX_AUTH_TRIES_LIMIT )); then
        add_finding MEDIUM \
            "SSH MaxAuthTries is above the recommended limit" \
            id="sshd-maxauthtries" \
            path="/etc/ssh/sshd_config" \
            confidence=85 \
            reasons="MaxAuthTries=${max_auth}, recommended maximum is ${SSHD_MAX_AUTH_TRIES_LIMIT}
Each connection may attempt ${max_auth} credentials before it is closed
This multiplies what an attacker gets per connection, and per Fail2Ban window" \
            evidence="MaxAuthTries ${max_auth}" \
            action="RECOMMENDATION ONLY. Set MaxAuthTries ${SSHD_MAX_AUTH_TRIES_LIMIT} and reload sshd."
    else
        add_pass "MaxAuthTries=${max_auth:-default} within policy"
    fi

    # ---- idle session handling ------------------------------
    #
    # Relevant to this project specifically: ClientAliveInterval
    # is how sshd closes dead connections. It is NOT a maximum
    # session duration - a user typing every few minutes keeps a
    # session alive forever. That is what the session module is
    # for, and saying so prevents a false sense of coverage.
    if [[ "$alive_interval" == "0" || -z "$alive_interval" ]]; then
        add_finding LOW \
            "SSH has no client alive interval configured" \
            id="sshd-clientalive" \
            path="/etc/ssh/sshd_config" \
            confidence=70 \
            reasons="ClientAliveInterval=${alive_interval:-0} means broken connections are never detected
Half-open sessions accumulate and keep credentials and forwarded agents alive" \
            evidence="ClientAliveInterval=${alive_interval:-0} ClientAliveCountMax=${alive_count:-?}" \
            action="RECOMMENDATION ONLY. ClientAliveInterval 300 with ClientAliveCountMax 2 closes dead connections after ~10 minutes. Note this detects DEAD connections only - it does not cap the duration of an active session. Maximum session duration is enforced by the ssh_session module."
    else
        local total_idle=$(( alive_interval * ${alive_count:-3} ))
        add_pass "ClientAliveInterval=${alive_interval} x ClientAliveCountMax=${alive_count:-3} (dead connection closed after ~${total_idle}s)"
    fi
}

# ============================================================
# ENTRY POINT
# ============================================================

run_audit_sshd() {

    module_begin "sshd" "SSH Server Configuration"
    check_sshd_config
    module_end
}

#!/usr/bin/env bash
# shellcheck shell=bash

# ============================================================
# ITM Server Security Monitor
# Module H: monitor health
#
# A monitoring system that stops silently is worse than no
# monitoring system, because it also produces confidence.
#
# This module answers one question: is the monitor itself
# actually working right now? It is the only module whose
# findings are about the tool rather than the host, and the
# only one that should still alert when everything else is
# quiet.
#
# Three states, and the middle one matters most:
#
#   HEALTHY   every component running, every scheduled run
#             completed within its window
#   DEGRADED  the monitor runs but part of it is blind or late
#   BROKEN    a required component is dead - nothing is being
#             watched, whatever the last report said
#
# The word CLEAN is never used about the host here, and
# HEALTHY is never a statement about the host either: it means
# the instrumentation works.
#
# Limitation, stated plainly and repeated in the report: an
# attacker with root can stop these services and delete this
# module. Local self-monitoring raises the effort required; it
# does not survive a determined root attacker. Ship the JSON to
# a remote collector (Wazuh, a syslog server, a Zabbix
# heartbeat) if the host matters.
# ============================================================

HEALTH_TIMER_GRACE_HOURS="${HEALTH_TIMER_GRACE_HOURS:-2}"
HEALTH_AUDIT_INTERVAL_HOURS="${HEALTH_AUDIT_INTERVAL_HOURS:-24}"
HEALTH_WEB_INTERVAL_HOURS="${HEALTH_WEB_INTERVAL_HOURS:-3}"
HEALTH_MIN_DISK_MB="${HEALTH_MIN_DISK_MB:-500}"
HEALTH_BASELINE_MAX_DAYS="${HEALTH_BASELINE_MAX_DAYS:-90}"

ITM_MANIFEST="${ITM_MANIFEST:-/var/lib/itm-security/manifest.sha256}"

# Components that must be present for the monitor to mean
# anything. Split by consequence, because a dead realtime
# watcher and a missing optional timer are not the same event.
HEALTH_REQUIRED_BINARIES="${HEALTH_REQUIRED_BINARIES:-/usr/local/sbin/security-notify /usr/local/sbin/itm-security}"
HEALTH_REQUIRED_SERVICES="${HEALTH_REQUIRED_SERVICES:-security-file-monitor.service}"
HEALTH_OPTIONAL_SERVICES="${HEALTH_OPTIONAL_SERVICES:-itm-command-monitor.service itm-web-realtime.service}"
HEALTH_TIMERS="${HEALTH_TIMERS:-itm-security-audit.timer itm-web-scan.timer}"

HEALTH_STATE="HEALTHY"
HEALTH_BROKEN=0
HEALTH_DEGRADED=0

health_mark_broken()   { HEALTH_BROKEN=$(( HEALTH_BROKEN + 1 ));   HEALTH_STATE="BROKEN"; }
health_mark_degraded() {
    HEALTH_DEGRADED=$(( HEALTH_DEGRADED + 1 ))
    [[ "$HEALTH_STATE" == "BROKEN" ]] || HEALTH_STATE="DEGRADED"
}

health_row() {
    (( ITM_QUIET )) && return 0
    local label="$1" state="$2" detail="${3:-}"
    local color="$C_INFO"
    case "$state" in
        OK)       color="$C_INFO" ;;
        WARN)     color="$C_MED" ;;
        FAIL)     color="$C_HIGH" ;;
        NA)       color="$C_DIM" ;;
    esac
    printf '  %-28s %s%-6s%s %s\n' "$label" "$color" "$state" "$C_RESET" "$detail"
}

# ------------------------------------------------------------
# Binaries and configuration
# ------------------------------------------------------------

health_check_install() {

    local bin missing=""

    for bin in $HEALTH_REQUIRED_BINARIES; do
        if [[ -x "$bin" ]]; then
            health_row "$(basename "$bin")" OK "installed"
        else
            missing+="$bin "
            health_row "$(basename "$bin")" FAIL "missing or not executable"
        fi
    done

    if [[ -n "$missing" ]]; then
        health_mark_broken
        add_finding CRITICAL \
            "MONITOR BROKEN: required component missing" \
            id="health-missing-binary" \
            confidence=99 \
            reasons="A binary the monitor depends on is absent or not executable
Nothing is being monitored by that component
This is a failure of the monitoring system, not a finding about the host" \
            evidence="Missing: $missing" \
            action="Reinstall: cd /path/to/itm-server-security-monitor && sudo bash install.sh"
    fi

    if [[ -r "$ITM_AUDIT_CONF" ]]; then
        health_row "audit.conf" OK "$ITM_AUDIT_CONF"
    else
        health_row "audit.conf" WARN "not readable - built-in defaults in use"
        health_mark_degraded
    fi

    # Presence only. The credentials are never read here.
    if [[ -r "$ITM_CONF_DIR/telegram.conf" ]]; then
        health_row "telegram.conf" OK "present (not read)"
    else
        health_row "telegram.conf" FAIL "missing - no alert can be delivered"
        health_mark_broken
        add_finding CRITICAL \
            "MONITOR BROKEN: Telegram configuration missing" \
            id="health-no-telegram-conf" \
            confidence=99 \
            reasons="No telegram.conf, so security-notify cannot deliver anything
Every alert this tool produces is being written to disk and nowhere else" \
            evidence="Expected: $ITM_CONF_DIR/telegram.conf" \
            action="Restore the file with mode 0600, or re-run the installer with BOT_TOKEN and CHAT_ID."
    fi
}

# ------------------------------------------------------------
# Services
# ------------------------------------------------------------

health_check_services() {

    have_cmd systemctl || { health_row "systemd" NA "not available"; return 0; }

    local svc state failed="" failed_names=""

    for svc in $HEALTH_REQUIRED_SERVICES; do
        if run_timeout 10 systemctl is-active --quiet "$svc" 2>/dev/null; then
            health_row "$svc" OK "active"
        else
            # is-active prints a state AND exits non-zero, so the
            # fallback must not be appended to its output.
            state="$(run_timeout 10 systemctl is-active "$svc" 2>/dev/null | head -1)"
            [[ -n "$state" ]] || state="unknown"
            health_row "$svc" FAIL "$state"
            failed+="$svc($state) "
            failed_names+="$svc "
        fi
    done

    if [[ -n "$failed" ]]; then
        local first_failed="${failed_names%% *}"
        health_mark_broken
        add_finding CRITICAL \
            "MONITOR BROKEN: required monitoring service is not running" \
            id="health-service-down" \
            confidence=99 \
            reasons="A service that watches this host in real time is not active
File changes it would have reported are not being seen
The absence of alerts from this host does not mean the host is quiet" \
            evidence="$failed
$(run_timeout 10 systemctl status "$first_failed" --no-pager 2>&1 | head -12)" \
            action="systemctl status $first_failed --no-pager ; journalctl -u $first_failed -n 50 --no-pager. Restart with: systemctl restart $first_failed"
    fi

    # Optional services: only meaningful where they apply.
    for svc in $HEALTH_OPTIONAL_SERVICES; do

        if ! run_timeout 10 systemctl list-unit-files "$svc" --no-legend 2>/dev/null | grep -q .; then
            health_row "$svc" NA "not installed"
            continue
        fi

        if run_timeout 10 systemctl is-active --quiet "$svc" 2>/dev/null; then
            health_row "$svc" OK "active"
            continue
        fi

        # itm-web-realtime exits 0 on hosts with no web workload:
        # that is correct behaviour, not a fault.
        if [[ "$svc" == "itm-web-realtime.service" ]] && ! role_is web_application 2>/dev/null; then
            health_row "$svc" NA "no web workload on this host"
            continue
        fi

        health_row "$svc" WARN "inactive"
        health_mark_degraded
        add_finding HIGH \
            "MONITORING DEGRADED: $svc is not running" \
            id="health-optional-service:$svc" \
            confidence=90 \
            reasons="This component is installed but not active
The detection it provides is currently absent" \
            evidence="$(run_timeout 10 systemctl status "$svc" --no-pager 2>&1 | head -10)" \
            action="journalctl -u $svc -n 50 --no-pager, then systemctl restart $svc"
    done

    # Repeated crashes: a service that restarts forever looks
    # active in a snapshot and is useless in practice.
    local restarts
    for svc in $HEALTH_REQUIRED_SERVICES $HEALTH_OPTIONAL_SERVICES; do
        restarts="$(run_timeout 10 systemctl show "$svc" -p NRestarts --value 2>/dev/null)"
        [[ "$restarts" =~ ^[0-9]+$ ]] || continue
        (( restarts >= 5 )) || continue
        health_row "$svc restarts" WARN "$restarts"
        health_mark_degraded
        add_finding HIGH \
            "MONITORING DEGRADED: $svc is restarting repeatedly" \
            id="health-crashloop:$svc" \
            confidence=85 \
            reasons="systemd has restarted this unit ${restarts} times
A crash looping monitor produces gaps that no report will show" \
            evidence="NRestarts=$restarts" \
            action="journalctl -u $svc -n 100 --no-pager to find the cause."
    done
}

# ------------------------------------------------------------
# Timers and missed runs
#
# The check the whole module exists for: a timer that stopped
# firing is invisible unless something looks for it.
# ------------------------------------------------------------

health_check_timers() {

    have_cmd systemctl || return 0

    local timer next

    for timer in $HEALTH_TIMERS; do

        if ! run_timeout 10 systemctl list-unit-files "$timer" --no-legend 2>/dev/null | grep -q .; then
            health_row "$timer" NA "not installed"
            continue
        fi

        if run_timeout 10 systemctl is-active --quiet "$timer" 2>/dev/null; then
            next="$(run_timeout 10 systemctl show "$timer" -p NextElapseUSecRealtime --value 2>/dev/null)"
            health_row "$timer" OK "next: ${next:-unknown}"
        else
            health_row "$timer" FAIL "inactive"
            health_mark_broken
            add_finding CRITICAL \
                "MONITOR BROKEN: scheduled scan timer is not active" \
                id="health-timer-inactive:$timer" \
                confidence=99 \
                reasons="$timer is installed but not active
No scheduled scan will run on this host until it is enabled" \
                evidence="$(run_timeout 10 systemctl status "$timer" --no-pager 2>&1 | head -8)" \
                action="systemctl enable --now $timer"
        fi
    done
}

health_check_last_runs() {

    local now last age_h label key interval

    now="$(date +%s)"

    for entry in "audit:${HEALTH_AUDIT_INTERVAL_HOURS}:full system audit" \
                 "web:${HEALTH_WEB_INTERVAL_HOURS}:web content scan"; do

        key="last-run:${entry%%:*}"
        interval="$(printf '%s' "$entry" | cut -d: -f2)"
        label="$(printf '%s' "$entry" | cut -d: -f3-)"

        last="$(scan_state_get "$key")"

        if [[ "$last" == "0" || -z "$last" ]]; then
            health_row "last $label" WARN "never recorded"
            health_mark_degraded
            add_finding MEDIUM \
                "No completed ${label} has been recorded" \
                id="health-never-ran:${entry%%:*}" \
                confidence=80 \
                reasons="The monitor has no record of a ${label} finishing on this host
Either it has never run, or it has never finished" \
                evidence="state key: $key" \
                action="Run it once by hand: itm-security audit"
            continue
        fi

        age_h=$(( ( now - last ) / 3600 ))

        if (( age_h > interval + HEALTH_TIMER_GRACE_HOURS )); then
            health_row "last $label" FAIL "${age_h}h ago (expected every ${interval}h)"
            health_mark_degraded
            add_finding HIGH \
                "MONITORING GAP: ${label} has not completed for ${age_h} hours" \
                id="health-gap:${entry%%:*}" \
                confidence=95 \
                reasons="Expected interval is ${interval}h, last completion was ${age_h}h ago
Anything that happened in that window was not examined
A quiet alert channel during a gap means nothing" \
                evidence="last completion: $(date -d "@$last" '+%Y-%m-%d %H:%M:%S' 2>/dev/null)" \
                action="Check the timer and the service: systemctl list-timers itm-*.timer ; journalctl -u itm-security-audit.service -n 50 --no-pager"
        else
            health_row "last $label" OK "${age_h}h ago"
        fi
    done
}

# ------------------------------------------------------------
# Realtime watcher capacity
#
# inotify limits are per user and silently truncate the watch
# list when exhausted: the watcher stays "active" while seeing
# nothing.
# ------------------------------------------------------------

health_check_inotify() {

    local max_watches used pct

    [[ -r /proc/sys/fs/inotify/max_user_watches ]] || { health_row "inotify" NA "not readable"; return 0; }

    read -r max_watches < /proc/sys/fs/inotify/max_user_watches

    used="$(find /proc/[0-9]*/fdinfo -type f 2>/dev/null \
            | xargs grep -l '^inotify' 2>/dev/null \
            | xargs grep -h '^inotify' 2>/dev/null | wc -l)"

    [[ "$used" =~ ^[0-9]+$ ]] || used=0
    [[ "$max_watches" =~ ^[0-9]+$ ]] || { health_row "inotify" NA "unknown limit"; return 0; }

    pct=$(( max_watches > 0 ? used * 100 / max_watches : 0 ))

    if (( pct >= 90 )); then
        health_row "inotify watches" FAIL "${used}/${max_watches} (${pct}%)"
        health_mark_degraded
        add_finding HIGH \
            "MONITORING DEGRADED: inotify watch limit nearly exhausted" \
            id="health-inotify-exhausted" \
            confidence=85 \
            reasons="${used} of ${max_watches} watches are in use (${pct}%)
When the limit is reached the watcher silently stops receiving events for new directories
The service keeps reporting as active while it is partially blind" \
            evidence="fs.inotify.max_user_watches=${max_watches} in use=${used}" \
            action="Raise the limit: sysctl -w fs.inotify.max_user_watches=524288 and persist it in /etc/sysctl.d/. Also confirm the realtime watcher is not recursing into cache or session directories."
    else
        health_row "inotify watches" OK "${used}/${max_watches} (${pct}%)"
    fi
}

# ------------------------------------------------------------
# Output paths and capacity
# ------------------------------------------------------------

health_check_storage() {

    local dir avail

    for dir in "$ITM_LOG_DIR" "$ITM_STATE_DIR" "$ITM_EVIDENCE_DIR"; do
        if [[ -d "$dir" && -w "$dir" ]]; then
            health_row "$(basename "$dir") writable" OK "$dir"
        elif [[ ! -d "$dir" ]]; then
            health_row "$(basename "$dir")" WARN "missing: $dir"
            health_mark_degraded
        else
            health_row "$(basename "$dir")" FAIL "not writable: $dir"
            health_mark_degraded
            add_finding HIGH \
                "MONITORING DEGRADED: $dir is not writable" \
                id="health-unwritable:$dir" \
                confidence=90 \
                reasons="Findings and evidence cannot be written to $dir
Evidence that cannot be stored is evidence that will not exist after the attacker cleans up" \
                evidence="$(ls -ld "$dir" 2>/dev/null)" \
                action="Restore ownership and permissions: chown root:root $dir && chmod 700 $dir"
        fi
    done

    avail="$(df -Pm "$ITM_LOG_DIR" 2>/dev/null | awk 'NR==2 {print $4}')"
    if [[ "$avail" =~ ^[0-9]+$ ]]; then
        if (( avail < HEALTH_MIN_DISK_MB )); then
            health_row "disk space" FAIL "${avail}MB free"
            health_mark_degraded
            add_finding HIGH \
                "MONITORING DEGRADED: low disk space for logs and evidence" \
                id="health-disk-low" \
                confidence=90 \
                reasons="${avail}MB free where the audit log, JSON output and evidence copies are written
Evidence preservation fails silently when the filesystem is full" \
                evidence="$(df -Ph "$ITM_LOG_DIR" 2>/dev/null | tail -1)" \
                action="Free space or extend the filesystem. Log rotation is configured in /etc/logrotate.d/itm-security."
        else
            health_row "disk space" OK "${avail}MB free"
        fi
    fi
}

# ------------------------------------------------------------
# Self protection: has the monitor itself been modified?
# ------------------------------------------------------------

health_check_manifest() {

    if [[ ! -r "$ITM_MANIFEST" ]]; then
        health_row "integrity manifest" WARN "not present"
        return 0
    fi

    local changed
    changed="$(cd / && sha256sum -c "$ITM_MANIFEST" 2>/dev/null | grep -v ': OK$' | head -10)"

    if [[ -z "$changed" ]]; then
        health_row "monitor integrity" OK "matches install manifest"
        return 0
    fi

    health_row "monitor integrity" FAIL "$(printf '%s' "$changed" | wc -l) file(s) changed"
    health_mark_degraded

    add_finding HIGH \
        "The security monitor's own files differ from the installed manifest" \
        id="health-self-modified" \
        confidence=80 \
        reasons="One or more monitor files no longer match the hashes recorded at install time
This is expected immediately after an upgrade, and is exactly what tampering looks like otherwise" \
        evidence="$(truncate_text "$changed" 500)" \
        action="If you have just upgraded, refresh the manifest by re-running install.sh. If you have not, treat the monitor as untrusted: compare against the repository and reinstall from a known good source."
}

# ------------------------------------------------------------
# Coverage: is the monitor looking at the right things?
# ------------------------------------------------------------

health_check_coverage() {

    role_classify 2>/dev/null || true

    health_row "host role" OK "$(role_summary_line 2>/dev/null || echo unknown)"

    if role_is web_application 2>/dev/null; then

        if declare -F web_discover_roots >/dev/null && web_discover_roots 2>/dev/null; then
            health_row "web roots" OK "${#WEB_SCAN_ROOTS[@]} discovered"
        else
            health_row "web roots" FAIL "none discovered"
            health_mark_degraded
            add_finding HIGH \
                "MONITORING DEGRADED: web workload detected but no document root found" \
                id="health-no-web-roots" \
                confidence=95 \
                reasons="This host serves web content but the monitor cannot find what to scan
Every web content module is therefore inspecting nothing" \
                evidence="web server: ${ROLE_WEB_SERVER:-unknown}" \
                action="Set WEB_ROOTS in $ITM_AUDIT_CONF"
        fi

        # Baseline age: an ancient baseline compares today's
        # files against a year-old idea of the application.
        local newest age_d
        if [[ -d "$WEB_BASELINE_DIR" ]]; then
            newest="$(find "$WEB_BASELINE_DIR" -name '*.db' -printf '%T@\n' 2>/dev/null | sort -rn | head -1 | cut -d. -f1)"
            if [[ "$newest" =~ ^[0-9]+$ ]]; then
                age_d=$(( ( $(date +%s) - newest ) / 86400 ))
                if (( age_d > HEALTH_BASELINE_MAX_DAYS )); then
                    health_row "integrity baseline" WARN "${age_d} days old"
                    health_mark_degraded
                else
                    health_row "integrity baseline" OK "${age_d} days old"
                fi
            fi
        else
            health_row "integrity baseline" WARN "not created"
            health_mark_degraded
        fi
    else
        health_row "web coverage" NA "no web workload"
    fi

    # Command monitor: installed is not the same as loaded.
    if [[ -r /etc/profile.d/sysadmin.sh ]]; then
        health_row "command monitor" OK "profile installed"
    else
        health_row "command monitor" WARN "profile missing"
        health_mark_degraded
    fi

    if have_cmd fail2ban-client; then
        if run_timeout 10 systemctl is-active --quiet fail2ban 2>/dev/null; then
            health_row "fail2ban" OK "active"
        else
            health_row "fail2ban" WARN "inactive"
            health_mark_degraded
        fi
    else
        health_row "fail2ban" NA "not installed"
    fi
}

# ------------------------------------------------------------
# Board
# ------------------------------------------------------------

health_board() {

    (( ITM_QUIET )) && return 0

    local color="$C_INFO"
    case "$HEALTH_STATE" in
        DEGRADED) color="$C_MED" ;;
        BROKEN)   color="$C_CRIT" ;;
    esac

    say ""
    say "${C_BOLD}============================================================${C_RESET}"
    printf ' MONITOR HEALTH: %s%s%s\n' "$color" "$HEALTH_STATE" "$C_RESET"
    say "${C_BOLD}============================================================${C_RESET}"
    printf ' broken components : %s\n' "$HEALTH_BROKEN"
    printf ' degraded checks   : %s\n' "$HEALTH_DEGRADED"
    say ""

    case "$HEALTH_STATE" in
        HEALTHY)
            say " The instrumentation is working. This says nothing about whether"
            say " the host is compromised - see the audit report for that."
            ;;
        DEGRADED)
            say " Part of the monitoring is blind or late. Findings from this host"
            say " are incomplete, and an absence of alerts cannot be trusted."
            ;;
        BROKEN)
            say " A required component is dead. This host is effectively unmonitored."
            say " Treat the most recent report as expired: it described a host that"
            say " was being watched, and this one is not."
            ;;
    esac

    say ""
    say "${C_DIM} Limitation: an attacker with root can stop these services and edit"
    say " this check. Local self-monitoring raises effort, it does not survive a"
    say " determined root attacker. Ship the JSON to a remote collector for real"
    say " assurance: /var/log/itm-security/post-compromise-audit.json${C_RESET}"
    say "${C_BOLD}============================================================${C_RESET}"
}

# ============================================================
# ENTRY POINT
# ============================================================

run_audit_health() {

    module_begin "health" "Monitor Health"

    say ""
    health_check_install
    health_check_services
    health_check_timers
    health_check_last_runs
    health_check_inotify
    health_check_storage
    health_check_manifest
    health_check_coverage

    add_pass "monitor health: $HEALTH_STATE (broken=$HEALTH_BROKEN degraded=$HEALTH_DEGRADED)"

    module_end
}

#!/usr/bin/env bash
# shellcheck shell=bash

# ============================================================
# ITM Server Security Monitor
# Module S1: SSH session monitoring and max-duration enforcement
#
# This is the ONLY module in the project allowed to change the
# state of the running system, and only in one specific way:
# terminating an SSH login session that has exceeded the
# configured maximum duration, and only when the operator has
# explicitly set mode=enforce.
#
# Default is monitor_only. An audit tool that starts closing
# people's sessions the moment it is installed is a tool nobody
# will be allowed to keep.
#
# WHY loginctl AND NOT kill
#
# Killing the sshd child PID leaves everything the user started
# behind: a "sudo su" root shell, a detached screen, a running
# script. loginctl terminate-session ends the whole systemd
# session scope, which is what "log this person out" actually
# means.
#
# WHAT IS NEVER TERMINATED, in any mode
#
#   local console sessions        (Remote=no / seat0)
#   non-interactive service users
#   systemd services, cron jobs
#   sftp/scp/rsync transfers      (unless explicitly enabled)
#   sessions running a package upgrade, reboot, backup or
#     migration, or anything in the exemption list
#   sessions whose liveness cannot be re-verified at the moment
#     of termination
#
# Everything here is idempotent and safe to run every minute:
# findings deduplicate through the existing fingerprint state,
# and a session that has already been terminated is recorded so
# it is never acted on twice.
# ============================================================

# ------------------------------------------------------------
# Policy (override in audit.conf)
# ------------------------------------------------------------

SSH_MAX_SESSION_ENABLED="${SSH_MAX_SESSION_ENABLED:-1}"
SSH_MAX_SESSION_SECONDS="${SSH_MAX_SESSION_SECONDS:-10800}"          # 3 hours
SSH_SESSION_CHECK_INTERVAL_SECONDS="${SSH_SESSION_CHECK_INTERVAL_SECONDS:-60}"

# monitor_only | enforce
SSH_SESSION_MODE="${SSH_SESSION_MODE:-monitor_only}"

# Classification only. Being on this list does NOT extend the
# timeout - that is a separate, deliberate setting below.
SSH_ALLOWED_USERS="${SSH_ALLOWED_USERS:-}"
SSH_ALLOWED_SOURCE_NETWORKS="${SSH_ALLOWED_SOURCE_NETWORKS:-}"

# The only list that actually exempts a session from the
# maximum duration.
SSH_TIMEOUT_EXEMPT_USERS="${SSH_TIMEOUT_EXEMPT_USERS:-}"

# A session running one of these is never terminated: cutting a
# dist-upgrade or a database migration in half is worse than a
# long session.
SSH_EXEMPT_PROCESSES="${SSH_EXEMPT_PROCESSES:-apt apt-get aptitude dpkg unattended-upgrade dnf yum rpm zypper do-release-upgrade reboot shutdown systemctl mysqldump mariadb-dump pg_dump pg_restore rsync borg borgmatic restic duplicity tar dd mkfs fsck resize2fs xfs_growfs docker podman kubeadm ansible-playbook terraform}"

# Transfer sessions are automation, not people. Off by default.
SSH_TERMINATE_TRANSFER_SESSIONS="${SSH_TERMINATE_TRANSFER_SESSIONS:-0}"

# Severity thresholds (seconds).
SSH_SEVERITY_WARN_SECONDS="${SSH_SEVERITY_WARN_SECONDS:-7200}"       # 2 hours

# Seams for testing. Never set these in production.
SSH_SESSION_FIXTURE="${SSH_SESSION_FIXTURE:-}"
SSH_TERMINATE_CMD="${SSH_TERMINATE_CMD:-}"

SSH_TERMINATED_STATE_KEY="ssh-terminated-sessions"

# ------------------------------------------------------------
# Session collection
#
# loginctl is the source of truth: it is the only interface
# that knows what a "session" is. ss/w/ps are enrichment only.
#
# Normalised record, pipe separated:
#   id|user|remote|remote_host|tty|leader|service|class|type|state|age_seconds|privesc
# ------------------------------------------------------------

ssh_collect_sessions() {

    # Test seam: a fixture file provides records directly so the
    # classification and enforcement logic can be exercised
    # without real login sessions.
    if [[ -n "$SSH_SESSION_FIXTURE" && -r "$SSH_SESSION_FIXTURE" ]]; then
        grep -vE '^\s*(#|$)' "$SSH_SESSION_FIXTURE"
        return 0
    fi

    have_cmd loginctl || return 1

    local id
    while read -r id; do
        [[ -n "$id" ]] || continue
        ssh_describe_session "$id"
    done < <(run_timeout "$CMD_TIMEOUT" loginctl list-sessions --no-legend 2>/dev/null | awk '{print $1}')
}

ssh_describe_session() {

    local id="$1" props
    local user="" remote="" remote_host="" tty="" leader="" service=""
    local class="" type="" state="" ts="" age=0

    props="$(run_timeout 10 loginctl show-session "$id" \
        -p Id -p Name -p User -p Remote -p RemoteHost -p TTY -p Leader \
        -p Service -p Class -p Type -p State -p Timestamp 2>/dev/null)"

    [[ -n "$props" ]] || return 0

    local line key value
    while IFS= read -r line; do
        key="${line%%=*}"
        value="${line#*=}"
        case "$key" in
            Name)       user="$value" ;;
            Remote)     remote="$value" ;;
            RemoteHost) remote_host="$value" ;;
            TTY)        tty="$value" ;;
            Leader)     leader="$value" ;;
            Service)    service="$value" ;;
            Class)      class="$value" ;;
            Type)       type="$value" ;;
            State)      state="$value" ;;
            Timestamp)  ts="$value" ;;
        esac
    done <<< "$props"

    age="$(ssh_session_age "$ts" "$leader")"

    printf '%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\n' \
        "$id" "${user:-unknown}" "${remote:-no}" "${remote_host:-}" \
        "${tty:-}" "${leader:-0}" "${service:-}" "${class:-}" \
        "${type:-}" "${state:-}" "$age" "$(ssh_session_privesc "$leader")"
}

# Session age in seconds. loginctl's Timestamp is authoritative;
# the leader process start time is the fallback, because some
# systemd versions report an empty Timestamp for old sessions.
ssh_session_age() {

    local ts="$1" leader="$2" start now

    now="$(date +%s)"

    if [[ -n "$ts" ]]; then
        start="$(date -d "$ts" +%s 2>/dev/null)"
        if [[ "$start" =~ ^[0-9]+$ ]] && (( start > 0 && start <= now )); then
            printf '%s' $(( now - start ))
            return 0
        fi
    fi

    if [[ "$leader" =~ ^[0-9]+$ ]] && (( leader > 0 )) && [[ -r "/proc/$leader/stat" ]]; then
        local btime clk ticks
        btime="$(awk '/^btime/ {print $2}' /proc/stat 2>/dev/null)"
        clk="$(getconf CLK_TCK 2>/dev/null || echo 100)"
        ticks="$(awk '{print $22}' "/proc/$leader/stat" 2>/dev/null)"
        if [[ "$btime" =~ ^[0-9]+$ && "$ticks" =~ ^[0-9]+$ ]]; then
            start=$(( btime + ticks / clk ))
            (( start > 0 && start <= now )) && { printf '%s' $(( now - start )); return 0; }
        fi
    fi

    printf '0'
}

# Did the session escalate privilege? Look for sudo/su, or a
# root shell, among the processes sharing the session leader's
# session id.
ssh_session_privesc() {

    local leader="$1" pid comm uid sid leader_sid=""

    [[ "$leader" =~ ^[0-9]+$ ]] && (( leader > 0 )) || { printf 'no'; return 0; }
    [[ -r "/proc/$leader/stat" ]] || { printf 'no'; return 0; }

    leader_sid="$(awk '{print $6}' "/proc/$leader/stat" 2>/dev/null)"
    [[ -n "$leader_sid" ]] || { printf 'no'; return 0; }

    while IFS= read -r pid; do
        [[ -r "/proc/$pid/stat" ]] || continue
        sid="$(awk '{print $6}' "/proc/$pid/stat" 2>/dev/null)"
        [[ "$sid" == "$leader_sid" ]] || continue
        comm="$(tr -d '\0' < "/proc/$pid/comm" 2>/dev/null)"
        case "$comm" in
            sudo|su|doas) printf 'yes'; return 0 ;;
        esac
        uid="$(awk '/^Uid:/ {print $2}' "/proc/$pid/status" 2>/dev/null)"
        if [[ "$uid" == "0" ]]; then
            case "$comm" in
                bash|sh|zsh|dash|ksh|fish) printf 'yes'; return 0 ;;
            esac
        fi
    done < <(find /proc -maxdepth 1 -regex '/proc/[0-9]+' -printf '%f\n' 2>/dev/null)

    printf 'no'
}

# ------------------------------------------------------------
# Classification
# ------------------------------------------------------------

ssh_is_remote_ssh() {
    local remote="$1" remote_host="$2" service="$3" class="$4" state="${5:-}"
    [[ "$remote" == "yes" ]] || return 1
    #
    # RemoteHost is NOT required.
    #
    # logind sometimes marks a session Remote=yes while leaving
    # RemoteHost empty. Requiring it made those sessions
    # invisible: they were never counted, never aged, and never
    # eligible for enforcement. A session whose source cannot be
    # established is the one that deserves MORE attention, not
    # less - so it is monitored, and the unknown source pushes it
    # to CRITICAL once it passes the limit.
    #
    # A session that is already closing or closed is not a
    # candidate for anything: acting on it either does nothing or
    # lands on a reused session id.
    case "$state" in
        active|online|opening|"") ;;
        *) return 1 ;;
    esac
    case "$service" in
        sshd|ssh) ;;
        *) return 1 ;;
    esac
    # greeter/lock-screen classes are not interactive logins.
    case "$class" in
        user|user-incomplete|"") ;;
        *) return 1 ;;
    esac
    return 0
}

ssh_source_is_known() {
    local ip="$1" net
    [[ -n "$ip" ]] || return 1
    ip_is_trusted "$ip" && return 0
    for net in $SSH_ALLOWED_SOURCE_NETWORKS; do
        [[ "$ip" == "$net" ]] && return 0
        ip_in_cidr "$ip" "$net" && return 0
    done
    return 1
}

ssh_user_is_allowed() {
    local user="$1" u
    for u in $SSH_ALLOWED_USERS; do
        [[ "$user" == "$u" ]] && return 0
    done
    return 1
}

ssh_user_is_timeout_exempt() {
    local user="$1" u
    for u in $SSH_TIMEOUT_EXEMPT_USERS; do
        [[ "$user" == "$u" ]] && return 0
    done
    return 1
}

# Is the session a file transfer rather than a person?
ssh_is_transfer_session() {
    local leader="$1" pid comm sid leader_sid
    [[ "$leader" =~ ^[0-9]+$ ]] || return 1
    [[ -r "/proc/$leader/stat" ]] || return 1
    leader_sid="$(awk '{print $6}' "/proc/$leader/stat" 2>/dev/null)"
    while IFS= read -r pid; do
        [[ -r "/proc/$pid/stat" ]] || continue
        sid="$(awk '{print $6}' "/proc/$pid/stat" 2>/dev/null)"
        [[ "$sid" == "$leader_sid" ]] || continue
        comm="$(tr -d '\0' < "/proc/$pid/comm" 2>/dev/null)"
        case "$comm" in
            sftp-server|scp|rsync) return 0 ;;
        esac
    done < <(find /proc -maxdepth 1 -regex '/proc/[0-9]+' -printf '%f\n' 2>/dev/null)
    return 1
}

# Is the session running work that must not be interrupted?
ssh_session_busy_process() {

    local leader="$1" pid comm sid leader_sid exempt

    [[ "$leader" =~ ^[0-9]+$ ]] || return 1
    [[ -r "/proc/$leader/stat" ]] || return 1
    leader_sid="$(awk '{print $6}' "/proc/$leader/stat" 2>/dev/null)"

    while IFS= read -r pid; do
        [[ -r "/proc/$pid/stat" ]] || continue
        sid="$(awk '{print $6}' "/proc/$pid/stat" 2>/dev/null)"
        [[ "$sid" == "$leader_sid" ]] || continue
        comm="$(tr -d '\0' < "/proc/$pid/comm" 2>/dev/null)"
        for exempt in $SSH_EXEMPT_PROCESSES; do
            if [[ "$comm" == "$exempt" ]]; then
                printf '%s' "$comm"
                return 0
            fi
        done
    done < <(find /proc -maxdepth 1 -regex '/proc/[0-9]+' -printf '%f\n' 2>/dev/null)

    return 1
}

ssh_severity_for() {
    local age="$1" known="$2"
    if (( age >= SSH_MAX_SESSION_SECONDS )); then
        [[ "$known" == "no" ]] && { printf 'CRITICAL'; return 0; }
        printf 'HIGH'; return 0
    fi
    (( age >= SSH_SEVERITY_WARN_SECONDS )) && { printf 'MEDIUM'; return 0; }
    printf 'INFO'
}

ssh_hms() {
    local s="$1"
    printf '%dh%02dm' $(( s / 3600 )) $(( (s % 3600) / 60 ))
}

# ------------------------------------------------------------
# Termination
#
# Re-validates the session immediately before acting: between
# the scan and the decision the user may already have logged
# out, and terminating a session id that has been reused would
# hit the wrong person.
# ------------------------------------------------------------

ssh_already_terminated() {
    local id="$1" file="$ITM_SCAN_STATE_DIR/$SSH_TERMINATED_STATE_KEY"
    [[ -r "$file" ]] || return 1
    grep -qxF "$id" "$file" 2>/dev/null
}

ssh_record_terminated() {
    local id="$1" file="$ITM_SCAN_STATE_DIR/$SSH_TERMINATED_STATE_KEY"
    (( ITM_DRY_RUN )) && return 0
    mkdir -p "$ITM_SCAN_STATE_DIR" 2>/dev/null || return 0
    printf '%s\n' "$id" >> "$file" 2>/dev/null || true
    # Keep the file bounded.
    tail -200 "$file" > "$file.tmp" 2>/dev/null && mv -f "$file.tmp" "$file" 2>/dev/null || true
    chmod 600 "$file" 2>/dev/null || true
}

ssh_revalidate_session() {

    local id="$1" user="$2"

    # In fixture mode the re-validation is assumed to pass: the
    # fixture IS the current state.
    [[ -n "$SSH_SESSION_FIXTURE" ]] && return 0

    have_cmd loginctl || return 1

    local props state remote service name
    props="$(run_timeout 10 loginctl show-session "$id" -p State -p Remote -p Service -p Name 2>/dev/null)"
    [[ -n "$props" ]] || return 1

    state="$(printf '%s' "$props"  | awk -F= '/^State=/{print $2}')"
    remote="$(printf '%s' "$props" | awk -F= '/^Remote=/{print $2}')"
    service="$(printf '%s' "$props"| awk -F= '/^Service=/{print $2}')"
    name="$(printf '%s' "$props"   | awk -F= '/^Name=/{print $2}')"

    [[ "$remote" == "yes" ]] || return 1
    [[ "$service" == "sshd" || "$service" == "ssh" ]] || return 1
    [[ "$name" == "$user" ]] || return 1
    case "$state" in
        active|online|opening) ;;
        *) return 1 ;;
    esac

    return 0
}

ssh_terminate_session() {

    local id="$1"

    if [[ -n "$SSH_TERMINATE_CMD" ]]; then
        # Test seam.
        $SSH_TERMINATE_CMD "$id"
        return $?
    fi

    have_cmd loginctl || return 1
    run_timeout 15 loginctl terminate-session "$id"
}

# ============================================================
# Main check
# ============================================================

check_ssh_sessions() {

    local record id user remote remote_host tty leader service class type state age privesc
    local total=0 remote_total=0 over_warn=0 over_max=0 terminated=0 skipped=0

    while IFS='|' read -r id user remote remote_host tty leader service class type state age privesc; do

        [[ -n "$id" ]] || continue
        total=$(( total + 1 ))

        # ---- never touch anything that is not a remote SSH login
        if ! ssh_is_remote_ssh "$remote" "$remote_host" "$service" "$class" "$state"; then
            audit_log INFO "session $id ($user) is not an actionable remote SSH login (remote=$remote service=$service class=$class state=$state) - ignored"
            continue
        fi

        remote_total=$(( remote_total + 1 ))
        [[ "$age" =~ ^[0-9]+$ ]] || age=0

        local known="yes"
        if [[ -z "$remote_host" ]]; then
            remote_host="unknown"
            known="no"
        else
            ssh_source_is_known "$remote_host" || known="no"
        fi

        local severity
        severity="$(ssh_severity_for "$age" "$known")"

        local reasons="user=${user} source=${remote_host} session=${id} age=$(ssh_hms "$age") tty=${tty:-none} leader=${leader}"
        reasons+="
source address is $( [[ "$known" == yes ]] && echo "within the allowed networks" || echo "NOT in any allowed network" )"
        [[ "$privesc" == "yes" ]] && reasons+="
session escalated privilege (sudo / su / root shell)"
        ssh_user_is_allowed "$user" && reasons+="
user is on the allowlist (classification only - does not extend the timeout)"

        # ---- under the warning threshold: inventory only
        if [[ "$severity" == "INFO" ]]; then
            add_pass "SSH session ${id}: ${user} from ${remote_host} for $(ssh_hms "$age")" \
                event=SSH_SESSION_ACTIVE
            continue
        fi

        (( age >= SSH_SEVERITY_WARN_SECONDS )) && over_warn=$(( over_warn + 1 ))

        # ---- 2-3 hours: warn, never act
        if (( age < SSH_MAX_SESSION_SECONDS )); then
            add_finding MEDIUM \
                "SSH session approaching the maximum duration" \
                id="ssh-session-long:$id:$user" \
                event=SSH_SESSION_LONG_RUNNING \
                confidence=99 \
                reasons="$reasons" \
                process="session=$id user=$user leader=$leader tty=${tty:-none} privilege_escalation=$privesc" \
                network="source=$remote_host known=$known" \
                evidence="age=$(ssh_hms "$age") limit=$(ssh_hms "$SSH_MAX_SESSION_SECONDS") mode=$SSH_SESSION_MODE" \
                action="No action taken. The session is terminated only past $(ssh_hms "$SSH_MAX_SESSION_SECONDS"), and only when mode=enforce."
            continue
        fi

        # ---- past the maximum
        over_max=$(( over_max + 1 ))

        local exempt_reason=""
        local busy=""

        if [[ "$SSH_MAX_SESSION_ENABLED" != "1" ]]; then
            exempt_reason="max session enforcement is disabled (ssh_max_session_enabled=0)"
        elif ssh_user_is_timeout_exempt "$user"; then
            exempt_reason="user '$user' is in ssh_timeout_exempt_users"
        elif busy="$(ssh_session_busy_process "$leader")"; then
            exempt_reason="session is running '$busy' - interrupting it could leave the system in a broken state"
        elif [[ "$SSH_TERMINATE_TRANSFER_SESSIONS" != "1" ]] && ssh_is_transfer_session "$leader"; then
            exempt_reason="session is an sftp/scp/rsync transfer (enable ssh_terminate_transfer_sessions to include these)"
        fi

        # ---- monitor_only, or exempt: report and stop
        if [[ "$SSH_SESSION_MODE" != "enforce" || -n "$exempt_reason" ]]; then

            local why="mode=$SSH_SESSION_MODE"
            [[ -n "$exempt_reason" ]] && why="$exempt_reason"
            [[ -n "$exempt_reason" ]] && skipped=$(( skipped + 1 ))

            say "${C_MED}[WARN] SSH_SESSION_EXCEEDED${C_RESET} session=$id user=$user source=$remote_host age=$(ssh_hms "$age")"

            add_finding "$severity" \
                "SSH session exceeded the maximum duration" \
                id="ssh-session-exceeded:$id:$user" \
                event=SSH_SESSION_LONG_RUNNING \
                confidence=99 \
                reasons="$reasons
not terminated: $why" \
                process="session=$id user=$user leader=$leader tty=${tty:-none} privilege_escalation=$privesc" \
                network="source=$remote_host known=$known" \
                evidence="age=$(ssh_hms "$age") limit=$(ssh_hms "$SSH_MAX_SESSION_SECONDS") mode=$SSH_SESSION_MODE
$( [[ -n "$exempt_reason" ]] && printf 'exemption: %s' "$exempt_reason" )" \
                action="$( [[ "$SSH_SESSION_MODE" == enforce ]] \
                    && printf 'Exempt from automatic termination. Close it manually if it is not expected: loginctl terminate-session %s' "$id" \
                    || printf 'monitor_only: nothing was terminated. Set ssh_session_mode=enforce in %s to act automatically, or close it manually: loginctl terminate-session %s' "$ITM_AUDIT_CONF" "$id" )"
            continue
        fi

        # ---- enforce
        if ssh_already_terminated "$id"; then
            audit_log INFO "session $id already terminated in an earlier run - not repeating"
            continue
        fi

        if ! ssh_revalidate_session "$id" "$user"; then
            add_finding MEDIUM \
                "SSH session disappeared or changed before it could be terminated" \
                id="ssh-session-stale:$id" \
                event=SSH_SESSION_LONG_RUNNING \
                confidence=70 \
                reasons="The session was over the limit when it was scanned
It is no longer a live remote SSH session for the same user
Nothing was terminated: acting on a reused session id would hit the wrong person" \
                process="session=$id user=$user" \
                action="No action needed. The session ended on its own."
            continue
        fi

        if ssh_terminate_session "$id"; then

            terminated=$(( terminated + 1 ))
            ssh_record_terminated "$id"

            add_finding "$severity" \
                "SSH session terminated after exceeding the maximum duration" \
                id="ssh-session-terminated:$id:$user" \
                event=SSH_SESSION_TERMINATED \
                confidence=99 \
                reasons="$reasons
session exceeded $(ssh_hms "$SSH_MAX_SESSION_SECONDS") and mode=enforce
whole login session ended with loginctl terminate-session, including any sudo/su shell it owned" \
                process="session=$id user=$user leader=$leader tty=${tty:-none} privilege_escalation=$privesc" \
                network="source=$remote_host known=$known" \
                evidence="age at termination=$(ssh_hms "$age") limit=$(ssh_hms "$SSH_MAX_SESSION_SECONDS")
command: loginctl terminate-session $id" \
                action="If this interrupted legitimate work, add the account to ssh_timeout_exempt_users in $ITM_AUDIT_CONF, or raise ssh_max_session_seconds. To stop all automatic termination set ssh_session_mode=monitor_only."
        else
            add_finding HIGH \
                "Failed to terminate an SSH session that exceeded the maximum duration" \
                id="ssh-session-terminate-failed:$id" \
                event=SSH_SESSION_LONG_RUNNING \
                confidence=90 \
                reasons="loginctl terminate-session returned an error
The session is still running" \
                process="session=$id user=$user" \
                action="Terminate it by hand and check why systemd refused: loginctl terminate-session $id"
        fi

    done < <(ssh_collect_sessions)

    audit_log INFO "ssh sessions: total=$total remote=$remote_total over_warn=$over_warn over_max=$over_max terminated=$terminated exempt=$skipped"

    if (( remote_total == 0 )); then
        add_pass "no remote SSH session is currently open"
    elif (( over_warn == 0 )); then
        add_pass "$remote_total remote SSH session(s), none older than $(ssh_hms "$SSH_SEVERITY_WARN_SECONDS")"
    fi

    SSH_SUMMARY_TOTAL="$remote_total"
    SSH_SUMMARY_WARN="$over_warn"
    SSH_SUMMARY_MAX="$over_max"
    SSH_SUMMARY_TERMINATED="$terminated"
}

# ============================================================
# ENTRY POINT
# ============================================================

SSH_SUMMARY_TOTAL=0; SSH_SUMMARY_WARN=0; SSH_SUMMARY_MAX=0; SSH_SUMMARY_TERMINATED=0

run_audit_ssh_session() {

    module_begin "ssh_session" "SSH Session Control"

    if ! have_cmd loginctl && [[ -z "$SSH_SESSION_FIXTURE" ]]; then
        add_skip "loginctl not available - SSH session monitoring requires systemd-logind"
        module_end
        return 0
    fi

    case "$SSH_SESSION_MODE" in
        monitor_only)
            add_pass "mode=monitor_only - sessions are reported, never terminated (limit $(ssh_hms "$SSH_MAX_SESSION_SECONDS"))" ;;
        enforce)
            add_finding INFO \
                "SSH session enforcement is ACTIVE on this host" \
                id="ssh-enforce-active" \
                event=SSH_SESSION_ENFORCE_ACTIVE \
                status=CHECK_PASS \
                evidence="Sessions older than $(ssh_hms "$SSH_MAX_SESSION_SECONDS") are terminated with loginctl terminate-session.
Exempt users: ${SSH_TIMEOUT_EXEMPT_USERS:-none}
Exempt processes: $SSH_EXEMPT_PROCESSES" \
                action="Set ssh_session_mode=monitor_only in $ITM_AUDIT_CONF to disable automatic termination." ;;
        *)
            add_finding LOW \
                "Unknown ssh_session_mode '$SSH_SESSION_MODE' - treating as monitor_only" \
                id="ssh-mode-invalid" \
                action="Set ssh_session_mode to monitor_only or enforce."
            SSH_SESSION_MODE="monitor_only" ;;
    esac

    check_ssh_sessions

    module_end
}

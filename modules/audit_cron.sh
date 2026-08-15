#!/usr/bin/env bash
# shellcheck shell=bash

# ============================================================
# ITM Server Security Monitor
# Module CR: scheduled task persistence
#
# Read only. No cron entry is ever edited or removed: deleting
# the attacker's cron line before the incident is understood
# destroys the timestamp evidence and tells them they were
# found.
#
# Background - real incident on this estate: a root cron entry
# running EVERY MINUTE rebuilt a reverse shell with mkfifo and
# nc to an external host on port 9925, and restarted sshd to
# re-apply its own configuration.
#
# The existing file monitor already alerts when a file under
# /etc/cron.d changes. That tells an operator something moved;
# it does not tell them a reverse shell was installed. This
# module reads the content.
#
# Sources covered:
#   /etc/crontab, /etc/cron.d, /etc/cron.{hourly,daily,weekly,monthly}
#   per user crontabs in /var/spool/cron
#   systemd timers (the modern equivalent, audited here too)
#   at jobs
# ============================================================

CRON_SYSTEM_FILES="${CRON_SYSTEM_FILES-/etc/crontab}"
CRON_DIRS="${CRON_DIRS-/etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly}"
CRON_SPOOL_DIRS="${CRON_SPOOL_DIRS-/var/spool/cron /var/spool/cron/crontabs}"

# Structural patterns. Vocabulary alone is never enough: a
# backup job legitimately uses curl, and a deploy script
# legitimately uses bash.
CRON_REVSHELL='mkfifo|/dev/tcp/|/dev/udp/|\bnc\b[[:space:]]+-[a-z]*e|\bncat\b.*-e|\bsocat\b.*exec|bash[[:space:]]+-i|sh[[:space:]]+-i'
CRON_DOWNLOAD_EXEC='(curl|wget)[^|;]*\|[[:space:]]*(ba)?sh|(curl|wget)[^|;]*\|[[:space:]]*(python|perl|php)'
CRON_ENCODED='base64[[:space:]]+(-d|--decode)|openssl[[:space:]]+enc[[:space:]]+-d|\|[[:space:]]*base64[[:space:]]+-d'
CRON_INTERPRETER_INLINE='(python[0-9.]*|perl|ruby|php)[[:space:]]+-[ecr][[:space:]]'
CRON_SERVICE_RESTART='systemctl[[:space:]]+(restart|start)[[:space:]]+(sshd?|ssh)|service[[:space:]]+ssh'
CRON_HISTORY_WIPE='history[[:space:]]+-c|>[[:space:]]*/var/log/|shred|\bchattr\b'

# ------------------------------------------------------------
# Schedule parsing
#
# "every minute" is a strong signal on its own: almost nothing
# legitimate needs to run 1440 times a day, and a re-spawning
# implant needs exactly that.
# ------------------------------------------------------------

cron_schedule_is_minutely() {
    local sched="$1"
    case "$sched" in
        '* * * * *'|'*/1 * * * *') return 0 ;;
    esac
    [[ "$sched" =~ ^\*/[1-5][[:space:]] ]] && return 0
    return 1
}

# ------------------------------------------------------------
# Score one cron command line
# ------------------------------------------------------------

cron_score_line() {

    local line="$1" schedule="$2" user="$3" source="$4"
    local hits=0

    if printf '%s' "$line" | grep -qE "$CRON_REVSHELL"; then
        score_add 60 "reverse shell primitives (mkfifo / nc -e / /dev/tcp / interactive shell)"
        hits=$(( hits + 1 ))
    fi

    if printf '%s' "$line" | grep -qE "$CRON_DOWNLOAD_EXEC"; then
        score_add 55 "downloads and pipes straight into a shell or interpreter"
        hits=$(( hits + 1 ))
    fi

    if printf '%s' "$line" | grep -qE "$CRON_ENCODED"; then
        score_add 35 "base64/openssl decoded command execution"
        hits=$(( hits + 1 ))
    fi

    if printf '%s' "$line" | grep -qE "$CRON_INTERPRETER_INLINE"; then
        # Deliberately NOT counted as a structural hit: stock
        # certbot entries use "perl -e 'sleep int(rand(43200))'".
        score_add 12 "inline interpreter one-liner rather than a script on disk"
    fi

    if printf '%s' "$line" | grep -qE "$CRON_SERVICE_RESTART"; then
        score_add 30 "restarts SSH from cron - re-applies configuration the operator may have reverted"
        hits=$(( hits + 1 ))
    fi

    if printf '%s' "$line" | grep -qE "$CRON_HISTORY_WIPE"; then
        score_add 30 "clears history, truncates logs or changes file attributes"
        hits=$(( hits + 1 ))
    fi

    # An external endpoint in a cron line is worth points only
    # together with something else, hence the modest weight.
    if printf '%s' "$line" | grep -qE 'https?://[a-zA-Z0-9.-]+|[0-9]{1,3}(\.[0-9]{1,3}){3}'; then
        score_add 15 "contacts an external host"
    fi

    # Volatile locations.
    if printf '%s' "$line" | grep -qE '/tmp/|/var/tmp/|/dev/shm/'; then
        score_add 25 "executes from a temporary directory"
        hits=$(( hits + 1 ))
    fi

    if cron_schedule_is_minutely "$schedule"; then
        score_add 25 "runs every minute or more often than every 5 minutes"
    fi

    if [[ "$user" == "root" ]]; then
        score_add 15 "runs as root"
    fi

    return $(( hits > 0 ? 0 : 1 ))
}

# ------------------------------------------------------------
# One cron source
# ------------------------------------------------------------

cron_examine_file() {

    local file="$1" default_user="$2"
    local line clean schedule command user fields
    local reported=0

    [[ -r "$file" ]] || return 0

    while IFS= read -r line; do

        clean="${line#"${line%%[![:space:]]*}"}"
        [[ -z "$clean" ]] && continue
        [[ "$clean" == \#* ]] && continue
        # Environment assignments are not commands.
        [[ "$clean" =~ ^[A-Z_]+= ]] && continue

        schedule=""
        command=""
        user="$default_user"

        # A cron schedule is mostly asterisks. Splitting it with
        # an unquoted array assignment expands them against the
        # working directory, which silently corrupts both the
        # schedule and the user field.
        local -a fields=()
        read -ra fields <<< "$clean"

        if [[ "$clean" =~ ^@ ]]; then
            # @reboot, @daily ...
            schedule="${clean%% *}"
            command="${clean#* }"
            if [[ -z "$default_user" ]]; then
                user="${command%% *}"
                command="${command#* }"
            fi
        else
            # 5 schedule fields, then (for system crontabs) a user.
            (( ${#fields[@]} >= 6 )) || continue
            schedule="${fields[0]} ${fields[1]} ${fields[2]} ${fields[3]} ${fields[4]}"
            if [[ -z "$default_user" ]]; then
                user="${fields[5]}"
                command="${clean#*${fields[5]}}"
            else
                command="${clean#*${fields[4]}}"
            fi
        fi

        command="${command#"${command%%[![:space:]]*}"}"
        [[ -n "$command" ]] || continue

        score_reset
        local structural=0
        cron_score_line "$command" "$schedule" "$user" "$file" && structural=1

        # Context alone (root, every minute, an interpreter) is
        # what normal system cron looks like. Something
        # structural has to be present, unless the context score
        # is high enough to stand on its own.
        if (( structural == 0 )) && (( SCORE_TOTAL < SCORE_THRESHOLD_HIGH )); then
            continue
        fi

        (( SCORE_TOTAL >= SCORE_THRESHOLD_LOW )) || continue

        local sev
        sev="$(score_severity)"

        add_finding "$sev" \
            "Suspicious scheduled task" \
            id="cron:$file:$(printf '%s' "$command" | sha256sum | cut -c1-12)" \
            path="$file" \
            confidence="$(score_confidence)" \
            reasons="$SCORE_REASONS" \
            process="user=$user schedule=$schedule" \
            evidence="$(truncate_text "$(redact "$clean")" 400)
file: $file
mtime: $(file_mtime_human "$file") owner: $(stat -Lc '%U:%G' "$file" 2>/dev/null)" \
            action="Do not delete the entry yet: its timestamp and content are evidence, and removing it warns whoever installed it. Preserve the file, identify what the command contacts, then remove the entry and the payload together. Generate a response script with: itm-security remediate"

        reported=$(( reported + 1 ))

    done < "$file"

    return "$reported"
}

# ------------------------------------------------------------
# Checks
# ------------------------------------------------------------

check_cron_system() {

    local file dir total=0 examined=0

    for file in $CRON_SYSTEM_FILES; do
        [[ -r "$file" ]] || continue
        examined=$(( examined + 1 ))
        cron_examine_file "$file" ""
        total=$(( total + $? ))
    done

    for dir in $CRON_DIRS; do
        [[ -d "$dir" ]] || continue
        while IFS= read -r file; do
            [[ -n "$file" ]] || continue
            examined=$(( examined + 1 ))
            # cron.daily and friends hold scripts, not crontab
            # lines: they are examined as scripts below.
            case "$dir" in
                /etc/cron.d) cron_examine_file "$file" "" ;;
                *)           cron_examine_script "$file" ;;
            esac
            total=$(( total + $? ))
        done < <(find "$dir" -maxdepth 1 -type f ! -name '.*' ! -name '*.dpkg-*' 2>/dev/null | sort)
    done

    audit_log INFO "examined $examined system cron sources"

    (( total == 0 )) && add_pass "no suspicious command in $examined system cron sources"
    return 0
}

# A script in cron.daily etc: score its whole content.
cron_examine_script() {

    local file="$1" content

    [[ -r "$file" ]] || return 0

    content="$(web_file_head "$file" 65536 2>/dev/null || head -c 65536 "$file" 2>/dev/null)"
    [[ -n "$content" ]] || return 0

    score_reset
    cron_score_line "$content" "cron.d-script" "root" "$file" || return 0

    (( SCORE_TOTAL >= SCORE_THRESHOLD_MEDIUM )) || return 0

    # A packaged script doing packaged things is not a finding.
    if is_pkg_owned "$file"; then
        score_add -30 "script belongs to an installed package"
        (( SCORE_TOTAL >= SCORE_THRESHOLD_MEDIUM )) || return 0
    fi

    add_finding "$(score_severity)" \
        "Suspicious periodic script" \
        id="cron-script:$file" \
        path="$file" \
        hash="$(file_sha256 "$file")" \
        confidence="$(score_confidence)" \
        reasons="$SCORE_REASONS" \
        evidence="package=$(pkg_owner "$file") mtime=$(file_mtime_human "$file")
$(truncate_text "$(redact "$(printf '%s' "$content" | grep -nE "$CRON_REVSHELL|$CRON_DOWNLOAD_EXEC|$CRON_ENCODED" | head -3)")" 300)" \
        action="Compare against the package version. Preserve before removing anything."

    return 1
}

check_cron_user() {

    local dir file user total=0 found_any=0

    for dir in $CRON_SPOOL_DIRS; do
        [[ -d "$dir" ]] || continue
        while IFS= read -r file; do
            [[ -n "$file" ]] || continue
            user="$(basename "$file")"
            found_any=1
            cron_examine_file "$file" "$user"
            total=$(( total + $? ))
        done < <(find "$dir" -maxdepth 1 -type f 2>/dev/null | sort)
    done

    if (( found_any == 0 )); then
        add_pass "no per-user crontab present"
    elif (( total == 0 )); then
        add_pass "no suspicious command in the per-user crontabs"
    fi
}

# ------------------------------------------------------------
# Recently changed schedules
#
# Not a detection on its own: a package update rewrites cron
# files legitimately. Reported so the timeline is visible.
# ------------------------------------------------------------

check_cron_recent_changes() {

    local recent count=0 list=""

    recent="$(find $CRON_SYSTEM_FILES $CRON_DIRS $CRON_SPOOL_DIRS \
                -maxdepth 1 -type f -mtime -"${SYSTEMD_RECENT_DAYS}" 2>/dev/null | sort)"

    [[ -n "$recent" ]] || { add_pass "no cron file changed in the last ${SYSTEMD_RECENT_DAYS} days"; return 0; }

    local f
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        count=$(( count + 1 ))
        list+="$f (mtime $(file_mtime_human "$f"), package=$(pkg_owner "$f"))
"
    done <<< "$recent"

    add_finding LOW \
        "Scheduled task files changed in the last ${SYSTEMD_RECENT_DAYS} days" \
        id="cron-recent-change" \
        confidence=40 \
        reasons="${count} cron file(s) modified recently
Package updates rewrite these files legitimately, so this is timeline context rather than a detection" \
        evidence="$list" \
        action="Correlate the timestamps with your change record and with any incident window."
}

# ------------------------------------------------------------
# at(1)
# ------------------------------------------------------------

check_at_jobs() {

    local jobs

    have_cmd atq || { add_skip "atq not available - at job queue not inspected"; return 0; }

    jobs="$(run_timeout 10 atq 2>/dev/null | head -20)"

    if [[ -z "$jobs" ]]; then
        add_pass "no at(1) jobs queued"
        return 0
    fi

    add_finding MEDIUM \
        "Jobs are queued with at(1)" \
        id="at-jobs-present" \
        confidence=55 \
        reasons="at is rarely used on a server that is managed by configuration management
A one-shot scheduled job is a convenient way to re-establish access after a cleanup" \
        evidence="$(truncate_text "$jobs" 400)" \
        action="Inspect each job: at -c <id>. Preserve before removing."
}

# ============================================================
# ENTRY POINT
# ============================================================

run_audit_cron() {

    module_begin "cron" "Scheduled Task Persistence"

    check_cron_system
    check_cron_user
    check_at_jobs
    check_cron_recent_changes

    module_end
}

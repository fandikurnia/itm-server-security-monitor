#!/usr/bin/env bash
# shellcheck shell=bash

# ============================================================
# ITM Server Security Monitor
# Post-Compromise Audit - Module D: systemd persistence
#
# Read only. No unit is ever stopped, disabled or masked, and
# no unit file is edited. Disabling a service during business
# hours can take the application down harder than the intruder
# did.
#
# Background: this estate has previously been hit by fake units
# (defaults.service, server-security.service) whose executables
# were dropped into /usr/bin and which were configured to
# restart automatically.
#
# ITM's own units are allowlisted through ITM_OWN_UNITS, which
# is printed in the report so the exemption stays visible.
# ============================================================

SYSTEMD_UNIT_DIRS="/etc/systemd/system /usr/lib/systemd/system /lib/systemd/system /run/systemd/system"

# Word boundaries matter here: without them "rsync --daemon"
# matches a bare "nc -" pattern and every packaged unit becomes
# a finding.
SYSTEMD_SUSPICIOUS_EXEC='\b(curl|wget|ncat|socat|telnet)\b|\bnc\b[[:space:]]+-|/dev/tcp/|\bbase64\b[[:space:]]+(-d|--decode)|\bxxd\b[[:space:]]+-r|\beval\b|\bpython[0-9.]*\b[[:space:]]+-c|\bperl\b[[:space:]]+-e|\bphp\b[[:space:]]+-r|\bchattr\b|\bhistory\b[[:space:]]+-c|\bcrontab\b'

unit_is_itm_own() {
    local unit="$1" own
    for own in $ITM_OWN_UNITS; do
        [[ "$unit" == "$own" ]] && return 0
    done
    return 1
}

unit_is_known_bad() {
    local unit="$1" bad
    for bad in $KNOWN_BAD_UNITS; do
        [[ "$unit" == "$bad" ]] && return 0
    done
    return 1
}

# systemd allows Exec= prefixes: - @ + ! !! : strip them, then
# take the first token as the program path.
#
# Sets UNIT_EXEC_BIN instead of printing: this runs for every
# Exec line on the host, and a command substitution is a fork.
UNIT_EXEC_BIN=""

unit_exec_binary_var() {
    local first="${1%%[[:space:]]*}"
    first="${first#[-@+!:]}"
    first="${first#[-@+!:]}"
    UNIT_EXEC_BIN="$first"
}

unit_exec_binary() {
    unit_exec_binary_var "$1"
    printf '%s' "$UNIT_EXEC_BIN"
}

# Pure bash: this runs for every unit file on the host, and a
# grep+sed pipeline per file is two forks each.
unit_exec_lines() {

    local line key val

    [[ -r "$1" ]] || return 0

    while IFS= read -r line; do

        # left trim
        line="${line#"${line%%[![:space:]]*}"}"
        [[ "$line" == Exec*=* ]] || continue

        key="${line%%=*}"
        key="${key%"${key##*[![:space:]]}"}"

        case "$key" in
            ExecStart|ExecStartPre|ExecStartPost|ExecStop|ExecStopPost|ExecReload) ;;
            *) continue ;;
        esac

        val="${line#*=}"
        val="${val#"${val%%[![:space:]]*}"}"

        [[ -n "$val" ]] && printf '%s\n' "$val"

    done < "$1"
}

path_is_writable_by_others() {
    local path="$1" mode
    [[ -e "$path" ]] || return 1
    mode="$(path_mode "$path")"
    [[ -n "$mode" ]] || return 1
    # Group or world write bit set.
    (( (8#$mode & 8#022) != 0 ))
}

unit_active_state() {
    have_cmd systemctl || { printf 'unknown'; return 0; }
    printf '%s/%s' \
        "$(run_timeout 10 systemctl is-active "$1" 2>/dev/null || echo inactive)" \
        "$(run_timeout 10 systemctl is-enabled "$1" 2>/dev/null || echo unknown)"
}

# ------------------------------------------------------------
# Unit file audit
# ------------------------------------------------------------

check_unit_files() {

    local file unit dir execline bin
    local total=0 findings=0 recent_unmanaged=0
    local recent_cutoff=$(( $(date +%s) - SYSTEMD_RECENT_DAYS * 86400 ))

    local dirs=() d
    for d in $SYSTEMD_UNIT_DIRS; do
        [[ -d "$d" ]] && dirs+=("$d")
    done

    if (( ${#dirs[@]} == 0 )); then
        add_skip "no systemd unit directory found"
        return 0
    fi

    find "${dirs[@]}" -maxdepth 2 -type f \
        \( -name '*.service' -o -name '*.timer' -o -name '*.socket' -o -name '*.conf' \) \
        2>/dev/null | sort -u > "$ITM_RUN_TMP/unit_files.txt"

    # One batched package ownership query for every unit file and
    # every Exec target, and one batched stat for their modes,
    # instead of one lookup per unit.
    local prefetch=() bins=() bin_line
    while IFS= read -r file; do
        [[ -n "$file" ]] && prefetch+=("$file")
        while IFS= read -r bin_line; do
            unit_exec_binary_var "$bin_line"
            bin_line="$UNIT_EXEC_BIN"
            if [[ "$bin_line" == /* ]]; then
                prefetch+=("$bin_line")
                [[ -e "$bin_line" ]] && bins+=("$bin_line")
            fi
        done < <(unit_exec_lines "$file")
        bins+=("$file")
    done < "$ITM_RUN_TMP/unit_files.txt"

    (( ${#prefetch[@]} > 0 )) && pkg_owner_prefetch "${prefetch[@]}"
    (( ${#bins[@]} > 0 )) && stat_mode_prefetch "${bins[@]}"

    while IFS= read -r file; do

        [[ -r "$file" ]] || continue

        unit="${file##*/}"
        dir="${file%/*}"
        total=$(( total + 1 ))

        # ---- units seen in previous incidents ------------------
        if unit_is_known_bad "$unit"; then
            findings=$(( findings + 1 ))
            add_finding CRITICAL \
                "Systemd unit matching a known malicious persistence name from a previous incident" \
                id="known-bad-unit:$unit" \
                event=SYSTEMD_KNOWN_BAD_UNIT \
                confidence=95 \
                reasons="Unit name '$unit' matches KNOWN_BAD_UNITS, recorded from a confirmed compromise on this estate
The name alone is the match - verify the ExecStart and the binary before acting
A legitimate service that happens to share the name would look identical here" \
                path="$file" \
                process="state=$(unit_active_state "$unit")" \
                evidence="Unit: $unit
$(unit_exec_lines "$file" | head -5)
package=$(pkg_owner "$file") mtime=$(file_mtime_human "$file")" \
                action="Preserve the unit file and its executable, capture the process if running, then isolate. Do not disable before evidence collection is complete."
        fi

        unit_is_itm_own "$unit" && { add_pass "ITM unit present: $unit ($(unit_active_state "$unit"))"; continue; }

        # Distribution units are held to a different standard
        # than locally created ones: a packaged unit referencing
        # an optional binary is normal, whereas an unpackaged
        # unit doing the same is how a quarantined implant
        # leaves its persistence behind.
        local unit_owned=0
        is_pkg_owned "$file" && unit_owned=1

        # A unit in /etc/systemd/system that shadows a
        # package-owned unit of the same name is an ADMINISTRATOR
        # OVERRIDE, which is the documented way to customise a
        # service. dpkg does not own the override, so a naive
        # ownership test calls it a dropped unit.
        #
        # This misfired on a production host: tuned.service, a
        # stock tuning daemon with a local override, was reported
        # as unknown persistence and an operator quarantined it.
        # Expressed as a relationship rather than a hardcoded
        # path: any unit outside the vendor directories that
        # shadows a package-owned unit of the same name is an
        # override, wherever the distribution keeps its units.
        local unit_is_override=0 packaged_original="" libdir
        if (( unit_owned == 0 )); then
            for libdir in $SYSTEMD_UNIT_DIRS; do
                [[ "$libdir" == "$dir" ]] && continue
                [[ -f "$libdir/$unit" ]] || continue
                if is_pkg_owned "$libdir/$unit"; then
                    unit_is_override=1
                    packaged_original="$libdir/$unit"
                    break
                fi
            done
        fi

        if (( unit_is_override )); then
            add_finding LOW \
                "Local override of a packaged systemd unit" \
                id="unit-local-override:$unit" \
                event=SYSTEMD_LOCAL_OVERRIDE \
                path="$file" \
                confidence=70 \
                reasons="A unit of this name is shipped by a package at ${packaged_original}
The copy in /etc/systemd/system overrides it, which is the supported way to customise a service
This is a change-review item, NOT unknown persistence: the service itself is packaged software
Do NOT quarantine it without checking: the packaged service stays installed either way, and removing a legitimate override stops it" \
                process="state=$(unit_active_state "$unit")" \
                evidence="override : $file (mtime $(file_mtime_human "$file"))
packaged : $packaged_original (package $(pkg_owner "$packaged_original"))
$(diff -u "$packaged_original" "$file" 2>/dev/null | head -12 | truncate_text_stdin 500)" \
                action="Confirm the override was made deliberately - compare it with the packaged unit above. Do NOT quarantine it without checking: removing the override does not remove the service, and quarantining a legitimate one stops it."
            continue
        fi

        # ---- executable targets --------------------------------
        while IFS= read -r execline; do

            [[ -n "$execline" ]] || continue
            unit_exec_binary_var "$execline"
            bin="$UNIT_EXEC_BIN"
            [[ -n "$bin" && "$bin" == /* ]] || continue

            # missing / removed executable
            if [[ ! -e "$bin" ]]; then

                if (( unit_owned )); then
                    # Distributions ship units for optional
                    # components that are not always installed.
                    add_finding INFO \
                        "Packaged systemd unit references a binary that is not installed" \
                        id="unit-missing-exec-pkg:$unit:$bin" \
                        path="$file" \
                        evidence="$bin is absent; unit is owned by $(pkg_owner "$file")." \
                        action="Normal for optional components. No action unless the unit is expected to run."
                    continue
                fi

                findings=$(( findings + 1 ))
                add_finding HIGH \
                    "Locally created systemd unit points at an executable that does not exist" \
                    id="unit-missing-exec:$unit:$bin" \
                reasons="The unit is owned by no package and its ExecStart target does not exist
This is what a quarantined implant leaves behind: the binary removed, the persistence not
It is also what an incomplete package removal leaves behind" \
                    path="$file" \
                    process="ExecStart target: $bin | state=$(unit_active_state "$unit")" \
                    evidence="The unit is owned by no package and references $bin, which is absent from disk. This is what a quarantined implant leaves behind when the binary was removed and the persistence was not." \
                    action="Keep the unit file as evidence and record it in the incident report before removing it."
                continue
            fi

            # executable in a volatile directory
            if is_volatile_path "$bin"; then
                findings=$(( findings + 1 ))
                add_finding CRITICAL \
                    "Systemd unit executes a binary from a temporary or user writable directory" \
                    id="unit-volatile-exec:$unit:$bin" \
                reasons="ExecStart runs a binary from a temporary directory
No packaged service ever executes from /tmp, /var/tmp or /dev/shm" \
                    path="$file" \
                    process="ExecStart target: $bin | state=$(unit_active_state "$unit")" \
                    evidence="$bin sha256=$(file_sha256 "$bin") mtime=$(file_mtime_human "$bin") owner=$(stat -c '%U:%G' "$bin" 2>/dev/null)" \
                    action="Preserve both the unit and the binary, then isolate the host. No packaged service runs from these directories."
                continue
            fi

            # executable in a home directory
            if is_user_home_path "$bin"; then
                findings=$(( findings + 1 ))
                add_finding HIGH \
                    "Systemd unit executes a binary from a home directory" \
                    id="unit-home-exec:$unit:$bin" \
                reasons="ExecStart runs a binary from a home directory
Whoever can write that directory controls whatever user the unit runs as" \
                    path="$file" \
                    process="ExecStart target: $bin | state=$(unit_active_state "$unit")" \
                    evidence="$bin owner=$(stat -c '%U:%G' "$bin" 2>/dev/null) mode=$(stat -c '%a' "$bin" 2>/dev/null) sha256=$(file_sha256 "$bin")" \
                    action="Legitimate for some application deployments, and a standard persistence location. Confirm with the application owner; whoever can write that directory controls whatever user the unit runs as."
                continue
            fi

            # executable writable by non root
            if path_is_writable_by_others "$bin"; then
                findings=$(( findings + 1 ))
                add_finding HIGH \
                    "Systemd unit executes a binary that is writable by a non-root account" \
                    id="unit-writable-exec:$unit:$bin" \
                reasons="The ExecStart target is writable by a non-root account
Any account that can write it gains that unit's privileges at the next start" \
                    path="$file" \
                    process="ExecStart target: $bin | state=$(unit_active_state "$unit")" \
                    evidence="$bin mode=$(stat -c '%a' "$bin" 2>/dev/null) owner=$(stat -c '%U:%G' "$bin" 2>/dev/null)" \
                    action="Any account that can write this file gains root at the next service start. Tighten to root:root 0755 or stricter after confirming the owning application."
            fi

            # unpackaged binary in a system directory
            case "$bin" in
                /usr/bin/*|/usr/sbin/*|/bin/*|/sbin/*)
                    if ! is_pkg_owned "$bin" && ! is_itm_binary "$bin"; then
                        findings=$(( findings + 1 ))
                        add_finding HIGH \
                            "Systemd unit executes an unpackaged binary placed in a system directory" \
                            id="unit-unowned-exec:$unit:$bin" \
                reasons="ExecStart runs a binary in a system directory that no package owns
This is the pattern of the fake units seen on this estate: a real looking unit plus a dropped binary
Locally compiled software looks identical, so the question is whether anyone can account for it" \
                            path="$file" \
                            process="ExecStart target: $bin | state=$(unit_active_state "$unit")" \
                            evidence="$bin is owned by no package. sha256=$(file_sha256 "$bin") mtime=$(file_mtime_human "$bin")
Unit mtime=$(file_mtime_human "$file") package=$(pkg_owner "$file")
$(unit_exec_lines "$file" | head -3)" \
                            action="This is the exact pattern of the persistence found previously on this estate: a fake unit plus a binary dropped into /usr/bin. Preserve both, verify with the application owner, then isolate if unexplained."
                    fi
                    ;;
            esac

            # suspicious command content
            #
            # Only for units no package owns: distributions do
            # legitimately call chattr, eval and friends from
            # their own units.
            if (( unit_owned == 0 )) && printf '%s' "$execline" | grep -qE "$SYSTEMD_SUSPICIOUS_EXEC"; then
                findings=$(( findings + 1 ))
                add_finding CRITICAL \
                    "Systemd unit runs a network or encoding command directly from Exec=" \
                    id="unit-suspicious-exec:$unit" \
                reasons="The unit is owned by no package AND its Exec line runs a network or encoding command
Downloaders and reverse shells are commonly wired straight into Exec=" \
                    path="$file" \
                    process="state=$(unit_active_state "$unit")" \
                    evidence="Exec line: $(truncate_text "$execline" 300)" \
                    action="Downloaders and reverse shells are commonly wired straight into Exec=. Preserve the unit, review the Nginx and auth logs around the unit mtime ($(file_mtime_human "$file")), and isolate."
            fi

        done < <(unit_exec_lines "$file")

        # ---- unmanaged units in /etc/systemd/system ------------
        if [[ "$dir" == "/etc/systemd/system" ]]; then

            local unit_mtime
            unit_mtime="$(path_mtime "$file")"
            [[ "$unit_mtime" =~ ^[0-9]+$ ]] || unit_mtime=0

            if (( unit_mtime > recent_cutoff )) && ! is_pkg_owned "$file"; then
                recent_unmanaged=$(( recent_unmanaged + 1 ))
                add_finding MEDIUM \
                    "Locally created systemd unit added or modified in the last ${SYSTEMD_RECENT_DAYS} days" \
                    id="unit-recent-local:$unit" \
                reasons="A unit not owned by any package was created or modified recently
Local units are normal for application deployments: this is a change-review item, not a detection" \
                    path="$file" \
                    process="state=$(unit_active_state "$unit")" \
                    evidence="mtime=$(file_mtime_human "$file")
$(unit_exec_lines "$file" | head -3)" \
                    action="Match against a change ticket. Local units are legitimate for application deployments, so this is a review item, not a detection."
            fi
        fi

        # ---- name masquerading as a distribution unit ----------
        case "$unit" in
            systemd-*|dbus-*|kernel-*|kworker*)
                if ! is_pkg_owned "$file"; then
                    findings=$(( findings + 1 ))
                    add_finding HIGH \
                        "Unit uses a distribution style name but is owned by no package" \
                        id="unit-masquerade:$unit" \
                reasons="The unit name follows a distribution naming convention but belongs to no package
Name imitation is used to survive a quick read of systemctl output" \
                        path="$file" \
                        process="state=$(unit_active_state "$unit")" \
                        evidence="Unit $unit imitates a system component naming convention. mtime=$(file_mtime_human "$file")
$(unit_exec_lines "$file" | head -3)" \
                        action="Verify against the distribution package list. Name imitation is used to survive a quick eyeball of systemctl output."
                fi
                ;;
        esac

    done < "$ITM_RUN_TMP/unit_files.txt"

    audit_log INFO "examined $total systemd unit files"

    (( findings == 0 )) && add_pass "no malicious persistence pattern in $total systemd unit files"
    (( recent_unmanaged == 0 )) && add_pass "no locally created unit changed in the last ${SYSTEMD_RECENT_DAYS} days"
}

# ------------------------------------------------------------
# Failed and transient units
# ------------------------------------------------------------

check_runtime_units() {

    have_cmd systemctl || {
        add_skip "systemctl not available - runtime unit state not evaluated"
        return 0
    }

    local failed transient

    failed="$(run_timeout "$CMD_TIMEOUT" systemctl list-units --state=failed --no-legend --no-pager 2>/dev/null \
        | awk '{print $1}' | head -20 | tr '\n' ' ')"

    if [[ -n "$failed" ]]; then
        add_finding LOW \
            "Failed systemd units present" \
            id="failed-units" \
            evidence="Failed: $failed" \
            action="A crash looping implant and a genuinely broken service look the same here. Check each with: systemctl status <unit> --no-pager"
    else
        add_pass "no failed systemd unit"
    fi

    # Units running from /run are transient: created at runtime
    # and gone after reboot.
    transient="$(find /run/systemd/system -maxdepth 1 -name '*.service' -type f 2>/dev/null | head -10 | tr '\n' ' ')"

    if [[ -n "$transient" ]]; then
        add_finding MEDIUM \
            "Transient systemd units present in /run/systemd/system" \
            id="transient-units" \
            path="/run/systemd/system" \
            evidence="$transient" \
            action="Transient units disappear on reboot and leave no trace in /etc. Capture them now: systemctl cat <unit>"
    else
        add_pass "no transient unit in /run/systemd/system"
    fi
}

# ============================================================
# ENTRY POINT
# ============================================================

run_audit_systemd() {

    module_begin "systemd" "Systemd Persistence"

    add_pass "ITM unit allowlist: $ITM_OWN_UNITS"

    check_unit_files
    check_runtime_units

    module_end
}

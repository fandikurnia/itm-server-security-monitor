#!/usr/bin/env bash
# shellcheck shell=bash

# ============================================================
# ITM Server Security Monitor
# Post-Compromise Audit - Module E: command integrity
#
# Read only. No binary is replaced, moved or deleted, even when
# it is proven to be a wrapper: the wrapper is evidence.
#
# Background: this estate has previously been hit by wrapper
# binaries dropped into /usr/local/bin (ps, lsof, netstat) that
# filtered specific PIDs, ports, addresses and process names
# out of their own output.
#
# /usr/local/bin and /usr/local/sbin come before /usr/bin in
# the default PATH on both supported distribution families, so
# a file placed there silently wins over the packaged tool.
# ============================================================

SHADOW_DIRS="/usr/local/bin /usr/local/sbin"
SYSTEM_BIN_DIRS="/usr/bin /usr/sbin /bin /sbin"

# Output filtering primitives, as they appear inside a wrapper.
WRAPPER_FILTER_PATTERN='grep[[:space:]]+-v|grep[[:space:]]+-[a-zA-Z]*v|egrep[[:space:]]+-v|sed[[:space:]]+-E?[[:space:]]*.?/.*/d|awk[[:space:]]+.*!~|--exclude|\bexcept\b'

command_system_twin() {
    local name="$1" d
    for d in $SYSTEM_BIN_DIRS; do
        if [[ -x "$d/$name" ]]; then
            printf '%s' "$d/$name"
            return 0
        fi
    done
    return 1
}

binary_is_script() {
    local path="$1" head
    [[ -r "$path" ]] || return 1
    head="$(head -c 2 "$path" 2>/dev/null)"
    [[ "$head" == "#!" ]]
}

# ------------------------------------------------------------
# Shadowed forensic commands
# ------------------------------------------------------------

check_command_resolution() {

    local name resolved twin shadowed=0 unowned=0 checked=0
    local sev evidence

    for name in $AUDIT_COMMANDS; do

        resolved="$(command -v "$name" 2>/dev/null || true)"

        if [[ -z "$resolved" ]]; then
            # Not every host has every tool. That is not a finding.
            continue
        fi

        # Resolve through symlinks so /bin -> /usr/bin merges do
        # not read as anomalies.
        resolved="$(readlink -f "$resolved" 2>/dev/null || printf '%s' "$resolved")"
        checked=$(( checked + 1 ))

        # ---- shadow in /usr/local ------------------------------
        case "$resolved" in
            /usr/local/bin/*|/usr/local/sbin/*)

                if is_itm_binary "$resolved"; then
                    continue
                fi

                twin="$(command_system_twin "$name" || true)"
                shadowed=$(( shadowed + 1 ))

                if [[ -n "$twin" ]]; then
                    sev=CRITICAL
                    evidence="'$name' resolves to $resolved while the packaged tool exists at $twin.
shadow : sha256=$(file_sha256 "$resolved") mtime=$(file_mtime_human "$resolved") package=$(pkg_owner "$resolved") script=$( binary_is_script "$resolved" && echo yes || echo no )
system : sha256=$(file_sha256 "$twin") package=$(pkg_owner "$twin")"
                else
                    sev=HIGH
                    evidence="'$name' resolves to $resolved and no packaged equivalent was found.
sha256=$(file_sha256 "$resolved") mtime=$(file_mtime_human "$resolved") package=$(pkg_owner "$resolved")"
                fi

                if binary_is_script "$resolved" \
                    && grep -qE "$WRAPPER_FILTER_PATTERN" "$resolved" 2>/dev/null; then
                    sev=CRITICAL
                    evidence+="
Filtering logic found inside the script: $(grep -nEo "$WRAPPER_FILTER_PATTERN" "$resolved" 2>/dev/null | head -5 | tr '\n' ' ')"
                fi

                add_finding "$sev" \
                    "Forensic command '$name' is shadowed by a binary in /usr/local" \
                    id="shadowed-command:$name:$resolved" \
                    path="$resolved" \
                    evidence="$evidence" \
                    action="Do not delete the wrapper: it is evidence. Compare output side by side, for example '$twin' versus '$resolved'. Until this is resolved, treat all output from '$name' on this host as unreliable and use /proc directly."
                continue
                ;;
        esac

        # ---- unpackaged system tool ----------------------------
        if ! is_pkg_owned "$resolved" && ! is_itm_binary "$resolved"; then
            unowned=$(( unowned + 1 ))
            add_finding HIGH \
                "Forensic command '$name' resolves to a binary owned by no package" \
                id="unowned-command:$name:$resolved" \
                path="$resolved" \
                evidence="sha256=$(file_sha256 "$resolved") mtime=$(file_mtime_human "$resolved") script=$( binary_is_script "$resolved" && echo yes || echo no )" \
                action="Reinstall the owning package on a known good host and compare hashes. Preserve the current file first."
        fi

    done

    audit_log INFO "verified resolution of $checked forensic commands"

    (( shadowed == 0 )) && add_pass "no forensic command shadowed from /usr/local ($checked commands verified)"
    (( unowned  == 0 )) && add_pass "all resolved forensic commands are owned by installed packages"
}

# ------------------------------------------------------------
# Any system command name present in /usr/local
#
# Catches wrappers that are not currently first in PATH, and
# wrappers for commands not in the audited list.
# ------------------------------------------------------------

check_shadow_directories() {

    local dir file name twin found=0

    for dir in $SHADOW_DIRS; do

        [[ -d "$dir" ]] || continue

        while IFS= read -r file; do

            [[ -n "$file" ]] || continue
            is_itm_binary "$file" && continue

            name="$(basename "$file")"
            twin="$(command_system_twin "$name" || true)"
            [[ -n "$twin" ]] || continue

            found=$(( found + 1 ))

            # A duplicate of a forensic tool is the incident
            # pattern. A duplicate of any other packaged command
            # is usually a local install, so it is reported for
            # review rather than as a detection.
            local dsev=MEDIUM
            case " $AUDIT_COMMANDS " in
                *" $name "*) dsev=HIGH ;;
            esac

            add_finding "$dsev" \
                "System command name duplicated in $dir" \
                id="shadow-file:$file" \
                path="$file" \
                evidence="$file duplicates the packaged command $twin.
local  : sha256=$(file_sha256 "$file") mtime=$(file_mtime_human "$file") owner=$(stat -c '%U:%G' "$file" 2>/dev/null) mode=$(stat -c '%a' "$file" 2>/dev/null)
system : sha256=$(file_sha256 "$twin") package=$(pkg_owner "$twin")" \
                action="Confirm with the platform owner whether this override is deliberate. If it is, allowlist it in ITM_OWN_BINARIES; if it is not, preserve it for analysis."

        done < <(find "$dir" -maxdepth 1 -type f -perm -u+x 2>/dev/null | sort)
    done

    (( found == 0 )) && add_pass "no packaged command name duplicated in $SHADOW_DIRS"
}

# ------------------------------------------------------------
# Shell level hiding
# ------------------------------------------------------------

check_shell_aliases() {

    local file found=0 hits
    local files=(/etc/bash.bashrc /etc/bashrc /etc/profile /root/.bashrc /root/.bash_profile /root/.profile)
    local f

    while IFS= read -r f; do
        [[ -n "$f" ]] && files+=("$f")
    done < <(find /etc/profile.d -maxdepth 1 -name '*.sh' -type f 2>/dev/null)

    for file in "${files[@]}"; do

        [[ -r "$file" ]] || continue

        # An alias or function that wraps a forensic command
        # changes what an administrator sees at the prompt while
        # leaving the binary untouched.
        hits="$(grep -nE "^[[:space:]]*(alias[[:space:]]+)?(ps|ss|netstat|lsof|top|last|who|w|dmesg|journalctl|find|ls)[[:space:]]*(=|\(\))" "$file" 2>/dev/null | head -5)"

        [[ -n "$hits" ]] || continue

        found=$(( found + 1 ))

        add_finding MEDIUM \
            "Shell startup file redefines a forensic command" \
            id="shell-alias:$file" \
            path="$file" \
            evidence="$(truncate_text "$hits" 400)" \
            action="Review each definition. An alias or shell function is the cheapest way to hide activity from an interactive administrator without touching a single binary."
    done

    (( found == 0 )) && add_pass "no shell startup file redefines a forensic command"
}

# ------------------------------------------------------------
# History tampering
# ------------------------------------------------------------

check_history_integrity() {

    local hf found=0 target

    for hf in /root/.bash_history /root/.ash_history; do

        [[ -e "$hf" ]] || continue

        # A history file symlinked to /dev/null is a deliberate
        # audit-trail suppression, not a user preference.
        if [[ -L "$hf" ]]; then
            target="$(readlink -f "$hf" 2>/dev/null)"
            if [[ "$target" == "/dev/null" ]]; then
                found=1
                add_finding HIGH \
                    "Root shell history redirected to /dev/null" \
                    id="history-devnull:$hf" \
                    path="$hf" \
                    evidence="$hf is a symlink to $target" \
                    action="Restore a real history file and investigate who created the symlink. ITM's command monitor still records commands to the journal (tag itm-command-monitor), which is a better source here."
            fi
            continue
        fi

        if [[ ! -s "$hf" ]] && [[ -f "$hf" ]]; then
            found=1
            add_finding LOW \
                "Root shell history file is empty" \
                id="history-empty:$hf" \
                path="$hf" \
                evidence="size=0 mtime=$(file_mtime_human "$hf")" \
                action="Expected on a fresh host, suspicious on a long lived one. Cross check against: journalctl -t itm-command-monitor"
        fi
    done

    (( found == 0 )) && add_pass "root shell history shows no sign of suppression"
}

# ============================================================
# ENTRY POINT
# ============================================================

run_audit_command() {

    module_begin "command" "Command Integrity"

    # Resolve package ownership for every path this module will
    # ask about, in one batched query.
    local prefetch=() name resolved dir file
    for name in $AUDIT_COMMANDS; do
        resolved="$(command -v "$name" 2>/dev/null || true)"
        [[ -n "$resolved" ]] || continue
        prefetch+=( "$(readlink -f "$resolved" 2>/dev/null || printf '%s' "$resolved")" )
        for dir in $SYSTEM_BIN_DIRS; do
            [[ -x "$dir/$name" ]] && prefetch+=("$dir/$name")
        done
    done
    for dir in $SHADOW_DIRS; do
        [[ -d "$dir" ]] || continue
        while IFS= read -r file; do
            [[ -n "$file" ]] && prefetch+=("$file")
        done < <(find "$dir" -maxdepth 1 -type f -perm -u+x 2>/dev/null)
    done
    (( ${#prefetch[@]} > 0 )) && pkg_owner_prefetch "${prefetch[@]}"

    check_command_resolution
    check_shadow_directories
    check_shell_aliases
    check_history_integrity

    module_end
}

#!/usr/bin/env bash
# shellcheck shell=bash

# ============================================================
# ITM Server Security Monitor
# Post-Compromise Audit - Module C: PAM integrity
#
# Read only. No PAM file is ever modified: a bad edit to
# /etc/pam.d locks every account out of the system, including
# the console.
#
# Background: this estate has previously been hit by a PAM
# credential stealer implemented as a pam_exec.so hook in
# /etc/pam.d/common-auth that piped the cleartext password to
# a helper script, which exfiltrated it with curl.
#
# ITM installs its own pam_exec hook (the SSH login alert). It
# is allowlisted through PAM_EXEC_ALLOW so that the tool does
# not report itself, and the allowlist is printed in the report
# so the exemption stays visible.
# ============================================================

# Overridable so the detection logic can be exercised against a
# fixture without touching the live PAM stack.
PAM_DIR="${PAM_DIR:-/etc/pam.d}"

PAM_EXFIL_PATTERN='curl|wget|nc[[:space:]]|ncat|socat|/dev/tcp/|telnet|openssl[[:space:]]+s_client|base64|xxd|sendmail|mail[[:space:]]+-s|python[0-9]?|perl|ruby|php|ftp|scp|rsync'

pam_exec_is_allowed() {
    local target="$1" allowed
    for allowed in $PAM_EXEC_ALLOW; do
        [[ "$target" == "$allowed" ]] && return 0
    done
    return 1
}

# Strip a bracketed control field so the remaining fields can be
# split on whitespace: "auth [success=1 default=ignore] pam_x.so"
pam_strip_control() {
    printf '%s' "$1" | sed -E 's/\[[^]]*\]/CONTROL/'
}

# ------------------------------------------------------------
# Inspect the helper a pam_exec hook calls
# ------------------------------------------------------------

pam_inspect_helper() {

    local target="$1" hits=""

    [[ -n "$target" && -e "$target" ]] || {
        printf 'helper not present on disk'
        return 0
    }

    if file "$target" 2>/dev/null | grep -qi 'text\|script'; then
        hits="$(grep -nEo "$PAM_EXFIL_PATTERN" "$target" 2>/dev/null | sort -u | head -8 | tr '\n' ' ')"
    else
        hits="$(strings -n 6 "$target" 2>/dev/null | grep -Eo "$PAM_EXFIL_PATTERN" | sort -u | head -8 | tr '\n' ' ')"
    fi

    printf 'owner=%s mode=%s package=%s sha256=%s mtime=%s exfil_indicators=%s' \
        "$(stat -c '%U:%G' "$target" 2>/dev/null || echo unknown)" \
        "$(stat -c '%a' "$target" 2>/dev/null || echo unknown)" \
        "$(pkg_owner "$target")" \
        "$(file_sha256 "$target")" \
        "$(file_mtime_human "$target")" \
        "${hits:-none}"
}

pam_helper_has_exfil() {
    local target="$1"
    [[ -r "$target" ]] || return 1
    if grep -qE "$PAM_EXFIL_PATTERN" "$target" 2>/dev/null; then
        return 0
    fi
    strings -n 6 "$target" 2>/dev/null | grep -qE "$PAM_EXFIL_PATTERN" && return 0
    return 1
}

# ------------------------------------------------------------
# pam_exec hooks
# ------------------------------------------------------------

check_pam_exec() {

    local file line clean type_field module_field
    local target opt has_expose has_authtok fields i
    local found=0 allowed_seen=0

    [[ -d "$PAM_DIR" ]] || {
        add_skip "$PAM_DIR does not exist - PAM audit skipped"
        return 0
    }

    while IFS= read -r file; do

        [[ -r "$file" ]] || continue

        while IFS= read -r line; do

            # Comments and blank lines are inert.
            case "${line#"${line%%[![:space:]]*}"}" in
                \#*|"") continue ;;
            esac

            [[ "$line" == *pam_exec.so* ]] || continue

            clean="$(pam_strip_control "$line")"
            # shellcheck disable=SC2206
            fields=( $clean )
            type_field="${fields[0]:-unknown}"

            has_expose=0
            has_authtok=0
            target=""

            # The first argument after pam_exec.so that looks like
            # a path is the program being executed.
            module_field=0
            for (( i = 0; i < ${#fields[@]}; i++ )); do
                opt="${fields[$i]}"
                [[ "$opt" == *pam_exec.so ]] && { module_field=1; continue; }
                (( module_field )) || continue
                case "$opt" in
                    expose_authtok) has_expose=1 ;;
                    /*)             [[ -z "$target" ]] && target="$opt" ;;
                esac
            done

            # pam_exec passes the authentication token on stdin
            # when expose_authtok is set. In the auth stack that
            # is a cleartext password handoff.
            if (( has_expose )); then
                has_authtok=1
            fi

            found=$(( found + 1 ))

            if pam_exec_is_allowed "$target" && (( has_authtok == 0 )); then
                allowed_seen=$(( allowed_seen + 1 ))
                add_pass "known ITM pam_exec hook: $file -> $target"
                continue
            fi

            # ---- credential stealer pattern --------------------
            if (( has_authtok )); then
                add_finding CRITICAL \
                    "PAM credential stealer pattern: active pam_exec.so with expose_authtok" \
                    id="pam-expose-authtok:$file:$target" \
                    path="$file" \
                    process="pam stack: $type_field -> ${target:-<no path argument>}" \
                    evidence="Line: $(truncate_text "$line" 200)
Helper: $(pam_inspect_helper "$target")
expose_authtok makes PAM write the cleartext authentication token to this program's stdin." \
                    action="ISOLATE THE HOST AND PRESERVE EVIDENCE. Do not edit PAM over SSH without an open console session. Rotate every credential that authenticated on this host since the helper's mtime. Treat host integrity as UNTRUSTED."
                continue
            fi

            # ---- pam_exec in the auth stack --------------------
            if [[ "$type_field" == "auth" || "$type_field" == "password" ]]; then
                add_finding CRITICAL \
                    "Unrecognised pam_exec.so hook in the ${type_field} stack" \
                    id="pam-auth-exec:$file:$target" \
                    path="$file" \
                    process="pam stack: $type_field -> ${target:-<no path argument>}" \
                    evidence="Line: $(truncate_text "$line" 200)
Helper: $(pam_inspect_helper "$target")
Any program in the auth or password stack observes authentication attempts." \
                    action="Preserve the helper and the PAM file, then isolate the host. Do not delete before the binary and its timestamps are captured."
                continue
            fi

            # ---- session hooks --------------------------------
            local sev=HIGH
            local why="Unrecognised program executed by PAM on session events."

            if pam_helper_has_exfil "$target"; then
                sev=CRITICAL
                why="The helper contains network or encoding commands typical of credential exfiltration."
            fi

            add_finding "$sev" \
                "Unrecognised pam_exec.so hook in the ${type_field} stack" \
                id="pam-session-exec:$file:$target" \
                path="$file" \
                process="pam stack: $type_field -> ${target:-<no path argument>}" \
                evidence="Line: $(truncate_text "$line" 200)
Helper: $(pam_inspect_helper "$target")
$why" \
                action="Confirm this hook was installed deliberately. If it is expected, add ${target} to PAM_EXEC_ALLOW in ${ITM_AUDIT_CONF}. If it is not, preserve evidence and isolate."

        done < "$file"

    done < <(find "$PAM_DIR" -maxdepth 1 -type f 2>/dev/null | sort)

    if (( found == 0 )); then
        add_pass "no pam_exec.so hook present in $PAM_DIR"
    elif (( found == allowed_seen )); then
        add_pass "all pam_exec.so hooks are the expected ITM hooks (allowlist: $PAM_EXEC_ALLOW)"
    fi
}

# ------------------------------------------------------------
# Dormant pam_exec entries
#
# A commented out pam_exec line is inert TODAY. It is not
# reassurance:
#
#   - it is proof that the hook was configured at some point
#   - the payload it called is usually still on disk
#   - re-arming it is one character of editing
#
# Real incident on this estate (2026-08):
#
#   #auth optional pam_exec.so quiet expose_authtok \
#        /usr/bin/x86_65-linux-gnu-op
#
# The line was commented, every "is pam_exec active?" check
# passed, and the credential stealer binary was still sitting in
# /usr/bin waiting to be re-enabled.
#
# A commented hook whose payload still exists is therefore
# CRITICAL, not INFO.
# ------------------------------------------------------------

check_pam_exec_dormant() {

    local file line stripped clean fields i opt target
    local found=0 payload_present=0

    [[ -d "$PAM_DIR" ]] || return 0

    while IFS= read -r file; do

        [[ -r "$file" ]] || continue

        while IFS= read -r line; do

            stripped="${line#"${line%%[![:space:]]*}"}"

            # Only commented lines: active ones are handled by
            # check_pam_exec.
            [[ "$stripped" == \#* ]] || continue
            [[ "$stripped" == *pam_exec.so* ]] || continue

            # Strip the comment marker(s) and re-parse as PAM.
            clean="${stripped#"${stripped%%[!#]*}"}"
            clean="$(pam_strip_control "$clean")"
            # shellcheck disable=SC2206
            fields=( $clean )

            target=""
            local has_expose=0 module_seen=0
            for (( i = 0; i < ${#fields[@]}; i++ )); do
                opt="${fields[$i]}"
                [[ "$opt" == *pam_exec.so ]] && { module_seen=1; continue; }
                (( module_seen )) || continue
                case "$opt" in
                    expose_authtok) has_expose=1 ;;
                    /*)             [[ -z "$target" ]] && target="$opt" ;;
                esac
            done

            found=$(( found + 1 ))

            local sev evidence action reasons confidence

            if [[ -n "$target" && -e "$target" ]]; then

                payload_present=1
                sev=CRITICAL
                confidence=95
                reasons="A pam_exec hook was configured in the PAM stack and then commented out
The program it called is STILL PRESENT on disk
Re-enabling the hook requires deleting one '#'"
                (( has_expose )) && reasons+="
The hook used expose_authtok: it received cleartext authentication tokens"

                evidence="Line: $(truncate_text "$stripped" 200)
Payload: $(pam_inspect_helper "$target")
The entry is inert right now. The capability is not: the payload is on disk and the configuration to invoke it was there long enough to be commented out rather than removed."

                action="TREAT AS AN ACTIVE COMPROMISE. Do not delete the payload before capturing it: copy it and its metadata to /root/forensic and record the SHA256. Rotate every credential that authenticated on this host since the payload's mtime. Search for the persistence that re-installs it (cron, systemd, other PAM files, package hooks). Set HOST_TRUST_STATUS=\"UNTRUSTED\" in ${ITM_AUDIT_CONF}. This host needs a rebuild, not a cleanup."

            elif [[ -n "$target" ]]; then

                sev=HIGH
                confidence=80
                reasons="A pam_exec hook was configured and later commented out
The program it called is no longer on disk
This is residue of a previous compromise or of an incident response"
                (( has_expose )) && reasons+="
The hook used expose_authtok: credentials were exposed to it while it was active"

                evidence="Line: $(truncate_text "$stripped" 200)
Payload ${target} is absent from disk."

                action="Confirm this is the remnant of a cleanup you performed. If it is not, the host was compromised and the payload has been removed by someone else. Either way the credentials that authenticated while the hook was live must be considered exposed, and the host trust status must reflect the incident."

            else

                sev=MEDIUM
                confidence=60
                reasons="A commented pam_exec entry exists with no resolvable program path"
                evidence="Line: $(truncate_text "$stripped" 200)"
                action="Review the PAM file history to establish what this hook called."
            fi

            add_finding "$sev" \
                "Dormant pam_exec hook in the PAM stack (commented, payload $( [[ -n "$target" && -e "$target" ]] && echo "STILL PRESENT" || echo "absent" ))" \
                id="pam-dormant-exec:$file:$target" \
                path="$file" \
                hash="$( [[ -n "$target" && -f "$target" ]] && file_sha256 "$target" )" \
                confidence="$confidence" \
                reasons="$reasons" \
                process="pam file: $file -> ${target:-<no path argument>}" \
                evidence="$evidence" \
                action="$action"

            if [[ -n "$target" && -f "$target" ]]; then
                evidence_snapshot "$target" \
                    "$(printf '%s|pam-dormant|%s' "$ITM_HOSTNAME" "$target" | sha256sum | cut -c1-32)" \
                    "dormant pam_exec payload referenced from $file" >/dev/null
            fi

        done < "$file"

    done < <(find "$PAM_DIR" -maxdepth 1 -type f 2>/dev/null | sort)

    if (( found == 0 )); then
        add_pass "no commented or dormant pam_exec entry in $PAM_DIR"
    elif (( payload_present == 0 )); then
        add_pass "dormant pam_exec entries found, none with a payload still on disk"
    fi
}

# ------------------------------------------------------------
# Modules loaded from outside the PAM module directory
# ------------------------------------------------------------

check_pam_module_paths() {

    local file line clean fields mod found=0

    [[ -d "$PAM_DIR" ]] || return 0

    while IFS= read -r file; do
        [[ -r "$file" ]] || continue

        while IFS= read -r line; do

            case "${line#"${line%%[![:space:]]*}"}" in
                \#*|"") continue ;;
            esac

            clean="$(pam_strip_control "$line")"
            # shellcheck disable=SC2206
            fields=( $clean )

            for mod in ${fields[@]+"${fields[@]}"}; do
                [[ "$mod" == /*.so ]] || continue

                # A PAM module referenced by absolute path bypasses
                # the distribution's module directory entirely.
                case "$mod" in
                    /lib/security/*|/lib64/security/*|/usr/lib/security/*|/usr/lib64/security/*|/lib/*/security/*|/usr/lib/*/security/*)
                        continue ;;
                esac

                found=1
                add_finding CRITICAL \
                    "PAM module loaded from outside the system module directory" \
                    id="pam-external-module:$file:$mod" \
                    path="$file" \
                    evidence="Line: $(truncate_text "$line" 200)
Module: $mod package=$(pkg_owner "$mod") sha256=$(file_sha256 "$mod") mtime=$(file_mtime_human "$mod")" \
                    action="Preserve the .so file for analysis and isolate the host. A PAM module runs inside every authenticating process."
            done

        done < "$file"
    done < <(find "$PAM_DIR" -maxdepth 1 -type f 2>/dev/null | sort)

    (( found == 0 )) && add_pass "all PAM modules load from the distribution module directory"
}

# ------------------------------------------------------------
# Integrity of the PAM shared objects themselves
# ------------------------------------------------------------

check_pam_binaries() {

    local dir so unowned=0 checked=0 dirs=()

    for dir in /lib/security /lib64/security /usr/lib/security /usr/lib64/security \
               /lib/x86_64-linux-gnu/security /usr/lib/x86_64-linux-gnu/security \
               /lib/aarch64-linux-gnu/security /usr/lib/aarch64-linux-gnu/security; do
        [[ -d "$dir" ]] && dirs+=("$dir")
    done

    if (( ${#dirs[@]} == 0 )); then
        add_skip "no PAM module directory found"
        return 0
    fi

    local prefetch=()
    while IFS= read -r so; do
        [[ -n "$so" ]] && prefetch+=("$so")
    done < <(find "${dirs[@]}" -maxdepth 1 -name '*.so' -type f 2>/dev/null)
    (( ${#prefetch[@]} > 0 )) && pkg_owner_prefetch "${prefetch[@]}"

    while IFS= read -r so; do

        [[ -n "$so" ]] || continue
        checked=$(( checked + 1 ))

        if ! is_pkg_owned "$so"; then
            unowned=$(( unowned + 1 ))
            add_finding CRITICAL \
                "PAM module present in the system directory but owned by no package" \
                id="pam-unowned-module:$so" \
                path="$so" \
                evidence="package=NONE sha256=$(file_sha256 "$so") mtime=$(file_mtime_human "$so") size=$(stat -c '%s' "$so" 2>/dev/null)
Exfil indicators: $(strings -n 6 "$so" 2>/dev/null | grep -Eo "$PAM_EXFIL_PATTERN" | sort -u | head -5 | tr '\n' ' ')" \
                action="Preserve the module and compare with the distribution package. An unpackaged PAM module is a direct credential interception capability."
        fi

    done < <(find "${dirs[@]}" -maxdepth 1 -name '*.so' -type f 2>/dev/null | sort)

    audit_log INFO "checked $checked PAM modules"

    (( unowned == 0 )) && add_pass "all $checked PAM modules are owned by installed packages"

    # pam_exec.so itself is the module used by the known attack.
    local pe
    while IFS= read -r pe; do
        [[ -n "$pe" ]] || continue
        add_pass "pam_exec.so: package=$(pkg_owner "$pe") sha256=$(file_sha256 "$pe")"
    done < <(find "${dirs[@]}" -maxdepth 1 -name 'pam_exec.so' -type f 2>/dev/null)
}

# ------------------------------------------------------------
# Recent changes to the PAM stack
# ------------------------------------------------------------

check_pam_changes() {

    local recent count=0 f

    recent="$(find "$PAM_DIR" -maxdepth 1 -type f -mtime -"${SYSTEMD_RECENT_DAYS}" 2>/dev/null | sort)"

    [[ -n "$recent" ]] || {
        add_pass "no PAM file modified in the last ${SYSTEMD_RECENT_DAYS} days"
        return 0
    }

    local list=""
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        count=$(( count + 1 ))
        list+="$f (mtime $(file_mtime_human "$f"))
"
    done <<< "$recent"

    add_finding LOW \
        "PAM configuration changed within the last ${SYSTEMD_RECENT_DAYS} days" \
        id="pam-recent-change" \
        path="$PAM_DIR" \
        evidence="$count file(s):
$list" \
        action="Correlate each change with a change ticket or a package upgrade. The ITM installer appends its SSH alert hook to /etc/pam.d/sshd and keeps a backup named sshd.before-itm-security-monitor.*"
}

# ============================================================
# ENTRY POINT
# ============================================================

run_audit_pam() {

    module_begin "pam" "PAM Integrity"

    if ! is_root; then
        add_skip "not running as root - some PAM files may be unreadable"
    fi

    check_pam_exec
    check_pam_exec_dormant
    check_pam_module_paths
    check_pam_binaries
    check_pam_changes

    module_end
}

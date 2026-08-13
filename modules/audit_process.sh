#!/usr/bin/env bash
# shellcheck shell=bash

# ============================================================
# ITM Server Security Monitor
# Post-Compromise Audit - Module A: process integrity
#
# Read only. No process is ever signalled.
#
# The process list is built from /proc directly instead of from
# ps(1), because ps is one of the binaries an attacker replaces
# with a filtering wrapper. The ps output is then compared back
# against /proc: a PID that exists in /proc but is invisible to
# ps is itself a CRITICAL finding.
# ============================================================

PROC_STANDARD_DIRS="/bin /sbin /usr/bin /usr/sbin /usr/libexec /usr/lib /lib /lib64 /usr/lib64 /opt /snap /usr/share /usr/local/lib"

# ------------------------------------------------------------
# Collect the forensic context for one PID.
# ------------------------------------------------------------

proc_evidence() {

    local pid="$1"
    local exe root cgroup ppid uid user cmdline comm state
    local fd_count deleted_maps

    [[ -d "/proc/$pid" ]] || { printf 'process exited before evidence collection'; return 0; }

    exe="$(readlink "/proc/$pid/exe" 2>/dev/null || echo unreadable)"
    root="$(readlink "/proc/$pid/root" 2>/dev/null || echo unreadable)"

    proc_read_status "$pid"
    ppid="$PROC_PPID"
    uid="$PROC_UID"
    comm="$PROC_COMM"
    state="$PROC_STATE"

    user="$(uid_to_name "${uid:-}")"

    cmdline="$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)"
    [[ -n "$cmdline" ]] || cmdline="[kernel or empty cmdline]"

    cgroup="$(head -3 "/proc/$pid/cgroup" 2>/dev/null | tr '\n' ' ')"

    fd_count="$(find "/proc/$pid/fd" -maxdepth 1 2>/dev/null | wc -l)"
    fd_count=$(( fd_count > 0 ? fd_count - 1 : 0 ))

    deleted_maps="$(grep -c '(deleted)' "/proc/$pid/maps" 2>/dev/null || echo 0)"

    printf 'PID=%s PPID=%s USER=%s STATE=%s COMM=%s
EXE=%s
ROOT=%s
CMDLINE=%s
CGROUP=%s
OPEN_FD=%s DELETED_MAPS=%s' \
        "$pid" "${ppid:-?}" "$user" "${state:-?}" "${comm:-?}" \
        "$exe" "$root" "$(truncate_text "$cmdline" 300)" \
        "${cgroup:-none}" "$fd_count" "$deleted_maps"
}

# Network connections owned by a PID, from the socket table
# snapshot taken at module start.
proc_connections() {

    local pid="$1" out=""

    [[ -r "$ITM_RUN_TMP/sockets.txt" ]] || { printf 'not collected'; return 0; }

    out="$(grep -F "pid=${pid}," "$ITM_RUN_TMP/sockets.txt" 2>/dev/null \
        | awk '{print $1, $2, $5, $6}' | head -10)"

    if [[ -z "$out" ]]; then
        printf 'none'
    else
        printf '%s' "$(printf '%s' "$out" | tr '\n' ';')"
    fi
}

proc_has_connection() {
    [[ -r "$ITM_RUN_TMP/sockets.txt" ]] || return 1
    grep -Fq "pid=${1}," "$ITM_RUN_TMP/sockets.txt" 2>/dev/null
}

is_standard_exec_dir() {
    local exe="$1" d
    for d in $PROC_STANDARD_DIRS; do
        [[ "$exe" == "$d"/* ]] && return 0
    done
    return 1
}

# ------------------------------------------------------------
# ps(1) versus /proc cross check
# ------------------------------------------------------------

check_hidden_pids() {

    have_cmd ps || {
        add_skip "ps not available - hidden process cross check skipped"
        return 0
    }

    local ps_pids proc_pids pid hidden=() comm exe

    ps_pids="$ITM_RUN_TMP/ps_pids.txt"
    proc_pids="$ITM_RUN_TMP/proc_pids.txt"

    run_timeout "$CMD_TIMEOUT" ps -eo pid= 2>/dev/null | tr -d ' ' | sort -n > "$ps_pids"

    if [[ ! -s "$ps_pids" ]]; then
        add_skip "ps produced no output - hidden process cross check skipped"
        return 0
    fi

    find /proc -maxdepth 1 -regex '/proc/[0-9]+' -printf '%f\n' 2>/dev/null | sort -n > "$proc_pids"

    while read -r pid; do
        [[ -n "$pid" ]] || continue
        grep -qx "$pid" "$ps_pids" && continue

        # Re-verify: the process must still exist, and ps must
        # still refuse to show it. This removes the race where a
        # process simply started or exited between the two reads.
        [[ -d "/proc/$pid" ]] || continue
        run_timeout 5 ps -p "$pid" -o pid= 2>/dev/null | grep -q '[0-9]' && continue
        [[ -d "/proc/$pid" ]] || continue

        hidden+=("$pid")
    done < "$proc_pids"

    if (( ${#hidden[@]} == 0 )); then
        add_pass "ps output consistent with /proc (no hidden PID)"
        return 0
    fi

    for pid in "${hidden[@]}"; do
        comm="$(tr -d '\0' < "/proc/$pid/comm" 2>/dev/null)"
        exe="$(readlink "/proc/$pid/exe" 2>/dev/null)"
        add_finding CRITICAL \
            "Process visible in /proc but hidden from ps output (anti-forensic filtering)" \
            id="hidden-pid:${comm:-unknown}:${exe:-unknown}" \
            path="${exe:-unknown}" \
            process="$(proc_evidence "$pid")" \
            network="$(proc_connections "$pid")" \
            evidence="PID $pid exists in /proc and survives re-verification, but 'ps -p $pid' returns nothing. This is the signature of a wrapper or rootkit filtering the process list." \
            action="Do not kill the process. Preserve evidence: copy /proc/$pid/exe, maps and fd, capture memory if possible, then isolate the host. Verify ps against package hashes."
    done
}

# ------------------------------------------------------------
# Executable state of every running process
# ------------------------------------------------------------

check_process_executables() {

    local pid exe uid user comm ppid
    local deleted=0 volatile=0 memfd=0 unowned=0 checked=0
    local owner sev

    # ---- pass 1: snapshot /proc -----------------------------
    #
    # The process table is captured once, so the evaluation
    # below cannot be skewed by processes starting or exiting
    # mid scan, and so package ownership can be resolved in a
    # single batched query.

    : > "$ITM_RUN_TMP/procmap.txt"

    while IFS= read -r pid; do
        [[ -n "$pid" && -d "/proc/$pid" ]] || continue
        exe="$(readlink "/proc/$pid/exe" 2>/dev/null)"
        # Kernel threads have no exe link. Not an anomaly.
        [[ -n "$exe" ]] || continue
        printf '%s\t%s\n' "$pid" "$exe" >> "$ITM_RUN_TMP/procmap.txt"
    done < <(find /proc -maxdepth 1 -regex '/proc/[0-9]+' -printf '%f\n' 2>/dev/null)

    local prefetch=()
    while IFS= read -r exe; do
        [[ -n "$exe" ]] && prefetch+=("$exe")
    done < <(cut -f2 "$ITM_RUN_TMP/procmap.txt" 2>/dev/null \
                | grep '^/' | grep -v '(deleted)$' | sort -u)

    (( ${#prefetch[@]} > 0 )) && pkg_owner_prefetch "${prefetch[@]}"

    # ---- pass 2: evaluate -----------------------------------

    while IFS=$'\t' read -r pid exe; do

        [[ -n "$pid" && -d "/proc/$pid" ]] || continue
        [[ -n "$exe" ]] || continue

        checked=$(( checked + 1 ))

        proc_read_status "$pid" || continue
        uid="$PROC_UID"
        ppid="$PROC_PPID"
        comm="$PROC_COMM"
        user="$(uid_to_name "$uid")"

        # ---- deleted executable ----------------------------
        if [[ "$exe" == *"(deleted)" ]]; then

            deleted=$(( deleted + 1 ))

            if proc_has_connection "$pid"; then
                sev=CRITICAL
            elif [[ "${uid:-1}" == "0" ]]; then
                sev=HIGH
            else
                sev=HIGH
            fi

            add_finding "$sev" \
                "Running process executes a deleted binary" \
                id="deleted-exe:${comm:-unknown}:${exe% (deleted)}" \
                path="${exe}" \
                process="$(proc_evidence "$pid")" \
                network="$(proc_connections "$pid")" \
                evidence="/proc/$pid/exe points at a file that no longer exists on disk. Common for a binary that unlinked itself after execution, and also for a process still running after a package upgrade.$( proc_has_connection "$pid" && printf ' This process holds network sockets.' )" \
                action="Do not kill the process. Dump the image with: cp /proc/$pid/exe /root/forensic/pid-$pid.bin ; record sha256 ; review parent PID ${ppid:-?} and its cgroup. If it is not explained by a package upgrade, treat the host as compromised."
            continue
        fi

        # ---- memfd / anonymous executable -------------------
        if [[ "$exe" == memfd:* || "$exe" == /memfd:* ]]; then
            memfd=$(( memfd + 1 ))
            add_finding CRITICAL \
                "Process running from an anonymous in-memory file (memfd)" \
                id="memfd-exe:${comm:-unknown}" \
                path="$exe" \
                process="$(proc_evidence "$pid")" \
                network="$(proc_connections "$pid")" \
                evidence="The executable was never written to disk. Fileless execution has almost no legitimate use on a production web server." \
                action="Do not kill the process. Capture /proc/$pid/exe and /proc/$pid/maps immediately, then isolate the host."
            continue
        fi

        # ---- executable in a temporary directory ------------
        if is_volatile_path "$exe"; then
            volatile=$(( volatile + 1 ))
            add_finding CRITICAL \
                "Process executing from a temporary directory" \
                id="volatile-exe:$exe" \
                path="$exe" \
                process="$(proc_evidence "$pid")" \
                network="$(proc_connections "$pid")" \
                evidence="Executable path $exe is under a directory that no packaged service should run from. sha256=$(file_sha256 "$exe") mtime=$(file_mtime_human "$exe")" \
                action="Do not kill or delete. Preserve the binary and its parent process chain, then isolate the host."
            continue
        fi

        # ---- executable in a home directory -----------------
        #
        # A user running a tool out of their own home is
        # ordinary. The same binary running as root, or out of
        # a different account's home, is not.
        if is_user_home_path "$exe"; then

            path_is_own_home "$exe" "$user" && continue

            volatile=$(( volatile + 1 ))

            if [[ "${uid:-1}" == "0" ]]; then
                sev=HIGH
            else
                sev=MEDIUM
            fi

            add_finding "$sev" \
                "Process executing from a home directory that is not its own account's" \
                id="home-exe:$exe:$user" \
                path="$exe" \
                process="$(proc_evidence "$pid")" \
                network="$(proc_connections "$pid")" \
                evidence="Running as $user from $exe. sha256=$(file_sha256 "$exe") mtime=$(file_mtime_human "$exe")" \
                action="Confirm the deployment. A root process running a binary out of a home directory means anyone with write access to that directory controls root."
            continue
        fi

        # ---- root process from an unpackaged binary ---------
        # Limited to root processes to keep dpkg/rpm queries bounded.
        if [[ "${uid:-1}" == "0" ]]; then

            is_itm_binary "$exe" && continue

            # Interpreted daemons and container runtimes live in
            # many places. Only unusual locations are queried.
            if ! is_standard_exec_dir "$exe"; then
                unowned=$(( unowned + 1 ))
                add_finding MEDIUM \
                    "Root process running from a non-standard executable path" \
                    id="nonstd-root-exe:$exe" \
                    path="$exe" \
                    process="$(proc_evidence "$pid")" \
                    network="$(proc_connections "$pid")" \
                    evidence="Executable is outside the usual system directories. package=$(pkg_owner "$exe") sha256=$(file_sha256 "$exe")" \
                    action="Confirm this binary belongs to a known application deployment. If it is unknown, preserve it and investigate."
                continue
            fi

            owner="$(pkg_owner "$exe")"
            if [[ "$owner" == "NONE" ]]; then
                unowned=$(( unowned + 1 ))
                add_finding HIGH \
                    "Root process running a binary in a system directory that no package owns" \
                    id="unowned-root-exe:$exe" \
                    path="$exe" \
                    process="$(proc_evidence "$pid")" \
                    network="$(proc_connections "$pid")" \
                    evidence="$exe is not owned by any installed package. sha256=$(file_sha256 "$exe") mtime=$(file_mtime_human "$exe")" \
                    action="Compare against the distribution package. A binary dropped into a system directory is a common persistence pattern. Preserve, do not delete."
            fi
        fi

    done < "$ITM_RUN_TMP/procmap.txt"

    (( deleted  == 0 )) && add_pass "no process is executing a deleted binary"
    (( memfd    == 0 )) && add_pass "no fileless (memfd) execution detected"
    (( volatile == 0 )) && add_pass "no process executing from /tmp, /var/tmp, /dev/shm or /home"
    (( unowned  == 0 )) && add_pass "all root process binaries resolve to known packages or known paths"

    audit_log INFO "examined $checked processes with a resolvable executable"
}

# ------------------------------------------------------------
# Parent/child anomalies
# ------------------------------------------------------------

check_process_ancestry() {

    local pid exe ppid pexe uid found=0

    while IFS= read -r pid; do

        [[ -d "/proc/$pid" ]] || continue

        exe="$(readlink "/proc/$pid/exe" 2>/dev/null)"
        [[ -n "$exe" ]] || continue

        proc_read_status "$pid" || continue
        [[ "$PROC_UID" == "0" ]] || continue

        ppid="$PROC_PPID"
        [[ -n "$ppid" && "$ppid" != "0" ]] || continue

        pexe="$(readlink "/proc/$ppid/exe" 2>/dev/null)"

        # A root shell or interpreter whose parent is a web
        # server or PHP worker is the classic webshell escalation
        # path on this stack.
        case "$exe" in
            */bash|*/sh|*/dash|*/zsh|*/python*|*/perl|*/ruby|*/nc|*/ncat|*/socat)
                case "$pexe" in
                    */nginx|*/php-fpm*|*/apache2|*/httpd|*/httpd.worker)
                        found=1
                        add_finding CRITICAL \
                            "Interactive shell or interpreter spawned by the web server" \
                            id="webshell-child:${exe}:${pexe}" \
                            path="$exe" \
                            process="$(proc_evidence "$pid")
PARENT: $(proc_evidence "$ppid")" \
                            network="$(proc_connections "$pid")" \
                            evidence="Parent $pexe (PID $ppid) spawned $exe (PID $pid). On an Nginx/PHP-FPM host this is the standard signature of webshell command execution." \
                            action="Preserve both processes and the PHP-FPM access log for the matching timestamp. Do not kill. Identify the request that triggered it in the Nginx access log."
                        ;;
                esac
                ;;
        esac

    done < <(find /proc -maxdepth 1 -regex '/proc/[0-9]+' -printf '%f\n' 2>/dev/null)

    (( found == 0 )) && add_pass "no shell or interpreter running as a child of the web server"
}

# ============================================================
# ENTRY POINT
# ============================================================

run_audit_process() {

    module_begin "process" "Process Integrity"

    if ! is_root; then
        add_finding LOW \
            "Audit not running as root - process visibility is limited to this user" \
            id="process-not-root" \
            evidence="Executable paths and open file descriptors of other users cannot be read without root." \
            action="Run: sudo itm-security audit process"
    fi

    # One socket table snapshot, reused by every PID lookup.
    if have_cmd ss; then
        run_timeout "$CMD_TIMEOUT" ss -tunap > "$ITM_RUN_TMP/sockets.txt" 2>/dev/null || true
    fi

    check_hidden_pids
    check_process_executables
    check_process_ancestry

    module_end
}

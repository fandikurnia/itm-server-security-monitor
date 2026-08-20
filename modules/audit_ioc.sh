#!/usr/bin/env bash
# shellcheck shell=bash

# ============================================================
# ITM Server Security Monitor
# Post-Compromise Audit - Module X: IOC hunt
#
# Read only. Nothing is quarantined, moved or deleted.
#
# Runs on every host regardless of role: credential stealers and
# persistence are not a web problem.
#
# Two kinds of detection, in order of value:
#
#  1. GENERIC - an executable sitting in a system binary
#     directory that no package owns. This needs no threat
#     intelligence and no IOC list, and it is what actually
#     catches the next payload:
#
#         /usr/bin/x86_65-linux-gnu-op
#
#     which imitates the Debian toolchain triplet
#     (x86_64-linux-gnu) with one digit changed, and which no
#     "is the hook active?" check would ever have found because
#     the PAM line calling it had been commented out.
#
#  2. SPECIFIC - the known IOC database in
#     /etc/security-monitor/ioc/known-iocs.conf: paths, hashes,
#     domains and strings recovered from previous incidents on
#     this estate. Cheap to check, and it turns one host's
#     incident into fleet-wide detection.
#
# The generic check exists because IOC lists only ever describe
# the last attack.
# ============================================================

IOC_SYSTEM_BIN_DIRS="${IOC_SYSTEM_BIN_DIRS:-/usr/bin /usr/sbin /bin /sbin /usr/local/bin /usr/local/sbin /usr/libexec}"

# Where a dropped payload is typically referenced from.
IOC_SEARCH_CONFIG_DIRS="${IOC_SEARCH_CONFIG_DIRS:-/etc/pam.d /etc/systemd/system /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/init.d /etc/profile.d /etc/rc.local /etc/ld.so.preload}"

KNOWN_IOCS=()

# ------------------------------------------------------------
# IOC database
#
# Format, one per line:
#   path:/usr/bin/evil
#   sha256:<64 hex>
#   domain:evil.example
#   string:/sudo/socket.php
# ------------------------------------------------------------

pid_owner() {
    local pid="$1"
    proc_read_status "$pid" 2>/dev/null || { printf 'unknown'; return 0; }
    uid_to_name "$PROC_UID"
}

ioc_load_database() {
    load_ioc_list "known-iocs.conf" KNOWN_IOCS || return 1
    (( ${#KNOWN_IOCS[@]} > 0 ))
}

# ------------------------------------------------------------
# Standalone C2 watchlist
#
# Kept separate from known-iocs.conf on purpose: during an
# incident somebody needs to add an address in ten seconds,
# without learning a file format or touching source code.
# ------------------------------------------------------------

ITM_C2_LIST="${ITM_C2_LIST:-$ITM_CONF_DIR/known-c2.list}"

C2_WATCHLIST=()

ioc_load_c2_watchlist() {

    local line

    C2_WATCHLIST=()

    [[ -r "$ITM_C2_LIST" ]] || return 1

    while IFS= read -r line; do
        line="${line%%#*}"
        line="${line//[[:space:]]/}"
        [[ -z "$line" ]] && continue
        C2_WATCHLIST+=("$line")
    done < "$ITM_C2_LIST"

    (( ${#C2_WATCHLIST[@]} > 0 ))
}

c2_entry_is_ip() {
    [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || [[ "$1" == *:*:* ]]
}

ioc_entries_of_type() {
    local want="$1" entry
    for entry in ${KNOWN_IOCS[@]+"${KNOWN_IOCS[@]}"}; do
        [[ "$entry" == "$want:"* ]] && printf '%s\n' "${entry#"$want":}"
    done
}

# ------------------------------------------------------------
# 1. Unpackaged executables in system binary directories
#
# On a package managed server every binary in /usr/bin belongs
# to a package. The exceptions are few, local, and known to the
# administrator - which is exactly why an unowned binary there
# is worth a look every single time.
# ------------------------------------------------------------

ioc_check_unpackaged_system_binaries() {

    local dir file batch=() reported=0 checked=0

    if [[ "$ITM_OS_FAMILY" != "debian" && "$ITM_OS_FAMILY" != "rhel" ]]; then
        add_skip "no supported package manager - unpackaged binary sweep skipped"
        return 0
    fi

    # Collect candidates first, then resolve ownership in
    # batches: one dpkg-query per binary would take minutes.
    while IFS= read -r file; do
        [[ -n "$file" ]] || continue
        is_itm_binary "$file" && continue
        batch+=("$file")
    done < <(
        for dir in $IOC_SYSTEM_BIN_DIRS; do
            [[ -d "$dir" ]] || continue
            run_scan 60 find "$dir" -maxdepth 1 -type f -perm -u+x -print 2>/dev/null
        done
    )

    checked="${#batch[@]}"

    if (( checked == 0 )); then
        add_skip "no system binaries enumerated"
        return 0
    fi

    # Chunked so the argument list stays sane on hosts with a
    # few thousand binaries.
    local i chunk=400
    for (( i = 0; i < checked; i += chunk )); do
        pkg_owner_prefetch "${batch[@]:i:chunk}"
    done

    for file in "${batch[@]}"; do

        is_pkg_owned "$file" && continue

        score_reset
        score_add 40 "executable in a system binary directory that no package owns"

        local name="${file##*/}"

        # Toolchain triplet imitation: x86_64-linux-gnu-* is a
        # real prefix, x86_65-linux-gnu-* is not.
        if [[ "$name" =~ ^(x86|i[36]86|aarch|arm|amd)[0-9_]*-[a-z]+-[a-z]+ ]]; then
            score_add 45 "name imitates a compiler toolchain prefix - blends into /usr/bin listings"
        fi

        # Other system naming conventions used as camouflage. The
        # real ones are all package owned; this file is not.
        case "$name" in
            systemd-*|dbus-*|udev*|kworker*|kthread*|ksoftirq*|migration*|rcu_*)
                score_add 45 "name imitates a systemd/kernel component while belonging to no package" ;;
            lib*.so*|ld-*)
                score_add 35 "executable named like a shared library" ;;
        esac

        # /usr/local is outside dpkg's remit by design, so an
        # unowned file there is expected - but it is also exactly
        # where the forensic-tool wrappers were planted on this
        # estate. Reviewable, not automatically malicious.
        case "$file" in
            /usr/local/*)
                score_add 25 "in /usr/local, which no package manages: it must be accounted for by an administrator" ;;
        esac

        # Payload characteristics.
        local ftype
        ftype="$(run_timeout 10 file -b "$file" 2>/dev/null)"
        case "$ftype" in
            *"shell script"*|*"Python script"*|*"Perl script"*)
                score_add 15 "script rather than a compiled program" ;;
        esac

        if run_timeout 10 strings -n 6 "$file" 2>/dev/null \
            | grep -qEi 'curl|wget|/dev/tcp/|https?://|socket|expose_authtok|PAM_AUTHTOK'; then
            score_add 30 "contains network or credential handling strings"
        fi

        web_file_facts "$file" 2>/dev/null || true

        add_finding "$(score_severity)" \
            "Unpackaged executable in a system binary directory" \
            id="ioc-unpackaged-bin:$file" \
            path="$file" \
            hash="$(file_sha256 "$file")" \
            confidence="$(score_confidence)" \
            reasons="$SCORE_REASONS" \
            evidence="type=${ftype:-unknown}
owner=$(stat -Lc '%U:%G' "$file" 2>/dev/null) mode=$(stat -Lc '%a' "$file" 2>/dev/null) size=$(stat -Lc '%s' "$file" 2>/dev/null)
mtime=$(file_mtime_human "$file")
sha256=$(file_sha256 "$file")
Strings of interest: $(run_timeout 10 strings -n 6 "$file" 2>/dev/null | grep -Eio 'curl|wget|/dev/tcp/|https?://[a-z0-9.:/_-]{4,60}|expose_authtok' | sort -u | head -6 | tr '\n' ' ')" \
            action="Confirm with the platform owner whether this binary was installed deliberately. Locally compiled tools do live here legitimately, so the question is whether anyone can account for it. If nobody can: preserve it (copy to /root/forensic, record the SHA256), search /etc/pam.d, cron, systemd and ld.so.preload for anything that invokes it, and treat the host as compromised."

        evidence_snapshot "$file" \
            "$(printf '%s|ioc-unpackaged|%s' "$ITM_HOSTNAME" "$file" | sha256sum | cut -c1-32)" \
            "unpackaged executable in a system binary directory" >/dev/null

        reported=$(( reported + 1 ))

    done

    audit_log INFO "checked $checked system binaries, $reported unpackaged"

    if (( reported == 0 )); then
        add_pass "all $checked executables in system binary directories are owned by packages"
    fi
}

# ------------------------------------------------------------
# 2a. Known IOC paths
# ------------------------------------------------------------

ioc_check_known_paths() {

    local path found=0 sha sha2 known_hashes h is_known

    # The hash list is loaded once so a path finding can say
    # whether the file IS the known payload, or merely carries
    # its name.
    known_hashes="$(ioc_entries_of_type sha256 | tr 'A-Z' 'a-z' | tr '\n' ' ')"

    while IFS= read -r path; do

        [[ -n "$path" ]] || continue
        [[ -e "$path" || -L "$path" ]] || continue

        found=$(( found + 1 ))

        local is_link="no" link_target=""
        if [[ -L "$path" ]]; then
            is_link="yes"
            link_target="$(readlink -f -- "$path" 2>/dev/null || readlink -- "$path" 2>/dev/null)"
        fi

        sha="$(trusted_sha256 "$path")"

        # A file that changes between two reads is being written
        # while it is examined: report the fact rather than a
        # hash that describes neither version.
        local changed="no"
        if [[ "$sha" != "unreadable" && "$sha" != "sha256sum-missing" ]]; then
            sha2="$(trusted_sha256 "$path")"
            [[ "$sha" == "$sha2" ]] || changed="yes"
        fi

        is_known="no"
        if [[ -n "$sha" && "$sha" != "unreadable" ]]; then
            for h in $known_hashes; do
                [[ "${sha,,}" == "$h" ]] && { is_known="yes"; break; }
            done
        fi

        local severity title reasons
        if [[ "$is_known" == "yes" ]]; then
            severity=CRITICAL
            title="Known malicious file from a previous incident is present on this host"
            reasons="Path matches an IOC recorded from a confirmed compromise on this estate
Content hash matches the recorded payload exactly
This is the same binary, not a coincidence of naming"
        elif [[ "$sha" == "unreadable" ]]; then
            severity=HIGH
            title="IOC path exists but could not be read"
            reasons="Path matches a known IOC from a confirmed compromise
The file could not be read to confirm its hash (permission denied or a special file)
Presence at this exact path is itself the indicator"
        else
            severity=HIGH
            title="Suspicious artifact: IOC filename present with an unrecognised hash"
            reasons="Path matches a known IOC from a confirmed compromise
The content hash does NOT match any recorded payload
This is either a different build of the same implant, or an unrelated file that happens to occupy the path"
        fi

        [[ "$is_link" == "yes" ]] && reasons+="
The path is a SYMLINK to ${link_target:-unknown} - the target is what executes"
        [[ "$changed" == "yes" ]] && reasons+="
The file CHANGED between two consecutive reads: it is being written to right now"

        add_finding "$severity" "$title" \
            id="ioc-known-path:$path" \
            event=IOC_KNOWN_PATH \
            path="$path" \
            hash="$sha" \
            confidence="$( [[ "$is_known" == yes ]] && echo 99 || echo 80 )" \
            reasons="$reasons" \
            evidence="sha256=$sha hash_matches_known_ioc=$is_known symlink=$is_link${link_target:+ -> $link_target} changed_while_reading=$changed
owner=$(stat -Lc '%U:%G' "$path" 2>/dev/null) mode=$(stat -Lc '%a' "$path" 2>/dev/null) size=$(stat -Lc '%s' "$path" 2>/dev/null) mtime=$(file_mtime_human "$path")
package=$(pkg_owner "$path")" \
            action="ISOLATE THIS HOST. Preserve the file and its metadata before anything else. Rotate every credential used on this host. Then find how it got here and what re-installs it - the payload is the symptom, the persistence is the problem. If root compromise is confirmed, rebuild from trusted media."

        evidence_snapshot "$path" \
            "$(printf '%s|ioc-known|%s' "$ITM_HOSTNAME" "$path" | sha256sum | cut -c1-32)" \
            "known IOC path from the incident database" >/dev/null

    done < <(ioc_entries_of_type path)

    (( found == 0 )) && add_pass "no known IOC file path present on this host"
}

# ------------------------------------------------------------
# IOC filenames anywhere in a BOUNDED set of directories
#
# "x86_65-linux-gnu-op" and "kiann.php" are names, not paths.
# Searching the whole filesystem every interval is exactly the
# behaviour this project refuses, so the hunt is limited to the
# directories a dropped payload actually lands in, with a depth
# limit and a timeout.
# ------------------------------------------------------------

IOC_FILENAME_SEARCH_DIRS="${IOC_FILENAME_SEARCH_DIRS:-/usr/bin /usr/sbin /bin /sbin /usr/local /opt /tmp /var/tmp /dev/shm /root /etc /var/www /website /srv}"
IOC_FILENAME_MAXDEPTH="${IOC_FILENAME_MAXDEPTH:-4}"

ioc_check_ioc_filenames() {

    local names=() n found=0 hit

    while IFS= read -r n; do
        [[ -n "$n" ]] && names+=("$n")
    done < <(ioc_entries_of_type filename)

    (( ${#names[@]} > 0 )) || { add_skip "no IOC filenames configured"; return 0; }

    local -a name_args=()
    local first=1
    for n in "${names[@]}"; do
        (( first )) || name_args+=( -o )
        name_args+=( -name "$n" )
        first=0
    done

    local -a dirs=()
    for n in $IOC_FILENAME_SEARCH_DIRS; do
        [[ -d "$n" ]] && dirs+=("$n")
    done
    (( ${#dirs[@]} > 0 )) || return 0

    while IFS= read -r hit; do

        [[ -n "$hit" ]] || continue
        found=$(( found + 1 ))

        local sha
        sha="$(trusted_sha256 "$hit")"

        add_finding CRITICAL \
            "File matching a known IOC filename" \
            id="ioc-filename:$hit" \
            event=IOC_KNOWN_FILENAME \
            path="$hit" \
            hash="$sha" \
            confidence=95 \
            reasons="Filename matches an artefact recovered from a confirmed compromise
The name imitates a toolchain or application file so it reads as ordinary in a directory listing
Found outside the paths previously recorded, which means it was dropped again or was missed" \
            evidence="owner=$(stat -Lc '%U:%G' "$hit" 2>/dev/null) mode=$(stat -Lc '%a' "$hit" 2>/dev/null) size=$(stat -Lc '%s' "$hit" 2>/dev/null)
mtime=$(file_mtime_human "$hit") sha256=$sha package=$(pkg_owner "$hit")" \
            action="ISOLATE THIS HOST and preserve the file. Search for what wrote it (cron, systemd, PAM, web upload) before removing anything."

        evidence_snapshot "$hit" \
            "$(printf '%s|ioc-filename|%s' "$ITM_HOSTNAME" "$hit" | sha256sum | cut -c1-32)" \
            "IOC filename hunt" >/dev/null

    done < <(run_scan "$FIND_TIMEOUT" find "${dirs[@]}" -maxdepth "$IOC_FILENAME_MAXDEPTH" \
                -type f \( "${name_args[@]}" \) -print 2>/dev/null | head -50)

    (( found == 0 )) && add_pass "no file matching a known IOC filename in the searched directories"
}

# ------------------------------------------------------------
# Active connection to a known C2 address
#
# ss is resolved from a trusted directory: on a host with a
# wrapped netstat/ss the output of the PATH version cannot be
# used to decide whether a C2 session exists.
# ------------------------------------------------------------

ioc_check_c2_connections() {

    local ips=() ip found=0 ss_bin out line

    while IFS= read -r ip; do
        [[ -n "$ip" ]] && ips+=("$ip")
    done < <(ioc_entries_of_type ip)

    # The standalone watchlist contributes its IP entries too.
    local w
    for w in ${C2_WATCHLIST[@]+"${C2_WATCHLIST[@]}"}; do
        c2_entry_is_ip "$w" && ips+=("$w")
    done

    (( ${#ips[@]} > 0 )) || { add_skip "no IOC IP addresses configured"; return 0; }

    ss_bin="$(trusted_bin ss)" || { add_skip "ss not found in a trusted directory - C2 connection check skipped"; return 0; }

    out="$(run_timeout "$CMD_TIMEOUT" "$ss_bin" -tunap 2>/dev/null)"
    [[ -n "$out" ]] || { add_skip "socket table unavailable"; return 0; }

    for ip in "${ips[@]}"; do

        while IFS= read -r line; do

            [[ -n "$line" ]] || continue
            found=$(( found + 1 ))

            local state peer proc pid port
            state="$(printf '%s' "$line" | awk '{print $2}')"
            peer="$(printf '%s' "$line"  | awk '{print $6}')"
            port="${peer##*:}"
            proc="$(printf '%s' "$line" | grep -oE 'users:\(\("[^"]+"' | head -1 | sed 's/.*"\(.*\)"/\1/')"
            pid="$(printf '%s' "$line" | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2)"

            add_finding CRITICAL \
                "Active network connection to a known command-and-control address" \
                id="ioc-c2-connection:$ip:${proc:-unknown}" \
                event=IOC_C2_CONNECTION \
                confidence=99 \
                reasons="Remote address ${ip} is recorded as C2 infrastructure from a confirmed compromise
A socket to it exists on this host right now
This is live attacker communication, not a historical artefact" \
                network="${state} -> ${peer} (port ${port})" \
                process="$( [[ -n "$pid" ]] && printf 'pid=%s comm=%s exe=%s user=%s' "$pid" "${proc:-unknown}" "$(readlink "/proc/$pid/exe" 2>/dev/null)" "$(pid_owner "$pid")" || printf 'process not attributable' )" \
                evidence="$(truncate_text "$(redact "$line")" 300)" \
                action="ISOLATE THIS HOST NOW - block the address at the perimeter first so the session is cut without warning the operator of the implant. Do not kill the process before capturing it. Preserve /proc/PID, then rotate every credential used on this host."

        done < <(printf '%s' "$out" | grep -F "$ip")
    done

    (( found == 0 )) && add_pass "no active connection to any known C2 address (${#ips[@]} checked)"
}

# ------------------------------------------------------------
# argv[0] masquerading
#
# The implant on this estate ran as:
#   exec -a '[php-fpm]' /usr/bin/defaults
#
# Brackets make a process look like a kernel thread in ps
# output. A kernel thread has no executable, so a bracketed
# name with a real exe behind it is a contradiction.
# ------------------------------------------------------------

ioc_check_argv_masquerade() {

    local pid cmdline argv0 exe found=0

    while IFS= read -r pid; do

        [[ -r "/proc/$pid/cmdline" ]] || continue

        cmdline="$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)"
        argv0="${cmdline%% *}"

        [[ "$argv0" == \[*\]* ]] || continue

        # A real kernel thread has no exe link at all.
        exe="$(readlink "/proc/$pid/exe" 2>/dev/null)" || continue
        [[ -n "$exe" ]] || continue

        found=$(( found + 1 ))

        proc_read_status "$pid" || true

        add_finding CRITICAL \
            "Process disguised as a kernel thread" \
            id="ioc-argv-masquerade:$exe" \
            event=IOC_PROCESS_MASQUERADE \
            path="$exe" \
            hash="$(trusted_sha256 "$exe")" \
            confidence=95 \
            reasons="argv[0] is ${argv0}, which reads as a kernel thread in ps output
A kernel thread has no executable, but this process does: ${exe}
Renaming a process this way has no legitimate use; it is done with exec -a to hide" \
            process="pid=$pid ppid=${PROC_PPID:-?} user=$(uid_to_name "${PROC_UID:-}") exe=$exe
cmdline=$(truncate_text "$(redact "$cmdline")" 200)" \
            evidence="exe package=$(pkg_owner "$exe") sha256=$(trusted_sha256 "$exe")
mtime=$(file_mtime_human "$exe")" \
            action="Do not kill the process yet. Capture /proc/$pid/exe, cmdline, maps and open sockets, then isolate the host. Check which systemd unit or cron entry starts it."

    done < <(find /proc -maxdepth 1 -regex '/proc/[0-9]+' -printf '%f\n' 2>/dev/null)

    (( found == 0 )) && add_pass "no process disguised with a bracketed kernel-thread name"
}

# ------------------------------------------------------------
# 2b. Known IOC hashes
#
# A renamed payload keeps its hash. Only the system binary
# directories are hashed, so this stays bounded.
# ------------------------------------------------------------

ioc_check_known_hashes() {

    local hashes=() h file sha found=0

    while IFS= read -r h; do
        h="${h,,}"
        [[ "$h" =~ ^[0-9a-f]{64}$ ]] && hashes+=("$h")
    done < <(ioc_entries_of_type sha256)

    if (( ${#hashes[@]} == 0 )); then
        add_skip "no IOC hashes configured"
        return 0
    fi

    local dir
    while IFS= read -r file; do

        [[ -f "$file" ]] || continue
        sha="$(file_sha256 "$file")"
        sha="${sha,,}"

        for h in "${hashes[@]}"; do
            [[ "$sha" == "$h" ]] || continue

            found=$(( found + 1 ))

            add_finding CRITICAL \
                "File matching a known malicious hash (renamed payload)" \
                id="ioc-known-hash:$sha" \
                path="$file" \
                hash="$sha" \
                confidence=99 \
                reasons="Content hash matches a payload recovered from a confirmed compromise
The file has been renamed or relocated, but the contents are identical" \
                evidence="path=$file
sha256=$sha
mtime=$(file_mtime_human "$file")" \
                action="ISOLATE THIS HOST and preserve the file. A renamed payload means whoever placed it expected the original path to be checked."

            evidence_snapshot "$file" "$sha" "known IOC hash match" >/dev/null
            break
        done

    done < <(
        for dir in $IOC_SYSTEM_BIN_DIRS; do
            [[ -d "$dir" ]] || continue
            run_scan 60 find "$dir" -maxdepth 1 -type f -size -"$(( WEB_MAX_FILE_BYTES / 1024 + 1 ))"k -print 2>/dev/null
        done
    )

    (( found == 0 )) && add_pass "no file matching a known malicious hash in the system binary directories"
}

# ------------------------------------------------------------
# 2c. Known C2 domains and strings
#
# Searched where a payload is referenced or configured, not
# across the whole filesystem.
# ------------------------------------------------------------

ioc_check_known_strings() {

    local needles=() n regex="" found=0 dir hits

    while IFS= read -r n; do
        [[ -n "$n" ]] && needles+=("$n")
    done < <( { ioc_entries_of_type domain; ioc_entries_of_type string; } )

    if (( ${#needles[@]} == 0 )); then
        add_skip "no IOC domains or strings configured"
        return 0
    fi

    for n in "${needles[@]}"; do
        regex+="${regex:+|}$(printf '%s' "$n" | sed 's/[.[\*^$+?()|{}]/\\&/g')"
    done

    local search_dirs=()
    for dir in $IOC_SEARCH_CONFIG_DIRS; do
        [[ -e "$dir" ]] && search_dirs+=("$dir")
    done

    for dir in $IOC_SYSTEM_BIN_DIRS; do
        [[ -d "$dir" ]] && search_dirs+=("$dir")
    done

    # Web roots too, when this host has them.
    if declare -F web_scan_roots >/dev/null && web_scan_roots 2>/dev/null; then
        search_dirs+=("${WEB_SCAN_ROOTS[@]}")
    fi

    (( ${#search_dirs[@]} > 0 )) || { add_skip "no directories to search for IOC strings"; return 0; }

    hits="$(run_scan "$FIND_TIMEOUT" grep -rlaE "$regex" \
                --exclude-dir=node_modules --exclude-dir=.git --exclude-dir=cache \
                --exclude-dir=sessions --exclude-dir=vendor \
                "${search_dirs[@]}" 2>/dev/null | head -20)"

    if [[ -n "$hits" ]]; then
        local file
        while IFS= read -r file; do

            [[ -n "$file" ]] || continue
            found=$(( found + 1 ))

            local matched
            matched="$(run_timeout 15 grep -oaEi "$regex" "$file" 2>/dev/null | sort -u | head -5 | tr '\n' ' ')"

            add_finding CRITICAL \
                "File references a known malicious domain or path from a previous incident" \
                id="ioc-known-string:$file" \
                path="$file" \
                hash="$(file_sha256 "$file")" \
                confidence=90 \
                reasons="Contains an indicator recovered from a confirmed compromise on this estate
Matched: ${matched}" \
                evidence="path=$file
matched indicators: ${matched}
mtime=$(file_mtime_human "$file") owner=$(stat -Lc '%U:%G' "$file" 2>/dev/null)
package=$(pkg_owner "$file")" \
                action="Preserve the file. Check whether the host has contacted the indicator: grep the DNS and proxy logs, and review outbound connections. Rotate credentials used on this host."

        done <<< "$hits"
    fi

    (( found == 0 )) && add_pass "no known IOC domain or string found in system binaries, configuration or web roots"
}

# ------------------------------------------------------------
# Can this host still reach the C2 by name?
#
# A live socket is the strongest signal, and its absence proves
# nothing: an implant that beacons hourly is idle most of the
# time. Resolving the watchlist domains answers a different and
# still useful question - whether the path out is open, and
# whether anything on this host has the name cached or pinned in
# /etc/hosts.
#
# Resolution is a read-only DNS query. No connection is made to
# the address.
# ------------------------------------------------------------

ioc_check_c2_dns() {

    local entry found=0 resolved hostsfile_hit dig_bin host_bin

    (( ${#C2_WATCHLIST[@]} > 0 )) || return 0

    dig_bin="$(trusted_bin dig 2>/dev/null || true)"
    host_bin="$(trusted_bin getent 2>/dev/null || true)"

    for entry in "${C2_WATCHLIST[@]}"; do

        c2_entry_is_ip "$entry" && continue

        # A pinned entry in /etc/hosts is stronger than a DNS
        # answer: somebody put it there deliberately.
        hostsfile_hit=""
        if [[ -r /etc/hosts ]]; then
            hostsfile_hit="$(grep -iE "[[:space:]]${entry//./\.}([[:space:]]|$)" /etc/hosts 2>/dev/null | head -3)"
        fi

        if [[ -n "$hostsfile_hit" ]]; then
            found=$(( found + 1 ))
            add_finding CRITICAL \
                "Known C2 domain pinned in /etc/hosts" \
                id="c2-hosts-pin:$entry" \
                event=IOC_C2_DNS \
                path="/etc/hosts" \
                confidence=99 \
                reasons="${entry} is on the command-and-control watchlist
It has a fixed entry in /etc/hosts, which overrides DNS for every process on this host
Nobody adds a C2 domain to /etc/hosts by accident" \
                evidence="$(truncate_text "$(redact "$hostsfile_hit")" 300)" \
                action="Preserve /etc/hosts before editing it. Find what wrote the entry and when: stat /etc/hosts. Treat the host as compromised."
            continue
        fi

        # Resolution itself: report only that it resolves, and to
        # what. Nothing connects to the result.
        resolved=""
        if [[ -n "$host_bin" ]]; then
            resolved="$(run_timeout 8 "$host_bin" ahosts "$entry" 2>/dev/null | awk '{print $1}' | sort -u | head -4 | tr '\n' ' ')"
        elif [[ -n "$dig_bin" ]]; then
            resolved="$(run_timeout 8 "$dig_bin" +short "$entry" 2>/dev/null | head -4 | tr '\n' ' ')"
        fi

        [[ -n "$resolved" ]] || continue

        found=$(( found + 1 ))
        add_finding MEDIUM \
            "Known C2 domain still resolves from this host" \
            id="c2-resolves:$entry" \
            event=IOC_C2_DNS \
            confidence=60 \
            reasons="${entry} is on the command-and-control watchlist and resolves to ${resolved}
This does not mean the host contacted it - it means the route out is open
An implant that beacons on a schedule shows no socket in between beacons" \
            network="$entry -> $resolved" \
            evidence="resolved via the system resolver, no connection was attempted" \
            action="Block the domain and its addresses at the perimeter, then check the DNS and proxy logs for past queries from this host. Absence of a live socket is not absence of the implant."

    done

    (( found == 0 )) && add_pass "no watchlist domain is pinned in /etc/hosts or resolvable"
}

# ------------------------------------------------------------
# 3. Preload based credential interception
#
# /etc/ld.so.preload injects a library into every dynamically
# linked process on the host, sshd and sudo included. It does
# not exist on a normal Debian or RHEL system.
# ------------------------------------------------------------

ioc_check_ld_preload() {

    local file="/etc/ld.so.preload" line

    if [[ ! -e "$file" ]]; then
        add_pass "/etc/ld.so.preload does not exist (normal)"
        return 0
    fi

    local content
    content="$(head -c 4096 "$file" 2>/dev/null)"

    add_finding CRITICAL \
        "/etc/ld.so.preload exists - a library is injected into every process" \
        id="ioc-ld-preload" \
        path="$file" \
        hash="$(file_sha256 "$file")" \
        confidence=85 \
        reasons="ld.so.preload loads a shared object into every dynamically linked process on the host
sshd, sudo and su are included, which makes it a credential interception primitive
A stock Debian or RHEL install does not have this file" \
        evidence="Contents:
$(truncate_text "$content" 400)
$(while IFS= read -r line; do
      [[ -n "$line" ]] || continue
      printf '%s: package=%s sha256=%s mtime=%s\n' "$line" "$(pkg_owner "$line")" "$(file_sha256 "$line")" "$(file_mtime_human "$line")"
  done <<< "$content")" \
        action="Preserve the file and every library it lists. Do not delete it over SSH without console access: a broken preload can make every binary on the host fail to start. Some commercial agents use this legitimately, so confirm with the platform owner before acting."
}

# ============================================================
# ENTRY POINT
# ============================================================

run_audit_ioc() {

    module_begin "ioc" "IOC Hunt"

    if ioc_load_c2_watchlist; then
        add_pass "C2 watchlist loaded (${#C2_WATCHLIST[@]} entries from ${ITM_C2_LIST})"
    else
        add_skip "no C2 watchlist at ${ITM_C2_LIST}"
    fi

    if ioc_load_database; then
        add_pass "IOC database loaded (${#KNOWN_IOCS[@]} indicators)"
        ioc_check_known_paths
        ioc_check_ioc_filenames
        ioc_check_known_hashes
        ioc_check_known_strings
        ioc_check_c2_connections
        ioc_check_c2_dns
    else
        add_skip "no IOC database at ${ITM_IOC_DIR}/known-iocs.conf - generic checks still run"
    fi

    ioc_check_unpackaged_system_binaries
    ioc_check_argv_masquerade
    ioc_check_ld_preload

    module_end
}

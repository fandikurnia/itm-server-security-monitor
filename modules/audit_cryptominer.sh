#!/usr/bin/env bash
# shellcheck shell=bash

# ============================================================
# ITM Server Security Monitor
# Module CM: cryptojacking and Zimbra exploitation
#
# Read only. No process is killed, no file is removed, no
# service is stopped or reconfigured.
#
# ------------------------------------------------------------
# Why this module exists
# ------------------------------------------------------------
#
# A Zimbra mail server on this estate was compromised and used
# for cryptomining. The whole monitoring stack was running at
# the time and none of it fired:
#
#   - a commercial EDR missed a miner burning >99% CPU for
#     40+ minutes, because the payload was not in its signature
#     database
#   - no alert existed for a binary appearing in /var/tmp
#   - no alert existed for sustained CPU consumption
#
# Detection happened only when users noticed the mail server was
# down. That is not detection, that is an outage report.
#
# The lesson is that signatures alone do not catch a payload
# nobody has seen yet. What does not change is the BEHAVIOUR:
# a miner has to consume CPU, has to persist, and has to talk to
# a pool. Those are what this module looks for, so the next
# variant is caught on shape rather than on name.
#
# ------------------------------------------------------------
# What the incident actually looked like
# ------------------------------------------------------------
#
# Entry was pre-authentication command injection in the Zimbra
# SNMP component on UDP/161. Four files were dropped in /var/tmp:
#
#   javab    the miner itself, an ELF binary
#   idle     a watchdog that re-downloaded the miner
#   .rguard  a "rival killer" that killed any process whose
#            command line matched */tmp/* every 0.1 seconds
#   .khp     a dropper and persistence loader
#
# .rguard is worth understanding, because it explains the
# collateral damage: it existed to kill COMPETING miners, and it
# matched on the substring /tmp/ anywhere in the command line.
# Zimbra's MySQL runs with a socket path containing /tmp/, so it
# was killed every 0.1 seconds. The mail outage was a side
# effect of one miner fighting another, not an attack on mail.
#
# That is why "the mail server is down" was the first symptom
# anyone noticed, and why the real cause looked nothing like a
# mail problem.
# ============================================================

# CPU percentage over a process's whole lifetime that counts as
# sustained. A miner sits near 100%; normal daemons average low
# even when they burst.
CRYPTO_CPU_THRESHOLD="${CRYPTO_CPU_THRESHOLD:-90}"

# How long a process must have been running before its average
# CPU means anything. A build or a backup can peg a core for a
# short while; 5 minutes of sustained load is a different claim.
CRYPTO_CPU_MIN_RUNTIME="${CRYPTO_CPU_MIN_RUNTIME:-300}"

# Directories a payload is dropped into. Executing from these is
# the single most reliable signal in the whole incident: nothing
# legitimate on a mail server runs from here.
CRYPTO_VOLATILE_DIRS="${CRYPTO_VOLATILE_DIRS:-/tmp /var/tmp /dev/shm}"

# Accounts whose sustained CPU is expected. Kept deliberately
# short: the point is to notice unexpected load, and a long
# allowlist is how a miner running as an allowed user hides.
CRYPTO_CPU_ALLOW_USERS="${CRYPTO_CPU_ALLOW_USERS:-}"

# Process names that legitimately burn CPU for long periods.
CRYPTO_CPU_ALLOW_COMMS="${CRYPTO_CPU_ALLOW_COMMS:-kswapd0 kcompactd0 ksoftirqd rcu_sched migration khugepaged mysqld mariadbd java clamd freshclam rsync borg restic tar gzip xz zstd bzip2 make cc1 cc1plus gcc g++ ld rustc cargo node npm yarn pnpm webpack esbuild ffmpeg convert mogrify}"

# Paths in the volatile directories that are created by ordinary
# system machinery rather than by an intruder.
#
# Kept deliberately NARROW. Every entry here is a place a payload
# could be parked to avoid this check, so the list must stay
# short enough to read and justify line by line:
#
#   systemd-private-*  systemd PrivateTmp= per-unit temp dirs
#   snap.*             snap confinement temp dirs
#   .org.chromium.*    Chromium/Chrome unpack their sandbox helper
#   .com.google.Chrome.*
#   pulse-*            PulseAudio shared memory
#   .X11-unix          X socket directory
#
# A mail or web server has none of these except the systemd one.
# On a workstation they are constant noise, and noise is what
# makes an operator stop reading the alerts.
CRYPTO_VOLATILE_EXCLUDE="${CRYPTO_VOLATILE_EXCLUDE:-*/systemd-private-*/* */snap.*/* */.org.chromium.* */.com.google.Chrome.* */pulse-*/* */.X11-unix/*}"

# Miner pool protocol markers and known mining software names.
# Used only as corroboration on a process already flagged by
# behaviour - never as the sole reason for a finding.
CRYPTO_MINER_NAMES="${CRYPTO_MINER_NAMES:-xmrig xmr-stak minerd cpuminer ccminer cgminer bfgminer ethminer phoenixminer lolminer teamredminer nbminer trex gminer srbminer nanominer xmrigDaemon xmrigMiner kdevtmpfsi kinsing dbused sysrv}"

# ------------------------------------------------------------
# Self-contained process evidence.
#
# audit_process.sh defines richer proc_evidence/proc_connections
# helpers, but they depend on state that module having already
# run and populated. This module must work when it is invoked
# alone - "itm-security audit cryptominer" - so it collects what
# it needs itself rather than assuming another module prepared
# it.
# ------------------------------------------------------------
crypto_proc_evidence() {

    local pid="$1" exe ppid uid user cmdline comm

    [[ -d "/proc/$pid" ]] || { printf 'process exited before evidence collection'; return 0; }

    exe="$(readlink "/proc/$pid/exe" 2>/dev/null || printf 'unreadable')"
    comm="$(tr -d '\0' < "/proc/$pid/comm" 2>/dev/null)"
    cmdline="$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)"

    if proc_read_status "$pid" 2>/dev/null; then
        ppid="$PROC_PPID"
        uid="$PROC_UID"
    else
        ppid="unknown"; uid=""
    fi
    user="$(uid_to_name "${uid:-}")"

    printf 'pid=%s comm=%s user=%s exe=%s ppid=%s parent_exe=%s cmdline=%s' \
        "$pid" "${comm:-unknown}" "$user" "$exe" "$ppid" \
        "$(readlink "/proc/${ppid}/exe" 2>/dev/null || printf 'unknown')" \
        "$(truncate_text "$cmdline" 200)"
}

crypto_proc_connections() {

    local pid="$1" out

    have_cmd ss || { printf 'ss unavailable'; return 0; }

    out="$(run_timeout 10 ss -tnp state established 2>/dev/null \
        | grep -F "pid=${pid}," | awk '{print $3, "->", $4}' | head -10)"

    if [[ -z "$out" ]]; then
        printf 'none'
    else
        printf '%s' "$(printf '%s' "$out" | tr '\n' ';')"
    fi
}

# ------------------------------------------------------------
# Is this a kernel thread?
#
# Kernel threads have no executable and legitimately show high
# CPU. They are never the payload.
# ------------------------------------------------------------
crypto_is_kernel_thread() {
    local pid="$1"
    [[ -n "$(readlink "/proc/$pid/exe" 2>/dev/null)" ]] && return 1
    return 0
}

# Is this path one of the narrow, documented exclusions?
crypto_path_excluded() {
    local file="$1" pattern
    for pattern in $CRYPTO_VOLATILE_EXCLUDE; do
        # shellcheck disable=SC2254
        case "$file" in
            $pattern) return 0 ;;
        esac
    done
    return 1
}

crypto_comm_allowed() {
    local comm="$1" allowed
    for allowed in $CRYPTO_CPU_ALLOW_COMMS; do
        [[ "$comm" == "$allowed" ]] && return 0
    done
    return 1
}

crypto_user_allowed() {
    local user="$1" allowed
    [[ -n "$CRYPTO_CPU_ALLOW_USERS" ]] || return 1
    for allowed in $CRYPTO_CPU_ALLOW_USERS; do
        [[ "$user" == "$allowed" ]] && return 0
    done
    return 1
}

# ------------------------------------------------------------
# Lifetime average CPU for a pid, as a whole-number percentage.
#
# Read from /proc directly rather than from ps, because ps can be
# replaced by a wrapper that hides a process - which happened in
# a previous incident on this estate. utime+stime over elapsed
# time is arithmetic on kernel-maintained counters.
# ------------------------------------------------------------
crypto_cpu_percent() {

    local pid="$1"
    local stat utime stime starttime clk_tck uptime_s total_s elapsed_s

    stat="$(tr -d '\0' < "/proc/$pid/stat" 2>/dev/null)" || { printf '0 0'; return 0; }

    # Field 2 is the comm, which may contain spaces inside
    # parentheses. Everything after the closing paren is safe to
    # split on whitespace.
    stat="${stat#*) }"

    # After stripping "pid (comm) ", field 1 is state, so utime
    # is field 12 and stime field 13 of the original become 12
    # and 13 minus the two removed.
    read -r _ _ _ _ _ _ _ _ _ _ _ utime stime _ _ _ _ _ _ starttime _ <<< "$stat"

    [[ "$utime"     =~ ^[0-9]+$ ]] || { printf '0 0'; return 0; }
    [[ "$stime"     =~ ^[0-9]+$ ]] || { printf '0 0'; return 0; }
    [[ "$starttime" =~ ^[0-9]+$ ]] || { printf '0 0'; return 0; }

    clk_tck="$(getconf CLK_TCK 2>/dev/null || echo 100)"
    [[ "$clk_tck" =~ ^[0-9]+$ ]] && (( clk_tck > 0 )) || clk_tck=100

    uptime_s="$(awk '{printf "%d", $1}' /proc/uptime 2>/dev/null)"
    [[ "$uptime_s" =~ ^[0-9]+$ ]] || { printf '0 0'; return 0; }

    total_s=$(( (utime + stime) / clk_tck ))
    elapsed_s=$(( uptime_s - starttime / clk_tck ))

    (( elapsed_s > 0 )) || { printf '0 0'; return 0; }

    printf '%d %d' $(( total_s * 100 / elapsed_s )) "$elapsed_s"
}

# ------------------------------------------------------------
# CHECK 1 - sustained CPU consumption
#
# The check the EDR did not have. A process averaging >90% CPU
# for more than five minutes is doing continuous computation.
# On a mail server there is no legitimate reason for that.
# ------------------------------------------------------------

check_sustained_cpu() {

    local pid comm exe user cpu elapsed uid found=0 sev conf reasons

    while IFS= read -r pid; do

        [[ "$pid" =~ ^[0-9]+$ ]] || continue
        [[ -d "/proc/$pid" ]] || continue

        crypto_is_kernel_thread "$pid" && continue

        read -r cpu elapsed <<< "$(crypto_cpu_percent "$pid")"

        (( cpu >= CRYPTO_CPU_THRESHOLD )) || continue
        (( elapsed >= CRYPTO_CPU_MIN_RUNTIME )) || continue

        exe="$(readlink "/proc/$pid/exe" 2>/dev/null)" || continue
        comm="$(tr -d '\0' < "/proc/$pid/comm" 2>/dev/null)"

        proc_read_status "$pid" || continue
        uid="$PROC_UID"
        user="$(uid_to_name "$uid")"

        crypto_comm_allowed "$comm" && continue
        crypto_user_allowed "$user" && continue

        found=$(( found + 1 ))

        # Severity rises with corroboration. Sustained CPU alone
        # is suspicious; sustained CPU from a volatile directory
        # is what the incident actually looked like.
        sev=HIGH
        conf=70
        reasons="Process has averaged ${cpu}% CPU over ${elapsed}s of runtime
Sustained full-core computation is the defining behaviour of a cryptominer
This check exists because signature-based EDR missed exactly this pattern for 40+ minutes"

        case "$exe" in
            /tmp/*|/var/tmp/*|/dev/shm/*)
                sev=CRITICAL
                conf=95
                reasons="$reasons
The executable lives in a volatile directory (${exe%/*}), where nothing legitimate runs from" ;;
        esac

        if [[ ! -e "$exe" ]]; then
            sev=CRITICAL
            conf=95
            reasons="$reasons
The executable has been DELETED from disk while still running - deliberate anti-forensics"
        fi

        add_finding "$sev" \
            "Sustained high CPU: possible cryptominer" \
            id="crypto-cpu:$exe:$pid" \
            event=CRYPTO_SUSTAINED_CPU \
            path="$exe" \
            confidence="$conf" \
            reasons="$reasons" \
            process="$(crypto_proc_evidence "$pid")" \
            network="$(crypto_proc_connections "$pid")" \
            evidence="cpu_average=${cpu}% runtime=${elapsed}s user=${user} comm=${comm}
sha256=$(file_sha256 "$exe") mtime=$(file_mtime_human "$exe")
package=$(pkg_owner "$exe")" \
            action="Do NOT kill it yet. Capture /proc/${pid}/exe, cmdline, maps and open sockets first, then check where it is connecting. If this is a legitimate workload, add its process name to CRYPTO_CPU_ALLOW_COMMS in ${ITM_AUDIT_CONF} so it stops being reported."

    done < <(find /proc -maxdepth 1 -regex '/proc/[0-9]+' -printf '%f\n' 2>/dev/null)

    (( found == 0 )) \
        && add_pass "no process sustaining >=${CRYPTO_CPU_THRESHOLD}% CPU beyond ${CRYPTO_CPU_MIN_RUNTIME}s"
}

# ------------------------------------------------------------
# CHECK 2 - payload artefacts in volatile directories
#
# Executable files in /tmp, /var/tmp and /dev/shm, whether or not
# anything is running them right now. The dropper survives a kill;
# the file is what re-infects.
#
# Hidden names are called out separately: .rguard and .khp were
# both dotfiles, which keeps them out of a plain ls.
# ------------------------------------------------------------

check_volatile_payloads() {

    local dir file found=0 ftype sev conf reasons hidden

    for dir in $CRYPTO_VOLATILE_DIRS; do

        [[ -d "$dir" ]] || continue

        while IFS= read -r file; do

            [[ -n "$file" ]] || continue
            [[ -f "$file" ]] || continue

            # Skip our own evidence and quarantine trees.
            case "$file" in
                */itm-security/*|/root/forensic/*) continue ;;
            esac

            crypto_path_excluded "$file" && continue

            ftype="$(run_timeout 10 file -b "$file" 2>/dev/null)"

            # Only executables and scripts matter here. A .png in
            # /tmp is noise; an ELF in /var/tmp is the incident.
            case "$ftype" in
                *ELF*|*executable*|*script*) ;;
                *) continue ;;
            esac

            found=$(( found + 1 ))

            hidden=no
            [[ "$(basename -- "$file")" == .* ]] && hidden=yes

            sev=HIGH
            conf=80
            reasons="Executable file in a volatile directory (${dir})
Nothing in a normal server deployment installs an executable here
This is where the miner, its watchdog and its dropper were all found in the incident"

            if [[ "$hidden" == "yes" ]]; then
                sev=CRITICAL
                conf=90
                reasons="$reasons
The filename is HIDDEN (leading dot) - it does not appear in a plain ls, which is how .rguard and .khp stayed unnoticed"
            fi

            case "$ftype" in
                *ELF*)
                    conf=$(( conf + 5 ))
                    (( conf > 99 )) && conf=99
                    reasons="$reasons
The file is a compiled ELF binary, not a config or data file" ;;
            esac

            add_finding "$sev" \
                "Executable dropped in a volatile directory" \
                id="crypto-volatile-file:$file" \
                event=CRYPTO_VOLATILE_PAYLOAD \
                path="$file" \
                confidence="$conf" \
                reasons="$reasons" \
                evidence="type=${ftype}
owner=$(stat -Lc '%U:%G' "$file" 2>/dev/null) mode=$(stat -Lc '%a' "$file" 2>/dev/null) size=$(stat -Lc '%s' "$file" 2>/dev/null)
sha256=$(file_sha256 "$file") mtime=$(file_mtime_human "$file")
running_now=$(crypto_file_is_running "$file")" \
                action="Preserve it before anything else: copy to /root/forensic and record the SHA256. Then find what wrote it and what re-creates it - a dropper survives deleting the miner. Do not delete until the persistence is understood."

        done < <(run_scan 60 find "$dir" -maxdepth 2 -type f \
                    \( -perm -u+x -o -name '.*' \) -print 2>/dev/null | head -100)
    done

    (( found == 0 )) \
        && add_pass "no executable or hidden file in ${CRYPTO_VOLATILE_DIRS// /, }"
}

# Is any live process executing this exact file?
crypto_file_is_running() {
    local target="$1" pid exe
    for pid in $(find /proc -maxdepth 1 -regex '/proc/[0-9]+' -printf '%f\n' 2>/dev/null); do
        exe="$(readlink "/proc/$pid/exe" 2>/dev/null)" || continue
        [[ "$exe" == "$target" ]] && { printf 'yes (pid %s)' "$pid"; return 0; }
    done
    printf 'no'
}

# ------------------------------------------------------------
# CHECK 3 - the rival killer
#
# .rguard killed every process whose command line contained
# /tmp/, every 0.1 seconds, to eliminate competing miners. It
# took Zimbra's MySQL with it because the MySQL socket path
# contains /tmp/.
#
# A process that repeatedly signals other processes is doing
# something no ordinary service does, and it is worth finding
# before it takes a database down again.
# ------------------------------------------------------------

check_process_killers() {

    local pid exe cmdline found=0 comm

    while IFS= read -r pid; do

        [[ "$pid" =~ ^[0-9]+$ ]] || continue
        [[ -d "/proc/$pid" ]] || continue
        crypto_is_kernel_thread "$pid" && continue

        cmdline="$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)"
        [[ -n "$cmdline" ]] || continue

        # Do not report the audit's own process tree. Running a
        # check whose description contains these words must not
        # make the checker report itself.
        case "$pid" in
            "$$"|"$PPID") continue ;;
        esac
        case "$cmdline" in
            *itm-security*|*audit_cryptominer*) continue ;;
        esac

        # A kill verb used as a COMMAND, not merely mentioned.
        # Requiring a word boundary keeps an ordinary admin script
        # that happens to contain the word "pkill" in a string or
        # a comment out of the results.
        case "$cmdline" in
            *pkill\ *|*killall\ *|*"kill -9 "*) ;;
            *) continue ;;
        esac

        # ...aimed at a path pattern, which is what made this
        # malware lethal: it matched a substring anywhere in a
        # command line, so Zimbra's MySQL died because its socket
        # path contains /tmp/.
        case "$cmdline" in
            */tmp/*|*/var/tmp/*|*/dev/shm/*) ;;
            *) continue ;;
        esac

        # ...in a TIGHT loop. This is the distinguishing feature.
        #
        # A maintenance script that cleans /tmp once an hour also
        # matches everything above; .rguard ran every 0.1s. Only
        # a sub-second interval, or a loop with no sleep at all,
        # is the rival-killer shape. Without this condition the
        # check fired on the very shell that was testing it.
        local tight=0
        case "$cmdline" in
            *usleep*)            tight=1 ;;
            *"sleep 0."*)        tight=1 ;;
            *"sleep 0"*)         tight=1 ;;
        esac

        # A loop that never sleeps is tighter still.
        case "$cmdline" in
            *while*|*for*)
                case "$cmdline" in
                    *sleep*) ;;
                    *) tight=1 ;;
                esac ;;
        esac

        (( tight )) || continue

        exe="$(readlink "/proc/$pid/exe" 2>/dev/null)"
        comm="$(tr -d '\0' < "/proc/$pid/comm" 2>/dev/null)"
        found=$(( found + 1 ))

        add_finding CRITICAL \
            "Process loop killing other processes by path pattern" \
            id="crypto-rival-killer:$pid" \
            event=CRYPTO_RIVAL_KILLER \
            path="${exe:-unknown}" \
            confidence=90 \
            reasons="A resident process repeatedly kills others matching a path pattern
This is the 'rival killer' pattern: malware eliminating competing miners
It matches on a substring, so it kills legitimate services whose command line happens to contain that path
In the incident this killed Zimbra's MySQL every 0.1s because the MySQL socket path contains /tmp/" \
            process="$(crypto_proc_evidence "$pid")" \
            evidence="cmdline=$(truncate_text "$cmdline" 300)
comm=${comm} exe=${exe:-unknown}" \
            action="This is almost certainly malware. Capture the process and its parent before stopping anything. If a database or mail service on this host has been dying repeatedly with no explanation, this is why."

    done < <(find /proc -maxdepth 1 -regex '/proc/[0-9]+' -printf '%f\n' 2>/dev/null)

    (( found == 0 )) && add_pass "no process-killing loop detected"
}

# ------------------------------------------------------------
# CHECK 4 - Zimbra SNMP exposure
#
# The entry vector. Pre-authentication command injection in the
# Zimbra SNMP component on UDP/161, fixed in 10.1.20.
#
# The firewall restriction applied after the incident is not
# visible from here and may not exist on another host, so the
# check reports the exposure itself rather than assuming a
# control is in place.
# ------------------------------------------------------------

check_zimbra_snmp() {

    local snmp_line listen_addr

    have_cmd ss || { add_skip "ss unavailable - SNMP exposure not checked"; return 0; }

    snmp_line="$(run_timeout 10 ss -lnup 2>/dev/null | awk '$5 ~ /:161$/')"

    if [[ -z "$snmp_line" ]]; then
        add_pass "no SNMP listener on UDP/161"
        return 0
    fi

    listen_addr="$(printf '%s' "$snmp_line" | awk '{print $5}' | head -1)"

    # Bound to loopback only is not exposure.
    case "$listen_addr" in
        127.0.0.1:161|\[::1\]:161)
            add_pass "SNMP listens on loopback only (${listen_addr})"
            return 0 ;;
    esac

    add_finding HIGH \
        "SNMP is listening on a non-loopback address on a Zimbra host" \
        id="zimbra-snmp-exposed:$listen_addr" \
        event=ZIMBRA_SNMP_EXPOSED \
        path="UDP/161" \
        confidence=85 \
        reasons="SNMP on UDP/161 is reachable beyond loopback (${listen_addr})
This is the entry vector used against a Zimbra host on this estate: pre-authentication command injection in the SNMP component
The vulnerability is pre-auth, so no credential is needed to exploit it
A firewall rule may already restrict this, but that cannot be confirmed from the listener alone" \
        network="$(printf '%s' "$snmp_line" | head -3)" \
        evidence="listener=${listen_addr}
$(printf '%s' "$snmp_line" | head -3)" \
        action="Confirm a firewall rule restricts UDP/161 to management addresses only, and verify the restriction actually blocks from outside. Patch Zimbra to 10.1.20 or later, which is where this injection is fixed. Do not rely on the listener being 'internal only' without testing it."
}

# ------------------------------------------------------------
# CHECK 5 - Zimbra version against the known-vulnerable release
#
# Reported, never changed. Upgrading a mail server is a planned
# maintenance action, not something an audit tool decides.
# ------------------------------------------------------------

check_zimbra_version() {

    local version_raw version

    [[ -x /opt/zimbra/bin/zmcontrol ]] || {
        add_skip "zmcontrol not present - Zimbra version not determined"
        return 0
    }

    version_raw="$(run_timeout "$CMD_TIMEOUT" /opt/zimbra/bin/zmcontrol -v 2>/dev/null | head -1 | tr -d '\r')"

    if [[ -z "$version_raw" ]]; then
        add_skip "zmcontrol returned no version string"
        return 0
    fi

    version="$(printf '%s' "$version_raw" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"

    if [[ -z "$version" ]]; then
        add_skip "could not parse a version from: $(truncate_text "$version_raw" 100)"
        return 0
    fi

    if crypto_version_lt "$version" "10.1.20"; then
        add_finding HIGH \
            "Zimbra is below the release that fixes the SNMP command injection" \
            id="zimbra-version-vulnerable:$version" \
            event=ZIMBRA_VERSION_VULNERABLE \
            path="/opt/zimbra" \
            confidence=90 \
            reasons="Installed version ${version} is older than 10.1.20
The pre-authentication SNMP command injection is fixed in 10.1.20
A host on this estate was compromised through exactly this path
Restricting SNMP at the firewall reduces exposure but does not remove the vulnerability" \
            evidence="zmcontrol -v: $(truncate_text "$version_raw" 200)
installed=${version} fixed_in=10.1.20" \
            action="Plan an upgrade to 10.1.20 or later with the mail service owner. This audit does not change Zimbra: upgrading a mail server is planned maintenance. Until it is patched, keep UDP/161 restricted and verify the restriction from outside."
    else
        add_pass "Zimbra ${version} is at or above the patched release (10.1.20)"
    fi
}

# Numeric version comparison: is $1 strictly lower than $2?
crypto_version_lt() {
    local a="$1" b="$2"
    [[ "$a" == "$b" ]] && return 1
    [[ "$(printf '%s\n%s\n' "$a" "$b" | sort -V | head -1)" == "$a" ]]
}

# ------------------------------------------------------------
# CHECK 6 - outbound connections from the mail service account
#
# A miner has to reach a pool. Zimbra's own processes talk to
# mail peers and to the local database; they do not open long
# lived sessions to arbitrary hosts on mining ports.
# ------------------------------------------------------------

# Ports commonly used by mining pools. Presence alone is not
# proof - it raises an existing connection from noise to finding.
CRYPTO_POOL_PORTS="${CRYPTO_POOL_PORTS:-3333 4444 5555 7777 8888 9999 14433 14444 45560 45700}"

check_miner_egress() {

    local line raddr rport proc pid found=0 user exe

    have_cmd ss || { add_skip "ss unavailable - egress not checked"; return 0; }

    while IFS= read -r line; do

        [[ -n "$line" ]] || continue

        raddr="$(printf '%s' "$line" | awk '{print $6}')"
        [[ -n "$raddr" ]] || continue

        rport="${raddr##*:}"
        [[ "$rport" =~ ^[0-9]+$ ]] || continue

        pid="$(printf '%s' "$line" | grep -oE 'pid=[0-9]+' | head -1)"
        pid="${pid#pid=}"
        [[ "$pid" =~ ^[0-9]+$ ]] || continue

        exe="$(readlink "/proc/$pid/exe" 2>/dev/null)"
        proc_read_status "$pid" 2>/dev/null || continue
        user="$(uid_to_name "$PROC_UID")"

        local is_pool_port=0 is_volatile=0
        case " $CRYPTO_POOL_PORTS " in
            *" $rport "*) is_pool_port=1 ;;
        esac
        case "$exe" in
            /tmp/*|/var/tmp/*|/dev/shm/*) is_volatile=1 ;;
        esac

        (( is_pool_port || is_volatile )) || continue

        # Trusted destinations are not the concern here.
        ip_is_trusted "${raddr%:*}" && continue

        found=$(( found + 1 ))

        local sev=HIGH conf=75
        local reasons="Outbound session to ${raddr} from ${exe:-unknown} running as ${user}"

        (( is_pool_port )) && reasons="$reasons
Destination port ${rport} is commonly used by cryptomining pools"

        if (( is_volatile )); then
            sev=CRITICAL
            conf=95
            reasons="$reasons
The connecting binary runs from a volatile directory - this is the miner calling home"
        fi

        add_finding "$sev" \
            "Outbound connection consistent with cryptomining" \
            id="crypto-egress:$raddr:$exe" \
            event=CRYPTO_POOL_EGRESS \
            path="${exe:-unknown}" \
            confidence="$conf" \
            reasons="$reasons" \
            process="$(crypto_proc_evidence "$pid")" \
            network="$(truncate_text "$line" 300)" \
            evidence="remote=${raddr} user=${user} exe=${exe:-unknown}
sha256=$(file_sha256 "${exe:-/nonexistent}")" \
            action="Block the destination at the perimeter first so the session is cut without warning whoever is operating it, then capture the process. Do not kill it before it is captured."

    done < <(run_timeout "$CMD_TIMEOUT" ss -tnp state established 2>/dev/null | tail -n +2)

    (( found == 0 )) && add_pass "no outbound session on a mining pool port or from a volatile directory"
}

# ------------------------------------------------------------
# Entry point
# ------------------------------------------------------------

run_audit_cryptominer() {

    module_begin cryptominer "Cryptojacking / Zimbra"

    # The behavioural checks apply to every host: a miner on a
    # web server is the same problem as a miner on a mail server,
    # and the incident showed that whatever the EDR is doing is
    # not enough on its own.
    check_sustained_cpu
    check_volatile_payloads
    check_process_killers
    check_miner_egress

    # The Zimbra specific checks only mean anything on a Zimbra
    # host. Reporting "SNMP not exposed" on a host that has no
    # Zimbra would be a PASS about a check that examined nothing.
    if role_is zimbra; then
        check_zimbra_snmp
        check_zimbra_version
    else
        add_na "Zimbra checks: NOT APPLICABLE to this host role" \
            id="na:zimbra" \
            evidence="No Zimbra installation found (/opt/zimbra absent and no zimbra account).
The behavioural cryptominer checks above still ran on this host." \
            action="No action. The SNMP and Zimbra version checks apply only to Zimbra hosts."
    fi

    module_end
}

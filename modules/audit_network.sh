#!/usr/bin/env bash
# shellcheck shell=bash

# ============================================================
# ITM Server Security Monitor
# Post-Compromise Audit - Module B: network exposure
#
# Read only. No firewall rule is added, changed or removed.
#
# As with the process module, the kernel tables in /proc/net
# are treated as ground truth and ss(1) output is compared back
# against them. A listening socket that exists in the kernel
# but not in ss output indicates a filtering wrapper.
#
# Trusted networks come from trusted_networks.conf. Nothing
# site specific is hardcoded here.
# ============================================================

# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------

# ------------------------------------------------------------
# Parsing helpers
#
# These run once per socket. On a host with a few hundred
# sockets, every command substitution here is a fork, so the
# parsing is done with bash builtins only: SS_NAME, SS_PID,
# SS_ADDR and SS_PORT are set as globals instead of printed.
# ------------------------------------------------------------

SS_NAME=""; SS_PID=0; SS_ADDR=""; SS_PORT=""

# "users:((\"nginx\",pid=1234,fd=6))" -> SS_NAME, SS_PID
ss_parse_proc() {
    SS_NAME="unknown"; SS_PID=0
    if [[ "$1" =~ users:\(\(\"([^\"]+)\",pid=([0-9]+) ]]; then
        SS_NAME="${BASH_REMATCH[1]}"
        SS_PID="${BASH_REMATCH[2]}"
    fi
}

# "0.0.0.0:80" / "[::]:443" / "*:111" -> SS_ADDR, SS_PORT
ss_parse_addr() {
    local ap="$1"
    SS_PORT="${ap##*:}"
    SS_ADDR="${ap%:*}"
    SS_ADDR="${SS_ADDR#[}"
    SS_ADDR="${SS_ADDR%]}"
    [[ -n "$SS_ADDR" ]] || SS_ADDR="*"
}

port_in_list() {
    local port="$1" list="$2" p
    for p in $list; do
        [[ "$port" == "$p" ]] && return 0
    done
    return 1
}

addr_is_loopback() {
    case "$1" in
        127.*|::1) return 0 ;;
    esac
    return 1
}

# Multicast and link-local group membership shows up in ss as a
# listening UDP socket. It is service discovery, not exposure.
addr_is_multicast() {
    case "$1" in
        22[4-9].*|23[0-9].*|ff0*:*|ff1*:*|ff2*:*|fe80:*) return 0 ;;
    esac
    return 1
}

proc_is_allowed_outbound() {
    local name="$1" p
    for p in $OUTBOUND_ALLOW_PROCS; do
        [[ "$name" == "$p" ]] && return 0
    done
    return 1
}

# Executable behind a PID, for outbound attribution.
pid_exe() {
    local pid="$1"
    [[ "$pid" =~ ^[0-9]+$ ]] || { printf 'unknown'; return 0; }
    readlink "/proc/$pid/exe" 2>/dev/null || printf 'unreadable'
}

pid_user() {
    local pid="$1"
    [[ "$pid" =~ ^[0-9]+$ ]] || { printf 'unknown'; return 0; }
    proc_read_status "$pid" || { printf 'unknown'; return 0; }
    uid_to_name "$PROC_UID"
}

# ------------------------------------------------------------
# Kernel socket table versus ss output
# ------------------------------------------------------------

kernel_listen_ports() {

    local file hexport

    for file in /proc/net/tcp /proc/net/tcp6; do
        [[ -r "$file" ]] || continue
        # Field 2 = local_address (hex addr:hex port), field 4 = state.
        # State 0A = TCP_LISTEN.
        awk 'NR > 1 && $4 == "0A" { split($2, a, ":"); print a[2] }' "$file" 2>/dev/null
    done | while read -r hexport; do
        [[ -n "$hexport" ]] && printf '%d\n' "$(( 16#$hexport ))"
    done | sort -un
}

check_hidden_listeners() {

    have_cmd ss || {
        add_skip "ss not available - hidden listener cross check skipped"
        return 0
    }

    local ss_ports kernel_ports port hidden=()

    ss_ports="$ITM_RUN_TMP/ss_ports.txt"
    kernel_ports="$ITM_RUN_TMP/kernel_ports.txt"

    run_timeout "$CMD_TIMEOUT" ss -ltn 2>/dev/null \
        | awk 'NR > 1 {n = split($4, a, ":"); print a[n]}' \
        | grep -E '^[0-9]+$' | sort -un > "$ss_ports"

    kernel_listen_ports > "$kernel_ports"

    if [[ ! -s "$kernel_ports" ]]; then
        add_skip "/proc/net/tcp unreadable - hidden listener cross check skipped"
        return 0
    fi

    while read -r port; do
        [[ -n "$port" ]] || continue
        grep -qx "$port" "$ss_ports" || hidden+=("$port")
    done < "$kernel_ports"

    if (( ${#hidden[@]} == 0 )); then
        add_pass "ss output consistent with /proc/net (no hidden listening port)"
        return 0
    fi

    for port in "${hidden[@]}"; do
        add_finding CRITICAL \
            "TCP port listening in the kernel but hidden from ss output" \
            id="hidden-listener:$port" \
            network="tcp/$port LISTEN (kernel table only)" \
            evidence="Port $port appears as TCP_LISTEN in /proc/net/tcp but is absent from 'ss -ltn'. This indicates a wrapper filtering socket output, or a socket in a state ss was told to hide." \
            action="Verify ss and netstat against package hashes (see the command module). Preserve the binaries, do not replace them yet, and isolate the host."
    done
}

# ------------------------------------------------------------
# Listener inventory and exposure policy
# ------------------------------------------------------------

check_listeners() {

    have_cmd ss || {
        add_skip "ss not available - listener audit skipped"
        return 0
    }

    # ss -tulnp columns: Netid State Recv-Q Send-Q Local Peer Process
    local line proto laddr addr port procfield pname ppid
    local total=0 exposed_db=0 unexpected=0
    local -A UNEXPECTED_PORTS=()

    [[ -s "$ITM_RUN_TMP/listeners.txt" ]] || \
        run_timeout "$CMD_TIMEOUT" ss -tulnp > "$ITM_RUN_TMP/listeners.txt" 2>/dev/null

    if [[ ! -s "$ITM_RUN_TMP/listeners.txt" ]]; then
        add_skip "ss returned no listener output"
        return 0
    fi

    while IFS= read -r line; do

        case "$line" in
            Netid*|State*|"") continue ;;
        esac

        read -r proto _ _ _ laddr _ <<< "$line"

        case "$proto" in
            tcp|udp) ;;
            *) continue ;;
        esac

        ss_parse_addr "$laddr"
        addr="$SS_ADDR"
        port="$SS_PORT"
        [[ "$port" =~ ^[0-9]+$ ]] || continue

        ss_parse_proc "$line"
        pname="$SS_NAME"
        ppid="$SS_PID"
        total=$(( total + 1 ))

        # ---- database ports ------------------------------------
        if port_in_list "$port" "$DB_PORTS"; then

            if addr_is_loopback "$addr"; then
                continue
            fi

            exposed_db=$(( exposed_db + 1 ))

            local sev="MEDIUM" scope="beyond loopback"

            case "$addr" in
                0.0.0.0|::|"*")
                    sev="MEDIUM"
                    scope="all interfaces" ;;
                *)
                    if ! ip_is_private "$addr"; then
                        sev="HIGH"
                        scope="a public address"
                    fi
                    ;;
            esac

            add_finding "$sev" \
                "Database port exposed $scope" \
                id="db-exposed:$port:$addr" \
                network="$proto/$port bound to $addr" \
                process="$pname (pid ${ppid})" \
                evidence="Listener $laddr owned by $pname. Policy allows database access from trusted networks only; the bind address does not enforce that." \
                action="Bind the service to 127.0.0.1 or the management interface, and restrict $port at the firewall to: ${TRUSTED_NETWORKS[*]:-trusted networks}. Do not change this during an active incident without a maintenance window."
            continue
        fi

        # ---- unexpected listening ports ------------------------
        #
        # Collected per PROCESS, not per port. One application
        # binding an ephemeral UDP port on twelve interfaces is
        # one fact, not twelve findings, and reporting it twelve
        # times is how an alert channel becomes unreadable.
        if ! port_in_list "$port" "$ALLOWED_LISTEN_PORTS"; then

            addr_is_loopback "$addr"  && continue
            addr_is_multicast "$addr" && continue

            unexpected=$(( unexpected + 1 ))

            local pkey="${pname:-unknown}|${ppid}"
            UNEXPECTED_PORTS["$pkey"]="${UNEXPECTED_PORTS[$pkey]:-}${proto}/${port}@${addr} "
        fi

    done < "$ITM_RUN_TMP/listeners.txt"

    # ---- one finding per process, scored ----------------------
    #
    # A deleted executable is the headline signal of a fileless
    # implant AND the ordinary result of upgrading a package
    # while its service is running. On its own it is therefore
    # worth points, not a CRITICAL: what makes it an incident is
    # the combination with root ownership, a public bind address
    # and a binary no package owns.
    local pkey pname2 ppid2 portlist uexe uuser
    for pkey in "${!UNEXPECTED_PORTS[@]}"; do

        pname2="${pkey%%|*}"
        ppid2="${pkey##*|}"
        portlist="${UNEXPECTED_PORTS[$pkey]}"

        uexe="$(pid_exe "$ppid2")"
        uuser="$(pid_user "$ppid2")"

        score_reset
        score_add 10 "listening on port(s) outside the expected service policy"

        [[ "$uexe" == *"(deleted)" ]] && \
            score_add 35 "the running binary has been DELETED from disk (also happens when a package is upgraded while its service runs)"

        is_volatile_path "$uexe" && \
            score_add 45 "runs from a temporary directory"

        [[ "$pname2" == \[*\]* ]] && \
            score_add 45 "process name imitates a kernel thread"

        if [[ "$uexe" == /* ]] && ! is_pkg_owned "$uexe" && ! is_itm_binary "$uexe"; then
            score_add 25 "binary is owned by no package"
        fi

        [[ "$uuser" == "root" ]] && score_add 15 "listening as root"

        case "$portlist" in
            *"@0.0.0.0"*|*"@::"*|*"@*"*) score_add 15 "bound to all interfaces" ;;
        esac

        [[ "$ppid2" == "0" || -z "$ppid2" ]] && \
            score_add 30 "no owning process could be attributed to the socket"

        # Below LOW this is inventory, not a finding.
        (( SCORE_TOTAL >= SCORE_THRESHOLD_LOW )) || continue

        add_finding "$(score_severity)" \
            "Listening port(s) outside the expected service policy" \
            id="unexpected-listener:$pname2:$uexe" \
            event=NET_UNEXPECTED_LISTENER \
            confidence="$(score_confidence)" \
            reasons="$SCORE_REASONS" \
            network="$(truncate_text "$portlist" 300)" \
            process="$pname2 (pid ${ppid2}) exe=$uexe user=$uuser package=$(pkg_owner "$uexe")" \
            evidence="Ports not in ALLOWED_LISTEN_PORTS: $(truncate_text "$portlist" 400)" \
            action="Confirm the service is intentional and firewalled. If it is expected, add the port(s) to ALLOWED_LISTEN_PORTS in ${ITM_AUDIT_CONF}. A deleted binary on a service you did not just upgrade is a different matter: preserve it before restarting anything."

    done

    audit_log INFO "enumerated $total listening sockets"

    (( exposed_db == 0 )) && add_pass "no database port exposed beyond loopback"
    (( unexpected == 0 )) && add_pass "all externally bound listeners are within policy"
}

# ------------------------------------------------------------
# Outbound sessions
# ------------------------------------------------------------

check_outbound() {

    have_cmd ss || {
        add_skip "ss not available - outbound audit skipped"
        return 0
    }

    local line state raddr rip rport procfield pname ppid puser pexe
    local suspicious=0 total=0

    [[ -s "$ITM_RUN_TMP/estab.txt" ]] || \
        run_timeout "$CMD_TIMEOUT" ss -tnp > "$ITM_RUN_TMP/estab.txt" 2>/dev/null

    [[ -s "$ITM_RUN_TMP/estab.txt" ]] || {
        add_pass "no established TCP session to evaluate"
        return 0
    }

    while IFS= read -r line; do

        read -r state _ _ _ raddr _ <<< "$line"
        [[ "$state" == "ESTAB" ]] || continue

        ss_parse_addr "$raddr"
        rip="$SS_ADDR"
        rport="$SS_PORT"

        total=$(( total + 1 ))

        ip_is_trusted "$rip" && continue

        ss_parse_proc "$line"
        pname="$SS_NAME"
        ppid="$SS_PID"

        puser="$(pid_user "$ppid")"
        pexe="$(pid_exe "$ppid")"

        # Only root owned egress is treated as a finding here.
        # Application level egress (php-fpm, nginx) is normal on
        # a web server and would drown the report.
        [[ "$puser" == "root" ]] || continue

        local sev=MEDIUM
        local why="Root owned process holds an outbound session to an address outside the trusted networks."

        if [[ "$pexe" == *"(deleted)" ]]; then
            sev=CRITICAL
            why="Root process with a DELETED executable holds an outbound session. This matches the C2 beacon pattern seen in the previous incident on this estate."
        elif is_volatile_path "$pexe"; then
            sev=CRITICAL
            why="Root process executing from a temporary directory holds an outbound session."
        elif proc_is_allowed_outbound "$pname"; then
            continue
        elif ! is_pkg_owned "$pexe" && ! is_itm_binary "$pexe"; then
            sev=HIGH
            why="Root process running an unpackaged binary holds an outbound session."
        fi

        suspicious=$(( suspicious + 1 ))

        add_finding "$sev" \
            "Outbound connection from a root process outside the trusted networks" \
            id="outbound:$pname:$pexe:$rport" \
            path="$pexe" \
            process="$pname (pid ${ppid}) user=$puser package=$(pkg_owner "$pexe")" \
            network="ESTAB -> ${rip}:${rport}" \
            evidence="$why Remote ${rip}:${rport} is not covered by trusted_networks.conf." \
            action="Do not kill the process. Capture: ls -l /proc/${ppid}/exe ; cat /proc/${ppid}/cmdline ; ss -tnp state established. Correlate the remote address with threat intelligence and block it at the perimeter first."

    done < "$ITM_RUN_TMP/estab.txt"

    audit_log INFO "evaluated $total established TCP sessions"

    (( suspicious == 0 )) && add_pass "no unexplained root owned outbound session"
}


# ------------------------------------------------------------
# Process attribution
#
# "which process owns this socket" is the question that decides
# whether a connection is routine or an incident. Four answers
# are bad news, in rising order:
#
#   unpackaged binary   nobody can account for it
#   deleted executable  it unlinked itself after starting
#   volatile path       it runs from /tmp or /dev/shm
#   NOT ATTRIBUTABLE    ss shows a socket with no owning process
#
# The last one matters most and is easy to dismiss: as root it
# should never happen for a local process. When it does, the
# socket usually belongs to another namespace (a container) or
# to something actively hiding.
# ------------------------------------------------------------

NET_PROCESS_VERDICT=""
NET_PROCESS_SCORE=0

net_classify_process() {

    local pname="$1" ppid="$2"
    local exe user pkg

    NET_PROCESS_VERDICT=""
    NET_PROCESS_SCORE=0

    if [[ -z "$ppid" || "$ppid" == "0" ]]; then
        NET_PROCESS_VERDICT="socket has NO owning process visible"
        NET_PROCESS_SCORE=45
        if ! is_root; then
            NET_PROCESS_VERDICT="$NET_PROCESS_VERDICT (audit is not running as root, which alone explains it)"
            NET_PROCESS_SCORE=10
        fi
        return 0
    fi

    exe="$(pid_exe "$ppid")"
    user="$(pid_user "$ppid")"

    if [[ "$exe" == *"(deleted)" ]]; then
        NET_PROCESS_VERDICT="process runs a DELETED executable ($exe), owner $user"
        NET_PROCESS_SCORE=55
        return 0
    fi

    if is_volatile_path "$exe"; then
        NET_PROCESS_VERDICT="process runs from a temporary directory ($exe), owner $user"
        NET_PROCESS_SCORE=50
        return 0
    fi

    # A bracketed name with a real executable is the exec -a
    # kernel-thread disguise.
    if [[ "$pname" == \[*\]* ]]; then
        NET_PROCESS_VERDICT="process name '$pname' imitates a kernel thread while having an executable ($exe)"
        NET_PROCESS_SCORE=55
        return 0
    fi

    if [[ "$exe" == /* ]] && ! is_pkg_owned "$exe" && ! is_itm_binary "$exe"; then
        pkg="$(pkg_owner "$exe")"
        NET_PROCESS_VERDICT="process runs an unpackaged binary ($exe, package=$pkg), owner $user"
        NET_PROCESS_SCORE=35
        return 0
    fi

    NET_PROCESS_VERDICT="process $pname ($exe) owned by $user, package $(pkg_owner "$exe")"
    NET_PROCESS_SCORE=0
    return 0
}

# ------------------------------------------------------------
# Listener baseline
#
# The inventory alone is noise; the CHANGE is the signal. A port
# that was not listening yesterday and is listening today is
# worth one alert, and the same port tomorrow is worth none.
# ------------------------------------------------------------

NET_LISTENER_BASELINE="${NET_LISTENER_BASELINE:-$ITM_SCAN_STATE_DIR/listeners.baseline}"

check_listener_baseline() {

    local current="$ITM_RUN_TMP/listeners.now"
    local line proto laddr addr port pname ppid key
    local new_count=0 first_run=0

    : > "$current"

    while IFS= read -r line; do
        case "$line" in Netid*|State*|"") continue ;; esac
        read -r proto _ _ _ laddr _ <<< "$line"
        case "$proto" in tcp|udp) ;; *) continue ;; esac
        ss_parse_addr "$laddr"
        [[ "$SS_PORT" =~ ^[0-9]+$ ]] || continue
        addr_is_multicast "$SS_ADDR" && continue
        ss_parse_proc "$line"
        printf '%s/%s|%s|%s\n' "$proto" "$SS_PORT" "$SS_ADDR" "$SS_NAME" >> "$current"
    done < "$ITM_RUN_TMP/listeners.txt"

    sort -u -o "$current" "$current" 2>/dev/null

    if [[ ! -s "$NET_LISTENER_BASELINE" ]]; then
        first_run=1
    fi

    # Report what is listening right now, always: an operator
    # reading the report should not have to run ss themselves.
    add_pass "listening sockets ($(wc -l < "$current")): $(awk -F'|' '{printf "%s(%s) ", $1, $3}' "$current" | truncate_text_stdin 600)"

    if (( first_run )); then
        add_finding INFO \
            "Listener baseline created" \
            id="net-listener-baseline-created" \
            event=NET_LISTENER_BASELINE \
            status=CHECK_PASS \
            evidence="$(wc -l < "$current") listening sockets recorded as the reference state.
A baseline records what is listening NOW; it does not assert that all of it is legitimate." \
            action="Review the list above once. From the next run, only NEW listeners are reported."
    else
        while IFS='|' read -r key addr pname; do

            [[ -n "$key" ]] || continue
            grep -qF -- "$key|$addr|$pname" "$NET_LISTENER_BASELINE" && continue

            new_count=$(( new_count + 1 ))

            local port="${key#*/}"
            local ppid=""
            ppid="$(grep -F "$port" "$ITM_RUN_TMP/listeners.txt" 2>/dev/null | head -1 | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2)"

            net_classify_process "$pname" "$ppid"

            score_reset
            score_add 30 "a network service is listening that was not present at the last check"
            addr_is_loopback "$addr" || score_add 20 "bound to ${addr}, reachable from outside this host"
            (( NET_PROCESS_SCORE > 0 )) && score_add "$NET_PROCESS_SCORE" "$NET_PROCESS_VERDICT"
            port_in_list "$port" "$ALLOWED_LISTEN_PORTS" || score_add 15 "port is not in the expected service policy"

            add_finding "$(score_severity)" \
                "New listening port appeared: $key" \
                id="net-new-listener:$key:$pname" \
                event=NET_NEW_LISTENER \
                confidence="$(score_confidence)" \
                reasons="$SCORE_REASONS" \
                network="$key bound to $addr" \
                process="$( [[ -n "$ppid" ]] && printf 'pid=%s ' "$ppid" )${pname:-unknown}: $NET_PROCESS_VERDICT" \
                evidence="Not present in the previous listener baseline.
$(grep -F "$port" "$ITM_RUN_TMP/listeners.txt" 2>/dev/null | head -2 | while IFS= read -r l; do redact "$l"; printf '\n'; done)" \
                action="Confirm the service was started deliberately. If it is expected, it becomes part of the baseline automatically on the next run; add the port to ALLOWED_LISTEN_PORTS to stop it being flagged as outside policy. If nobody can account for it, preserve the process before stopping it: itm-security remediate"

        done < "$current"
    fi

    if (( ITM_DRY_RUN == 0 )); then
        # The state directory may not exist yet on a first run.
        mkdir -p "$(dirname "$NET_LISTENER_BASELINE")" 2>/dev/null || true
        cp -f "$current" "$NET_LISTENER_BASELINE" 2>/dev/null \
            && chmod 600 "$NET_LISTENER_BASELINE" 2>/dev/null \
            || audit_log INFO "could not persist the listener baseline to $NET_LISTENER_BASELINE"
    fi

    (( new_count == 0 )) && (( first_run == 0 )) \
        && add_pass "no new listening port since the last check"
}

# ------------------------------------------------------------
# Inbound sessions from outside the estate
#
# check_outbound answers "what is this host talking to". This
# answers the opposite and equally important question: "who is
# talking to this host, and what is serving them".
# ------------------------------------------------------------

check_inbound_connections() {

    local line state laddr raddr lport rip pname ppid
    local reported=0 total=0

    [[ -s "$ITM_RUN_TMP/estab.txt" ]] || return 0

    while IFS= read -r line; do

        read -r state _ _ laddr raddr _ <<< "$line"
        [[ "$state" == "ESTAB" ]] || continue

        ss_parse_addr "$laddr"; lport="$SS_PORT"
        ss_parse_addr "$raddr"; rip="$SS_ADDR"

        # Inbound = the peer connected to a port we listen on.
        port_in_list "$lport" "$(awk -F'|' '{print $1}' "$ITM_RUN_TMP/listeners.now" 2>/dev/null | cut -d/ -f2 | tr '\n' ' ')" || continue

        total=$(( total + 1 ))

        ip_is_trusted "$rip" && continue

        ss_parse_proc "$line"
        pname="$SS_NAME"; ppid="$SS_PID"

        net_classify_process "$pname" "$ppid"

        score_reset
        score_add 20 "inbound session from ${rip}, which is outside the trusted networks"
        (( NET_PROCESS_SCORE > 0 )) && score_add "$NET_PROCESS_SCORE" "$NET_PROCESS_VERDICT"

        # A public peer on a service that should be internal.
        port_in_list "$lport" "$DB_PORTS" \
            && score_add 40 "the service is a database, which should never accept sessions from outside"

        # Established sessions to a public address are normal for
        # a web server, so a clean process on 80/443 stays INFO.
        if (( SCORE_TOTAL < SCORE_THRESHOLD_LOW )); then
            continue
        fi

        reported=$(( reported + 1 ))

        add_finding "$(score_severity)" \
            "Inbound connection from outside the trusted networks" \
            id="net-inbound:$rip:$lport:$pname" \
            event=NET_INBOUND_EXTERNAL \
            confidence="$(score_confidence)" \
            reasons="$SCORE_REASONS" \
            network="${rip} -> local port ${lport}" \
            process="$( [[ -n "$ppid" && "$ppid" != 0 ]] && printf 'pid=%s ' "$ppid" )${pname:-unattributable}: $NET_PROCESS_VERDICT" \
            evidence="$(redact "$line")" \
            action="Confirm the service is meant to be reachable from ${rip}. If the owning process cannot be accounted for, capture it before doing anything else: itm-security remediate"

    done < "$ITM_RUN_TMP/estab.txt"

    audit_log INFO "inbound sessions evaluated: $total, reported: $reported"

    (( reported == 0 )) && add_pass "no inbound session from an untrusted source with an unexplained process ($total evaluated)"
}

# ============================================================
# ENTRY POINT
# ============================================================

run_audit_network() {

    module_begin "network" "Network Exposure"

    if (( ${#TRUSTED_NETWORKS[@]} == 0 )); then
        add_finding LOW \
            "No trusted network policy configured" \
            id="no-trusted-networks" \
            path="$ITM_TRUSTED_NET_CONF" \
            evidence="Without a trusted network list every non private address is treated as untrusted." \
            action="Populate $ITM_TRUSTED_NET_CONF with the management networks for this estate."
    else
        add_pass "trusted network policy loaded (${#TRUSTED_NETWORKS[@]} entries: ${TRUSTED_NETWORKS[*]})"
    fi

    # Socket tables are captured once, then every check reads
    # the same snapshot. Package ownership for the owning
    # executables is resolved in a single batched query: one
    # dpkg-query per socket turns this module into minutes of
    # work on a host with many listeners.
    if have_cmd ss; then
        run_timeout "$CMD_TIMEOUT" ss -tulnp > "$ITM_RUN_TMP/listeners.txt" 2>/dev/null
        run_timeout "$CMD_TIMEOUT" ss -tnp    > "$ITM_RUN_TMP/estab.txt"     2>/dev/null

        local pid exe prefetch=()
        while IFS= read -r pid; do
            [[ -n "$pid" ]] || continue
            exe="$(pid_exe "$pid")"
            [[ "$exe" == /* ]] && prefetch+=("$exe")
        done < <(grep -hoE 'pid=[0-9]+' "$ITM_RUN_TMP/listeners.txt" "$ITM_RUN_TMP/estab.txt" 2>/dev/null \
                    | cut -d= -f2 | sort -un)

        (( ${#prefetch[@]} > 0 )) && pkg_owner_prefetch "${prefetch[@]}"
    fi

    check_hidden_listeners
    check_listeners
    check_listener_baseline
    check_inbound_connections
    check_outbound

    module_end
}

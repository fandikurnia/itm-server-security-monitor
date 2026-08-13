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
        if ! port_in_list "$port" "$ALLOWED_LISTEN_PORTS"; then

            # Loopback only services, and multicast group
            # membership, are not exposure.
            addr_is_loopback "$addr"  && continue
            addr_is_multicast "$addr" && continue

            unexpected=$(( unexpected + 1 ))

            local usev=LOW
            local uexe
            uexe="$(pid_exe "$ppid")"

            if [[ "$uexe" == *"(deleted)" ]] || is_volatile_path "$uexe"; then
                usev=CRITICAL
            elif ! is_pkg_owned "$uexe" && [[ "$uexe" != unknown && "$uexe" != unreadable ]] && ! is_itm_binary "$uexe"; then
                usev=HIGH
            fi

            # Only the first few are reported individually; the
            # rest are rolled up so an inventory difference
            # cannot bury a real detection.
            if [[ "$usev" == "LOW" ]] && (( unexpected > 10 )); then
                printf '%s/%s %s (%s)\n' "$proto" "$port" "$addr" "$pname" >> "$ITM_RUN_TMP/listener_rollup.txt"
                continue
            fi

            add_finding "$usev" \
                "Listening port outside the expected service policy" \
                id="unexpected-listener:$port:$pname" \
                network="$proto/$port bound to $addr" \
                process="$pname (pid ${ppid}) exe=$uexe user=$(pid_user "$ppid")" \
                evidence="Port $port is not in ALLOWED_LISTEN_PORTS. package=$(pkg_owner "$uexe")" \
                action="Confirm the service is intentional and firewalled. If it is expected, add the port to ALLOWED_LISTEN_PORTS in ${ITM_AUDIT_CONF}."
        fi

    done < "$ITM_RUN_TMP/listeners.txt"

    audit_log INFO "enumerated $total listening sockets"

    if [[ -s "$ITM_RUN_TMP/listener_rollup.txt" ]]; then
        add_finding LOW \
            "Further listening ports outside the expected service policy" \
            id="unexpected-listener-rollup" \
            evidence="$(wc -l < "$ITM_RUN_TMP/listener_rollup.txt") additional listener(s):
$(truncate_text "$(cat "$ITM_RUN_TMP/listener_rollup.txt")" 800)" \
            action="Review the inventory and extend ALLOWED_LISTEN_PORTS in ${ITM_AUDIT_CONF} for the ports that belong here."
    fi

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
    check_outbound

    module_end
}

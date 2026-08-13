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

ioc_load_database() {
    load_ioc_list "known-iocs.conf" KNOWN_IOCS || return 1
    (( ${#KNOWN_IOCS[@]} > 0 ))
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
            if ! is_pkg_owned "$file"; then
                score_add 35 "name imitates a compiler toolchain prefix - blends into /usr/bin listings"
            fi
        fi

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

    local path found=0

    while IFS= read -r path; do

        [[ -n "$path" ]] || continue
        [[ -e "$path" ]] || continue

        found=$(( found + 1 ))

        add_finding CRITICAL \
            "Known malicious file from a previous incident is present on this host" \
            id="ioc-known-path:$path" \
            path="$path" \
            hash="$(file_sha256 "$path")" \
            confidence=99 \
            reasons="Path matches an IOC recorded from a confirmed compromise on this estate
The file exists on this host right now" \
            evidence="owner=$(stat -Lc '%U:%G' "$path" 2>/dev/null) mode=$(stat -Lc '%a' "$path" 2>/dev/null) size=$(stat -Lc '%s' "$path" 2>/dev/null)
mtime=$(file_mtime_human "$path")
sha256=$(file_sha256 "$path")
package=$(pkg_owner "$path")" \
            action="ISOLATE THIS HOST. Preserve the file and its metadata before anything else. Rotate every credential used on this host. Then find how it got here and what re-installs it - the payload is the symptom, the persistence is the problem."

        evidence_snapshot "$path" \
            "$(printf '%s|ioc-known|%s' "$ITM_HOSTNAME" "$path" | sha256sum | cut -c1-32)" \
            "known IOC path from the incident database" >/dev/null

    done < <(ioc_entries_of_type path)

    (( found == 0 )) && add_pass "no known IOC file path present on this host"
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

    if ioc_load_database; then
        add_pass "IOC database loaded (${#KNOWN_IOCS[@]} indicators)"
        ioc_check_known_paths
        ioc_check_known_hashes
        ioc_check_known_strings
    else
        add_skip "no IOC database at ${ITM_IOC_DIR}/known-iocs.conf - generic checks still run"
    fi

    ioc_check_unpackaged_system_binaries
    ioc_check_ld_preload

    module_end
}

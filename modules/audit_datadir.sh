#!/usr/bin/env bash
# shellcheck shell=bash

# ============================================================
# ITM Server Security Monitor
# Module D2: exposed data directories
#
# Read only. No permission is changed and no ownership is
# touched: chmod on a live database directory is how an
# application stops being able to write its own data.
#
# Background - a real case on this estate: an application's
# database directory under /opt was mode 777 and held raw InnoDB
# files (ibdata1, ib_logfile0).
# World-writable there means any local account - including the
# web server user, which is reachable from the internet through
# the application - can read the entire database byte for byte,
# and can corrupt it at will. No SQL credential is involved.
#
# The severity distinction that matters:
#
#   world-writable directory                 HIGH
#   world-writable AND holds database files  CRITICAL
#
# because the second one is a full data breach waiting for one
# file read, not a hygiene issue.
# ============================================================

DATADIR_SCAN_PATHS="${DATADIR_SCAN_PATHS:-/opt /var/www /var/lib/mysql /var/lib/mysql-files /var/lib/postgresql /var/lib/mongodb /srv /data}"
DATADIR_MAXDEPTH="${DATADIR_MAXDEPTH:-3}"

# Files that mean "this is a live datastore", not just a folder.
DATADIR_DB_FILES="${DATADIR_DB_FILES:-ibdata1 ib_logfile0 ib_logfile1 ibtmp1 aria_log_control mysql.ibd *.ibd *.frm *.MYD *.MYI *.db *.sqlite *.sqlite3 base pg_wal postmaster.pid WiredTiger}"

# ------------------------------------------------------------
# Which account should own this directory?
#
# Guessing from the directory name is unreliable. The processes
# that currently hold files open in it are not.
# ------------------------------------------------------------

datadir_probable_owner() {

    local dir="$1" owner="" bin

    bin="$(trusted_bin lsof 2>/dev/null || true)"
    if [[ -n "$bin" ]]; then
        owner="$(run_timeout 15 "$bin" +D "$dir" -F Lc 2>/dev/null \
                 | awk '/^L/ {sub(/^L/,"",$0); print}' | sort | uniq -c | sort -rn | head -1 | awk '{print $2}')"
    fi

    if [[ -z "$owner" ]]; then
        bin="$(trusted_bin fuser 2>/dev/null || true)"
        if [[ -n "$bin" ]]; then
            local pid
            pid="$(run_timeout 15 "$bin" -m "$dir" 2>/dev/null | tr -s ' ' '\n' | grep -E '^[0-9]+$' | head -1)"
            [[ -n "$pid" ]] && owner="$(pid_owner "$pid" 2>/dev/null)"
        fi
    fi

    # Fall back to whoever owns the files inside.
    if [[ -z "$owner" || "$owner" == "unknown" ]]; then
        owner="$(run_scan 20 find "$dir" -maxdepth 1 -type f -printf '%u\n' 2>/dev/null \
                 | sort | uniq -c | sort -rn | head -1 | awk '{print $2}')"
    fi

    printf '%s' "${owner:-root}"
}

datadir_has_db_files() {
    local dir="$1" pattern
    for pattern in $DATADIR_DB_FILES; do
        # shellcheck disable=SC2086
        if run_scan 10 find "$dir" -maxdepth 2 -name "$pattern" -print -quit 2>/dev/null | grep -q .; then
            printf '%s' "$pattern"
            return 0
        fi
    done
    return 1
}

# ============================================================

check_world_writable_datadirs() {

    local dir mode owner group found=0 checked=0
    local -a scan_dirs=()

    local p
    for p in $DATADIR_SCAN_PATHS; do
        [[ -d "$p" ]] && scan_dirs+=("$p")
    done

    if (( ${#scan_dirs[@]} == 0 )); then
        add_skip "none of the configured data paths exist on this host"
        return 0
    fi

    while IFS= read -r dir; do

        [[ -n "$dir" ]] || continue
        checked=$(( checked + 1 ))

        mode="$(stat -Lc '%a' "$dir" 2>/dev/null)" || continue
        [[ "$mode" =~ ^[0-7]+$ ]] || continue

        # World-writable only. Group-writable is normal for a
        # shared application directory.
        (( (8#$mode & 8#0002) != 0 )) || continue

        # The sticky bit makes a shared directory safe: /tmp is
        # 1777 for a reason, and so are some spool directories.
        if (( (8#$mode & 8#1000) != 0 )); then
            audit_log INFO "world-writable but sticky, not reported: $dir ($mode)"
            continue
        fi

        owner="$(stat -Lc '%U' "$dir" 2>/dev/null)"
        group="$(stat -Lc '%G' "$dir" 2>/dev/null)"

        local db_marker=""
        db_marker="$(datadir_has_db_files "$dir" || true)"

        score_reset
        score_add 40 "directory is world-writable (mode ${mode}): every local account can create, modify and delete files in it"

        local sev title
        if [[ -n "$db_marker" ]]; then
            score_add 45 "it holds live datastore files (matched: ${db_marker})"
            score_add 15 "raw database files can be read byte for byte without any database credential"
            title="World-writable directory holding database files"
        else
            title="World-writable data directory"
        fi

        # A web-reachable path makes it worse: the account that
        # can write here is exposed to the internet.
        case "$dir" in
            /var/www/*|/var/www) score_add 15 "inside a web document root" ;;
        esac

        sev="$(score_severity)"
        found=$(( found + 1 ))

        local probable
        probable="$(datadir_probable_owner "$dir")"

        add_finding "$sev" \
            "$title" \
            id="datadir-world-writable:$dir" \
            event=DATA_DIR_WORLD_WRITABLE \
            path="$dir" \
            confidence="$(score_confidence)" \
            reasons="$SCORE_REASONS" \
            evidence="mode=${mode} owner=${owner}:${group}
$( [[ -n "$db_marker" ]] && printf 'datastore files present (matched pattern: %s)\n' "$db_marker" )probable owning account (from open files): ${probable}
contents: $(run_scan 10 find "$dir" -maxdepth 1 -printf '%f ' 2>/dev/null | truncate_text_stdin 200)" \
            action="Do NOT chmod this directory while the service is running without checking first: the owning process must keep write access. Recommended, after confirming the account: chown -R ${probable}:${probable} ${dir} && chmod 700 ${dir}. Generate a reviewed script with: itm-security remediate"

    done < <(
        for p in "${scan_dirs[@]}"; do
            run_scan "$FIND_TIMEOUT" find "$p" -maxdepth "$DATADIR_MAXDEPTH" -type d -perm -0002 -print 2>/dev/null
        done | sort -u | head -50
    )

    audit_log INFO "checked $checked world-writable directories under $DATADIR_SCAN_PATHS"

    (( found == 0 )) && add_pass "no world-writable data directory under ${DATADIR_SCAN_PATHS// /, }"
}

# ============================================================
# ENTRY POINT
# ============================================================

run_audit_datadir() {

    module_begin "datadir" "Data Directory Exposure"
    check_world_writable_datadirs
    module_end
}

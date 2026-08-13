#!/usr/bin/env bash
# shellcheck shell=bash

# ============================================================
# ITM Server Security Monitor
# Web content audit - Module W4: source integrity baseline
#
# Read only. The baseline is a record of what the application
# looked like; it is never used to "restore" anything, and no
# file is ever written back, replaced or deleted.
#
# Content scanning finds known-bad patterns. This module finds
# unknown-bad: a change to a file that should not have changed.
# An attacker who appends one line to an existing index.php
# leaves no keyword and no new file, and only a hash comparison
# will see it.
#
# States reported: CREATED, MODIFIED, DELETED, OWNER_CHANGED,
# PERMISSION_CHANGED.
#
# The baseline lives in /var/lib/itm-security/web-baseline and
# is created on first run. Until an operator has confirmed the
# application was clean when the baseline was taken, the
# baseline records a state, not a guarantee - which is why the
# first-run finding says exactly that.
# ============================================================

INTEGRITY_MAX_REPORT="${INTEGRITY_MAX_REPORT:-40}"

# ------------------------------------------------------------
# Baseline files are one record per line:
#   sha256<TAB>mode<TAB>owner:group<TAB>path
# ------------------------------------------------------------

integrity_baseline_file() {
    local root="$1" slug
    slug="$(printf '%s' "$root" | sed 's|^/||; s|/|_|g')"
    printf '%s/%s.db' "$WEB_BASELINE_DIR" "${slug:-root}"
}

integrity_build_baseline() {

    local root="$1" out="$2"
    local file tmp count=0

    tmp="$ITM_RUN_TMP/baseline.$$"
    : > "$tmp"

    while IFS= read -r file; do

        [[ -n "$file" ]] || continue
        web_path_excluded "$file" && continue
        web_file_facts "$file" || continue

        # Files too large to hash are recorded by size and mtime
        # instead, so they are still tracked for replacement.
        printf '%s\t%s\t%s:%s\t%s\n' \
            "$WF_SHA" "$WF_MODE" "$WF_OWNER" "$WF_GROUP" "$file" >> "$tmp"

        count=$(( count + 1 ))

    done < <(web_enumerate "$root" both 0)

    (( ITM_DRY_RUN )) && { printf '%s' "$count"; return 0; }

    mkdir -p "$WEB_BASELINE_DIR" 2>/dev/null || { printf '0'; return 1; }
    chmod 700 "$WEB_BASELINE_DIR" 2>/dev/null || true

    sort -k4 "$tmp" > "$out" 2>/dev/null || { printf '0'; return 1; }
    chmod 600 "$out" 2>/dev/null || true

    printf '%s' "$count"
}

# ------------------------------------------------------------
# Comparison
# ------------------------------------------------------------

integrity_compare() {

    local root="$1" baseline="$2"
    local current="$ITM_RUN_TMP/current.$$"
    local file line
    local created=0 modified=0 deleted=0 owner_changed=0 perm_changed=0
    local reported=0

    : > "$current"

    while IFS= read -r file; do
        [[ -n "$file" ]] || continue
        web_path_excluded "$file" && continue
        web_file_facts "$file" || continue
        printf '%s\t%s\t%s:%s\t%s\n' \
            "$WF_SHA" "$WF_MODE" "$WF_OWNER" "$WF_GROUP" "$file" >> "$current"
    done < <(web_enumerate "$root" both 0)

    sort -k4 -o "$current" "$current" 2>/dev/null

    # Index the baseline for lookup.
    local -A base_sha=() base_mode=() base_own=()
    while IFS=$'\t' read -r sha mode own path; do
        [[ -n "$path" ]] || continue
        base_sha["$path"]="$sha"
        base_mode["$path"]="$mode"
        base_own["$path"]="$own"
    done < "$baseline"

    local -A seen=()

    # ---- created / modified / attribute changes -------------
    while IFS=$'\t' read -r sha mode own path; do

        [[ -n "$path" ]] || continue
        seen["$path"]=1

        if [[ -z "${base_sha[$path]:-}" ]]; then

            (( created++ ))
            (( reported >= INTEGRITY_MAX_REPORT )) && continue

            web_file_facts "$path" || continue
            score_reset
            score_add 25 "file did not exist when the baseline was taken"
            web_owner_is_service_account "$WF_OWNER" \
                && score_add 30 "created by the web service account ($WF_OWNER)"
            web_file_is_new && score_add 15 "created in the last ${WF_AGE_HOURS}h"
            case "$path" in
                *.php|*.phtml|*.phar|*.inc)
                    score_add 25 "new executable PHP file in application source" ;;
            esac
            web_php_reachable "$path" && score_add 10 "reachable as PHP over HTTP"

            web_report_file_finding \
                "integrity-created:$path" \
                "CREATED - new file in application source" \
                "Match against the deployment record. A file the release did not ship, created by the web account, is unauthorised code until proven otherwise." \
                && reported=$(( reported + 1 ))

            continue
        fi

        if [[ "$sha" != "${base_sha[$path]}" ]]; then

            (( modified++ ))
            (( reported >= INTEGRITY_MAX_REPORT )) && continue

            web_file_facts "$path" || continue
            score_reset
            score_add 30 "content hash differs from the baseline"
            web_owner_is_service_account "$WF_OWNER" \
                && score_add 30 "modified by the web service account ($WF_OWNER)"
            web_file_is_new && score_add 15 "modified in the last ${WF_AGE_HOURS}h"
            case "$path" in
                *.php|*.phtml|*.phar|*.inc)
                    score_add 20 "executable PHP source modified" ;;
            esac

            web_report_file_finding \
                "integrity-modified:$path" \
                "MODIFIED - application source changed since baseline" \
                "Diff against your deployment repository. If the change is a legitimate release, refresh the baseline: itm-security web baseline" \
                && reported=$(( reported + 1 ))

            continue
        fi

        # Same content, different attributes.
        if [[ "$own" != "${base_own[$path]}" ]]; then
            (( owner_changed++ ))
            (( reported >= INTEGRITY_MAX_REPORT )) && continue
            add_finding MEDIUM \
                "OWNER_CHANGED - file ownership changed since baseline" \
                id="integrity-owner:$path" \
                path="$path" \
                confidence=70 \
                reasons="Content is unchanged but ownership moved from ${base_own[$path]} to ${own}
Ownership changes are not part of normal application behaviour" \
                evidence="baseline=${base_own[$path]} current=${own}" \
                action="Identify what changed ownership. A move to the web account makes a previously read-only file writable by the application."
            reported=$(( reported + 1 ))
            continue
        fi

        if [[ "$mode" != "${base_mode[$path]}" ]]; then
            (( perm_changed++ ))
            (( reported >= INTEGRITY_MAX_REPORT )) && continue

            local sev=LOW
            [[ "$mode" =~ ^[0-7]+$ ]] && (( (8#$mode & 8#0111) != 0 )) && sev=MEDIUM
            [[ "$mode" =~ ^[0-7]+$ ]] && (( (8#$mode & 8#0002) != 0 )) && sev=HIGH

            add_finding "$sev" \
                "PERMISSION_CHANGED - file permissions changed since baseline" \
                id="integrity-perm:$path" \
                path="$path" \
                confidence=65 \
                reasons="Permissions moved from ${base_mode[$path]} to ${mode}
Content is unchanged
An added executable or world-write bit on web content is never required" \
                evidence="baseline=${base_mode[$path]} current=${mode}" \
                action="Restore the intended permissions after confirming which process changed them."
            reported=$(( reported + 1 ))
        fi

    done < "$current"

    # ---- deleted --------------------------------------------
    local deleted_list=""
    for line in "${!base_sha[@]}"; do
        [[ -n "${seen[$line]:-}" ]] && continue
        (( deleted++ ))
        [[ $(printf '%s' "$deleted_list" | wc -l) -lt 20 ]] && deleted_list+="$line
"
    done

    if (( deleted > 0 )); then
        add_finding MEDIUM \
            "DELETED - files present in the baseline are gone" \
            id="integrity-deleted:$root" \
            path="$root" \
            confidence=60 \
            reasons="${deleted} file(s) recorded in the baseline no longer exist
Deletion is normal after a release, and is also how an attacker removes a webshell after use" \
            evidence="$(truncate_text "$deleted_list" 600)" \
            action="If no deployment happened, treat this as evidence removal and check the access log around the deletion window. The realtime monitor records files that existed briefly."
    fi

    audit_log INFO "integrity $root: created=$created modified=$modified deleted=$deleted owner=$owner_changed perm=$perm_changed"

    if (( created == 0 && modified == 0 && deleted == 0 && owner_changed == 0 && perm_changed == 0 )); then
        add_pass "source integrity unchanged since baseline: $root"
    elif (( reported >= INTEGRITY_MAX_REPORT )); then
        add_finding MEDIUM \
            "Integrity report truncated at ${INTEGRITY_MAX_REPORT} findings" \
            id="integrity-truncated:$root" \
            path="$root" \
            evidence="created=$created modified=$modified deleted=$deleted owner_changed=$owner_changed permission_changed=$perm_changed
A change of this size is usually a deployment. If it was not, this host needs manual review rather than an alert list." \
            action="If a release was deployed, refresh the baseline: itm-security web baseline"
    fi
}

# ------------------------------------------------------------
# Entry points
# ------------------------------------------------------------

integrity_run() {

    local root baseline count

    for root in "${WEB_SCAN_ROOTS[@]}"; do

        baseline="$(integrity_baseline_file "$root")"

        if [[ ! -s "$baseline" ]]; then

            count="$(integrity_build_baseline "$root" "$baseline")"

            add_finding INFO \
                "Integrity baseline created for $root" \
                id="integrity-baseline-created:$root" \
                path="$root" \
                status=CHECK_PASS \
                evidence="${count} files recorded in $baseline
A baseline records the current state. It is not evidence that the current state is clean: on a host whose trust status is not established, treat the first baseline as a reference point only." \
                action="If this application has just been reviewed or reinstalled from a trusted release, this baseline is meaningful. Otherwise re-take it after cleanup: itm-security web baseline"

            continue
        fi

        integrity_compare "$root" "$baseline"

    done
}

# Called by "itm-security web baseline"
web_baseline_rebuild() {

    local root baseline count total=0

    web_load_iocs

    if ! web_scan_roots; then
        say_err "[ERROR] No web root resolved. Set WEB_ROOTS in $ITM_AUDIT_CONF"
        return 1
    fi

    for root in "${WEB_SCAN_ROOTS[@]}"; do
        baseline="$(integrity_baseline_file "$root")"
        count="$(integrity_build_baseline "$root" "$baseline")"
        total=$(( total + count ))
        printf '  %-50s %6s files -> %s\n' "$root" "$count" "$baseline"
    done

    printf '\nBaseline written for %s file(s).\n' "$total"
    printf 'A baseline records state, not cleanliness. Take it from a known good release.\n'
}

# ============================================================
# ENTRY POINT
# ============================================================

run_audit_integrity() {

    module_begin "integrity" "Source Integrity"

    require_web_workload "Source integrity baseline" || { module_end; return 0; }

    web_load_iocs

    if ! web_scan_roots; then
        add_skip "no web root resolved - set WEB_ROOTS in ${ITM_AUDIT_CONF}"
        module_end
        return 0
    fi

    integrity_run

    module_end
}

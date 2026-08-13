#!/usr/bin/env bash
# shellcheck shell=bash

# ============================================================
# ITM Server Security Monitor
# Web content monitoring - shared primitives
#
# Sourced by the webshell, gambling, seo and integrity modules.
#
# Read only. Nothing here deletes, renames, quarantines or
# chmods a web file. On a production CMS a false positive that
# removes a file is an outage, and a real webshell that gets
# deleted before it is captured is destroyed evidence.
#
# Everything in this file is bounded: timeouts, depth limits,
# prune lists, file size caps and result caps, run at idle CPU
# and IO priority.
# ============================================================

[[ -n "${ITM_WEB_COMMON_LOADED:-}" ]] && return 0
ITM_WEB_COMMON_LOADED=1

# ------------------------------------------------------------
# Policy defaults (override in audit.conf)
# ------------------------------------------------------------

# Never read or hash a file larger than this. A 4 GB video is
# not a webshell, and hashing it would stall the scan.
WEB_MAX_FILE_BYTES="${WEB_MAX_FILE_BYTES:-2097152}"

# Content types worth reading.
WEB_CODE_EXT="${WEB_CODE_EXT:-php phtml phar php3 php4 php5 php7 php8 pht phps inc}"
WEB_MARKUP_EXT="${WEB_MARKUP_EXT:-html htm js json xml txt}"

# A file newer than this is "recent" for scoring purposes.
WEB_NEW_FILE_HOURS="${WEB_NEW_FILE_HOURS:-72}"

# Full reconciliation interval. Between full passes the scan is
# incremental (only files newer than the last run).
WEB_FULL_SCAN_HOURS="${WEB_FULL_SCAN_HOURS:-24}"

WEB_BASELINE_DIR="${WEB_BASELINE_DIR:-/var/lib/itm-security/web-baseline}"

# Accounts a web server runs as. Files owned by these accounts
# inside application source are suspicious: deployments are not
# normally written by the web server itself.
WEB_SERVICE_USERS="${WEB_SERVICE_USERS:-www-data nginx apache httpd php-fpm daemon}"

# ------------------------------------------------------------
# IOC lists
#
# Loaded from /etc/security-monitor/ioc/. Empty arrays simply
# disable the corresponding checks, which is why every consumer
# tests for emptiness rather than assuming content.
# ------------------------------------------------------------

WEB_IOC_LOADED=0

GAMBLING_KEYWORDS=()
WEBSHELL_PATTERNS=()
SEO_PATTERNS=()
SUSPICIOUS_FILENAMES=()
WEB_EXCLUSIONS=()

web_load_iocs() {

    (( WEB_IOC_LOADED )) && return 0
    WEB_IOC_LOADED=1

    load_ioc_list "gambling-keywords.conf"      GAMBLING_KEYWORDS    || true
    load_ioc_list "webshell-patterns.conf"      WEBSHELL_PATTERNS    || true
    load_ioc_list "seo-poisoning-patterns.conf" SEO_PATTERNS         || true
    load_ioc_list "suspicious-filenames.conf"   SUSPICIOUS_FILENAMES || true
    load_ioc_list "web-exclusions.conf"         WEB_EXCLUSIONS       || true
}

web_ioc_status() {
    printf 'gambling=%s webshell=%s seo=%s filenames=%s exclusions=%s' \
        "${#GAMBLING_KEYWORDS[@]}" "${#WEBSHELL_PATTERNS[@]}" \
        "${#SEO_PATTERNS[@]}" "${#SUSPICIOUS_FILENAMES[@]}" "${#WEB_EXCLUSIONS[@]}"
}

# Operator maintained allowlist: paths that must never produce a
# finding (a known gambling-news article, a legitimate adminer
# install, a vendor tree with eval in it).
web_path_excluded() {
    local path="$1" rule
    for rule in ${WEB_EXCLUSIONS[@]+"${WEB_EXCLUSIONS[@]}"}; do
        [[ -n "$rule" ]] || continue
        # shellcheck disable=SC2053
        [[ "$path" == $rule ]] && return 0
    done
    return 1
}

# ------------------------------------------------------------
# Web roots
#
# Discovered from the Nginx effective configuration plus
# WEB_ROOTS from audit.conf. Only called after the role module
# has confirmed a web application workload.
# ------------------------------------------------------------

WEB_SCAN_ROOTS=()

web_scan_roots() {

    (( ${#WEB_SCAN_ROOTS[@]} > 0 )) && return 0

    local candidates=() root seen covered

    for root in $WEB_ROOTS; do
        candidates+=("$root")
    done

    # Roots the nginx module already discovered this run, or the
    # cached copy from a previous run.
    local cache
    for cache in "$ITM_RUN_TMP/nginx-roots.list" "$ITM_NGINX_ROOT_CACHE"; do
        [[ -r "$cache" ]] || continue
        while IFS= read -r root; do
            [[ -n "$root" ]] && candidates+=("$root")
        done < "$cache"
        break
    done

    # Nothing cached: ask nginx directly, still without touching
    # the filesystem.
    if (( ${#candidates[@]} == 0 )) && have_cmd nginx; then
        while IFS= read -r root; do
            [[ -n "$root" ]] && candidates+=("$root")
        done < <(run_timeout "$CMD_TIMEOUT" nginx -T 2>/dev/null \
                    | awk '/^[[:space:]]*root[[:space:]]/ {
                             v = $2; gsub(/[;"'"'"']/, "", v); if (v != "") print v
                           }' | sort -u)
    fi

    for root in ${candidates[@]+"${candidates[@]}"}; do

        [[ -d "$root" ]] || continue

        covered=0
        for seen in ${WEB_SCAN_ROOTS[@]+"${WEB_SCAN_ROOTS[@]}"}; do
            [[ "$root" == "$seen" || "$root" == "$seen"/* ]] && covered=1 && break
        done
        (( covered )) && continue

        WEB_SCAN_ROOTS+=("$root")
    done

    (( ${#WEB_SCAN_ROOTS[@]} > 0 ))
}

# ------------------------------------------------------------
# Bounded enumeration
#
# One find invocation shared by every module, with the prune
# list, depth limit and size cap applied consistently.
#
# web_enumerate <root> <mode> [since-epoch]
#   mode: code | markup | all
# ------------------------------------------------------------

WEB_PRUNE_ARGS=()

web_build_prune() {
    local d
    WEB_PRUNE_ARGS=()
    for d in $WEB_EXCLUDE_DIRS; do
        WEB_PRUNE_ARGS+=( -name "$d" -o )
    done
    (( WEB_EXCLUDE_VENDOR )) && WEB_PRUNE_ARGS+=( -name vendor -o )
    WEB_PRUNE_ARGS+=( -false )
}

web_enumerate() {

    local root="$1" mode="${2:-code}" since="${3:-0}"
    local -a name_args=()
    local ext first=1

    web_build_prune

    case "$mode" in
        code)   for ext in $WEB_CODE_EXT; do
                    (( first )) || name_args+=( -o )
                    name_args+=( -name "*.$ext" ); first=0
                done ;;
        markup) for ext in $WEB_MARKUP_EXT; do
                    (( first )) || name_args+=( -o )
                    name_args+=( -name "*.$ext" ); first=0
                done ;;
        both)   for ext in $WEB_CODE_EXT $WEB_MARKUP_EXT; do
                    (( first )) || name_args+=( -o )
                    name_args+=( -name "*.$ext" ); first=0
                done ;;
        all)    name_args=( -true ) ;;
    esac

    local -a time_args=()
    if [[ "$since" =~ ^[0-9]+$ ]] && (( since > 0 )); then
        time_args=( -newermt "@$since" )
    fi

    run_scan "$FIND_TIMEOUT" find "$root" \
        -maxdepth "$WEB_SCAN_MAXDEPTH" \
        \( "${WEB_PRUNE_ARGS[@]}" \) -prune -o \
        -type f \( "${name_args[@]}" \) \
        ${time_args[@]+"${time_args[@]}"} \
        -size -"$(( WEB_MAX_FILE_BYTES / 1024 + 1 ))"k \
        -print 2>/dev/null
}

# Directories that hold uploaded or static content.
web_upload_dirs() {
    local root="$1"
    web_build_prune
    run_scan "$FIND_TIMEOUT" find "$root" \
        -regextype posix-extended \
        -maxdepth "$WEB_SCAN_MAXDEPTH" \
        \( "${WEB_PRUNE_ARGS[@]}" \) -prune -o \
        -type d -iregex ".*/${UPLOAD_DIR_PATTERN}" -print 2>/dev/null
}

# ------------------------------------------------------------
# File facts
#
# Collected once per candidate file and reused by every check,
# so a file is stat'ed once rather than five times.
# ------------------------------------------------------------

WF_PATH=""; WF_SIZE=0; WF_MODE=""; WF_OWNER=""; WF_GROUP=""
WF_MTIME=0; WF_MTIME_H=""; WF_SHA=""; WF_AGE_HOURS=0; WF_NAME=""

web_file_facts() {

    local path="$1" line

    WF_PATH="$path"
    WF_NAME="${path##*/}"
    WF_SIZE=0; WF_MODE=""; WF_OWNER=""; WF_GROUP=""
    WF_MTIME=0; WF_MTIME_H=""; WF_SHA=""; WF_AGE_HOURS=0

    [[ -f "$path" ]] || return 1

    line="$(stat -c '%s|%a|%U|%G|%Y|%y' "$path" 2>/dev/null)" || return 1

    IFS='|' read -r WF_SIZE WF_MODE WF_OWNER WF_GROUP WF_MTIME WF_MTIME_H <<< "$line"
    WF_MTIME_H="${WF_MTIME_H%.*}"

    [[ "$WF_MTIME" =~ ^[0-9]+$ ]] || WF_MTIME=0
    WF_AGE_HOURS=$(( ( $(date +%s) - WF_MTIME ) / 3600 ))
    (( WF_AGE_HOURS < 0 )) && WF_AGE_HOURS=0

    # Hash only what is worth hashing.
    if [[ "$WF_SIZE" =~ ^[0-9]+$ ]] && (( WF_SIZE <= WEB_MAX_FILE_BYTES )); then
        WF_SHA="$(file_sha256 "$path")"
    else
        WF_SHA="not-hashed-size-$WF_SIZE"
    fi

    return 0
}

web_file_is_new() {
    (( WF_AGE_HOURS <= WEB_NEW_FILE_HOURS ))
}

web_owner_is_service_account() {
    local u="${1:-$WF_OWNER}" svc
    for svc in $WEB_SERVICE_USERS; do
        [[ "$u" == "$svc" ]] && return 0
    done
    return 1
}

# Read a bounded amount of a file for pattern matching.
web_file_head() {
    local path="$1" bytes="${2:-65536}"
    run_scan 15 head -c "$bytes" "$path" 2>/dev/null
}

# ------------------------------------------------------------
# PHP execution reachability
#
# Whether Nginx would execute a PHP file at this path. Uses the
# server records the nginx module produced this run.
# ------------------------------------------------------------

web_php_reachable() {

    local path="$1" root
    local servers="$ITM_RUN_TMP/nginx_servers.txt"

    [[ -s "$servers" ]] || return 1

    while IFS='|' read -r _ _ php roots _; do
        [[ "$php" == "1" ]] || continue
        local IFS_SAVE="$IFS"
        IFS=','
        # shellcheck disable=SC2206
        local rl=( $roots )
        IFS="$IFS_SAVE"
        for root in ${rl[@]+"${rl[@]}"}; do
            [[ "$root" == "-" ]] && continue
            [[ "$path" == "$root"/* || "$path" == "$root" ]] && return 0
        done
    done < "$servers"

    return 1
}

# Is the directory writable by a web service account?
web_dir_service_writable() {

    local dir="$1" mode owner

    [[ -d "$dir" ]] || return 1

    mode="$(stat -Lc '%a' "$dir" 2>/dev/null)" || return 1
    owner="$(stat -Lc '%U' "$dir" 2>/dev/null)"

    # World writable, or owned by the web account with owner
    # write, both mean the web server can create files here.
    if [[ "$mode" =~ ^[0-7]+$ ]] && (( (8#$mode & 8#0002) != 0 )); then
        return 0
    fi

    if web_owner_is_service_account "$owner"; then
        (( (8#$mode & 8#0200) != 0 )) && return 0
    fi

    # Group writable and the group is a web group.
    local group
    group="$(stat -Lc '%G' "$dir" 2>/dev/null)"
    if web_owner_is_service_account "$group"; then
        (( (8#$mode & 8#0020) != 0 )) && return 0
    fi

    return 1
}

# ------------------------------------------------------------
# Incremental scan window
#
# Returns the epoch to scan from, and whether this run is a full
# reconciliation pass.
# ------------------------------------------------------------

WEB_SCAN_SINCE=0
WEB_SCAN_FULL=0

web_scan_window() {

    local key="$1" last now full_age

    now="$(date +%s)"
    last="$(scan_state_get "$key")"
    full_age="$(scan_state_get "full:$key")"

    WEB_SCAN_FULL=0
    WEB_SCAN_SINCE="$last"

    if [[ "${WEB_FORCE_FULL:-0}" == "1" ]] || (( last == 0 )); then
        WEB_SCAN_FULL=1
        WEB_SCAN_SINCE=0
        return 0
    fi

    if (( now - full_age >= WEB_FULL_SCAN_HOURS * 3600 )); then
        WEB_SCAN_FULL=1
        WEB_SCAN_SINCE=0
    fi

    return 0
}

web_scan_window_commit() {
    local key="$1" now
    now="$(date +%s)"
    scan_state_set "$key" "$now"
    (( WEB_SCAN_FULL )) && scan_state_set "full:$key" "$now"
}

# ------------------------------------------------------------
# Reporting helper
#
# Every content finding goes through here so that scoring,
# evidence snapshotting and the "do not delete" instruction are
# applied uniformly.
# ------------------------------------------------------------

web_report_file_finding() {

    local id="$1" title="$2" action="$3"
    local severity confidence snapshot=""

    severity="$(score_severity)"
    confidence="$(score_confidence)"

    [[ "$severity" == "INFO" ]] && return 1

    if [[ "$severity" == "CRITICAL" || "$severity" == "HIGH" ]]; then
        snapshot="$(evidence_snapshot "$WF_PATH" \
            "$(printf '%s|%s|%s' "$ITM_HOSTNAME" "$id" "$WF_PATH" | sha256sum | cut -c1-32)" \
            "$title
score=$SCORE_TOTAL
$SCORE_REASONS")"
    fi

    add_finding "$severity" "$title" \
        id="$id" \
        path="$WF_PATH" \
        hash="$WF_SHA" \
        confidence="$confidence" \
        reasons="$SCORE_REASONS" \
        evidence="owner=${WF_OWNER}:${WF_GROUP} mode=${WF_MODE} size=${WF_SIZE} modified=${WF_MTIME_H} (${WF_AGE_HOURS}h ago)
sha256=${WF_SHA}
score=${SCORE_TOTAL}${snapshot:+
evidence copy=${snapshot}}" \
        action="$action"

    return 0
}

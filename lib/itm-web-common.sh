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
# Extensions are matched CASE INSENSITIVELY (-iname). A real
# upload directory on this estate contained x.Phar and x.PHP
# alongside x.phtml: case-sensitive matching let two of them
# through untouched.
#
# php~ and php_ are editor/backup artefacts that many PHP
# handlers still execute, and .phtm/.pht are handler aliases.
WEB_CODE_EXT="${WEB_CODE_EXT:-php phtml phtm phar php3 php4 php5 php6 php7 php8 pht phps inc phpt php~ php_}"
WEB_MARKUP_EXT="${WEB_MARKUP_EXT:-html htm js mjs json xml txt css}"

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
# Unified discovery across every supported web server.
#
# This function is the reason the Satudata incident produced no
# alert. The previous implementation asked Nginx and only Nginx,
# so on an Apache host it returned nothing, every content module
# skipped, and the skip was logged at INFO - below the Telegram
# threshold. The monitor was blind and silent at the same time.
#
# Sources, in order of authority:
#   1. WEB_ROOTS in audit.conf          (operator override)
#   2. roots discovered this run        (nginx/apache modules)
#   3. live web server configuration    (nginx -T, apache config)
#   4. conventional locations that exist AND hold content
#
# Each root records where it came from, so the report can say
# what the scan was actually based on.
# ------------------------------------------------------------

WEB_SCAN_ROOTS=()
declare -A WEB_ROOT_SOURCE=()

# --- Nginx -----------------------------------------------------

web_nginx_roots() {
    have_cmd nginx || return 0
    run_timeout "$CMD_TIMEOUT" nginx -T 2>/dev/null \
        | awk '/^[[:space:]]*root[[:space:]]/ {
                 v = $2; gsub(/[;"'"'"']/, "", v); if (v != "") print v
               }' | sort -u
}

# --- Apache ----------------------------------------------------
#
# apache2ctl -S reports vhosts and the config file each was
# defined in, but not the DocumentRoot. The roots therefore come
# from the configuration files themselves, which also works when
# apache2ctl is unavailable or refuses to run.
# ---------------------------------------------------------------

APACHE_CONF_DIRS="${APACHE_CONF_DIRS:-/etc/apache2 /etc/httpd /usr/local/apache2/conf /etc/apache2/sites-enabled /etc/httpd/conf.d}"

web_apache_ctl() {
    local ctl
    for ctl in apache2ctl apachectl httpd; do
        have_cmd "$ctl" && { printf '%s' "$ctl"; return 0; }
    done
    return 1
}

web_apache_config_files() {
    local dir
    for dir in $APACHE_CONF_DIRS; do
        [[ -d "$dir" ]] || continue
        run_scan 30 find "$dir" -maxdepth 3 -type f \
            \( -name '*.conf' -o -name 'httpd.conf' -o -name 'apache2.conf' \) \
            -print 2>/dev/null
    done | sort -u
}

web_apache_roots() {

    local file

    # Only enabled vhosts matter, but sites-available is included
    # when nothing is enabled, so a misconfigured host still gets
    # its roots reported rather than silently skipped.
    while IFS= read -r file; do
        [[ -r "$file" ]] || continue
        awk '
            /^[[:space:]]*#/ { next }
            /^[[:space:]]*DocumentRoot[[:space:]]/ {
                v = $2
                gsub(/["'"'"']/, "", v)
                sub(/\/+$/, "", v)
                if (v != "") print v
            }
        ' "$file" 2>/dev/null
    done < <(web_apache_config_files) | sort -u
}

# --- Conventional locations ------------------------------------

WEB_DEFAULT_ROOT_CANDIDATES="${WEB_DEFAULT_ROOT_CANDIDATES:-/var/www/html /var/www /website /usr/share/nginx/html /srv/www /home/www /opt/www}"

# A default location only counts when it actually holds content:
# an empty /var/www on a database server is not a web root.
web_default_roots() {
    local root
    for root in $WEB_DEFAULT_ROOT_CANDIDATES; do
        [[ -d "$root" ]] || continue
        run_scan 15 find "$root" -maxdepth 2 -type f \
            \( -iname '*.php' -o -iname '*.html' -o -iname '*.htm' -o -iname 'index.*' \) \
            -print -quit 2>/dev/null | grep -q . && printf '%s\n' "$root"
    done
}

# --- Orchestration ---------------------------------------------

web_discover_roots() {

    (( ${#WEB_SCAN_ROOTS[@]} > 0 )) && return 0

    local root seen covered source
    local -a candidates=() sources=()

    add_candidate() {
        [[ -n "$1" ]] || return 0
        candidates+=("$1")
        sources+=("$2")
    }

    # 1. operator configuration
    for root in $WEB_ROOTS; do
        add_candidate "$root" "audit.conf:WEB_ROOTS"
    done

    # 2. roots discovered earlier in this run, or cached
    local cache
    for cache in "$ITM_RUN_TMP/nginx-roots.list" "$ITM_NGINX_ROOT_CACHE"; do
        [[ -r "$cache" ]] || continue
        while IFS= read -r root; do
            add_candidate "$root" "nginx"
        done < "$cache"
        break
    done

    for cache in "$ITM_RUN_TMP/apache-roots.list" "$ITM_APACHE_ROOT_CACHE"; do
        [[ -r "$cache" ]] || continue
        while IFS= read -r root; do
            add_candidate "$root" "apache"
        done < "$cache"
        break
    done

    # 3. ask the web servers directly
    while IFS= read -r root; do
        add_candidate "$root" "nginx -T"
    done < <(web_nginx_roots)

    while IFS= read -r root; do
        add_candidate "$root" "apache config"
    done < <(web_apache_roots)

    # 4. conventional locations holding content
    while IFS= read -r root; do
        add_candidate "$root" "conventional location"
    done < <(web_default_roots)

    local i
    for (( i = 0; i < ${#candidates[@]}; i++ )); do

        root="${candidates[$i]}"
        source="${sources[$i]}"

        [[ -d "$root" ]] || continue

        # Refuse roots that would scan the whole filesystem.
        case "$root" in
            /|/usr|/etc|/var|/home|/opt|/srv) continue ;;
        esac

        covered=0
        for seen in ${WEB_SCAN_ROOTS[@]+"${WEB_SCAN_ROOTS[@]}"}; do
            [[ "$root" == "$seen" || "$root" == "$seen"/* ]] && covered=1 && break
        done
        (( covered )) && continue

        WEB_SCAN_ROOTS+=("$root")
        WEB_ROOT_SOURCE["$root"]="$source"
    done

    (( ${#WEB_SCAN_ROOTS[@]} > 0 ))
}

# Backwards compatible name used by the existing modules.
web_scan_roots() { web_discover_roots; }

web_roots_provenance() {
    local root out=""
    for root in ${WEB_SCAN_ROOTS[@]+"${WEB_SCAN_ROOTS[@]}"}; do
        out+="${out:+, }${root} (via ${WEB_ROOT_SOURCE[$root]:-unknown})"
    done
    printf '%s' "$out"
}

# ------------------------------------------------------------
# No roots on a host that serves web content is a MONITORING
# FAILURE, not an informational note.
#
# Reporting it at INFO is what kept the Satudata host quiet: the
# scan found nothing because it looked nowhere, and nothing below
# HIGH ever reaches Telegram.
# ------------------------------------------------------------

web_report_no_roots() {

    local module_label="$1"

    add_finding HIGH \
        "MONITORING DEGRADED: ${module_label} has no web root to scan" \
        id="web-no-roots:${CURRENT_MODULE}" \
        confidence=99 \
        reasons="This host is classified as running a web application
No document root could be discovered from Nginx, Apache, or the conventional locations
The scan therefore examined NOTHING - this is not a clean result" \
        evidence="Discovery sources tried: audit.conf WEB_ROOTS, nginx -T, Apache configuration ($APACHE_CONF_DIRS), conventional locations.
Web server detected by role module: ${ROLE_WEB_SERVER:-unknown}" \
        action="Set WEB_ROOTS in ${ITM_AUDIT_CONF} to the document root(s) of this host, then re-run: itm-security audit webshell gambling seo. Until then the web content modules are blind on this server."
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
                    name_args+=( -iname "*.$ext" ); first=0
                done ;;
        markup) for ext in $WEB_MARKUP_EXT; do
                    (( first )) || name_args+=( -o )
                    name_args+=( -iname "*.$ext" ); first=0
                done ;;
        both)   for ext in $WEB_CODE_EXT $WEB_MARKUP_EXT; do
                    (( first )) || name_args+=( -o )
                    name_args+=( -iname "*.$ext" ); first=0
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

# ------------------------------------------------------------
# Files that must be examined on EVERY run
#
# The incremental window makes routine scans cheap, but a
# handful of files decide whether a site is poisoned and must
# never be skipped because their mtime is older than the last
# scan:
#
#   index.php  vendor.js  robots.txt  sitemap.xml
#   .htaccess  .user.ini
#
# The Satudata payload was exactly this shape: a top level
# vendor.js and an edited index.php.
# ------------------------------------------------------------

WEB_ALWAYS_CHECK="${WEB_ALWAYS_CHECK:-index.php index.html vendor.js app.js main.js bundle.js robots.txt sitemap.xml sitemap_index.xml .htaccess .user.ini .env}"

web_enumerate_always() {

    local root="$1" name

    # Top level of the root, plus one level down for the common
    # public/ layout.
    for name in $WEB_ALWAYS_CHECK; do
        [[ -f "$root/$name" ]]         && printf '%s\n' "$root/$name"
        [[ -f "$root/public/$name" ]]  && printf '%s\n' "$root/public/$name"
    done

    # Any file sitting at the very top of a document root is
    # worth looking at regardless of its name or extension: that
    # is where a dropped payload has to live to be reachable.
    run_scan 20 find "$root" -maxdepth 1 -type f \
        -size -"$(( WEB_MAX_FILE_BYTES / 1024 + 1 ))"k -print 2>/dev/null
}

# ------------------------------------------------------------
# The enumeration every content module should use.
#
# Incremental window PLUS the always-check set, deduplicated.
# A file whose mtime predates the last scan is still examined
# when it is one of the files that decides whether the site is
# poisoned.
# ------------------------------------------------------------

web_enumerate_scan() {
    local root="$1" mode="${2:-both}" since="${3:-0}"
    {
        web_enumerate "$root" "$mode" "$since"
        web_enumerate_always "$root"
    } | awk '!seen[$0]++'
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

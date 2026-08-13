#!/usr/bin/env bash
# shellcheck shell=bash

# ============================================================
# ITM Server Security Monitor
# Post-Compromise Audit - Module G: web filesystem
#
# Read only. No web file is quarantined, renamed or deleted:
# on a production CMS a false positive that removes a file is
# an outage.
#
# Web roots come from three sources, in this order:
#   1. WEB_ROOTS in audit.conf
#   2. document roots discovered by the Nginx module
#   3. conventional locations that actually exist
#
# Scans are bounded: every find and grep runs under timeout,
# with a depth limit, a prune list and a result cap, so this
# module cannot turn into an IO storm on a busy server.
#
# False positive policy:
#   Generic strings such as "socket", "curl", "ngrok" or
#   "base64_decode" on their own are NOT treated as malicious.
#   A finding needs a dangerous sink combined with attacker
#   controlled input, an obfuscation chain, or a known shell
#   signature.
# ============================================================

WEB_DEFAULT_ROOTS="/website /var/www /usr/share/nginx/html /srv/www /home/www"

# High confidence webshell signatures.
WEB_IOC_PATTERN='eval[[:space:]]*\([[:space:]]*(base64_decode|gzinflate|gzuncompress|str_rot13|\$_(GET|POST|REQUEST|COOKIE))|(system|exec|shell_exec|passthru|popen|proc_open)[[:space:]]*\([[:space:]]*(\$_(GET|POST|REQUEST|COOKIE)|"?\$)|assert[[:space:]]*\([[:space:]]*\$_(GET|POST|REQUEST|COOKIE)|preg_replace[[:space:]]*\(.*/[a-z]*e[a-z]*["'"'"'],|create_function[[:space:]]*\([[:space:]]*.{0,20}\$_(GET|POST|REQUEST)|\$_(GET|POST|REQUEST|COOKIE)\[[^]]*\][[:space:]]*\([[:space:]]*\$_(GET|POST|REQUEST|COOKIE)|FilesMan|b374k|c99shell|r57shell|IndoXploit|wso_version|WSO[[:space:]]*[0-9]\.[0-9]|Mini[[:space:]]*Shell|AnonymousFox'

WEB_ROOT_LIST=()

# ------------------------------------------------------------
# Root discovery
# ------------------------------------------------------------

web_collect_roots() {

    local root candidates=() seen

    for root in $WEB_ROOTS; do
        candidates+=("$root")
    done

    if [[ -r "$ITM_RUN_TMP/nginx-roots.list" ]]; then
        while IFS= read -r root; do
            [[ -n "$root" ]] && candidates+=("$root")
        done < "$ITM_RUN_TMP/nginx-roots.list"
    elif [[ -r "$ITM_NGINX_ROOT_CACHE" ]]; then
        while IFS= read -r root; do
            [[ -n "$root" ]] && candidates+=("$root")
        done < "$ITM_NGINX_ROOT_CACHE"
    fi

    for root in $WEB_DEFAULT_ROOTS; do
        candidates+=("$root")
    done

    WEB_ROOT_LIST=()

    for root in ${candidates[@]+"${candidates[@]}"}; do

        [[ -d "$root" ]] || continue

        # Skip a root already covered by a shorter root, so a
        # deep vhost root is not rescanned under its parent.
        local covered=0
        for seen in ${WEB_ROOT_LIST[@]+"${WEB_ROOT_LIST[@]}"}; do
            [[ "$root" == "$seen" || "$root" == "$seen"/* ]] && covered=1 && break
        done
        (( covered )) && continue

        WEB_ROOT_LIST+=("$root")
    done
}

# Prune expression shared by every find in this module.
web_find_prune_args() {
    local d
    WEB_PRUNE=()
    for d in $WEB_EXCLUDE_DIRS; do
        WEB_PRUNE+=( -name "$d" -o )
    done
    (( WEB_EXCLUDE_VENDOR )) && WEB_PRUNE+=( -name vendor -o )
    WEB_PRUNE+=( -false )
}

web_grep_exclude_args() {
    local d
    WEB_GREP_EXCLUDE=()
    for d in $WEB_EXCLUDE_DIRS; do
        WEB_GREP_EXCLUDE+=( "--exclude-dir=$d" )
    done
    (( WEB_EXCLUDE_VENDOR )) && WEB_GREP_EXCLUDE+=( "--exclude-dir=vendor" )
}

# Was PHP execution confirmed for this path by the Nginx module?
web_php_enabled_here() {
    local path="$1" root
    [[ -s "$ITM_RUN_TMP/nginx_servers.txt" ]] || return 1
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
    done < "$ITM_RUN_TMP/nginx_servers.txt"
    return 1
}

# ------------------------------------------------------------
# PHP inside upload / data directories
# ------------------------------------------------------------

check_php_in_upload_dirs() {

    local root dir file count=0 listed
    local total_dirs=0

    for root in ${WEB_ROOT_LIST[@]+"${WEB_ROOT_LIST[@]}"}; do

        web_find_prune_args

        while IFS= read -r dir; do

            [[ -n "$dir" ]] || continue
            total_dirs=$(( total_dirs + 1 ))

            listed="$(run_timeout "$FIND_TIMEOUT" find "$dir" -maxdepth 4 -type f \
                \( -name '*.php' -o -name '*.phtml' -o -name '*.phar' -o -name '*.php[0-9]' -o -name '*.pht' \) \
                2>/dev/null | head -"$WEB_MAX_REPORTED")"

            [[ -n "$listed" ]] || continue

            count=$(( count + 1 ))

            local sev=HIGH
            local why="This directory is intended for uploaded or static content."

            if web_php_enabled_here "$dir"; then
                sev=CRITICAL
                why="The Nginx module confirmed a PHP handler covers this path, so these files are DIRECTLY EXECUTABLE over HTTP."
            fi

            add_finding "$sev" \
                "PHP source files present in an upload/data directory" \
                id="php-in-upload:$dir" \
                path="$dir" \
                evidence="$why
Files:
$(truncate_text "$listed" 700)" \
                action="Review each file against the application's release. Preserve anything unexpected (copy to /root/forensic) before removing it, and remove PHP execution for this directory in Nginx rather than relying on file cleanup."

        done < <(run_timeout "$FIND_TIMEOUT" find "$root" -regextype posix-extended -maxdepth "$WEB_SCAN_MAXDEPTH" \
                    \( "${WEB_PRUNE[@]}" \) -prune -o \
                    -type d -iregex ".*/${UPLOAD_DIR_PATTERN}" -print 2>/dev/null)

    done

    audit_log INFO "examined $total_dirs upload/data directories"

    (( count == 0 )) && add_pass "no PHP source file found in upload/data directories"
}

# ------------------------------------------------------------
# Webshell signatures
# ------------------------------------------------------------

check_webshell_signatures() {

    local root hits count=0 file

    have_cmd grep || { add_skip "grep not available - IOC scan skipped"; return 0; }

    web_grep_exclude_args

    for root in ${WEB_ROOT_LIST[@]+"${WEB_ROOT_LIST[@]}"}; do

        hits="$(run_timeout "$FIND_TIMEOUT" grep -rlIE \
                    --include='*.php' --include='*.phtml' --include='*.phar' \
                    --include='*.inc' --include='*.php[0-9]' \
                    "${WEB_GREP_EXCLUDE[@]}" \
                    "$WEB_IOC_PATTERN" "$root" 2>/dev/null | head -"$WEB_MAX_REPORTED")"

        [[ -n "$hits" ]] || continue

        while IFS= read -r file; do

            [[ -n "$file" ]] || continue
            count=$(( count + 1 ))

            add_finding CRITICAL \
                "PHP file matches a webshell signature" \
                id="webshell:$file" \
                path="$file" \
                evidence="owner=$(stat -c '%U:%G' "$file" 2>/dev/null) mode=$(stat -c '%a' "$file" 2>/dev/null) size=$(stat -c '%s' "$file" 2>/dev/null) mtime=$(file_mtime_human "$file") sha256=$(file_sha256 "$file")
Match: $(truncate_text "$(run_timeout 15 grep -oEm2 "$WEB_IOC_PATTERN" "$file" 2>/dev/null | tr '\n' ' ')" 200)" \
                action="Do not delete yet. Copy the file to /root/forensic, then find the upload in the Nginx access log by matching the file mtime. Rotate any credential present in the application configuration."

        done <<< "$hits"
    done

    (( count == 0 )) && add_pass "no webshell signature matched in the scanned web roots"
}

# ------------------------------------------------------------
# PHP code hidden inside non-PHP files
# ------------------------------------------------------------

check_polyglot_uploads() {

    local root dir hits file count=0

    web_grep_exclude_args

    for root in ${WEB_ROOT_LIST[@]+"${WEB_ROOT_LIST[@]}"}; do

        web_find_prune_args

        while IFS= read -r dir; do

            [[ -n "$dir" ]] || continue

            hits="$(run_timeout 60 grep -rlI \
                        --include='*.jpg' --include='*.jpeg' --include='*.png' --include='*.gif' \
                        --include='*.pdf' --include='*.txt' --include='*.html' --include='*.htaccess' \
                        "${WEB_GREP_EXCLUDE[@]}" \
                        -e '<?php' "$dir" 2>/dev/null | head -10)"

            [[ -n "$hits" ]] || continue

            while IFS= read -r file; do
                [[ -n "$file" ]] || continue
                count=$(( count + 1 ))
                add_finding HIGH \
                    "PHP code embedded in a non-PHP file inside an upload directory" \
                    id="polyglot:$file" \
                    path="$file" \
                    evidence="mtime=$(file_mtime_human "$file") size=$(stat -c '%s' "$file" 2>/dev/null) sha256=$(file_sha256 "$file")
The file carries a static content extension but contains a PHP open tag." \
                    action="Harmless while PHP execution is disabled for this directory, and immediately exploitable if it is not. Confirm the Nginx PHP rule for this path, then preserve and remove the file."
            done <<< "$hits"

        done < <(run_timeout "$FIND_TIMEOUT" find "$root" -regextype posix-extended -maxdepth "$WEB_SCAN_MAXDEPTH" \
                    \( "${WEB_PRUNE[@]}" \) -prune -o \
                    -type d -iregex ".*/${UPLOAD_DIR_PATTERN}" -print 2>/dev/null)
    done

    (( count == 0 )) && add_pass "no PHP code embedded in static upload files"
}

# ------------------------------------------------------------
# Exposed development and deployment artefacts
# ------------------------------------------------------------

check_exposed_artifacts() {

    local root found=0 item sev

    for root in ${WEB_ROOT_LIST[@]+"${WEB_ROOT_LIST[@]}"}; do

        web_find_prune_args

        while IFS= read -r item; do

            [[ -n "$item" ]] || continue

            case "$(basename "$item")" in
                .env|.env.*)
                    sev=HIGH ;;
                .git|.svn|.hg)
                    sev=HIGH ;;
                composer.json|composer.lock|package.json|yarn.lock|Dockerfile|docker-compose.yml)
                    sev=LOW ;;
                *.sql|*.sql.gz|*.dump)
                    sev=HIGH ;;
                *.bak|*.old|*.orig|*.save|*.swp|*.zip|*.tar|*.tar.gz|*.tgz|*.rar)
                    sev=MEDIUM ;;
                *)
                    continue ;;
            esac

            found=$(( found + 1 ))

            add_finding "$sev" \
                "Development or backup artefact exposed under a web root" \
                id="web-artifact:$item" \
                path="$item" \
                evidence="owner=$(stat -c '%U:%G' "$item" 2>/dev/null) mode=$(stat -c '%a' "$item" 2>/dev/null) mtime=$(file_mtime_human "$item")
Reachable over HTTP unless an Nginx deny rule covers it." \
                action="Move the artefact outside the document root. Database dumps and .env files hand over credentials in a single request; .git exposes the full source history."

        done < <(run_timeout "$FIND_TIMEOUT" find "$root" -maxdepth 4 \
                    \( "${WEB_PRUNE[@]}" \) -prune -o \
                    \( -name '.env' -o -name '.env.*' -o -name '.git' -o -name '.svn' -o -name '.hg' \
                       -o -name 'composer.json' -o -name 'composer.lock' \
                       -o -name '*.sql' -o -name '*.sql.gz' -o -name '*.dump' \
                       -o -name '*.bak' -o -name '*.old' -o -name '*.orig' -o -name '*.save' \
                       -o -name '*.zip' -o -name '*.tar' -o -name '*.tar.gz' -o -name '*.tgz' -o -name '*.rar' \) \
                    -print 2>/dev/null | head -"$WEB_MAX_REPORTED")
    done

    (( found == 0 )) && add_pass "no exposed development or backup artefact under the web roots"
}

# ------------------------------------------------------------
# Permissions
# ------------------------------------------------------------

check_web_permissions() {

    local root listed suid=0 ww=0

    for root in ${WEB_ROOT_LIST[@]+"${WEB_ROOT_LIST[@]}"}; do

        web_find_prune_args

        # SUID/SGID under a web root has no legitimate use.
        listed="$(run_timeout "$FIND_TIMEOUT" find "$root" -maxdepth "$WEB_SCAN_MAXDEPTH" \
                    \( "${WEB_PRUNE[@]}" \) -prune -o \
                    -type f \( -perm -4000 -o -perm -2000 \) -print 2>/dev/null | head -20)"

        if [[ -n "$listed" ]]; then
            suid=$(( suid + 1 ))
            add_finding CRITICAL \
                "SUID or SGID file inside a web root" \
                id="web-suid:$root" \
                path="$root" \
                evidence="$(truncate_text "$listed" 600)" \
                action="A setuid binary reachable from the web tree is a privilege escalation primitive. Preserve it, record the hash, then isolate the host."
        fi

        # World writable directories let any local account, and
        # any web process, drop a file into the tree.
        listed="$(run_timeout "$FIND_TIMEOUT" find "$root" -maxdepth "$WEB_SCAN_MAXDEPTH" \
                    \( "${WEB_PRUNE[@]}" \) -prune -o \
                    -type d -perm -0002 ! -type l -print 2>/dev/null | head -20)"

        if [[ -n "$listed" ]]; then
            ww=$(( ww + 1 ))
            add_finding MEDIUM \
                "World writable directory inside a web root" \
                id="web-worldwritable:$root" \
                path="$root" \
                evidence="$(truncate_text "$listed" 600)" \
                action="Tighten to the application owner and group (typically 0755, or 0775 where the PHP-FPM pool user must write). Do not change permissions during peak hours without testing uploads afterwards."
        fi
    done

    (( suid == 0 )) && add_pass "no SUID/SGID file inside the web roots"
    (( ww   == 0 )) && add_pass "no world writable directory inside the web roots"
}

# ------------------------------------------------------------
# Recent changes
# ------------------------------------------------------------

check_recent_web_changes() {

    local root listed count

    for root in ${WEB_ROOT_LIST[@]+"${WEB_ROOT_LIST[@]}"}; do

        web_find_prune_args

        listed="$(run_timeout "$FIND_TIMEOUT" find "$root" -maxdepth "$WEB_SCAN_MAXDEPTH" \
                    \( "${WEB_PRUNE[@]}" \) -prune -o \
                    -type f \( -name '*.php' -o -name '*.phtml' -o -name '*.js' -o -name '*.htaccess' \) \
                    -mtime -"$WEB_RECENT_DAYS" -print 2>/dev/null | head -"$WEB_MAX_REPORTED")"

        [[ -n "$listed" ]] || continue

        count="$(printf '%s\n' "$listed" | wc -l)"

        add_finding LOW \
            "Executable web content modified in the last ${WEB_RECENT_DAYS} days" \
            id="web-recent:$root" \
            path="$root" \
            evidence="$count file(s), newest first:
$(truncate_text "$listed" 700)" \
            action="Match against the deployment record. On a CMS this is normal after an update and worth a second look otherwise."
    done
}

# ============================================================
# ENTRY POINT
# ============================================================

run_audit_web() {

    module_begin "web" "Web Filesystem"

    web_collect_roots

    if (( ${#WEB_ROOT_LIST[@]} == 0 )); then
        add_skip "no web root found - set WEB_ROOTS in ${ITM_AUDIT_CONF}"
        module_end
        return 0
    fi

    add_pass "web roots in scope: ${WEB_ROOT_LIST[*]}"

    check_php_in_upload_dirs
    check_webshell_signatures
    check_polyglot_uploads
    check_exposed_artifacts
    check_web_permissions
    check_recent_web_changes

    module_end
}

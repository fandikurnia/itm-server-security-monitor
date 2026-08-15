#!/usr/bin/env bash
# shellcheck shell=bash

# ============================================================
# ITM Server Security Monitor
# Web content audit - Module W1: webshell and upload abuse
#
# Read only. A suspected webshell is hashed, snapshotted and
# reported. It is never deleted, renamed, chmod'ed or executed.
#
# Scoring, not signatures alone. Every one of these appears in
# legitimate code:
#
#   base64_decode   - used by half the CMS ecosystem
#   eval            - used by templating engines
#   adminer.php     - a real database tool people install
#   a .php in /data - some applications really do that
#
# What separates a webshell from a framework is the
# combination: an obfuscated payload, in a directory meant for
# uploads, owned by the web server account, created hours ago,
# reachable as PHP over HTTP. Each of those adds points; the
# total decides the severity and the confidence, and every
# reason is reported so an operator can disagree with the tool.
# ============================================================

# ------------------------------------------------------------
# Built-in structural patterns
#
# These describe code STRUCTURE, not vocabulary, so they stay
# in the module. Vocabulary lives in the IOC files.
# ------------------------------------------------------------

WS_EXEC_SINK='\b(system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)[[:space:]]*\('
WS_EVAL_SINK='\b(eval|assert|create_function)[[:space:]]*\('
WS_DECODER='\b(base64_decode|gzinflate|gzuncompress|str_rot13|hex2bin|convert_uudecode|zlib_decode)[[:space:]]*\('
WS_INPUT='\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)\b'
WS_DYNAMIC_CALL='\$[a-zA-Z_][a-zA-Z0-9_]*[[:space:]]*\([[:space:]]*\$'
WS_REMOTE='\b(curl_exec|file_get_contents[[:space:]]*\([[:space:]]*["'"'"']https?://|fsockopen|fopen[[:space:]]*\([[:space:]]*["'"'"']https?://|socket_create)'
WS_FILEWRITE='\b(file_put_contents|fwrite|fputs)[[:space:]]*\('
WS_OBFUSCATION='(\\\\x[0-9a-fA-F]{2}){4,}|(chr[[:space:]]*\([0-9]+\)[[:space:]]*\.[[:space:]]*){4,}|\$[a-zA-Z_]+\{[0-9]+\}'
WS_UPLOAD='\bmove_uploaded_file[[:space:]]*\('
WS_SELFMOD='__FILE__[^;]{0,60}(file_put_contents|fwrite|unlink|chmod)'

# Double extension: image.jpg.php, document.pdf.php
WS_DOUBLE_EXT='\.(jpe?g|png|gif|bmp|webp|svg|pdf|docx?|xlsx?|zip|rar|txt|csv)\.(php|phtml|phar|php[0-9]|pht)$'

# ------------------------------------------------------------
# Content classification of one PHP file
# ------------------------------------------------------------

ws_score_file() {

    local content="$1"
    local hits=0

    # ---- obfuscation and dynamic execution ----
    if printf '%s' "$content" | grep -qE "$WS_EVAL_SINK"; then
        if printf '%s' "$content" | grep -qE "${WS_EVAL_SINK}[[:space:]]*[^;]{0,80}${WS_DECODER}"; then
            score_add 45 "eval/assert of a decoded payload (classic packed webshell)"
            hits=$(( hits + 1 ))
        elif printf '%s' "$content" | grep -qE "${WS_EVAL_SINK}[[:space:]]*[^;]{0,80}${WS_INPUT}"; then
            score_add 50 "eval/assert applied directly to request input"
            hits=$(( hits + 1 ))
        else
            score_add 10 "eval/assert present (also used by legitimate templating)"
        fi
    fi

    # ---- command execution on request input ----
    if printf '%s' "$content" | grep -qE "${WS_EXEC_SINK}[[:space:]]*[^;]{0,60}${WS_INPUT}"; then
        score_add 50 "shell command executed with request input"
        hits=$(( hits + 1 ))
    elif printf '%s' "$content" | grep -qE "$WS_EXEC_SINK"; then
        score_add 12 "command execution function present"
    fi

    # ---- decoders on their own ----
    if printf '%s' "$content" | grep -qE "$WS_DECODER"; then
        score_add 8 "payload decoder present"
    fi

    # ---- dynamic function invocation ----
    if printf '%s' "$content" | grep -qE "$WS_DYNAMIC_CALL"; then
        score_add 15 "dynamic function invocation from a variable"
        hits=$(( hits + 1 ))
    fi

    # ---- character level obfuscation ----
    if printf '%s' "$content" | grep -qE "$WS_OBFUSCATION"; then
        score_add 25 "character level obfuscation (hex/chr concatenation)"
        hits=$(( hits + 1 ))
    fi

    # ---- remote fetch ----
    if printf '%s' "$content" | grep -qE "$WS_REMOTE"; then
        score_add 15 "remote download / raw socket capability"
    fi

    # ---- writes executable content ----
    if printf '%s' "$content" | grep -qE "$WS_FILEWRITE" \
        && printf '%s' "$content" | grep -qE '\.ph(p|tml|ar)'; then
        score_add 30 "writes a PHP file to disk"
        hits=$(( hits + 1 ))
    fi

    # ---- self modifying ----
    if printf '%s' "$content" | grep -qE "$WS_SELFMOD"; then
        score_add 25 "self modifying code"
        hits=$(( hits + 1 ))
    fi

    # ---- upload handler ----
    if printf '%s' "$content" | grep -qE "$WS_UPLOAD"; then
        score_add 10 "file upload handler"
    fi

    # ---- named shell families from the IOC list ----
    local pattern
    for pattern in ${WEBSHELL_PATTERNS[@]+"${WEBSHELL_PATTERNS[@]}"}; do
        local value weight
        value="$(ioc_entry_value "$pattern")"
        weight="$(ioc_entry_weight "$pattern" 40)"
        [[ -n "$value" ]] || continue
        if printf '%s' "$content" | grep -qiE "$value"; then
            score_add "$weight" "matches known webshell signature: ${value:0:40}"
            hits=$(( hits + 1 ))
        fi
    done

    return $(( hits > 0 ? 0 : 1 ))
}

# ------------------------------------------------------------
# Context scoring: where the file is, who owns it, how old
# ------------------------------------------------------------

ws_score_context() {

    local path="$1" in_upload="$2"

    if (( in_upload )); then
        score_add 30 "located in an upload/static content directory"

        if web_php_reachable "$path"; then
            score_add 25 "Nginx executes PHP for this path (directly reachable over HTTP)"
        fi
    fi

    if web_owner_is_service_account "$WF_OWNER"; then
        score_add 20 "owned by the web service account ($WF_OWNER) - written by the application, not deployed"
    fi

    if web_file_is_new; then
        score_add 20 "created or modified in the last ${WF_AGE_HOURS}h"
    fi

    # A tiny PHP file that does something is a loader.
    if (( WF_SIZE > 0 && WF_SIZE < 700 )); then
        score_add 10 "very small PHP file (${WF_SIZE} bytes) - typical loader/stager size"
    fi

    if [[ "$WF_NAME" =~ ^\. ]]; then
        score_add 20 "hidden file"
    fi

    if printf '%s' "$WF_NAME" | grep -qE "$WS_DOUBLE_EXT"; then
        score_add 45 "double extension ($WF_NAME) - disguised as a document or image"
    fi

    # Executable bit on web content is never needed.
    if [[ "$WF_MODE" =~ ^[0-7]+$ ]] && (( (8#$WF_MODE & 8#0111) != 0 )); then
        score_add 10 "executable permission bit set on web content"
    fi

    local entry value weight
    for entry in ${SUSPICIOUS_FILENAMES[@]+"${SUSPICIOUS_FILENAMES[@]}"}; do
        value="$(ioc_entry_value "$entry")"
        weight="$(ioc_entry_weight "$entry" 20)"
        [[ -n "$value" ]] || continue
        # shellcheck disable=SC2053
        if [[ "$WF_NAME" == $value ]]; then
            score_add "$weight" "filename matches a known tool/shell name pattern ($value)"
            break
        fi
    done
}

# ------------------------------------------------------------
# Main scan
# ------------------------------------------------------------

check_webshells() {

    local root dir file content
    local scanned=0 reported=0
    local -A upload_index=()

    for root in "${WEB_SCAN_ROOTS[@]}"; do

        # Index of upload directories, for context scoring.
        while IFS= read -r dir; do
            [[ -n "$dir" ]] && upload_index["$dir"]=1
        done < <(web_upload_dirs "$root")

        while IFS= read -r file; do

            [[ -n "$file" ]] || continue
            web_path_excluded "$file" && continue
            web_file_facts "$file" || continue

            scanned=$(( scanned + 1 ))

            local in_upload=0 d
            for d in "${!upload_index[@]}"; do
                [[ "$file" == "$d"/* ]] && in_upload=1 && break
            done

            content="$(web_file_head "$file" 131072)"
            [[ -n "$content" ]] || continue

            score_reset
            local content_hit=0
            ws_score_file "$content" && content_hit=1
            ws_score_context "$file" "$in_upload"

            # Provenance alone is not a detection. Every
            # application has small, recently deployed PHP files
            # in its source tree; without a single code
            # indicator, and outside an upload directory, that is
            # a release, not an intrusion.
            if (( content_hit == 0 && in_upload == 0 )); then
                continue
            fi

            if (( SCORE_TOTAL >= SCORE_THRESHOLD_LOW )); then
                if web_report_file_finding \
                    "webshell:$file" \
                    "Suspected webshell or unauthorised PHP file" \
                    "Do not delete or open in a browser. Preserve it: the audit has already copied it to the evidence directory and recorded its SHA256. Correlate the modification time with the Nginx access log to find the upload request, then remove PHP execution for the containing directory before cleaning up files."
                then
                    reported=$(( reported + 1 ))
                fi
            fi

        done < <(web_enumerate_scan "$root" code "$WEB_SCAN_SINCE")

    done

    audit_log INFO "webshell scan examined $scanned PHP files, reported $reported"

    if (( reported == 0 )); then
        if (( WEB_SCAN_FULL )); then
            add_pass "no known webshell indicator in $scanned PHP files (full scan)"
        else
            add_pass "no known webshell indicator in $scanned PHP files changed since the last scan"
        fi
    fi
}

# ------------------------------------------------------------
# PHP code hidden inside static uploads
# ------------------------------------------------------------

check_polyglot_files() {

    local root dir hits file found=0

    for root in "${WEB_SCAN_ROOTS[@]}"; do
        while IFS= read -r dir; do

            [[ -n "$dir" ]] || continue

            hits="$(run_scan 60 grep -rlI \
                        --include='*.jpg' --include='*.jpeg' --include='*.png' \
                        --include='*.gif' --include='*.webp' --include='*.pdf' \
                        --include='*.txt' --include='*.csv' --include='*.svg' \
                        -e '<?php' -e '<?=' "$dir" 2>/dev/null | head -10)"

            [[ -n "$hits" ]] || continue

            while IFS= read -r file; do

                [[ -n "$file" ]] || continue
                web_path_excluded "$file" && continue
                web_file_facts "$file" || continue

                score_reset
                score_add 40 "PHP open tag inside a static content file"
                web_php_reachable "$file" && score_add 25 "PHP handler covers this directory"
                web_file_is_new && score_add 15 "written in the last ${WF_AGE_HOURS}h"
                web_owner_is_service_account "$WF_OWNER" && score_add 15 "owned by $WF_OWNER"

                web_report_file_finding \
                    "polyglot:$file" \
                    "PHP code embedded in a static upload file" \
                    "Harmless while PHP execution is disabled for this directory and immediately exploitable if it is not. Confirm the Nginx rule for this path first, then preserve and remove the file." \
                    && found=$(( found + 1 ))

            done <<< "$hits"

        done < <(web_upload_dirs "$root")
    done

    (( found == 0 )) && add_pass "no PHP code embedded in static upload files"
}

# ------------------------------------------------------------
# Writable directories that also execute PHP
#
# This is the condition that turns any file upload bug into
# remote code execution.
# ------------------------------------------------------------

check_writable_php_dirs() {

    local root dir found=0 checked=0

    for root in "${WEB_SCAN_ROOTS[@]}"; do
        while IFS= read -r dir; do

            [[ -n "$dir" ]] || continue
            checked=$(( checked + 1 ))

            web_dir_service_writable "$dir" || continue

            local reachable=0
            web_php_reachable "$dir" && reachable=1

            score_reset
            score_add 35 "directory is writable by the web service account"
            (( reachable )) && score_add 50 "Nginx executes PHP in this directory"

            local sev="MEDIUM"
            (( reachable )) && sev="CRITICAL"

            found=$(( found + 1 ))

            add_finding "$sev" \
                "Writable web directory permits PHP execution" \
                id="writable-php-dir:$dir" \
                path="$dir" \
                confidence="$(score_confidence)" \
                reasons="$SCORE_REASONS" \
                evidence="mode=$(stat -Lc '%a' "$dir" 2>/dev/null) owner=$(stat -Lc '%U:%G' "$dir" 2>/dev/null)
PHP execution reachable: $( (( reachable )) && echo YES || echo "not confirmed" )
Any upload flaw in the application becomes remote code execution while both conditions hold." \
                action="Break one of the two conditions. Preferred, and reversible without touching permissions:
  location ~* /$(basename "$dir")/.*\\.(php|phtml|phar|php[0-9]*)\$ { return 403; }
Then verify with 'nginx -t' and reload in a maintenance window. Do not simply chmod the directory: the application needs to write there."

        done < <(web_upload_dirs "$root")
    done

    (( found == 0 )) && add_pass "no writable upload directory with PHP execution ($checked directories checked)"
}

# ------------------------------------------------------------
# Access log correlation
#
# The sequence that matters:
#   POST to an upload endpoint -> new PHP file appears ->
#   GET of that new file
#
# Any one of those alone is noise. Together they are an
# exploited upload.
# ------------------------------------------------------------

ws_access_logs() {

    local logs=() f

    if [[ -s "$ITM_RUN_TMP/nginx-T.txt" ]]; then
        while IFS= read -r f; do
            [[ -n "$f" && -r "$f" ]] && logs+=("$f")
        done < <(grep -hoE '^[[:space:]]*access_log[[:space:]]+[^;[:space:]]+' "$ITM_RUN_TMP/nginx-T.txt" 2>/dev/null \
                    | awk '{print $2}' | grep '^/' | sort -u)
    fi

    if (( ${#logs[@]} == 0 )); then
        while IFS= read -r f; do
            [[ -n "$f" ]] && logs+=("$f")
        done < <(find /var/log/nginx /var/log/httpd /var/log/apache2 -maxdepth 1 \
                    -name '*access*.log' -type f 2>/dev/null | head -10)
    fi

    printf '%s\n' ${logs[@]+"${logs[@]}"}
}

check_access_log_correlation() {

    local log lines tmp
    local suspicious=0 logs_read=0

    ACCESSLOG_MAX_LINES="${ACCESSLOG_MAX_LINES:-20000}"

    tmp="$ITM_RUN_TMP/accesslog.txt"
    : > "$tmp"

    while IFS= read -r log; do
        [[ -n "$log" && -r "$log" ]] || continue
        logs_read=$(( logs_read + 1 ))
        run_scan 30 tail -n "$ACCESSLOG_MAX_LINES" "$log" >> "$tmp" 2>/dev/null
    done < <(ws_access_logs)

    if (( logs_read == 0 )) || [[ ! -s "$tmp" ]]; then
        add_skip "no readable web access log - request correlation not performed"
        return 0
    fi

    lines="$(wc -l < "$tmp" 2>/dev/null || echo 0)"
    audit_log INFO "access log correlation over $lines lines from $logs_read log(s)"

    # ---- POST followed by GET of the same PHP file ----------
    #
    # Extracted with awk in one pass: the request path of every
    # POST to a .php, and of every GET to a .php.
    local correlated
    correlated="$(awk '
        {
            # Combined log format: ... "METHOD /path HTTP/1.1" status ...
            if (match($0, /"(GET|POST|PUT) [^ ]+ HTTP/)) {
                req = substr($0, RSTART + 1, RLENGTH - 6)
                split(req, parts, " ")
                method = parts[1]
                path = parts[2]
                sub(/\?.*$/, "", path)
                if (path ~ /\.(php|phtml|phar)$/) {
                    if (method == "POST") posted[path] = 1
                    else if (method == "GET" && posted[path]) hit[path] = 1
                }
            }
        }
        END { for (p in hit) print p }
    ' "$tmp" 2>/dev/null | head -10)"

    if [[ -n "$correlated" ]]; then
        suspicious=$(( suspicious + 1 ))
        add_finding HIGH \
            "PHP endpoint received a POST and was then fetched with GET" \
            id="accesslog-post-get" \
            confidence=70 \
            reasons="POST to a PHP path followed by a GET of the same path
This is the normal shape of upload-then-execute
Legitimate for some form handlers, so it is corroborating evidence rather than proof" \
            evidence="Paths: $(truncate_text "$(printf '%s' "$correlated" | tr '\n' ' ')" 400)" \
            action="Cross check each path against the webshell findings above and against the application's real endpoints. If the path is not a known endpoint, treat it as an exploited upload."
    fi

    # ---- requests for known shell filenames ------------------
    local shellnames=""
    local entry value
    for entry in ${SUSPICIOUS_FILENAMES[@]+"${SUSPICIOUS_FILENAMES[@]}"}; do
        value="$(ioc_entry_value "$entry")"
        value="${value//\*/}"
        [[ ${#value} -ge 4 ]] || continue
        shellnames+="${shellnames:+|}$(printf '%s' "$value" | sed 's/[.[\*^$]/\\&/g')"
    done

    if [[ -n "$shellnames" ]]; then
        local shellhits
        shellhits="$(grep -oiE "\"(GET|POST) [^ \"]*(${shellnames})[^ \"]*" "$tmp" 2>/dev/null \
            | awk '{print $2}' | sort | uniq -c | sort -rn | head -8)"

        if [[ -n "$shellhits" ]]; then
            suspicious=$(( suspicious + 1 ))
            add_finding MEDIUM \
                "Web requests for known webshell or admin tool filenames" \
                id="accesslog-shellnames" \
                confidence=55 \
                reasons="Request paths match known shell/tool filename patterns
Scanners probe for these names constantly, so a 404 storm is background noise
Only a 200 response indicates the file exists" \
                evidence="$(truncate_text "$shellhits" 400)" \
                action="Check the response codes for these paths. Sustained 404s are internet background scanning; a 200 means the file is present and must be investigated immediately."
        fi
    fi

    # ---- traversal and command injection parameters ----------
    local traversal
    traversal="$(grep -acE '(\.\./){2,}|%2e%2e%2f|\bcmd=|\bexec=|\bpasswd\b.*\betc\b' "$tmp" 2>/dev/null || echo 0)"

    if [[ "$traversal" =~ ^[0-9]+$ ]] && (( traversal > 20 )); then
        add_finding LOW \
            "Path traversal or command injection attempts in the access log" \
            id="accesslog-traversal" \
            confidence=40 \
            reasons="${traversal} requests contain traversal or command parameters
Constant background scanning makes volume alone weak evidence
Relevant only if a matching request returned 200" \
            evidence="${traversal} matching requests in the sampled window" \
            action="Confirm Fail2Ban is banning repeat offenders, and check whether any of these requests returned 200."
    fi

    (( suspicious == 0 )) && add_pass "no upload-then-execute pattern in the sampled access logs"
}

# ------------------------------------------------------------
# Web server spawning interpreters
# ------------------------------------------------------------

check_web_process_children() {

    local pid ppid exe pexe found=0 uid

    while IFS= read -r pid; do

        [[ -d "/proc/$pid" ]] || continue
        exe="$(readlink "/proc/$pid/exe" 2>/dev/null)" || continue
        [[ -n "$exe" ]] || continue

        case "$exe" in
            */bash|*/sh|*/dash|*/zsh|*/python*|*/perl|*/ruby|*/nc|*/ncat|*/socat|*/curl|*/wget) ;;
            *) continue ;;
        esac

        proc_read_status "$pid" || continue
        ppid="$PROC_PPID"
        uid="$PROC_UID"
        [[ -n "$ppid" && "$ppid" != "0" ]] || continue

        pexe="$(readlink "/proc/$ppid/exe" 2>/dev/null)"

        case "$pexe" in
            */php-fpm*|*/nginx|*/apache2|*/httpd|*/php) ;;
            *) continue ;;
        esac

        found=1

        add_finding CRITICAL \
            "Web server or PHP-FPM spawned an interpreter or network tool" \
            id="web-child:$exe:$pexe" \
            path="$exe" \
            confidence=95 \
            reasons="Parent process is the web server or PHP-FPM
Child is a shell, interpreter or network client
This is the execution stage of a webshell, not a normal request path" \
            process="child pid=$pid exe=$exe user=$(uid_to_name "$uid")
parent pid=$ppid exe=$pexe
cmdline=$(truncate_text "$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)" 200)" \
            evidence="A PHP application that shells out for image processing or mail can look like this. A shell, nc, curl or python under PHP-FPM during an incident is not that." \
            action="Do not kill the process. Capture /proc/$pid/exe, cmdline and open sockets now, then find the request in the Nginx access log at this timestamp."

    done < <(find /proc -maxdepth 1 -regex '/proc/[0-9]+' -printf '%f\n' 2>/dev/null)

    (( found == 0 )) && add_pass "no interpreter running as a child of the web server"
}

# ============================================================
# ENTRY POINT
# ============================================================

run_audit_webshell() {

    module_begin "webshell" "Webshell Detection"

    require_web_workload "Webshell scan" || { module_end; return 0; }

    web_load_iocs

    if ! web_scan_roots; then
        web_report_no_roots "Webshell scan"
        module_end
        return 0
    fi

    web_scan_window "webshell"

    add_pass "scanning $(printf '%s' "${#WEB_SCAN_ROOTS[@]}") web root(s): ${WEB_SCAN_ROOTS[*]} | mode=$( (( WEB_SCAN_FULL )) && echo full || echo "incremental since $(date -d "@$WEB_SCAN_SINCE" '+%Y-%m-%d %H:%M' 2>/dev/null)" ) | IOC $(web_ioc_status)"

    check_webshells
    check_polyglot_files
    check_writable_php_dirs
    check_access_log_correlation
    check_web_process_children

    web_scan_window_commit "webshell"

    module_end
}

#!/usr/bin/env bash
# shellcheck shell=bash

# ============================================================
# ITM Server Security Monitor
# Web content audit - Module W2: gambling / judi slot injection
#
# Read only. Nothing is edited or removed.
#
# Context decides severity, never a single keyword:
#
#   "deposit" in a government service page   -> vocabulary
#   "bonus new member" in an article          -> vocabulary
#   14 gambling terms in a file written by
#   www-data three hours ago, with an
#   external redirect and hidden anchors      -> injection
#
# On a .go.id host the appearance of this vocabulary anywhere
# is worth a look, which is why keyword density and file
# provenance are scored together rather than separately.
#
# Keywords live in config/gambling-keywords.conf so the list
# can be tuned without touching this file.
# ============================================================

GAMBLING_REGEX=""
GAMBLING_MIN_HITS="${GAMBLING_MIN_HITS:-1}"

gambling_build_regex() {
    [[ -n "$GAMBLING_REGEX" ]] && return 0
    GAMBLING_REGEX="$(ioc_build_regex GAMBLING_KEYWORDS)"
    [[ -n "$GAMBLING_REGEX" ]]
}

# ------------------------------------------------------------
# Count distinct gambling terms in a file
# ------------------------------------------------------------

gambling_hits() {
    local content="$1"
    printf '%s' "$content" | grep -oiE "$GAMBLING_REGEX" 2>/dev/null \
        | tr '[:upper:]' '[:lower:]' | sort -u
}

# ------------------------------------------------------------
# Corroborating indicators
#
# Injected gambling content almost never arrives alone: it
# comes with hidden markup, an external link farm, or a
# redirect.
# ------------------------------------------------------------

gambling_score_context() {

    local content="$1" path="$2"

    # Hidden text: the visitor never sees it, the crawler does.
    if printf '%s' "$content" | grep -qiE 'style=["'"'"'][^"'"'"']*(display[[:space:]]*:[[:space:]]*none|visibility[[:space:]]*:[[:space:]]*hidden|position[[:space:]]*:[[:space:]]*absolute[^"]*(left|top)[[:space:]]*:[[:space:]]*-[0-9]{3,}|text-indent[[:space:]]*:[[:space:]]*-[0-9]{4,}|font-size[[:space:]]*:[[:space:]]*0)'; then
        score_add 30 "hidden markup (display:none / off-screen / zero font) around the content"
    fi

    # Link farm.
    local extlinks
    extlinks="$(printf '%s' "$content" | grep -ocE 'href=["'"'"']https?://' 2>/dev/null || echo 0)"
    if [[ "$extlinks" =~ ^[0-9]+$ ]]; then
        if (( extlinks >= 30 )); then
            score_add 30 "${extlinks} external links in one file (link farm)"
        elif (( extlinks >= 10 )); then
            score_add 15 "${extlinks} external links in one file"
        fi
    fi

    # Redirect.
    if printf '%s' "$content" | grep -qiE '(header[[:space:]]*\([[:space:]]*["'"'"']Location:|window\.location(\.href)?[[:space:]]*=|http-equiv=["'"'"']refresh)'; then
        score_add 25 "outbound redirect in the same file"
    fi

    # Obfuscated JavaScript alongside the keywords.
    if printf '%s' "$content" | grep -qiE '(eval[[:space:]]*\(|atob[[:space:]]*\(|unescape[[:space:]]*\(|String\.fromCharCode|\\\\x[0-9a-f]{2}){2,}'; then
        score_add 25 "obfuscated JavaScript in the same file"
    fi

    # Injected into PHP rather than sitting in an HTML page.
    case "$path" in
        *.php|*.phtml|*.inc)
            score_add 15 "gambling content inside executable PHP rather than static markup" ;;
    esac
}

# ------------------------------------------------------------
# Main scan
# ------------------------------------------------------------

check_gambling_content() {

    local root file content hits count distinct
    local scanned=0 reported=0

    for root in "${WEB_SCAN_ROOTS[@]}"; do

        while IFS= read -r file; do

            [[ -n "$file" ]] || continue
            web_path_excluded "$file" && continue
            web_file_facts "$file" || continue

            content="$(web_file_head "$file" 131072)"
            [[ -n "$content" ]] || continue

            scanned=$(( scanned + 1 ))

            hits="$(gambling_hits "$content")"
            [[ -n "$hits" ]] || continue

            distinct="$(printf '%s\n' "$hits" | grep -c . || echo 0)"
            count="$(printf '%s' "$content" | grep -ociE "$GAMBLING_REGEX" 2>/dev/null || echo 0)"

            (( distinct >= GAMBLING_MIN_HITS )) || continue

            score_reset

            # Keyword density: one term is vocabulary, a dozen
            # is a landing page.
            if   (( distinct >= 8 )); then
                score_add 55 "${distinct} distinct gambling terms in one file"
            elif (( distinct >= 4 )); then
                score_add 35 "${distinct} distinct gambling terms in one file"
            elif (( distinct >= 2 )); then
                score_add 18 "${distinct} distinct gambling terms in one file"
            else
                score_add 6 "1 gambling term present (may be ordinary vocabulary)"
            fi

            [[ "$count" =~ ^[0-9]+$ ]] && (( count >= 20 )) \
                && score_add 15 "${count} keyword occurrences (repetition typical of SEO landing content)"

            gambling_score_context "$content" "$file"

            if web_owner_is_service_account "$WF_OWNER"; then
                score_add 25 "file owned by the web service account ($WF_OWNER) - written by the application, not deployed"
            fi

            if web_file_is_new; then
                score_add 20 "written in the last ${WF_AGE_HOURS}h"
            fi

            # Upload directories have no business holding
            # marketing copy of any kind.
            local d
            for d in $(web_upload_dirs "$root" 2>/dev/null); do
                if [[ "$file" == "$d"/* ]]; then
                    score_add 25 "located in an upload/static directory"
                    break
                fi
            done

            if web_report_file_finding \
                "gambling:$file" \
                "Gambling / judi slot content in web content" \
                "Do not edit the file yet. Confirm whether this is legitimate editorial content. If it is injected: preserve the file, find the write in the access log by its modification time, check the CMS user table and every other file written in the same minute, then restore from a known good release rather than editing the injected block out."
            then
                reported=$(( reported + 1 ))

                # Matched vocabulary is reported as terms, never
                # as a copy of the page body.
                audit_log INFO "gambling terms in $file: $(printf '%s' "$hits" | tr '\n' ' ')"
            fi

        done < <(web_enumerate_scan "$root" both "$WEB_SCAN_SINCE")

    done

    audit_log INFO "gambling scan examined $scanned files, reported $reported"

    if (( reported == 0 )); then
        add_pass "no gambling injection indicator in $scanned files scanned"
    fi
}

# ------------------------------------------------------------
# Spam page clusters
#
# Injected gambling campaigns usually drop many similar pages
# at once. A burst of new HTML/PHP files in one directory is
# more telling than any single file.
# ------------------------------------------------------------

check_spam_page_clusters() {

    local root dir count found=0

    for root in "${WEB_SCAN_ROOTS[@]}"; do

        # Directories holding many recently written pages.
        while read -r count dir; do

            [[ "$count" =~ ^[0-9]+$ ]] || continue
            (( count >= 10 )) || continue
            [[ -n "$dir" ]] || continue

            found=$(( found + 1 ))

            add_finding HIGH \
                "Burst of recently created web pages in one directory" \
                id="spam-cluster:$dir" \
                path="$dir" \
                confidence=65 \
                reasons="${count} .html/.php files written within the last ${WEB_RECENT_DAYS} days in a single directory
Mass page generation is how doorway/spam campaigns scale
A site migration or a CMS cache rebuild produces the same shape, so this needs confirmation" \
                evidence="${count} recently written pages under $dir" \
                action="Compare the file list against the application's own content. If these pages are not from the CMS, treat them as doorway pages: preserve a sample, then remove them together with the injection point."

        done < <(run_scan "$FIND_TIMEOUT" find "$root" -maxdepth "$WEB_SCAN_MAXDEPTH" \
                    -type f \( -name '*.html' -o -name '*.htm' -o -name '*.php' \) \
                    -mtime -"$WEB_RECENT_DAYS" -printf '%h\n' 2>/dev/null \
                    | sort | uniq -c | sort -rn | head -5)
    done

    (( found == 0 )) && add_pass "no burst of newly created pages in a single directory"
}

# ============================================================
# ENTRY POINT
# ============================================================

run_audit_gambling() {

    module_begin "gambling" "Gambling Injection"

    require_web_workload "Gambling injection scan" || { module_end; return 0; }

    web_load_iocs

    if ! gambling_build_regex; then
        add_skip "gambling keyword list is empty - install config/gambling-keywords.conf"
        module_end
        return 0
    fi

    if ! web_scan_roots; then
        web_report_no_roots "Gambling injection scan"
        module_end
        return 0
    fi

    web_scan_window "gambling"

    add_pass "gambling keyword list loaded (${#GAMBLING_KEYWORDS[@]} entries), mode=$( (( WEB_SCAN_FULL )) && echo full || echo incremental )"

    check_gambling_content
    check_spam_page_clusters

    web_scan_window_commit "gambling"

    module_end
}

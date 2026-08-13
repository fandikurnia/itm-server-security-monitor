#!/usr/bin/env bash
# shellcheck shell=bash

# ============================================================
# ITM Server Security Monitor
# Web content audit - Module W3: SEO poisoning and cloaking
#
# Read only. No page, sitemap, robots.txt or template is
# modified.
#
# SEO poisoning is designed to be invisible to the site owner:
# the injected content is served only to search engine crawlers,
# or hidden off-screen, or placed in pages nobody links to. That
# is why this module looks at how a page treats crawlers, not
# just at what the page says.
#
# The strongest single indicator is cloaking: code that branches
# on User-Agent or Referer and serves different content to
# Googlebot. Legitimate applications do sometimes read the User
# Agent, so the branch alone scores low; the branch combined
# with a redirect, an external canonical or injected keywords is
# what makes a finding.
# ============================================================

# ------------------------------------------------------------
# Structural patterns
# ------------------------------------------------------------

SEO_CRAWLER_UA='(googlebot|bingbot|yandex|baiduspider|duckduckbot|slurp|ahrefsbot|semrushbot|facebookexternalhit|twitterbot)'
SEO_UA_READ='(HTTP_USER_AGENT|\$_SERVER\[[[:space:]]*["'"'"']HTTP_USER_AGENT|navigator\.userAgent)'
SEO_REFERER_READ='(HTTP_REFERER|\$_SERVER\[[[:space:]]*["'"'"']HTTP_REFERER|document\.referrer)'
SEO_REDIRECT='(header[[:space:]]*\([[:space:]]*["'"'"']Location:|window\.location(\.href|\.replace)?[[:space:]]*=|http-equiv=["'"'"']refresh|<meta[^>]+refresh)'

# ------------------------------------------------------------
# Cloaking: different content for crawlers
# ------------------------------------------------------------

seo_score_cloaking() {

    local content="$1"
    local ua_read=0 crawler=0 redirect=0 referer=0

    printf '%s' "$content" | grep -qiE "$SEO_UA_READ"      && ua_read=1
    printf '%s' "$content" | grep -qiE "$SEO_CRAWLER_UA"   && crawler=1
    printf '%s' "$content" | grep -qiE "$SEO_REDIRECT"     && redirect=1
    printf '%s' "$content" | grep -qiE "$SEO_REFERER_READ" && referer=1

    # Reading the User Agent is normal. Branching on a specific
    # crawler name is not.
    if (( ua_read && crawler )); then
        score_add 45 "code branches on a search engine crawler User-Agent (cloaking)"
    elif (( crawler )); then
        score_add 20 "search engine crawler name hardcoded in page content"
    elif (( ua_read )); then
        score_add 5 "reads the User-Agent (common in legitimate code)"
    fi

    if (( referer && redirect )); then
        score_add 35 "redirect conditional on the HTTP Referer (search traffic hijack)"
    elif (( referer )); then
        score_add 8 "reads the HTTP Referer"
    fi

    if (( crawler && redirect )); then
        score_add 30 "crawler detection combined with a redirect"
    fi
}

# ------------------------------------------------------------
# Injected head elements
# ------------------------------------------------------------

seo_score_head() {

    local content="$1" path="$2"
    local host_domain canonical base

    # Canonical pointing somewhere else hands the ranking to the
    # attacker's domain.
    canonical="$(printf '%s' "$content" \
        | grep -ioE '<link[^>]+rel=["'"'"']canonical["'"'"'][^>]*>' | head -1)"

    if [[ -n "$canonical" ]]; then
        local target
        target="$(printf '%s' "$canonical" | grep -ioE 'href=["'"'"']https?://[^"'"'"']+' | head -1)"
        if [[ -n "$target" ]]; then
            host_domain="$(printf '%s' "$ITM_HOSTNAME" | awk -F. '{ if (NF>=2) print $(NF-1)"."$NF; else print $0 }')"
            if [[ -n "$host_domain" ]] && ! printf '%s' "$target" | grep -qi "$host_domain"; then
                score_add 40 "canonical URL points to an external domain"
            fi
        fi
    fi

    # <base href> to an external host rewrites every relative
    # link on the page.
    base="$(printf '%s' "$content" | grep -ioE '<base[^>]+href=["'"'"']https?://[^"'"'"']+' | head -1)"
    if [[ -n "$base" ]]; then
        host_domain="$(printf '%s' "$ITM_HOSTNAME" | awk -F. '{ if (NF>=2) print $(NF-1)"."$NF; else print $0 }')"
        if [[ -n "$host_domain" ]] && ! printf '%s' "$base" | grep -qi "$host_domain"; then
            score_add 40 "<base href> points to an external domain"
        fi
    fi

    # Spam vocabulary inside title/meta is what actually ranks.
    local head_block
    head_block="$(printf '%s' "$content" \
        | grep -ioE '<title>[^<]*</title>|<meta[^>]+name=["'"'"'](description|keywords)["'"'"'][^>]*>' | head -5)"

    if [[ -n "$head_block" && -n "${GAMBLING_REGEX:-}" ]]; then
        local terms
        terms="$(printf '%s' "$head_block" | grep -oiE "$GAMBLING_REGEX" | sort -u | head -8)"
        if [[ -n "$terms" ]]; then
            score_add 50 "gambling vocabulary in <title>/<meta> - the page is ranking for it"
        fi
    fi

    if [[ -n "$head_block" ]]; then
        local pharma
        pharma="$(printf '%s' "$head_block" | grep -oiE '\b(viagra|cialis|levitra|tramadol|xanax|casino|porn|escort|payday[[:space:]]*loan|essay[[:space:]]*writing)\b' | sort -u | head -5)"
        if [[ -n "$pharma" ]]; then
            score_add 50 "pharmacy/adult/spam vocabulary in <title>/<meta>"
        fi
    fi

    # Japanese keyword hack: CJK text in a site that is
    # otherwise Latin script, in the head or in link text.
    if printf '%s' "$head_block" | grep -qP '[\x{3040}-\x{30ff}\x{4e00}-\x{9fff}]' 2>/dev/null; then
        score_add 45 "CJK (Japanese) text injected into page metadata - Japanese keyword hack"
    fi

    case "$path" in
        */robots.txt)
            printf '%s' "$content" | grep -qiE 'Sitemap:[[:space:]]*https?://' && {
                local sm
                sm="$(printf '%s' "$content" | grep -ioE 'Sitemap:[[:space:]]*https?://[^[:space:]]+' | head -3)"
                host_domain="$(printf '%s' "$ITM_HOSTNAME" | awk -F. '{ if (NF>=2) print $(NF-1)"."$NF; else print $0 }')"
                if [[ -n "$host_domain" ]] && ! printf '%s' "$sm" | grep -qi "$host_domain"; then
                    score_add 45 "robots.txt advertises a sitemap on an external domain"
                fi
            }
            ;;
    esac
}

# ------------------------------------------------------------
# Hidden links
# ------------------------------------------------------------

seo_score_hidden_links() {

    local content="$1" hidden

    hidden="$(printf '%s' "$content" \
        | grep -ocE '<a[^>]+style=["'"'"'][^"'"'"']*(display[[:space:]]*:[[:space:]]*none|visibility[[:space:]]*:[[:space:]]*hidden|font-size[[:space:]]*:[[:space:]]*0|text-indent[[:space:]]*:[[:space:]]*-)' 2>/dev/null || echo 0)"

    if [[ "$hidden" =~ ^[0-9]+$ ]] && (( hidden > 0 )); then
        if (( hidden >= 5 )); then
            score_add 40 "${hidden} hidden anchor tags (link injection)"
        else
            score_add 20 "${hidden} hidden anchor tag(s)"
        fi
    fi

    # Off-screen containers holding links.
    if printf '%s' "$content" | grep -qiE '<div[^>]+style=["'"'"'][^"'"'"']*(position[[:space:]]*:[[:space:]]*absolute[^"]*(left|top)[[:space:]]*:[[:space:]]*-[0-9]{3,}|height[[:space:]]*:[[:space:]]*[01]px[^"]*overflow[[:space:]]*:[[:space:]]*hidden)'; then
        score_add 25 "off-screen or 1px container in the page body"
    fi
}

# ------------------------------------------------------------
# Main scan
# ------------------------------------------------------------

check_seo_poisoning() {

    local root file content
    local scanned=0 reported=0

    for root in "${WEB_SCAN_ROOTS[@]}"; do

        while IFS= read -r file; do

            [[ -n "$file" ]] || continue
            web_path_excluded "$file" && continue
            web_file_facts "$file" || continue

            content="$(web_file_head "$file" 131072)"
            [[ -n "$content" ]] || continue

            scanned=$(( scanned + 1 ))

            score_reset
            seo_score_cloaking "$content"
            seo_score_head "$content" "$file"
            seo_score_hidden_links "$content"

            # Provenance, same as the other content modules.
            (( SCORE_TOTAL > 0 )) || continue

            web_owner_is_service_account "$WF_OWNER" \
                && score_add 20 "owned by the web service account ($WF_OWNER)"

            web_file_is_new \
                && score_add 15 "modified in the last ${WF_AGE_HOURS}h"

            web_report_file_finding \
                "seo:$file" \
                "SEO poisoning indicators in web content" \
                "Do not edit the file before capturing it. Check the same directory for sibling doorway pages, review the CMS for unauthorised accounts and plugins, then restore the file from a known good release. After cleanup, request re-indexing so the poisoned entries are dropped." \
                && reported=$(( reported + 1 ))

        done < <(web_enumerate "$root" both "$WEB_SCAN_SINCE")

    done

    audit_log INFO "SEO scan examined $scanned files, reported $reported"

    (( reported == 0 )) && add_pass "no SEO poisoning indicator in $scanned files scanned"
}

# ------------------------------------------------------------
# Crawler control files
#
# robots.txt, sitemap.xml and .htaccess are small, high value
# targets that rarely change legitimately.
# ------------------------------------------------------------

check_crawler_control_files() {

    local root file found=0 content

    for root in "${WEB_SCAN_ROOTS[@]}"; do
        for file in "$root/robots.txt" "$root/sitemap.xml" "$root/sitemap_index.xml" "$root/.htaccess"; do

            [[ -f "$file" ]] || continue
            web_path_excluded "$file" && continue
            web_file_facts "$file" || continue

            score_reset

            content="$(web_file_head "$file" 65536)"
            seo_score_head "$content" "$file"

            # .htaccess is a redirect engine of its own.
            if [[ "$file" == *.htaccess ]]; then
                if printf '%s' "$content" | grep -qiE 'RewriteCond[^\n]*HTTP_USER_AGENT[^\n]*'"$SEO_CRAWLER_UA"; then
                    score_add 50 ".htaccess redirects search engine crawlers specifically (cloaking)"
                fi
                if printf '%s' "$content" | grep -qiE 'RewriteRule[^\n]+https?://'; then
                    score_add 25 ".htaccess rewrites requests to an external URL"
                fi
                if printf '%s' "$content" | grep -qiE 'AddType[[:space:]]+application/x-httpd-php[[:space:]]+\.(jpg|png|gif|txt)'; then
                    score_add 60 ".htaccess maps image/text extensions to the PHP handler"
                fi
            fi

            if web_file_is_new; then
                score_add 25 "crawler control file modified in the last ${WF_AGE_HOURS}h"
            fi

            web_owner_is_service_account "$WF_OWNER" \
                && score_add 20 "owned by the web service account ($WF_OWNER)"

            web_report_file_finding \
                "seo-control:$file" \
                "Crawler control file shows signs of tampering" \
                "Compare against the version in your deployment repository. robots.txt, sitemap.xml and .htaccess are the first files a SEO campaign edits and the last ones anybody looks at." \
                && found=$(( found + 1 ))

        done
    done

    (( found == 0 )) && add_pass "robots.txt, sitemap and .htaccess show no tampering indicators"
}

# ============================================================
# ENTRY POINT
# ============================================================

run_audit_seo() {

    module_begin "seo" "SEO Poisoning"

    require_web_workload "SEO poisoning scan" || { module_end; return 0; }

    web_load_iocs

    # Shared with the gambling module: spam vocabulary in a
    # <title> is the same signal from both directions.
    GAMBLING_REGEX="${GAMBLING_REGEX:-$(ioc_build_regex GAMBLING_KEYWORDS)}"

    if ! web_scan_roots; then
        add_skip "no web root resolved - set WEB_ROOTS in ${ITM_AUDIT_CONF}"
        module_end
        return 0
    fi

    web_scan_window "seo"

    add_pass "SEO pattern list loaded (${#SEO_PATTERNS[@]} entries), mode=$( (( WEB_SCAN_FULL )) && echo full || echo incremental )"

    check_seo_poisoning
    check_crawler_control_files

    web_scan_window_commit "seo"

    module_end
}

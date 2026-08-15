#!/usr/bin/env bash
# shellcheck shell=bash

# ============================================================
# ITM Server Security Monitor
# Post-Compromise Audit - Module A2: Apache exposure
#
# Read only. No Apache configuration is written and Apache is
# never reloaded by this tool.
#
# Apache is a first class citizen here, not an afterthought.
# The estate's most damaging incident ran on an Apache host, and
# the previous version of this monitor could not even find its
# document root - so every web content module skipped silently
# while a gambling landing page sat in the web root.
#
# What this module answers:
#
#   where does Apache serve from      -> DocumentRoot per vhost
#   what can be reached over HTTP     -> project root vs public/
#   what may execute                  -> mod_php, proxy_fcgi, CGI
#   what can override policy          -> AllowOverride, .htaccess
#   who does the log say the client   -> mod_remoteip behind a proxy
#      was
#
# Discovery of the roots themselves lives in itm-web-common.sh
# so that the content modules can find them even when this
# module is not part of the selected scope.
# ============================================================

APACHE_UPLOAD_EXEC_PATTERN='AddType[[:space:]]+application/x-httpd-php|AddHandler[[:space:]]+[^[:space:]]*php|SetHandler[[:space:]]+[^[:space:]]*php|php_(admin_)?(flag|value)[[:space:]]+engine[[:space:]]+on'

apache_service_name() {
    local svc
    for svc in apache2 httpd; do
        role_service_active "$svc" 2>/dev/null && { printf '%s' "$svc"; return 0; }
    done
    printf 'apache2'
}

# ------------------------------------------------------------
# Effective configuration
# ------------------------------------------------------------

apache_dump_vhosts() {
    local ctl
    ctl="$(web_apache_ctl)" || return 1
    run_timeout "$CMD_TIMEOUT" "$ctl" -S 2>&1
}

apache_modules() {
    local ctl
    ctl="$(web_apache_ctl)" || return 1
    run_timeout "$CMD_TIMEOUT" "$ctl" -M 2>/dev/null
}

apache_has_module() {
    [[ -s "$ITM_RUN_TMP/apache-modules.txt" ]] || return 1
    grep -qi "^[[:space:]]*$1" "$ITM_RUN_TMP/apache-modules.txt"
}

# ------------------------------------------------------------
# Inventory
# ------------------------------------------------------------

check_apache_inventory() {

    local roots=() root count=0

    apache_modules > "$ITM_RUN_TMP/apache-modules.txt" 2>/dev/null || true
    apache_dump_vhosts > "$ITM_RUN_TMP/apache-vhosts.txt" 2>/dev/null || true

    while IFS= read -r root; do
        [[ -n "$root" ]] && roots+=("$root")
    done < <(web_apache_roots)

    # Publish the roots for the content modules, exactly as the
    # nginx module does.
    if (( ${#roots[@]} > 0 )); then
        printf '%s\n' "${roots[@]}" | sort -u > "$ITM_RUN_TMP/apache-roots.list"
        if (( ITM_DRY_RUN == 0 )) && [[ -d "$ITM_STATE_DIR" ]]; then
            cp -f "$ITM_RUN_TMP/apache-roots.list" "$ITM_APACHE_ROOT_CACHE" 2>/dev/null || true
            chmod 600 "$ITM_APACHE_ROOT_CACHE" 2>/dev/null || true
        fi
    fi

    count="${#roots[@]}"

    if (( count == 0 )); then
        add_finding MEDIUM \
            "Apache is running but no DocumentRoot could be read from its configuration" \
            id="apache-no-documentroot" \
            confidence=70 \
            reasons="Apache was detected as an active service
No DocumentRoot directive was found in $APACHE_CONF_DIRS
Without a document root the web content modules have nothing to scan" \
            evidence="$(truncate_text "$(head -10 "$ITM_RUN_TMP/apache-vhosts.txt" 2>/dev/null)" 400)" \
            action="Set WEB_ROOTS in ${ITM_AUDIT_CONF} to the served directories, or point APACHE_CONF_DIRS at the correct configuration directory."
        return 1
    fi

    add_pass "Apache document roots discovered ($count): ${roots[*]}"

    local mods=""
    apache_has_module php  && mods+="mod_php "
    apache_has_module proxy_fcgi && mods+="proxy_fcgi "
    apache_has_module cgi  && mods+="cgi "
    apache_has_module cgid && mods+="cgid "
    apache_has_module remoteip && mods+="remoteip "
    apache_has_module rewrite && mods+="rewrite "
    add_pass "Apache modules of interest: ${mods:-none detected}"

    return 0
}

# ------------------------------------------------------------
# Project root exposed instead of public/
#
# The single most common Apache mistake on framework
# applications: DocumentRoot points at the repository root, so
# .env, .git, composer.json, vendor/ and the application source
# are all reachable over HTTP.
# ------------------------------------------------------------

check_apache_documentroot_layout() {

    local root found=0 marker exposed

    for root in ${WEB_SCAN_ROOTS[@]+"${WEB_SCAN_ROOTS[@]}"}; do

        # Is this the root of a framework project rather than its
        # public directory?
        local is_project=0 framework="unknown"

        if [[ -f "$root/composer.json" ]]; then is_project=1; fi
        if [[ -d "$root/public" && -f "$root/public/index.php" ]]; then is_project=1; fi
        if [[ -f "$root/artisan" ]]; then is_project=1; framework="Laravel"; fi
        if [[ -f "$root/spark" || -d "$root/system" && -d "$root/app" ]]; then is_project=1; framework="CodeIgniter"; fi
        if [[ -f "$root/wp-config.php" ]]; then framework="WordPress"; is_project=0; fi

        (( is_project )) || continue

        exposed=""
        for marker in .env .env.example .git composer.json composer.lock phpunit.xml \
                      artisan spark vendor app system tests writable storage config; do
            [[ -e "$root/$marker" ]] && exposed+="${marker} "
        done

        found=1

        score_reset
        score_add 45 "DocumentRoot is the ${framework} project root, not its public/ directory"
        [[ -e "$root/.env" ]]        && score_add 30 ".env is inside the served directory"
        [[ -e "$root/.git" ]]        && score_add 30 ".git is inside the served directory"
        [[ -d "$root/vendor" ]]      && score_add 15 "vendor/ is directly reachable"
        [[ -d "$root/tests" ]]       && score_add 10 "tests/ is directly reachable"

        add_finding "$(score_severity)" \
            "Apache serves the application project root instead of its public directory" \
            id="apache-project-root-exposed:$root" \
            path="$root" \
            confidence="$(score_confidence)" \
            reasons="$SCORE_REASONS" \
            evidence="DocumentRoot: $root
Framework: $framework
Reachable from the web: ${exposed:-none detected}
An HTTP request for /.env or /.git/config is answered by Apache unless a deny rule happens to cover it." \
            action="Point DocumentRoot at ${root}/public (and set <Directory ${root}/public>) in a maintenance window, then verify with 'apache2ctl -t' before reloading. Until then add explicit deny rules for .env, .git, composer.json, vendor and tests. Do not let this tool change the configuration: a wrong DocumentRoot takes the site down."

    done

    (( found == 0 )) && add_pass "no Apache document root exposes an application project root"
}

# ------------------------------------------------------------
# Sensitive files reachable over HTTP
# ------------------------------------------------------------

check_apache_exposed_files() {

    local root file found=0

    for root in ${WEB_SCAN_ROOTS[@]+"${WEB_SCAN_ROOTS[@]}"}; do
        for file in .env .git/config composer.json composer.lock phpunit.xml \
                    .env.backup .env.save wp-config.php.bak; do

            [[ -e "$root/$file" ]] || continue

            # A deny rule in the effective configuration removes
            # the exposure, so look for one before alerting.
            local denied=0
            if grep -rqiE "(FilesMatch|Files|LocationMatch)[[:space:]]+.*($(printf '%s' "${file%%/*}" | sed 's/\./\\./g'))" \
                $APACHE_CONF_DIRS 2>/dev/null; then
                denied=1
            fi
            [[ -f "$root/.htaccess" ]] && grep -qiE "${file%%/*}" "$root/.htaccess" 2>/dev/null && denied=1

            (( denied )) && continue

            found=1

            local sev=HIGH
            [[ "$file" == ".env" ]] && sev=CRITICAL

            add_finding "$sev" \
                "Sensitive file inside an Apache document root with no deny rule" \
                id="apache-exposed-file:$root/$file" \
                path="$root/$file" \
                confidence=85 \
                reasons="File is inside a served DocumentRoot
No matching Files/FilesMatch/Location deny rule was found in the Apache configuration or .htaccess
A single HTTP request retrieves it" \
                evidence="URL path: /${file}
owner=$(stat -Lc '%U:%G' "$root/$file" 2>/dev/null) mode=$(stat -Lc '%a' "$root/$file" 2>/dev/null)" \
                action="Verify with: curl -sI http://127.0.0.1/${file} -H 'Host: <vhost>'. Then either move the file outside the document root or add a deny rule. If .env was reachable, rotate every credential it contains."

        done
    done

    (( found == 0 )) && add_pass "no unprotected sensitive file in the Apache document roots"
}

# ------------------------------------------------------------
# PHP execution where it must not exist
#
# .htaccess and .user.ini can both re-enable PHP inside an
# upload directory, which is how a .pdf becomes code.
# ------------------------------------------------------------

check_apache_upload_execution() {

    local root dir found=0 allow_override_all=0

    # AllowOverride All means every .htaccess on the host is
    # policy, including one an attacker uploads.
    if grep -rhiE '^[[:space:]]*AllowOverride[[:space:]]+All' $APACHE_CONF_DIRS 2>/dev/null | grep -q .; then
        allow_override_all=1
        add_finding MEDIUM \
            "AllowOverride All is enabled" \
            id="apache-allowoverride-all" \
            confidence=70 \
            reasons="Any .htaccess file under the affected directory can change Apache behaviour
An attacker who can write a file into an upload directory can therefore re-enable PHP execution there
This is required by some applications, so it is a review item rather than a detection" \
            evidence="$(grep -rliE '^[[:space:]]*AllowOverride[[:space:]]+All' $APACHE_CONF_DIRS 2>/dev/null | head -5 | tr '\n' ' ')" \
            action="Restrict AllowOverride to the directives the application actually needs (commonly 'FileInfo Options=FollowSymLinks Indexes'), and set AllowOverride None for upload directories."
    fi

    for root in ${WEB_SCAN_ROOTS[@]+"${WEB_SCAN_ROOTS[@]}"}; do
        while IFS= read -r dir; do

            [[ -n "$dir" ]] || continue

            local htaccess="$dir/.htaccess" userini="$dir/.user.ini"

            # ---- .htaccess enabling a PHP handler ----
            if [[ -f "$htaccess" ]] && grep -qiE "$APACHE_UPLOAD_EXEC_PATTERN" "$htaccess" 2>/dev/null; then
                found=1
                web_file_facts "$htaccess" || true
                score_reset
                score_add 60 ".htaccess in an upload directory enables a PHP handler"
                (( allow_override_all )) && score_add 25 "AllowOverride All makes this .htaccess effective"
                web_owner_is_service_account "$WF_OWNER" && score_add 25 "written by the web service account ($WF_OWNER)"
                web_file_is_new && score_add 15 "written in the last ${WF_AGE_HOURS}h"

                add_finding "$(score_severity)" \
                    "Upload directory .htaccess enables PHP execution" \
                    id="apache-upload-htaccess:$htaccess" \
                    path="$htaccess" \
                    hash="$WF_SHA" \
                    confidence="$(score_confidence)" \
                    reasons="$SCORE_REASONS" \
                    evidence="Directives: $(truncate_text "$(grep -iE "$APACHE_UPLOAD_EXEC_PATTERN" "$htaccess" 2>/dev/null | head -4 | tr '\n' ' ')" 300)
This maps uploaded files - including .pdf and .jpg - to the PHP interpreter." \
                    action="Preserve the file, then remove the handler directives and set AllowOverride None for this directory. Check every file in the directory for PHP content before deleting anything."

                evidence_snapshot "$htaccess" \
                    "$(printf '%s|apache-htaccess|%s' "$ITM_HOSTNAME" "$htaccess" | sha256sum | cut -c1-32)" \
                    "upload directory .htaccess enabling PHP" >/dev/null
            fi

            # ---- .user.ini auto_prepend / auto_append ----
            if [[ -f "$userini" ]] && grep -qiE 'auto_(prepend|append)_file' "$userini" 2>/dev/null; then
                found=1
                web_file_facts "$userini" || true
                score_reset
                score_add 70 ".user.ini sets auto_prepend_file/auto_append_file - PHP-FPM executes it on every request in this directory"
                web_owner_is_service_account "$WF_OWNER" && score_add 25 "written by the web service account ($WF_OWNER)"
                web_file_is_new && score_add 15 "written in the last ${WF_AGE_HOURS}h"

                add_finding "$(score_severity)" \
                    "PHP .user.ini injects code on every request" \
                    id="apache-user-ini:$userini" \
                    path="$userini" \
                    hash="$WF_SHA" \
                    confidence="$(score_confidence)" \
                    reasons="$SCORE_REASONS" \
                    evidence="Directives: $(truncate_text "$(grep -iE 'auto_(prepend|append)_file' "$userini" 2>/dev/null | head -3 | tr '\n' ' ')" 300)
.user.ini needs no Apache configuration and no AllowOverride: PHP-FPM reads it directly." \
                    action="Preserve the file and the script it references, then remove both. Confirm no other .user.ini exists under any web root."

                evidence_snapshot "$userini" \
                    "$(printf '%s|apache-userini|%s' "$ITM_HOSTNAME" "$userini" | sha256sum | cut -c1-32)" \
                    ".user.ini with auto_prepend/auto_append" >/dev/null
            fi

        done < <( { web_upload_dirs "$root"; printf '%s\n' "$root"; } )
    done

    (( found == 0 )) && add_pass "no upload directory re-enables PHP execution through .htaccess or .user.ini"
}

# ------------------------------------------------------------
# CGI
# ------------------------------------------------------------

check_apache_cgi() {

    local scriptalias

    if apache_has_module cgi || apache_has_module cgid; then

        scriptalias="$(grep -rhiE '^[[:space:]]*ScriptAlias[[:space:]]' $APACHE_CONF_DIRS 2>/dev/null | head -5 | tr '\n' ' ')"

        add_finding MEDIUM \
            "Apache CGI module is enabled" \
            id="apache-cgi-enabled" \
            confidence=60 \
            reasons="mod_cgi or mod_cgid is loaded
CGI turns any writable, aliased directory into an execution path
Most PHP applications do not need CGI at all" \
            evidence="ScriptAlias: ${scriptalias:-none configured}" \
            action="If the application does not use CGI, disable it: a2dismod cgi cgid (Debian) and reload in a maintenance window. If it is required, confirm the ScriptAlias target is not writable by the web account."
    else
        add_pass "Apache CGI modules are not loaded"
    fi
}

# ------------------------------------------------------------
# Real client IP behind a proxy
#
# When Apache sits behind a WAF or load balancer and mod_remoteip
# is not configured, every log line and every Fail2Ban decision
# sees the proxy, not the attacker.
# ------------------------------------------------------------

check_apache_real_ip() {

    local has_remoteip=0 header="" trusted=""

    apache_has_module remoteip && has_remoteip=1

    header="$(grep -rhiE '^[[:space:]]*RemoteIPHeader[[:space:]]' $APACHE_CONF_DIRS 2>/dev/null | head -1)"
    trusted="$(grep -rhiE '^[[:space:]]*RemoteIP(TrustedProxy|InternalProxy)[[:space:]]' $APACHE_CONF_DIRS 2>/dev/null | head -5 | tr '\n' ' ')"

    if (( has_remoteip )) && [[ -n "$header" ]]; then

        if [[ -z "$trusted" ]]; then
            add_finding HIGH \
                "mod_remoteip trusts a forwarded header from any source" \
                id="apache-remoteip-untrusted" \
                confidence=85 \
                reasons="RemoteIPHeader is set but no RemoteIPTrustedProxy/RemoteIPInternalProxy restricts who may send it
Any client can then set that header and forge its own source address
Forged addresses poison the access log and can be used to get another IP banned by Fail2Ban" \
                evidence="$header
Trusted proxies configured: none" \
                action="Add RemoteIPInternalProxy (or RemoteIPTrustedProxy) listing only the proxy/WAF addresses. This is environment specific, so it is not changed automatically."
        else
            add_pass "mod_remoteip configured with restricted trusted proxies"
        fi

    else

        # Only a finding if the host actually looks proxied.
        local proxied=0
        grep -rqiE '^[[:space:]]*LogFormat.*X-Forwarded-For' $APACHE_CONF_DIRS 2>/dev/null && proxied=1

        if (( proxied )); then
            add_finding MEDIUM \
                "Apache logs a forwarded header without mod_remoteip" \
                id="apache-no-remoteip" \
                confidence=65 \
                reasons="LogFormat references X-Forwarded-For but mod_remoteip is not active
The client address Apache authorises and rate limits on is still the proxy
Fail2Ban acting on these logs will ban the proxy, not the attacker" \
                evidence="mod_remoteip loaded: $( (( has_remoteip )) && echo yes || echo no )
RemoteIPHeader: ${header:-not set}" \
                action="Enable and configure mod_remoteip with the proxy addresses, then confirm the access log records public client addresses before relying on Fail2Ban."
        else
            add_pass "no reverse proxy indications in the Apache logging configuration"
        fi
    fi
}

# ============================================================
# ENTRY POINT
# ============================================================

run_audit_apache() {

    module_begin "apache" "Apache Exposure"

    if ! role_is apache 2>/dev/null; then
        add_na "Apache audit: NOT APPLICABLE - Apache is not the web server on this host" \
            id="na:apache" \
            action="No action. The Nginx module covers this host if it serves web content."
        module_end
        return 0
    fi

    if check_apache_inventory; then
        web_discover_roots || true
        check_apache_documentroot_layout
        check_apache_exposed_files
        check_apache_upload_execution
        check_apache_cgi
        check_apache_real_ip
    fi

    module_end
}

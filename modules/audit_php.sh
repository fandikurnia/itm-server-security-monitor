#!/usr/bin/env bash
# shellcheck shell=bash

# ============================================================
# ITM Server Security Monitor
# Post-Compromise Audit - Module H: PHP-FPM posture
#
# Read only. No PHP setting is changed and no FPM pool is
# stopped.
#
# disable_functions in particular is reported but never
# applied: disabling exec/system on a live CMS breaks image
# processing, mail and backup features that legitimately shell
# out. That change belongs to the application owner.
# ============================================================

PHP_INI_KEYS="expose_php display_errors display_startup_errors log_errors allow_url_include allow_url_fopen open_basedir disable_functions cgi.fix_pathinfo file_uploads upload_max_filesize session.save_path"

php_version_lt() {
    # php_version_lt A B  ->  true when A < B
    [[ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -1)" == "$1" && "$1" != "$2" ]]
}

php_ini_value() {
    local file="$1" key="$2" val
    [[ -r "$file" ]] || return 1
    val="$(grep -E "^[[:space:]]*${key//./\\.}[[:space:]]*=" "$file" 2>/dev/null | tail -1)"
    [[ -n "$val" ]] || return 1
    val="${val#*=}"
    val="${val%%;*}"
    # trim
    val="${val#"${val%%[![:space:]]*}"}"
    val="${val%"${val##*[![:space:]]}"}"
    printf '%s' "$val"
}

php_value_is_on() {
    case "${1,,}" in
        on|1|true|yes) return 0 ;;
    esac
    return 1
}

# ------------------------------------------------------------
# FPM services
# ------------------------------------------------------------

check_fpm_services() {

    have_cmd systemctl || {
        add_skip "systemctl not available - PHP-FPM service audit skipped"
        return 0
    }

    local line unit active_units=() all_units=() version versions=()

    while IFS= read -r line; do
        unit="$(printf '%s' "$line" | awk '{print $1}')"
        [[ "$unit" == php*fpm*.service || "$unit" == *php-fpm*.service ]] || continue
        all_units+=("$unit")
    done < <(run_timeout "$CMD_TIMEOUT" systemctl list-units --type=service --all --no-legend --no-pager 2>/dev/null)

    if (( ${#all_units[@]} == 0 )); then
        add_skip "no PHP-FPM service unit found"
        return 0
    fi

    # The column layout of list-units varies between systemd
    # versions, so state is resolved per unit instead of parsed.
    for unit in "${all_units[@]}"; do
        if run_timeout 10 systemctl is-active --quiet "$unit" 2>/dev/null; then
            active_units+=("$unit")
        fi
    done

    add_pass "PHP-FPM units present: ${all_units[*]} | active: ${active_units[*]:-none}"

    for unit in ${active_units[@]+"${active_units[@]}"}; do
        version="$(printf '%s' "$unit" | grep -oE '[0-9]+\.[0-9]+' | head -1)"
        [[ -n "$version" ]] && versions+=("$version")
    done

    # ---- multiple active FPM versions --------------------------
    if (( ${#active_units[@]} > 1 )); then
        add_finding MEDIUM \
            "Multiple PHP-FPM versions are running at the same time" \
            id="php-multi-fpm" \
            process="${active_units[*]}" \
            evidence="Active units: ${active_units[*]}
Versions: ${versions[*]:-unknown}
Each running pool is an independent execution path into the application, and only the version Nginx points at is normally patched and reviewed." \
            action="Identify which version Nginx actually uses (see the fastcgi_pass check below), then stop and disable the unused pools during a maintenance window."
    else
        add_pass "a single PHP-FPM version is active"
    fi

    # ---- unsupported versions ----------------------------------
    local v unsupported=0
    for v in ${versions[@]+"${versions[@]}"}; do
        if php_version_lt "$v" "$PHP_MIN_SUPPORTED"; then
            unsupported=1
            add_finding HIGH \
                "Active PHP-FPM version is below the supported baseline" \
                id="php-eol:$v" \
                process="PHP $v" \
                evidence="PHP $v is active while the configured baseline is PHP $PHP_MIN_SUPPORTED. Versions past end of life stop receiving security fixes entirely." \
                action="Plan an upgrade with the application owner. If the application cannot move yet, restrict the exposure: keep the old pool off the internet facing vhosts and record the risk acceptance."
        fi
    done
    (( unsupported == 0 )) && add_pass "all active PHP versions are at or above the ${PHP_MIN_SUPPORTED} baseline"

    # ---- FPM pools not referenced by Nginx ---------------------
    if [[ -s "$ITM_RUN_TMP/nginx-T.txt" ]]; then

        local used_sockets orphan=0
        used_sockets="$(grep -hoE 'fastcgi_pass[[:space:]]+[^;]+' "$ITM_RUN_TMP/nginx-T.txt" 2>/dev/null \
            | sed -E 's/fastcgi_pass[[:space:]]+//' | sort -u | tr '\n' ' ')"

        for unit in ${active_units[@]+"${active_units[@]}"}; do
            version="$(printf '%s' "$unit" | grep -oE '[0-9]+\.[0-9]+' | head -1)"
            [[ -n "$version" ]] || continue
            if [[ -n "$used_sockets" ]] && ! printf '%s' "$used_sockets" | grep -q "$version"; then
                orphan=1
                add_finding MEDIUM \
                    "Active PHP-FPM pool is not referenced by any Nginx vhost" \
                    id="php-orphan-fpm:$unit" \
                    process="$unit (PHP $version)" \
                    evidence="Nginx fastcgi_pass targets: ${used_sockets:-none}
$unit listens but no vhost sends requests to it. An unused interpreter still runs as a service, still ages, and is still reachable through any other path that can talk to its socket." \
                    action="Confirm with the application owner, then disable the unused pool: systemctl disable --now $unit (maintenance window, and verify every vhost afterwards)."
            fi
        done

        (( orphan == 0 )) && add_pass "every active PHP-FPM pool is referenced by Nginx"
        [[ -n "$used_sockets" ]] && add_pass "Nginx fastcgi_pass targets: $used_sockets"
    else
        add_skip "Nginx effective configuration not available - FPM to vhost mapping not verified"
    fi
}

# ------------------------------------------------------------
# php.ini hardening
# ------------------------------------------------------------

check_php_ini() {

    local ini inis=() found=0 val

    while IFS= read -r ini; do
        [[ -n "$ini" ]] && inis+=("$ini")
    done < <(find /etc/php /etc/php.d /etc -maxdepth 4 -name 'php.ini' -type f 2>/dev/null | sort -u | head -10)

    if (( ${#inis[@]} == 0 )); then
        add_skip "no php.ini found"
        return 0
    fi

    for ini in "${inis[@]}"; do

        # Only the FPM and CLI SAPIs matter here; skip others to
        # avoid duplicate findings on multi-SAPI installations.
        case "$ini" in
            *cli*) continue ;;
        esac

        found=1

        # ---- remote code inclusion -----------------------------
        val="$(php_ini_value "$ini" allow_url_include || true)"
        if [[ -n "$val" ]] && php_value_is_on "$val"; then
            add_finding CRITICAL \
                "allow_url_include is enabled" \
                id="php-allow-url-include:$ini" \
                path="$ini" \
                evidence="allow_url_include = $val
Any file inclusion bug in the application becomes remote code execution." \
                action="Set allow_url_include = Off and reload PHP-FPM in a maintenance window. No modern application needs it."
        else
            add_pass "allow_url_include disabled ($ini)"
        fi

        # ---- error disclosure ----------------------------------
        val="$(php_ini_value "$ini" display_errors || true)"
        if [[ -n "$val" ]] && php_value_is_on "$val"; then
            add_finding MEDIUM \
                "display_errors is enabled on a production host" \
                id="php-display-errors:$ini" \
                path="$ini" \
                evidence="display_errors = $val
PHP errors are returned to the browser, exposing absolute paths, SQL fragments and occasionally credentials." \
                action="Set display_errors = Off and log_errors = On, then reload PHP-FPM."
        else
            add_pass "display_errors disabled ($ini)"
        fi

        val="$(php_ini_value "$ini" log_errors || true)"
        if [[ -n "$val" ]] && ! php_value_is_on "$val"; then
            add_finding LOW \
                "log_errors is disabled" \
                id="php-log-errors:$ini" \
                path="$ini" \
                evidence="log_errors = $val" \
                action="Enable log_errors so application failures remain investigable after an incident."
        fi

        # ---- information disclosure ----------------------------
        val="$(php_ini_value "$ini" expose_php || true)"
        if [[ -n "$val" ]] && php_value_is_on "$val"; then
            add_finding LOW \
                "expose_php is enabled" \
                id="php-expose:$ini" \
                path="$ini" \
                evidence="expose_php = $val - the exact PHP version is advertised in the X-Powered-By header." \
                action="Set expose_php = Off."
        fi

        # ---- remote fopen --------------------------------------
        val="$(php_ini_value "$ini" allow_url_fopen || true)"
        if [[ -n "$val" ]] && php_value_is_on "$val"; then
            add_finding LOW \
                "allow_url_fopen is enabled" \
                id="php-allow-url-fopen:$ini" \
                path="$ini" \
                evidence="allow_url_fopen = $val
Enabled by default and required by some libraries, but it also gives any SSRF bug a working transport." \
                action="Disable it only after confirming the application does not fetch remote URLs through the filesystem functions."
        fi

        # ---- containment ---------------------------------------
        val="$(php_ini_value "$ini" open_basedir || true)"
        if [[ -z "$val" || "$val" == "none" ]]; then
            add_finding LOW \
                "open_basedir is not set" \
                id="php-open-basedir:$ini" \
                path="$ini" \
                evidence="Without open_basedir a webshell in one vhost can read the document root, configuration and credentials of every other vhost on this host." \
                action="Set open_basedir per pool in the FPM pool file rather than globally, so each site is confined to its own root plus its temp directory. Test uploads and image handling after the change."
        else
            add_pass "open_basedir configured ($ini)"
        fi

        # ---- dangerous functions -------------------------------
        val="$(php_ini_value "$ini" disable_functions || true)"
        if [[ -z "$val" ]]; then
            add_finding LOW \
                "disable_functions is empty" \
                id="php-disable-functions:$ini" \
                path="$ini" \
                evidence="exec, shell_exec, system, passthru, popen and proc_open are all callable from application code, which is what a PHP webshell depends on." \
                action="REVIEW ONLY - do not apply blindly. Many CMS features (image conversion, mail, backup) call these functions. Agree a list with the application owner, then test in staging."
        else
            add_pass "disable_functions configured ($ini): $(truncate_text "$val" 160)"
        fi

        # ---- path info -----------------------------------------
        val="$(php_ini_value "$ini" cgi.fix_pathinfo || true)"
        if [[ "$val" == "1" ]]; then
            add_finding MEDIUM \
                "cgi.fix_pathinfo is enabled" \
                id="php-fix-pathinfo:$ini" \
                path="$ini" \
                evidence="cgi.fix_pathinfo = 1 lets PHP-FPM execute /uploads/image.jpg when a request arrives for /uploads/image.jpg/x.php, which turns an image upload into code execution." \
                action="Set cgi.fix_pathinfo = 0 and add 'try_files \$uri =404;' inside every PHP location in Nginx."
        else
            add_pass "cgi.fix_pathinfo is not enabled ($ini)"
        fi

    done

    (( found == 0 )) && add_skip "no FPM php.ini evaluated"
}

# ------------------------------------------------------------
# FPM pool configuration
# ------------------------------------------------------------

check_fpm_pools() {

    local pool pools=() val raw found=0

    # Debian/Ubuntu keep pools in /etc/php/<v>/fpm/pool.d,
    # RHEL family in /etc/php-fpm.d.
    while IFS= read -r pool; do
        [[ -n "$pool" ]] && pools+=("$pool")
    done < <( {
        find /etc/php /etc/opt/remi -maxdepth 5 -path '*pool.d*' -name '*.conf' -type f 2>/dev/null
        find /etc/php-fpm.d -maxdepth 1 -name '*.conf' -type f 2>/dev/null
    } | sort -u | head -20 )

    if (( ${#pools[@]} == 0 )); then
        add_skip "no PHP-FPM pool configuration found"
        return 0
    fi

    for pool in "${pools[@]}"; do

        found=1

        # security.limit_extensions decides which files FPM will
        # execute at all. An empty value means "anything".
        raw="$(grep -E '^[[:space:]]*security\.limit_extensions[[:space:]]*=' "$pool" 2>/dev/null | tail -1)"
        val="$(printf '%s' "$raw" | cut -d= -f2- | xargs 2>/dev/null || true)"

        if [[ -z "$raw" ]]; then
            add_finding LOW \
                "security.limit_extensions is not set in the FPM pool" \
                id="fpm-limit-ext:$pool" \
                path="$pool" \
                evidence="The pool relies on the compiled default (.php .phar). Setting it explicitly documents the intent and survives a default change." \
                action="Add: security.limit_extensions = .php"
        elif [[ -z "$val" ]]; then
            add_finding HIGH \
                "security.limit_extensions is empty - FPM will execute any file it is handed" \
                id="fpm-limit-ext-empty:$pool" \
                path="$pool" \
                evidence="security.limit_extensions = (empty)" \
                action="Set security.limit_extensions = .php so an uploaded .jpg cannot be executed even if Nginx routes it to FPM."
        else
            add_pass "security.limit_extensions set in $(basename "$pool"): $val"
        fi

        # A pool running as root removes every containment
        # boundary the web server has.
        val="$(grep -E '^[[:space:]]*user[[:space:]]*=' "$pool" 2>/dev/null | tail -1 | cut -d= -f2- | xargs 2>/dev/null || true)"
        if [[ "$val" == "root" ]]; then
            add_finding CRITICAL \
                "PHP-FPM pool runs as root" \
                id="fpm-root-pool:$pool" \
                path="$pool" \
                evidence="user = root
Any code execution through this pool is immediately root level." \
                action="Run the pool as the application account (www-data, nginx or a per-site user) and restart FPM in a maintenance window."
        fi

    done

    (( found == 0 )) && add_skip "no FPM pool evaluated"
}

# ============================================================
# ENTRY POINT
# ============================================================

run_audit_php() {

    module_begin "php" "PHP-FPM Posture"

    require_web_workload "PHP-FPM audit" || { module_end; return 0; }

    if ! have_cmd php && ! find /etc/php -maxdepth 1 -type d 2>/dev/null | grep -q .; then
        add_skip "PHP does not appear to be installed"
        module_end
        return 0
    fi

    check_fpm_services
    check_php_ini
    check_fpm_pools

    module_end
}

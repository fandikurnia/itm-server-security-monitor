#!/usr/bin/env bash
# shellcheck shell=bash

# ============================================================
# ITM Server Security Monitor
# Post-Compromise Audit - Module F: Nginx PHP exposure
#
# Read only. No Nginx configuration file is ever written, and
# nginx is never reloaded by this tool.
#
# The audit runs against the effective configuration produced
# by "nginx -T", not against individual files, so includes and
# overrides are evaluated the way Nginx actually sees them.
#
# The condition that matters on this estate:
#
#   a server block whose document root is an upload or data
#   directory, in a server that also has a PHP/FastCGI handler
#
# which makes any .php file an attacker manages to upload
# directly executable.
#
# The parser is deliberately simple: brace depth plus directive
# matching. It is good enough to find the dangerous pattern and
# is honest about the roots it could not resolve, but it is not
# a full Nginx grammar.
# ============================================================

nginx_dump_config() {

    have_cmd nginx || return 1

    run_timeout "$CMD_TIMEOUT" nginx -T > "$ITM_RUN_TMP/nginx-T.txt" 2>"$ITM_RUN_TMP/nginx-T.err"
    local rc=$?

    [[ -s "$ITM_RUN_TMP/nginx-T.txt" ]] || return "$rc"
    return 0
}

# ------------------------------------------------------------
# Effective configuration parser
#
# Emits one record per server block:
#   server_name | listen | php_handler | roots | php_locations
# ------------------------------------------------------------

nginx_parse_servers() {

    local src="$1" out="$2"

    awk '
        function flush_server(   i, rootlist, loclist) {
            if (in_server == 0) return
            rootlist = ""
            for (i = 1; i <= nroots; i++)
                rootlist = rootlist (i > 1 ? "," : "") roots[i]
            loclist = ""
            for (i = 1; i <= nlocs; i++)
                loclist = loclist (i > 1 ? "," : "") phplocs[i]
            printf "%s|%s|%s|%s|%s\n",
                (srv_name != "" ? srv_name : "-"),
                (srv_listen != "" ? srv_listen : "-"),
                php,
                (rootlist != "" ? rootlist : "-"),
                (loclist != "" ? loclist : "-")
            in_server = 0
        }

        {
            line = $0
            sub(/#.*$/, "", line)

            # ---- server block start ----
            if (in_server == 0 && line ~ /^[[:space:]]*server[[:space:]]*\{/) {
                in_server   = 1
                srv_depth   = depth
                srv_name    = ""
                srv_listen  = ""
                php         = 0
                nroots      = 0
                nlocs       = 0
                cur_loc     = ""
            }

            if (in_server == 1) {

                if (line ~ /^[[:space:]]*location[[:space:]]/) {
                    cur_loc = line
                    sub(/^[[:space:]]*location[[:space:]]+/, "", cur_loc)
                    sub(/[[:space:]]*\{.*$/, "", cur_loc)
                }

                if (line ~ /^[[:space:]]*server_name[[:space:]]/) {
                    v = line
                    sub(/^[[:space:]]*server_name[[:space:]]+/, "", v)
                    sub(/;.*$/, "", v)
                    gsub(/[[:space:]]+/, " ", v)
                    srv_name = (srv_name == "" ? v : srv_name " " v)
                }

                if (line ~ /^[[:space:]]*listen[[:space:]]/) {
                    v = line
                    sub(/^[[:space:]]*listen[[:space:]]+/, "", v)
                    sub(/;.*$/, "", v)
                    srv_listen = (srv_listen == "" ? v : srv_listen " " v)
                }

                if (line ~ /^[[:space:]]*root[[:space:]]/) {
                    v = line
                    sub(/^[[:space:]]*root[[:space:]]+/, "", v)
                    sub(/;.*$/, "", v)
                    gsub(/["'"'"']/, "", v)
                    gsub(/[[:space:]]/, "", v)
                    if (v != "") {
                        dup = 0
                        for (i = 1; i <= nroots; i++) if (roots[i] == v) dup = 1
                        if (dup == 0) roots[++nroots] = v
                    }
                }

                if (line ~ /fastcgi_pass[[:space:]]/ || line ~ /php-fpm/ ) {
                    php = 1
                    if (cur_loc != "") {
                        dup = 0
                        for (i = 1; i <= nlocs; i++) if (phplocs[i] == cur_loc) dup = 1
                        if (dup == 0) phplocs[++nlocs] = cur_loc
                    }
                }
            }

            # ---- brace accounting ----
            o = gsub(/\{/, "{", line)
            c = gsub(/\}/, "}", line)
            depth += o - c

            if (in_server == 1 && depth <= srv_depth) flush_server()
        }

        END { flush_server() }
    ' "$src" > "$out" 2>/dev/null
}

root_is_upload_dir() {
    printf '%s' "$1" | grep -qiE "/${UPLOAD_DIR_PATTERN}(/|$)"
}

root_has_php_files() {
    local root="$1"
    [[ -d "$root" ]] || return 1
    run_timeout 20 find "$root" -maxdepth 4 -type f \
        \( -name '*.php' -o -name '*.phtml' -o -name '*.phar' -o -name '*.php[0-9]' \) \
        2>/dev/null | head -1 | grep -q .
}

# ------------------------------------------------------------
# Checks
# ------------------------------------------------------------

check_nginx_config_state() {

    if ! have_cmd nginx; then
        add_skip "nginx not installed - Nginx audit skipped"
        return 1
    fi

    if ! nginx_dump_config; then
        add_finding MEDIUM \
            "Effective Nginx configuration could not be read" \
            id="nginx-dump-failed" \
            evidence="$(truncate_text "$(head -5 "$ITM_RUN_TMP/nginx-T.err" 2>/dev/null)" 400)" \
            action="Run 'nginx -T' manually. Until it succeeds the PHP exposure of every vhost on this host is unverified."
        return 1
    fi

    if run_timeout "$CMD_TIMEOUT" nginx -t >/dev/null 2>&1; then
        add_pass "nginx configuration syntax valid"
    else
        add_finding MEDIUM \
            "Nginx reports a configuration syntax error" \
            id="nginx-syntax" \
            evidence="$(truncate_text "$(run_timeout "$CMD_TIMEOUT" nginx -t 2>&1 | head -5)" 400)" \
            action="The running Nginx keeps its last valid configuration in memory. A reload will fail until this is fixed."
    fi

    return 0
}

check_php_in_upload_roots() {

    local name listen php roots locs root
    local risky=0 servers=0
    local cache_tmp="$ITM_RUN_TMP/roots.all"

    : > "$cache_tmp"

    nginx_parse_servers "$ITM_RUN_TMP/nginx-T.txt" "$ITM_RUN_TMP/nginx_servers.txt"

    if [[ ! -s "$ITM_RUN_TMP/nginx_servers.txt" ]]; then
        add_skip "no server block found in the effective Nginx configuration"
        return 0
    fi

    while IFS='|' read -r name listen php roots locs; do

        [[ -n "$name" ]] || continue
        servers=$(( servers + 1 ))

        local IFS_SAVE="$IFS"
        IFS=','
        # shellcheck disable=SC2206
        local root_list=( $roots )
        IFS="$IFS_SAVE"

        for root in ${root_list[@]+"${root_list[@]}"}; do

            [[ "$root" == "-" || -z "$root" ]] && continue
            printf '%s\n' "$root" >> "$cache_tmp"

            root_is_upload_dir "$root" || continue
            [[ "$php" == "1" ]] || continue

            risky=$(( risky + 1 ))

            local sev=HIGH
            local extra="No PHP file is present under this root right now."

            if root_has_php_files "$root"; then
                sev=CRITICAL
                extra="PHP files are ALREADY PRESENT under this root and are directly executable through this vhost."
            fi

            add_finding "$sev" \
                "PHP execution is enabled for an upload/data document root" \
                id="nginx-php-upload:$name:$root" \
                path="$root" \
                network="server_name=$name listen=$listen" \
                evidence="Server block root: $root
PHP handler locations: $locs
$extra
Any .php, .phtml or .phar file written into this directory by the application, or by an attacker abusing an upload form, is executed by PHP-FPM." \
                action="In the server block for $name add a deny rule ahead of the PHP handler:
  location ~* \\.(php|phtml|phar|php[0-9]*)\$ { return 403; }
and serve content with:
  try_files \$uri \$uri/ =404;
Review the directory for existing PHP files before changing anything. Apply the change in a maintenance window and verify with 'nginx -t' first. Do not let this tool edit the config."
        done

    done < "$ITM_RUN_TMP/nginx_servers.txt"

    # Cache the discovered roots for the web filesystem module.
    if [[ -s "$cache_tmp" ]] && (( ITM_DRY_RUN == 0 )) && [[ -d "$ITM_STATE_DIR" ]]; then
        sort -u "$cache_tmp" > "$ITM_NGINX_ROOT_CACHE" 2>/dev/null || true
        chmod 600 "$ITM_NGINX_ROOT_CACHE" 2>/dev/null || true
    fi
    sort -u "$cache_tmp" > "$ITM_RUN_TMP/nginx-roots.list" 2>/dev/null || true

    audit_log INFO "parsed $servers Nginx server blocks"

    add_pass "Nginx inventory: $servers server block(s), $(wc -l < "$ITM_RUN_TMP/nginx-roots.list" 2>/dev/null || echo 0) document root(s)"

    (( risky == 0 )) && add_pass "no upload/data document root is served by a PHP handler"
}

check_php_location_anchoring() {

    local name listen php roots locs loc
    local unanchored=0

    [[ -s "$ITM_RUN_TMP/nginx_servers.txt" ]] || return 0

    while IFS='|' read -r name listen php roots locs; do

        [[ "$php" == "1" ]] || continue
        [[ "$locs" != "-" ]] || continue

        local IFS_SAVE="$IFS"
        IFS=','
        # shellcheck disable=SC2206
        local loc_list=( $locs )
        IFS="$IFS_SAVE"

        for loc in ${loc_list[@]+"${loc_list[@]}"}; do

            [[ -n "$loc" ]] || continue

            # A PHP location that is not anchored at end of URI
            # also matches paths such as /uploads/evil.php/x.jpg
            # and /uploads/evil.php.jpg.
            if [[ "$loc" == *".php"* && "$loc" != *'$'* ]]; then
                unanchored=$(( unanchored + 1 ))
                add_finding MEDIUM \
                    "PHP handler location is not anchored to the end of the URI" \
                    id="nginx-unanchored-php:$name:$loc" \
                    network="server_name=$name" \
                    evidence="location $loc
Without a trailing \$ this also matches URIs such as /uploads/shell.php/x.jpg, which some PHP-FPM configurations still execute." \
                    action="Anchor the handler: location ~ \\.php\$ { ... } and set 'try_files \$uri =404;' inside it so PHP-FPM never receives a request for a file Nginx cannot see."
            fi
        done

    done < "$ITM_RUN_TMP/nginx_servers.txt"

    (( unanchored == 0 )) && add_pass "all PHP handler locations are anchored"
}

check_nginx_hygiene() {

    local conf="$ITM_RUN_TMP/nginx-T.txt"

    [[ -s "$conf" ]] || return 0

    # autoindex exposes the contents of upload directories.
    local autoindex
    autoindex="$(grep -nE '^[[:space:]]*autoindex[[:space:]]+on' "$conf" 2>/dev/null | head -5)"

    if [[ -n "$autoindex" ]]; then
        add_finding MEDIUM \
            "Directory listing (autoindex) is enabled" \
            id="nginx-autoindex" \
            evidence="$(truncate_text "$autoindex" 300)" \
            action="Disable autoindex on production vhosts unless a directory index is an intended feature. It hands an attacker a full inventory of uploaded files."
    else
        add_pass "directory listing is not enabled"
    fi

    # Hidden file protection.
    if grep -qE 'location[[:space:]]+~[[:space:]]*/?\\?\.\(?\.\.' "$conf" 2>/dev/null \
        || grep -qE 'location[[:space:]]+~[[:space:]]+/\\\.' "$conf" 2>/dev/null \
        || grep -qE '/\\\.\(git\|svn\|env\)' "$conf" 2>/dev/null; then
        add_pass "a deny rule for hidden files is present in the effective configuration"
    else
        add_finding LOW \
            "No deny rule for dot files found in the effective Nginx configuration" \
            id="nginx-no-dotfile-deny" \
            evidence="No location block denying /\\. was found in 'nginx -T' output." \
            action="Add to each vhost:
  location ~ /\\. { deny all; }
This blocks .env, .git, .svn and editor backup files even when they exist in the web root."
    fi

    # server_tokens leaks the exact Nginx version.
    if grep -qE '^[[:space:]]*server_tokens[[:space:]]+off' "$conf" 2>/dev/null; then
        add_pass "server_tokens is off"
    else
        add_finding INFO \
            "server_tokens is not disabled" \
            id="nginx-server-tokens" \
            action="Set 'server_tokens off;' in the http block to stop advertising the exact Nginx version."
    fi
}

# ============================================================
# ENTRY POINT
# ============================================================

run_audit_nginx() {

    module_begin "nginx" "Nginx PHP Exposure"

    if check_nginx_config_state; then
        check_php_in_upload_roots
        check_php_location_anchoring
        check_nginx_hygiene
    fi

    module_end
}

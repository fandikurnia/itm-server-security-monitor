#!/usr/bin/env bash
# shellcheck shell=bash

# ============================================================
# ITM Server Security Monitor
# Post-Compromise Audit - Module R: host role detection
#
# Runs first. Every other module asks this module what kind of
# host it is standing on before it touches the filesystem.
#
# The point is not classification for its own sake. It is that
# a Proxmox hypervisor, a DNS server or a database host must
# never have its disks walked looking for PHP webshells or
# gambling keywords: the scan would find nothing, cost real IO
# and produce a report full of misleading "PASS" lines about
# checks that examined nothing.
#
# Discovery is deliberately cheap: listening sockets, service
# states and command presence. No recursive filesystem scan
# happens here, or anywhere, before this module has decided.
#
# Two distinctions matter and are easy to get wrong:
#
#   web APPLICATION workload   vs   web MANAGEMENT interface
#     (Nginx serving /website)      (Proxmox 8006, cockpit,
#                                    webmin - infrastructure UI,
#                                    not content to audit)
#
#   installed package          vs   serving workload
#     (php-cli present)             (PHP-FPM actually wired to
#                                    a web server)
#
# The classification is cached and only recomputed when the
# host's service/port signature changes.
# ============================================================

ITM_ROLE_CACHE="${ITM_ROLE_CACHE:-/var/lib/itm-security/host-role.conf}"

# ------------------------------------------------------------
# Role facts
#
# Consumed by other modules through role_is().
# ------------------------------------------------------------

ROLE_WEB_APPLICATION=0
ROLE_WEB_SERVER="none"
ROLE_WEB_MANAGEMENT=0
ROLE_PHP_APPLICATION=0
ROLE_NODE_APPLICATION=0
ROLE_REVERSE_PROXY_ONLY=0
ROLE_DATABASE=0
ROLE_PROXMOX=0
ROLE_MAIL=0
ROLE_DNS=0
ROLE_CONTAINER_HOST=0
ROLE_HYPERVISOR=0

ROLE_SIGNATURE=""
ROLE_DETECTED_AT=""
ROLE_EVIDENCE=""

role_note() {
    ROLE_EVIDENCE+="$1
"
}

# ------------------------------------------------------------
# Cheap primitives
# ------------------------------------------------------------

ROLE_LISTEN_CACHE=""

role_listeners() {
    [[ -n "$ROLE_LISTEN_CACHE" ]] && { printf '%s' "$ROLE_LISTEN_CACHE"; return 0; }
    have_cmd ss || return 1
    ROLE_LISTEN_CACHE="$(run_timeout 10 ss -lntup 2>/dev/null)"
    printf '%s' "$ROLE_LISTEN_CACHE"
}

# Is any process listening on this TCP port?
role_port_open() {
    # ss -lntup columns: Netid State Recv-Q Send-Q Local Peer Process
    local port="$1"
    role_listeners | awk -v port="$port" '
        $1 == "tcp" {
            n = split($5, a, ":")
            if (a[n] == port) found = 1
        }
        END { exit(found ? 0 : 1) }
    '
}

role_service_active() {
    have_cmd systemctl || return 1
    run_timeout 8 systemctl is-active --quiet "$1" 2>/dev/null
}

# Any active unit matching a glob, e.g. "php*-fpm.service"
role_service_glob_active() {
    have_cmd systemctl || return 1
    run_timeout 10 systemctl list-units --type=service --state=active --no-legend --no-pager "$1" 2>/dev/null \
        | grep -q .
}

# A process running on the HOST, not inside a container.
#
# On a container host, pgrep sees every containerised process:
# a Kubernetes cluster running Nginx pods makes the hypervisor
# look like a web server. Those workloads have no document root
# on this filesystem and are the container image's problem, not
# this host's, so scanning the host's disks because of them is
# exactly the irrelevant IO this module exists to prevent.
role_process_running() {

    local name="$1" pid cgroup host_pids=0 container_pids=0

    while IFS= read -r pid; do

        [[ "$pid" =~ ^[0-9]+$ ]] || continue

        cgroup="$(tr -d '\0' < "/proc/$pid/cgroup" 2>/dev/null)"

        case "$cgroup" in
            *docker*|*kubepods*|*containerd*|*crio*|*libpod*|*lxc*|*machine.slice*)
                container_pids=$(( container_pids + 1 )) ;;
            *)
                host_pids=$(( host_pids + 1 )) ;;
        esac

    done < <(run_timeout 8 pgrep -x "$name" 2>/dev/null)

    if (( host_pids > 0 )); then
        return 0
    fi

    if (( container_pids > 0 )); then
        role_note "$name runs only inside containers (${container_pids} process(es)) - container workload, not host workload"
    fi

    return 1
}

# ------------------------------------------------------------
# Web server
# ------------------------------------------------------------

role_detect_web_server() {

    local http_open=0

    role_port_open 80  && http_open=1
    role_port_open 443 && http_open=1

    if role_service_active nginx || role_process_running nginx; then
        ROLE_WEB_SERVER="nginx"
        role_note "nginx service active"
    elif role_service_active apache2 || role_service_active httpd \
        || role_process_running apache2 || role_process_running httpd; then
        ROLE_WEB_SERVER="apache"
        role_note "apache/httpd service active"
    fi

    if (( http_open )); then
        role_note "listening on port 80/443"
    fi

    # A web server binary that is installed but not running, and
    # no HTTP port open, is not a workload.
    if [[ "$ROLE_WEB_SERVER" == "none" ]] && (( http_open )); then
        role_note "HTTP port open without a recognised web server - review"
    fi
}

# ------------------------------------------------------------
# Web management interfaces
#
# These serve infrastructure UI, not site content. Their
# presence must never enable content scanning.
# ------------------------------------------------------------

role_detect_web_management() {

    local found=0

    if role_port_open 8006 || role_service_active pveproxy; then
        ROLE_WEB_MANAGEMENT=1
        ROLE_PROXMOX=1
        found=1
        role_note "Proxmox VE web interface (pveproxy / port 8006)"
    fi

    if role_service_active cockpit.socket || role_port_open 9090; then
        ROLE_WEB_MANAGEMENT=1
        found=1
        role_note "Cockpit management interface"
    fi

    if role_service_active webmin || role_port_open 10000; then
        ROLE_WEB_MANAGEMENT=1
        found=1
        role_note "Webmin management interface"
    fi

    return $(( found ? 0 : 1 ))
}

# ------------------------------------------------------------
# PHP workload
#
# An installed PHP package is not a workload. PHP CLI is not a
# workload. What counts is PHP wired to a web server.
# ------------------------------------------------------------

role_detect_php() {

    local fpm_active=0 wired=0

    if role_service_glob_active 'php*-fpm.service' || role_service_glob_active 'php-fpm.service' \
        || role_process_running php-fpm; then
        fpm_active=1
        role_note "PHP-FPM service active"
    fi

    # Nginx -> FPM
    if [[ "$ROLE_WEB_SERVER" == "nginx" ]] && have_cmd nginx; then
        if run_timeout "$CMD_TIMEOUT" nginx -T 2>/dev/null | grep -q 'fastcgi_pass'; then
            wired=1
            role_note "nginx fastcgi_pass to PHP"
        fi
    fi

    # Apache -> mod_php or php-fpm handler
    # The control program is named differently per family:
    # apache2ctl on Debian/Ubuntu, apachectl or httpd on
    # RHEL/AlmaLinux/Rocky. Probing for one name only means a
    # PHP-serving Rocky host is classified as not running a PHP
    # application, and every web module then skips it.
    if [[ "$ROLE_WEB_SERVER" == "apache" ]]; then
        local apache_ctl=""
        if declare -F web_apache_ctl >/dev/null 2>&1; then
            apache_ctl="$(web_apache_ctl || true)"
        else
            # itm-web-common.sh is sourced before this module, but
            # it is loaded behind a readability check. Losing PHP
            # detection because a helper is missing would silently
            # exclude the host from every web module, so the probe
            # is repeated here rather than assumed.
            local c
            for c in apache2ctl apachectl httpd; do
                have_cmd "$c" && { apache_ctl="$c"; break; }
            done
        fi

        if [[ -n "$apache_ctl" ]]; then
            if run_timeout "$CMD_TIMEOUT" "$apache_ctl" -M 2>/dev/null | grep -qi 'php\|proxy_fcgi'; then
                wired=1
                role_note "apache PHP module or proxy_fcgi loaded (via $apache_ctl)"
            fi
        fi
    fi

    if (( fpm_active && wired )); then
        ROLE_PHP_APPLICATION=1
    elif (( fpm_active )) && [[ "$ROLE_WEB_SERVER" != "none" ]]; then
        # FPM running alongside a web server whose wiring could
        # not be read: treat as PHP workload, and say why.
        ROLE_PHP_APPLICATION=1
        role_note "PHP-FPM active with a web server present (wiring not confirmed)"
    fi
}

# ------------------------------------------------------------
# Node.js workload
#
# /usr/bin/node existing means somebody built an asset once.
# A workload means a Node process actually serving HTTP.
# ------------------------------------------------------------

role_detect_node() {

    local pid cgroup listening=0 service_managed=0 upstream=0 port

    # Node listeners, with the PID so the process can be judged
    # rather than just counted.
    while read -r pid port; do

        [[ "$pid" =~ ^[0-9]+$ ]] || continue
        listening=1

        cgroup="$(tr -d '\0' < "/proc/$pid/cgroup" 2>/dev/null)"

        case "$cgroup" in
            *docker*|*kubepods*|*containerd*|*crio*|*libpod*|*lxc*)
                role_note "Node listener pid=$pid is containerised - container workload"
                continue ;;
            *user.slice*|*user@*)
                # A developer tool, an editor language server or a
                # desktop application. Not a served workload.
                role_note "Node listener pid=$pid runs in a user session (developer tooling), not a service"
                continue ;;
        esac

        service_managed=1
        role_note "Node service listening on port ${port:-unknown} (pid $pid)"

        [[ "$port" == "80" || "$port" == "443" ]] && upstream=1

    done < <(role_listeners | awk '
        $1 == "tcp" && /users:\(\("(node|nodejs|next-server|pm2)/ {
            pid = ""
            if (match($0, /pid=[0-9]+/)) pid = substr($0, RSTART + 4, RLENGTH - 4)
            n = split($5, a, ":")
            print pid, a[n]
        }')

    # Reverse proxy upstream is the other way a Node app is
    # actually serving traffic.
    if (( service_managed )) && [[ "$ROLE_WEB_SERVER" == "nginx" ]] && have_cmd nginx; then
        if run_timeout "$CMD_TIMEOUT" nginx -T 2>/dev/null \
            | grep -qE 'proxy_pass[[:space:]]+https?://(127\.0\.0\.1|localhost|\[::1\])'; then
            upstream=1
            role_note "Node reachable as an Nginx upstream"
        fi
    fi

    # Listening alone is not enough: it has to be a managed
    # service, and either fronted by the web server or serving
    # HTTP directly.
    if (( service_managed && (upstream || ROLE_WEB_SERVER != "none") )); then
        ROLE_NODE_APPLICATION=1
    elif (( listening && service_managed == 0 )); then
        role_note "Node web workload: NOT DETECTED (only user-session or containerised listeners)"
    fi
}

# ------------------------------------------------------------
# Everything else
# ------------------------------------------------------------

role_detect_other() {

    local svc

    for svc in mysql mysqld mariadb postgresql; do
        if role_service_active "$svc"; then
            ROLE_DATABASE=1
            role_note "database service active: $svc"
            break
        fi
    done

    for svc in postfix exim4 dovecot; do
        if role_service_active "$svc"; then
            ROLE_MAIL=1
            role_note "mail service active: $svc"
            break
        fi
    done

    for svc in named bind9 unbound pdns dnsmasq; do
        if role_service_active "$svc"; then
            ROLE_DNS=1
            role_note "DNS service active: $svc"
            break
        fi
    done

    for svc in docker containerd k3s lxd; do
        if role_service_active "$svc"; then
            ROLE_CONTAINER_HOST=1
            role_note "container runtime active: $svc"
            break
        fi
    done

    if (( ROLE_PROXMOX )); then
        ROLE_HYPERVISOR=1
    elif role_service_active libvirtd || [[ -d /proc/vz ]]; then
        ROLE_HYPERVISOR=1
        role_note "hypervisor service active"
    fi
}

# ------------------------------------------------------------
# Web application decision
#
# The single decision the content modules depend on.
# ------------------------------------------------------------

role_decide_web_application() {

    # No web server, no web application. A management interface
    # on its own is explicitly not enough.
    if [[ "$ROLE_WEB_SERVER" == "none" ]]; then
        ROLE_WEB_APPLICATION=0
        return 0
    fi

    # PHP or Node workload behind the web server: application.
    if (( ROLE_PHP_APPLICATION || ROLE_NODE_APPLICATION )); then
        ROLE_WEB_APPLICATION=1
        return 0
    fi

    # Static content still counts as an application workload if
    # a document root with content exists, because SEO poisoning
    # and injected JavaScript do not need PHP.
    local root
    while IFS= read -r root; do
        [[ -n "$root" && -d "$root" ]] || continue
        case "$root" in
            /usr/share/nginx/html|/var/www/html) ;;
            *) ROLE_WEB_APPLICATION=1
               role_note "document root with content: $root"
               return 0 ;;
        esac
    done < <(role_document_roots)

    # Web server present, no application content found: this is a
    # reverse proxy, load balancer or TLS terminator.
    ROLE_REVERSE_PROXY_ONLY=1
    role_note "web server present without application content (proxy/static only)"
    return 0
}

# Document roots, from the Nginx effective config only. Cheap:
# no filesystem walk.
role_document_roots() {

    [[ "$ROLE_WEB_SERVER" == "nginx" ]] || return 0
    have_cmd nginx || return 0

    run_timeout "$CMD_TIMEOUT" nginx -T 2>/dev/null \
        | awk '/^[[:space:]]*root[[:space:]]/ {
                 v = $2; gsub(/[;"'"'"']/, "", v); if (v != "") print v
               }' \
        | sort -u
}

# ------------------------------------------------------------
# Cache
#
# The signature is what the classification was derived from. If
# it has not changed, neither has the answer.
# ------------------------------------------------------------

role_compute_signature() {
    {
        role_listeners | awk '{print $1, $5}' | sort -u
        have_cmd systemctl && run_timeout 10 systemctl list-units --type=service --state=active --no-legend --no-pager 2>/dev/null | awk '{print $1}' | sort
    } 2>/dev/null | sha256sum 2>/dev/null | cut -c1-32
}

role_cache_load() {

    [[ -r "$ITM_ROLE_CACHE" ]] || return 1

    local cached_sig current_sig
    cached_sig="$(awk -F= '/^ROLE_SIGNATURE=/ {gsub(/"/, "", $2); print $2}' "$ITM_ROLE_CACHE" 2>/dev/null)"
    [[ -n "$cached_sig" ]] || return 1

    current_sig="$(role_compute_signature)"
    [[ "$cached_sig" == "$current_sig" ]] || return 1

    # shellcheck disable=SC1090
    source "$ITM_ROLE_CACHE"
    return 0
}

role_cache_save() {

    (( ITM_DRY_RUN )) && return 0

    local dir="${ITM_ROLE_CACHE%/*}"
    mkdir -p "$dir" 2>/dev/null || return 0

    {
        printf '# ITM host role classification - generated %s\n' "$(date '+%Y-%m-%d %H:%M:%S %Z')"
        printf '# Regenerated automatically when the service/port signature changes.\n'
        printf 'ROLE_SIGNATURE="%s"\n'        "$ROLE_SIGNATURE"
        printf 'ROLE_DETECTED_AT="%s"\n'      "$ROLE_DETECTED_AT"
        printf 'ROLE_WEB_APPLICATION=%s\n'    "$ROLE_WEB_APPLICATION"
        printf 'ROLE_WEB_SERVER="%s"\n'       "$ROLE_WEB_SERVER"
        printf 'ROLE_WEB_MANAGEMENT=%s\n'     "$ROLE_WEB_MANAGEMENT"
        printf 'ROLE_PHP_APPLICATION=%s\n'    "$ROLE_PHP_APPLICATION"
        printf 'ROLE_NODE_APPLICATION=%s\n'   "$ROLE_NODE_APPLICATION"
        printf 'ROLE_REVERSE_PROXY_ONLY=%s\n' "$ROLE_REVERSE_PROXY_ONLY"
        printf 'ROLE_DATABASE=%s\n'           "$ROLE_DATABASE"
        printf 'ROLE_PROXMOX=%s\n'            "$ROLE_PROXMOX"
        printf 'ROLE_MAIL=%s\n'               "$ROLE_MAIL"
        printf 'ROLE_DNS=%s\n'                "$ROLE_DNS"
        printf 'ROLE_CONTAINER_HOST=%s\n'     "$ROLE_CONTAINER_HOST"
        printf 'ROLE_HYPERVISOR=%s\n'         "$ROLE_HYPERVISOR"
    } > "$ITM_ROLE_CACHE" 2>/dev/null || return 0

    chmod 600 "$ITM_ROLE_CACHE" 2>/dev/null || true
}

# ------------------------------------------------------------
# Public entry point for other modules
#
# role_classify is safe to call repeatedly: it runs once.
# ------------------------------------------------------------

ROLE_CLASSIFIED=0

role_classify() {

    (( ROLE_CLASSIFIED )) && return 0
    ROLE_CLASSIFIED=1

    if [[ "${ROLE_FORCE_REFRESH:-0}" != "1" ]] && role_cache_load; then
        ROLE_EVIDENCE="loaded from cache ($ITM_ROLE_CACHE), signature unchanged"
        return 0
    fi

    role_detect_web_server
    role_detect_web_management
    role_detect_php
    role_detect_node
    role_detect_other
    role_decide_web_application

    # Operator override, for the cases automatic classification
    # cannot reach: a custom web server, an application served
    # from a path no configuration reveals, or a host that must
    # be excluded from content scanning regardless of what is
    # running on it.
    case "${WEB_WORKLOAD_OVERRIDE:-auto}" in
        yes|YES|1)
            ROLE_WEB_APPLICATION=1
            role_note "web application workload FORCED ON by WEB_WORKLOAD_OVERRIDE in $ITM_AUDIT_CONF" ;;
        no|NO|0)
            ROLE_WEB_APPLICATION=0
            role_note "web application workload FORCED OFF by WEB_WORKLOAD_OVERRIDE in $ITM_AUDIT_CONF" ;;
    esac

    ROLE_SIGNATURE="$(role_compute_signature)"
    ROLE_DETECTED_AT="$(date '+%Y-%m-%d %H:%M:%S %Z')"

    role_cache_save
    return 0
}

# role_is <fact>
role_is() {
    role_classify
    case "$1" in
        web_application) (( ROLE_WEB_APPLICATION )) ;;
        php_application) (( ROLE_PHP_APPLICATION )) ;;
        node_application)(( ROLE_NODE_APPLICATION )) ;;
        nginx)           [[ "$ROLE_WEB_SERVER" == "nginx" ]] ;;
        apache)          [[ "$ROLE_WEB_SERVER" == "apache" ]] ;;
        web_server)      [[ "$ROLE_WEB_SERVER" != "none" ]] ;;
        web_management)  (( ROLE_WEB_MANAGEMENT )) ;;
        proxy_only)      (( ROLE_REVERSE_PROXY_ONLY )) ;;
        database)        (( ROLE_DATABASE )) ;;
        proxmox)         (( ROLE_PROXMOX )) ;;
        mail)            (( ROLE_MAIL )) ;;
        dns)             (( ROLE_DNS )) ;;
        container_host)  (( ROLE_CONTAINER_HOST )) ;;
        hypervisor)      (( ROLE_HYPERVISOR )) ;;
        *)               return 1 ;;
    esac
}

# Guard used at the top of every content module.
require_web_workload() {

    local module_label="$1"

    role_is web_application && return 0

    local why="No web application workload detected on this host."

    if role_is web_management; then
        why="This host serves a web MANAGEMENT interface"
        role_is proxmox && why="$why (Proxmox VE)"
        why="$why, not a web application. Infrastructure UI is not site content: scanning it for webshells, SEO poisoning or gambling injection would examine nothing relevant."
    elif role_is proxy_only; then
        why="The web server on this host is a reverse proxy / static or TLS endpoint with no application content to audit."
    elif role_is database; then
        why="This host is a database server with no web application workload."
    fi

    add_na "${module_label}: NOT APPLICABLE to this host role" \
        id="na:${CURRENT_MODULE}" \
        evidence="$why
Host role: $(role_summary_line)" \
        action="No action. System level auditing (process, network, PAM, systemd, command, SSH, Fail2Ban) still runs on this host."

    return 1
}

role_summary_line() {
    local parts=()
    (( ROLE_WEB_APPLICATION ))  && parts+=("web-application")
    (( ROLE_REVERSE_PROXY_ONLY )) && parts+=("reverse-proxy-only")
    (( ROLE_WEB_MANAGEMENT ))   && parts+=("web-management")
    (( ROLE_PHP_APPLICATION ))  && parts+=("php")
    (( ROLE_NODE_APPLICATION )) && parts+=("node")
    (( ROLE_DATABASE ))         && parts+=("database")
    (( ROLE_MAIL ))             && parts+=("mail")
    (( ROLE_DNS ))              && parts+=("dns")
    (( ROLE_PROXMOX ))          && parts+=("proxmox")
    (( ROLE_HYPERVISOR ))       && parts+=("hypervisor")
    (( ROLE_CONTAINER_HOST ))   && parts+=("container-host")
    [[ "$ROLE_WEB_SERVER" != "none" ]] && parts+=("webserver=$ROLE_WEB_SERVER")
    (( ${#parts[@]} )) || parts=("no-recognised-workload")
    printf '%s' "${parts[*]}"
}

yesno() { (( $1 )) && printf 'YES' || printf 'NO'; }

# ============================================================
# ENTRY POINT
# ============================================================

run_audit_role() {

    module_begin "role" "Host Role Detection"

    role_classify

    if (( ITM_QUIET == 0 )); then
        say ""
        printf '  %-24s : %s\n' "Web Application"    "$(yesno "$ROLE_WEB_APPLICATION")"
        printf '  %-24s : %s\n' "Web Server"         "$ROLE_WEB_SERVER"
        printf '  %-24s : %s\n' "PHP Application"    "$(yesno "$ROLE_PHP_APPLICATION")"
        printf '  %-24s : %s\n' "Node Application"   "$(yesno "$ROLE_NODE_APPLICATION")"
        printf '  %-24s : %s\n' "Reverse Proxy Only" "$(yesno "$ROLE_REVERSE_PROXY_ONLY")"
        printf '  %-24s : %s\n' "Web Management UI"  "$(yesno "$ROLE_WEB_MANAGEMENT")"
        printf '  %-24s : %s\n' "Database"           "$(yesno "$ROLE_DATABASE")"
        printf '  %-24s : %s\n' "Proxmox VE"         "$(yesno "$ROLE_PROXMOX")"
        printf '  %-24s : %s\n' "Hypervisor"         "$(yesno "$ROLE_HYPERVISOR")"
        printf '  %-24s : %s\n' "Container Host"     "$(yesno "$ROLE_CONTAINER_HOST")"
        printf '  %-24s : %s\n' "Mail Server"        "$(yesno "$ROLE_MAIL")"
        printf '  %-24s : %s\n' "DNS Server"         "$(yesno "$ROLE_DNS")"
        say ""
    fi

    add_pass "host role: $(role_summary_line)" \
        id="host-role" \
        evidence="$(truncate_text "$ROLE_EVIDENCE" 800)"

    # State the consequence explicitly, so a report can never be
    # misread as "the web checks passed".
    if role_is web_application; then
        add_pass "web content modules ACTIVE (webshell, gambling, seo, integrity, nginx, php)"
    else
        add_pass "web content modules NOT APPLICABLE - system level auditing continues normally"
    fi

    module_end
}

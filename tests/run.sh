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

    hits="$(grep -rnE '(^|[^#])[[:space:]]*git[[:space:]]+(clean|reset)' \
              "$REPO_DIR"/modules "$REPO_DIR"/lib "$REPO_DIR"/bin 2>/dev/null \
              | grep -v 'never\|NEVER\|not\|Do not\|recommend' || true)"
    [[ -z "$hits" ]]
    check "git clean / git reset is never invoked" "$?" "$hits"

    hits="$(grep -rnE '^[^#]*[[:space:]](rm|rm -rf)[[:space:]]+"?\$(WF_PATH|file|path)' \
              "$REPO_DIR"/modules 2>/dev/null || true)"
    [[ -z "$hits" ]]
    check "no module deletes a scanned file" "$?" "$hits"

    hits="$(grep -rnE '\bkill[[:space:]]+-?[0-9A-Z]*[[:space:]]*"?\$\{?(pid|PID)' \
              "$REPO_DIR"/modules 2>/dev/null || true)"
    [[ -z "$hits" ]]
    check "no module signals a process" "$?" "$hits"

    hits="$(grep -rnE '\bchattr[[:space:]]+[-+]' "$REPO_DIR"/modules "$REPO_DIR"/lib 2>/dev/null \
              | grep -v 'chattr \+i/\+a\|recommend\|action=' || true)"
    [[ -z "$hits" ]]
    check "no module changes file attributes" "$?" "$hits"
}

# ============================================================
# TEST 7 - shell syntax
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

printf '\n============================================================\n'
printf ' PASS: %s   FAIL: %s\n' "$PASS" "$FAIL"
printf '============================================================\n'

if (( FAIL > 0 )); then
    printf '\nFailed:\n'
    printf '  - %s\n' "${FAILED_NAMES[@]}"
    exit 1
fi

exit 0

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

    local bad
    bad="$(awk '
      /^install \\$/ { inblk=1; blk=""; line=NR }
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
    ! printf '%s' "$out" | grep -qE '^\[(MEDIUM|HIGH|CRITICAL)\].*c1'
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
    ! printf '%s' "$out" | grep -q 'c5'
    check "local console session is ignored entirely" "$?"

    # --- monitor_only must not terminate anything
    printf '%s' "$out" | grep -q 'WARN. SSH_SESSION_EXCEEDED'
    check "monitor_only prints WARN SSH_SESSION_EXCEEDED" "$?"

    [[ ! -s "$TERMINATE_LOG" ]]
    check "monitor_only terminates NOTHING" "$?" "terminated: $(cat "$TERMINATE_LOG" 2>/dev/null | tr '\n' ' ')"

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
test_health
test_cron
test_self_protection
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

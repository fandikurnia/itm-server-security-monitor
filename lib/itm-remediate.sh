#!/usr/bin/env bash
# shellcheck shell=bash

# ============================================================
# ITM Server Security Monitor
# Incident response script generator
#
# Turns each finding into a script an operator can read, then
# run. Generating a script changes NOTHING on the host: the
# generator only writes files under /root/forensic.
#
# Every generated script has the same four phases, in this
# order, and the order is the whole point:
#
#   1 PRESERVE   copy the artefact and its full metadata into
#                the incident directory. Always runs, needs no
#                confirmation, and runs even if the operator
#                never continues to phase 3.
#
#   2 VERIFY     re-check that the artefact is still the one
#                the audit saw (SHA256). If the file changed
#                since the scan, the script ABORTS rather than
#                acting on something it has not examined.
#
#   3 CONTAIN    the actual remediation, gated behind
#                CONFIRM=yes. Files are MOVED to quarantine,
#                never deleted: a webshell that gets rm'ed is
#                destroyed evidence, and a false positive that
#                gets rm'ed is an outage.
#
#   4 ROLLBACK   printed in every script, as a command that
#                actually works.
#
# What these scripts will never do, because the estate cannot
# afford it:
#
#   rm -rf on a directory        git reset --hard
#   git clean                    chmod -R
#   chattr -R                    truncating logs
#   killing processes unattended firewall changes
#
# Running a generated script WITHOUT CONFIRM=yes performs the
# preservation and prints exactly what phase 3 would do. That
# dry run is the intended first step.
# ============================================================

[[ -n "${ITM_REMEDIATE_LOADED:-}" ]] && return 0
ITM_REMEDIATE_LOADED=1

REMEDIATE_BASE_DIR="${REMEDIATE_BASE_DIR:-/root/forensic}"

# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------

rem_slug() {
    # module + file basename, not the whole path: incident
    # directories are read by a human under pressure.
    local module="$1" path="$2" ref="$3"
    local base="${path##*/}"
    base="$(printf '%s' "${base:-$module}" | tr -c 'A-Za-z0-9._-' '-')"
    printf '%s-%s-%s' "$module" "${base:0:32}" "${ref:0:8}"
}

# Shell-quote a value for safe embedding in a generated script.
rem_q() {
    printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
}

rem_header() {

    local file="$1" title="$2" severity="$3" confidence="$4"
    local finding_path="$5" hash="$6" reasons="$7" fingerprint="$8" module="$9"

    {
        printf '#!/usr/bin/env bash\n'
        printf '#\n'
        printf '# ITM Server Security Monitor - incident response script\n'
        printf '# GENERATED %s on %s\n' "$(date '+%Y-%m-%d %H:%M:%S %Z')" "$ITM_HOSTNAME"
        printf '#\n'
        printf '# FINDING    : %s\n' "$title"
        printf '# SEVERITY   : %s (confidence %s%%)\n' "$severity" "$confidence"
        printf '# MODULE     : %s\n' "$module"
        [[ -n "$finding_path" ]] && printf '# PATH       : %s\n' "$finding_path"
        [[ -n "$hash" ]]         && printf '# SHA256     : %s\n' "$hash"
        printf '# REF        : %s\n' "$fingerprint"
        printf '#\n'
        printf '# WHY THIS WAS FLAGGED:\n'
        while IFS= read -r line; do
            [[ -n "$line" ]] && printf '#   - %s\n' "$line"
        done <<< "$reasons"
        printf '#\n'
        printf '# HOW TO RUN\n'
        printf '#   1. Read this script. All of it.\n'
        printf '#   2. bash %s              # preserves evidence, changes nothing\n' "${file##*/}"
        printf '#   3. CONFIRM=yes bash %s  # applies the containment below\n' "${file##*/}"
        printf '#\n'
        printf 'set -uo pipefail\n\n'
        printf 'CONFIRM="${CONFIRM:-no}"\n'
        printf 'INCIDENT_DIR=%s\n' "$(rem_q "$REM_INCIDENT_DIR")"
        printf 'QUARANTINE="$INCIDENT_DIR/quarantine"\n'
        printf 'EVIDENCE="$INCIDENT_DIR/evidence"\n'
        printf 'mkdir -p "$QUARANTINE" "$EVIDENCE"\n'
        printf 'chmod 700 "$INCIDENT_DIR" "$QUARANTINE" "$EVIDENCE"\n\n'
        printf 'CHANGED=0\n'
        printf 'NOTIFY=%s\n' "$(rem_q "$ITM_NOTIFY_BIN")"
        printf 'log() { printf "[%%s] %%s\\n" "$(date +%%H:%%M:%%S)" "$*"; }\n'
        printf '\n'
        printf '# Containment is an outward facing action. It is announced on\n'
        printf '# the same channel as the detection, so the change is visible to\n'
        printf '# everyone watching - including whoever did not run it.\n'
        printf 'notify() {\n'
        printf '    [[ -x "$NOTIFY" ]] || return 0\n'
        printf '    "$NOTIFY" "$1" >/dev/null 2>&1 || log "WARN: Telegram notification failed"\n'
        printf '}\n'
        printf 'abort() { printf "\\n*** ABORTED: %%s\\n" "$*" >&2; exit 1; }\n\n'
        printf 'if [[ $EUID -ne 0 ]]; then\n'
        printf '    log "WARNING: not running as root - evidence collection may be incomplete"\n'
        printf 'fi\n\n'
    } > "$file"
}

# Phase 1+2: preserve the artefact and verify it is unchanged.
rem_preserve_file() {

    local file="$1" target="$2" hash="$3"

    {
        printf '# ------------------------------------------------------------\n'
        printf '# PHASE 1 - PRESERVE (always runs)\n'
        printf '# ------------------------------------------------------------\n\n'
        printf 'TARGET=%s\n' "$(rem_q "$target")"
        printf 'SAFE_NAME="$(printf "%%s" "$TARGET" | tr -c "A-Za-z0-9._-" "_")"\n\n'
        printf 'if [[ -e "$TARGET" ]]; then\n'
        printf '    log "preserving $TARGET"\n'
        printf '    cp -a -- "$TARGET" "$EVIDENCE/$SAFE_NAME" 2>/dev/null || log "WARN: copy failed"\n'
        printf '    {\n'
        printf '        printf "path      : %%s\\n" "$TARGET"\n'
        printf '        printf "collected : %%s\\n" "$(date "+%%F %%T %%Z")"\n'
        printf '        printf "stat      : %%s\\n" "$(stat -c "mode=%%a owner=%%U:%%G size=%%s mtime=%%y ctime=%%z inode=%%i links=%%h" -- "$TARGET" 2>/dev/null)"\n'
        printf '        printf "sha256    : %%s\\n" "$(sha256sum -- "$TARGET" 2>/dev/null | awk "{print \\$1}")"\n'
        printf '        printf "attrs     : %%s\\n" "$(lsattr -d -- "$TARGET" 2>/dev/null)"\n'
        printf '        printf "file      : %%s\\n" "$(file -b -- "$TARGET" 2>/dev/null)"\n'
        printf '        if command -v git >/dev/null && git -C "$(dirname -- "$TARGET")" rev-parse --is-inside-work-tree >/dev/null 2>&1; then\n'
        printf '            printf "git_head  : %%s\\n" "$(git -C "$(dirname -- "$TARGET")" rev-parse HEAD 2>/dev/null)"\n'
        printf '            printf "git_state : %%s\\n" "$(git -C "$(dirname -- "$TARGET")" status --porcelain -- "$TARGET" 2>/dev/null)"\n'
        printf '        fi\n'
        printf '    } > "$EVIDENCE/$SAFE_NAME.meta" 2>/dev/null\n'
        printf '    log "evidence -> $EVIDENCE/$SAFE_NAME"\n'
        printf 'else\n'
        printf '    log "NOTE: $TARGET no longer exists - it may have been removed since the scan"\n'
        printf 'fi\n\n'

        if [[ -n "$hash" && "$hash" != "unreadable" && "$hash" != not-hashed* ]]; then
            printf '# ------------------------------------------------------------\n'
            printf '# PHASE 2 - VERIFY (the file must be the one that was scanned)\n'
            printf '# ------------------------------------------------------------\n\n'
            printf 'EXPECTED_SHA=%s\n' "$(rem_q "$hash")"
            printf 'if [[ -f "$TARGET" ]]; then\n'
            printf '    CURRENT_SHA="$(sha256sum -- "$TARGET" 2>/dev/null | awk "{print \\$1}")"\n'
            printf '    if [[ "$CURRENT_SHA" != "$EXPECTED_SHA" ]]; then\n'
            printf '        log "content changed since the audit:"\n'
            printf '        log "  scanned: $EXPECTED_SHA"\n'
            printf '        log "  now    : $CURRENT_SHA"\n'
            printf '        abort "refusing to act on a file that changed after it was examined. Re-run: itm-security audit"\n'
            printf '    fi\n'
            printf '    log "hash verified"\n'
            printf 'fi\n\n'
        fi
    } >> "$file"
}

rem_confirm_gate() {
    local file="$1" impact="$2"
    {
        printf '# ------------------------------------------------------------\n'
        printf '# PHASE 3 - CONTAIN\n'
        printf '# ------------------------------------------------------------\n\n'
        printf 'printf "\\nIMPACT OF THE NEXT STEP:\\n%%s\\n\\n" %s\n' "$(rem_q "$impact")"
        printf 'if [[ "$CONFIRM" != "yes" ]]; then\n'
        printf '    log "DRY RUN - evidence preserved, nothing changed."\n'
        printf '    log "Re-run with CONFIRM=yes to apply the containment above."\n'
        printf '    exit 0\n'
        printf 'fi\n\n'
        printf '# A typed confirmation, not just an environment variable.\n'
        printf '# CONFIRM=yes can be set by accident, reused from shell history,\n'
        printf '# or inherited by a script. Typing the word cannot.\n'
        printf 'if [[ "${FORCE:-no}" != "yes" ]]; then\n'
        printf '    if [[ -t 0 ]]; then\n'
        printf '        printf "Type CONTAIN to proceed, anything else to abort: "\n'
        printf '        read -r ANSWER\n'
        printf '        [[ "$ANSWER" == "CONTAIN" ]] || abort "not confirmed by the operator"\n'
        printf '    else\n'
        printf '        # No terminal: a containment cannot be triggered by a\n'
        printf '        # pipeline, a cron job or a copied command line without\n'
        printf '        # someone saying so explicitly.\n'
        printf '        abort "no terminal available for confirmation - re-run interactively, or set FORCE=yes to bypass the typed confirmation deliberately"\n'
        printf '    fi\n'
        printf 'fi\n\n'
        printf 'OPERATOR="${SUDO_USER:-$(id -un 2>/dev/null)}"\n'
        printf 'FROM="${SSH_CONNECTION:-}"\n'
        printf 'FROM="${FROM%%%% *}"\n'
        printf '[[ -n "$FROM" ]] || FROM="local session (not proof of console access)"\n\n'
    } >> "$file"
}

REM_NOTIFY_TITLE=""; REM_NOTIFY_SEV=""; REM_NOTIFY_PATH=""; REM_NOTIFY_REF=""

rem_footer() {
    local file="$1" rollback="$2"
    {
        printf '\n# ------------------------------------------------------------\n'
        printf '# PHASE 4 - ROLLBACK\n'
        printf '# ------------------------------------------------------------\n'
        printf '#\n'
        while IFS= read -r line; do
            printf '#   %s\n' "$line"
        done <<< "$rollback"
        printf '#\n\n'
        printf 'if (( CHANGED )); then\n'
        printf '    notify "🛠️ REMEDIATION APPLIED\n'
        printf '\n'
        printf 'Finding  : %s\n' "$REM_NOTIFY_TITLE"
        printf 'Severity : %s\n' "$REM_NOTIFY_SEV"
        printf 'Path     : %s\n' "$REM_NOTIFY_PATH"
        printf 'Action   : contained (file moved to quarantine, not deleted)\n'
        printf 'Operator : $OPERATOR\n'
        printf 'Source   : $FROM\n'
        printf 'Evidence : $INCIDENT_DIR\n'
        printf 'Ref      : %s\n' "$REM_NOTIFY_REF"
        printf '\n'
        printf 'Rollback instructions are in PHASE 4 of the script."\n'
        printf '    log "Telegram notified"\n'
        printf 'else\n'
        printf '    log "nothing was changed on this host"\n'
        printf 'fi\n\n'
        printf 'log "done. Evidence: $EVIDENCE   Quarantine: $QUARANTINE"\n'
        printf 'log "Re-run the audit to confirm: itm-security audit"\n'
    } >> "$file"
    chmod 700 "$file"
}

# Move a file to quarantine instead of deleting it.
rem_quarantine_move() {
    local file="$1"
    {
        printf '[[ -w "$(dirname -- "$TARGET")" ]] || abort "no write access to $(dirname -- "$TARGET") - run as root"\n'
        printf 'log "moving $TARGET to quarantine"\n'
        printf 'mv -- "$TARGET" "$QUARANTINE/$SAFE_NAME" || abort "move failed"\n'
        printf 'chmod 600 "$QUARANTINE/$SAFE_NAME" 2>/dev/null || true\n'
        printf 'CHANGED=1\n'
        printf 'log "quarantined -> $QUARANTINE/$SAFE_NAME"\n'
        printf 'log "the file is NO LONGER served, and is NOT deleted"\n'
    } >> "$file"
}

# ============================================================
# Per finding-type templates
#
# Keyed on the finding id prefix produced by the modules.
# Anything without a specific template gets the generic one:
# preserve, verify, and a documented manual review step.
# ============================================================

rem_template() {

    local file="$1" id="$2" path="$3" hash="$4" title="$5" action="$6"

    case "$id" in

        # ---- malicious web content ------------------------------
        webshell:*|polyglot:*|gambling:*|seo:*|integrity-created:*)
            rem_preserve_file "$file" "$path" "$hash"
            rem_confirm_gate "$file" \
"The file will be MOVED out of the web root into the incident quarantine.
It is not deleted, so it can be restored if this turns out to be legitimate.
The URL that served it will start returning 404.
If the application imports this file, that feature breaks until it is restored."
            rem_quarantine_move "$file"
            {
                printf '\nlog "checking for sibling files written in the same minute"\n'
                printf 'DIR="$(dirname -- "$TARGET")"\n'
                printf 'find "$DIR" -maxdepth 1 -newermt "$(date -d "@$(( $(date +%%s) - 900 ))" "+%%F %%T")" -type f 2>/dev/null \\\n'
                printf '    | head -20 | tee "$EVIDENCE/$SAFE_NAME.siblings.txt"\n'
                printf 'log "review the list above: an upload rarely arrives alone"\n'
            } >> "$file"
            rem_footer "$file" \
"mv -- \"\$QUARANTINE/\$SAFE_NAME\" \"$path\"
Then re-run: itm-security audit webshell gambling seo"
            ;;

        # ---- PHP handler re-enabled in an upload directory -------
        apache-upload-htaccess:*|apache-user-ini:*)
            rem_preserve_file "$file" "$path" "$hash"
            rem_confirm_gate "$file" \
"The handler file will be MOVED to quarantine, which stops PHP execution in this
upload directory. If the application legitimately relies on it (rare for uploads),
uploads keep working but any PHP behaviour configured here stops."
            rem_quarantine_move "$file"
            {
                printf '\nlog "scanning the directory for files that were executable because of it"\n'
                printf 'DIR="$(dirname -- "$TARGET")"\n'
                printf 'grep -rlI -e "<?php" -e "<?=" "$DIR" 2>/dev/null | head -20 \\\n'
                printf '    | tee "$EVIDENCE/$SAFE_NAME.php-content.txt"\n'
                printf 'log "every file listed above must be reviewed before it is trusted"\n'
            } >> "$file"
            rem_footer "$file" \
"mv -- \"\$QUARANTINE/\$SAFE_NAME\" \"$path\"
Longer term: set AllowOverride None for this directory in the Apache config."
            ;;

        # ---- unpackaged / known malicious system binary ----------
        ioc-unpackaged-bin:*|ioc-known-path:*|ioc-known-hash:*)
            rem_preserve_file "$file" "$path" "$hash"
            {
                printf 'log "recording what currently uses this binary"\n'
                printf '{\n'
                printf '    printf "=== running processes ===\\n"\n'
                printf '    for p in /proc/[0-9]*; do\n'
                printf '        [[ "$(readlink "$p/exe" 2>/dev/null)" == "$TARGET" ]] || continue\n'
                printf '        printf "PID %%s cmdline: %%s\\n" "${p##*/}" "$(tr "\\\\0" " " < "$p/cmdline" 2>/dev/null)"\n'
                printf '    done\n'
                printf '    printf "\\n=== systemd units referencing it ===\\n"\n'
                printf '    grep -rl -- "$TARGET" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null\n'
                printf '    printf "\\n=== cron referencing it ===\\n"\n'
                printf '    grep -rl -- "$TARGET" /etc/cron* /var/spool/cron 2>/dev/null\n'
                printf '    printf "\\n=== PAM referencing it ===\\n"\n'
                printf '    grep -rl -- "$TARGET" /etc/pam.d 2>/dev/null\n'
                printf '} > "$EVIDENCE/$SAFE_NAME.usage.txt" 2>/dev/null\n'
                printf 'cat "$EVIDENCE/$SAFE_NAME.usage.txt"\n\n'
            } >> "$file"
            rem_confirm_gate "$file" \
"The binary will be MOVED to quarantine. Anything that invokes it - a systemd unit,
a cron job, a PAM hook - will start failing, which is the intended outcome but WILL
appear in logs. Read the usage report printed above FIRST: if a unit calls it, disable
that unit before moving the binary, or the service will crash-loop."
            rem_quarantine_move "$file"
            rem_footer "$file" \
"mv -- \"\$QUARANTINE/\$SAFE_NAME\" \"$path\" && chmod 755 \"$path\"
The persistence that installed it is the real problem: review the usage report."
            ;;

        # ---- malicious systemd persistence ----------------------
        known-bad-unit:*|unit-unowned-exec:*|unit-volatile-exec:*|unit-suspicious-exec:*|unit-home-exec:*)
            rem_preserve_file "$file" "$path" "$hash"
            {
                printf 'UNIT="$(basename -- "$TARGET")"\n'
                printf 'log "recording unit state"\n'
                printf '{\n'
                printf '    systemctl status "$UNIT" --no-pager 2>&1 | head -30\n'
                printf '    printf "\\n=== unit file ===\\n"\n'
                printf '    systemctl cat "$UNIT" 2>/dev/null\n'
                printf '} > "$EVIDENCE/$SAFE_NAME.unit.txt" 2>/dev/null\n\n'
            } >> "$file"
            rem_confirm_gate "$file" \
"The unit will be STOPPED and DISABLED, then its file moved to quarantine.
If this unit is legitimate, the service it provides goes down immediately.
Check the unit file in the evidence directory before continuing."
            {
                printf 'log "stopping and disabling $UNIT"\n'
                printf 'systemctl disable --now "$UNIT" 2>&1 | tee -a "$EVIDENCE/$SAFE_NAME.unit.txt"\n'
                printf 'systemctl mask "$UNIT" 2>&1 | tee -a "$EVIDENCE/$SAFE_NAME.unit.txt"\n'
                printf 'CHANGED=1\n'
            } >> "$file"
            rem_quarantine_move "$file"
            {
                printf 'systemctl daemon-reload\n'
                printf 'log "unit stopped, masked and quarantined"\n'
                printf 'log "NOTE: the process it started may still be running - check before killing it"\n'
                printf 'pgrep -a -f "${UNIT%%.service}" 2>/dev/null | head -5 || true\n'
            } >> "$file"
            rem_footer "$file" \
"systemctl unmask \"\$UNIT\"
mv -- \"\$QUARANTINE/\$SAFE_NAME\" \"$path\"
systemctl daemon-reload && systemctl enable --now \"\$UNIT\""
            ;;

        # ---- PAM credential stealer -----------------------------
        pam-expose-authtok:*|pam-dormant-exec:*|pam-auth-exec:*|pam-session-exec:*)
            rem_preserve_file "$file" "$path" "$hash"
            {
                printf 'log "backing up the whole PAM directory before anything else"\n'
                printf 'tar -czf "$EVIDENCE/pam.d-backup.tar.gz" -C /etc pam.d 2>/dev/null \\\n'
                printf '    && log "PAM backup -> $EVIDENCE/pam.d-backup.tar.gz"\n\n'
                printf 'printf "\\n"\n'
                printf 'printf "############################################################\\n"\n'
                printf 'printf "# EDITING PAM CAN LOCK EVERY ACCOUNT OUT OF THIS SERVER.\\n"\n'
                printf 'printf "# Do not continue over SSH without a second, already-open\\n"\n'
                printf 'printf "# root session AND console/KVM/iDRAC access you have tested.\\n"\n'
                printf 'printf "############################################################\\n\\n"\n'
                printf 'if [[ "${CONSOLE_ACCESS:-no}" != "yes" ]]; then\n'
                printf '    log "set CONSOLE_ACCESS=yes as well, once you have a recovery path"\n'
                printf '    log "evidence has been preserved; nothing was changed"\n'
                printf '    exit 0\n'
                printf 'fi\n\n'
            } >> "$file"
            rem_confirm_gate "$file" \
"The pam_exec line will be commented out in the PAM file, and the helper binary moved
to quarantine. A mistake here locks out every login on this host.
The full PAM directory has already been backed up to the evidence folder."
            {
                printf 'PAMFILE=%s\n' "$(rem_q "$path")"
                printf 'log "commenting pam_exec lines in $PAMFILE"\n'
                printf 'cp -a -- "$PAMFILE" "$EVIDENCE/$(basename -- "$PAMFILE").before"\n'
                printf 'sed -i "s|^\\([^#].*pam_exec\\.so.*\\)$|# ITM-DISABLED \\1|" -- "$PAMFILE"\n'
                printf 'log "diff:"\n'
                printf 'diff -u "$EVIDENCE/$(basename -- "$PAMFILE").before" "$PAMFILE" || true\n'
                printf 'CHANGED=1\n'
                printf 'log "TEST AUTHENTICATION NOW, from a second session, before closing this one"\n'
            } >> "$file"
            rem_footer "$file" \
"cp -a \"\$EVIDENCE/\$(basename \"$path\").before\" \"$path\"
Full restore: tar -xzf \"\$EVIDENCE/pam.d-backup.tar.gz\" -C /etc
Rotate every credential used on this host: the stealer saw them in cleartext."
            ;;

        # ---- shadowed forensic commands -------------------------
        shadowed-command:*|shadow-file:*)
            rem_preserve_file "$file" "$path" "$hash"
            rem_confirm_gate "$file" \
"The wrapper in /usr/local will be MOVED to quarantine so the packaged command in
/usr/bin takes over again. If someone installed this override deliberately, whatever
depended on it changes behaviour."
            rem_quarantine_move "$file"
            {
                printf '\nlog "verifying the command now resolves to the packaged binary"\n'
                printf 'CMD="$(basename -- "$TARGET")"\n'
                printf 'hash -r 2>/dev/null || true\n'
                printf 'command -v "$CMD" | tee -a "$EVIDENCE/$SAFE_NAME.resolution.txt"\n'
                printf 'log "output of $CMD can be trusted again once this points at /usr/bin or /bin"\n'
            } >> "$file"
            rem_footer "$file" \
"mv -- \"\$QUARANTINE/\$SAFE_NAME\" \"$path\" && chmod 755 \"$path\""
            ;;

        # ---- world-writable data directory ----------------------
        datadir-world-writable:*)
            rem_preserve_file "$file" "$path" "$hash"
            {
                printf 'log "recording current state before anything is proposed"\n'
                printf '{\n'
                printf '    stat -c "mode=%%a owner=%%U:%%G %%n" -- "$TARGET"\n'
                printf '    printf "\\n=== contents ===\\n"\n'
                printf '    ls -la -- "$TARGET" 2>/dev/null | head -40\n'
                printf '    printf "\\n=== processes holding files open ===\\n"\n'
                printf '    lsof +D "$TARGET" 2>/dev/null | head -20 || fuser -v -m "$TARGET" 2>&1 | head -20\n'
                printf '} > "$EVIDENCE/$SAFE_NAME.state.txt" 2>/dev/null\n'
                printf 'cat "$EVIDENCE/$SAFE_NAME.state.txt"\n\n'
            } >> "$file"
            rem_confirm_gate "$file" \
"NOTHING is changed automatically. Tightening permissions on a live datastore
directory stops the database writing to it if the owning account is guessed wrong,
and a database that cannot write its redo log stops serving immediately.
This step prints the exact commands for you to apply after checking the owner above."
            {
                printf 'OWNER="$(stat -c %%U -- "$TARGET" 2>/dev/null)"\n'
                printf 'cat <<PLAN | tee "$INCIDENT_DIR/plan-$SAFE_NAME.txt"\n'
                printf 'Confirm the owning account from the lsof/fuser output above, then:\n'
                printf '\n'
                printf '  systemctl stop <the service that uses this directory>\n'
                printf '  chown -R <account>:<account> %%s\n' "$path"
                printf '  chmod 700 %%s\n' "$path"
                printf '  systemctl start <the service>\n'
                printf '\n'
                printf 'Verify afterwards that the service still writes: check its log and\n'
                printf 'that the datastore files keep their mtime moving.\n'
                printf '\n'
                printf 'While the directory was world-writable, treat the data as exposed:\n'
                printf 'any local account could read the raw files without a database password.\n'
                printf 'PLAN\n'
            } >> "$file"
            rem_footer "$file" "Nothing was changed, so there is nothing to roll back."
            ;;

        # ---- writable directory that executes PHP ---------------
        writable-php-dir:*)
            rem_preserve_file "$file" "$path" "$hash"
            {
                printf 'log "recording current permissions"\n'
                printf 'stat -c "%%a %%U:%%G %%n" -- "$TARGET" > "$EVIDENCE/$SAFE_NAME.perm.txt"\n'
                printf 'ls -la -- "$TARGET" >> "$EVIDENCE/$SAFE_NAME.perm.txt" 2>/dev/null\n\n'
            } >> "$file"
            rem_confirm_gate "$file" \
"NOTHING is changed automatically here. Tightening permissions on an upload directory
breaks uploads if the application writes there as a different user, and blocking PHP
belongs in the web server configuration, not in a permission change.
This step only prints the exact commands for you to apply after review."
            {
                printf 'cat <<PLAN | tee "$INCIDENT_DIR/plan-$SAFE_NAME.txt"\n'
                printf 'Preferred fix - stop PHP execution, keep the directory writable:\n'
                printf '\n'
                printf '  Nginx, inside the server block:\n'
                printf '    location ~* ^%%s/.*\\.(php|phtml|phar|php[0-9]*)$ { return 403; }\n' "${path}"
                printf '\n'
                printf '  Apache, inside the vhost:\n'
                printf '    <Directory %%s>\n' "${path}"
                printf '        AllowOverride None\n'
                printf '        php_admin_flag engine off\n'
                printf '        <FilesMatch "\\.(php|phtml|phar|php[0-9]*)$">\n'
                printf '            Require all denied\n'
                printf '        </FilesMatch>\n'
                printf '    </Directory>\n'
                printf '\n'
                printf 'Then: nginx -t   (or apache2ctl -t)   and reload in a maintenance window.\n'
                printf 'PLAN\n'
                printf 'log "plan written to $INCIDENT_DIR/plan-$SAFE_NAME.txt - apply it manually"\n'
            } >> "$file"
            rem_footer "$file" \
"Nothing was changed, so there is nothing to roll back.
Remove the location/Directory block again if it breaks the application."
            ;;

        # ---- deleted or fileless process ------------------------
        deleted-exe:*|memfd-exe:*|volatile-exe:*|hidden-pid:*)
            {
                printf '# ------------------------------------------------------------\n'
                printf '# PHASE 1 - PRESERVE (always runs)\n'
                printf '# ------------------------------------------------------------\n\n'
                printf 'TARGET=%s\n' "$(rem_q "$path")"
                printf 'SAFE_NAME="$(printf "%%s" "$TARGET" | tr -c "A-Za-z0-9._-" "_")"\n\n'
                printf 'log "capturing every live process matching this executable"\n'
                printf 'for p in /proc/[0-9]*; do\n'
                printf '    LINK="$(readlink "$p/exe" 2>/dev/null)" || continue\n'
                printf '    [[ "$LINK" == "$TARGET"* ]] || continue\n'
                printf '    PID="${p##*/}"\n'
                printf '    log "capturing PID $PID"\n'
                printf '    D="$EVIDENCE/pid-$PID"\n'
                printf '    mkdir -p "$D"\n'
                printf '    cp -- "$p/exe" "$D/exe.bin" 2>/dev/null && log "  image dumped"\n'
                printf '    tr "\\\\0" " " < "$p/cmdline" > "$D/cmdline.txt" 2>/dev/null\n'
                printf '    cp -- "$p/status" "$p/maps" "$p/cgroup" "$D/" 2>/dev/null\n'
                printf '    ls -l "$p/fd" > "$D/fd.txt" 2>/dev/null\n'
                printf '    ss -tunap 2>/dev/null | grep "pid=$PID," > "$D/sockets.txt"\n'
                printf '    sha256sum "$D/exe.bin" >> "$D/sha256.txt" 2>/dev/null\n'
                printf 'done\n'
                printf 'log "process evidence under $EVIDENCE"\n\n'
            } >> "$file"
            rem_confirm_gate "$file" \
"NOTHING is killed automatically. Killing the process destroys the only copy of a
fileless payload that exists in memory, and a service manager will often restart it
anyway. The commands to stop it are printed for you to run AFTER the capture above
is confirmed complete."
            {
                printf 'cat <<PLAN | tee "$INCIDENT_DIR/plan-process.txt"\n'
                printf 'Evidence is captured. To stop the process, in this order:\n'
                printf '\n'
                printf '  1. Find what restarts it (systemd unit, cron, parent PID) and disable that FIRST,\n'
                printf '     otherwise it comes straight back.\n'
                printf '  2. Block its egress at the perimeter rather than killing it, if you still need\n'
                printf '     to observe it.\n'
                printf '  3. Only then:  kill -TERM <PID>     and verify it does not reappear.\n'
                printf '\n'
                printf 'On a host with a confirmed root compromise, the correct end state is a rebuild.\n'
                printf 'PLAN\n'
            } >> "$file"
            rem_footer "$file" "Nothing was changed, so there is nothing to roll back."
            ;;

        # ---- generic ---------------------------------------------
        *)
            rem_preserve_file "$file" "$path" "$hash"
            rem_confirm_gate "$file" \
"No automated containment is defined for this finding type, on purpose.
The recommended action from the audit is printed below for manual execution."
            {
                printf 'cat <<PLAN | tee "$INCIDENT_DIR/plan-$SAFE_NAME.txt"\n'
                printf '%s\n' "$action"
                printf 'PLAN\n'
            } >> "$file"
            rem_footer "$file" "Nothing was changed, so there is nothing to roll back."
            ;;
    esac
}

# ============================================================
# Generator
# ============================================================

REM_INCIDENT_DIR=""

rem_generate() {

    local min_sev="${1:-HIGH}"
    local total="${#REM_SEV[@]}"
    local i generated=0 min_num
    local file slug

    min_num="$(sev_num "$min_sev")"

    if (( total == 0 )); then
        say ""
        say "No finding at or above ${min_sev} - no response script generated."
        return 0
    fi

    REM_INCIDENT_DIR="$REMEDIATE_BASE_DIR/incident-$(date '+%Y%m%d-%H%M%S')"

    if ! mkdir -p "$REM_INCIDENT_DIR"; then
        say_err "[ERROR] Cannot create $REM_INCIDENT_DIR (run as root)"
        return 1
    fi
    chmod 700 "$REMEDIATE_BASE_DIR" "$REM_INCIDENT_DIR" 2>/dev/null || true

    # --- incident summary -------------------------------------
    local summary="$REM_INCIDENT_DIR/00-INCIDENT-SUMMARY.txt"
    {
        printf '============================================================\n'
        printf ' ITM INCIDENT RESPONSE PACK\n'
        printf '============================================================\n\n'
        printf 'Host        : %s (%s)\n' "$ITM_HOSTNAME" "$ITM_PRIVATE_IP"
        printf 'Generated   : %s\n' "$(date '+%Y-%m-%d %H:%M:%S %Z')"
        printf 'Host trust  : %s\n' "$HOST_TRUST_STATUS"
        printf 'Findings    : %s at or above %s\n\n' "$total" "$min_sev"
        printf 'HOW TO USE THIS DIRECTORY\n'
        printf '  Every script below preserves evidence first and changes nothing\n'
        printf '  until you re-run it with CONFIRM=yes.\n\n'
        printf '    bash 10-*.sh              # preserve + show what would happen\n'
        printf '    CONFIRM=yes bash 10-*.sh  # apply the containment\n\n'
        printf '  Work through them in order. Re-run the audit afterwards:\n'
        printf '    itm-security audit\n\n'
        printf 'WHAT THESE SCRIPTS WILL NEVER DO\n'
        printf '  No rm of a suspect file (moved to quarantine instead)\n'
        printf '  No git reset / git clean\n'
        printf '  No recursive chmod / chattr\n'
        printf '  No unattended process kill\n'
        printf '  No firewall or SSH changes\n\n'
        printf 'IMPORTANT\n'
        printf '  Containing a payload is not the same as trusting the host again.\n'
        printf '  A host with a confirmed root level compromise stays UNTRUSTED\n'
        printf '  until it is rebuilt from trusted media.\n\n'
        printf '============================================================\n'
        printf ' FINDINGS\n'
        printf '============================================================\n\n'
    } > "$summary"

    for (( i = 0; i < total; i++ )); do

        (( $(sev_num "${REM_SEV[$i]}") >= min_num )) || continue

        generated=$(( generated + 1 ))

        slug="$(rem_slug "${REM_MODULE[$i]}" "${REM_PATH[$i]:-${REM_ID[$i]}}" "${REM_FP[$i]}")"
        file="$(printf '%s/10-%02d-%s.sh' "$REM_INCIDENT_DIR" "$generated" "$slug")"

        rem_header "$file" \
            "${REM_TITLE[$i]}" "${REM_SEV[$i]}" "${REM_CONF[$i]}" \
            "${REM_PATH[$i]}" "${REM_HASH[$i]}" "${REM_REASONS[$i]}" \
            "${REM_FP[$i]}" "${REM_MODULE[$i]}"

        REM_NOTIFY_TITLE="${REM_TITLE[$i]}"
        REM_NOTIFY_SEV="${REM_SEV[$i]}"
        REM_NOTIFY_PATH="${REM_PATH[$i]:-n/a}"
        REM_NOTIFY_REF="${REM_FP[$i]}"

        rem_template "$file" \
            "${REM_ID[$i]}" "${REM_PATH[$i]}" "${REM_HASH[$i]}" \
            "${REM_TITLE[$i]}" "${REM_ACTION[$i]}"

        # Machine readable index for the triage runner.
        printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
            "${file##*/}" "${REM_SEV[$i]}" "${REM_CONF[$i]}" \
            "${REM_TITLE[$i]}" "${REM_PATH[$i]}" "${REM_FP[$i]}" \
            >> "$REM_INCIDENT_DIR/findings.tsv"

        # Reasons, one per line, for the triage display.
        printf '%s\n' "${REM_REASONS[$i]}" > "$REM_INCIDENT_DIR/.reasons-${REM_FP[$i]}"

        {
            printf '[%s] %s (confidence %s%%)\n' "${REM_SEV[$i]}" "${REM_TITLE[$i]}" "${REM_CONF[$i]}"
            [[ -n "${REM_PATH[$i]}" ]] && printf '    path   : %s\n' "${REM_PATH[$i]}"
            [[ -n "${REM_HASH[$i]}" ]] && printf '    sha256 : %s\n' "${REM_HASH[$i]}"
            printf '    script : %s\n' "${file##*/}"
            printf '    why    :\n'
            while IFS= read -r line; do
                [[ -n "$line" ]] && printf '             - %s\n' "$line"
            done <<< "${REM_REASONS[$i]}"
            printf '\n'
        } >> "$summary"

    done

    chmod 600 "$summary" 2>/dev/null || true

    # --- interactive triage runner ----------------------------
    #
    # Walking the findings one at a time and recording the
    # decision is the part that makes an incident reviewable a
    # month later. "Why is this file in quarantine?" and "why did
    # we leave that one alone?" both have written answers here,
    # with who decided and when.
    local triage="$REM_INCIDENT_DIR/00-triage.sh"
    {
        printf '#!/usr/bin/env bash\n'
        printf '#\n'
        printf '# ITM incident triage - interactive.\n'
        printf '#\n'
        printf '# Goes through every finding in this pack and asks one\n'
        printf '# question per finding. Nothing is contained without an\n'
        printf '# explicit yes, and every decision is written to\n'
        printf '# DECISIONS.log with the reason you give.\n'
        printf '#\n'
        printf 'set -uo pipefail\n\n'
        printf 'INCIDENT_DIR=%s\n' "$(rem_q "$REM_INCIDENT_DIR")"
        printf 'cd "$INCIDENT_DIR" || exit 1\n\n'
        printf 'DECISIONS="$INCIDENT_DIR/DECISIONS.log"\n'
        printf 'NOTIFY=%s\n' "$(rem_q "$ITM_NOTIFY_BIN")"
        printf 'OPERATOR="${SUDO_USER:-$(id -un 2>/dev/null)}"\n'
        printf 'FROM="${SSH_CONNECTION:-}"; FROM="${FROM%%%% *}"\n'
        printf '[[ -n "$FROM" ]] || FROM="local session (not proof of console access)"\n\n'
        printf 'C_RED=""; C_YEL=""; C_DIM=""; C_OFF=""\n'
        printf 'if [[ -t 1 ]]; then C_RED=$(printf "\\033[1;31m"); C_YEL=$(printf "\\033[1;33m"); C_DIM=$(printf "\\033[2m"); C_OFF=$(printf "\\033[0m"); fi\n\n'
        printf '# Answers are read from the controlling terminal, so that\n'
        printf '# is what must exist - stdin may legitimately be something\n'
        printf '# else (a log pipe, a here-document driving the outer run).\n'
        printf 'if [[ ! -e /dev/tty ]] || ! : >/dev/tty 2>/dev/null; then\n'
        printf '    printf "This script is interactive and needs a controlling terminal.\\n" >&2\n'
        printf '    printf "Run it from a shell: sudo bash %%s/00-triage.sh\\n" "$INCIDENT_DIR" >&2\n'
        printf '    exit 1\n'
        printf 'fi\n\n'
        printf 'TOTAL=$(wc -l < "$INCIDENT_DIR/findings.tsv" 2>/dev/null || echo 0)\n'
        printf 'CONTAINED=0; ACCEPTED=0; SKIPPED=0; N=0\n\n'
        printf 'printf "\\n============================================================\\n"\n'
        printf 'printf " INCIDENT TRIAGE - %%s finding(s)\\n" "$TOTAL"\n'
        printf 'printf "============================================================\\n"\n'
        printf 'printf "\\nFor each finding you decide one thing:\\n"\n'
        printf 'printf "  is it legitimate, or is it not?\\n\\n"\n'
        printf 'printf "  y = NOT legitimate  -> contain it (file is MOVED to quarantine, never deleted)\\n"\n'
        printf 'printf "  n = legitimate      -> leave it alone, decision recorded  [default]\\n"\n'
        printf 'printf "  v = view the full response script first\\n"\n'
        printf 'printf "  s = skip, decide later\\n"\n'
        printf 'printf "  q = stop here\\n\\n"\n'
        printf 'printf "Every answer is written to %%s\\n\\n" "$DECISIONS"\n\n'
        printf '{\n'
        printf '  printf "============================================================\\n"\n'
        printf '  printf " TRIAGE SESSION %%s\\n" "$(date "+%%Y-%%m-%%d %%H:%%M:%%S %%Z")"\n'
        printf '  printf " operator : %%s\\n" "$OPERATOR"\n'
        printf '  printf " source   : %%s\\n" "$FROM"\n'
        printf '  printf " host     : %%s\\n" "$(hostname -f 2>/dev/null || hostname)"\n'
        printf '  printf "============================================================\\n\\n"\n'
        printf '} >> "$DECISIONS"\n\n'
        printf 'TAB="$(printf "\\t")"\n'
        printf 'while IFS="$TAB" read -r SCRIPT SEV CONF TITLE FPATH REF; do\n\n'
        printf '    [[ -n "$SCRIPT" ]] || continue\n'
        printf '    N=$(( N + 1 ))\n\n'
        printf '    COLOR="$C_YEL"; [[ "$SEV" == "CRITICAL" ]] && COLOR="$C_RED"\n\n'
        printf '    printf "\\n------------------------------------------------------------\\n"\n'
        printf '    printf "[%%s/%%s] %%s%%s%%s (confidence %%s%%%%)\\n" "$N" "$TOTAL" "$COLOR" "$SEV" "$C_OFF" "$CONF"\n'
        printf '    printf "%%s\\n" "$TITLE"\n'
        printf '    [[ -n "$FPATH" ]] && printf "path    : %%s\\n" "$FPATH"\n'
        printf '    if [[ -f "$INCIDENT_DIR/.reasons-$REF" ]]; then\n'
        printf '        printf "why     :\\n"\n'
        printf '        sed "s/^/          - /" "$INCIDENT_DIR/.reasons-$REF" | head -8\n'
        printf '    fi\n'
        printf '    if [[ -n "$FPATH" && -e "$FPATH" ]]; then\n'
        printf '        printf "on disk : %%s\\n" "$(stat -c "mode=%%a owner=%%U:%%G size=%%s mtime=%%y" -- "$FPATH" 2>/dev/null | cut -c1-90)"\n'
        printf '    elif [[ -n "$FPATH" ]]; then\n'
        printf '        printf "on disk : %%sno longer present%%s\\n" "$C_DIM" "$C_OFF"\n'
        printf '    fi\n\n'
        printf '    ANSWER=""\n'
        printf '    while :; do\n'
        printf '        printf "\\n%%sIs this legitimate?%%s  y=no,contain  n=yes,leave  v=view  s=skip  q=quit [n]: " "$C_DIM" "$C_OFF"\n'
        printf '        read -r ANSWER </dev/tty || ANSWER="q"\n'
        printf '        case "${ANSWER,,}" in\n'
        printf '            v) printf "\\n"; ${PAGER:-less} "$INCIDENT_DIR/$SCRIPT" </dev/tty >/dev/tty 2>&1 || cat "$INCIDENT_DIR/$SCRIPT" ;;\n'
        printf '            y|n|s|q|"") break ;;\n'
        printf '            *) printf "  please answer y, n, v, s or q\\n" ;;\n'
        printf '        esac\n'
        printf '    done\n\n'
        printf '    case "${ANSWER,,}" in\n\n'
        printf '        q) printf "\\nStopped by operator.\\n"; break ;;\n\n'
        printf '        s)\n'
        printf '            SKIPPED=$(( SKIPPED + 1 ))\n'
        printf '            printf "%%s | SKIPPED  | %%s | %%s | ref=%%s\\n" "$(date "+%%F %%T")" "$SEV" "$TITLE" "$REF" >> "$DECISIONS"\n'
        printf '            printf "  -> skipped, no decision recorded\\n" ;;\n\n'
        printf '        y)\n'
        printf '            printf "  reason for containing (one line, optional): "\n'
        printf '            read -r REASON </dev/tty || REASON=""\n'
        printf '            printf "\\n"\n'
        printf '            if CONFIRM=yes FORCE=yes bash "$INCIDENT_DIR/$SCRIPT"; then\n'
        printf '                CONTAINED=$(( CONTAINED + 1 ))\n'
        printf '                QPATH="$(ls -1t "$INCIDENT_DIR/quarantine" 2>/dev/null | head -1)"\n'
        printf '                {\n'
        printf '                  printf "%%s | CONTAINED | %%s | %%s\\n" "$(date "+%%F %%T")" "$SEV" "$TITLE"\n'
        printf '                  printf "    path      : %%s\\n" "${FPATH:-n/a}"\n'
        printf '                  printf "    operator  : %%s from %%s\\n" "$OPERATOR" "$FROM"\n'
        printf '                  printf "    reason    : %%s\\n" "${REASON:-(none given)}"\n'
        printf '                  printf "    script    : %%s\\n" "$SCRIPT"\n'
        printf '                  printf "    quarantine: %%s\\n" "${QPATH:-see script output}"\n'
        printf '                  printf "    rollback  : see PHASE 4 in %%s\\n" "$SCRIPT"\n'
        printf '                  printf "    ref       : %%s\\n\\n" "$REF"\n'
        printf '                } >> "$DECISIONS"\n'
        printf '            else\n'
        printf '                printf "  -> the response script did not complete; nothing recorded as contained\\n"\n'
        printf '                printf "%%s | FAILED   | %%s | %%s | ref=%%s\\n" "$(date "+%%F %%T")" "$SEV" "$TITLE" "$REF" >> "$DECISIONS"\n'
        printf '            fi ;;\n\n'
        printf '        *)\n'
        printf '            printf "  why is it legitimate? (this is what you will read in a month): "\n'
        printf '            read -r REASON </dev/tty || REASON=""\n'
        printf '            ACCEPTED=$(( ACCEPTED + 1 ))\n'
        printf '            {\n'
        printf '              printf "%%s | ACCEPTED  | %%s | %%s\\n" "$(date "+%%F %%T")" "$SEV" "$TITLE"\n'
        printf '              printf "    path      : %%s\\n" "${FPATH:-n/a}"\n'
        printf '              printf "    operator  : %%s from %%s\\n" "$OPERATOR" "$FROM"\n'
        printf '              printf "    reason    : %%s\\n" "${REASON:-(none given)}"\n'
        printf '              printf "    ref       : %%s\\n\\n" "$REF"\n'
        printf '            } >> "$DECISIONS"\n'
        printf '            printf "  -> left in place, decision recorded\\n"\n'
        printf '            if [[ -n "$FPATH" && -f "$FPATH" ]]; then\n'
        printf '                printf "  add it to the exclusion list so future scans stop reporting it? [y/N]: "\n'
        printf '                read -r EXC </dev/tty || EXC="n"\n'
        printf '                if [[ "${EXC,,}" == "y" ]]; then\n'
        printf '                    EXCFILE="/etc/security-monitor/ioc/web-exclusions.conf"\n'
        printf '                    if [[ -w "$(dirname "$EXCFILE")" ]]; then\n'
        printf '                        printf "\\n# accepted by %%s on %%s: %%s\\n%%s\\n" \\\n'
        printf '                            "$OPERATOR" "$(date "+%%F")" "${REASON:-no reason given}" "$FPATH" >> "$EXCFILE"\n'
        printf '                        printf "  -> added to %%s\\n" "$EXCFILE"\n'
        printf '                        printf "    excluded  : added to %%s\\n\\n" "$EXCFILE" >> "$DECISIONS"\n'
        printf '                    else\n'
        printf '                        printf "  -> cannot write %%s (run as root)\\n" "$EXCFILE"\n'
        printf '                    fi\n'
        printf '                fi\n'
        printf '            fi ;;\n'
        printf '    esac\n\n'
        printf 'done < "$INCIDENT_DIR/findings.tsv"\n\n'
        printf 'printf "\\n============================================================\\n"\n'
        printf 'printf " TRIAGE COMPLETE\\n"\n'
        printf 'printf "============================================================\\n"\n'
        printf 'printf "  contained : %%s\\n" "$CONTAINED"\n'
        printf 'printf "  accepted  : %%s\\n" "$ACCEPTED"\n'
        printf 'printf "  skipped   : %%s\\n" "$SKIPPED"\n'
        printf 'printf "\\n  decisions : %%s\\n" "$DECISIONS"\n'
        printf 'printf "  evidence  : %%s/evidence\\n" "$INCIDENT_DIR"\n'
        printf 'printf "  quarantine: %%s/quarantine\\n\\n" "$INCIDENT_DIR"\n'
        printf '{ printf "  SESSION TOTAL: contained=%%s accepted=%%s skipped=%%s\\n\\n" "$CONTAINED" "$ACCEPTED" "$SKIPPED"; } >> "$DECISIONS"\n\n'
        printf 'if [[ -x "$NOTIFY" ]] && (( CONTAINED > 0 || ACCEPTED > 0 )); then\n'
        printf '    "$NOTIFY" "📋 INCIDENT TRIAGE COMPLETED\n'
        printf '\n'
        printf 'Operator : $OPERATOR\n'
        printf 'Source   : $FROM\n'
        printf 'Contained: $CONTAINED\n'
        printf 'Accepted : $ACCEPTED (recorded as legitimate)\n'
        printf 'Skipped  : $SKIPPED\n'
        printf '\n'
        printf 'Decisions: $DECISIONS" >/dev/null 2>&1 || true\n'
        printf 'fi\n'
        printf 'printf "  Re-run the audit to confirm: itm-security audit\\n\\n"\n'
    } > "$triage"
    chmod 700 "$triage"

    # --- verification script ----------------------------------
    local verify="$REM_INCIDENT_DIR/99-verify.sh"
    {
        printf '#!/usr/bin/env bash\n'
        printf '# Re-run the audit and show what is still outstanding.\n'
        printf 'set -uo pipefail\n'
        printf 'itm-security audit\n'
    } > "$verify"
    chmod 700 "$verify"

    say ""
    say "${C_BOLD}Incident response pack generated${C_RESET}"
    say ""
    say "  Directory : $REM_INCIDENT_DIR"
    say "  Summary   : ${summary##*/}"
    say "  Scripts   : $generated (one per finding at or above $min_sev)"
    say ""
    say "  Walk through them one at a time, deciding y/n per finding:"
    say "    sudo bash $REM_INCIDENT_DIR/00-triage.sh"
    say ""
    say "  Or review first:"
    say "    less $summary"
    say ""
    say "  Then, per finding:"
    say "    bash $REM_INCIDENT_DIR/10-01-*.sh              # preserve only"
    say "    CONFIRM=yes bash $REM_INCIDENT_DIR/10-01-*.sh  # contain"
    say ""
    say "${C_DIM}  Nothing has been changed on this host by generating these scripts.${C_RESET}"

    return 0
}

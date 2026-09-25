#!/usr/bin/env bash
# ============================================================================
#  linux_persistence_hunter.sh
#
#  Read-only Linux persistence / compromise triage.
#  Merges reverse_check.sh + persistance_check_2.sh and extends them with:
#    - a findings engine (severity, category, location, detail, remediation)
#    - many additional persistence techniques (ld.so.preload, PAM, udev, APT
#      hooks, kernel modules, file capabilities, fileless processes, packet
#      sockets, package integrity, python .pth, anti-forensics, ...)
#    - far fewer false positives (comments ignored, targeted locations only)
#    - reports: colour terminal table, Markdown, HTML, CSV + raw evidence log
#    - offline mode (--root) to analyse a mounted disk image
#
#  The script never modifies the system it inspects.
#  Run as root for full coverage.
# ============================================================================

set -u
export LC_ALL=C
shopt -s nullglob
shopt -u patsub_replacement 2>/dev/null || true   # bash 5.2: keep "&" literal in ${v//x/y}
exec </dev/null   # empty globs must never make a tool wait on stdin

VERSION="3.0"
ROOT="/"
OUTBASE="."
DAYS=7
QUICK=0
COLOR=1
TOP=25

usage() {
    cat <<EOF
Usage: $0 [options]

  -r, --root DIR     Analyse a mounted image rooted at DIR (offline mode;
                     live process/network/kernel checks are skipped)
  -o, --output DIR   Directory where the report folder is created (default: .)
  -d, --days N       "Recently modified" window in days (default: 7)
  -q, --quick        Skip slow checks (package integrity, full SUID/caps scan)
  -t, --top N        Rows shown in terminal priority table (default: 25)
      --no-color     Disable coloured terminal output
  -h, --help         Show this help

Outputs (in <output>/persistence-report-<host>-<timestamp>/):
  report.html   styled report with priority table and remediation plan
  report.md     same content in Markdown
  findings.csv  all findings, machine readable
  evidence.log  raw collected evidence
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        -r|--root)   ROOT="${2:?}"; shift 2 ;;
        -o|--output) OUTBASE="${2:?}"; shift 2 ;;
        -d|--days)   DAYS="${2:?}"; shift 2 ;;
        -q|--quick)  QUICK=1; shift ;;
        -t|--top)    TOP="${2:?}"; shift 2 ;;
        --no-color)  COLOR=0; shift ;;
        -h|--help)   usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

case "$DAYS" in ''|*[!0-9]*) echo "--days must be a number" >&2; exit 2 ;; esac
case "$TOP"  in ''|*[!0-9]*) echo "--top must be a number" >&2; exit 2 ;; esac
[ -d "$ROOT" ] || { echo "Root directory not found: $ROOT" >&2; exit 2; }

# R is the path prefix: "" on a live system, "/mnt/image" offline.
R="$(cd "$ROOT" && pwd)"; [ "$R" = "/" ] && R=""
LIVE=1; [ -n "$R" ] && LIVE=0

if [ "$LIVE" -eq 1 ]; then
    HOST="$(hostname 2>/dev/null || cat /etc/hostname 2>/dev/null || echo unknown)"
else
    HOST="$(cat "$R/etc/hostname" 2>/dev/null || echo image)"
fi
HOST="${HOST//[^A-Za-z0-9._-]/_}"
TS="$(date +%Y%m%d-%H%M%S)"
STARTED="$(date '+%Y-%m-%d %H:%M:%S %Z')"

OUTDIR="$OUTBASE/persistence-report-$HOST-$TS"
mkdir -p "$OUTDIR" || { echo "Cannot create $OUTDIR" >&2; exit 1; }
chmod 700 "$OUTDIR"   # evidence may contain secrets
OUTDIR="$(cd "$OUTDIR" && pwd)"

EVIDENCE="$OUTDIR/evidence.log"
FINDINGS_RAW="$OUTDIR/.findings.raw"
FINDINGS="$OUTDIR/.findings.sorted"
CSV="$OUTDIR/findings.csv"
MD="$OUTDIR/report.md"
HTML="$OUTDIR/report.html"
OWNED="$OUTDIR/.owned_files"
: > "$EVIDENCE"; : > "$FINDINGS_RAW"
trap 'rm -f "$FINDINGS_RAW" "$FINDINGS" "$OWNED"' EXIT

if [ "$COLOR" -eq 1 ] && [ -t 1 ]; then
    C_CRIT=$'\e[1;41;97m'; C_HIGH=$'\e[1;31m'; C_MED=$'\e[1;33m'
    C_LOW=$'\e[36m'; C_INFO=$'\e[37m'; C_BOLD=$'\e[1m'; C_DIM=$'\e[2m'
    C_OK=$'\e[1;32m'; C_RST=$'\e[0m'
else
    C_CRIT=""; C_HIGH=""; C_MED=""; C_LOW=""; C_INFO=""; C_BOLD=""
    C_DIM=""; C_OK=""; C_RST=""
fi

TIMEOUT=""; command -v timeout >/dev/null 2>&1 && TIMEOUT="timeout 600"

# ============================================================================
# Helpers
# ============================================================================

progress() { printf '%s[*]%s %s\n' "$C_BOLD" "$C_RST" "$1" >&2; }

section() {
    progress "$1"
    printf '\n\n############################################################\n# %s\n############################################################\n' "$1" >> "$EVIDENCE"
}

# evidence "title" cmd args...   -> raw output into evidence.log
evidence() {
    local t="$1"; shift
    { printf '\n---- %s ----\n' "$t"; "$@" 2>&1; } >> "$EVIDENCE"
}

# Strip the image prefix for display.
disp() { local p="$1"; [ -n "$R" ] && p="${p#"$R"}"; printf '%s' "${p:-/}"; }

trim() { local s="$1"; s="${s#"${s%%[![:space:]]*}"}"; printf '%s' "${s:0:220}"; }

# add_finding SEVERITY CATEGORY LOCATION DETAIL
add_finding() {
    local sev="$1" cat="$2" loc="$3" det="$4"
    loc="${loc//$'\t'/ }"; loc="${loc//$'\n'/ }"
    det="${det//$'\t'/ }"; det="${det//$'\n'/ }"; det="${det//$'\r'/ }"
    printf '%s\t%s\t%s\t%s\n' "$sev" "$cat" "$loc" "${det:0:260}" >> "$FINDINGS_RAW"
}

is_elf() {
    [ -f "$1" ] && [ -r "$1" ] || return 1
    local magic=""
    read -r -N 4 magic 2>/dev/null < "$1"
    [ "$magic" = $'\x7fELF' ]
}

recent() { [ -n "$(find "$1" -maxdepth 0 -mtime "-$DAYS" 2>/dev/null)" ]; }

mtime() { stat -c '%y' "$1" 2>/dev/null | cut -d. -f1; }

# Home directories from passwd (plus /root), prefixed with R.
HOMES=()
while IFS=: read -r _u _x _uid _gid _g home _sh; do
    [ -n "$home" ] && [ "$home" != "/" ] && [ -d "$R$home" ] && HOMES+=("$R$home")
done < <(cat "$R/etc/passwd" 2>/dev/null; echo "root:x:0:0::/root:")
mapfile -t HOMES < <(printf '%s\n' "${HOMES[@]}" | sort -u)

# ============================================================================
# Package ownership (used to flag files that no package installed)
# ============================================================================

PKG=none
: > "$OWNED"
if [ -d "$R/var/lib/dpkg/info" ]; then
    PKG=dpkg
    cat "$R"/var/lib/dpkg/info/*.list 2>/dev/null | sort -u > "$OWNED"
elif command -v rpm >/dev/null 2>&1 && { [ -d "$R/var/lib/rpm" ] || [ -d "$R/usr/lib/sysimage/rpm" ]; }; then
    PKG=rpm
    if [ "$LIVE" -eq 1 ]; then
        rpm -qa --qf '[%{FILENAMES}\n]' 2>/dev/null | sort -u > "$OWNED"
    else
        rpm --root "$R" -qa --qf '[%{FILENAMES}\n]' 2>/dev/null | sort -u > "$OWNED"
    fi
fi
[ -s "$OWNED" ] || PKG=none

# Owned paths as a hash, so a lookup costs no process (a grep of the list
# per file made the systemd and SUID checks slow).
declare -A OWNED_SET=()
if [ "$PKG" != none ]; then
    while IFS= read -r _p; do [ -n "$_p" ] && OWNED_SET[$_p]=1; done < "$OWNED"
    unset _p
fi

# is_owned /path (display path, without R prefix). Handles usr-merge aliases.
is_owned() {
    [ "$PKG" = none ] && return 0
    local p="$1" c=""
    [ -n "$p" ] || return 1
    case "$p" in /snap/*|/var/lib/snapd/snap/*) return 0 ;; esac   # read-only squashfs managed by snapd
    [ -n "${OWNED_SET[$p]+x}" ] && return 0
    case "$p" in
        /usr/bin/*|/usr/sbin/*|/usr/lib/*|/usr/lib64/*|/usr/lib32/*) c="${p#/usr}" ;;
        /bin/*|/sbin/*|/lib/*|/lib64/*|/lib32/*) c="/usr$p" ;;
    esac
    [ -n "$c" ] && [ -n "${OWNED_SET[$c]+x}" ] && return 0
    if [ "$LIVE" -eq 1 ]; then
        c="$(readlink -f "$p" 2>/dev/null)" && [ -n "$c" ] && [ -n "${OWNED_SET[$c]+x}" ] && return 0
    fi
    return 1
}

# ============================================================================
# Detection patterns (POSIX ERE)
# ============================================================================

P_REVSHELL='/dev/(tcp|udp)/[^[:space:]]+/[0-9]+|(ba)?sh[[:space:]]+-i[[:space:]]*[<>&0-9]|(^|[[:space:];|&(])(nc|ncat|netcat)[[:space:]][^;|]*[[:space:]]-[a-z]*[ec][[:space:]]|socat[[:space:]][^;]*(exec|system):|mkfifo[^;]*;[^;]*(nc|ncat|telnet|openssl)|python[0-9.]*[[:space:]]+-c.*socket|perl[[:space:]]+-e.*[Ss]ocket|php[[:space:]]+-r.*fsockopen|ruby[[:space:]].*-rsocket|openssl[[:space:]]+s_client[^|]*\|[[:space:]]*(/bin/)?(ba)?sh|telnet[[:space:]][^|]*\|[[:space:]]*(/bin/)?(ba)?sh'
P_DLEXEC='(curl|wget|fetch)[^|;]*\|[[:space:]]*(sudo[[:space:]]+)?(/bin/|/usr/bin/)?(ba|da|z)?sh|(curl|wget)[^|;]*\|[[:space:]]*(python[0-9.]*|perl|php|ruby)|(curl|wget)[^;&|]*[[:space:]]-[oO][^;&|]*[;&|]+[^;]*chmod[[:space:]]+[+0-7]*x'
P_ENCODED='base64[[:space:]]+(-d|--decode|-D)[^|]*\|[[:space:]]*(/bin/)?(ba|z|da)?sh|echo[[:space:]]+["'"'"']?[A-Za-z0-9+/=]{100,}|eval[[:space:]]*["'"'"']?\$\((echo|printf|base64)|xxd[[:space:]]+-r[^|]*\|[[:space:]]*(ba)?sh|python[0-9.]*[[:space:]]+-c.*(b64decode|exec\()'
P_MINER='xmrig|minerd|cpuminer|stratum\+(tcp|ssl)://|cryptonight|nicehash|kinsing|kdevtmpfsi|--donate-level'
P_DOWNLOAD='(^|[[:space:];|&(`])(curl|wget)[[:space:]]'
# Execution of something living in a world-writable dir (command position only).
P_TMPRUN='(^|[;&|`(][[:space:]]*|[[:space:]](sh|bash|dash|zsh|python[0-9.]*|perl|php|ruby|exec|nohup|setsid|env|sudo)[[:space:]]+|^@[a-z]+[[:space:]]+|^([^[:space:]#]+[[:space:]]+){5}([a-z_][a-z0-9_.-]*[[:space:]]+)?|Exec[A-Za-z]*=[-@:+!]*)(/tmp|/var/tmp|/dev/shm)/'
P_HIDDENRUN='(^|[[:space:]=;&|])/(home|root|tmp|var|opt|usr/local|etc|dev/shm|srv|mnt)(/[^[:space:]]*)?/\.[A-Za-z0-9_][^/[:space:]]*(/[^[:space:]]*)?([[:space:]]|$)'
SHELLS_RE='^(bash|sh|dash|zsh|ksh|csh|tcsh|fish|busybox|python[0-9.]*|perl|php[0-9.]*|ruby|lua|node|nc|ncat|netcat|socat|telnet|awk|gawk)$'

# _grep_add SEV CAT LABEL REGEX file...  (comment lines ignored)
_grep_add() {
    local sev="$1" cat="$2" what="$3" re="$4"; shift 4
    [ $# -gt 0 ] || return 0
    local hit f rest ln txt
    grep -rnIEsH -e "$re" -- "$@" 2>/dev/null \
        | grep -vE '^[^:]+:[0-9]+:[[:space:]]*(#|;|//|")' \
        | head -n 300 \
        | while IFS= read -r hit; do
            f="${hit%%:*}"; rest="${hit#*:}"; ln="${rest%%:*}"; txt="${rest#*:}"
            s="$sev"
            if [ "$s" = MEDIUM ] && [ "$PKG" != none ] && is_owned "$(disp "$f")"; then s=LOW; fi
            add_finding "$s" "$cat" "$(disp "$f"):$ln" "$what: $(trim "$txt")"
        done
}

# scan_paths CATEGORY [--exec] path...
#   --exec : also flag execution from /tmp & hidden paths (cron/systemd/etc)
scan_paths() {
    local cat="$1"; shift
    local exec=0; [ "${1:-}" = "--exec" ] && { exec=1; shift; }
    local p ex=()
    for p in "$@"; do [ -e "$p" ] && ex+=("$p"); done
    [ ${#ex[@]} -gt 0 ] || return 0
    _grep_add CRITICAL "$cat" "Reverse-shell pattern"       "$P_REVSHELL" "${ex[@]}"
    _grep_add CRITICAL "$cat" "Download-and-execute"        "$P_DLEXEC"   "${ex[@]}"
    _grep_add CRITICAL "$cat" "Crypto-miner indicator"      "$P_MINER"    "${ex[@]}"
    _grep_add HIGH     "$cat" "Encoded/obfuscated command"  "$P_ENCODED"  "${ex[@]}"
    _grep_add MEDIUM   "$cat" "Network download command"    "$P_DOWNLOAD" "${ex[@]}"
    if [ "$exec" -eq 1 ]; then
        _grep_add CRITICAL "$cat" "Executes from world-writable dir" "$P_TMPRUN"    "${ex[@]}"
        _grep_add MEDIUM   "$cat" "Executes file in hidden path"     "$P_HIDDENRUN" "${ex[@]}"
    fi
}

# ============================================================================
# 0. Context
# ============================================================================

section "SYSTEM INFORMATION"
{
    echo "Tool      : linux_persistence_hunter.sh v$VERSION"
    echo "Started   : $STARTED"
    echo "Mode      : $([ "$LIVE" -eq 1 ] && echo live || echo "offline image at $R")"
    echo "Host      : $HOST"
    echo "Run as    : $(id)"
    echo "Pkg DB    : $PKG ($(wc -l < "$OWNED") owned paths)"
    [ "$LIVE" -eq 1 ] && echo "Kernel    : $(uname -a)" && echo "Uptime    : $(uptime 2>/dev/null)"
    echo; cat "$R/etc/os-release" 2>/dev/null
} >> "$EVIDENCE"

if [ "$LIVE" -eq 1 ] && [ "$(id -u)" -ne 0 ]; then
    add_finding INFO COVERAGE "script" "Not running as root: other users' files, /proc entries, shadow and sudoers are unreadable - results are incomplete"
fi
[ "$PKG" = none ] && add_finding INFO COVERAGE "package database" "No dpkg/rpm database found - 'not owned by any package' checks disabled"
[ "$LIVE" -eq 0 ] && add_finding INFO COVERAGE "$R" "Offline mode: process, network and loaded-kernel-module checks skipped"

# ============================================================================
# 1. Dynamic linker hijacking
# ============================================================================

section "DYNAMIC LINKER (LD_PRELOAD) HIJACKING"
if [ -e "$R/etc/ld.so.preload" ]; then
    evidence "/etc/ld.so.preload" cat "$R/etc/ld.so.preload"
    while IFS= read -r lib; do
        lib="$(trim "$lib")"; [ -z "$lib" ] || [ "${lib:0:1}" = "#" ] && continue
        add_finding CRITICAL PRELOAD "/etc/ld.so.preload" "Library force-loaded into every process: $lib$(is_owned "$lib" || echo ' (not owned by any package)')"
    done < "$R/etc/ld.so.preload"
fi
_grep_add HIGH PRELOAD "LD_PRELOAD/LD_LIBRARY_PATH set globally" '^[[:space:]]*(export[[:space:]]+)?LD_(PRELOAD|LIBRARY_PATH|AUDIT)=' \
    "$R/etc/environment" "$R/etc/profile" "$R"/etc/profile.d/* "$R/etc/bash.bashrc" "$R/etc/bashrc"
for f in "$R"/etc/ld.so.conf "$R"/etc/ld.so.conf.d/*; do
    _grep_add HIGH PRELOAD "Library search path in user/world-writable location" '^[[:space:]]*(/tmp|/var/tmp|/dev/shm|/home|/root)' "$f"
done

if [ "$LIVE" -eq 1 ]; then
    for env in /proc/[0-9]*/environ; do
        pid="${env#/proc/}"; pid="${pid%%/*}"
        v="$(tr '\0' '\n' 2>/dev/null < "$env" | grep -E '^LD_(PRELOAD|AUDIT)=' | head -1)"
        [ -n "$v" ] && add_finding HIGH PROCESS "pid $pid ($(cat "/proc/$pid/comm" 2>/dev/null))" "Process runs with $v"
    done
fi

# ============================================================================
# 2. Accounts, sudo
# ============================================================================

section "ACCOUNTS AND PRIVILEGES"
evidence "/etc/passwd" cat "$R/etc/passwd"
evidence "/etc/group (privileged groups)" grep -E '^(root|sudo|wheel|admin|adm|docker|lxd|disk|shadow):' "$R/etc/group"

awk -F: '$3==0 && $1!="root" {print $1}' "$R/etc/passwd" 2>/dev/null | while read -r u; do
    add_finding CRITICAL ACCOUNT "/etc/passwd" "Additional UID 0 (root-equivalent) account: $u"
done
awk -F: '{c[$3]++; n[$3]=n[$3]" "$1} END{for(u in c) if(c[u]>1) print u":"n[u]}' "$R/etc/passwd" 2>/dev/null | while read -r d; do
    add_finding HIGH ACCOUNT "/etc/passwd" "Duplicate UID ${d%%:*} shared by:${d#*:}"
done
awk -F: '$3>0 && $3<1000 && $7!~/(nologin|false|sync|shutdown|halt)$/ && $7!="" {print $1" "$7}' "$R/etc/passwd" 2>/dev/null | while read -r u sh; do
    case "$u" in postgres|git|nx|halt) continue ;; esac
    add_finding MEDIUM ACCOUNT "/etc/passwd" "System account '$u' has interactive shell $sh"
done
awk -F: '$7 ~ /^\/(tmp|var\/tmp|dev\/shm)\// {print $1" "$7}' "$R/etc/passwd" 2>/dev/null | while read -r u sh; do
    add_finding CRITICAL ACCOUNT "/etc/passwd" "Account '$u' uses shell in world-writable dir: $sh"
done
if [ -r "$R/etc/shadow" ]; then
    declare -A UIDOF=()
    while IFS=: read -r u _ uid _; do UIDOF[$u]=$uid; done < "$R/etc/passwd"
    while IFS=: read -r u hash _; do
        uid="${UIDOF[$u]:-}"
        if [ -z "$hash" ]; then
            add_finding HIGH ACCOUNT "/etc/shadow" "Account '$u' has an EMPTY password"
        elif [ "${hash:0:1}" = '$' ] && [ -n "$uid" ] && [ "$uid" -gt 0 ] && [ "$uid" -lt 1000 ]; then
            add_finding HIGH ACCOUNT "/etc/shadow" "System/service account '$u' (uid $uid) has a usable password"
        fi
    done < "$R/etc/shadow"
fi

SUDO_FILES=("$R/etc/sudoers" "$R"/etc/sudoers.d/*)
for f in "${SUDO_FILES[@]}"; do [ -r "$f" ] && evidence "$(disp "$f")" grep -vE '^[[:space:]]*(#|$)' "$f"; done
_grep_add CRITICAL SUDO "Sudo granted to ALL users" '^[[:space:]]*ALL[[:space:]]+ALL[[:space:]]*=' "${SUDO_FILES[@]}"
_grep_add MEDIUM   SUDO "Passwordless sudo" 'NOPASSWD' "${SUDO_FILES[@]}"
_grep_add HIGH     SUDO "Sudo rule runs from world-writable dir" '(/tmp|/var/tmp|/dev/shm)/' "${SUDO_FILES[@]}"
for f in "$R"/etc/sudoers.d/*; do
    is_owned "$(disp "$f")" || add_finding LOW SUDO "$(disp "$f")" "sudoers drop-in not owned by any package (modified $(mtime "$f")) - verify who created it"
done

# ============================================================================
# 3. SSH
# ============================================================================

section "SSH"
for h in "${HOMES[@]}"; do
    for ak in "$h"/.ssh/authorized_keys "$h"/.ssh/authorized_keys2; do
        [ -f "$ak" ] || continue
        evidence "$(disp "$ak")" cat "$ak"
        n=0; ln=0
        while IFS= read -r line; do
            ln=$((ln+1))
            line="$(trim "$line")"; [ -z "$line" ] || [ "${line:0:1}" = "#" ] && continue
            n=$((n+1))
            case "$line" in
                *command=*) add_finding HIGH SSH-KEYS "$(disp "$ak"):$ln" "Key with forced command (backdoor pattern): $(printf '%s' "$line" | grep -oE 'command="[^"]*"' | head -1)" ;;
            esac
            if printf '%s' "$line" | grep -qE "$P_REVSHELL|$P_DLEXEC"; then
                add_finding CRITICAL SSH-KEYS "$(disp "$ak"):$ln" "authorized_keys contains shell/download payload"
            fi
        done < "$ak"
        comments="$(grep -vE '^[[:space:]]*(#|$)' "$ak" 2>/dev/null | awk '{print $NF}' | tr '\n' ' ')"
        owner="$(disp "$h")"
        if [ "$owner" = "/root" ]; then
            add_finding MEDIUM SSH-KEYS "$(disp "$ak")" "root accepts $n key(s): $comments- verify each"
        else
            add_finding INFO SSH-KEYS "$(disp "$ak")" "$n key(s): $comments"
        fi
        case "$ak" in *authorized_keys2) add_finding MEDIUM SSH-KEYS "$(disp "$ak")" "Legacy authorized_keys2 file in use (often overlooked by admins)" ;; esac
        recent "$ak" && add_finding MEDIUM SSH-KEYS "$(disp "$ak")" "Modified within last $DAYS days ($(mtime "$ak"))"
    done
    # shellcheck disable=SC2088  # literal "~/.ssh/rc" is the message text
    [ -f "$h/.ssh/rc" ] && add_finding HIGH SSH-KEYS "$(disp "$h")/.ssh/rc" "~/.ssh/rc executes on every SSH login"
    [ -f "$h/.ssh/rc" ] && scan_paths SSH-KEYS --exec "$h/.ssh/rc"
done
[ -f "$R/etc/ssh/sshrc" ] && add_finding HIGH SSHD-CONFIG "/etc/ssh/sshrc" "Global sshrc executes on every SSH login" && scan_paths SSHD-CONFIG --exec "$R/etc/ssh/sshrc"

SSHD=("$R/etc/ssh/sshd_config" "$R"/etc/ssh/sshd_config.d/*.conf)
for f in "${SSHD[@]}"; do [ -r "$f" ] && evidence "$(disp "$f")" grep -vE '^[[:space:]]*(#|$)' "$f"; done
_grep_add MEDIUM SSHD-CONFIG "Root login with password allowed" '^[[:space:]]*PermitRootLogin[[:space:]]+yes' "${SSHD[@]}"
_grep_add HIGH   SSHD-CONFIG "Empty passwords allowed" '^[[:space:]]*PermitEmptyPasswords[[:space:]]+yes' "${SSHD[@]}"
_grep_add HIGH   SSHD-CONFIG "Non-default AuthorizedKeysFile (hidden key location?)" '^[[:space:]]*AuthorizedKeysFile[[:space:]]+' "${SSHD[@]}"
_grep_add HIGH   SSHD-CONFIG "AuthorizedKeysCommand executes a program on login" '^[[:space:]]*AuthorizedKeysCommand[[:space:]]+' "${SSHD[@]}"
_grep_add MEDIUM SSHD-CONFIG "PermitUserEnvironment enabled (LD_PRELOAD via ~/.ssh/environment)" '^[[:space:]]*PermitUserEnvironment[[:space:]]+yes' "${SSHD[@]}"
# default AuthorizedKeysFile values are fine - drop those hits
sed -i -E '/AuthorizedKeysFile[[:space:]]+\.ssh\/authorized_keys([[:space:]]+\.ssh\/authorized_keys2)?[[:space:]]*$/d' "$FINDINGS_RAW"

# ============================================================================
# 4. systemd
# ============================================================================

section "SYSTEMD"
if [ "$LIVE" -eq 1 ] && command -v systemctl >/dev/null 2>&1; then
    evidence "Enabled unit files" systemctl list-unit-files --state=enabled --no-pager
    evidence "All services" systemctl list-units --type=service --all --no-pager
    evidence "Timers" systemctl list-timers --all --no-pager
    for h in "${HOMES[@]}"; do
        [ -d "$h/.config/systemd/user" ] && evidence "User units in $h" ls -laR "$h/.config/systemd/user"
    done
fi

SYS_ETC_DIRS=("$R/etc/systemd/system" "$R/etc/systemd/user" "$R/run/systemd/system" "$R/usr/local/lib/systemd/system")
SYS_PKG_DIRS=("$R/usr/lib/systemd/system" "$R/lib/systemd/system" "$R/usr/lib/systemd/user")
USER_UNIT_DIRS=()
for h in "${HOMES[@]}"; do USER_UNIT_DIRS+=("$h/.config/systemd/user" "$h/.local/share/systemd/user"); done

scan_paths SYSTEMD --exec "${SYS_ETC_DIRS[@]}" "${SYS_PKG_DIRS[@]}" "${USER_UNIT_DIRS[@]}"

unit_exec() { grep -hE '^[[:space:]]*Exec(Start|StartPre|StartPost|Stop|Reload)=' "$1" 2>/dev/null | head -2 | tr '\n' ' '; }

while IFS= read -r -d '' u; do
    d="${u#"$R"}"; b="${u##*/}"   # same as disp/basename, without a subshell per unit
    case "$b" in .*) add_finding HIGH SYSTEMD "$d" "Hidden unit file name" ;; esac
    is_owned "$d" && continue
    case "$d" in
        /etc/systemd/system/*|/etc/systemd/user/*|/usr/local/*|/run/*) sev=MEDIUM ;;
        *) sev=HIGH ;;  # unowned file inside a package-managed dir
    esac
    case "$b" in snap.*|snap-*) sev=LOW ;; esac
    [ "$PKG" = none ] && continue
    add_finding "$sev" SYSTEMD "$d" "Unit not owned by any package (modified $(mtime "$u")): $(unit_exec "$u")"
done < <(find "${SYS_ETC_DIRS[@]}" "${SYS_PKG_DIRS[@]}" -type f \( -name '*.service' -o -name '*.timer' -o -name '*.socket' -o -name '*.path' \) -print0 2>/dev/null)

while IFS= read -r -d '' u; do
    add_finding MEDIUM SYSTEMD "$(disp "$u")" "Per-user unit (runs at user login/linger): $(unit_exec "$u")"
done < <(find "${USER_UNIT_DIRS[@]}" -type f \( -name '*.service' -o -name '*.timer' \) -print0 2>/dev/null)

for g in "$R"/etc/systemd/system-generators "$R"/usr/local/lib/systemd/system-generators "$R"/etc/systemd/user-generators; do
    for f in "$g"/*; do [ -L "$f" ] && [ "$(readlink "$f")" = /dev/null ] && continue; add_finding HIGH SYSTEMD "$(disp "$f")" "systemd generator (runs at every boot/daemon-reload)"; done
done
for f in "$R"/etc/systemd/system/*.d/*.conf; do
    grep -qE '^[[:space:]]*Exec' "$f" 2>/dev/null && ! is_owned "$(disp "$f")" && \
        add_finding MEDIUM SYSTEMD "$(disp "$f")" "Drop-in overrides Exec of a unit: $(unit_exec "$f")"
done

# ============================================================================
# 5. cron / at / anacron
# ============================================================================

section "CRON / AT"
CRON_FILES=("$R/etc/crontab" "$R/etc/anacrontab" "$R"/etc/cron.d/* "$R"/etc/cron.hourly/* "$R"/etc/cron.daily/* \
            "$R"/etc/cron.weekly/* "$R"/etc/cron.monthly/* "$R"/var/spool/cron/* "$R"/var/spool/cron/crontabs/* \
            "$R"/var/spool/cron/atjobs/* "$R"/var/spool/at/*)
for f in "${CRON_FILES[@]}"; do
    [ -f "$f" ] || continue
    evidence "$(disp "$f")" grep -vE '^[[:space:]]*(#|$)' "$f"
done
scan_paths CRON --exec "${CRON_FILES[@]}"

for f in "$R"/var/spool/cron/* "$R"/var/spool/cron/crontabs/*; do
    [ -f "$f" ] || continue
    n="$(grep -cvE '^[[:space:]]*(#|$)' "$f" 2>/dev/null)"
    [ "${n:-0}" -gt 0 ] && add_finding LOW CRON "$(disp "$f")" "User crontab for '$(basename "$f")' with $n active entr(y/ies) - review"
done
for f in "$R"/var/spool/cron/atjobs/* "$R"/var/spool/at/*; do
    [ -f "$f" ] && add_finding MEDIUM CRON "$(disp "$f")" "Pending 'at' job (rarely used legitimately)"
done
for f in "$R"/etc/cron.d/* "$R"/etc/cron.hourly/* "$R"/etc/cron.daily/* "$R"/etc/cron.weekly/* "$R"/etc/cron.monthly/*; do
    [ -f "$f" ] || continue
    case "$(basename "$f")" in .placeholder) continue ;; .*) add_finding HIGH CRON "$(disp "$f")" "Hidden file in cron directory" ;; esac
    [ "$PKG" != none ] && ! is_owned "$(disp "$f")" && \
        add_finding MEDIUM CRON "$(disp "$f")" "Cron job not owned by any package (modified $(mtime "$f"))"
done
_grep_add LOW CRON "@reboot job" '^[[:space:]]*@reboot' "${CRON_FILES[@]}"

# ============================================================================
# 6. Shell startup files, rc.local, init.d, XDG autostart
# ============================================================================

section "SHELL STARTUP / INIT SCRIPTS"
RC_SYS=("$R/etc/profile" "$R"/etc/profile.d/* "$R/etc/bash.bashrc" "$R/etc/bashrc" "$R/etc/bash.bash_logout" \
        "$R"/etc/zsh/* "$R/etc/zshrc" "$R/etc/zprofile" "$R/etc/zshenv" "$R/etc/environment" "$R"/etc/fish/config.fish)
RC_USER=()
for h in "${HOMES[@]}"; do
    for n in .bashrc .bash_profile .bash_login .bash_logout .profile .zshrc .zshenv .zprofile .zlogin .zlogout \
             .config/fish/config.fish .xprofile .xinitrc .xsession .xsessionrc .pam_environment .ssh/environment; do
        [ -f "$h/$n" ] && RC_USER+=("$h/$n")
    done
done
RC_ALL=("${RC_SYS[@]}" "${RC_USER[@]}")
for f in "${RC_ALL[@]}"; do [ -f "$f" ] && evidence "$(disp "$f")" grep -vE '^[[:space:]]*(#|$)' "$f"; done

scan_paths SHELL-RC --exec "${RC_ALL[@]}"
_grep_add HIGH   SHELL-RC "Alias hijacks credential command" '^[[:space:]]*alias[[:space:]]+(sudo|su|ssh|scp|passwd|doas)=' "${RC_ALL[@]}"
_grep_add HIGH   SHELL-RC "Function overrides credential command" '^[[:space:]]*(function[[:space:]]+)?(sudo|su|ssh|passwd|doas)[[:space:]]*\([[:space:]]*\)' "${RC_ALL[@]}"
_grep_add MEDIUM SHELL-RC "Alias hides forensic tool output" '^[[:space:]]*alias[[:space:]]+(ps|netstat|ss|lsof|top|who|w|last|crontab|systemctl)=' "${RC_ALL[@]}"
_grep_add MEDIUM SHELL-RC "DEBUG trap (runs code before every command)" 'trap[[:space:]].*[[:space:]]DEBUG' "${RC_ALL[@]}"
_grep_add LOW    SHELL-RC "PROMPT_COMMAND set (runs code at every prompt)" '^[[:space:]]*(export[[:space:]]+)?PROMPT_COMMAND=' "${RC_ALL[@]}"
_grep_add MEDIUM HISTORY  "Shell history disabled (anti-forensics)" '(HISTFILE=/dev/null|unset[[:space:]]+HISTFILE|HISTSIZE=0|HISTFILESIZE=0|set[[:space:]]+\+o[[:space:]]+history)' "${RC_ALL[@]}"

for f in "$R/etc/rc.local" "$R/etc/rc.d/rc.local"; do
    [ -f "$f" ] || continue
    evidence "$(disp "$f")" cat "$f"
    if grep -vE '^[[:space:]]*(#|$|exit[[:space:]]+0)' "$f" >/dev/null 2>&1; then
        add_finding MEDIUM INIT "$(disp "$f")" "rc.local contains commands (runs as root at boot): $(grep -vE '^[[:space:]]*(#|$|exit[[:space:]]+0)' "$f" | head -2 | tr '\n' ';')"
    fi
    scan_paths INIT --exec "$f"
done
for f in "$R"/etc/init.d/*; do
    [ -f "$f" ] || continue
    scan_paths INIT --exec "$f"
    [ "$PKG" != none ] && ! is_owned "$(disp "$f")" && add_finding MEDIUM INIT "$(disp "$f")" "SysV init script not owned by any package (modified $(mtime "$f"))"
done

AUTOSTART=("$R"/etc/xdg/autostart/*.desktop)
for h in "${HOMES[@]}"; do AUTOSTART+=("$h"/.config/autostart/*.desktop); done
scan_paths HOOKS --exec "${AUTOSTART[@]}"
for f in "${AUTOSTART[@]}"; do
    d="$(disp "$f")"
    case "$d" in /etc/*) is_owned "$d" && continue; sev=MEDIUM ;; *) sev=LOW ;; esac
    add_finding "$sev" HOOKS "$d" "XDG autostart entry: $(grep -m1 '^Exec=' "$f" 2>/dev/null)"
done

# ============================================================================
# 7. Other execution hooks: udev, APT/DNF, motd, NetworkManager, PAM, python
# ============================================================================

section "SYSTEM HOOKS (udev / package manager / motd / network / PAM / python)"
UDEV=("$R"/etc/udev/rules.d/*.rules "$R"/usr/lib/udev/rules.d/*.rules "$R"/lib/udev/rules.d/*.rules)
_grep_add CRITICAL HOOKS "udev rule runs from world-writable dir" 'RUN\+?=.*(/tmp|/var/tmp|/dev/shm)/' "${UDEV[@]}"
scan_paths HOOKS "${UDEV[@]}"
for f in "$R"/etc/udev/rules.d/*.rules; do
    sev=MEDIUM; case "$(basename "$f")" in 70-snap.*) sev=LOW ;; esac
    grep -qE 'RUN\+?=' "$f" 2>/dev/null && ! is_owned "$(disp "$f")" && \
        add_finding "$sev" HOOKS "$(disp "$f")" "Unowned udev rule with RUN action: $(grep -m1 -oE 'RUN\+?="[^"]*"' "$f")"
done

PKGHOOKS=("$R"/etc/apt/apt.conf.d/* "$R"/etc/dnf/plugins/* "$R"/etc/yum/pluginconf.d/* "$R"/etc/dpkg/dpkg.cfg.d/*)
scan_paths HOOKS --exec "${PKGHOOKS[@]}"
for f in "$R"/etc/apt/apt.conf.d/*; do
    grep -qE '(Pre|Post)-Invoke' "$f" 2>/dev/null && ! is_owned "$(disp "$f")" && \
        add_finding HIGH HOOKS "$(disp "$f")" "Unowned APT hook runs commands on every apt operation"
done

OTHERHOOKS=("$R"/etc/update-motd.d/* "$R"/etc/NetworkManager/dispatcher.d/* "$R"/etc/network/if-*.d/* \
            "$R"/etc/ppp/ip-up.d/* "$R"/etc/X11/Xsession.d/* "$R"/etc/logrotate.d/*)
scan_paths HOOKS --exec "${OTHERHOOKS[@]}"
for f in "$R"/etc/update-motd.d/* "$R"/etc/NetworkManager/dispatcher.d/* "$R"/etc/network/if-up.d/*; do
    [ -f "$f" ] && [ "$PKG" != none ] && ! is_owned "$(disp "$f")" && \
        add_finding MEDIUM HOOKS "$(disp "$f")" "Unowned hook script (runs automatically as root)"
done

# PAM
PAM=("$R"/etc/pam.d/*)
for f in "${PAM[@]}"; do evidence "$(disp "$f")" grep -vE '^[[:space:]]*(#|$)' "$f"; done
_grep_add HIGH PAM "pam_exec runs a program during authentication" '^[^#]*pam_exec\.so' "${PAM[@]}"
_grep_add HIGH PAM "PAM module loaded from absolute non-standard path" '^[^#]*[[:space:]]/(tmp|var/tmp|dev/shm|home|root|opt|usr/local)/[^[:space:]]+\.so' "${PAM[@]}"
_grep_add CRITICAL PAM "pam_permit.so as 'sufficient' auth (accepts any password)" '^[[:space:]]*auth[[:space:]]+sufficient[[:space:]]+pam_permit\.so' "${PAM[@]}"
if [ "$PKG" != none ]; then
    for m in "$R"/lib/security/*.so "$R"/lib64/security/*.so "$R"/usr/lib/security/*.so "$R"/usr/lib64/security/*.so \
             "$R"/lib/*-linux-gnu/security/*.so "$R"/usr/lib/*-linux-gnu/security/*.so; do
        is_owned "$(disp "$m")" || add_finding CRITICAL PAM "$(disp "$m")" "PAM module not owned by any package (modified $(mtime "$m")) - possible credential-stealing backdoor"
    done
fi

# Python .pth auto-exec
while IFS= read -r -d '' f; do
    if grep -qE 'exec\(|eval\(|b64decode|socket|urllib|subprocess|os\.system' "$f" 2>/dev/null && ! { [ "$PKG" != none ] && is_owned "$(disp "$f")"; }; then
        add_finding HIGH PYTHON-PTH "$(disp "$f")" "Python .pth executes code on every interpreter start: $(head -c 150 "$f" | tr '\n' ' ')"
    fi
done < <(find "$R"/usr/lib/python3* "$R"/usr/local/lib/python3* "$R"/usr/lib64/python3* -maxdepth 3 -name '*.pth' -print0 2>/dev/null)

# ============================================================================
# 8. Kernel modules / rootkits
# ============================================================================

section "KERNEL MODULES"
MODCONF=("$R/etc/modules" "$R"/etc/modules-load.d/*.conf "$R"/etc/modprobe.d/*.conf)
for f in "${MODCONF[@]}"; do [ -f "$f" ] && evidence "$(disp "$f")" grep -vE '^[[:space:]]*(#|$)' "$f"; done
grep -HnE '^[[:space:]]*install[[:space:]]+' "$R"/etc/modprobe.d/*.conf 2>/dev/null \
    | grep -vE 'install[[:space:]]+[^[:space:]]+[[:space:]]+(/bin/|/usr/bin/)?(true|false)([[:space:]]|$)|/sbin/modprobe|/usr/sbin/modprobe|/bin/echo|/usr/bin/echo' \
    | while IFS= read -r hit; do
        add_finding HIGH KERNEL "$(disp "${hit%%:*}"):$(echo "$hit" | cut -d: -f2)" "modprobe 'install' directive runs a command: $(trim "$(echo "$hit" | cut -d: -f3-)")"
    done

if [ "$LIVE" -eq 1 ]; then
    evidence "lsmod" cat /proc/modules
    t="$(cat /proc/sys/kernel/tainted 2>/dev/null || echo 0)"
    evidence "kernel taint value" echo "$t"
    for tf in /sys/module/*/taint; do
        v="$(cat "$tf" 2>/dev/null)"; m="$(basename "$(dirname "$tf")")"
        case "$v" in *O*|*E*) add_finding MEDIUM KERNEL "/sys/module/$m" "Out-of-tree (O) / unsigned (E) module loaded: $m [$v] - verify it is expected (e.g. nvidia, vbox, zfs)" ;; esac
    done
    for st in /sys/module/*/initstate; do
        m="$(basename "$(dirname "$st")")"
        grep -q "^$m " /proc/modules 2>/dev/null || add_finding CRITICAL KERNEL "/sys/module/$m" "Module present in sysfs but hidden from /proc/modules (lsmod) - rootkit indicator"
    done
    if command -v modinfo >/dev/null 2>&1; then
        while read -r m _; do
            modinfo -n "$m" >/dev/null 2>&1 || add_finding HIGH KERNEL "/proc/modules" "Loaded module '$m' has no file in /lib/modules (loaded from elsewhere?)"
        done < /proc/modules
    fi
fi

# ============================================================================
# 9. Package integrity (trojanised binaries)
# ============================================================================

if [ "$QUICK" -eq 0 ]; then
    section "PACKAGE INTEGRITY (this can take a few minutes)"
    VERIFY_OUT="$OUTDIR/.verify"
    if [ "$PKG" = dpkg ] && command -v dpkg >/dev/null 2>&1; then
        # Verifying packages in parallel batches is about twice as fast as one
        # "dpkg --verify" and prints the same lines. Capped at 4 jobs so a
        # spinning disk is not thrashed.
        JOBS="$(nproc 2>/dev/null || echo 1)"; [ "$JOBS" -gt 4 ] && JOBS=4
        DPKG_ROOT=(); [ "$LIVE" -eq 0 ] && DPKG_ROOT=(--root="$R")
        dpkg-query "${DPKG_ROOT[@]}" -W -f '${db:Status-Abbrev} ${binary:Package}\n' 2>/dev/null \
            | awk '$1 ~ /^.[^nc]/ { print $2 }' \
            | $TIMEOUT xargs -r -P "$JOBS" -n 16 dpkg "${DPKG_ROOT[@]}" --verify > "$VERIFY_OUT" 2>/dev/null
    elif [ "$PKG" = rpm ]; then
        if [ "$LIVE" -eq 1 ]; then $TIMEOUT rpm -Va --nomtime > "$VERIFY_OUT" 2>/dev/null
        else $TIMEOUT rpm --root "$R" -Va --nomtime > "$VERIFY_OUT" 2>/dev/null; fi
    fi
    if [ -s "${VERIFY_OUT:-/nonexistent}" ]; then
        evidence "Package verification (changed files)" cat "$VERIFY_OUT"
        awk '{ if (substr($1,3,1)=="5" && $2!="c") print $NF }' "$VERIFY_OUT" \
            | grep -E '^/(usr/)?(s?bin|lib(64|32)?|libexec)/|/security/|/sshd$|\.so(\.[0-9]+)*$' \
            | head -100 | while read -r p; do
                add_finding CRITICAL PKG-INTEGRITY "$p" "Binary/library content differs from package checksum (possible trojan)"
            done
    fi
    rm -f "$VERIFY_OUT"
    [ "$PKG" != none ] && add_finding INFO COVERAGE "package database" \
        "Package checksums come from $([ "$LIVE" -eq 1 ] && echo "this host's" || echo "the image's") own package database, which an attacker with root can rewrite - a clean result is not proof; verify against packages from a trusted mirror"
fi

# ============================================================================
# 10. Processes (live only)
# ============================================================================

if [ "$LIVE" -eq 1 ]; then
    section "PROCESSES"
    evidence "ps auxwwf" ps auxwwf
    SELF=$$
    for pd in /proc/[0-9]*; do
        pid="${pd#/proc/}"
        [ "$pid" = "$SELF" ] && continue
        exe="$(readlink "$pd/exe" 2>/dev/null)" || continue      # kernel threads / no permission
        [ -z "$exe" ] && continue
        comm="$(cat "$pd/comm" 2>/dev/null)"
        cmd="$(tr '\0' ' ' 2>/dev/null < "$pd/cmdline")"; cmd="${cmd:0:250}"
        ppid="$(awk '/^PPid:/{print $2}' "$pd/status" 2>/dev/null)"
        who="pid $pid ($comm, ppid $ppid)"

        case "$exe" in
            /memfd:*|*"(deleted)"*memfd*) add_finding CRITICAL PROCESS "$who" "Fileless execution from memfd: $exe | $cmd"; continue ;;
            /tmp/*|/var/tmp/*|/dev/shm/*)  add_finding CRITICAL PROCESS "$who" "Running binary from world-writable dir: $exe | $cmd" ;;
            *" (deleted)")
                case "$exe" in
                    /usr/*|/bin/*|/sbin/*|/lib*|/opt/*|/snap/*) add_finding LOW PROCESS "$who" "Binary deleted on disk (likely upgraded, restart service): $exe" ;;
                    *) add_finding HIGH PROCESS "$who" "Running binary was deleted from disk: $exe | $cmd" ;;
                esac ;;
        esac
        case "$cmd" in
            "["*) add_finding HIGH PROCESS "$who" "Masquerades as kernel thread '$cmd' but runs user binary $exe" ;;
        esac
        [[ $cmd =~ $P_REVSHELL ]] && add_finding CRITICAL PROCESS "$who" "Reverse-shell command line: $cmd"
        [[ $cmd =~ $P_MINER ]]    && add_finding CRITICAL PROCESS "$who" "Crypto-miner command line: $cmd"
        [[ $cmd =~ $P_DLEXEC ]]   && add_finding HIGH PROCESS "$who" "Download-and-execute command line: $cmd"
    done

    # --------------------------------------------------------------------
    section "NETWORK"
    if command -v ss >/dev/null 2>&1; then
        evidence "Listening sockets" ss -lntup
        evidence "Established sockets" ss -ntup
        evidence "Packet (raw) sockets" ss -0 -p
        ss -Hntupa 2>/dev/null | awk '{
                st=$2; loc=$5; peer=$6; proc=$0; sub(/.*users:\(\(/,"",proc);
                split(proc,a,","); name=a[1]; gsub(/"/,"",name); pid=a[2]; sub(/pid=/,"",pid);
                if (name!="") print st"\t"loc"\t"peer"\t"name"\t"pid }' \
        | while IFS=$'\t' read -r st loc peer name pid; do
            if [[ $name =~ $SHELLS_RE ]]; then
                if [ "$st" = "LISTEN" ] || [ "$st" = "UNCONN" ]; then
                    add_finding CRITICAL NETWORK "pid $pid ($name)" "Shell/interpreter LISTENING on $loc (bind shell?)"
                elif [ "$st" = "ESTAB" ]; then
                    case "$peer" in 127.*|"[::1]"*|"::1"*) sev=MEDIUM ;; *) sev=HIGH ;; esac
                    add_finding "$sev" NETWORK "pid $pid ($name)" "Shell/interpreter has live connection $loc -> $peer (reverse shell?)"
                fi
            fi
            if [ "$st" = "LISTEN" ] && [ -n "$pid" ]; then
                exe="$(readlink "/proc/$pid/exe" 2>/dev/null)"
                case "$exe" in
                    /tmp/*|/var/tmp/*|/dev/shm/*|*"(deleted)") add_finding CRITICAL NETWORK "pid $pid ($name)" "Listener $loc served by suspicious binary $exe" ;;
                    "") ;;
                    *) [ "$PKG" != none ] && [ -e "$exe" ] && ! is_owned "$exe" && \
                        add_finding LOW NETWORK "pid $pid ($name)" "Listener $loc from binary not owned by any package: $exe" ;;
                esac
            fi
        done
        # Packet sockets: used by BPF backdoors (e.g. BPFDoor) to sniff "magic" packets
        ss -H -0 -p 2>/dev/null | grep -oE 'users:\(\("[^"]+",pid=[0-9]+' | sed -E 's/users:\(\("([^"]+)",pid=([0-9]+)/\1 \2/' | sort -u \
        | while read -r name pid; do
            case "$name" in dhclient|dhcpcd|NetworkManager|systemd-network*|wpa_supplicant|tcpdump|wireshark|dumpcap|lldpd|keepalived|arping|hostapd|dnsmasq|suricata|zeek|snort|charon|udhcpc|cdpr|ladvd) continue ;; esac
            add_finding HIGH NETWORK "pid $pid ($name)" "Unexpected process holds a raw packet socket (BPF backdoor / sniffer?)"
        done
    fi
fi

# ============================================================================
# 11. SUID / SGID / capabilities
# ============================================================================

section "SUID / SGID / FILE CAPABILITIES"
GTFO='^(bash|sh|dash|zsh|ksh|csh|tcsh|fish|busybox|python[0-9.]*|perl|php[0-9.]*|ruby|lua|node|vim?|vi|nano|less|more|find|awk|gawk|nawk|env|tar|zip|cp|mv|nmap|socat|nc|ncat|tee|dd|xxd|base64|openssl|gdb|strace|ld\.so|ld-linux.*|docker|rsync|git|make|tclsh|expect|screen|tmux|script|journalctl|systemctl|chmod|chown|cat|head|tail)$'
if [ "$QUICK" -eq 1 ]; then
    SUID_SCOPE=("$R/bin" "$R/sbin" "$R/usr" "$R/opt" "$R/tmp" "$R/var/tmp" "$R/dev/shm" "$R/home" "$R/root")
else
    SUID_SCOPE=("$R/")
fi
SUID_FILES=()
while IFS= read -r -d '' f; do
    d="${f#"$R"}"; b="${f##*/}"
    SUID_FILES+=("$f")
    case "$d" in
        /tmp/*|/var/tmp/*|/dev/shm/*|/home/*|/root/*|/run/*)
            add_finding CRITICAL SUID "$d" "SUID/SGID file in user-writable location (owner $(stat -c %U "$f"))" ; continue ;;
    esac
    if [[ $b =~ $GTFO ]]; then
        add_finding CRITICAL SUID "$d" "SUID/SGID on shell/interpreter/GTFOBin '$b' = instant root"
    elif [ "$PKG" != none ] && ! is_owned "$d"; then
        add_finding HIGH SUID "$d" "SUID/SGID file not owned by any package (modified $(mtime "$f"))"
    fi
done < <(find "${SUID_SCOPE[@]}" -xdev -type f \( -perm -4000 -o -perm -2000 \) -print0 2>/dev/null)
# One ls for the whole list instead of one per file
[ ${#SUID_FILES[@]} -gt 0 ] && printf '%s\0' "${SUID_FILES[@]}" | xargs -0 ls -la -- >> "$EVIDENCE" 2>/dev/null

if command -v getcap >/dev/null 2>&1; then
    CAPS_SCOPE=("$R/usr" "$R/bin" "$R/sbin" "$R/opt" "$R/home" "$R/root" "$R/tmp" "$R/var/tmp")
    [ "$QUICK" -eq 0 ] && CAPS_SCOPE=("$R/")
    $TIMEOUT getcap -r "${CAPS_SCOPE[@]}" 2>/dev/null | while IFS= read -r line; do
        echo "$line" >> "$EVIDENCE"
        f="${line%% *}"; caps="${line#* }"; d="$(disp "$f")"; b="$(basename "$f")"
        case "$d" in /proc/*|/sys/*) continue ;; esac
        if [[ $caps =~ cap_(setuid|setgid|sys_admin|dac_override|dac_read_search|sys_ptrace|sys_module|chown|fowner) ]]; then
            if [[ $b =~ $GTFO ]]; then
                add_finding CRITICAL CAPABILITIES "$d" "Dangerous capability on interpreter/GTFOBin: $caps"
            elif [ "$PKG" != none ] && ! is_owned "$d"; then
                add_finding HIGH CAPABILITIES "$d" "Dangerous capability on unowned file: $caps"
            fi
        fi
    done
fi

# ============================================================================
# 12. Staging areas (/tmp, /var/tmp, /dev/shm)
# ============================================================================

section "STAGING AREAS (/tmp /var/tmp /dev/shm)"
while IFS= read -r -d '' f; do
    is_elf "$f" && add_finding HIGH TMP-ARTIFACT "$(disp "$f")" "ELF executable in world-writable dir (size $(stat -c %s "$f"), owner $(stat -c %U "$f"), modified $(mtime "$f"))"
done < <(find "$R/tmp" "$R/var/tmp" "$R/dev/shm" -xdev -type f -size -50M -print0 2>/dev/null)
while IFS= read -r -d '' d; do
    case "$(basename "$d")" in .X11-unix|.ICE-unix|.font-unix|.XIM-unix|.Test-unix|.X*-lock) continue ;; esac
    add_finding MEDIUM TMP-ARTIFACT "$(disp "$d")" "Hidden directory in world-writable location (owner $(stat -c %U "$d"))"
done < <(find "$R/tmp" "$R/var/tmp" "$R/dev/shm" -xdev -mindepth 1 -maxdepth 2 -type d -name '.*' -print0 2>/dev/null)
while IFS= read -r -d '' d; do
    add_finding HIGH TMP-ARTIFACT "$(disp "$d")" "Directory named with spaces/dots only (classic hiding trick)"
done < <(find "$R/tmp" "$R/var/tmp" "$R/dev/shm" "$R/root" "$R/home" -xdev -maxdepth 3 -type d \( -name '...' -o -name '.. ' -o -name ' ' -o -name '. ' \) -print0 2>/dev/null)

# ============================================================================
# 13. Shell history (attacker traces / anti-forensics)
# ============================================================================

section "SHELL HISTORY"
HIST=()
for h in "${HOMES[@]}"; do
    for n in .bash_history .zsh_history .sh_history .ash_history .python_history .mysql_history; do
        f="$h/$n"
        if [ -L "$f" ] && [ "$(readlink "$f")" = "/dev/null" ]; then
            add_finding HIGH HISTORY "$(disp "$f")" "History file symlinked to /dev/null (anti-forensics)"
        elif [ -f "$f" ]; then
            HIST+=("$f")
        fi
    done
done
_grep_add MEDIUM HISTORY "History shows reverse-shell command"   "$P_REVSHELL" "${HIST[@]}"
_grep_add MEDIUM HISTORY "History shows download-and-execute"    "$P_DLEXEC"   "${HIST[@]}"
_grep_add MEDIUM HISTORY "History shows miner"                   "$P_MINER"    "${HIST[@]}"
_grep_add MEDIUM HISTORY "History shows log/history tampering"   '(history[[:space:]]+-c|unset[[:space:]]+HISTFILE|shred[[:space:]].*(log|history)|>[[:space:]]*/var/log/|rm[[:space:]].*/var/log/(wtmp|btmp|lastlog|auth|secure))' "${HIST[@]}"
_grep_add LOW     HISTORY "History shows persistence setup"      '(crontab[[:space:]]+-|systemctl[[:space:]]+enable|authorized_keys|ld\.so\.preload|chmod[[:space:]]+[ugo]*\+?[0-7]*s|useradd|usermod[[:space:]].*-G[[:space:]]*(sudo|wheel))' "${HIST[@]}"

# ============================================================================
# 14. Recent changes & timeline evidence
# ============================================================================

section "RECENTLY MODIFIED PERSISTENCE LOCATIONS (last $DAYS days)"
HOT=("$R/etc/crontab" "$R"/etc/cron.* "$R/var/spool/cron" "$R/etc/systemd/system" "$R/etc/ld.so.preload" \
     "$R/etc/pam.d" "$R/etc/sudoers" "$R/etc/sudoers.d" "$R/etc/passwd" "$R/etc/shadow" "$R/etc/group" \
     "$R/etc/ssh" "$R/etc/rc.local" "$R/etc/init.d" "$R/etc/profile" "$R/etc/profile.d" "$R/etc/bash.bashrc" \
     "$R/etc/udev/rules.d" "$R/etc/apt/apt.conf.d" "$R/etc/update-motd.d" "$R/etc/modprobe.d" "$R/etc/modules-load.d")
for h in "${HOMES[@]}"; do HOT+=("$h/.ssh" "$h/.bashrc" "$h/.profile" "$h/.bash_profile" "$h/.zshrc" "$h/.config/systemd" "$h/.config/autostart"); done
EX=(); for p in "${HOT[@]}"; do [ -e "$p" ] && EX+=("$p"); done
if [ ${#EX[@]} -gt 0 ]; then
    find "${EX[@]}" -type f -mtime "-$DAYS" -not -name 'ssh_host_*' -not -name '*.mount' -printf '%TY-%Tm-%Td %TH:%TM\t%p\n' 2>/dev/null | sort -r | head -60 \
    | while IFS=$'\t' read -r when p; do
        add_finding LOW RECENT-CHANGE "$(disp "$p")" "Modified $when"
    done
fi

# Paths are passed as arguments, never pasted into a shell string, so an
# image path containing quotes cannot break or inject into the command.
# recent_files FIND_AGE_TEST...  (e.g. -mmin -1440)
recent_files() {
    find "$R/etc" "$R/usr/local" "$R/opt" "$R/home" "$R/root" "$R/var" -xdev -type f "$@" \
        -not -path '*/var/log/*' -not -path '*/var/cache/*' -not -path '*/var/lib/docker/*' -not -path '*/.cache/*' \
        -printf '%TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort -r | head -500
}
evidence "Files modified in last 24h (/etc /usr/local /opt /home /root /var excl. logs/caches)" recent_files -mmin -1440
evidence "Files modified in last $DAYS days (same scope)" recent_files -mtime "-$DAYS"
if [ -f "$R/var/log/dpkg.log" ]; then
    dpkg_installs() { grep ' install ' "$R/var/log/dpkg.log" | tail -100; }
    evidence "Recent package installs (dpkg)" dpkg_installs
fi
if [ "$PKG" = rpm ] && [ "$LIVE" -eq 1 ]; then
    rpm_installs() { rpm -qa --last | head -100; }
    evidence "Recent package installs (rpm)" rpm_installs
fi
if [ "$LIVE" -eq 1 ]; then
    last_logins() { last -Faiw 2>/dev/null | head -50; }
    evidence "Last logins" last_logins
    evidence "Currently logged in" who -a
fi

# ============================================================================
# REPORTING
# ============================================================================

progress "Building reports"

# Sort by severity, dedupe (one row per file:line - highest severity wins).
awk -F'\t' 'BEGIN{r["CRITICAL"]=1;r["HIGH"]=2;r["MEDIUM"]=3;r["LOW"]=4;r["INFO"]=5}
            {print r[$1] "\t" $0}' "$FINDINGS_RAW" \
    | sort -t$'\t' -k1,1n -k3,3 -k4,4 \
    | awk -F'\t' '{ key = ($4 ~ /:[0-9]+$/) ? $4 : $3 FS $4 FS $5 } !seen[key]++' \
    | cut -f2- > "$FINDINGS"

count() { awk -F'\t' -v s="$1" '$1==s' "$FINDINGS" | wc -l | tr -d ' '; }
N_CRIT=$(count CRITICAL); N_HIGH=$(count HIGH); N_MED=$(count MEDIUM); N_LOW=$(count LOW); N_INFO=$(count INFO)
TOTAL=$((N_CRIT+N_HIGH+N_MED+N_LOW+N_INFO))

if   [ "$N_CRIT" -gt 0 ]; then VERDICT="LIKELY COMPROMISED - critical indicators present"; VCLASS=crit
elif [ "$N_HIGH" -gt 0 ]; then VERDICT="SUSPICIOUS - high-severity findings need investigation"; VCLASS=high
elif [ "$N_MED"  -gt 0 ]; then VERDICT="REVIEW - no strong indicators, but risky configuration found"; VCLASS=med
else                           VERDICT="CLEAN - no persistence indicators detected"; VCLASS=ok; fi

recommend() {
    case "$1" in
        PRELOAD)       echo "Inspect each preloaded library and compare with package checksums. Remove the /etc/ld.so.preload entry from rescue/live media (preload rootkits hide files and processes on the running system), then reimage." ;;
        ACCOUNT)       echo "Confirm every account with its owner. Lock unknown accounts (usermod -L -e 1 USER), remove extra UID 0 users, set service accounts to /usr/sbin/nologin and lock their passwords (passwd -l)." ;;
        SUDO)          echo "Remove NOPASSWD unless strictly required, keep drop-ins root:root 0440, validate with visudo -c, and investigate who created unexpected sudoers files." ;;
        SSH-KEYS)      echo "Verify every key with its owner; delete unknown keys and command= entries; rotate keys; remove ~/.ssh/rc; consider SSH certificates or a root-owned AuthorizedKeysFile." ;;
        SSHD-CONFIG)   echo "Set PermitRootLogin prohibit-password (or no), PermitEmptyPasswords no, PermitUserEnvironment no, default AuthorizedKeysFile; remove unknown AuthorizedKeysCommand/sshrc; sshd -t && systemctl reload sshd." ;;
        SYSTEMD)       echo "Inspect with 'systemctl cat UNIT'. If malicious: copy unit + binary as evidence, systemctl disable --now UNIT, delete files, systemctl daemon-reload, and find how it was created." ;;
        CRON)          echo "Review with 'crontab -l -u USER' and the listed files; preserve then remove malicious entries; restrict scheduling via /etc/cron.allow and /etc/at.allow." ;;
        SHELL-RC)      echo "Diff against /etc/skel and distro defaults; remove injected lines. Aliases/functions wrapping sudo/ssh harvest passwords - rotate credentials of affected users." ;;
        INIT)          echo "Review rc.local and init.d scripts; disable and remove unknown ones (update-rc.d -f NAME remove / chkconfig --del NAME)." ;;
        HOOKS)         echo "udev/APT/motd/NetworkManager/XDG hooks run automatically as root or at login. Verify ownership (dpkg -S / rpm -qf) and remove unowned malicious hooks." ;;
        PAM)           echo "PAM backdoors capture or bypass passwords. Reinstall PAM packages (apt install --reinstall libpam-modules / dnf reinstall pam), restore /etc/pam.d from defaults, rotate ALL passwords." ;;
        KERNEL)        echo "Hidden or unexplained kernel modules mean the running kernel cannot be trusted: capture memory (AVML/LiME), then reimage. Enable Secure Boot, module signature enforcement and lockdown." ;;
        PKG-INTEGRITY) echo "System binaries differ from package checksums (trojan). Confirm from trusted media (debsums / rpm -Va from live USB) and reimage - do not just reinstall packages in place." ;;
        PROCESS)       echo "Capture first: cp /proc/PID/exe, cmdline, environ, maps, ls -l /proc/PID/fd. Then kill, trace parent and persistence. Deleted binaries under /usr are usually upgrades - restart the service." ;;
        NETWORK)       echo "Identify owner (ss -tunap, lsof -i), block remote IP at the firewall, capture traffic (tcpdump) if still active. Shells/interpreters with sockets are strong reverse/bind-shell indicators." ;;
        SUID)          echo "Remove the SUID/SGID bit (chmod u-s,g-s FILE) from unexpected files and copies of shells/interpreters; mount /tmp, /var/tmp, /dev/shm, /home with nosuid." ;;
        CAPABILITIES)  echo "Remove unexpected capabilities (setcap -r FILE). cap_setuid/cap_sys_admin on an interpreter is equivalent to a root backdoor." ;;
        TMP-ARTIFACT)  echo "Hash (sha256sum) and preserve, check against threat intel (VirusTotal), then delete. Mount /tmp, /var/tmp, /dev/shm with noexec,nosuid,nodev." ;;
        HISTORY)       echo "Build a timeline around the listed commands; correlate with auth logs (journalctl -u ssh, /var/log/auth.log or secure) and last/lastb. Disabled history indicates an attacker covering tracks." ;;
        PYTHON-PTH)    echo ".pth files run on every Python start. Remove code-executing .pth files not shipped by a known package and check who wrote them." ;;
        RECENT-CHANGE) echo "Correlate modification times with logins and package logs; any change not explained by admin activity or updates should be reviewed." ;;
        COVERAGE)      echo "Re-run as root on the live host (or with the package database available) for full coverage. A clean package check only means files match the local checksum database; for certainty compare against packages from a trusted mirror or rescue media." ;;
        *)             echo "Review manually." ;;
    esac
}

# ----------------------------------------------------------------------------
# CSV
# ----------------------------------------------------------------------------
{
    echo 'severity,category,location,detail,recommendation'
    while IFS=$'\t' read -r s c l d; do
        rec="$(recommend "$c")"
        printf '"%s","%s","%s","%s","%s"\n' "$s" "$c" "${l//\"/\"\"}" "${d//\"/\"\"}" "${rec//\"/\"\"}"
    done < "$FINDINGS"
} > "$CSV"

# ----------------------------------------------------------------------------
# Category rollup (category, count, highest severity) used by MD/HTML
# ----------------------------------------------------------------------------
ROLLUP="$(awk -F'\t' 'BEGIN{r["CRITICAL"]=1;r["HIGH"]=2;r["MEDIUM"]=3;r["LOW"]=4;r["INFO"]=5}
    { n[$2]++; if (!($2 in best) || r[$1]<r[best[$2]]) best[$2]=$1 }
    END { for (c in n) print r[best[c]] "\t" best[c] "\t" c "\t" n[c] }' "$FINDINGS" | sort -t$'\t' -k1,1n -k4,4nr | cut -f2-)"

NEXT_STEPS=(
"If any CRITICAL finding is confirmed: isolate the host from the network (keep it powered on), capture memory (AVML/LiME) and a disk image BEFORE cleaning."
"Assume credentials on this host are stolen: rotate passwords, SSH keys, API tokens and cloud credentials that were present or used here."
"Prefer rebuilding from a known-good image over in-place cleaning when rootkit, PAM, preload or package-integrity findings exist."
"Find the initial access vector (auth logs, web server logs, exposed services) or the attacker will return."
"Add auditd watches on persistence paths (e.g. -w /etc/cron.d -p wa, -w /etc/systemd/system -p wa, -w /etc/ld.so.preload -p wa, -w /root/.ssh -p wa) and ship logs off-host."
"Deploy file integrity monitoring (AIDE / Wazuh / osquery) and re-run this script periodically; diff findings.csv between runs."
"Harden: mount /tmp,/var/tmp,/dev/shm noexec,nosuid,nodev; SSH keys only with PermitRootLogin no; minimal sudo; automatic security updates."
)

# ----------------------------------------------------------------------------
# Markdown
# ----------------------------------------------------------------------------
md_esc() { local s="$1"; s="${s//|/\\|}"; s="${s//\`/\'}"; printf '%s' "$s"; }
{
    echo "# Linux Persistence Hunt - \`$HOST\`"
    echo
    echo "| | |"; echo "|---|---|"
    echo "| **Verdict** | **$VERDICT** |"
    echo "| Scan started | $STARTED |"
    echo "| Mode | $([ "$LIVE" -eq 1 ] && echo live || echo "offline image \`$R\`") |"
    echo "| Run as | \`$(id -un 2>/dev/null)\` (uid $(id -u)) |"
    echo "| Findings | CRITICAL **$N_CRIT** · HIGH **$N_HIGH** · MEDIUM **$N_MED** · LOW **$N_LOW** · INFO **$N_INFO** |"
    echo
    echo "## Most critical findings"
    echo
    if [ "$((N_CRIT+N_HIGH))" -eq 0 ]; then
        echo "_No CRITICAL or HIGH findings._"
    else
        echo "| # | Severity | Category | Location | Finding |"
        echo "|---|---|---|---|---|"
        i=0
        awk -F'\t' '$1=="CRITICAL"||$1=="HIGH"' "$FINDINGS" | head -n "$TOP" | while IFS=$'\t' read -r s c l d; do
            i=$((i+1)); echo "| $i | **$s** | $c | \`$(md_esc "$l")\` | $(md_esc "$d") |"
        done
    fi
    echo
    echo "## Remediation plan (by category)"
    echo
    echo "| Category | Worst | Count | Proposed fix |"
    echo "|---|---|---|---|"
    printf '%s\n' "$ROLLUP" | while IFS=$'\t' read -r s c n; do
        [ -n "$c" ] && echo "| $c | $s | $n | $(md_esc "$(recommend "$c")") |"
    done
    echo
    echo "## Next steps"
    echo
    for s in "${NEXT_STEPS[@]}"; do echo "1. $s"; done
    echo
    echo "## All findings"
    echo
    echo "| Severity | Category | Location | Finding |"
    echo "|---|---|---|---|"
    while IFS=$'\t' read -r s c l d; do echo "| $s | $c | \`$(md_esc "$l")\` | $(md_esc "$d") |"; done < "$FINDINGS"
    echo
    echo "_Raw evidence: \`evidence.log\` · machine-readable: \`findings.csv\`_"
} > "$MD"

# ----------------------------------------------------------------------------
# HTML
# ----------------------------------------------------------------------------
h() { local s="$1"; s="${s//&/&amp;}"; s="${s//</&lt;}"; s="${s//>/&gt;}"; s="${s//\"/&quot;}"; printf '%s' "$s"; }
row() { # sev cat loc det [n]
    local s="$1" c="$2" l="$3" d="$4" n="${5:-}"
    printf '<tr class="r-%s">' "$(echo "$s" | tr 'A-Z' 'a-z')"
    [ -n "$n" ] && printf '<td class="n">%s</td>' "$n"
    printf '<td><span class="b %s">%s</span></td><td>%s</td><td><code>%s</code></td><td>%s</td></tr>\n' \
        "$(echo "$s" | tr 'A-Z' 'a-z')" "$s" "$(h "$c")" "$(h "$l")" "$(h "$d")"
}
{
cat <<'CSS'
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<style>
:root{--bg:#f6f7f9;--card:#fff;--fg:#1d2330;--mut:#667085;--line:#e4e7ec;
--crit:#b42318;--high:#d9480f;--med:#b8860b;--low:#1570a6;--info:#667085;--ok:#067647}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){color-scheme:dark;--bg:#0f1115;--card:#171a21;--fg:#e6e8ec;--mut:#98a2b3;--line:#2a2f3a;
--crit:#f97066;--high:#fb923c;--med:#facc15;--low:#60a5fa;--info:#98a2b3;--ok:#4ade80}}
:root[data-theme="dark"]{color-scheme:dark;--bg:#0f1115;--card:#171a21;--fg:#e6e8ec;--mut:#98a2b3;--line:#2a2f3a;
--crit:#f97066;--high:#fb923c;--med:#facc15;--low:#60a5fa;--info:#98a2b3;--ok:#4ade80}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
.wrap{max-width:1200px;margin:auto;padding:24px 16px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:32px 0 10px}.mut{color:var(--mut)}
.verdict{margin:16px 0;padding:14px 16px;border-radius:10px;border-left:6px solid;background:var(--card);font-weight:600}
.verdict.crit{border-color:var(--crit)}.verdict.high{border-color:var(--high)}.verdict.med{border-color:var(--med)}.verdict.ok{border-color:var(--ok)}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px}
.card .v{font-size:26px;font-weight:700}.card.crit .v{color:var(--crit)}.card.high .v{color:var(--high)}
.card.medium .v{color:var(--med)}.card.low .v{color:var(--low)}.card.info .v{color:var(--info)}
.tw{overflow-x:auto;background:var(--card);border:1px solid var(--line);border-radius:10px}
table{border-collapse:collapse;width:100%}th,td{padding:8px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
th{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--mut);background:var(--card);position:sticky;top:0}
tr:last-child td{border-bottom:0}td.n{color:var(--mut);width:32px}
code{font:12px ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-all}
.b{display:inline-block;padding:1px 8px;border-radius:99px;font-size:11px;font-weight:700;color:#fff}
.b.critical{background:var(--crit)}.b.high{background:var(--high)}.b.medium{background:var(--med);color:#111}.b.low{background:var(--low)}.b.info{background:var(--info)}
tr.r-critical td:first-child,tr.r-critical td.n{box-shadow:inset 3px 0 var(--crit)}
ol li{margin:6px 0}
details summary{cursor:pointer;font-weight:600;margin:24px 0 10px}
</style>
CSS
echo "<title>Persistence Hunt $(h "$HOST")</title></head><body><div class=\"wrap\">"
echo "<h1>Linux Persistence Hunt &mdash; $(h "$HOST")</h1>"
echo "<div class=\"mut\">$(h "$STARTED") &middot; $([ "$LIVE" -eq 1 ] && echo "live system" || h "offline image $R") &middot; run as $(h "$(id -un 2>/dev/null)") &middot; v$VERSION</div>"
echo "<div class=\"verdict $VCLASS\">$(h "$VERDICT")</div>"
echo "<div class=\"cards\">"
for pair in "crit:CRITICAL:$N_CRIT" "high:HIGH:$N_HIGH" "medium:MEDIUM:$N_MED" "low:LOW:$N_LOW" "info:INFO:$N_INFO"; do
    IFS=: read -r cls lbl v <<< "$pair"
    echo "<div class=\"card $cls\"><div class=\"mut\">$lbl</div><div class=\"v\">$v</div></div>"
done
echo "</div>"

echo "<h2>Most critical findings</h2>"
if [ "$((N_CRIT+N_HIGH))" -eq 0 ]; then
    echo "<p class=\"mut\">No CRITICAL or HIGH findings.</p>"
else
    echo "<div class=\"tw\"><table><thead><tr><th>#</th><th>Severity</th><th>Category</th><th>Location</th><th>Finding</th></tr></thead><tbody>"
    i=0
    while IFS=$'\t' read -r s c l d; do i=$((i+1)); row "$s" "$c" "$l" "$d" "$i"; done \
        < <(awk -F'\t' '$1=="CRITICAL"||$1=="HIGH"' "$FINDINGS" | head -n "$TOP")
    echo "</tbody></table></div>"
fi

echo "<h2>Remediation plan</h2>"
echo "<div class=\"tw\"><table><thead><tr><th>Category</th><th>Worst</th><th>Count</th><th>Proposed fix</th></tr></thead><tbody>"
printf '%s\n' "$ROLLUP" | while IFS=$'\t' read -r s c n; do
    [ -z "$c" ] && continue
    echo "<tr><td><b>$(h "$c")</b></td><td><span class=\"b $(echo "$s" | tr 'A-Z' 'a-z')\">$s</span></td><td>$n</td><td>$(h "$(recommend "$c")")</td></tr>"
done
echo "</tbody></table></div>"

echo "<h2>Next steps</h2><ol>"
for s in "${NEXT_STEPS[@]}"; do echo "<li>$(h "$s")</li>"; done
echo "</ol>"

echo "<details open><summary>All findings ($TOTAL)</summary>"
echo "<div class=\"tw\"><table><thead><tr><th>Severity</th><th>Category</th><th>Location</th><th>Finding</th></tr></thead><tbody>"
while IFS=$'\t' read -r s c l d; do row "$s" "$c" "$l" "$d"; done < "$FINDINGS"
echo "</tbody></table></div></details>"
echo "<p class=\"mut\">Raw evidence: <code>evidence.log</code> &middot; machine-readable: <code>findings.csv</code></p>"
echo "</div></body></html>"
} > "$HTML"

# ----------------------------------------------------------------------------
# Terminal summary
# ----------------------------------------------------------------------------
sevcol() { case "$1" in CRITICAL) printf '%s' "$C_CRIT";; HIGH) printf '%s' "$C_HIGH";; MEDIUM) printf '%s' "$C_MED";; LOW) printf '%s' "$C_LOW";; *) printf '%s' "$C_INFO";; esac; }
cut_to() { local s="$1" n="$2"; [ "${#s}" -gt "$n" ] && s="${s:0:$((n-1))}…"; printf '%s' "$s"; }

COLS="$(tput cols 2>/dev/null || echo 140)"; [ "$COLS" -lt 100 ] && COLS=100
W_LOC=38; W_DET=$((COLS - 4 - 10 - 15 - W_LOC - 8)); [ "$W_DET" -lt 30 ] && W_DET=30
LINE="$(printf '%*s' "$COLS" '' | tr ' ' '-')"

echo
echo "${C_BOLD}LINUX PERSISTENCE HUNT - $HOST${C_RST}"
echo "$LINE"
case "$VCLASS" in crit) vc="$C_CRIT";; high) vc="$C_HIGH";; med) vc="$C_MED";; *) vc="$C_OK";; esac
echo "Verdict  : ${vc} $VERDICT ${C_RST}"
printf 'Findings : %sCRITICAL %s%s  %sHIGH %s%s  %sMEDIUM %s%s  %sLOW %s%s  INFO %s\n' \
    "$C_CRIT" "$N_CRIT" "$C_RST" "$C_HIGH" "$N_HIGH" "$C_RST" "$C_MED" "$N_MED" "$C_RST" "$C_LOW" "$N_LOW" "$C_RST" "$N_INFO"
echo "$LINE"
printf "${C_BOLD}%-3s %-9s %-14s %-${W_LOC}s %s${C_RST}\n" "#" "SEVERITY" "CATEGORY" "LOCATION" "FINDING"
echo "$LINE"
if [ "$TOTAL" -eq 0 ]; then
    echo "${C_OK}No findings.${C_RST}"
else
    i=0
    awk -F'\t' '$1!="INFO"' "$FINDINGS" | head -n "$TOP" | while IFS=$'\t' read -r s c l d; do
        i=$((i+1))
        printf "%-3s %s%-9s%s %-14s %-${W_LOC}s %s\n" "$i" "$(sevcol "$s")" "$s" "$C_RST" "$c" \
            "$(cut_to "$l" "$W_LOC")" "$(cut_to "$d" "$W_DET")"
    done
    shown=$(awk -F'\t' '$1!="INFO"' "$FINDINGS" | head -n "$TOP" | wc -l)
    rest=$(( TOTAL - N_INFO - shown ))
    [ "$rest" -gt 0 ] && echo "${C_DIM}... $rest more in the report${C_RST}"
fi
echo "$LINE"
if [ -n "$ROLLUP" ]; then
    echo "${C_BOLD}TOP FIXES${C_RST}"
    printf '%s\n' "$ROLLUP" | awk -F'\t' '$1=="CRITICAL"||$1=="HIGH"' | head -6 | while IFS=$'\t' read -r s c n; do
        printf ' %s%-8s%s %-14s %s\n' "$(sevcol "$s")" "$s" "$C_RST" "$c" "$(cut_to "$(recommend "$c")" $((COLS-26)))"
    done
    echo "$LINE"
fi
echo "HTML report : $HTML"
echo "Markdown    : $MD"
echo "CSV         : $CSV"
echo "Evidence    : $EVIDENCE"
echo

# Exit code for automation: 2 = critical, 1 = high, 0 = otherwise
[ "$N_CRIT" -gt 0 ] && exit 2
[ "$N_HIGH" -gt 0 ] && exit 1
exit 0

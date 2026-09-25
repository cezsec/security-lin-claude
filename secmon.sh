#!/usr/bin/env bash

# ╔════════════════════════════════════════════════════════════════════════════╗
# ║                                                                            ║
# ║   secmon - Security Audit, Enumeration & Intrusion Detection               ║
# ║   Enterprise Edition v3.0                                                  ║
# ║                                                                            ║
# ║   Audits host configuration (packages, kernel, network, services, users,   ║
# ║   hardening, file permissions, processes) and analyzes system logs for     ║
# ║   failed logins, intrusion attempts, privilege escalation and persistence. ║
# ║   Writes text, JSON and self-contained HTML reports.                       ║
# ║                                                                            ║
# ║   © 2024 Cezary Kos. All rights reserved.                                  ║
# ║                                                                            ║
# ╚════════════════════════════════════════════════════════════════════════════╝

set -Eeuo pipefail
IFS=$'\n\t'
umask 077
export LC_ALL=C
# Keep "&" literal in ${var//pattern/replacement} (bash 5.2+), used for HTML escaping
shopt -u patsub_replacement 2>/dev/null || true

# ┌────────────────────────────────────────────────────────────────────────────┐
# │ Script Metadata                                                            │
# └────────────────────────────────────────────────────────────────────────────┘

readonly SCRIPT_VERSION="3.0.0"
readonly SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
readonly TAB=$'\t'
readonly US=$'\x1f'   # internal list separator

# ┌────────────────────────────────────────────────────────────────────────────┐
# │ Configuration (defaults < config file < command line)                      │
# └────────────────────────────────────────────────────────────────────────────┘

# Time window
HOURS=24
SINCE=""

# Output
TOP_N=20
VERBOSE=0
QUIET=0
JSON_OUTPUT=0
NAGIOS_MODE=0
COLOR_MODE="auto"
RESOLVE_DNS=1
DNS_TIMEOUT=2
SECTIONS="all"

# Watch mode
WATCH_MODE=0
WATCH_INTERVAL=60

# Detection thresholds
ALERT_THRESHOLD=50                 # SSH failures per IP => brute force
SUCCESS_AFTER_FAIL_THRESHOLD=10    # failures before a successful login => possible compromise
SPRAY_USER_THRESHOLD=10            # distinct usernames per IP => password spraying
DISTRIBUTED_IP_THRESHOLD=100       # distinct attacking IPs => distributed attack
SCAN_PORT_THRESHOLD=20             # distinct blocked ports per IP => port scan
WEB_IP_THRESHOLD=20                # malicious web requests per IP => flag IP

# Alerting
NOTIFY_LEVEL=3                     # 1=LOW 2=MEDIUM 3=HIGH 4=CRITICAL
EMAIL_ALERT=""
WEBHOOK_URL=""
SYSLOG_ALERT=0

# Allowlist (IPs or IPv4 CIDRs that are never flagged)
WHITELIST=""
WHITELIST_FILE=""

# Reports
REPORT_DIR="${SCRIPT_DIR}/logs"
REPORT_RETENTION_DAYS=30

# Log sources (empty = auto-detect)
USE_JOURNAL="auto"                 # auto | yes | no
AUTH_LOG=""
SYSLOG_FILE=""
KERN_LOG=""
FAIL2BAN_LOG=""
UFW_LOG=""
WEB_LOGS="/var/log/apache2/access.log /var/log/nginx/access.log /var/log/httpd/access_log"

# Host audit
HTML_REPORT=1                      # write the self-contained HTML report
NET_SAMPLE_SECONDS=3               # interface traffic sampling period, 0 = off
FS_SCAN=1                          # scan local file systems (world-writable, SUID, unowned)
FS_SCAN_TIMEOUT=180                # seconds before the file system scan gives up
DEEP_SCAN=0                        # rkhunter/chkrootkit/lynis + full package verification
ONLINE=0                           # allow network access (apt-get update, rkhunter --update)
INSTALL_TOOLS=0                    # install missing rkhunter/chkrootkit/lynis (needs ONLINE)

readonly DEFAULT_CONFIG="/etc/secmon.conf"
readonly CONFIG_KEYS=" HOURS TOP_N VERBOSE RESOLVE_DNS DNS_TIMEOUT SECTIONS WATCH_INTERVAL
    ALERT_THRESHOLD SUCCESS_AFTER_FAIL_THRESHOLD SPRAY_USER_THRESHOLD DISTRIBUTED_IP_THRESHOLD
    SCAN_PORT_THRESHOLD WEB_IP_THRESHOLD NOTIFY_LEVEL EMAIL_ALERT WEBHOOK_URL SYSLOG_ALERT
    WHITELIST WHITELIST_FILE REPORT_DIR REPORT_RETENTION_DAYS USE_JOURNAL AUTH_LOG SYSLOG_FILE
    KERN_LOG FAIL2BAN_LOG UFW_LOG WEB_LOGS HTML_REPORT NET_SAMPLE_SECONDS FS_SCAN FS_SCAN_TIMEOUT
    DEEP_SCAN ONLINE "
readonly AUDIT_SECTIONS="system packages modules network services users hardening filesystem processes"
readonly LOG_SECTIONS="ssh bruteforce fail2ban firewall privesc accounts web persistence kernel"
readonly ALL_SECTIONS="$AUDIT_SECTIONS $LOG_SECTIONS rootkit"

# ┌────────────────────────────────────────────────────────────────────────────┐
# │ Runtime State                                                              │
# └────────────────────────────────────────────────────────────────────────────┘

readonly TIMESTAMP="$(date +%F_%H-%M-%S)"
HOSTNAME_SHORT="$(hostname -s 2>/dev/null || echo "${HOSTNAME%%.*}")"
HOSTNAME_SHORT="${HOSTNAME_SHORT//[^A-Za-z0-9._-]/_}"
HOSTNAME_FQDN="$(hostname -f 2>/dev/null || hostname 2>/dev/null || echo "$HOSTNAME")"
readonly HOSTNAME_SHORT HOSTNAME_FQDN

IS_ROOT=0
WORKDIR=""
REPORT_BASE=""
REPORT_TXT=""
REPORT_JSON=""
REPORT_BLOCKLIST=""
REPORT_HTML=""
PROGRESS=0
REAL_OUT=1
TEE_PID=""
CUTOFF_EPOCH=0
COLLECTED_COUNT=0
UNREADABLE_COUNT=0
CUTOFF_KEY=""
CUR_YEAR=0
CUR_MON=0
WINDOW_LABEL=""
FW_KIND=""
FW_ACTIVE=0
F2B_STATE=""
SYS_OS=""
SYS_KERNEL="$(uname -r 2>/dev/null || echo unknown)"
SYS_UPTIME=""
UU_STATE=""                        # unattended-upgrades state, set by the packages section

ALERT_LEVEL=0  # 0=OK, 1=LOW, 2=MEDIUM, 3=HIGH, 4=CRITICAL
readonly LEVEL_NAMES=(OK LOW MEDIUM HIGH CRITICAL)

TOTAL_FAILED_LOGINS=0
TOTAL_BLOCKED_IPS=0
TOTAL_FIREWALL_BLOCKS=0
TOTAL_SUSPICIOUS=0

declare -a F_LEVEL=() F_CAT=() F_MSG=()     # findings
declare -a RECOMMENDATIONS=() WARNINGS=() SECTIONS_RUN=() STAT_ORDER=() WHITELIST_ENTRIES=()
declare -A STATS=() SUSP_IPS=() SOURCE_DESC=() SOURCE_OK=() SOURCE_READY=() WL_CACHE=()

# Per-section records for the HTML and JSON reports
SECTION_CUR=""                     # section being run
SUB_CUR=""                         # current subheader
TBL_SEQ=0                          # tables created so far
TBL_CUR=""                         # table being filled by tbl_row
TBL_OPENED=""                      # table most recently registered
TBL_REC_FILE="" TBL_REC_KEY="" TBL_REC_SEQ=-1
declare -a F_SEC=()                # section of each finding
declare -a N_SEC=() N_MSG=()       # informational notes
declare -a T_SEC=() T_KIND=() T_FILE=()   # tables: section, kind (kv|table), TSV file
declare -A SEC_TITLE=() SEC_LEVEL=() SEC_NFIND=() SEC_STATUS=() SEC_MS=() STAT_SEC=()

# ┌────────────────────────────────────────────────────────────────────────────┐
# │ Terminal Colors & Symbols                                                  │
# └────────────────────────────────────────────────────────────────────────────┘

setup_colors() {
    local enable="$1"
    if [[ "$enable" -eq 1 ]]; then
        C_RESET='\033[0m'
        C_BOLD='\033[1m'
        C_DIM='\033[2m'
        C_RED='\033[38;5;196m'
        C_GREEN='\033[38;5;82m'
        C_YELLOW='\033[38;5;220m'
        C_BLUE='\033[38;5;39m'
        C_MAGENTA='\033[38;5;213m'
        C_CYAN='\033[38;5;51m'
        C_WHITE='\033[38;5;255m'
        C_GREY='\033[38;5;245m'
        C_ORANGE='\033[38;5;208m'

        SYM_CHECK="✓"
        SYM_CROSS="✗"
        SYM_WARN="⚠"
        SYM_INFO="ℹ"
        SYM_ARROW="→"
        SYM_BULLET="•"
        SYM_STAR="★"
        SYM_SKULL="☠"
        SYM_SHIELD="🛡"
        SYM_ALERT="🚨"
        SYM_EYE="👁"
        SYM_GEAR="⚙"
    else
        C_RESET='' C_BOLD='' C_DIM=''
        C_RED='' C_GREEN='' C_YELLOW='' C_BLUE='' C_MAGENTA=''
        C_CYAN='' C_WHITE='' C_GREY='' C_ORANGE=''
        SYM_CHECK="[OK]" SYM_CROSS="[X]" SYM_WARN="[!]" SYM_INFO="[i]"
        SYM_ARROW="->" SYM_BULLET="*" SYM_STAR="*" SYM_SKULL="[!]"
        SYM_SHIELD="[S]" SYM_ALERT="[A]" SYM_EYE="[E]" SYM_GEAR="[G]"
    fi
}

setup_colors 0

# ┌────────────────────────────────────────────────────────────────────────────┐
# │ Shared AWK Library                                                         │
# └────────────────────────────────────────────────────────────────────────────┘

# ts_key(line) normalizes a log timestamp to "YYYY-MM-DDTHH:MM:SS" (local time)
# so it can be compared as a string. Supported formats:
#   RFC 3339 / ISO 8601  2026-09-22T10:15:30.123+02:00   (rsyslog, journald short-iso)
#   fail2ban             2026-09-22 10:15:30,123
#   classic syslog       Sep 22 10:15:30                 (year inferred)
#   Apache/nginx         [22/Sep/2026:10:15:30 +0000]
AWK_TS_LIB=$(cat <<'AWK'
function mon_num(m,    i) {
    i = index("JanFebMarAprMayJunJulAugSepOctNovDec", m)
    return (i && (i % 3) == 1) ? (i + 2) / 3 : 0
}
function ts_key(line,    a, m, y, s) {
    if (line ~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9][T ][0-9][0-9]:[0-9][0-9]:[0-9][0-9]/)
        return substr(line, 1, 10) "T" substr(line, 12, 8)
    if (line ~ /^[A-Z][a-z][a-z] +[0-9]+ [0-9][0-9]:[0-9][0-9]:[0-9][0-9]/) {
        split(line, a, " ")
        m = mon_num(a[1]); if (!m) return ""
        y = CUR_YEAR; if (m > CUR_MON) y = y - 1
        return sprintf("%04d-%02d-%02dT%s", y, m, a[2], substr(a[3], 1, 8))
    }
    if (match(line, /\[[0-9][0-9]\/[A-Z][a-z][a-z]\/[0-9][0-9][0-9][0-9]:[0-9][0-9]:[0-9][0-9]:[0-9][0-9]/)) {
        s = substr(line, RSTART + 1, 20)
        m = mon_num(substr(s, 4, 3)); if (!m) return ""
        return sprintf("%s-%02d-%sT%s", substr(s, 8, 4), m, substr(s, 1, 2), substr(s, 13, 8))
    }
    return ""
}
function clean(s) { gsub(/[^ -~]/, "?", s); return s }
AWK
)
readonly AWK_TS_LIB

# ┌────────────────────────────────────────────────────────────────────────────┐
# │ Error Handling                                                             │
# └────────────────────────────────────────────────────────────────────────────┘

cleanup() {
    local exit_code=$?
    if [[ -n "$WORKDIR" && -d "$WORKDIR" ]]; then
        rm -rf -- "$WORKDIR"
    fi
    exit "$exit_code"
}

err_trap() {
    local exit_code=$?
    local line_no="$1"
    local cmd="$2"

    # A failing command in a $(...) or <(...) subshell only ends that subshell;
    # the caller decides whether the failure matters
    if [[ "$BASH_SUBSHELL" -gt 0 ]]; then
        exit "$exit_code"
    fi

    if [[ "$NAGIOS_MODE" -eq 1 ]]; then
        printf 'SECMON UNKNOWN - internal error at line %s (exit %s)\n' "$line_no" "$exit_code" >&"$REAL_OUT"
        exit 3
    fi

    {
        echo
        printf '%b┌─ ERROR ──────────────────────────────────────────────────────────────────┐%b\n' "${C_RED}${C_BOLD}" "$C_RESET"
        printf '%b│%b  Script failed at line %s with exit code %s\n' "${C_RED}${C_BOLD}" "$C_WHITE" "$line_no" "$exit_code"
        printf '%b│%b  Command: %s\n' "${C_RED}${C_BOLD}" "$C_WHITE" "$cmd"
        printf '%b└──────────────────────────────────────────────────────────────────────────┘%b\n' "${C_RED}${C_BOLD}" "$C_RESET"
    } >&2

    exit "$exit_code"
}

trap 'err_trap "$LINENO" "$BASH_COMMAND"' ERR
trap cleanup EXIT

warn() {
    local w
    for w in "${WARNINGS[@]}"; do
        [[ "$w" == "$*" ]] && return 0
    done
    WARNINGS+=("$*")
    printf '%b%s warning:%b %s\n' "$C_YELLOW" "$SCRIPT_NAME" "$C_RESET" "$*" >&2
}

die() {
    local code="$1"; shift
    if [[ "$NAGIOS_MODE" -eq 1 ]]; then
        printf 'SECMON UNKNOWN - %s\n' "$*" >&"$REAL_OUT"
        exit 3
    fi
    printf '%b%s error:%b %s\n' "$C_RED" "$SCRIPT_NAME" "$C_RESET" "$*" >&2
    exit "$code"
}

# ┌────────────────────────────────────────────────────────────────────────────┐
# │ Output Functions                                                           │
# └────────────────────────────────────────────────────────────────────────────┘

print_header() {
    local title="$1"
    local icon="${2:-$SYM_INFO}"

    if [[ -n "$SECTION_CUR" ]]; then
        SEC_TITLE[$SECTION_CUR]="$title"
    fi
    SUB_CUR=""
    TBL_REC_SEQ=-1

    echo
    printf '%b╭──────────────────────────────────────────────────────────────────────────╮%b\n' \
        "${C_BLUE}${C_BOLD}" "$C_RESET"
    printf '%b│%b  %s  %b%-66s%b %b│%b\n' \
        "${C_BLUE}${C_BOLD}" "$C_RESET" \
        "$icon" \
        "${C_WHITE}${C_BOLD}" "$title" "$C_RESET" \
        "${C_BLUE}${C_BOLD}" "$C_RESET"
    printf '%b╰──────────────────────────────────────────────────────────────────────────╯%b\n' \
        "${C_BLUE}${C_BOLD}" "$C_RESET"
}

print_subheader() {
    local title="$1"
    SUB_CUR="$title"
    TBL_REC_SEQ=-1
    echo
    printf '  %b%s %s%b\n' "${C_CYAN}${C_BOLD}" "$SYM_ARROW" "$title" "$C_RESET"
    printf '  %b%s%b\n' "${C_GREY}" "$(printf '─%.0s' {1..70})" "$C_RESET"
}

print_stat() {
    local label="$1"
    local value="$2"
    local color="${3:-$C_WHITE}"

    printf '  %b%-35s%b %b%s%b\n' "$C_GREY" "$label:" "$C_RESET" "$color" "$value" "$C_RESET"
    rec_row kv "Item|Value" "$label" "$value"
}

print_line() {
    printf '    %s\n' "$1"
}

print_none() {
    printf '    %b(none)%b\n' "$C_GREY" "$C_RESET"
}

# print_alert <level 0-4> <message>
print_alert() {
    local level="$1"
    local message="$2"

    local color icon
    case "$level" in
        4) color="${C_RED}${C_BOLD}"; icon="$SYM_SKULL" ;;
        3) color="${C_RED}"; icon="$SYM_ALERT" ;;
        2) color="${C_ORANGE}"; icon="$SYM_WARN" ;;
        1) color="${C_YELLOW}"; icon="$SYM_INFO" ;;
        *) color="${C_GREY}"; icon="$SYM_BULLET" ;;
    esac

    printf '  %b%s %s%b\n' "$color" "$icon" "$message" "$C_RESET"
    if [[ "$level" -eq 0 && -n "$SECTION_CUR" ]]; then
        N_SEC+=("$SECTION_CUR")
        N_MSG+=("$message")
    fi
}

print_ip_entry() {
    local ip="$1"
    local count="$2"
    local extra="${3:-attempts}"

    local color="$C_WHITE"
    if [[ "$count" -ge 100 ]]; then
        color="${C_RED}${C_BOLD}"
    elif [[ "$count" -ge 50 ]]; then
        color="${C_RED}"
    elif [[ "$count" -ge 20 ]]; then
        color="${C_ORANGE}"
    elif [[ "$count" -ge 10 ]]; then
        color="${C_YELLOW}"
    fi

    if is_whitelisted "$ip"; then
        extra="$extra (allowlisted)"
    fi

    printf '    %b%-39s%b %b%7d%b  %s\n' "$C_CYAN" "$ip" "$C_RESET" "$color" "$count" "$C_RESET" "$extra"
    rec_row table "IP|Count|Details" "$ip" "$count" "$extra"
}

# ┌────────────────────────────────────────────────────────────────────────────┐
# │ Findings, Statistics & Helpers                                             │
# └────────────────────────────────────────────────────────────────────────────┘

# add_finding <level 1-4> <category> <message>
add_finding() {
    local level="$1" category="$2" message="$3"
    F_LEVEL+=("$level")
    F_CAT+=("$category")
    F_MSG+=("$message")
    F_SEC+=("${SECTION_CUR:-general}")
    if [[ "$level" -gt "$ALERT_LEVEL" ]]; then
        ALERT_LEVEL="$level"
    fi
    if [[ -n "$SECTION_CUR" ]]; then
        SEC_NFIND[$SECTION_CUR]=$(( ${SEC_NFIND[$SECTION_CUR]:-0} + 1 ))
        if [[ "$level" -gt "${SEC_LEVEL[$SECTION_CUR]:-0}" ]]; then
            SEC_LEVEL[$SECTION_CUR]="$level"
        fi
    fi
    print_alert "$level" "$message"
}

add_rec() {
    local rec="$1" r
    for r in "${RECOMMENDATIONS[@]}"; do
        if [[ "$r" == "$rec" ]]; then
            return 0
        fi
    done
    RECOMMENDATIONS+=("$rec")
}

stat_set() {
    local key="$1" value="$2"
    [[ "$value" =~ ^[0-9]+$ ]] || value=0
    if [[ -z "${STATS[$key]+x}" ]]; then
        STAT_ORDER+=("$key")
        STAT_SEC[$key]="${SECTION_CUR:-general}"
    fi
    STATS[$key]="$value"
}

# flag_ip <ip> <reason> — adds an IP to the high-risk list unless allowlisted
flag_ip() {
    local ip="$1" reason="$2"
    if [[ -z "$ip" || "$ip" == "-" ]] || is_whitelisted "$ip"; then
        return 0
    fi
    local cur="${SUSP_IPS[$ip]:-}"
    case "${US}${cur}${US}" in
        *"${US}${reason}${US}"*) return 0 ;;
    esac
    SUSP_IPS[$ip]="${cur:+${cur}${US}}${reason}"
}

ip4_to_int() {
    local IFS=. a b c d
    read -r a b c d <<< "$1"
    local o
    for o in "$a" "$b" "$c" "$d"; do
        if ! [[ "$o" =~ ^[0-9]{1,3}$ ]] || [[ "$o" -gt 255 ]]; then
            return 1
        fi
    done
    echo $(( (10#$a << 24) | (10#$b << 16) | (10#$c << 8) | 10#$d ))
}

is_whitelisted() {
    local ip="${1,,}"
    if [[ -n "${WL_CACHE[$ip]:-}" ]]; then
        [[ "${WL_CACHE[$ip]}" == 1 ]]
        return
    fi
    local entry result=0
    for entry in "${WHITELIST_ENTRIES[@]}"; do
        if [[ "$entry" == */* ]]; then
            [[ "$ip" == *:* || "$entry" == *:* ]] && continue
            local net="${entry%/*}" bits="${entry#*/}" ipi neti mask
            ipi=$(ip4_to_int "$ip") || continue
            neti=$(ip4_to_int "$net") || continue
            mask=$(( bits == 0 ? 0 : (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF ))
            if (( (ipi & mask) == (neti & mask) )); then
                result=1
                break
            fi
        elif [[ "$ip" == "$entry" ]]; then
            result=1
            break
        fi
    done
    WL_CACHE[$ip]="$result"
    [[ "$result" == 1 ]]
}

build_whitelist() {
    local raw="$WHITELIST" entry
    if [[ -n "$WHITELIST_FILE" ]]; then
        [[ -r "$WHITELIST_FILE" ]] || die 2 "Allowlist file not readable: $WHITELIST_FILE"
        raw+=$'\n'"$(sed -e 's/#.*//' -- "$WHITELIST_FILE")"
    fi
    while IFS= read -r entry; do
        [[ -z "$entry" ]] && continue
        entry="${entry,,}"
        if [[ "$entry" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/([0-9]|[12][0-9]|3[0-2]))?$ ]] ||
           [[ "$entry" =~ ^[0-9a-f:]+$ && "$entry" == *:* ]]; then
            WHITELIST_ENTRIES+=("$entry")
        else
            warn "Ignoring invalid allowlist entry: $entry"
        fi
    done < <(printf '%s\n' "$raw" | tr ', ' '\n\n')
}

# Count and rank: stdin lines -> "count<TAB>value", highest first
tally() {
    awk '{ c[$0]++ } END { for (k in c) printf "%d\t%s\n", c[k], k }' | sort -t "$TAB" -k1,1nr -k2,2
}

# First N lines without closing the pipe early (avoids SIGPIPE with pipefail)
top_n() {
    awk -v n="${1:-$TOP_N}" 'NR <= n'
}

count_re() {
    local re="$1" file="$2" n
    n=$(grep -cE -e "$re" -- "$file" 2>/dev/null) || true
    echo "${n:-0}"
}

sanitize() {
    printf '%s' "${1//[^[:print:]]/?}"
}

json_str() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    s="${s//[$'\001'-$'\037']/}"
    printf '"%s"' "$s"
}

first_existing() {
    local f
    for f in "$@"; do
        if [[ -n "$f" && -e "$f" ]]; then
            printf '%s' "$f"
            return 0
        fi
    done
    return 1
}

journal_ok() {
    [[ "$USE_JOURNAL" != "no" ]] && command -v journalctl >/dev/null 2>&1
}

geoip_lookup() {
    local ip="$1" tool="geoiplookup" out
    [[ "$ip" == *:* ]] && tool="geoiplookup6"
    if command -v "$tool" >/dev/null 2>&1; then
        out=$(timeout 3 "$tool" "$ip" 2>/dev/null | awk -F': ' 'NR == 1 { print $2 }') || true
        printf '%s' "${out:-Unknown}"
    else
        printf 'N/A'
    fi
}

reverse_dns() {
    local ip="$1" out
    if [[ "$RESOLVE_DNS" -ne 1 ]]; then
        printf 'not resolved (--no-dns)'
        return 0
    fi
    out=$(timeout "$DNS_TIMEOUT" getent hosts "$ip" 2>/dev/null | awk 'NR == 1 { print $2 }') || true
    printf '%s' "${out:-N/A}"
}

section_enabled() {
    [[ "$SECTIONS" == "all" ]] && return 0
    [[ ",${SECTIONS}," == *",$1,"* ]]
}

level_from_name() {
    case "${1,,}" in
        1|low) echo 1 ;;
        2|medium) echo 2 ;;
        3|high) echo 3 ;;
        4|critical) echo 4 ;;
        *) return 1 ;;
    esac
}

have() {
    command -v "$1" >/dev/null 2>&1
}

# join <separator> <item>... — prints the items joined by the separator
join() {
    local sep="$1" out="" item
    shift
    for item in "$@"; do
        out+="${out:+$sep}$item"
    done
    printf '%s' "$out"
}

# human_bytes <bytes> — 1536 -> "1.5 KiB"
human_bytes() {
    awk -v b="${1:-0}" 'BEGIN {
        split("B KiB MiB GiB TiB PiB", u, " "); i = 1
        while (b >= 1024 && i < 6) { b /= 1024; i++ }
        fmt = (i == 1) ? "%d %s" : "%.1f %s"; printf fmt, b, u[i] }'
}

fmt_duration() {
    local s="${1:-0}"
    printf '%dd %dh %dm' $((s / 86400)) $((s % 86400 / 3600)) $((s % 3600 / 60))
}

# read_first <file> — prints the first line of a file, or nothing
read_first() {
    local v=""
    if [[ -r "$1" ]]; then
        IFS= read -r v < "$1" || true
    fi
    printf '%s' "$v"
}

# has_opt <comma list> <option> — true if the mount option list contains it
has_opt() {
    [[ ",$1," == *",$2,"* ]]
}

# ┌────────────────────────────────────────────────────────────────────────────┐
# │ Report Tables                                                              │
# └────────────────────────────────────────────────────────────────────────────┘

# tsv_line <field>... — one TSV row; tabs, newlines and control characters in
# fields are neutralized
tsv_line() {
    local f out="" sep=""
    for f in "$@"; do
        f="${f//[$'\t\r\n']/ }"
        f="${f//[^[:print:]]/?}"
        out+="$sep$f"
        sep="$TAB"
    done
    printf '%s\n' "$out"
}

# tbl_open <kind> <title> <column>... — registers a table file for the reports
tbl_open() {
    local kind="$1" title="$2"; shift 2
    TBL_SEQ=$((TBL_SEQ + 1))
    TBL_OPENED="$WORKDIR/tables/$(printf '%04d' "$TBL_SEQ").tsv"
    { tsv_line "$title"; tsv_line "$@"; } > "$TBL_OPENED"
    T_SEC+=("${SECTION_CUR:-general}")
    T_KIND+=("$kind")
    T_FILE+=("$TBL_OPENED")
}

# tbl_new <title> <column>... ; tbl_row <value>... ; tbl_end [console rows]
# The table goes to the console (aligned, truncated) and in full to HTML/JSON.
tbl_new() {
    local title="$1"; shift
    print_subheader "$title"
    tbl_open table "$title" "$@"
    TBL_CUR="$TBL_OPENED"
}

tbl_row() {
    tsv_line "$@" >> "$TBL_CUR"
}

tbl_end() {
    local max="${1:-$TOP_N}" rows
    if [[ "$VERBOSE" -eq 1 ]]; then
        max=1000000
    fi
    rows=$(( $(wc -l < "$TBL_CUR") - 2 ))
    if [[ "$rows" -le 0 ]]; then
        print_none
        return 0
    fi
    awk -F'\t' -v max="$max" -v hc="$C_GREY" -v rc="$C_RESET" '
        NR == 1 { next }
        NR - 2 <= max {
            n++
            for (i = 1; i <= NF; i++) { v[n, i] = $i; if (length($i) > w[i]) w[i] = length($i) }
            if (NF > nf) nf = NF
        }
        END {
            for (i = 1; i <= nf; i++) if (w[i] > 48) w[i] = 48
            for (r = 1; r <= n; r++) {
                line = "    "
                for (i = 1; i <= nf; i++) {
                    s = v[r, i]
                    if (length(s) > w[i]) s = substr(s, 1, w[i] - 1) "~"
                    line = line ((i < nf) ? sprintf("%-" w[i] "s  ", s) : s)
                }
                if (r == 1) printf "%s%s%s\n", hc, line, rc; else print line
            }
        }' "$TBL_CUR"
    if [[ "$rows" -gt "$max" ]]; then
        print_line "... $((rows - max)) more row(s) in the HTML/JSON report"
    fi
}

# rec_row <kind> <columns "A|B"> <value>... — records a row the caller already
# printed. Consecutive rows under one subheader share a table.
rec_row() {
    [[ -n "$SECTION_CUR" && -n "$WORKDIR" ]] || return 0
    local kind="$1" cols="$2"; shift 2
    local key="$SUB_CUR|$kind|$cols"
    if [[ "$TBL_REC_SEQ" -ne "$TBL_SEQ" || "$TBL_REC_KEY" != "$key" ]]; then
        local -a hdr=()
        IFS='|' read -r -a hdr <<< "$cols"
        tbl_open "$kind" "$SUB_CUR" "${hdr[@]}"
        TBL_REC_FILE="$TBL_OPENED"
        TBL_REC_KEY="$key"
        TBL_REC_SEQ="$TBL_SEQ"
    fi
    tsv_line "$@" >> "$TBL_REC_FILE"
}

# ┌────────────────────────────────────────────────────────────────────────────┐
# │ Banner & Usage                                                             │
# └────────────────────────────────────────────────────────────────────────────┘

print_banner() {
    cat <<'BANNER'

    ╔═══════════════════════════════════════════════════════════════════════╗
    ║                                                                       ║
    ║   ███████╗███████╗ ██████╗    ███╗   ███╗ ██████╗ ███╗   ██╗         ║
    ║   ██╔════╝██╔════╝██╔════╝    ████╗ ████║██╔═══██╗████╗  ██║         ║
    ║   ███████╗█████╗  ██║         ██╔████╔██║██║   ██║██╔██╗ ██║         ║
    ║   ╚════██║██╔══╝  ██║         ██║╚██╔╝██║██║   ██║██║╚██╗██║         ║
    ║   ███████║███████╗╚██████╗    ██║ ╚═╝ ██║╚██████╔╝██║ ╚████║         ║
    ║   ╚══════╝╚══════╝ ╚═════╝    ╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═══╝         ║
    ║                                                                       ║
    ║            Security Audit & Intrusion Detection                       ║
    ║                                                                       ║
    ║                   © 2024 Cezary Kos. All rights reserved.             ║
    ║                                                                       ║
    ╚═══════════════════════════════════════════════════════════════════════╝

BANNER

    printf '    %b%s Version:%b   %s\n' "${C_GREY}" "$SYM_INFO" "$C_RESET" "$SCRIPT_VERSION"
    printf '    %b%s Date:%b      %s\n' "${C_GREY}" "$SYM_INFO" "$C_RESET" "$(date '+%Y-%m-%d %H:%M:%S %Z')"
    printf '    %b%s Host:%b      %s\n' "${C_GREY}" "$SYM_INFO" "$C_RESET" "$HOSTNAME_FQDN"
    if [[ "$WATCH_MODE" -eq 0 ]]; then
        printf '    %b%s Timeframe:%b %s\n' "${C_GREY}" "$SYM_INFO" "$C_RESET" "$WINDOW_LABEL"
        printf '    %b%s Report:%b    %s\n' "${C_GREY}" "$SYM_INFO" "$C_RESET" "$REPORT_TXT"
    fi
    if [[ "$IS_ROOT" -eq 0 ]]; then
        printf '    %b%s Privileges:%b not root - results may be incomplete\n' "${C_YELLOW}" "$SYM_WARN" "$C_RESET"
    fi
    echo
}

usage() {
    echo
    printf '%bUSAGE%b\n' "${C_BOLD}" "${C_RESET}"
    echo "    sudo $SCRIPT_NAME [OPTIONS]"
    echo
    printf '%bDESCRIPTION%b\n' "${C_BOLD}" "${C_RESET}"
    echo "    Audits and enumerates the host (OS, packages and updates, kernel modules,"
    echo "    network sockets and traffic, services, users, hardening, file permissions,"
    echo "    processes) and analyzes system logs for security events: SSH brute force"
    echo "    and password spraying, logins after repeated failures, port scans, web"
    echo "    attacks, privilege escalation, account changes, persistence mechanisms"
    echo "    and kernel security events. Produces text, JSON and HTML reports."
    echo
    echo "    Nothing is sent anywhere unless you configure --email or --webhook, or"
    echo "    allow network access with --online. Reverse DNS lookups of attacking IPs"
    echo "    use the system resolver; disable them with --no-dns."
    echo
    printf '%bOPTIONS%b\n' "${C_BOLD}" "${C_RESET}"
    printf '    %bTime Range:%b\n' "${C_GREEN}" "${C_RESET}"
    echo "      --hours <N>           Analyze last N hours (default: 24)"
    echo "      --since <TIME>        Analyze since TIME (anything 'date -d' accepts)"
    echo "      --today               Analyze since midnight"
    echo "      --week                Analyze last 7 days"
    echo
    printf '    %bOutput:%b\n' "${C_GREEN}" "${C_RESET}"
    echo "      --top <N>             Show top N results (default: 20)"
    echo "      --sections <LIST>     Comma-separated checks to run (default: all)"
    echo "                            audit: ${AUDIT_SECTIONS// /,}"
    echo "                            logs:  ${LOG_SECTIONS// /,}"
    echo "                            deep:  rootkit"
    echo "                            'audit' and 'logs' select a whole group"
    echo "      --verbose, -v         Show detailed output"
    echo "      --quiet, -q           Print only the summary (full report still saved)"
    echo "      --json                Print the JSON report to stdout"
    echo "      --nagios              Nagios/Icinga plugin output and exit codes"
    echo "      --no-color            Disable colors"
    echo "      --no-dns              Skip reverse DNS lookups"
    echo "      --no-html             Do not write the HTML report"
    echo
    printf '    %bHost Audit:%b\n' "${C_GREEN}" "${C_RESET}"
    echo "      --deep                Run rkhunter, chkrootkit and lynis if installed, and"
    echo "                            verify all package files (slow)"
    echo "      --online              Allow network access: apt-get update, rkhunter --update"
    echo "      --install-tools       With --online: install missing rkhunter/chkrootkit/lynis"
    echo "      --net-sample <sec>    Traffic sampling period for interface rates"
    echo "                            (default: 3, 0 = off)"
    echo "      --no-fs-scan          Skip the file system scan (world-writable, SUID, ...)"
    echo "      --quick               Same as --no-fs-scan --net-sample 0 --no-dns"
    echo
    printf '    %bMonitoring:%b\n' "${C_GREEN}" "${C_RESET}"
    echo "      --watch               Real-time monitoring (follows logs, survives rotation)"
    echo "      --interval <sec>      Watch-mode status interval in seconds (default: 60)"
    echo
    printf '    %bDetection:%b\n' "${C_GREEN}" "${C_RESET}"
    echo "      --threshold <N>       SSH failures per IP to flag brute force (default: 50)"
    echo "      --whitelist <LIST>    Comma-separated IPs/IPv4 CIDRs never to flag"
    echo
    printf '    %bAlerting:%b\n' "${C_GREEN}" "${C_RESET}"
    echo "      --email <addr>        Send alert e-mail (requires mail or sendmail)"
    echo "      --webhook <url>       POST alert JSON to a webhook (Slack/Teams/Mattermost)"
    echo "      --syslog              Log every finding to syslog for SIEM ingestion"
    echo "      --notify-level <L>    Minimum level for e-mail/webhook: low|medium|high|critical"
    echo "                            (default: high)"
    echo
    printf '    %bConfiguration:%b\n' "${C_GREEN}" "${C_RESET}"
    echo "      --config <file>       Config file (default: $DEFAULT_CONFIG if present)"
    echo "      --report-dir <dir>    Report directory (default: <script dir>/logs)"
    echo "      --retention <days>    Delete reports older than N days, 0 = keep (default: 30)"
    echo
    printf '    %bInformation:%b\n' "${C_GREEN}" "${C_RESET}"
    echo "      --help, -h            Show this help message"
    echo "      --version             Show version information"
    echo
    printf '%bEXIT CODES%b\n' "${C_BOLD}" "${C_RESET}"
    echo "    0  analysis completed        2  usage error        3  runtime error"
    echo "    With --nagios: 0 OK (threat OK/LOW), 1 WARNING (MEDIUM), 2 CRITICAL (HIGH/"
    echo "    CRITICAL), 3 UNKNOWN."
    echo
    printf '%bEXAMPLES%b\n' "${C_BOLD}" "${C_RESET}"
    printf '    %b# Full audit + last 24 hours of logs, HTML report in ./logs%b\n' "${C_GREY}" "${C_RESET}"
    echo "    sudo $SCRIPT_NAME"
    echo
    printf '    %b# Host audit only, including rootkit scanners%b\n' "${C_GREY}" "${C_RESET}"
    echo "    sudo $SCRIPT_NAME --sections audit,rootkit --deep"
    echo
    printf '    %b# Last 48 hours, top 50 results, SSH checks only%b\n' "${C_GREY}" "${C_RESET}"
    echo "    sudo $SCRIPT_NAME --hours 48 --top 50 --sections ssh,bruteforce"
    echo
    printf '    %b# Hourly cron job: alert on HIGH findings, feed the SIEM%b\n' "${C_GREY}" "${C_RESET}"
    echo "    sudo $SCRIPT_NAME --sections logs --hours 1 --quiet --syslog --email soc@example.com"
    echo
    printf '    %b# Nagios/Icinga check%b\n' "${C_GREY}" "${C_RESET}"
    echo "    sudo $SCRIPT_NAME --nagios --sections logs --hours 1 --no-dns"
    echo
    printf '    %b# Real-time monitoring%b\n' "${C_GREY}" "${C_RESET}"
    echo "    sudo $SCRIPT_NAME --watch --interval 30"
    echo
    printf '%bREQUIRED PRIVILEGES%b\n' "${C_BOLD}" "${C_RESET}"
    echo "    Root is recommended. Without root the script runs, but it skips logs and"
    echo "    checks it cannot read, and it warns about them."
    echo
    printf '%bVERSION%b\n' "${C_BOLD}" "${C_RESET}"
    echo "    $SCRIPT_VERSION"
    echo
}

# ┌────────────────────────────────────────────────────────────────────────────┐
# │ Configuration Loading & Argument Parsing                                   │
# └────────────────────────────────────────────────────────────────────────────┘

# Parses KEY=VALUE lines. The file is never sourced, so it cannot run code, and
# only the keys in CONFIG_KEYS are accepted.
load_config() {
    local file="$1" explicit="$2"

    if [[ ! -e "$file" ]]; then
        if [[ "$explicit" -eq 1 ]]; then
            die 2 "Config file not found: $file"
        fi
        return 0
    fi
    [[ -r "$file" ]] || die 3 "Config file not readable: $file"

    if [[ "$(id -u)" -eq 0 ]]; then
        local owner mode
        IFS=' ' read -r owner mode < <(stat -L -c '%u %a' -- "$file")
        if [[ "$owner" != "0" ]] || (( 8#$mode & 8#022 )); then
            die 3 "Refusing insecure config $file: it must be owned by root and not group/world-writable"
        fi
    fi

    local line key value lineno=0
    while IFS= read -r line || [[ -n "$line" ]]; do
        lineno=$((lineno + 1))
        if [[ "$line" =~ ^[[:space:]]*(#.*)?$ ]]; then
            continue
        fi
        if [[ "$line" =~ ^[[:space:]]*([A-Z][A-Z0-9_]*)[[:space:]]*=[[:space:]]*(.*)$ ]]; then
            key="${BASH_REMATCH[1]}"
            value="${BASH_REMATCH[2]}"
            value="${value%"${value##*[![:space:]]}"}"
            if [[ "$value" =~ ^\"(.*)\"$ ]] || [[ "$value" =~ ^\'(.*)\'$ ]]; then
                value="${BASH_REMATCH[1]}"
            fi
            if [[ "$CONFIG_KEYS" == *[[:space:]]"$key"[[:space:]]* ]]; then
                printf -v "$key" '%s' "$value"
            else
                warn "$file:$lineno: unknown key '$key' ignored"
            fi
        else
            warn "$file:$lineno: cannot parse line, ignored"
        fi
    done < "$file"
}

# --config must be applied before the other options so the command line wins
preload_config() {
    local config="" explicit=0
    while [[ $# -gt 0 ]]; do
        if [[ "$1" == "--config" ]]; then
            [[ $# -ge 2 ]] || die 2 "Option --config requires a value"
            config="$2"
            explicit=1
            shift
        fi
        shift
    done
    load_config "${config:-$DEFAULT_CONFIG}" "$explicit"
}

need_value() {
    if [[ -z "${2:-}" || "$2" == --* ]]; then
        die 2 "Option $1 requires a value"
    fi
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --hours)        need_value "$1" "${2:-}"; HOURS="$2"; SINCE=""; shift ;;
            --since)        need_value "$1" "${2:-}"; SINCE="$2"; shift ;;
            --today)        SINCE="today 00:00" ;;
            --week)         HOURS=168; SINCE="" ;;
            --top)          need_value "$1" "${2:-}"; TOP_N="$2"; shift ;;
            --sections)     need_value "$1" "${2:-}"; SECTIONS="$2"; shift ;;
            --verbose|-v)   VERBOSE=1 ;;
            --quiet|-q)     QUIET=1 ;;
            --json)         JSON_OUTPUT=1 ;;
            --nagios)       NAGIOS_MODE=1 ;;
            --no-color)     COLOR_MODE="never" ;;
            --no-dns)       RESOLVE_DNS=0 ;;
            --no-html)      HTML_REPORT=0 ;;
            --deep)         DEEP_SCAN=1 ;;
            --online)       ONLINE=1 ;;
            --install-tools) INSTALL_TOOLS=1 ;;
            --net-sample)   need_value "$1" "${2:-}"; NET_SAMPLE_SECONDS="$2"; shift ;;
            --no-fs-scan)   FS_SCAN=0 ;;
            --quick)        FS_SCAN=0; NET_SAMPLE_SECONDS=0; RESOLVE_DNS=0 ;;
            --watch)        WATCH_MODE=1 ;;
            --interval)     need_value "$1" "${2:-}"; WATCH_INTERVAL="$2"; shift ;;
            --threshold)    need_value "$1" "${2:-}"; ALERT_THRESHOLD="$2"; shift ;;
            --whitelist)    need_value "$1" "${2:-}"; WHITELIST="${WHITELIST:+$WHITELIST,}$2"; shift ;;
            --email)        need_value "$1" "${2:-}"; EMAIL_ALERT="$2"; shift ;;
            --webhook)      need_value "$1" "${2:-}"; WEBHOOK_URL="$2"; shift ;;
            --syslog)       SYSLOG_ALERT=1 ;;
            --notify-level) need_value "$1" "${2:-}"; NOTIFY_LEVEL="$2"; shift ;;
            --config)       shift ;;   # already applied by preload_config
            --report-dir)   need_value "$1" "${2:-}"; REPORT_DIR="$2"; shift ;;
            --retention)    need_value "$1" "${2:-}"; REPORT_RETENTION_DAYS="$2"; shift ;;
            --version)
                echo "$SCRIPT_NAME version $SCRIPT_VERSION"
                exit 0
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            -*)
                die 2 "Unknown option: $1 (see --help)"
                ;;
            *)
                die 2 "Unexpected argument: $1 (see --help)"
                ;;
        esac
        shift
    done
}

validate_settings() {
    local var
    for var in HOURS TOP_N WATCH_INTERVAL ALERT_THRESHOLD SUCCESS_AFTER_FAIL_THRESHOLD \
               SPRAY_USER_THRESHOLD DISTRIBUTED_IP_THRESHOLD SCAN_PORT_THRESHOLD \
               WEB_IP_THRESHOLD DNS_TIMEOUT REPORT_RETENTION_DAYS NET_SAMPLE_SECONDS FS_SCAN_TIMEOUT; do
        if ! [[ "${!var}" =~ ^[0-9]+$ ]]; then
            die 2 "$var must be a non-negative integer (got '${!var}')"
        fi
    done
    for var in HOURS TOP_N WATCH_INTERVAL ALERT_THRESHOLD; do
        if [[ "${!var}" -eq 0 ]]; then
            die 2 "$var must be greater than zero"
        fi
    done
    if [[ "$NET_SAMPLE_SECONDS" -gt 60 ]]; then
        die 2 "NET_SAMPLE_SECONDS must be 60 or less"
    fi
    for var in VERBOSE RESOLVE_DNS SYSLOG_ALERT HTML_REPORT FS_SCAN DEEP_SCAN ONLINE; do
        case "${!var,,}" in
            1|yes|true|on)  printf -v "$var" '1' ;;
            0|no|false|off) printf -v "$var" '0' ;;
            *) die 2 "$var must be yes or no (got '${!var}')" ;;
        esac
    done

    NOTIFY_LEVEL=$(level_from_name "$NOTIFY_LEVEL") || die 2 "Invalid notify level (use low, medium, high or critical)"

    case "$USE_JOURNAL" in
        auto|yes|no) ;;
        *) die 2 "USE_JOURNAL must be auto, yes or no" ;;
    esac

    if [[ "$SECTIONS" != "all" ]]; then
        local s expanded=""
        SECTIONS="${SECTIONS// /}"
        while IFS= read -r s; do
            [[ -z "$s" ]] && continue
            case "$s" in
                audit) expanded+=",${AUDIT_SECTIONS// /,}" ;;
                logs)  expanded+=",${LOG_SECTIONS// /,}" ;;
                *)
                    if [[ " $ALL_SECTIONS " != *" $s "* ]]; then
                        die 2 "Unknown section '$s'. Valid: audit,logs,${ALL_SECTIONS// /,}"
                    fi
                    expanded+=",$s"
                    ;;
            esac
        done < <(tr ',' '\n' <<< "$SECTIONS")
        SECTIONS="${expanded#,}"
        # Naming the rootkit section explicitly asks for the deep scan
        if [[ ",$SECTIONS," == *",rootkit,"* ]]; then
            DEEP_SCAN=1
        fi
    fi
    if [[ "$INSTALL_TOOLS" -eq 1 && "$ONLINE" -eq 0 ]]; then
        die 2 "--install-tools needs --online (it downloads packages)"
    fi

    if [[ -n "$EMAIL_ALERT" && ! "$EMAIL_ALERT" =~ ^[A-Za-z0-9._%+=-]+@[A-Za-z0-9.-]+$ ]]; then
        die 2 "Invalid e-mail address: $EMAIL_ALERT"
    fi
    if [[ -n "$WEBHOOK_URL" && ! "$WEBHOOK_URL" =~ ^https?://[^[:space:]]+$ ]]; then
        die 2 "Webhook URL must start with http:// or https://"
    fi
    if [[ "$WATCH_MODE" -eq 1 && ( "$JSON_OUTPUT" -eq 1 || "$NAGIOS_MODE" -eq 1 ) ]]; then
        die 2 "--watch cannot be combined with --json or --nagios"
    fi
    if [[ "$JSON_OUTPUT" -eq 1 && "$NAGIOS_MODE" -eq 1 ]]; then
        die 2 "--json and --nagios are mutually exclusive"
    fi
}

compute_window() {
    local now
    now=$(date +%s)
    if [[ -n "$SINCE" ]]; then
        CUTOFF_EPOCH=$(date -d "$SINCE" +%s 2>/dev/null) || die 2 "Cannot parse --since value: $SINCE"
        if [[ "$CUTOFF_EPOCH" -gt "$now" ]]; then
            die 2 "--since is in the future: $SINCE"
        fi
        HOURS=$(( (now - CUTOFF_EPOCH + 3599) / 3600 ))
        [[ "$HOURS" -ge 1 ]] || HOURS=1
    else
        CUTOFF_EPOCH=$(( now - HOURS * 3600 ))
    fi
    CUTOFF_KEY=$(date -d "@$CUTOFF_EPOCH" '+%Y-%m-%dT%H:%M:%S')
    CUR_YEAR=$(date +%Y)
    CUR_MON=$(date +%-m)
    WINDOW_LABEL="since $(date -d "@$CUTOFF_EPOCH" '+%Y-%m-%d %H:%M:%S') (~${HOURS}h)"
}

check_privileges() {
    if [[ "$(id -u)" -eq 0 ]]; then
        IS_ROOT=1
    else
        IS_ROOT=0
        warn "Not running as root: unreadable logs and root-only checks will be skipped. Use sudo for a complete report."
    fi
}

acquire_lock() {
    local name="$1" dir="/run/lock"
    [[ -d "$dir" && -w "$dir" ]] || dir="$REPORT_DIR"
    if ! command -v flock >/dev/null 2>&1; then
        warn "flock not available; concurrent runs are not prevented"
        return 0
    fi
    local lock_file="$dir/$name.lock"
    # A lock file left by a root run is not writable for other users
    if [[ -e "$lock_file" && ! -w "$lock_file" ]]; then
        lock_file="$REPORT_DIR/$name.lock"
    fi
    exec 9>"$lock_file" || die 3 "Cannot open lock file $lock_file"
    flock -n 9 || die 3 "Another $name instance is already running (lock: $lock_file)"
}

# ┌────────────────────────────────────────────────────────────────────────────┐
# │ Log Collection                                                             │
# └────────────────────────────────────────────────────────────────────────────┘

# Keeps only lines inside the analysis window. Lines without a timestamp (for
# example continuation lines) follow the decision made for the previous line.
window_filter() {
    awk -v CUTOFF="$CUTOFF_KEY" -v CUR_YEAR="$CUR_YEAR" -v CUR_MON="$CUR_MON" \
        "$AWK_TS_LIB"'
        { k = ts_key($0); if (k != "") keep = (k >= CUTOFF) }
        keep'
}

# collect_files <dest> <base path>... — reads each log plus its rotations
# (.1, .2.gz, -20260920, ...) that were modified inside the window, oldest first.
collect_files() {
    local dest="$1"; shift
    local base dir name f
    local -a files=()
    UNREADABLE_COUNT=0

    for base in "$@"; do
        [[ -n "$base" ]] || continue
        dir="${base%/*}"
        name="${base##*/}"
        [[ -d "$dir" ]] || continue
        while IFS= read -r f; do
            if [[ -r "$f" ]]; then
                files+=("$f")
            else
                UNREADABLE_COUNT=$((UNREADABLE_COUNT + 1))
                warn "Cannot read $f (insufficient privileges)"
            fi
        done < <(find "$dir" -maxdepth 1 -type f \
                    \( -name "$name" -o -name "$name.[0-9]*" -o -name "$name-[0-9]*" \) \
                    -newermt "@$CUTOFF_EPOCH" -printf '%T@\t%p\n' 2>/dev/null |
                 sort -n | cut -f2-)
    done

    COLLECTED_COUNT=${#files[@]}
    if [[ ${#files[@]} -eq 0 ]]; then
        : > "$dest"
        return 0
    fi

    for f in "${files[@]}"; do
        case "$f" in
            *.gz)  gzip -dc -- "$f" 2>/dev/null || echo "secmon: failed to decompress $f" >&2 ;;
            *.xz)  xz -dc -- "$f" 2>/dev/null || echo "secmon: failed to decompress $f" >&2 ;;
            *.zst) zstd -dcq -- "$f" 2>/dev/null || echo "secmon: failed to decompress $f" >&2 ;;
            *)     cat -- "$f" ;;
        esac
    done | window_filter > "$dest"
}

collect_journal() {
    local dest="$1"; shift
    journalctl --no-pager -q -o short-iso --since "@$CUTOFF_EPOCH" "$@" 2>/dev/null | window_filter > "$dest" || true
}

# resolve_source <name> <dest> <configured path> <candidates> <journal args...>
resolve_source() {
    local name="$1" dest="$2" configured="$3" candidates="$4"; shift 4
    local file=""

    if [[ -n "$configured" && ! -e "$configured" ]]; then
        warn "Configured $name log not found: $configured"
    fi

    if [[ "$USE_JOURNAL" != "yes" ]]; then
        # shellcheck disable=SC2086
        file=$(IFS=' '; first_existing "$configured" $candidates) || true
    fi

    if [[ -n "$file" ]]; then
        collect_files "$dest" "$file"
        SOURCE_DESC[$name]="file: $file ($COLLECTED_COUNT file(s) in window)"
        SOURCE_OK[$name]=1
        # The log exists but could not be read: results would be falsely empty
        if [[ "$COLLECTED_COUNT" -eq 0 && "$UNREADABLE_COUNT" -gt 0 ]]; then
            if [[ $# -gt 0 ]] && journal_ok; then
                collect_journal "$dest" "$@"
                SOURCE_DESC[$name]="journald (partial: $file is unreadable without root)"
                warn "Reading the journal without root may miss system entries"
            else
                SOURCE_DESC[$name]="unreadable: $file (needs root)"
                SOURCE_OK[$name]=0
            fi
        fi
    elif [[ $# -gt 0 ]] && journal_ok; then
        collect_journal "$dest" "$@"
        SOURCE_DESC[$name]="journald"
        SOURCE_OK[$name]=1
        if [[ "$IS_ROOT" -eq 0 ]]; then
            warn "Reading the journal without root may miss system entries"
        fi
    else
        : > "$dest"
        SOURCE_DESC[$name]="unavailable"
        SOURCE_OK[$name]=0
    fi
}

# ensure_source <name> — collects a source once into $WORKDIR/<name>.log
ensure_source() {
    local name="$1"
    [[ -n "${SOURCE_READY[$name]:-}" ]] && return 0
    local dest="$WORKDIR/$name.log"

    case "$name" in
        auth)
            resolve_source auth "$dest" "$AUTH_LOG" "/var/log/auth.log /var/log/secure" \
                SYSLOG_FACILITY=4 SYSLOG_FACILITY=10
            ;;
        syslog)
            resolve_source syslog "$dest" "$SYSLOG_FILE" "/var/log/syslog /var/log/messages" --
            ;;
        kern)
            resolve_source kern "$dest" "$KERN_LOG" "/var/log/kern.log" -k
            if [[ "${SOURCE_OK[kern]}" -eq 0 ]]; then
                ensure_source syslog
                cp -- "$WORKDIR/syslog.log" "$dest"
                SOURCE_DESC[kern]="${SOURCE_DESC[syslog]} (syslog fallback)"
                SOURCE_OK[kern]="${SOURCE_OK[syslog]}"
            fi
            ;;
        fw)
            resolve_source fw "$dest" "$UFW_LOG" "/var/log/ufw.log"
            if [[ "${SOURCE_OK[fw]}" -eq 0 ]]; then
                ensure_source kern
                cp -- "$WORKDIR/kern.log" "$dest"
                SOURCE_DESC[fw]="${SOURCE_DESC[kern]} (kernel log)"
                SOURCE_OK[fw]="${SOURCE_OK[kern]}"
            fi
            ;;
        f2b)
            resolve_source f2b "$dest" "$FAIL2BAN_LOG" "/var/log/fail2ban.log" -u fail2ban.service
            ;;
        web)
            local -a logs=() existing=()
            local l
            IFS=', ' read -r -a logs <<< "$WEB_LOGS"
            for l in "${logs[@]}"; do
                [[ -n "$l" && -e "$l" ]] && existing+=("$l")
            done
            if [[ ${#existing[@]} -gt 0 ]]; then
                collect_files "$dest" "${existing[@]}"
                SOURCE_DESC[web]="file: ${existing[*]} ($COLLECTED_COUNT file(s) in window)"
                SOURCE_OK[web]=1
            else
                : > "$dest"
                SOURCE_DESC[web]="unavailable"
                SOURCE_OK[web]=0
            fi
            ;;
    esac
    SOURCE_READY[$name]=1
}

source_log() {
    printf '%s/%s.log' "$WORKDIR" "$1"
}

# ┌────────────────────────────────────────────────────────────────────────────┐
# │ Event Extraction                                                           │
# └────────────────────────────────────────────────────────────────────────────┘

# ssh.events:  type <TAB> ip <TAB> user <TAB> method <TAB> timestamp
#   type = FAIL | FAIL_INV | INVALID | ACCEPT | MAXAUTH | PREAUTH
# ssh.ips:     ip <TAB> failure score <TAB> accepted <TAB> distinct users <TAB> first <TAB> last
prepare_ssh() {
    [[ -f "$WORKDIR/ssh.events" ]] && return 0
    ensure_source auth
    [[ "${SOURCE_OK[auth]}" -eq 1 ]] || return 1

    awk -v CUR_YEAR="$CUR_YEAR" -v CUR_MON="$CUR_MON" "$AWK_TS_LIB"'
        function ipof(s) {
            if (match(s, / from [0-9a-fA-F:.]+ port /)) return substr(s, RSTART + 6, RLENGTH - 12)
            if (match(s, / from [0-9a-fA-F:.]+$/)) return substr(s, RSTART + 6)
            return "-"
        }
        function upto_from(s,    i) { i = index(s, " from "); return i ? substr(s, 1, i - 1) : s }
        $0 !~ /sshd(-session)?(\[[0-9]+\])?: / { next }
        {
            t = ""; u = ""; m = "-"
            if (match($0, /: Failed [^ ]+ for /)) {
                m = substr($0, RSTART + 9, RLENGTH - 14)
                rest = substr($0, RSTART + RLENGTH)
                if (substr(rest, 1, 13) == "invalid user ") { t = "FAIL_INV"; rest = substr(rest, 14) }
                else t = "FAIL"
                u = upto_from(rest)
            } else if (match($0, /: Invalid user /)) {
                t = "INVALID"
                u = upto_from(substr($0, RSTART + RLENGTH))
            } else if (match($0, /: Accepted [^ ]+ for /)) {
                t = "ACCEPT"
                m = substr($0, RSTART + 11, RLENGTH - 16)
                u = upto_from(substr($0, RSTART + RLENGTH))
            } else if ($0 ~ /maximum authentication attempts exceeded/) {
                t = "MAXAUTH"
            } else if ($0 ~ /Did not receive identification string|banner exchange|kex_exchange_identification|Unable to negotiate|invalid format/) {
                t = "PREAUTH"
            } else next
            u = clean(u); if (u == "") u = "(empty)"
            print t "\t" ipof($0) "\t" u "\t" clean(m) "\t" ts_key($0)
        }' "$(source_log auth)" > "$WORKDIR/ssh.events"

    # Per-IP failure score: failures for valid users plus the larger of
    # "Failed ... for invalid user" and "Invalid user" lines, because sshd logs
    # both for the same password attempt against a non-existent account.
    awk -F'\t' '
        $2 == "-" { next }
        $1 == "FAIL"     { fv[$2]++ }
        $1 == "FAIL_INV" { fi[$2]++ }
        $1 == "INVALID"  { inv[$2]++ }
        $1 == "ACCEPT"   { acc[$2]++; seen[$2] = 1 }
        $1 == "FAIL" || $1 == "FAIL_INV" || $1 == "INVALID" {
            ip = $2; seen[ip] = 1
            if (!((ip SUBSEP $3) in pu)) { pu[ip SUBSEP $3] = 1; du[ip]++ }
            if ($5 != "") {
                if (first[ip] == "" || $5 < first[ip]) first[ip] = $5
                if ($5 > last[ip]) last[ip] = $5
            }
        }
        END {
            for (ip in seen) {
                s = fv[ip] + (fi[ip] > inv[ip] ? fi[ip] : inv[ip])
                printf "%s\t%d\t%d\t%d\t%s\t%s\n", ip, s, acc[ip], du[ip], \
                    (first[ip] == "" ? "-" : first[ip]), (last[ip] == "" ? "-" : last[ip])
            }
        }' "$WORKDIR/ssh.events" | sort -t "$TAB" -k2,2nr -k1,1 > "$WORKDIR/ssh.ips"
}

# f2b.events: BAN <TAB> jail <TAB> ip   |   UNBAN <TAB> jail <TAB> ip
prepare_f2b() {
    [[ -f "$WORKDIR/f2b.events" ]] && return 0
    ensure_source f2b
    awk '
        match($0, /\[[^]]+\] +(Restore +)?(Un)?[Bb]an +[0-9a-fA-F:.]+/) {
            s = substr($0, RSTART, RLENGTH)
            jail = substr(s, 2, index(s, "]") - 2)
            n = split(s, a, " ")
            print ((s ~ /Unban/) ? "UNBAN" : "BAN") "\t" jail "\t" a[n]
        }' "$(source_log f2b)" > "$WORKDIR/f2b.events"
}

# fw.events: src <TAB> dpt <TAB> proto
prepare_fw() {
    [[ -f "$WORKDIR/fw.events" ]] && return 0
    ensure_source fw
    awk '
        /\[UFW BLOCK\]|FINAL_(REJECT|DROP)|_(REJECT|DROP):? IN=/ {
            src = "-"; dpt = "-"; proto = "-"
            if (match($0, /SRC=[0-9a-fA-F:.]+/)) src = substr($0, RSTART + 4, RLENGTH - 4)
            if (match($0, /DPT=[0-9]+/)) dpt = substr($0, RSTART + 4, RLENGTH - 4)
            if (match($0, /PROTO=[A-Za-z0-9]+/)) proto = tolower(substr($0, RSTART + 6, RLENGTH - 6))
            print src "\t" dpt "\t" proto
        }' "$(source_log fw)" > "$WORKDIR/fw.events"
}

detect_firewall() {
    [[ -n "$FW_KIND" ]] && return 0
    FW_KIND="none"
    FW_ACTIVE=0
    if [[ "$IS_ROOT" -eq 0 ]]; then
        FW_KIND="unknown"
        return 0
    fi

    local out=""
    if command -v ufw >/dev/null 2>&1; then
        out=$(ufw status 2>/dev/null) || true
        if [[ "$out" == *"Status: active"* ]]; then
            FW_KIND="ufw"; FW_ACTIVE=1; return 0
        fi
    fi
    if command -v firewall-cmd >/dev/null 2>&1; then
        out=$(firewall-cmd --state 2>/dev/null) || true
        if [[ "$out" == "running" ]]; then
            FW_KIND="firewalld"; FW_ACTIVE=1; return 0
        fi
    fi
    if command -v nft >/dev/null 2>&1; then
        out=$(nft list ruleset 2>/dev/null) || true
        if [[ "$out" == *"hook input"* && ( "$out" == *drop* || "$out" == *reject* ) ]]; then
            FW_KIND="nftables"; FW_ACTIVE=1; return 0
        fi
    fi
    if command -v iptables >/dev/null 2>&1; then
        out=$(iptables -S INPUT 2>/dev/null) || true
        if [[ "$out" =~ -P\ INPUT\ DROP|-j\ (DROP|REJECT) ]]; then
            FW_KIND="iptables"; FW_ACTIVE=1; return 0
        fi
    fi
    if command -v ufw >/dev/null 2>&1; then
        FW_KIND="ufw (inactive)"
    fi
}

detect_fail2ban() {
    [[ -n "$F2B_STATE" ]] && return 0
    if ! command -v fail2ban-server >/dev/null 2>&1 && ! command -v fail2ban-client >/dev/null 2>&1; then
        F2B_STATE="not installed"
    elif command -v systemctl >/dev/null 2>&1; then
        F2B_STATE=$(systemctl is-active fail2ban 2>/dev/null) || true
        F2B_STATE="${F2B_STATE:-unknown}"
    else
        F2B_STATE="unknown"
    fi
}

# ┌────────────────────────────────────────────────────────────────────────────┐
# │ Analysis: SSH                                                              │
# └────────────────────────────────────────────────────────────────────────────┘

section_ssh() {
    print_header "SSH SERVER & AUTHENTICATION" "$SYM_ALERT"

    if ! prepare_ssh; then
        print_alert 0 "No authentication log source available (auth.log, secure or journald)"
        audit_sshd_config 0
        return 0
    fi

    local ev="$WORKDIR/ssh.events" ips="$WORKDIR/ssh.ips"
    local failed failed_inv invalid accepted maxauth preauth score_total uniq

    IFS="$TAB" read -r failed failed_inv invalid accepted maxauth preauth < <(awk -F'\t' '
        { c[$1]++ }
        END { printf "%d\t%d\t%d\t%d\t%d\t%d\n", c["FAIL"], c["FAIL_INV"], c["INVALID"], c["ACCEPT"], c["MAXAUTH"], c["PREAUTH"] }' "$ev")
    IFS="$TAB" read -r score_total uniq < <(awk -F'\t' '$2 > 0 { s += $2; n++ } END { printf "%d\t%d\n", s, n }' "$ips")

    TOTAL_FAILED_LOGINS="$score_total"
    stat_set ssh_failure_events "$score_total"
    stat_set ssh_failed_password "$((failed + failed_inv))"
    stat_set ssh_invalid_user "$invalid"
    stat_set ssh_accepted "$accepted"
    stat_set ssh_max_auth_exceeded "$maxauth"
    stat_set ssh_preauth_probes "$preauth"
    stat_set ssh_attacking_ips "$uniq"

    print_subheader "Summary"
    print_stat "Failed authentications (deduped)" "$score_total"
    print_stat "Failed password/keyboard auth" "$((failed + failed_inv))"
    print_stat "Invalid-user attempts" "$invalid"
    print_stat "Max auth attempts exceeded" "$maxauth"
    print_stat "Pre-auth probes / scanners" "$preauth"
    print_stat "Distinct attacking IPs" "$uniq"
    print_stat "Successful logins" "$accepted"

    if [[ "$score_total" -ge 1000 ]]; then
        add_finding 2 ssh "$score_total SSH authentication failures from $uniq IPs"
    elif [[ "$score_total" -ge 100 ]]; then
        add_finding 1 ssh "$score_total SSH authentication failures from $uniq IPs"
    elif [[ "$score_total" -eq 0 ]]; then
        print_alert 0 "No SSH authentication failures in window"
    fi

    if [[ "$score_total" -gt 0 ]]; then
        print_subheader "Top Attacking IPs"
        local ip score acc du first last
        while IFS="$TAB" read -r ip score acc du first last; do
            print_ip_entry "$ip" "$score" "failures, $du username(s)$([[ "$acc" -gt 0 ]] && echo ", $acc SUCCESSFUL")"
        done < <(awk -F'\t' '$2 > 0' "$ips" | top_n)

        print_subheader "Targeted Existing Accounts"
        local count user
        local shown=0
        while IFS="$TAB" read -r count user; do
            printf '    %b%-30s%b %7d failures\n' "$C_MAGENTA" "$user" "$C_RESET" "$count"
            rec_row table "User|Failures" "$user" "$count"
            shown=1
        done < <(awk -F'\t' '$1 == "FAIL" { print $3 }' "$ev" | tally | top_n)
        [[ "$shown" -eq 1 ]] || print_none

        print_subheader "Top Invalid Usernames Attempted"
        shown=0
        while IFS="$TAB" read -r count user; do
            printf '    %b%-30s%b %7d attempts\n' "$C_MAGENTA" "$user" "$C_RESET" "$count"
            rec_row table "Username|Attempts" "$user" "$count"
            shown=1
        done < <(awk -F'\t' '$1 == "INVALID" { print $3 }' "$ev" | tally | top_n)
        [[ "$shown" -eq 1 ]] || print_none
    fi

    # Root
    local root_fail root_ok
    root_fail=$(awk -F'\t' '$1 == "FAIL" && $3 == "root"' "$ev" | wc -l)
    root_ok=$(awk -F'\t' '$1 == "ACCEPT" && $3 == "root"' "$ev" | wc -l)
    stat_set ssh_root_failures "$root_fail"
    stat_set ssh_root_logins "$root_ok"

    print_subheader "Root Access"
    print_stat "Failed root login attempts" "$root_fail"
    print_stat "Successful root logins" "$root_ok"
    if [[ "$root_fail" -ge 50 ]]; then
        add_finding 2 ssh "$root_fail failed SSH login attempts for root"
    fi
    if [[ "$root_ok" -gt 0 ]]; then
        add_finding 1 ssh "$root_ok direct root SSH login(s); prefer named accounts + sudo for accountability"
    fi

    # Successful logins
    print_subheader "Successful Logins (user / source / method)"
    local count key
    local shown=0
    while IFS="$TAB" read -r count key; do
        IFS="$TAB" read -r user ip method <<< "$key"
        printf '    %b%-20s%b from %b%-39s%b %-18s %5dx\n' "$C_GREEN" "$user" "$C_RESET" "$C_CYAN" "$ip" "$C_RESET" "$method" "$count"
        rec_row table "User|Source|Method|Logins" "$user" "$ip" "$method" "$count"
        shown=1
    done < <(awk -F'\t' '$1 == "ACCEPT" { print $3 "\t" $2 "\t" $4 }' "$ev" | tally | top_n)
    [[ "$shown" -eq 1 ]] || print_none

    # Compromise indicator: success from an IP that failed many times
    print_subheader "Logins After Repeated Failures"
    shown=0
    local n
    while IFS="$TAB" read -r ip user n; do
        if is_whitelisted "$ip"; then
            continue
        fi
        add_finding 4 ssh "Successful SSH login as '$user' from $ip after $n failed attempts - possible compromised account"
        flag_ip "$ip" "successful login after $n failures"
        shown=1
    done < <(awk -F'\t' -v t="$SUCCESS_AFTER_FAIL_THRESHOLD" '
        NR == FNR { s[$1] = $2; next }
        $1 == "ACCEPT" && ($2 in s) && s[$2] >= t && !(($2 SUBSEP $3) in seen) {
            seen[$2 SUBSEP $3] = 1; print $2 "\t" $3 "\t" s[$2]
        }' "$ips" "$ev")
    [[ "$shown" -eq 1 ]] || print_alert 0 "None (threshold: $SUCCESS_AFTER_FAIL_THRESHOLD failures)"

    # Password spraying
    local sprayers=0
    while IFS="$TAB" read -r ip du; do
        flag_ip "$ip" "password spraying ($du usernames)"
        sprayers=$((sprayers + 1))
    done < <(awk -F'\t' -v t="$SPRAY_USER_THRESHOLD" '$4 >= t { print $1 "\t" $4 }' "$ips")
    stat_set ssh_spraying_ips "$sprayers"
    if [[ "$sprayers" -gt 0 ]]; then
        add_finding 2 ssh "$sprayers IP(s) tried $SPRAY_USER_THRESHOLD+ different usernames (password spraying)"
    fi
    if [[ "$uniq" -ge "$DISTRIBUTED_IP_THRESHOLD" ]]; then
        add_finding 1 ssh "Distributed SSH attack: $uniq distinct source IPs"
    fi

    audit_sshd_config "$score_total"

    if [[ "$VERBOSE" -eq 1 && "$score_total" -gt 0 ]]; then
        print_subheader "Hourly Distribution of Failures"
        local max hour bar_len bar
        max=$(awk -F'\t' '($1 == "FAIL" || $1 == "FAIL_INV" || $1 == "INVALID") && $5 != "" { c[substr($5, 12, 2)]++ }
                          END { m = 0; for (h in c) if (c[h] > m) m = c[h]; print m }' "$ev")
        while IFS="$TAB" read -r count hour; do
            bar_len=$(( max > 0 ? count * 50 / max : 0 ))
            [[ "$bar_len" -eq 0 ]] && bar_len=1
            bar=$(printf '%*s' "$bar_len" '' | tr ' ' '#')
            printf '    %b%s:00%b  %b%-50s%b %d\n' "$C_GREY" "$hour" "$C_RESET" "$C_CYAN" "$bar" "$C_RESET" "$count"
        done < <(awk -F'\t' '($1 == "FAIL" || $1 == "FAIL_INV" || $1 == "INVALID") && $5 != "" { print substr($5, 12, 2) }' "$ev" |
                 tally | sort -t "$TAB" -k2,2)
    fi
    return 0
}

# sshd_config_fallback [file] [depth] — "key value" lines from sshd_config and
# its Include files in file order. Used when "sshd -T" is unavailable (no root).
# Settings inside Match blocks are conditional and are ignored.
sshd_config_fallback() {
    local file="${1:-/etc/ssh/sshd_config}" depth="${2:-0}"
    [[ "$depth" -lt 5 && -r "$file" ]] || return 0
    local line key rest pat inc
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%%#*}"
        IFS=$' \t=' read -r key rest <<< "$line" || true
        [[ -n "$key" ]] || continue
        key="${key,,}"
        case "$key" in
            match) break ;;
            include)
                local -a pats=()
                IFS=' ' read -r -a pats <<< "$rest"
                for pat in "${pats[@]}"; do
                    [[ "$pat" == /* ]] || pat="/etc/ssh/$pat"
                    while IFS= read -r inc; do
                        sshd_config_fallback "$inc" $((depth + 1))
                    done < <(compgen -G "$pat" | sort)
                done
                ;;
            *) printf '%s %s\n' "$key" "$rest" ;;
        esac
    done < "$file"
}

audit_sshd_config() {
    local failures="$1" sshd_bin cfg="" src=""
    sshd_bin=$(command -v sshd 2>/dev/null) || sshd_bin=""
    [[ -z "$sshd_bin" && -x /usr/sbin/sshd ]] && sshd_bin="/usr/sbin/sshd"
    if [[ -z "$sshd_bin" && ! -e /etc/ssh/sshd_config ]]; then
        print_subheader "SSH Server Configuration"
        print_alert 0 "OpenSSH server is not installed"
        return 0
    fi
    if [[ -n "$sshd_bin" && "$IS_ROOT" -eq 1 ]]; then
        cfg=$(timeout 5 "$sshd_bin" -T 2>/dev/null) && src="sshd -T (effective configuration)"
    fi
    if [[ -z "$cfg" ]]; then
        cfg=$(sshd_config_fallback | awk '!seen[$1]++')
        src="sshd_config + drop-ins (defaults assumed for unset options; run as root for sshd -T)"
    fi

    sshd_opt() { awk -v k="$1" '$1 == k { $1 = ""; sub(/^ +/, ""); print; exit }' <<< "$cfg"; }

    # OpenSSH defaults for options the fallback parser may not see
    local -A def=(
        [permitrootlogin]="prohibit-password" [passwordauthentication]="yes" [permitemptypasswords]="no"
        [maxauthtries]="6" [pubkeyauthentication]="yes" [kbdinteractiveauthentication]="yes"
        [hostbasedauthentication]="no" [ignorerhosts]="yes" [permituserenvironment]="no"
        [x11forwarding]="no" [allowtcpforwarding]="yes" [allowagentforwarding]="yes"
        [permittunnel]="no" [logingracetime]="120" [clientaliveinterval]="0" [maxsessions]="10"
        [loglevel]="INFO" [usepam]="no" [port]="22" [listenaddress]="0.0.0.0 / ::"
        [allowusers]="" [allowgroups]="" [ciphers]="" [macs]="" [kexalgorithms]=""
    )
    local -A val=()
    local k v
    for k in "${!def[@]}"; do
        v=$(sshd_opt "$k")
        val[$k]="${v:-${def[$k]}}"
    done

    print_subheader "SSH Server Configuration"
    print_stat "Source" "$src"
    tbl_new "SSH Server Settings" "Option" "Value" "Status" "Note"

    # ssh_row <option> <status> <note>
    ssh_row() {
        tbl_row "$1" "${val[$1]:--}" "$2" "$3"
    }

    case "${val[permitrootlogin],,}" in
        yes)
            ssh_row permitrootlogin FAIL "root may log in with a password"
            add_finding 2 ssh "sshd allows root login with a password (PermitRootLogin yes)"
            add_rec "Set 'PermitRootLogin no' (or 'prohibit-password') in /etc/ssh/sshd_config"
            ;;
        no|forced-commands-only) ssh_row permitrootlogin OK "" ;;
        *) ssh_row permitrootlogin OK "key-only root login; 'no' is stricter" ;;
    esac
    if [[ "${val[permitemptypasswords],,}" == "yes" ]]; then
        ssh_row permitemptypasswords FAIL "accounts without a password can log in"
        add_finding 3 ssh "sshd allows empty passwords (PermitEmptyPasswords yes)"
    else
        ssh_row permitemptypasswords OK ""
    fi
    if [[ "${val[passwordauthentication],,}" == "yes" ]]; then
        ssh_row passwordauthentication WARN "passwords can be brute-forced; prefer keys"
        if [[ "$failures" -gt 0 ]]; then
            add_rec "Disable SSH password authentication and use keys (PasswordAuthentication no)"
        fi
    else
        ssh_row passwordauthentication OK ""
    fi
    if [[ "${val[kbdinteractiveauthentication],,}" == "yes" && "${val[usepam],,}" == "yes" ]]; then
        ssh_row kbdinteractiveauthentication WARN "with UsePAM this also allows password logins"
    else
        ssh_row kbdinteractiveauthentication OK ""
    fi
    ssh_row pubkeyauthentication "$([[ "${val[pubkeyauthentication],,}" == "yes" ]] && echo OK || echo WARN)" ""
    if [[ "${val[hostbasedauthentication],,}" == "yes" || "${val[ignorerhosts],,}" == "no" ]]; then
        ssh_row hostbasedauthentication FAIL "trust based on client host / .rhosts"
        add_finding 2 ssh "sshd trusts host-based or .rhosts authentication (HostbasedAuthentication yes / IgnoreRhosts no)"
    else
        ssh_row hostbasedauthentication OK ""
    fi
    if [[ "${val[permituserenvironment],,}" != "no" ]]; then
        ssh_row permituserenvironment FAIL "users can set LD_PRELOAD etc. for sshd sessions"
        add_finding 1 ssh "sshd PermitUserEnvironment is enabled (can bypass restrictions)"
    else
        ssh_row permituserenvironment OK ""
    fi
    if [[ "${val[maxauthtries]}" =~ ^[0-9]+$ && "${val[maxauthtries]}" -gt 4 ]]; then
        ssh_row maxauthtries REVIEW "3-4 slows down guessing"
        add_rec "Lower sshd MaxAuthTries (currently ${val[maxauthtries]}) to 3-4"
    else
        ssh_row maxauthtries OK ""
    fi
    ssh_row x11forwarding "$([[ "${val[x11forwarding],,}" == "yes" ]] && echo REVIEW || echo OK)" "disable unless needed"
    ssh_row allowtcpforwarding "$([[ "${val[allowtcpforwarding],,}" == "no" ]] && echo OK || echo INFO)" "tunnels can bypass the firewall"
    ssh_row allowagentforwarding INFO ""
    ssh_row permittunnel "$([[ "${val[permittunnel],,}" == "no" ]] && echo OK || echo REVIEW)" ""
    ssh_row logingracetime INFO ""
    ssh_row clientaliveinterval INFO "idle session timeout"
    ssh_row maxsessions INFO ""
    ssh_row loglevel "$([[ "${val[loglevel]^^}" =~ ^(VERBOSE|DEBUG) ]] && echo OK || echo INFO)" "VERBOSE logs key fingerprints"
    ssh_row port INFO ""
    ssh_row listenaddress INFO ""
    ssh_row allowusers "$([[ -n "${val[allowusers]}${val[allowgroups]}" ]] && echo OK || echo INFO)" "AllowUsers/AllowGroups limit who may log in"
    ssh_row allowgroups INFO ""

    local weak
    weak=$(tr ',' '\n' <<< "${val[ciphers]}" | grep -E -- '-cbc$|arcfour|3des|blowfish|cast128' | paste -sd, -) || weak=""
    if [[ -n "$weak" ]]; then
        ssh_row ciphers FAIL "weak: $weak"
        add_finding 2 ssh "sshd offers weak ciphers: $weak"
    elif [[ -n "${val[ciphers]}" ]]; then
        ssh_row ciphers OK ""
    fi
    weak=$(tr ',' '\n' <<< "${val[macs]}" | grep -E -- 'md5|-96|ripemd|umac-64' | paste -sd, -) || weak=""
    if [[ -n "$weak" ]]; then
        ssh_row macs FAIL "weak: $weak"
        add_finding 1 ssh "sshd offers weak MACs: $weak"
    elif [[ -n "${val[macs]}" ]]; then
        ssh_row macs OK ""
    fi
    weak=$(tr ',' '\n' <<< "${val[kexalgorithms]}" | grep -E -- 'group1-sha1|group14-sha1|group-exchange-sha1' | paste -sd, -) || weak=""
    if [[ -n "$weak" ]]; then
        ssh_row kexalgorithms FAIL "weak: $weak"
        add_finding 1 ssh "sshd offers weak key exchange algorithms: $weak"
    elif [[ -n "${val[kexalgorithms]}" ]]; then
        ssh_row kexalgorithms OK ""
    fi
    tbl_end 100
    unset -f ssh_row sshd_opt
}

section_bruteforce() {
    print_header "BRUTE FORCE DETECTION" "$SYM_SKULL"

    if ! prepare_ssh; then
        print_alert 0 "No authentication log source available"
        return 0
    fi
    prepare_f2b
    detect_fail2ban

    print_subheader "IPs with ${ALERT_THRESHOLD}+ SSH Failures"

    local -A banned=()
    local ip
    while IFS= read -r ip; do
        banned[$ip]=1
    done < <(awk -F'\t' '$1 == "BAN" { print $3 }' "$WORKDIR/f2b.events")

    local total=0 shown=0 unbanned=0 score acc du first last geo rdns status
    while IFS="$TAB" read -r ip score acc du first last; do
        if is_whitelisted "$ip"; then
            continue
        fi
        total=$((total + 1))
        flag_ip "$ip" "SSH brute force ($score failures)"
        if [[ -n "${banned[$ip]:-}" ]]; then
            status="banned by fail2ban"
        else
            status="NOT banned"
            unbanned=$((unbanned + 1))
        fi
        if [[ "$shown" -lt "$TOP_N" ]]; then
            geo=$(geoip_lookup "$ip")
            rdns=$(reverse_dns "$ip")
            printf '    %b%s%b %b%s%b\n' "${C_RED}${C_BOLD}" "$SYM_SKULL" "$C_RESET" "$C_RED" "$ip" "$C_RESET"
            printf '       Failures:   %b%d%b (%d username(s))\n' "${C_RED}${C_BOLD}" "$score" "$C_RESET" "$du"
            printf '       Active:     %s -> %s\n' "${first/T/ }" "${last/T/ }"
            printf '       Location:   %s\n' "$(sanitize "$geo")"
            printf '       Hostname:   %s\n' "$(sanitize "$rdns")"
            printf '       Status:     %s\n' "$status"
            echo
            rec_row table "IP|Failures|Usernames|First seen|Last seen|Location|Hostname|Status" \
                "$ip" "$score" "$du" "${first/T/ }" "${last/T/ }" "$geo" "$rdns" "$status"
            shown=$((shown + 1))
        fi
    done < <(awk -F'\t' -v t="$ALERT_THRESHOLD" '$2 >= t' "$WORKDIR/ssh.ips")

    stat_set bruteforce_ips "$total"

    if [[ "$total" -eq 0 ]]; then
        print_alert 0 "No brute force sources detected (threshold: $ALERT_THRESHOLD failures per IP)"
        return 0
    fi
    if [[ "$total" -gt "$shown" ]]; then
        print_line "... and $((total - shown)) more (see JSON report)"
    fi

    if [[ "$total" -ge 5 ]]; then
        add_finding 2 bruteforce "$total IPs conducting SSH brute force attacks"
    else
        add_finding 1 bruteforce "$total IP(s) conducting SSH brute force attacks"
    fi
    if [[ "$F2B_STATE" == "active" && "$unbanned" -gt 0 ]]; then
        add_rec "Review fail2ban sshd jail: $unbanned brute-force IP(s) were never banned"
    fi
    return 0
}

# ┌────────────────────────────────────────────────────────────────────────────┐
# │ Analysis: Fail2ban & Firewall                                              │
# └────────────────────────────────────────────────────────────────────────────┘

section_fail2ban() {
    print_header "FAIL2BAN ACTIVITY" "$SYM_SHIELD"

    detect_fail2ban
    print_stat "Service status" "$F2B_STATE"

    case "$F2B_STATE" in
        "not installed")
            add_rec "Install and enable fail2ban for automatic IP blocking"
            ;;
        active|unknown) ;;
        *)
            add_finding 2 fail2ban "fail2ban is installed but not running (state: $F2B_STATE)"
            ;;
    esac

    prepare_f2b
    if [[ "${SOURCE_OK[f2b]}" -eq 0 ]]; then
        print_alert 0 "Fail2ban log not found"
        return 0
    fi

    local ev="$WORKDIR/f2b.events"
    local bans unbans uniq
    IFS="$TAB" read -r bans unbans uniq < <(awk -F'\t' '
        $1 == "BAN" { b++; u[$3] = 1 } $1 == "UNBAN" { ub++ }
        END { n = 0; for (i in u) n++; printf "%d\t%d\t%d\n", b, ub, n }' "$ev")

    TOTAL_BLOCKED_IPS="$uniq"
    stat_set fail2ban_bans "$bans"
    stat_set fail2ban_unbans "$unbans"
    stat_set fail2ban_banned_ips "$uniq"

    print_subheader "Summary"
    print_stat "Bans" "$bans"
    print_stat "Unbans" "$unbans"
    print_stat "Distinct banned IPs" "$uniq"

    if [[ "$bans" -gt 0 ]]; then
        print_subheader "Most Frequently Banned IPs"
        local count ip jail
        while IFS="$TAB" read -r count ip; do
            print_ip_entry "$ip" "$count" "bans"
            if [[ "$count" -ge 3 ]]; then
                flag_ip "$ip" "repeat offender ($count fail2ban bans)"
            fi
        done < <(awk -F'\t' '$1 == "BAN" { print $3 }' "$ev" | tally | top_n)

        print_subheader "Bans by Jail"
        while IFS="$TAB" read -r count jail; do
            printf '    %b%-30s%b %7d bans\n' "$C_CYAN" "$(sanitize "$jail")" "$C_RESET" "$count"
            rec_row table "Jail|Bans" "$jail" "$count"
        done < <(awk -F'\t' '$1 == "BAN" { print $2 }' "$ev" | tally)
    fi

    if [[ "$IS_ROOT" -eq 1 ]] && command -v fail2ban-client >/dev/null 2>&1 && [[ "$F2B_STATE" == "active" ]]; then
        print_subheader "Currently Banned IPs"
        local status jails banned nbanned
        status=$(timeout 10 fail2ban-client status 2>/dev/null) || status=""
        jails=$(awk -F':' '/Jail list/ { print $2 }' <<< "$status" | tr ',' '\n' | awk '{ $1 = $1; if ($0 != "") print }')
        while IFS= read -r jail; do
            [[ -z "$jail" ]] && continue
            banned=$(timeout 10 fail2ban-client status "$jail" 2>/dev/null | awk -F':' '/Banned IP list/ { print $2 }') || banned=""
            nbanned=$(wc -w <<< "$banned")
            printf '    %b%-30s%b %7d banned\n' "$C_YELLOW" "$jail" "$C_RESET" "$nbanned"
            rec_row table "Jail|Banned now|IPs" "$jail" "$nbanned" "$(echo $banned)"
            if [[ "$VERBOSE" -eq 1 && "$nbanned" -gt 0 ]]; then
                printf '      %s\n' "$(echo $banned)"
            fi
        done <<< "$jails"
    fi
    return 0
}

# Current policy and rules of the active firewall (needs root)
firewall_rules() {
    [[ "$IS_ROOT" -eq 1 ]] || return 0
    case "$FW_KIND" in
        ufw)
            local out policy
            out=$(timeout 10 ufw status verbose 2>/dev/null) || return 0
            policy=$(awk -F': ' '/^Default:/ { print $2 }' <<< "$out")
            print_stat "UFW default policy" "${policy:-unknown}"
            print_stat "UFW logging" "$(awk -F': ' '/^Logging:/ { print $2 }' <<< "$out")"
            if [[ "$policy" == *"allow (incoming)"* ]]; then
                add_finding 2 firewall "UFW default policy for incoming traffic is ALLOW"
            fi
            tbl_new "UFW Rules" "To" "Action" "From"
            local to action from
            while IFS="$TAB" read -r to action from; do
                tbl_row "$to" "$action" "$from"
            done < <(awk '/^--/ { r = 1; next } r && NF {
                        if (match($0, /  +(ALLOW|DENY|REJECT|LIMIT)( IN| OUT| FWD)?  +/)) {
                            a = substr($0, RSTART, RLENGTH); gsub(/^ +| +$/, "", a)
                            print substr($0, 1, RSTART - 1) "\t" a "\t" substr($0, RSTART + RLENGTH)
                        } }' <<< "$out")
            tbl_end 50
            ;;
        firewalld)
            print_stat "Default zone" "$(timeout 10 firewall-cmd --get-default-zone 2>/dev/null)"
            print_stat "Active zones" "$(timeout 10 firewall-cmd --get-active-zones 2>/dev/null | awk 'NR % 2 == 1' | paste -sd, -)"
            print_stat "Allowed services" "$(timeout 10 firewall-cmd --list-services 2>/dev/null)"
            print_stat "Allowed ports" "$(timeout 10 firewall-cmd --list-ports 2>/dev/null)"
            ;;
        nftables)
            local tables rules
            tables=$(nft list tables 2>/dev/null | wc -l)
            rules=$(nft -a list ruleset 2>/dev/null | grep -c '# handle' || true)
            print_stat "nftables tables / rules" "$tables / $rules"
            ;;
        iptables)
            print_stat "INPUT policy" "$(iptables -S INPUT 2>/dev/null | awk '$1 == "-P" { print $3 }')"
            print_stat "iptables rules" "$(iptables -S 2>/dev/null | grep -c '^-A' || true)"
            ;;
    esac
}

section_firewall() {
    print_header "FIREWALL" "$SYM_SHIELD"

    detect_firewall
    print_stat "Active host firewall" "$FW_KIND"

    case "$FW_KIND" in
        none)
            add_finding 2 firewall "No active host firewall detected (ufw/firewalld/nftables/iptables)"
            ;;
        "ufw (inactive)")
            add_finding 2 firewall "UFW is installed but inactive"
            ;;
    esac

    firewall_rules

    prepare_fw
    if [[ "${SOURCE_OK[fw]}" -eq 0 ]]; then
        print_alert 0 "No firewall log source available"
        return 0
    fi

    local ev="$WORKDIR/fw.events"
    local blocks uniq
    IFS="$TAB" read -r blocks uniq < <(awk -F'\t' '{ b++; u[$1] = 1 } END { n = 0; for (i in u) n++; printf "%d\t%d\n", b, n }' "$ev")

    TOTAL_FIREWALL_BLOCKS="$blocks"
    stat_set firewall_blocks "$blocks"
    stat_set firewall_blocked_sources "$uniq"

    print_subheader "Blocked Connections"
    print_stat "Blocked packets" "$blocks"
    print_stat "Distinct sources" "$uniq"

    if [[ "$blocks" -eq 0 ]]; then
        print_alert 0 "No blocked connections logged"
        if [[ "$FW_KIND" == "ufw" ]]; then
            add_rec "Enable UFW logging to record blocked connections: sudo ufw logging on"
        fi
        return 0
    fi

    print_subheader "Top Blocked Sources"
    local count ip key proto port svc
    while IFS="$TAB" read -r count ip; do
        print_ip_entry "$ip" "$count" "blocks"
    done < <(cut -f1 "$ev" | tally | top_n)

    print_subheader "Top Blocked Destination Ports"
    while IFS="$TAB" read -r count key; do
        IFS="$TAB" read -r port proto <<< "$key"
        svc=$(getent services "$port/$proto" 2>/dev/null | awk '{ print $1 }') || true
        printf '    %bPort %-12s%b %-16s %7d blocks\n' "$C_CYAN" "$port/$proto" "$C_RESET" "(${svc:-unknown})" "$count"
        rec_row table "Port|Service|Blocks" "$port/$proto" "${svc:-unknown}" "$count"
    done < <(awk -F'\t' '$2 != "-" { print $2 "\t" $3 }' "$ev" | tally | top_n)

    print_subheader "Port Scanners (${SCAN_PORT_THRESHOLD}+ distinct ports)"
    local scanners=0 ports total
    while IFS="$TAB" read -r ip ports total; do
        print_ip_entry "$ip" "$ports" "distinct ports ($total packets)"
        flag_ip "$ip" "port scan ($ports ports)"
        scanners=$((scanners + 1))
    done < <(awk -F'\t' -v t="$SCAN_PORT_THRESHOLD" '
        { tot[$1]++ }
        $2 != "-" && !(($1 SUBSEP $2) in s) { s[$1 SUBSEP $2] = 1; n[$1]++ }
        END { for (i in n) if (n[i] >= t) printf "%s\t%d\t%d\n", i, n[i], tot[i] }' "$ev" | sort -t "$TAB" -k2,2nr)

    stat_set port_scanners "$scanners"
    if [[ "$scanners" -gt 0 ]]; then
        add_finding 2 firewall "$scanners source(s) port-scanning this host"
    else
        print_alert 0 "No port scanners detected"
    fi
    return 0
}

# ┌────────────────────────────────────────────────────────────────────────────┐
# │ Analysis: Privilege Escalation                                             │
# └────────────────────────────────────────────────────────────────────────────┘

# Commands that indicate an attack or defense evasion
readonly HIGH_RISK_CMD_RE='/dev/(tcp|udp)/|bash -i|(^|/| )nc(at)? .*-[ec] |mkfifo|socat .*exec|(curl|wget) [^|]*\| *(sudo +)?(ba|z|da)?sh|base64 (-d|--decode)|setenforce 0|(systemctl|service) +(stop|disable|mask) +(auditd|fail2ban|ufw|firewalld|apparmor|rsyslog|syslog|systemd-journald)|ufw +disable|iptables +-F|history +-c|shred .*(/var/log|history)|chattr +[+-]i|insmod|LD_PRELOAD|/etc/ld\.so\.preload'
# Commands worth reviewing
readonly SUSPICIOUS_CMD_RE='/etc/shadow|/etc/sudoers|visudo|chmod +(-R +)?[0-7]*777|chmod +[ugoa]*\+s|setcap|(^|/)(useradd|userdel|usermod|adduser|deluser)( |$)|(^|/s?bin/)passwd( |$)|crontab|authorized_keys|^/(tmp|var/tmp|dev/shm)/|(^|/)(nmap|tcpdump|tshark|john|hashcat|hydra)( |$)'

section_privesc() {
    print_header "SUDO & PRIVILEGE ESCALATION" "$SYM_WARN"

    ensure_source auth
    if [[ "${SOURCE_OK[auth]}" -eq 0 ]]; then
        print_alert 0 "No authentication log source available"
        return 0
    fi

    local log ev="$WORKDIR/sudo.events"
    log=$(source_log auth)
    awk "$AWK_TS_LIB"'
        /sudo(\[[0-9]+\])?: / {
            user = ""
            if (match($0, /sudo(\[[0-9]+\])?: +[^ ]+ : /)) {
                s = substr($0, RSTART, RLENGTH); sub(/^sudo(\[[0-9]+\])?: +/, "", s); sub(/ : $/, "", s); user = s
            }
            if ($0 ~ /NOT in sudoers|is not in the sudoers file|NOT authorized on host|command not allowed/) {
                print "DENIED\t" clean(user) "\t-"; next
            }
            if ($0 ~ /incorrect password attempt/) { print "BADPW\t" clean(user) "\t-"; next }
            if ($0 ~ /pam_unix\(sudo(-i)?:auth\): authentication failure/) {
                u = ""; if (match($0, / user=[^ ]+/)) u = substr($0, RSTART + 6, RLENGTH - 6)
                print "AUTHFAIL\t" clean(u) "\t-"; next
            }
            if (user != "" && index($0, "COMMAND=")) {
                print "CMD\t" clean(user) "\t" clean(substr($0, index($0, "COMMAND=") + 8)); next
            }
        }' "$log" > "$ev"

    local cmds denied badpw authfail su_fail sudo_fail
    IFS="$TAB" read -r cmds denied badpw authfail < <(awk -F'\t' '{ c[$1]++ }
        END { printf "%d\t%d\t%d\t%d\n", c["CMD"], c["DENIED"], c["BADPW"], c["AUTHFAIL"] }' "$ev")
    sudo_fail=$(( authfail > badpw ? authfail : badpw ))
    su_fail=$(count_re 'pam_unix\(su(-l)?:auth\): authentication failure|FAILED (su|SU) ' "$log")

    stat_set sudo_commands "$cmds"
    stat_set sudo_auth_failures "$sudo_fail"
    stat_set sudo_denied "$denied"
    stat_set su_failures "$su_fail"

    print_subheader "Summary"
    print_stat "Sudo commands executed" "$cmds"
    print_stat "Sudo authentication failures" "$sudo_fail"
    print_stat "Sudo denied (not in sudoers)" "$denied"
    print_stat "Failed su attempts" "$su_fail"

    if [[ "$denied" -gt 0 ]]; then
        local users
        users=$(awk -F'\t' '$1 == "DENIED" { print $2 }' "$ev" | sort -u | paste -sd, - | sed 's/,/, /g')
        add_finding 3 privesc "$denied sudo attempt(s) by users without sudo rights: $users"
    fi
    if [[ "$sudo_fail" -ge 10 ]]; then
        add_finding 2 privesc "$sudo_fail sudo authentication failures"
    fi
    if [[ "$su_fail" -ge 5 ]]; then
        add_finding 1 privesc "$su_fail failed su attempts"
    fi

    print_subheader "Users Running Sudo"
    local count user shown=0
    while IFS="$TAB" read -r count user; do
        printf '    %b%-25s%b %7d commands\n' "$C_CYAN" "$user" "$C_RESET" "$count"
        rec_row table "User|Commands" "$user" "$count"
        shown=1
    done < <(awk -F'\t' '$1 == "CMD" { print $2 }' "$ev" | tally | top_n)
    [[ "$shown" -eq 1 ]] || print_none

    # Classify privileged commands
    local type cmd high=0 susp=0
    local -a high_ex=() susp_ex=()
    while IFS="$TAB" read -r type user cmd; do
        if [[ "$cmd" =~ $HIGH_RISK_CMD_RE ]]; then
            high=$((high + 1))
            high_ex+=("$user: $cmd")
        elif [[ "$cmd" =~ $SUSPICIOUS_CMD_RE ]]; then
            susp=$((susp + 1))
            susp_ex+=("$user: $cmd")
        fi
    done < <(awk -F'\t' '$1 == "CMD"' "$ev")

    TOTAL_SUSPICIOUS=$((TOTAL_SUSPICIOUS + high + susp))
    stat_set sudo_high_risk_commands "$high"
    stat_set sudo_suspicious_commands "$susp"

    print_subheader "High-Risk Privileged Commands"
    if [[ "$high" -gt 0 ]]; then
        local e
        for e in "${high_ex[@]:$(( ${#high_ex[@]} > 10 ? ${#high_ex[@]} - 10 : 0 ))}"; do
            printf '    %b%s%b %s\n' "$C_RED" "$SYM_ALERT" "$C_RESET" "$e"
            rec_row table "User: command" "$e"
        done
        add_finding 3 privesc "$high high-risk command(s) run via sudo (reverse shells, log wiping, disabling defenses...)"
    else
        print_none
    fi

    print_subheader "Privileged Commands to Review"
    if [[ "$susp" -gt 0 ]]; then
        local e
        for e in "${susp_ex[@]:$(( ${#susp_ex[@]} > 10 ? ${#susp_ex[@]} - 10 : 0 ))}"; do
            printf '    %b%s%b %s\n' "$C_ORANGE" "$SYM_WARN" "$C_RESET" "$e"
            rec_row table "User: command" "$e"
        done
        add_finding 1 privesc "$susp sensitive command(s) run via sudo (account/permission changes)"
    else
        print_none
    fi
    return 0
}

# ┌────────────────────────────────────────────────────────────────────────────┐
# │ Analysis: User Accounts                                                    │
# └────────────────────────────────────────────────────────────────────────────┘

readonly PRIV_GROUPS_RE="sudo|wheel|admin|root|adm|docker|lxd|libvirt|disk|shadow"

section_accounts() {
    print_header "ACCOUNT CHANGES (LOGS)" "$SYM_EYE"

    ensure_source auth
    local log
    log=$(source_log auth)

    local new_users deleted pw_changes group_changes
    new_users=$(count_re '(useradd|adduser)(\[[0-9]+\])?: new user' "$log")
    deleted=$(count_re '(userdel|deluser)(\[[0-9]+\])?: (delete user|removed )' "$log")
    pw_changes=$(count_re 'password changed for' "$log")
    group_changes=$(count_re '(groupadd|groupdel|groupmod|gpasswd|usermod)(\[[0-9]+\])?: ' "$log")

    stat_set users_created "$new_users"
    stat_set users_deleted "$deleted"
    stat_set password_changes "$pw_changes"
    stat_set group_changes "$group_changes"

    print_subheader "Account Changes in Window"
    print_stat "Users created" "$new_users"
    print_stat "Users deleted" "$deleted"
    print_stat "Password changes" "$pw_changes"
    print_stat "Group modifications" "$group_changes"

    if [[ "$new_users" -gt 0 || "$deleted" -gt 0 ]]; then
        print_subheader "User Creation / Deletion Events"
        local ts event
        while IFS="$TAB" read -r ts event; do
            printf '    %b%s%b  %s\n' "$C_GREY" "$ts" "$C_RESET" "$event"
            rec_row table "Time|Event" "${ts/T/ }" "$event"
        done < <(grep -E '(useradd|adduser|userdel|deluser)(\[[0-9]+\])?: (new user|delete user|removed )' "$log" | tail -n 10 |
                 awk "$AWK_TS_LIB"'{ k = ts_key($0); e = $0; sub(/^.*(useradd|adduser|userdel|deluser)(\[[0-9]+\])?: /, "", e)
                                     print (k == "" ? "-" : k) "\t" clean(e) }')
    fi
    if [[ "$new_users" -ge 3 ]]; then
        add_finding 2 accounts "$new_users new user accounts created"
    fi

    # New accounts with UID 0
    local line
    while IFS= read -r line; do
        add_finding 4 accounts "Account created with UID 0: $(sanitize "$line")"
    done < <(grep -oE 'new user: name=[^,]+, UID=0,' "$log" 2>/dev/null | sed -E 's/new user: name=([^,]+),.*/\1/' || true)

    # Additions to privileged groups
    print_subheader "Privileged Group Additions"
    local priv=0
    while IFS= read -r line; do
        print_line "$(sanitize "$line")"
        priv=$((priv + 1))
    done < <(grep -oE "(add '[^']+' to group|user [^ ]+ added by [^ ]+ to group) '?($PRIV_GROUPS_RE)'?( |$|,)" "$log" 2>/dev/null || true)
    stat_set privileged_group_additions "$priv"
    if [[ "$priv" -gt 0 ]]; then
        add_finding 3 accounts "$priv user(s) added to privileged groups ($PRIV_GROUPS_RE)"
    else
        print_none
    fi

    # Critical files changed in window
    local f changed=0 sudoers_changed=0
    local -a files=()
    while IFS= read -r f; do
        files+=("$f")
    done < <(find /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers /etc/sudoers.d \
                -maxdepth 1 -type f -newermt "@$CUTOFF_EPOCH" 2>/dev/null || true)
    print_subheader "Account Files Modified in Window"
    for f in "${files[@]}"; do
        printf '    %b%s%b  modified %s\n' "$C_YELLOW" "$(sanitize "$f")" "$C_RESET" "$(date -r "$f" '+%Y-%m-%d %H:%M:%S')"
        rec_row table "File|Modified" "$f" "$(date -r "$f" '+%Y-%m-%d %H:%M:%S')"
        changed=$((changed + 1))
        [[ "$f" == /etc/sudoers* ]] && sudoers_changed=$((sudoers_changed + 1))
    done
    [[ "$changed" -gt 0 ]] || print_none
    stat_set account_files_modified "$changed"
    if [[ "$sudoers_changed" -gt 0 ]]; then
        add_finding 2 accounts "sudoers configuration modified in window ($sudoers_changed file(s))"
    fi
    return 0
}

# ┌────────────────────────────────────────────────────────────────────────────┐
# │ Analysis: Web Applications                                                 │
# └────────────────────────────────────────────────────────────────────────────┘

# Each request is counted once, in the first matching category.
WEB_AWK=$(cat <<'AWK'
{
    line = tolower($0); ip = $1; req = ""; status = ""
    q = index(line, "\"")
    if (q) {
        rest = substr(line, q + 1); q2 = index(rest, "\"")
        if (q2) { req = substr(rest, 1, q2 - 1); split(substr(rest, q2 + 1), f, " "); status = f[1] }
    }
    total++
    if (status ~ /^4/) e4++
    else if (status ~ /^5/) e5++

    cat = ""
    if (line ~ /[$][{]jndi:|%24%7bjndi/) cat = "jndi"
    else if (req ~ /\.\.\/|\.\.%2f|%2e%2e(\/|%2f)|\.\.\\/) cat = "traversal"
    else if (req ~ /etc\/passwd|etc%2fpasswd|etc\/shadow|proc\/self\/environ|win\.ini|boot\.ini/) cat = "lfi"
    else if (req ~ /(cmd|exec|command)=|shell_exec|passthru|system\(|\/bin\/(ba)?sh|%2fbin%2f(ba)?sh|;(\+|%20)*(id|wget|curl|uname)([^a-z]|$)/) cat = "cmdi"
    else if (req ~ /union(\+|%20| |\/\*\*\/)+(all(\+|%20| )+)?select|information_schema|sleep\(|benchmark\(|(\+|%20| )or(\+|%20| )+1=1|%27(\+|%20)*or(\+|%20)/) cat = "sqli"
    else if (req ~ /<script|%3cscript|javascript:|onerror=|onload=|%3csvg/) cat = "xss"
    else if (req ~ /\/\.env|\/\.git\/|\/\.aws\/|\/\.ssh\/|\/\.htpasswd|wp-config\.php|\.sql( |\?)|\.bak( |\?)/) cat = "sensitive"
    else if (req ~ /(c99|r57|wso|shell|cmd)\.php|\/cgi-bin\/.*\.(sh|cgi|pl)/) cat = "webshell"
    else if (req ~ /\/wp-login\.php|\/xmlrpc\.php|\/phpmyadmin|\/pma\/|\/administrator\/|\/wp-admin\/setup-config/ && status ~ /^(401|403|404)$/) cat = "cms"
    else if (line ~ /sqlmap|nikto|masscan|zgrab|nuclei|acunetix|dirbuster|gobuster|wpscan|nmap scripting engine|fuzz faster/) cat = "scanner"

    if (cat != "") {
        c[cat]++; attacks++; ipc[ip]++
        if (status ~ /^2/ && cat ~ /^(jndi|traversal|lfi|cmdi|sqli|sensitive|webshell)$/) { ok[cat]++; okn++ }
    }
}
END {
    printf "SUM\t%d\t%d\t%d\t%d\t%d\n", total, attacks, okn, e4, e5
    for (k in c) print "CAT\t" k "\t" c[k] "\t" (ok[k] + 0)
    for (i in ipc) print "IP\t" i "\t" ipc[i]
}
AWK
)
readonly WEB_AWK

web_category_name() {
    case "$1" in
        jndi)      echo "Log4Shell / JNDI injection" ;;
        traversal) echo "Path traversal" ;;
        lfi)       echo "Local file inclusion" ;;
        cmdi)      echo "Command injection" ;;
        sqli)      echo "SQL injection" ;;
        xss)       echo "Cross-site scripting" ;;
        sensitive) echo "Sensitive file probing" ;;
        webshell)  echo "Web shell access" ;;
        cms)       echo "CMS/admin panel probing" ;;
        scanner)   echo "Vulnerability scanner" ;;
        *)         echo "$1" ;;
    esac
}

section_web() {
    print_header "WEB APPLICATION ATTACKS" "$SYM_ALERT"

    ensure_source web
    if [[ "${SOURCE_OK[web]}" -eq 0 ]]; then
        print_alert 0 "No web server access logs found"
        return 0
    fi

    local out="$WORKDIR/web.analysis"
    awk "$WEB_AWK" "$(source_log web)" > "$out"

    local total attacks okn e4 e5
    IFS="$TAB" read -r _ total attacks okn e4 e5 < <(grep '^SUM' "$out")

    stat_set web_requests "$total"
    stat_set web_attack_requests "$attacks"
    stat_set web_attacks_2xx "$okn"
    stat_set web_4xx "$e4"
    stat_set web_5xx "$e5"
    TOTAL_SUSPICIOUS=$((TOTAL_SUSPICIOUS + attacks))

    print_subheader "Summary"
    print_stat "Requests in window" "$total"
    print_stat "Malicious requests" "$attacks"
    print_stat "Attacks answered with 2xx" "$okn"
    print_stat "4xx client errors" "$e4"
    print_stat "5xx server errors" "$e5"

    if [[ "$attacks" -eq 0 ]]; then
        print_alert 0 "No web attack patterns detected"
        return 0
    fi

    print_subheader "Attack Categories"
    local kind cat count ok
    while IFS="$TAB" read -r kind cat count ok; do
        printf '    %b%-32s%b %7d requests' "$C_ORANGE" "$(web_category_name "$cat")" "$C_RESET" "$count"
        if [[ "$ok" -gt 0 ]]; then
            printf '  %b(%d answered 2xx)%b' "$C_RED" "$ok" "$C_RESET"
        fi
        echo
        rec_row table "Category|Requests|Answered 2xx" "$(web_category_name "$cat")" "$count" "$ok"
    done < <(grep '^CAT' "$out" | sort -t "$TAB" -k3,3nr)

    print_subheader "Top Attack Sources"
    local ip flagged=0
    while IFS="$TAB" read -r kind ip count; do
        print_ip_entry "$ip" "$count" "malicious requests"
    done < <(grep '^IP' "$out" | sort -t "$TAB" -k3,3nr | top_n)
    while IFS="$TAB" read -r kind ip count; do
        flag_ip "$ip" "web attacks ($count requests)"
        flagged=$((flagged + 1))
    done < <(awk -F'\t' -v t="$WEB_IP_THRESHOLD" '$1 == "IP" && $3 >= t' "$out")

    local sources
    sources=$(grep -c '^IP' "$out") || sources=0
    add_finding 1 web "$attacks malicious web requests from $sources source(s)"
    if [[ "$okn" -gt 0 ]]; then
        add_finding 2 web "$okn attack request(s) received a 2xx response - verify they did not succeed"
    fi
    return 0
}

# ┌────────────────────────────────────────────────────────────────────────────┐
# │ Analysis: Persistence (cron, systemd, SSH keys, preload, SUID)             │
# └────────────────────────────────────────────────────────────────────────────┘

readonly PERSIST_RE='/dev/(tcp|udp)/|bash -i|sh -i|(^|[ /;|])nc(at)? [^|;]*-[ec] |mkfifo|socat .*exec|base64 (-d|--decode)|(curl|wget) [^|;]*\|[[:space:]]*(ba|z|da)?sh|python[0-9.]* -c|perl -e|/dev/shm/|xmrig|minerd|stratum\+tcp'

section_persistence() {
    print_header "PERSISTENCE & SCHEDULED TASKS" "$SYM_GEAR"

    print_subheader "Cron Activity"
    ensure_source syslog
    if [[ "${SOURCE_OK[syslog]}" -eq 1 ]]; then
        local log cron_jobs cron_errors
        log=$(source_log syslog)
        cron_jobs=$(count_re 'CRON\[[0-9]+\]|crond\[[0-9]+\]' "$log")
        cron_errors=$(count_re '(CRON|crond).*(error|ERROR)|crontab.*error' "$log")
        stat_set cron_executions "$cron_jobs"
        stat_set cron_errors "$cron_errors"
        print_stat "Cron executions" "$cron_jobs"
        print_stat "Cron errors" "$cron_errors"
    else
        print_alert 0 "No syslog source available"
    fi

    local f dir count
    local -a cron_files=() recent=() suspicious=()

    print_subheader "Crontab Inventory"
    for dir in /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly \
               /var/spool/cron/crontabs /var/spool/cron; do
        [[ -e "$dir" ]] || continue
        count=0
        while IFS= read -r f; do
            cron_files+=("$f")
            count=$((count + 1))
        done < <(find "$dir" -maxdepth 1 -type f 2>/dev/null || true)
        printf '    %b%-35s%b %s file(s)\n' "$C_GREY" "$dir" "$C_RESET" "$count"
    done

    # Scheduled/startup definitions that are checked for malicious content
    local -a startup_files=("${cron_files[@]}")
    while IFS= read -r f; do
        startup_files+=("$f")
    done < <(find /etc/systemd/system /home/*/.config/systemd/user /root/.config/systemd/user \
                -maxdepth 2 -type f \( -name '*.service' -o -name '*.timer' \) 2>/dev/null || true)
    [[ -f /etc/rc.local ]] && startup_files+=("/etc/rc.local")

    for f in "${startup_files[@]}"; do
        if [[ -r "$f" ]] && grep -qE -e "$PERSIST_RE" -- "$f" 2>/dev/null; then
            suspicious+=("$f")
        fi
        if [[ -n "$(find "$f" -maxdepth 0 -newermt "@$CUTOFF_EPOCH" 2>/dev/null)" ]]; then
            recent+=("$f")
        fi
    done

    print_subheader "Suspicious Cron / systemd / rc.local Entries"
    if [[ ${#suspicious[@]} -gt 0 ]]; then
        for f in "${suspicious[@]}"; do
            printf '    %b%s%b %s\n' "$C_RED" "$SYM_ALERT" "$C_RESET" "$(sanitize "$f")"
            if [[ "$VERBOSE" -eq 1 ]]; then
                grep -nE -e "$PERSIST_RE" -- "$f" 2>/dev/null | head -n 3 | while IFS= read -r line; do
                    printf '        %s\n' "$(sanitize "$line")"
                done
            fi
        done
        add_finding 3 persistence "${#suspicious[@]} scheduled/startup file(s) contain reverse-shell, download-and-execute or miner patterns"
    else
        print_none
    fi

    print_subheader "Scheduled / Startup Files Modified in Window"
    if [[ ${#recent[@]} -gt 0 ]]; then
        for f in "${recent[@]}"; do
            printf '    %b%s%b  modified %s\n' "$C_YELLOW" "$(sanitize "$f")" "$C_RESET" "$(date -r "$f" '+%Y-%m-%d %H:%M:%S')"
        done
        add_finding 1 persistence "${#recent[@]} cron/systemd/rc.local file(s) modified in window"
    else
        print_none
    fi

    # SSH authorized_keys changes
    print_subheader "SSH authorized_keys Modified in Window"
    local -a keys=()
    while IFS= read -r f; do
        keys+=("$f")
    done < <(find /root/.ssh /home/*/.ssh -maxdepth 1 -type f -name 'authorized_keys*' -newermt "@$CUTOFF_EPOCH" 2>/dev/null || true)
    if [[ ${#keys[@]} -gt 0 ]]; then
        for f in "${keys[@]}"; do
            printf '    %b%s%b  modified %s\n' "$C_ORANGE" "$(sanitize "$f")" "$C_RESET" "$(date -r "$f" '+%Y-%m-%d %H:%M:%S')"
        done
        add_finding 2 persistence "${#keys[@]} authorized_keys file(s) changed in window - verify new SSH keys"
    else
        print_none
    fi
    stat_set authorized_keys_modified "${#keys[@]}"

    # Rootkit-style indicators
    print_subheader "Host Integrity Indicators"
    if [[ -s /etc/ld.so.preload ]]; then
        add_finding 3 persistence "/etc/ld.so.preload is in use (common userland rootkit technique): $(sanitize "$(head -c 200 /etc/ld.so.preload | tr '\n' ' ')")"
    else
        print_stat "/etc/ld.so.preload" "not used"
    fi

    local -a suid=() shm_exec=()
    while IFS= read -r f; do
        suid+=("$f")
    done < <(find /tmp /var/tmp /dev/shm -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null || true)
    while IFS= read -r f; do
        shm_exec+=("$f")
    done < <(find /dev/shm -xdev -type f -perm /111 2>/dev/null || true)

    print_stat "SUID/SGID files in temp dirs" "${#suid[@]}"
    print_stat "Executables in /dev/shm" "${#shm_exec[@]}"
    stat_set tmp_suid_files "${#suid[@]}"
    stat_set shm_executables "${#shm_exec[@]}"

    for f in "${suid[@]}"; do
        print_line "$(sanitize "$f")"
    done
    if [[ ${#suid[@]} -gt 0 ]]; then
        add_finding 3 persistence "${#suid[@]} SUID/SGID file(s) in world-writable temp directories"
    fi
    if [[ ${#shm_exec[@]} -gt 0 ]]; then
        add_finding 2 persistence "${#shm_exec[@]} executable file(s) in /dev/shm"
    fi
    return 0
}

# ┌────────────────────────────────────────────────────────────────────────────┐
# │ Analysis: Kernel                                                           │
# └────────────────────────────────────────────────────────────────────────────┘

section_kernel() {
    print_header "KERNEL LOG EVENTS" "$SYM_SHIELD"

    ensure_source kern
    if [[ "${SOURCE_OK[kern]}" -eq 0 ]]; then
        print_alert 0 "No kernel log source available"
        return 0
    fi

    local log segfaults oom apparmor selinux usb promisc taint
    log=$(source_log kern)
    segfaults=$(count_re 'segfault at|general protection( fault)?' "$log")
    oom=$(count_re 'Out of memory|oom-kill' "$log")
    apparmor=$(count_re 'apparmor="DENIED"' "$log")
    selinux=$(count_re 'avc: +denied' "$log")
    usb=$(count_re 'New USB device found|new [a-zA-Z-]+ USB device number' "$log")
    promisc=$(count_re 'entered promiscuous mode' "$log")
    taint=$(count_re 'module verification failed|taints kernel|loading out-of-tree module' "$log")

    stat_set kernel_segfaults "$segfaults"
    stat_set kernel_oom_kills "$oom"
    stat_set apparmor_denials "$apparmor"
    stat_set selinux_denials "$selinux"
    stat_set usb_devices "$usb"
    stat_set promiscuous_mode "$promisc"
    stat_set kernel_taint_events "$taint"

    print_subheader "Security-Related Kernel Events"
    print_stat "Segfaults / protection faults" "$segfaults"
    print_stat "OOM kills" "$oom"
    print_stat "AppArmor denials" "$apparmor"
    print_stat "SELinux denials" "$selinux"
    print_stat "Interfaces in promiscuous mode" "$promisc"
    print_stat "Unsigned / out-of-tree modules" "$taint"
    print_stat "USB device connections" "$usb"

    if [[ "$segfaults" -ge 10 ]]; then
        add_finding 1 kernel "$segfaults segfaults (possible exploitation attempts or unstable software)"
    fi
    if [[ "$promisc" -gt 0 ]]; then
        add_finding 2 kernel "Network interface entered promiscuous mode $promisc time(s) - possible packet sniffing"
    fi
    if [[ "$taint" -gt 0 ]]; then
        add_finding 1 kernel "Unsigned or out-of-tree kernel module loaded $taint time(s)"
    fi
    if [[ "$apparmor" -ge 50 || "$selinux" -ge 50 ]]; then
        add_finding 1 kernel "High number of MAC denials (AppArmor: $apparmor, SELinux: $selinux)"
    fi

    if [[ "$VERBOSE" -eq 1 && "$usb" -gt 0 ]]; then
        print_subheader "Recent USB Devices"
        grep -E 'New USB device found|new [a-zA-Z-]+ USB device number' "$log" | tail -n 5 | awk '{ gsub(/[^ -~]/, "?"); print "    " $0 }'
    fi
    return 0
}

# ┌────────────────────────────────────────────────────────────────────────────┐
# │ Audit: System                                                              │
# └────────────────────────────────────────────────────────────────────────────┘

section_system() {
    print_header "SYSTEM INFORMATION" "$SYM_INFO"

    local os arch virt cpu cores up_s boot load
    os=$(awk -F= '$1 == "PRETTY_NAME" { gsub(/"/, "", $2); print $2 }' /etc/os-release 2>/dev/null) || os=""
    arch=$(uname -m)
    virt=$(systemd-detect-virt 2>/dev/null) || true
    cpu=$(awk -F': *' '/^model name/ { print $2; exit }' /proc/cpuinfo 2>/dev/null) || cpu=""
    if [[ -z "$cpu" ]] && have lscpu; then
        cpu=$(lscpu 2>/dev/null | awk -F': +' '/^Vendor ID/ { v = $2 } /^Model name/ && $2 != "-" { m = $2 }
                                             END { print (m != "" ? m : v) }') || cpu=""
    fi
    cores=$(nproc 2>/dev/null) || cores=0
    up_s=$(awk '{ printf "%d", $1 }' /proc/uptime 2>/dev/null) || up_s=0
    boot=$(date -d "@$(( $(date +%s) - up_s ))" '+%Y-%m-%d %H:%M')
    load=$(awk '{ print $1 " / " $2 " / " $3 }' /proc/loadavg 2>/dev/null) || load=""

    local mem_kb avail_kb swap_kb swapfree_kb
    IFS="$TAB" read -r mem_kb avail_kb swap_kb swapfree_kb < <(awk '
        $1 == "MemTotal:" { t = $2 } $1 == "MemAvailable:" { a = $2 }
        $1 == "SwapTotal:" { s = $2 } $1 == "SwapFree:" { f = $2 }
        END { printf "%d\t%d\t%d\t%d\n", t, a, s, f }' /proc/meminfo 2>/dev/null)

    SYS_OS="${os:-unknown}"
    SYS_UPTIME=$(fmt_duration "$up_s")

    print_subheader "Host"
    print_stat "Hostname" "$HOSTNAME_FQDN"
    print_stat "Operating system" "$SYS_OS"
    print_stat "Kernel" "$SYS_KERNEL ($arch)"
    print_stat "Virtualization" "${virt:-none}"
    print_stat "CPU" "${cpu:-unknown} ($cores cores)"
    print_stat "Memory" "$(human_bytes $((mem_kb * 1024))) total, $(human_bytes $((avail_kb * 1024))) available"
    print_stat "Swap" "$(human_bytes $((swap_kb * 1024))) total, $(human_bytes $(( (swap_kb - swapfree_kb) * 1024 ))) used"
    print_stat "Load average (1/5/15 min)" "$load"
    print_stat "Uptime" "$SYS_UPTIME (booted $boot)"
    stat_set uptime_days $((up_s / 86400))
    stat_set cpu_cores "$cores"
    stat_set memory_total_mib $((mem_kb / 1024))

    # Time: reliable timestamps matter for log correlation
    if have timedatectl; then
        local k v tz="" ntp="" ntp_on=""
        while IFS='=' read -r k v; do
            case "$k" in
                Timezone) tz="$v" ;;
                NTPSynchronized) ntp="$v" ;;
                NTP) ntp_on="$v" ;;
            esac
        done < <(timeout 5 timedatectl show 2>/dev/null || true)
        if [[ -n "$ntp$tz" ]]; then
            print_subheader "Time"
            print_stat "Time zone" "${tz:-unknown}"
            print_stat "NTP enabled" "${ntp_on:-unknown}"
            print_stat "Clock synchronized" "${ntp:-unknown}"
            if [[ "$ntp" == "no" ]]; then
                add_finding 1 system "System clock is not NTP-synchronized; log timestamps may be unreliable"
                add_rec "Enable time synchronization: sudo timedatectl set-ntp true (systemd-timesyncd or chrony)"
            fi
        fi
    fi

    # Disk usage: a full /var stops logging
    tbl_new "Disk Usage" "Mount" "Device" "Type" "Size" "Used" "Free" "Use%"
    local src fstype size used avail pct mnt
    local -a full=()
    while IFS=' ' read -r src fstype size used avail pct mnt; do
        [[ -n "$mnt" ]] || continue
        tbl_row "$mnt" "$src" "$fstype" "$(human_bytes $((size * 1024)))" "$(human_bytes $((used * 1024)))" \
            "$(human_bytes $((avail * 1024)))" "$pct"
        if [[ "${pct%\%}" =~ ^[0-9]+$ && "${pct%\%}" -ge 90 ]]; then
            full+=("$mnt ($pct)")
        fi
    done < <(df -PTk -x tmpfs -x devtmpfs -x squashfs -x overlay -x efivarfs 2>/dev/null | tail -n +2)
    tbl_end
    if [[ ${#full[@]} -gt 0 ]]; then
        add_finding 1 system "File system(s) at 90%+ capacity (logging may stop): $(join ', ' "${full[@]}")"
    fi

    # Errors logged since boot, grouped by source
    if journal_ok; then
        local errs="$WORKDIR/journal.errors" count total=0
        journalctl -b -p 3 -q --no-pager -o short-iso 2>/dev/null |
            awk '{ s = $3; sub(/\[[0-9]+\]:$/, "", s); sub(/:$/, "", s); print s }' | tally > "$errs" || true
        total=$(awk -F'\t' '{ s += $1 } END { print s + 0 }' "$errs")
        stat_set journal_errors_boot "$total"
        tbl_new "Error-Level Journal Messages Since Boot" "Messages" "Source"
        while IFS="$TAB" read -r count src; do
            tbl_row "$count" "$src"
        done < "$errs"
        tbl_end 10
        if [[ "$IS_ROOT" -eq 0 ]]; then
            print_line "(without root only messages visible to your user are counted)"
        fi
    fi
    return 0
}

# ┌────────────────────────────────────────────────────────────────────────────┐
# │ Audit: Packages & Updates                                                  │
# └────────────────────────────────────────────────────────────────────────────┘

# Server packages for cleartext or unauthenticated legacy services
readonly LEGACY_PKGS_RE='^(telnetd|inetutils-telnetd|telnetd-ssl|telnet-server|rsh-server|rsh-redone-server|rlogin|nis|ypserv|ypbind|tftpd|tftpd-hpa|atftpd|tftp-server|talkd|inetutils-talkd|xinetd)$'
# Packages whose files are verified against the package checksums by default
readonly CORE_PKGS="openssh-server openssh-client sudo passwd login coreutils util-linux procps bash dash libpam-modules libpam-modules-bin libpam-runtime systemd iproute2 net-tools findutils grep sed tar gzip cron openssl libc-bin"

# pkg.events: date time <TAB> action <TAB> package <TAB> old version <TAB> new version
prepare_pkg_events() {
    [[ -f "$WORKDIR/pkg.events" ]] && return 0
    : > "$WORKDIR/pkg.events"
    if [[ -e /var/log/dpkg.log ]]; then
        collect_files "$WORKDIR/dpkg.log" /var/log/dpkg.log
        awk '$3 == "install" || $3 == "upgrade" || $3 == "remove" || $3 == "purge" {
                p = $4; sub(/:.*/, "", p); print $1 " " $2 "\t" $3 "\t" p "\t" $5 "\t" $6 }' \
            "$WORKDIR/dpkg.log" > "$WORKDIR/pkg.events"
    elif [[ -e /var/log/dnf.rpm.log ]]; then
        collect_files "$WORKDIR/dnf.log" /var/log/dnf.rpm.log
        awk '{ if (match($0, / (Installed|Upgraded|Erased|Upgrade|Installed): /)) {
                 a = tolower(substr($0, RSTART + 1, RLENGTH - 3)); p = substr($0, RSTART + RLENGTH)
                 print substr($1, 1, 10) " " substr($1, 12, 8) "\t" a "\t" p "\t-\t-" } }' \
            "$WORKDIR/dnf.log" > "$WORKDIR/pkg.events"
    fi
}

# pkg_owners — reads paths on stdin, prints "path<TAB>package" ("-" if unowned)
pkg_owners() {
    local -a paths=()
    local p
    while IFS= read -r p; do
        [[ -n "$p" ]] && paths+=("$p")
    done
    [[ ${#paths[@]} -gt 0 ]] || return 0
    if have dpkg; then
        local -A owner=()
        local line pk path alias
        while IFS= read -r line; do
            [[ "$line" == diversion* || "$line" != *": /"* ]] && continue
            pk="${line%%: /*}"; path="/${line#*: /}"
            owner[$path]="$pk"
        done < <(dpkg -S -- "${paths[@]}" 2>/dev/null)
        # merged /usr: dpkg may know a file only by its /bin, /sbin or /lib alias
        local -a aliases=()
        for p in "${paths[@]}"; do
            if [[ -z "${owner[$p]:-}" ]]; then
                case "$p" in
                    /usr/bin/*|/usr/sbin/*|/usr/lib/*|/usr/lib64/*) aliases+=("${p#/usr}") ;;
                    /bin/*|/sbin/*|/lib/*|/lib64/*) aliases+=("/usr$p") ;;
                esac
            fi
        done
        if [[ ${#aliases[@]} -gt 0 ]]; then
            while IFS= read -r line; do
                [[ "$line" == diversion* || "$line" != *": /"* ]] && continue
                pk="${line%%: /*}"; path="/${line#*: /}"
                case "$path" in
                    /usr/*) alias="${path#/usr}" ;;
                    *) alias="/usr$path" ;;
                esac
                owner[$alias]="$pk"
            done < <(dpkg -S -- "${aliases[@]}" 2>/dev/null)
        fi
        for p in "${paths[@]}"; do
            printf '%s\t%s\n' "$p" "${owner[$p]:--}"
        done
    elif have rpm; then
        for p in "${paths[@]}"; do
            printf '%s\t%s\n' "$p" "$(rpm -qf --qf '%{NAME}\n' -- "$p" 2>/dev/null | head -n 1 | grep -v 'not owned' || echo -)"
        done
    else
        for p in "${paths[@]}"; do
            printf '%s\t?\n' "$p"
        done
    fi
}

section_packages() {
    print_header "PACKAGES & UPDATES" "$SYM_GEAR"

    local dpkg_total=0 dpkg_rc=0 dpkg_broken=0 rpm_total=0 snap_total=0 flatpak_total=0 total
    if have dpkg-query; then
        IFS="$TAB" read -r dpkg_total dpkg_rc dpkg_broken < <(dpkg-query -W -f '${db:Status-Abbrev}\n' 2>/dev/null | awk '
            /^ii/ { i++ } /^rc/ { r++ }
            substr($0, 2, 1) ~ /[UHFWt]/ || substr($0, 3, 1) == "R" { b++ }
            END { printf "%d\t%d\t%d\n", i, r, b }')
    fi
    if have rpm && ! have dpkg-query; then
        rpm_total=$(rpm -qa 2>/dev/null | wc -l)
    fi
    if have snap; then
        snap_total=$(timeout 20 snap list 2>/dev/null | awk 'NR > 1' | wc -l)
    fi
    if have flatpak; then
        flatpak_total=$(timeout 20 flatpak list --columns=application 2>/dev/null | wc -l)
    fi
    total=$((dpkg_total + rpm_total + snap_total + flatpak_total))

    tbl_new "Installed Packages" "Source" "Packages"
    [[ "$dpkg_total" -gt 0 ]] && tbl_row "dpkg / apt" "$dpkg_total"
    [[ "$rpm_total" -gt 0 ]] && tbl_row "rpm" "$rpm_total"
    have snap && tbl_row "snap" "$snap_total"
    have flatpak && tbl_row "flatpak" "$flatpak_total"
    tbl_row "Total" "$total"
    tbl_end
    [[ "$dpkg_rc" -gt 0 ]] && print_stat "Removed, config files left (rc)" "$dpkg_rc"
    stat_set packages_installed "$total"
    stat_set packages_dpkg "$dpkg_total"
    stat_set packages_snap "$snap_total"
    stat_set packages_broken "$dpkg_broken"
    if [[ "$dpkg_broken" -gt 0 ]]; then
        add_finding 1 packages "$dpkg_broken package(s) are half-installed or broken (dpkg --audit)"
    fi

    # Pending updates
    local pending=0 security=0 age_days=""
    print_subheader "Updates"
    if have apt-get; then
        if [[ "$ONLINE" -eq 1 ]]; then
            if [[ "$IS_ROOT" -eq 1 ]]; then
                timeout 300 apt-get update -qq >/dev/null 2>&1 || warn "apt-get update failed; update counts may be stale"
            else
                warn "Refreshing package lists (--online) needs root"
            fi
        fi
        local newest
        newest=$(find /var/lib/apt/lists -maxdepth 1 -type f -name '*Release' -printf '%T@\n' 2>/dev/null | sort -n | tail -n 1)
        newest="${newest%.*}"
        if [[ -n "$newest" ]]; then
            age_days=$(( ($(date +%s) - newest) / 86400 ))
        fi
        timeout 120 apt-get -s -o Debug::NoLocking=1 dist-upgrade 2>/dev/null | awk '
            /^Inst / {
                cur = "-"; if ($3 ~ /^\[/) { cur = $3; gsub(/[][]/, "", cur) }
                new = "-"; if (match($0, /\([^ ]+/)) new = substr($0, RSTART + 1, RLENGTH - 1)
                print $2 "\t" cur "\t" new "\t" (($0 ~ /-security/) ? "yes" : "no")
            }' | sort -t "$TAB" -k4,4r -k1,1 > "$WORKDIR/updates.tsv" || true
    elif have dnf; then
        local -a dnf_opts=(-q)
        [[ "$ONLINE" -eq 1 ]] || dnf_opts+=(-C)
        timeout 120 dnf "${dnf_opts[@]}" check-update 2>/dev/null |
            awk 'NF == 3 && $1 ~ /\./ { print $1 "\t-\t" $2 "\tno" }' > "$WORKDIR/updates.tsv" || true
        security=$(timeout 120 dnf "${dnf_opts[@]}" updateinfo list --security 2>/dev/null | awk 'NF >= 3' | wc -l) || security=0
    fi
    if [[ -f "$WORKDIR/updates.tsv" ]]; then
        pending=$(wc -l < "$WORKDIR/updates.tsv")
        if have apt-get; then
            security=$(awk -F'\t' '$4 == "yes"' "$WORKDIR/updates.tsv" | wc -l)
        fi
        print_stat "Pending updates" "$pending"
        print_stat "Pending security updates" "$security"
        if [[ -n "$age_days" ]]; then
            print_stat "Package lists age" "$age_days day(s)"
            if [[ "$age_days" -gt 7 ]]; then
                add_rec "Package lists are $age_days days old; run 'sudo apt update' (or use --online) for accurate update counts"
            fi
        fi
        stat_set updates_pending "$pending"
        stat_set updates_security "$security"
        if [[ "$pending" -gt 0 ]]; then
            tbl_new "Pending Updates" "Package" "Installed" "Candidate" "Security"
            local pkg cur new sec
            while IFS="$TAB" read -r pkg cur new sec; do
                tbl_row "$pkg" "$cur" "$new" "$sec"
            done < "$WORKDIR/updates.tsv"
            tbl_end
        fi
        if [[ "$security" -gt 0 ]]; then
            add_finding 2 packages "$security security update(s) pending"
            add_rec "Install pending security updates (sudo apt upgrade / sudo dnf upgrade --security)"
        fi
    else
        print_alert 0 "No supported package manager for update checks (apt, dnf)"
    fi

    # Automatic updates
    if have apt-config; then
        local uu_pkg="no" uu_on
        if dpkg-query -W -f '${db:Status-Abbrev}' unattended-upgrades 2>/dev/null | grep -q '^ii'; then
            uu_pkg="yes"
        fi
        uu_on=$(apt-config dump 2>/dev/null | awk -F'"' '/^APT::Periodic::Unattended-Upgrade / { v = $2 } END { print v }')
        if [[ "$uu_pkg" == "yes" && "${uu_on:-0}" != "0" ]]; then
            UU_STATE="enabled"
        elif [[ "$uu_pkg" == "yes" ]]; then
            UU_STATE="installed, disabled"
        else
            UU_STATE="not installed"
        fi
    elif have systemctl && systemctl list-unit-files dnf-automatic.timer >/dev/null 2>&1; then
        UU_STATE="dnf-automatic $(systemctl is-enabled dnf-automatic.timer 2>/dev/null || echo disabled)"
    fi
    if [[ -n "$UU_STATE" ]]; then
        print_stat "Automatic security updates" "$UU_STATE"
        if [[ "$UU_STATE" != "enabled" && "$UU_STATE" != *" enabled" ]]; then
            add_finding 1 packages "Automatic security updates are not enabled ($UU_STATE)"
            add_rec "Enable automatic security updates: sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades"
        fi
    fi
    if have apt-mark; then
        print_stat "Held packages" "$(apt-mark showhold 2>/dev/null | wc -l)"
    fi

    # Reboot needed to activate updates
    local newest_k reboot_pkgs=""
    newest_k=$(find /boot -maxdepth 1 -name 'vmlinuz-*' -printf '%f\n' 2>/dev/null | sed 's/^vmlinuz-//' | sort -V | tail -n 1)
    print_stat "Running kernel" "$SYS_KERNEL"
    print_stat "Newest installed kernel" "${newest_k:-unknown}"
    if [[ -f /run/reboot-required ]]; then
        reboot_pkgs=$(sort -u /run/reboot-required.pkgs 2>/dev/null | paste -sd' ' -) || true
        print_stat "Reboot required" "yes${reboot_pkgs:+ ($reboot_pkgs)}"
        add_finding 1 packages "Restart required to activate installed updates${reboot_pkgs:+ ($reboot_pkgs)}"
    fi
    if [[ -n "$newest_k" && "$newest_k" != "$SYS_KERNEL" ]] && [[ "$(printf '%s\n%s\n' "$SYS_KERNEL" "$newest_k" | sort -V | tail -n 1)" == "$newest_k" ]]; then
        add_finding 1 packages "Running kernel $SYS_KERNEL is older than installed kernel $newest_k; reboot to activate its security fixes"
    fi

    # Legacy insecure servers
    if have dpkg-query; then
        local legacy
        legacy=$(dpkg-query -W -f '${db:Status-Abbrev}\t${Package}\n' 2>/dev/null |
                 awk -F'\t' -v re="$LEGACY_PKGS_RE" '$1 ~ /^ii/ && $2 ~ re { print $2 }' | paste -sd, -) || legacy=""
        if [[ -n "$legacy" ]]; then
            add_finding 2 packages "Legacy cleartext/unauthenticated service packages installed: ${legacy//,/, }"
            add_rec "Remove legacy service packages unless required: sudo apt purge ${legacy//,/ }"
        fi
    fi
    local tools="" t
    for t in gcc cc clang make as gdb; do
        have "$t" && tools+="${tools:+, }$t"
    done
    print_stat "Compilers / build tools" "${tools:-none}"

    # Package activity inside the analysis window
    prepare_pkg_events
    local changes
    changes=$(wc -l < "$WORKDIR/pkg.events")
    stat_set packages_changed_window "$changes"
    if [[ "$changes" -gt 0 ]]; then
        tbl_new "Package Changes in Window (most recent first)" "Time" "Action" "Package" "From" "To"
        local ts action pkg from to
        while IFS="$TAB" read -r ts action pkg from to; do
            tbl_row "$ts" "$action" "$pkg" "$from" "$to"
        done < <(tac "$WORKDIR/pkg.events")
        tbl_end
    else
        print_subheader "Package Changes in Window"
        print_alert 0 "No packages installed, upgraded or removed in window"
    fi

    # Integrity of installed files (dpkg -V is like debsums)
    if have dpkg; then
        local -a verify=()
        local label
        if [[ "$DEEP_SCAN" -eq 1 ]]; then
            label="all packages"
        else
            local -a core=()
            IFS=' ' read -r -a core <<< "$CORE_PKGS"
            while IFS= read -r t; do
                verify+=("$t")
            done < <(dpkg-query -W -f '${db:Status-Abbrev}\t${Package}\n' "${core[@]}" 2>/dev/null | awk '$1 ~ /^ii/ { print $2 }')
            label="${#verify[@]} core packages (all with --deep)"
        fi
        if [[ "$DEEP_SCAN" -eq 1 || ${#verify[@]} -gt 0 ]]; then
            timeout 900 dpkg -V "${verify[@]}" 2>/dev/null > "$WORKDIR/dpkg.verify" || true
        else
            : > "$WORKDIR/dpkg.verify"
        fi
        local modified conf_mod
        awk '{ flags = $1; conf = ($2 == "c"); path = conf ? $3 : $2
               if (flags == "missing") type = "missing"
               else if (substr(flags, 3, 1) == "5") type = conf ? "conffile changed" : "CONTENT CHANGED"
               else next
               if (type == "missing" && path ~ /^\/usr\/share\/(doc|man|info|locale|lintian)\//) next
               print path "\t" type "\t" flags }' "$WORKDIR/dpkg.verify" > "$WORKDIR/dpkg.changed"
        modified=$(awk -F'\t' '$2 == "CONTENT CHANGED"' "$WORKDIR/dpkg.changed" | wc -l)
        conf_mod=$(awk -F'\t' '$2 == "conffile changed"' "$WORKDIR/dpkg.changed" | wc -l)
        print_subheader "Package File Integrity"
        print_stat "Verified" "$label"
        print_stat "Files with changed content" "$modified"
        print_stat "Locally modified config files" "$conf_mod"
        stat_set package_files_modified "$modified"
        if [[ -s "$WORKDIR/dpkg.changed" ]]; then
            tbl_new "Files Differing from Package Checksums" "Path" "Change" "dpkg flags"
            local path type flags
            while IFS="$TAB" read -r path type flags; do
                tbl_row "$path" "$type" "$flags"
            done < <(sort -t "$TAB" -k2,2 "$WORKDIR/dpkg.changed")
            tbl_end
        fi
        if [[ "$modified" -gt 0 ]]; then
            add_finding 3 packages "$modified packaged file(s) differ from package checksums - possible tampering (verify with 'dpkg -V')"
        fi
    fi
    return 0
}

# ┌────────────────────────────────────────────────────────────────────────────┐
# │ Audit: Kernel Modules                                                      │
# └────────────────────────────────────────────────────────────────────────────┘

# Rarely needed file system and network protocol modules (CIS)
readonly RISKY_MODULES=" cramfs freevxfs jffs2 hfs hfsplus udf dccp sctp rds tipc n_hdlc "

section_modules() {
    print_header "KERNEL MODULES & TAINT" "$SYM_GEAR"

    if [[ ! -r /proc/modules ]]; then
        print_alert 0 "/proc/modules is not readable"
        return 0
    fi
    local kr="$SYS_KERNEL" total size available builtin
    IFS="$TAB" read -r total size < <(awk '{ n++; s += $2 } END { printf "%d\t%d\n", n, s }' /proc/modules)
    available=$(find "/lib/modules/$kr" -type f -name '*.ko*' 2>/dev/null | wc -l)
    builtin=$(wc -l < "/lib/modules/$kr/modules.builtin" 2>/dev/null) || builtin=0

    print_subheader "Summary"
    print_stat "Loaded modules" "$total"
    print_stat "Memory used by modules" "$(human_bytes "$size")"
    print_stat "Built-in modules" "$builtin"
    print_stat "Modules available on disk" "$available"
    print_stat "Module loading disabled" "$( [[ "$(read_first /proc/sys/kernel/modules_disabled)" == 1 ]] && echo yes || echo no)"
    stat_set kernel_modules_loaded "$total"

    # Kernel taint flags (Documentation/admin-guide/tainted-kernels.rst)
    local taint flags="" i
    local -a letters=(P F S R M B U D A W C I O E L K X T N)
    taint=$(read_first /proc/sys/kernel/tainted)
    [[ "$taint" =~ ^[0-9]+$ ]] || taint=0
    for i in "${!letters[@]}"; do
        if (( (taint >> i) & 1 )); then
            flags+="${letters[$i]}"
        fi
    done
    print_stat "Kernel taint" "$taint${flags:+ (flags: $flags)}"
    stat_set kernel_taint_value "$taint"
    if [[ "$flags" == *[FR]* ]]; then
        add_finding 2 modules "Kernel tainted by a forced module load/unload (taint flags: $flags)"
    fi
    if [[ "$flags" == *E* ]]; then
        add_finding 2 modules "An unsigned kernel module is loaded (taint flag E) - verify its origin"
    elif [[ "$flags" == *[OP]* ]]; then
        add_finding 1 modules "Kernel tainted by proprietary or out-of-tree module(s) (flags: $flags)"
    fi

    # Every loaded module should have a file under /lib/modules/<kernel>
    local -A infile=()
    local have_tree=0 m
    if [[ -d "/lib/modules/$kr" ]]; then
        have_tree=1
        while IFS= read -r m; do
            infile[$m]=1
        done < <({ find "/lib/modules/$kr" -type f -name '*.ko*' -printf '%f\n' 2>/dev/null
                   awk -F/ '{ print $NF }' "/lib/modules/$kr/modules.builtin" 2>/dev/null; } |
                 sed -E 's/\.ko(\.(xz|gz|zst))?$//; s/-/_/g' | sort -u)
    fi

    local name msize used deps state rest mt file
    local -a nofile=() tainted=() risky=()
    tbl_new "Loaded Modules (largest first)" "Module" "Size" "Used by" "Taint" "Module file"
    while IFS=' ' read -r name msize used deps state rest; do
        mt=$(read_first "/sys/module/$name/taint")
        file="n/a"
        if [[ "$have_tree" -eq 1 ]]; then
            if [[ -n "${infile[$name]:-}" ]]; then
                file="found"
            else
                file="NOT FOUND"
                nofile+=("$name")
            fi
        fi
        [[ -n "$mt" ]] && tainted+=("$name($mt)")
        [[ "$RISKY_MODULES" == *" $name "* ]] && risky+=("$name")
        [[ "$deps" == "-" ]] && deps="" || deps=" (${deps%,})"
        tbl_row "$name" "$msize" "$used$deps" "${mt:--}" "$file"
    done < <(sort -k2,2nr /proc/modules)
    tbl_end
    stat_set kernel_modules_tainted "${#tainted[@]}"
    print_stat "Tainted modules" "${#tainted[@]}${tainted[*]:+ ($(join ' ' "${tainted[@]}"))}"

    if [[ ${#nofile[@]} -gt 0 ]]; then
        add_finding 2 modules "${#nofile[@]} loaded module(s) have no file under /lib/modules/$kr (loaded from elsewhere or hidden): $(join ' ' "${nofile[@]:0:10}")"
    fi
    if [[ ${#risky[@]} -gt 0 ]]; then
        add_finding 1 modules "Rarely needed file system/protocol module(s) loaded: $(join ' ' "${risky[@]}")"
        add_rec "Disable unneeded kernel modules, e.g. 'install ${risky[0]} /bin/false' in /etc/modprobe.d/disable.conf"
    fi
    local blocked
    blocked=$(cat /etc/modprobe.d/*.conf /lib/modprobe.d/*.conf 2>/dev/null |
              awk '$1 == "blacklist" || ($1 == "install" && $3 ~ /\/(false|true)$/) { print $2 }' | sort -u | wc -l)
    print_stat "Blacklisted / disabled modules" "$blocked"
    return 0
}

# ┌────────────────────────────────────────────────────────────────────────────┐
# │ Audit: Network                                                             │
# └────────────────────────────────────────────────────────────────────────────┘

# Services that should rarely be reachable from the network: port:proto:level:name
readonly RISKY_PORTS="21:tcp:2:FTP,23:tcp:3:Telnet,69:udp:2:TFTP,111:any:1:rpcbind,135:tcp:2:MS-RPC,137:udp:1:NetBIOS,139:tcp:2:NetBIOS/SMB,445:tcp:2:SMB,512:tcp:3:rexec,513:tcp:3:rlogin,514:tcp:3:rsh,873:tcp:2:rsync daemon,1433:tcp:2:MS SQL,1521:tcp:2:Oracle DB,2049:any:2:NFS,2375:tcp:4:Docker API without TLS,2379:tcp:2:etcd,3306:tcp:2:MySQL/MariaDB,3389:tcp:1:RDP,4444:tcp:3:common backdoor port,5432:tcp:2:PostgreSQL,5900:tcp:2:VNC,5901:tcp:2:VNC,5984:tcp:2:CouchDB,6379:tcp:3:Redis,8086:tcp:2:InfluxDB,9200:tcp:2:Elasticsearch,10250:tcp:2:Kubelet API,11211:any:2:Memcached,27017:tcp:2:MongoDB,31337:tcp:3:common backdoor port"
# Remote ports typical of mining pools, IRC botnets and Tor
readonly SUSPECT_REMOTE_PORTS=" 1080 3333 3334 3357 4444 5555 6666 6667 6668 6669 6697 7777 8333 9050 9051 14433 14444 45560 45700 "

# split_hostport <addr:port> — sets HP_ADDR and HP_PORT (handles [v6]:port, %iface)
split_hostport() {
    local s="$1"
    HP_PORT="${s##*:}"
    HP_ADDR="${s%:*}"
    HP_ADDR="${HP_ADDR#[}"
    HP_ADDR="${HP_ADDR%]}"
    HP_ADDR="${HP_ADDR%%\%*}"
    HP_ADDR="${HP_ADDR#::ffff:}"
}

is_loopback() {
    [[ "$1" == 127.* || "$1" == "::1" ]]
}

# net_counters <file> — /proc/net/dev as "iface rx_bytes rx_pkts rx_errs rx_drop tx_bytes tx_pkts tx_errs tx_drop"
net_counters() {
    awk 'NR > 2 { i = index($0, ":"); n = substr($0, 1, i - 1); gsub(/ /, "", n)
                  split(substr($0, i + 1), v, " ")
                  print n "\t" v[1] "\t" v[2] "\t" v[3] "\t" v[4] "\t" v[9] "\t" v[10] "\t" v[11] "\t" v[12] }' /proc/net/dev > "$1"
}

section_network() {
    print_header "NETWORK" "$SYM_EYE"

    if ! have ss; then
        warn "ss (iproute2) is not installed; socket checks skipped"
    fi

    # Listening sockets
    local -A risky=()
    local p pr lv nm
    while IFS=':' read -r p pr lv nm; do
        risky[$p/$pr]="$lv:$nm"
    done < <(tr ',' '\n' <<< "$RISKY_PORTS")

    local lst="$WORKDIR/listen.tsv"
    : > "$lst"
    if have ss; then
        ss -Hlnptu 2>/dev/null | awk '{
            proc = "-"
            if (match($0, /users:\(\("[^"]+",pid=[0-9]+/)) {
                s = substr($0, RSTART + 9, RLENGTH - 9); split(s, a, "\",pid="); proc = a[1] " (" a[2] ")"
            }
            print $1 "\t" $5 "\t" proc }' | sort -u > "$lst"
    fi

    local proto loc proc scope svc info level exposed=0 nlisten=0
    local -A seen_port=()
    tbl_new "Listening Sockets" "Proto" "Address" "Port" "Service" "Process" "Exposure"
    while IFS="$TAB" read -r proto loc proc; do
        split_hostport "$loc"
        if is_loopback "$HP_ADDR" || [[ "$loc" == *%lo:* ]]; then
            scope="local only"
        else
            if [[ "$HP_ADDR" == "*" || "$HP_ADDR" == "0.0.0.0" || "$HP_ADDR" == "::" ]]; then
                scope="ALL interfaces"
            else
                scope="$HP_ADDR"
            fi
            exposed=$((exposed + 1))
            info="${risky[$HP_PORT/$proto]:-${risky[$HP_PORT/any]:-}}"
            if [[ -n "$info" && -z "${seen_port[$HP_PORT/$proto]:-}" ]]; then
                seen_port[$HP_PORT/$proto]=1
                level="${info%%:*}"
                add_finding "$level" network "${info#*:} ($HP_PORT/$proto) is listening on ${scope,,} - restrict it to localhost or firewall it"
            fi
        fi
        svc=$(getent services "$HP_PORT/$proto" 2>/dev/null | awk '{ print $1 }') || svc=""
        nlisten=$((nlisten + 1))
        tbl_row "$proto" "$HP_ADDR" "$HP_PORT" "${svc:--}" "$proc" "$scope"
    done < <(sort -t "$TAB" -k1,1 -k2,2 "$lst")
    tbl_end 40
    stat_set net_listening_sockets "$nlisten"
    stat_set net_listening_exposed "$exposed"
    if [[ "$IS_ROOT" -eq 0 && "$nlisten" -gt 0 ]]; then
        print_line "(process names of other users' sockets need root)"
    fi

    # Connections
    local est="$WORKDIR/established.tsv"
    : > "$est"
    if have ss; then
        tbl_new "TCP Connection States" "State" "Sockets"
        local state count
        while IFS="$TAB" read -r count state; do
            tbl_row "$state" "$count"
        done < <(ss -Htan 2>/dev/null | awk '{ print $1 }' | tally)
        tbl_end

        ss -Htnp state established 2>/dev/null | awk '{
            proc = "-"
            if (match($0, /users:\(\("[^"]+"/)) proc = substr($0, RSTART + 9, RLENGTH - 10)
            print $3 "\t" $4 "\t" proc }' > "$WORKDIR/est.raw"
        local l r
        while IFS="$TAB" read -r l r proc; do
            split_hostport "$r"
            local raddr="$HP_ADDR" rport="$HP_PORT"
            split_hostport "$l"
            printf '%s\t%s\t%s\t%s\t%s\n' "$raddr" "$rport" "$HP_ADDR" "$HP_PORT" "$proc"
        done < "$WORKDIR/est.raw" > "$est"
    fi
    local nest remote_peers
    nest=$(wc -l < "$est")
    remote_peers=$(awk -F'\t' '$1 !~ /^127\./ && $1 != "::1" { print $1 }' "$est" | sort -u | wc -l)
    stat_set net_established "$nest"
    stat_set net_remote_peers "$remote_peers"
    print_stat "Established TCP connections" "$nest"
    print_stat "Distinct remote peers" "$remote_peers"

    if [[ "$nest" -gt 0 ]]; then
        tbl_new "Top Remote Peers" "Remote address" "Connections" "Remote ports" "Processes"
        local ip conns ports procs
        while IFS="$TAB" read -r ip conns ports procs; do
            tbl_row "$ip" "$conns" "$ports" "$procs"
        done < <(awk -F'\t' '$1 !~ /^127\./ && $1 != "::1" {
                    c[$1]++
                    if (!(($1, $2) in sp)) { sp[$1, $2] = 1; p[$1] = p[$1] (p[$1] == "" ? "" : ",") $2 }
                    if (!(($1, $5) in sq)) { sq[$1, $5] = 1; q[$1] = q[$1] (q[$1] == "" ? "" : ",") $5 } }
                 END { for (i in c) printf "%s\t%d\t%s\t%s\n", i, c[i], substr(p[i], 1, 60), substr(q[i], 1, 60) }' "$est" |
                 sort -t "$TAB" -k2,2nr | top_n)
        tbl_end

        tbl_new "Connections by Process" "Process" "Connections"
        while IFS="$TAB" read -r count proc; do
            tbl_row "$proc" "$count"
        done < <(cut -f5 "$est" | tally | top_n)
        tbl_end
    fi

    # Outbound connections to suspicious ports (local side is not a listener)
    local -A lports=()
    while IFS="$TAB" read -r proto loc proc; do
        split_hostport "$loc"
        lports[$HP_PORT]=1
    done < "$lst"
    local -a suspect=()
    local raddr rport laddr lport
    while IFS="$TAB" read -r raddr rport laddr lport proc; do
        if [[ "$SUSPECT_REMOTE_PORTS" == *" $rport "* && -z "${lports[$lport]:-}" ]]; then
            suspect+=("$raddr:$rport ($proc)")
            flag_ip "$raddr" "outbound connection to suspicious port $rport"
        fi
    done < "$est"
    if [[ ${#suspect[@]} -gt 0 ]]; then
        add_finding 2 network "${#suspect[@]} connection(s) to ports used by mining pools, IRC botnets or Tor: $(join ', ' "${suspect[@]:0:5}")"
    fi

    # Interfaces and traffic
    local c1="$WORKDIR/netdev.1" c2="$WORKDIR/netdev.2" secs="$NET_SAMPLE_SECONDS"
    net_counters "$c1"
    if [[ "$secs" -gt 0 ]]; then
        sleep "$secs"
        net_counters "$c2"
    fi
    local -A addrs=()
    local ifn a
    while IFS=' ' read -r ifn a; do
        addrs[$ifn]+="${addrs[$ifn]:+, }$a"
    done < <(ip -o addr show 2>/dev/null | awk '$4 !~ /^fe80:/ { print $2, $4 }')

    local rxb rxp rxe rxd txb txp txe txd rx2 tx2 opstate flags_hex rate_rx rate_tx
    local total_rx=0 total_tx=0 nif=0
    local -a promisc=()
    local -A later_rx=() later_tx=()
    if [[ "$secs" -gt 0 ]]; then
        while IFS="$TAB" read -r ifn rx2 _ _ _ tx2 _; do
            later_rx[$ifn]="$rx2"; later_tx[$ifn]="$tx2"
        done < "$c2"
    fi
    tbl_new "Interfaces & Traffic (counters since boot)" "Interface" "State" "Addresses" "RX" "TX" "RX packets" \
        "TX packets" "Errors rx/tx" "Drops rx/tx" "RX rate" "TX rate"
    while IFS="$TAB" read -r ifn rxb rxp rxe rxd txb txp txe txd; do
        nif=$((nif + 1))
        opstate=$(read_first "/sys/class/net/$ifn/operstate")
        flags_hex=$(read_first "/sys/class/net/$ifn/flags")
        if [[ -n "$flags_hex" ]] && (( flags_hex & 0x100 )); then
            if [[ -e "/sys/class/net/$ifn/brport" ]]; then
                opstate+=" (promisc, bridge port)"
            else
                opstate+=" PROMISC"
                promisc+=("$ifn")
            fi
        fi
        rate_rx="-"; rate_tx="-"
        if [[ "$secs" -gt 0 && -n "${later_rx[$ifn]:-}" ]]; then
            rate_rx="$(human_bytes $(( (later_rx[$ifn] - rxb) / secs )))/s"
            rate_tx="$(human_bytes $(( (later_tx[$ifn] - txb) / secs )))/s"
        fi
        if [[ "$ifn" != "lo" ]]; then
            total_rx=$((total_rx + rxb)); total_tx=$((total_tx + txb))
        fi
        tbl_row "$ifn" "${opstate:-?}" "${addrs[$ifn]:--}" "$(human_bytes "$rxb")" "$(human_bytes "$txb")" \
            "$rxp" "$txp" "$rxe/$txe" "$rxd/$txd" "$rate_rx" "$rate_tx"
    done < "$c1"
    tbl_end 30
    stat_set net_interfaces "$nif"
    stat_set net_rx_bytes "$total_rx"
    stat_set net_tx_bytes "$total_tx"
    print_stat "Total received (excluding lo)" "$(human_bytes "$total_rx")"
    print_stat "Total sent (excluding lo)" "$(human_bytes "$total_tx")"
    if [[ ${#promisc[@]} -gt 0 ]]; then
        add_finding 2 network "Interface(s) in promiscuous mode - a packet sniffer may be running: $(join ', ' "${promisc[@]}")"
    fi

    # Protocol counters
    local snmp="$WORKDIR/snmp.tsv"
    cat /proc/net/snmp /proc/net/netstat 2>/dev/null | awk '
        { p = $1; sub(/:$/, "", p) }
        !(p in hdr) { hdr[p] = 1; for (i = 2; i <= NF; i++) name[p, i] = $i; next }
        { for (i = 2; i <= NF; i++) print p "." name[p, i] "\t" $i; delete hdr[p] }' > "$snmp"
    local -A ctr=()
    local key value
    while IFS="$TAB" read -r key value; do
        ctr[$key]="$value"
    done < "$snmp"
    tbl_new "Protocol Counters (since boot)" "Counter" "Value" "Meaning"
    local spec desc
    for spec in "Tcp.ActiveOpens|outgoing connections opened" "Tcp.PassiveOpens|incoming connections accepted" \
                "Tcp.AttemptFails|failed connection attempts" "Tcp.EstabResets|established connections reset" \
                "Tcp.InSegs|segments received" "Tcp.OutSegs|segments sent" "Tcp.RetransSegs|segments retransmitted" \
                "Tcp.InErrs|bad segments received" "Tcp.OutRsts|resets sent (closed-port probes)" \
                "Udp.InDatagrams|datagrams received" "Udp.OutDatagrams|datagrams sent" \
                "Udp.NoPorts|datagrams to closed ports (UDP scans)" "Udp.InErrors|receive errors" \
                "Udp.RcvbufErrors|dropped, receive buffer full" "Icmp.InMsgs|ICMP messages received" \
                "Icmp.InEchos|pings received" "Icmp.InDestUnreachs|destination unreachable received" \
                "TcpExt.SyncookiesSent|SYN cookies sent (SYN flood)" "TcpExt.ListenOverflows|accept queue overflows" \
                "TcpExt.ListenDrops|SYNs dropped at listeners"; do
        key="${spec%%|*}"; desc="${spec#*|}"
        [[ -n "${ctr[$key]:-}" ]] && tbl_row "$key" "${ctr[$key]}" "$desc"
    done
    tbl_end 40
    if [[ "${ctr[Tcp.OutSegs]:-0}" -gt 0 ]]; then
        print_stat "TCP retransmission rate" "$(awk -v r="${ctr[Tcp.RetransSegs]:-0}" -v o="${ctr[Tcp.OutSegs]}" 'BEGIN { printf "%.2f%%", r * 100 / o }')"
    fi
    stat_set tcp_syncookies_sent "${ctr[TcpExt.SyncookiesSent]:-0}"
    if [[ "${ctr[TcpExt.SyncookiesSent]:-0}" -gt 0 ]]; then
        add_finding 1 network "SYN cookies were sent ${ctr[TcpExt.SyncookiesSent]} time(s) since boot - SYN flood or listen queue overflow"
    fi

    # Routing and name resolution
    print_subheader "Routing & Name Resolution"
    local gw dns fwd4 fwd6 neigh
    gw=$(ip route show default 2>/dev/null | awk '{ for (i = 1; i < NF; i++) if ($i == "via") v = $(i + 1); for (i = 1; i < NF; i++) if ($i == "dev") d = $(i + 1); print v " (" d ")" }' | paste -sd, -) || gw=""
    if have resolvectl; then
        dns=$(timeout 5 resolvectl dns 2>/dev/null | awk -F': ' 'NF > 1 && $2 != "" { print $2 }' | tr ' ' '\n' | sort -u | paste -sd' ' -) || dns=""
    fi
    [[ -n "${dns:-}" ]] || dns=$(awk '$1 == "nameserver" { print $2 }' /etc/resolv.conf 2>/dev/null | paste -sd' ' -)
    fwd4=$(read_first /proc/sys/net/ipv4/ip_forward)
    fwd6=$(read_first /proc/sys/net/ipv6/conf/all/forwarding)
    neigh=$(ip neigh show 2>/dev/null | grep -c lladdr) || neigh=0
    print_stat "Default gateway" "${gw:-none}"
    print_stat "DNS servers" "${dns:-unknown}"
    print_stat "IPv4 forwarding" "$( [[ "$fwd4" == 1 ]] && echo enabled || echo disabled)"
    print_stat "IPv6 forwarding" "$( [[ "$fwd6" == 1 ]] && echo enabled || echo disabled)"
    print_stat "IPv6" "$( [[ "$(read_first /proc/sys/net/ipv6/conf/all/disable_ipv6)" == 1 ]] && echo disabled || echo enabled)"
    print_stat "Neighbour (ARP/NDP) entries" "$neigh"
    if [[ "$fwd4" == 1 || "$fwd6" == 1 ]] && ! have docker && ! have podman && ! have libvirtd && ! have lxd; then
        add_rec "IP forwarding is enabled; disable it (net.ipv4.ip_forward=0) unless this host routes traffic"
    fi

    # ARP spoofing: the gateway's MAC shared with another IPv4 address
    local gwip gwmac
    gwip=$(ip -4 route show default 2>/dev/null | awk '{ for (i = 1; i < NF; i++) if ($i == "via") { print $(i + 1); exit } }')
    if [[ -n "$gwip" ]]; then
        gwmac=$(ip -4 neigh show "$gwip" 2>/dev/null | awk '{ for (i = 1; i < NF; i++) if ($i == "lladdr") print $(i + 1) }' | head -n 1)
        if [[ -n "$gwmac" ]]; then
            local others
            others=$(ip -4 neigh show 2>/dev/null | awk -v m="$gwmac" -v g="$gwip" '{ for (i = 1; i < NF; i++) if ($i == "lladdr" && $(i + 1) == m && $1 != g) print $1 }' | paste -sd, -)
            if [[ -n "$others" ]]; then
                add_finding 2 network "Gateway $gwip MAC $gwmac is also claimed by $others - possible ARP spoofing"
            fi
        fi
    fi
    return 0
}

# ┌────────────────────────────────────────────────────────────────────────────┐
# │ Audit: Services & Containers                                               │
# └────────────────────────────────────────────────────────────────────────────┘

# unit:level:description — level is the finding severity when the unit is active
readonly RISKY_UNITS="telnet.socket:3:Telnet (cleartext),inetd.service:2:inetd super-server,inetutils-inetd.service:2:inetd super-server,openbsd-inetd.service:2:inetd super-server,xinetd.service:2:xinetd super-server,rsh.socket:3:rsh (cleartext),rlogin.socket:3:rlogin (cleartext),rexec.socket:3:rexec (cleartext),vsftpd.service:1:FTP server,proftpd.service:1:FTP server,pure-ftpd.service:1:FTP server,tftpd-hpa.service:2:TFTP (no authentication),atftpd.service:2:TFTP (no authentication),ypbind.service:2:NIS client,ypserv.service:2:NIS server,rpcbind.service:1:rpcbind portmapper,nfs-server.service:0:NFS server,smbd.service:0:Samba file server,nmbd.service:1:NetBIOS name server,snmpd.service:1:SNMP agent (check community strings),avahi-daemon.service:0:mDNS/zeroconf,cups.service:0:print server,cups-browsed.service:0:printer discovery,slapd.service:0:LDAP server,named.service:0:DNS server,bind9.service:0:DNS server,dnsmasq.service:0:DNS/DHCP server,squid.service:0:HTTP proxy,apache2.service:0:web server,nginx.service:0:web server,httpd.service:0:web server,mysql.service:0:MySQL,mariadb.service:0:MariaDB,postgresql.service:0:PostgreSQL,redis-server.service:0:Redis,mongod.service:0:MongoDB,docker.service:0:Docker engine,containerd.service:0:containerd,libvirtd.service:0:libvirt,ssh.service:0:SSH server,sshd.service:0:SSH server,xrdp.service:1:RDP server,vncserver@.service:1:VNC server"

section_services() {
    print_header "SERVICES & CONTAINERS" "$SYM_GEAR"

    if ! have systemctl || [[ ! -d /run/systemd/system ]]; then
        print_alert 0 "systemd is not running; service checks skipped"
    else
        local units="$WORKDIR/units.tsv" files="$WORKDIR/unitfiles.tsv"
        systemctl list-units --type=service,socket --all --no-legend --plain 2>/dev/null |
            awk '{ d = ""; for (i = 5; i <= NF; i++) d = d (d == "" ? "" : " ") $i; print $1 "\t" $2 "\t" $3 "\t" $4 "\t" d }' > "$units"
        systemctl list-unit-files --type=service,socket --no-legend --plain 2>/dev/null |
            awk '{ print $1 "\t" $2 }' > "$files"

        local running enabled failed timers sockets
        running=$(awk -F'\t' '$1 ~ /\.service$/ && $4 == "running"' "$units" | wc -l)
        sockets=$(awk -F'\t' '$1 ~ /\.socket$/ && $4 == "listening"' "$units" | wc -l)
        enabled=$(awk -F'\t' '$1 ~ /\.service$/ && $2 == "enabled"' "$files" | wc -l)
        failed=$(awk -F'\t' '$3 == "failed"' "$units" | wc -l)
        timers=$(systemctl list-timers --all --no-legend 2>/dev/null | wc -l)

        print_subheader "Summary"
        print_stat "Running services" "$running"
        print_stat "Enabled services" "$enabled"
        print_stat "Listening socket units" "$sockets"
        print_stat "Timers" "$timers"
        print_stat "Failed units" "$failed"
        stat_set services_running "$running"
        stat_set services_enabled "$enabled"
        stat_set services_failed "$failed"

        if [[ "$failed" -gt 0 ]]; then
            tbl_new "Failed Units" "Unit" "Load" "Active" "Sub" "Description"
            local u l a sb d
            while IFS="$TAB" read -r u l a sb d; do
                tbl_row "$u" "$l" "$a" "$sb" "$d"
            done < <(awk -F'\t' '$3 == "failed"' "$units")
            tbl_end
            add_finding 1 services "$failed systemd unit(s) in failed state (a failed security service leaves a gap)"
        fi

        # Network-facing and legacy services
        local -A ustate=() fstate=()
        local u st
        while IFS="$TAB" read -r u _ a sb _; do
            ustate[$u]="$a/$sb"
        done < "$units"
        while IFS="$TAB" read -r u st; do
            fstate[$u]="$st"
        done < "$files"
        tbl_new "Notable Services Present" "Unit" "Enabled" "State" "Description"
        local lvl desc
        while IFS=':' read -r u lvl desc; do
            [[ -n "${ustate[$u]:-}${fstate[$u]:-}" ]] || continue
            tbl_row "$u" "${fstate[$u]:--}" "${ustate[$u]:-inactive}" "$desc"
            if [[ "$lvl" -gt 0 && "${ustate[$u]:-}" == active/* ]]; then
                add_finding "$lvl" services "Risky service active: $u ($desc)"
            fi
        done < <(tr ',' '\n' <<< "$RISKY_UNITS")
        tbl_end 60
    fi

    # Containers
    if have docker || [[ -S /var/run/docker.sock ]]; then
        print_subheader "Docker"
        if [[ -S /var/run/docker.sock ]]; then
            local sock_mode
            sock_mode=$(stat -c '%a %U:%G' /var/run/docker.sock 2>/dev/null) || sock_mode="?"
            print_stat "docker.sock" "$sock_mode"
            if [[ "${sock_mode%% *}" =~ [2367]$ ]]; then
                add_finding 4 services "docker.sock is world-writable - any local user can become root"
            fi
        fi
        if have docker && timeout 10 docker info >/dev/null 2>&1; then
            local ids
            ids=$(timeout 20 docker ps -q 2>/dev/null | paste -sd' ' -) || ids=""
            print_stat "Running containers" "$(wc -w <<< "$ids")"
            print_stat "All containers" "$(timeout 20 docker ps -aq 2>/dev/null | wc -l)"
            print_stat "Images" "$(timeout 20 docker images -q 2>/dev/null | sort -u | wc -l)"
            if [[ -n "$ids" ]]; then
                tbl_new "Running Containers" "Name" "Image" "Privileged" "Network" "PID mode" "Mounts"
                local name image priv net pidm mounts
                local -a idlist=()
                IFS=' ' read -r -a idlist <<< "$ids"
                while IFS="$TAB" read -r name image priv net pidm mounts; do
                    tbl_row "${name#/}" "$image" "$priv" "$net" "${pidm:-private}" "$mounts"
                    if [[ "$priv" == "true" ]]; then
                        add_finding 2 services "Container ${name#/} runs privileged (full access to the host)"
                    fi
                    if [[ "$mounts" == *docker.sock* ]]; then
                        add_finding 3 services "Container ${name#/} has the Docker socket mounted (host root equivalent)"
                    fi
                done < <(timeout 30 docker inspect -f '{{.Name}}{{"\t"}}{{.Config.Image}}{{"\t"}}{{.HostConfig.Privileged}}{{"\t"}}{{.HostConfig.NetworkMode}}{{"\t"}}{{.HostConfig.PidMode}}{{"\t"}}{{range .Mounts}}{{.Source}} {{end}}' "${idlist[@]}" 2>/dev/null)
                tbl_end
            fi
        else
            print_alert 0 "Docker daemon not reachable (not running or needs root)"
        fi
    fi
    if have podman; then
        print_subheader "Podman"
        print_stat "Containers running (current user)" "$(timeout 20 podman ps -q 2>/dev/null | wc -l)"
    fi
    return 0
}

# ┌────────────────────────────────────────────────────────────────────────────┐
# │ Audit: Users & Groups                                                      │
# └────────────────────────────────────────────────────────────────────────────┘

# Groups whose members can become root without a password prompt
readonly ROOT_EQUIV_GROUPS_RE="^(docker|lxd|libvirt|disk)$"

is_login_shell() {
    case "$1" in
        ""|*/nologin|*/false|/bin/sync|/usr/bin/sync|/sbin/shutdown|/sbin/halt|/usr/sbin/shutdown|/usr/sbin/halt) return 1 ;;
    esac
    return 0
}

section_users() {
    print_header "USERS, GROUPS & AUTHENTICATION" "$SYM_EYE"

    # Password state from /etc/shadow (root only)
    local -A pw=() pwdate=()
    local shadow_ok=0 u h lc rest
    local -a weak_hash=() empty_pw=()
    if [[ -r /etc/shadow ]]; then
        shadow_ok=1
        while IFS=: read -r u h lc rest; do
            case "$h" in
                "")          pw[$u]="EMPTY"; empty_pw+=("$u") ;;
                "*"|"!"|"!*"|"!!") pw[$u]="no password" ;;
                "!"*|"*"*)   pw[$u]="locked" ;;
                '$y$'*|'$gy$'*) pw[$u]="yescrypt" ;;
                '$7$'*)      pw[$u]="scrypt" ;;
                '$6$'*)      pw[$u]="SHA-512" ;;
                '$5$'*)      pw[$u]="SHA-256" ;;
                '$2'*)       pw[$u]="bcrypt" ;;
                '$1$'*)      pw[$u]="MD5 (weak)"; weak_hash+=("$u") ;;
                *)           pw[$u]="DES/unknown (weak)"; weak_hash+=("$u") ;;
            esac
            if [[ "$lc" =~ ^[0-9]+$ && "$lc" -gt 0 ]]; then
                pwdate[$u]=$(date -d "@$((lc * 86400))" +%F)
            fi
        done < /etc/shadow
    fi

    # Privileged group membership (supplementary and primary)
    local -A privg=() gname=()
    local g x gid members m
    while IFS=: read -r g x gid members; do
        gname[$gid]="$g"
        if [[ "$g" =~ ^($PRIV_GROUPS_RE)$ ]]; then
            local -a ms=()
            IFS=',' read -r -a ms <<< "$members"
            for m in "${ms[@]}"; do
                [[ -n "$m" ]] && privg[$m]+="${privg[$m]:+,}$g"
            done
        fi
    done < /etc/group

    local total=0 system=0 human=0 login=0 uid home shell gecos
    local -a uid0=() root_equiv=()
    tbl_new "Accounts with a Login Shell" "User" "UID" "Home" "Shell" "Password" "Last change" "Privileged groups"
    while IFS=: read -r u x uid gid gecos home shell; do
        total=$((total + 1))
        if [[ "$uid" -eq 0 && "$u" != "root" ]]; then
            uid0+=("$u")
        fi
        if [[ "$uid" -ge 1000 && "$uid" -lt 60000 ]]; then
            human=$((human + 1))
        elif [[ "$uid" -ne 0 ]]; then
            system=$((system + 1))
        fi
        local pg="${gname[$gid]:-}"
        if [[ -n "$pg" && "$pg" =~ ^($PRIV_GROUPS_RE)$ && ",${privg[$u]:-}," != *",$pg,"* ]]; then
            privg[$u]+="${privg[$u]:+,}$pg"
        fi
        if [[ "$uid" -ne 0 ]]; then
            local grp
            local -a gl=()
            IFS=',' read -r -a gl <<< "${privg[$u]:-}"
            for grp in "${gl[@]}"; do
                if [[ "$grp" =~ $ROOT_EQUIV_GROUPS_RE ]]; then
                    root_equiv+=("$u($grp)")
                fi
            done
        fi
        is_login_shell "$shell" || continue
        login=$((login + 1))
        tbl_row "$u" "$uid" "$home" "$shell" "${pw[$u]:-$([[ $shadow_ok -eq 1 ]] && echo "-" || echo "needs root")}" \
            "${pwdate[$u]:--}" "${privg[$u]:--}"
    done < /etc/passwd
    tbl_end 50

    print_subheader "Summary"
    print_stat "Accounts" "$total ($human regular, $system system)"
    print_stat "Accounts with a login shell" "$login"
    print_stat "root password" "${pw[root]:-$([[ $shadow_ok -eq 1 ]] && echo "not set" || echo "needs root")}"
    stat_set users_total "$total"
    stat_set users_regular "$human"
    stat_set users_login_shell "$login"

    if [[ ${#uid0[@]} -gt 0 ]]; then
        add_finding 4 users "Non-root account(s) with UID 0: $(sanitize "$(join ', ' "${uid0[@]}")")"
    fi
    if [[ ${#empty_pw[@]} -gt 0 ]]; then
        add_finding 3 users "Account(s) with an empty password: $(sanitize "$(join ', ' "${empty_pw[@]}")")"
    fi
    if [[ ${#weak_hash[@]} -gt 0 ]]; then
        add_finding 2 users "Account(s) with weak password hashes (MD5/DES): $(join ', ' "${weak_hash[@]}")"
        add_rec "Reset passwords hashed with MD5/DES; set ENCRYPT_METHOD YESCRYPT (or SHA512) in /etc/login.defs"
    fi
    if [[ "$shadow_ok" -eq 0 ]]; then
        print_line "(password status needs root to read /etc/shadow)"
    fi
    local dups
    dups=$(awk -F: '{ c[$3]++; n[$3] = n[$3] " " $1 } END { for (u in c) if (c[u] > 1) printf "UID %s:%s; ", u, n[u] }' /etc/passwd)
    [[ -n "$dups" ]] && add_finding 2 users "Duplicate UIDs: ${dups%; }"
    dups=$(awk -F: '{ c[$1]++ } END { for (u in c) if (c[u] > 1) printf "%s ", u }' /etc/passwd)
    [[ -n "$dups" ]] && add_finding 2 users "Duplicate user names: $dups"
    dups=$(awk -F: '{ c[$3]++; n[$3] = n[$3] " " $1 } END { for (g in c) if (c[g] > 1) printf "GID %s:%s; ", g, n[g] }' /etc/group)
    [[ -n "$dups" ]] && add_finding 1 users "Duplicate GIDs: ${dups%; }"

    tbl_new "Privileged Groups" "Group" "Members"
    local grp
    for grp in root sudo admin wheel adm shadow disk docker lxd libvirt; do
        members=$(awk -F: -v g="$grp" '$1 == g { print $4 }' /etc/group)
        if getent group "$grp" >/dev/null 2>&1; then
            tbl_row "$grp" "${members:--}"
        fi
    done
    tbl_end
    if [[ ${#root_equiv[@]} -gt 0 ]]; then
        add_finding 1 users "User(s) in root-equivalent groups (docker/lxd/libvirt/disk): $(join ', ' "${root_equiv[@]}")"
    fi

    # sudoers rules
    if [[ -r /etc/sudoers ]]; then
        local f line nopw=0
        local -a nopw_all=()
        tbl_new "Sudo Rules" "File" "Rule"
        while IFS= read -r f; do
            while IFS= read -r line; do
                if [[ "$line" =~ ^(Defaults|Cmnd_Alias|User_Alias|Host_Alias|Runas_Alias)[\ :@!\>] ]]; then
                    if [[ "$line" == Defaults* && "$line" == *'!authenticate'* ]]; then
                        add_finding 2 users "sudo password prompt disabled by 'Defaults !authenticate' in $f"
                    fi
                    continue
                fi
                tbl_row "${f#/etc/}" "$line"
                if [[ "$line" == *NOPASSWD* ]]; then
                    nopw=$((nopw + 1))
                    if [[ "$line" =~ NOPASSWD:[[:space:]]*ALL[[:space:]]*$ ]]; then
                        nopw_all+=("${line%%[[:space:]]*}")
                    fi
                fi
            done < <(sed -e 's/[[:space:]]\+/ /g' -e 's/^ //' -- "$f" 2>/dev/null | grep -vE '^(#|$|@include)' || true)
        done < <(printf '%s\n' /etc/sudoers; find /etc/sudoers.d -maxdepth 1 -type f ! -name '*~' ! -name '*.*' ! -name README 2>/dev/null | sort)
        tbl_end 40
        stat_set sudo_nopasswd_rules "$nopw"
        if [[ ${#nopw_all[@]} -gt 0 ]]; then
            add_finding 1 users "Passwordless sudo to ALL commands for: $(join ', ' "${nopw_all[@]}") (a stolen session is instantly root)"
        fi
    else
        print_subheader "Sudo Rules"
        print_line "(reading sudoers needs root)"
    fi

    # Sessions
    tbl_new "Logged-in Sessions" "User" "Terminal" "Since" "From"
    local wu wt wd wtm wf
    while IFS=' ' read -r wu wt wd wtm wf; do
        tbl_row "$wu" "$wt" "$wd $wtm" "${wf:--}"
    done < <(who 2>/dev/null)
    tbl_end
    local -a lastcmd=()
    if have last; then
        lastcmd=(last -n 20 -w)
    elif have wtmpdb; then
        lastcmd=(wtmpdb last -n 20)
    fi
    if [[ ${#lastcmd[@]} -gt 0 ]]; then
        tbl_new "Recent Logins (wtmp)" "Entry"
        while IFS= read -r line; do
            [[ -n "$line" && "$line" != wtmp* && "$line" != *"begins"* ]] && tbl_row "$line"
        done < <(timeout 10 "${lastcmd[@]}" 2>/dev/null)
        tbl_end
    fi

    # Trust files and SSH keys
    local -a trust=()
    while IFS= read -r f; do
        [[ -s "$f" ]] && trust+=("$f")
    done < <(find /root /home -maxdepth 2 \( -name '.rhosts' -o -name '.shosts' -o -name '.netrc' \) -type f 2>/dev/null
             ls /etc/hosts.equiv /etc/shosts.equiv 2>/dev/null || true)
    local tf
    for tf in "${trust[@]}"; do
        case "$tf" in
            *.netrc) add_finding 1 users "Cleartext credentials file present: $tf" ;;
            *) add_finding 2 users "Host-based trust file present (rhosts/hosts.equiv): $tf" ;;
        esac
    done

    tbl_new "SSH Authorized Keys" "File" "Keys" "Restricted keys" "Mode" "Owner"
    local keys restricted mode owner nkeys=0
    while IFS= read -r f; do
        keys=$(grep -cvE '^[[:space:]]*(#|$)' -- "$f" 2>/dev/null) || keys=0
        restricted=$(grep -cE '^[[:space:]]*(from=|command=|restrict|no-)' -- "$f" 2>/dev/null) || restricted=0
        IFS=" " read -r mode owner < <(stat -c '%a %U' -- "$f" 2>/dev/null) || true
        nkeys=$((nkeys + keys))
        tbl_row "$f" "$keys" "$restricted" "${mode:-?}" "${owner:-?}"
        if [[ "$mode" =~ [2367].$|[2367]$ ]]; then
            add_finding 2 users "Group/world-writable authorized_keys file: $f (mode $mode)"
        fi
    done < <(find /root/.ssh /home/*/.ssh -maxdepth 1 -type f -name 'authorized_keys*' 2>/dev/null)
    tbl_end
    stat_set ssh_authorized_keys "$nkeys"

    # Home directory permissions
    tbl_new "Home Directories" "User" "Home" "Mode" "Owner" "Status"
    local hmode howner status
    while IFS=: read -r u x uid gid gecos home shell; do
        [[ "$uid" -ge 1000 && "$uid" -lt 60000 ]] || [[ "$uid" -eq 0 ]] || continue
        is_login_shell "$shell" || continue
        [[ -d "$home" ]] || { tbl_row "$u" "$home" "-" "-" "missing"; continue; }
        IFS=" " read -r hmode howner < <(stat -c '%a %U' -- "$home" 2>/dev/null) || continue
        status="OK"
        if (( 8#$hmode & 8#002 )); then
            status="FAIL"
            add_finding 3 users "Home directory $home is world-writable (mode $hmode)"
        elif [[ "$howner" != "$u" ]]; then
            status="FAIL"
            add_finding 2 users "Home directory $home of $u is owned by $howner"
        elif (( 8#$hmode & 8#007 )); then
            status="REVIEW"
            add_rec "Restrict home directories readable by other users: chmod 750 <home> (seen: $home $hmode)"
        fi
        tbl_row "$u" "$home" "$hmode" "$howner" "$status"
    done < /etc/passwd
    tbl_end
    return 0
}

# ┌────────────────────────────────────────────────────────────────────────────┐
# │ Audit: Hardening                                                           │
# └────────────────────────────────────────────────────────────────────────────┘

# key:operator:value:level:purpose — level 0 = informational, not a finding
readonly SYSCTL_BASELINE="kernel.randomize_va_space:eq:2:3:full ASLR,kernel.kptr_restrict:ge:1:1:hide kernel pointers,kernel.dmesg_restrict:eq:1:1:kernel log readable by root only,kernel.yama.ptrace_scope:ge:1:1:restrict ptrace to parents,kernel.unprivileged_bpf_disabled:ge:1:1:block unprivileged eBPF,kernel.perf_event_paranoid:ge:2:1:restrict perf events,kernel.kexec_load_disabled:eq:1:0:block kexec kernel replacement,kernel.sysrq:in:0/176:0:limit magic SysRq,kernel.apparmor_restrict_unprivileged_userns:eq:1:0:restrict unprivileged user namespaces,fs.protected_hardlinks:eq:1:2:hardlink protection,fs.protected_symlinks:eq:1:2:symlink protection,fs.protected_fifos:ge:1:1:FIFO protection in sticky dirs,fs.protected_regular:ge:1:1:file protection in sticky dirs,fs.suid_dumpable:eq:0:1:no core dumps of setuid programs,dev.tty.ldisc_autoload:eq:0:0:no automatic TTY line discipline loading,net.ipv4.tcp_syncookies:eq:1:1:SYN flood protection,net.ipv4.conf.all.rp_filter:in:1/2:1:reverse path filtering,net.ipv4.conf.all.accept_redirects:eq:0:1:ignore ICMP redirects,net.ipv4.conf.default.accept_redirects:eq:0:1:ignore ICMP redirects,net.ipv6.conf.all.accept_redirects:eq:0:1:ignore ICMPv6 redirects,net.ipv4.conf.all.secure_redirects:eq:0:0:ignore gateway redirects,net.ipv4.conf.all.send_redirects:eq:0:1:do not send redirects,net.ipv4.conf.all.accept_source_route:eq:0:1:drop source-routed packets,net.ipv6.conf.all.accept_source_route:eq:0:1:drop source-routed packets,net.ipv4.conf.all.log_martians:eq:1:0:log impossible addresses,net.ipv4.icmp_echo_ignore_broadcasts:eq:1:1:no smurf amplification,net.ipv4.icmp_ignore_bogus_error_responses:eq:1:0:ignore bogus ICMP errors,net.ipv4.ip_forward:eq:0:0:no routing unless needed"

section_hardening() {
    print_header "SECURITY HARDENING" "$SYM_SHIELD"

    detect_firewall
    detect_fail2ban

    # Security controls overview
    local aa="not available" aa_st="WARN" se="not present" se_st="INFO" v
    v=$(read_first /sys/module/apparmor/parameters/enabled)
    if [[ "$v" == "Y" ]]; then
        if [[ "$IS_ROOT" -eq 1 && -r /sys/kernel/security/apparmor/profiles ]]; then
            aa=$(awk '/\(enforce\)/ { e++ } /\(complain\)/ { c++ } /\(kill\)/ { k++ } /\(unconfined\)/ { u++ }
                      END { printf "enabled: %d enforce, %d complain, %d unconfined profiles", e + k, c, u }' /sys/kernel/security/apparmor/profiles)
        else
            aa="enabled (profile counts need root)"
        fi
        aa_st="OK"
    elif [[ -n "$v" ]]; then
        aa="disabled"
    fi
    if [[ -r /sys/fs/selinux/enforce ]]; then
        if [[ "$(read_first /sys/fs/selinux/enforce)" == 1 ]]; then
            se="enforcing"; se_st="OK"; aa_st="${aa_st/WARN/INFO}"
        else
            se="permissive"; se_st="WARN"
        fi
    fi
    if [[ "$aa_st" != "OK" && "$se_st" != "OK" ]]; then
        add_finding 2 hardening "No mandatory access control is enforcing (AppArmor: $aa, SELinux: $se)"
    fi

    local sb="n/a (legacy BIOS boot)" sb_st="INFO" f
    if [[ -d /sys/firmware/efi ]]; then
        sb="unknown"
        f=$(find /sys/firmware/efi/efivars -maxdepth 1 -name 'SecureBoot-*' 2>/dev/null | head -n 1)
        if [[ -n "$f" ]]; then
            v=$(od -An -t u1 -j 4 -N 1 -- "$f" 2>/dev/null | tr -d ' ')
            [[ "$v" == 1 ]] && { sb="enabled"; sb_st="OK"; } || { sb="disabled"; sb_st="WARN"; }
        elif have mokutil; then
            v=$(timeout 5 mokutil --sb-state 2>/dev/null) || true
            [[ "$v" == *enabled* ]] && { sb="enabled"; sb_st="OK"; }
            [[ "$v" == *disabled* ]] && { sb="disabled"; sb_st="WARN"; }
        fi
    fi
    local lockdown
    lockdown=$(read_first /sys/kernel/security/lockdown | sed -E 's/.*\[([a-z]+)\].*/\1/')

    local audit_state="not installed" audit_st="WARN" rules
    if have auditctl || [[ -e /etc/audit/auditd.conf ]]; then
        audit_state=$(systemctl is-active auditd 2>/dev/null) || true
        audit_state="${audit_state:-unknown}"
        if [[ "$audit_state" == "active" ]]; then
            audit_st="OK"
            if [[ "$IS_ROOT" -eq 1 ]]; then
                rules=$(auditctl -l 2>/dev/null | grep -vc '^No rules' || true)
                audit_state+=", $rules rule(s)"
                [[ "$rules" -eq 0 ]] && audit_st="WARN"
            fi
        fi
    fi
    [[ "$audit_st" == "OK" ]] || add_rec "Install and enable auditd with a rule set (e.g. audit-rules for CIS) to record security-relevant syscalls"

    local logging="volatile" log_st="WARN" rsys
    rsys=$(systemctl is-active rsyslog 2>/dev/null) || rsys=""
    if [[ -d /var/log/journal ]] || grep -qsE '^\s*Storage\s*=\s*persistent' /etc/systemd/journald.conf /etc/systemd/journald.conf.d/*.conf; then
        logging="persistent journal"; log_st="OK"
    fi
    if [[ "$rsys" == "active" ]]; then
        logging+=" + rsyslog"; log_st="OK"
    fi
    if [[ "$log_st" != "OK" ]]; then
        add_finding 1 hardening "Logs are not persistent (no /var/log/journal and rsyslog inactive); evidence is lost on reboot"
    fi

    local ntp="unknown" ntp_st="INFO"
    if have timedatectl; then
        v=$(timeout 5 timedatectl show -p NTPSynchronized --value 2>/dev/null) || v=""
        case "$v" in yes) ntp="synchronized"; ntp_st="OK" ;; no) ntp="not synchronized"; ntp_st="WARN" ;; esac
    fi

    local root_src crypt_root="no" crypt_st="WARN" swap_state="none" dev
    root_src=$(findmnt -no SOURCE / 2>/dev/null) || root_src=""
    root_src="${root_src%%\[*}"
    if [[ -n "$root_src" ]] && lsblk -rsno TYPE "$root_src" 2>/dev/null | grep -qx crypt; then
        crypt_root="yes"; crypt_st="OK"
    fi
    while IFS=' ' read -r dev _; do
        [[ "$dev" == /* ]] || continue
        if [[ "$dev" == /dev/zram* ]]; then
            swap_state="zram (volatile)"
        elif lsblk -rsno TYPE "$dev" 2>/dev/null | grep -qx crypt; then
            swap_state="encrypted"
        else
            swap_state="NOT encrypted"
        fi
    done < <(tail -n +2 /proc/swaps 2>/dev/null)
    if [[ "$crypt_root" == "no" ]]; then
        add_rec "Root file system is not encrypted; use LUKS full-disk encryption on laptops and hosts outside a secured data center"
    fi

    tbl_new "Security Controls" "Control" "State" "Status"
    tbl_row "AppArmor" "$aa" "$aa_st"
    tbl_row "SELinux" "$se" "$se_st"
    tbl_row "Secure Boot" "$sb" "$sb_st"
    tbl_row "Kernel lockdown" "${lockdown:-unknown}" "$([[ "$lockdown" =~ ^(integrity|confidentiality)$ ]] && echo OK || echo INFO)"
    tbl_row "Host firewall" "$FW_KIND" "$([[ "$FW_ACTIVE" -eq 1 ]] && echo OK || { [[ "$FW_KIND" == unknown ]] && echo INFO || echo FAIL; })"
    tbl_row "fail2ban" "$F2B_STATE" "$([[ "$F2B_STATE" == active ]] && echo OK || echo INFO)"
    tbl_row "auditd" "$audit_state" "$audit_st"
    tbl_row "Persistent logging" "$logging" "$log_st"
    tbl_row "Time synchronization" "$ntp" "$ntp_st"
    tbl_row "Automatic security updates" "${UU_STATE:-not checked (packages section)}" "$([[ "$UU_STATE" == enabled ]] && echo OK || echo INFO)"
    tbl_row "Root file system encrypted" "$crypt_root" "$crypt_st"
    tbl_row "Swap" "$swap_state" "$([[ "$swap_state" == "NOT encrypted" && "$crypt_root" == yes ]] && echo WARN || echo INFO)"
    tbl_end 100
    [[ "$sb_st" == "WARN" ]] && add_rec "Enable UEFI Secure Boot to block unsigned bootloaders and kernel modules"

    # Kernel parameters
    local key op want lvl why path cur expect status
    local -i fails=0
    local -a fail_keys=()
    tbl_new "Kernel Parameters (sysctl)" "Parameter" "Current" "Recommended" "Status" "Purpose"
    while IFS=':' read -r key op want lvl why; do
        path="/proc/sys/${key//.//}"
        case "$op" in
            eq) expect="$want" ;;
            ge) expect=">= $want" ;;
            in) expect="${want//\// or }" ;;
        esac
        if [[ ! -e "$path" ]]; then
            continue
        fi
        cur=$(read_first "$path")
        if [[ -z "$cur" ]]; then
            tbl_row "$key" "unreadable" "$expect" "N/A" "$why"
            continue
        fi
        case "$op" in
            eq) [[ "$cur" == "$want" ]] ;;
            ge) [[ "$cur" =~ ^-?[0-9]+$ && "$cur" -ge "$want" ]] ;;
            in) [[ "/$want/" == *"/$cur/"* ]] ;;
        esac && status="OK" || status="FAIL"
        if [[ "$status" == "FAIL" ]]; then
            if [[ "$lvl" -eq 0 ]]; then
                status="REVIEW"
            elif [[ "$lvl" -ge 2 ]]; then
                add_finding "$lvl" hardening "Kernel parameter $key = $cur disables $why"
            else
                fails=$((fails + 1))
                fail_keys+=("$key=$cur")
            fi
        fi
        tbl_row "$key" "$cur" "$expect" "$status" "$why"
    done < <(tr ',' '\n' <<< "$SYSCTL_BASELINE")
    tbl_end 100
    if [[ "$fails" -gt 0 ]]; then
        add_finding 1 hardening "$fails kernel parameter(s) below the hardening baseline: $(join ', ' "${fail_keys[@]}")"
        add_rec "Persist hardened kernel parameters in /etc/sysctl.d/99-hardening.conf and run 'sudo sysctl --system'"
    fi

    # Mount options
    local mp opts sep want_opts o missing
    local -a mount_issues=()
    tbl_new "Mount Options" "Path" "Separate mount" "nodev" "nosuid" "noexec" "Status"
    for mp in /tmp /var/tmp /dev/shm /home /var/log; do
        [[ -d "$mp" ]] || continue
        opts=$(findmnt -rno OPTIONS --mountpoint "$mp" 2>/dev/null) || opts=""
        sep="yes"
        if [[ -z "$opts" ]]; then
            sep="no"
            opts=$(findmnt -rno OPTIONS -T "$mp" 2>/dev/null) || opts=""
        fi
        case "$mp" in
            /home) want_opts="nodev nosuid" ;;
            *) want_opts="nodev nosuid noexec" ;;
        esac
        missing=""
        local -a wanted=()
        IFS=' ' read -r -a wanted <<< "$want_opts"
        for o in "${wanted[@]}"; do
            has_opt "$opts" "$o" || missing+="${missing:+,}$o"
        done
        if [[ "$sep" == "no" ]]; then
            status="INFO"
        elif [[ -n "$missing" ]]; then
            status="WARN"
            mount_issues+=("$mp (missing $missing)")
        else
            status="OK"
        fi
        tbl_row "$mp" "$sep" "$(has_opt "$opts" nodev && echo yes || echo no)" "$(has_opt "$opts" nosuid && echo yes || echo no)" \
            "$(has_opt "$opts" noexec && echo yes || echo no)" "$status"
    done
    tbl_end
    if [[ ${#mount_issues[@]} -gt 0 ]]; then
        add_finding 1 hardening "Mount(s) missing hardening options: $(join ', ' "${mount_issues[@]}")"
    fi

    # Password and login policy
    local defs=/etc/login.defs
    local max_days min_days warn_age enc umask_v pam_pw="" pam_auth="" quality="no" lockout="no"
    max_days=$(awk '$1 == "PASS_MAX_DAYS" { print $2 }' "$defs" 2>/dev/null)
    min_days=$(awk '$1 == "PASS_MIN_DAYS" { print $2 }' "$defs" 2>/dev/null)
    warn_age=$(awk '$1 == "PASS_WARN_AGE" { print $2 }' "$defs" 2>/dev/null)
    enc=$(awk '$1 == "ENCRYPT_METHOD" { print $2 }' "$defs" 2>/dev/null)
    umask_v=$(awk '$1 == "UMASK" { print $2 }' "$defs" 2>/dev/null)
    pam_pw=$(first_existing /etc/pam.d/common-password /etc/pam.d/system-auth /etc/pam.d/password-auth) || pam_pw=""
    pam_auth=$(first_existing /etc/pam.d/common-auth /etc/pam.d/system-auth) || pam_auth=""
    [[ -n "$pam_pw" ]] && grep -qsE '^[^#]*pam_(pwquality|cracklib|passwdqc)\.so' "$pam_pw" && quality="yes"
    [[ -n "$pam_auth" ]] && grep -qsE '^[^#]*pam_(faillock|tally2)\.so' "$pam_auth" && lockout="yes"

    tbl_new "Password & Login Policy" "Setting" "Value" "Status"
    tbl_row "ENCRYPT_METHOD (login.defs)" "${enc:-default}" "$([[ "${enc^^}" =~ ^(MD5|DES)$ ]] && echo FAIL || echo OK)"
    tbl_row "Password quality check (pam_pwquality)" "$quality" "$([[ $quality == yes ]] && echo OK || echo WARN)"
    tbl_row "Lockout after failed logins (pam_faillock)" "$lockout" "$([[ $lockout == yes ]] && echo OK || echo WARN)"
    tbl_row "PASS_MAX_DAYS" "${max_days:-unset}" "INFO"
    tbl_row "PASS_MIN_DAYS" "${min_days:-unset}" "INFO"
    tbl_row "PASS_WARN_AGE" "${warn_age:-unset}" "INFO"
    tbl_row "Default UMASK" "${umask_v:-unset}" "$([[ "$umask_v" =~ ^0?(27|77)$ ]] && echo OK || echo INFO)"
    tbl_row "Core dump handler" "$(read_first /proc/sys/kernel/core_pattern)" "INFO"
    tbl_end 100
    if [[ "${enc^^}" =~ ^(MD5|DES)$ ]]; then
        add_finding 2 hardening "Weak password hashing configured in /etc/login.defs (ENCRYPT_METHOD $enc)"
    fi
    [[ "$quality" == "yes" ]] || add_rec "Enforce password strength with pam_pwquality (sudo apt install libpam-pwquality)"
    [[ "$lockout" == "yes" ]] || add_rec "Lock accounts after repeated failed logins with pam_faillock"
    return 0
}

# ┌────────────────────────────────────────────────────────────────────────────┐
# │ Audit: File System & Permissions                                           │
# └────────────────────────────────────────────────────────────────────────────┘

# path:max mode:owner
readonly PERM_BASELINE="/etc/passwd:644:root,/etc/group:644:root,/etc/shadow:640:root,/etc/gshadow:640:root,/etc/sudoers:440:root,/etc/sudoers.d:755:root,/etc/ssh/sshd_config:644:root,/etc/crontab:644:root,/etc/cron.d:755:root,/etc/login.defs:644:root,/etc/security/opasswd:600:root,/root:700:root,/boot/grub/grub.cfg:644:root"
# Programs that give a shell or arbitrary file access when setuid (GTFOBins)
readonly SUID_RISKY_RE='/(bash|dash|sh|zsh|ksh|csh|tcsh|fish|python[0-9.]*|perl[0-9.]*|ruby[0-9.]*|php[0-9.]*|lua[0-9.]*|node|nodejs|vi|vim|vim\.basic|vim\.tiny|nvim|nano|ed|emacs|less|more|find|awk|gawk|mawk|nawk|env|xargs|tar|zip|cp|mv|dd|tee|nmap|busybox|socat|nc|ncat|netcat|gdb|strace|git|make|rsync|wget|curl|openssl|base64|chmod|chown|cat|sed|timeout|nice|stdbuf|taskset|ionice|script|systemctl|journalctl|docker)$'
readonly DANGEROUS_CAPS_RE='cap_setuid|cap_setgid|cap_sys_admin|cap_sys_ptrace|cap_sys_module|cap_dac_override|cap_dac_read_search|cap_chown|cap_fowner|cap_sys_rawio|cap_bpf'

section_filesystem() {
    print_header "FILE SYSTEM & PERMISSIONS" "$SYM_WARN"

    # Critical file permissions
    local entry path max want mode owner group extra status lvl
    local -a entries=()
    IFS=',' read -r -a entries <<< "$PERM_BASELINE"
    while IFS= read -r path; do
        entries+=("$path:600:root")
    done < <(find /etc/ssh -maxdepth 1 -name 'ssh_host_*_key' -type f 2>/dev/null)
    tbl_new "Critical File Permissions" "Path" "Mode" "Owner:Group" "Max mode" "Status"
    for entry in "${entries[@]}"; do
        IFS=':' read -r path max want <<< "$entry"
        [[ -e "$path" ]] || continue
        IFS=" " read -r mode owner group < <(stat -Lc '%a %U %G' -- "$path" 2>/dev/null) || continue
        extra=$(( 8#$mode & ~8#$max & 8#7777 ))
        status="OK"
        if [[ "$owner" != "$want" ]]; then
            status="FAIL"
            add_finding 3 filesystem "$path is owned by $owner (expected $want)"
        elif [[ "$extra" -ne 0 ]]; then
            status="FAIL"
            if (( 8#$mode & 8#002 )); then
                lvl=4
            elif [[ "$path" =~ (shadow|_key)$ ]] && (( 8#$mode & 8#004 )); then
                lvl=4
            elif (( 8#$mode & 8#020 )); then
                lvl=3
            else
                lvl=1
            fi
            add_finding "$lvl" filesystem "$path has permissions $mode (should be $max or stricter)"
        fi
        tbl_row "$path" "$mode" "$owner:$group" "$max" "$status"
    done
    tbl_end 100

    # Temp directories: hidden entries and dropped ELF binaries
    local -a hidden=() elf=()
    local f magic
    while IFS= read -r f; do
        hidden+=("$f")
    done < <(find /tmp /var/tmp /dev/shm -xdev -mindepth 1 -maxdepth 2 -name '.*' \
                ! -name '.X11-unix' ! -name '.ICE-unix' ! -name '.font-unix' ! -name '.XIM-unix' ! -name '.Test-unix' \
                ! -name '.X*-lock' ! -name '.snapshot' 2>/dev/null | head -n 200)
    while IFS= read -r f; do
        magic=$(head -c 4 -- "$f" 2>/dev/null | od -An -c 2>/dev/null | tr -d ' ')
        [[ "$magic" == '177ELF' ]] && elf+=("$f")
    done < <(find /tmp /var/tmp /dev/shm -xdev -type f -perm /111 2>/dev/null | head -n 500)
    tbl_new "Suspicious Items in Temp Directories" "Path" "Type"
    for f in "${hidden[@]}"; do tbl_row "$f" "hidden"; done
    for f in "${elf[@]}"; do tbl_row "$f" "ELF executable"; done
    tbl_end
    if [[ ${#elf[@]} -gt 0 ]]; then
        add_finding 2 filesystem "${#elf[@]} ELF executable(s) in temp directories (common malware drop location)"
    fi
    if [[ ${#hidden[@]} -gt 0 ]]; then
        add_finding 1 filesystem "${#hidden[@]} hidden file(s)/directory(ies) in temp directories - review"
    fi

    if [[ "$FS_SCAN" -eq 0 ]]; then
        print_subheader "File System Scan"
        print_alert 0 "Skipped (--no-fs-scan / --quick)"
        return 0
    fi

    # One pass over local file systems collects everything
    local -a roots=() pexpr=(-path /proc)
    local m
    while IFS= read -r m; do
        roots+=("$m")
    done < <(findmnt -rn -o TARGET -t ext2,ext3,ext4,xfs,btrfs,zfs,f2fs,jfs,reiserfs,bcachefs 2>/dev/null | awk '!seen[$0]++')
    [[ ${#roots[@]} -gt 0 ]] || roots=(/)
    for m in /sys /dev /run /snap /var/lib/docker /var/lib/containers /var/lib/lxd /var/lib/lxc /var/snap/lxd; do
        pexpr+=(-o -path "$m")
    done
    local scan="$WORKDIR/fs.scan" rc=0 t0=$SECONDS
    timeout "$FS_SCAN_TIMEOUT" find "${roots[@]}" -xdev \( "${pexpr[@]}" \) -prune -o \( \
        \( -type f -perm -0002 -printf 'WWF\t%m\t%u:%g\t%p\n' \) , \
        \( -type d -perm -0002 ! -perm -1000 -printf 'WWD\t%m\t%u:%g\t%p\n' \) , \
        \( -type f -perm /6000 -printf 'SUID\t%m\t%u:%g\t%p\n' \) , \
        \( \( -nouser -o -nogroup \) -printf 'NOOWN\t%m\t%u:%g\t%p\n' \) \
        \) 2>/dev/null | sort -u > "$scan" || rc=$?
    print_subheader "File System Scan"
    print_stat "Scanned" "$(join ' ' "${roots[@]}") ($((SECONDS - t0))s)"
    if [[ "$rc" -eq 124 ]] || [[ "$((SECONDS - t0))" -ge "$FS_SCAN_TIMEOUT" ]]; then
        warn "File system scan hit the ${FS_SCAN_TIMEOUT}s limit; results are partial (raise FS_SCAN_TIMEOUT)"
    fi
    if [[ "$IS_ROOT" -eq 0 ]]; then
        print_line "(without root, unreadable directories are skipped)"
    fi

    local kind perm own p
    local -a wwf=() wwd=() suid=() noown=()
    while IFS="$TAB" read -r kind perm own p; do
        case "$kind" in
            WWF) [[ "$p" =~ ^/(tmp|var/tmp|dev/shm)/ ]] || wwf+=("$perm$TAB$own$TAB$p") ;;
            WWD) wwd+=("$perm$TAB$own$TAB$p") ;;
            SUID) suid+=("$perm$TAB$own$TAB$p") ;;
            NOOWN) noown+=("$perm$TAB$own$TAB$p") ;;
        esac
    done < "$scan"
    stat_set world_writable_files "${#wwf[@]}"
    stat_set world_writable_dirs_no_sticky "${#wwd[@]}"
    stat_set suid_sgid_files "${#suid[@]}"
    stat_set unowned_files "${#noown[@]}"
    print_stat "World-writable files (outside temp dirs)" "${#wwf[@]}"
    print_stat "World-writable dirs without sticky bit" "${#wwd[@]}"
    print_stat "SUID/SGID files" "${#suid[@]}"
    print_stat "Files without valid owner/group" "${#noown[@]}"

    local row sys=0
    if [[ ${#wwf[@]} -gt 0 ]]; then
        tbl_new "World-Writable Files" "Mode" "Owner" "Path"
        for row in "${wwf[@]}"; do
            IFS="$TAB" read -r perm own p <<< "$row"
            tbl_row "$perm" "$own" "$p"
            [[ "$p" =~ ^/(etc|usr|bin|sbin|lib|lib64|boot|root|opt)/ ]] && sys=$((sys + 1))
        done
        tbl_end
        if [[ "$sys" -gt 0 ]]; then
            add_finding 3 filesystem "$sys world-writable file(s) in system directories (/etc, /usr, /opt, ...)"
        else
            add_finding 1 filesystem "${#wwf[@]} world-writable file(s) outside temp directories"
        fi
    fi
    if [[ ${#wwd[@]} -gt 0 ]]; then
        tbl_new "World-Writable Directories without Sticky Bit" "Mode" "Owner" "Path"
        for row in "${wwd[@]}"; do
            IFS="$TAB" read -r perm own p <<< "$row"
            tbl_row "$perm" "$own" "$p"
        done
        tbl_end
        add_finding 2 filesystem "${#wwd[@]} world-writable director(ies) without the sticky bit (anyone can delete/replace files)"
    fi
    if [[ ${#noown[@]} -gt 0 ]]; then
        tbl_new "Files without Valid Owner/Group" "Mode" "Owner" "Path"
        for row in "${noown[@]:0:1000}"; do
            IFS="$TAB" read -r perm own p <<< "$row"
            tbl_row "$perm" "$own" "$p"
        done
        tbl_end
        add_finding 1 filesystem "${#noown[@]} file(s) without a valid owner/group (a new account reusing the ID would own them)"
    fi

    # SUID/SGID and file capabilities vs. package ownership
    local caps="$WORKDIR/caps.tsv"
    : > "$caps"
    if have getcap; then
        local -a capdirs=(/usr /opt /home /root /srv /tmp /var/tmp)
        for m in /bin /sbin /lib; do
            [[ -d "$m" && ! -L "$m" ]] && capdirs+=("$m")
        done
        timeout 120 getcap -r "${capdirs[@]}" 2>/dev/null | awk '{ c = $NF; $NF = ""; sub(/ +$/, ""); print $0 "\t" c }' > "$caps" || true
    fi
    local owners="$WORKDIR/owners.tsv"
    {
        for row in "${suid[@]}"; do printf '%s\n' "${row##*$TAB}"; done
        cut -f1 "$caps"
    } | sort -u | pkg_owners > "$owners"
    local -A pkgof=()
    local pk
    while IFS="$TAB" read -r p pk; do
        pkgof[$p]="$pk"
    done < "$owners"

    local -a unowned_suid=() risky_suid=()
    if [[ ${#suid[@]} -gt 0 ]]; then
        tbl_new "SUID/SGID Files" "Mode" "Owner" "Path" "Package" "Status"
        for row in "${suid[@]}"; do
            IFS="$TAB" read -r perm own p <<< "$row"
            pk="${pkgof[$p]:-?}"
            status="OK"
            if [[ "$p" =~ $SUID_RISKY_RE && "$own" == root:* && $(( 8#$perm & 8#4000 )) -ne 0 ]]; then
                status="FAIL"; risky_suid+=("$p")
            elif [[ "$pk" == "-" ]]; then
                status="REVIEW"; unowned_suid+=("$p")
            fi
            tbl_row "$perm" "$own" "$p" "$pk" "$status"
        done
        tbl_end 30
    fi
    if [[ ${#risky_suid[@]} -gt 0 ]]; then
        add_finding 4 filesystem "SUID root set on shell/interpreter/file tool - instant root for any user: $(join ', ' "${risky_suid[@]}")"
    fi
    if [[ ${#unowned_suid[@]} -gt 0 ]]; then
        add_finding 3 filesystem "${#unowned_suid[@]} SUID/SGID file(s) not installed by any package: $(join ', ' "${unowned_suid[@]:0:5}")"
    fi

    if [[ -s "$caps" ]]; then
        tbl_new "Files with Capabilities" "Path" "Capabilities" "Package" "Status"
        local capv
        while IFS="$TAB" read -r p capv; do
            pk="${pkgof[$p]:-?}"
            status="OK"
            if [[ "$capv" =~ $DANGEROUS_CAPS_RE ]]; then
                if [[ "$p" =~ $SUID_RISKY_RE ]]; then
                    status="FAIL"
                    add_finding 4 filesystem "Dangerous capability on an interpreter/tool: $p ($capv) - root equivalent"
                elif [[ "$pk" == "-" ]]; then
                    status="FAIL"
                    add_finding 3 filesystem "Dangerous capability on a file not installed by any package: $p ($capv)"
                else
                    status="REVIEW"
                fi
            fi
            tbl_row "$p" "$capv" "$pk" "$status"
        done < "$caps"
        tbl_end
    fi

    # System binaries whose inode changed in the window without a package update
    prepare_pkg_events
    local -A updated=()
    local ts action from to
    while IFS="$TAB" read -r ts action pk from to; do
        updated[$pk]=1
    done < "$WORKDIR/pkg.events"
    local -a bindirs=(/usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /usr/lib/systemd)
    for m in /bin /sbin; do
        [[ -d "$m" && ! -L "$m" ]] && bindirs+=("$m")
    done
    local changed="$WORKDIR/bin.changed"
    find "${bindirs[@]}" -xdev -type f -newerct "@$CUTOFF_EPOCH" 2>/dev/null | head -n 500 | pkg_owners > "$changed" || true
    local nchanged tampered=0 unpackaged=0
    nchanged=$(wc -l < "$changed")
    stat_set system_binaries_changed "$nchanged"
    if [[ "$nchanged" -gt 0 ]]; then
        tbl_new "System Binaries Changed in Window" "Path" "Package" "Status"
        local pkg_base
        while IFS="$TAB" read -r p pk; do
            pkg_base="${pk%%,*}"; pkg_base="${pkg_base%%:*}"
            if [[ "$pk" == "-" ]]; then
                status="REVIEW"; unpackaged=$((unpackaged + 1))
            elif [[ -n "${updated[$pkg_base]:-}" ]]; then
                status="OK (package updated)"
            else
                status="FAIL"; tampered=$((tampered + 1))
            fi
            tbl_row "$p" "$pk" "$status"
        done < "$changed"
        tbl_end
    else
        print_subheader "System Binaries Changed in Window"
        print_alert 0 "None"
    fi
    if [[ "$tampered" -gt 0 ]]; then
        add_finding 3 filesystem "$tampered packaged system binar(ies) changed in window without a matching package update - possible tampering"
    fi
    if [[ "$unpackaged" -gt 0 ]]; then
        add_finding 1 filesystem "$unpackaged unpackaged file(s) added/changed in system binary directories in window"
    fi
    return 0
}

# ┌────────────────────────────────────────────────────────────────────────────┐
# │ Audit: Processes                                                           │
# └────────────────────────────────────────────────────────────────────────────┘

readonly MINER_RE='xmrig|xmr-stak|kdevtmpfsi|kinsing|minerd|cpuminer|cgminer|bfgminer|nbminer|lolminer|t-rex|ethminer|phoenixminer|nanominer|srbminer|stratum\+(tcp|ssl)|--donate-level|cryptonight'
readonly REVSHELL_RE='/dev/(tcp|udp)/|(ba|z|da)?sh -i( |$)|(^|[ /])nc(at)? [^|;]*-[ec] |socat [^|;]*exec|pty\.spawn|perl [^|;]*socket|php [^|;]*fsockopen|mkfifo [^|;]*(nc|sh)'

section_processes() {
    print_header "PROCESSES" "$SYM_EYE"

    local ps="$WORKDIR/ps.tsv"
    ps -eww -o pid=,ppid=,user:32=,pcpu=,pmem=,rss=,etimes=,stat=,nlwp=,args= 2>/dev/null | awk '{
        a = $0; for (i = 1; i <= 9; i++) sub(/^ *[^ ]+/, "", a); sub(/^ +/, "", a)
        print $1 "\t" $2 "\t" $3 "\t" $4 "\t" $5 "\t" $6 "\t" $7 "\t" $8 "\t" $9 "\t" a }' > "$ps"

    local total threads zombies users
    IFS="$TAB" read -r total threads zombies users < <(awk -F'\t' '{ n++; t += $9; if ($8 ~ /^Z/) z++; u[$3] = 1 }
        END { for (k in u) nu++; printf "%d\t%d\t%d\t%d\n", n, t, z, nu }' "$ps")
    print_subheader "Summary"
    print_stat "Processes" "$total"
    print_stat "Threads" "$threads"
    print_stat "Zombie processes" "$zombies"
    print_stat "Users with processes" "$users"
    stat_set processes_total "$total"
    stat_set processes_zombie "$zombies"

    tbl_new "Processes by User" "User" "Processes" "CPU%" "Memory"
    local u n c r
    while IFS="$TAB" read -r u n c r; do
        tbl_row "$u" "$n" "$c" "$(human_bytes $((r * 1024)))"
    done < <(awk -F'\t' '{ n[$3]++; c[$3] += $4; r[$3] += $6 } END { for (u in n) printf "%s\t%d\t%.1f\t%d\n", u, n[u], c[u], r[u] }' "$ps" |
             sort -t "$TAB" -k2,2nr | top_n)
    tbl_end

    local pid ppid user cpu mem rss et st nl args
    tbl_new "Top CPU Consumers" "PID" "User" "CPU%" "MEM%" "RSS" "Running" "Command"
    while IFS="$TAB" read -r pid ppid user cpu mem rss et st nl args; do
        tbl_row "$pid" "$user" "$cpu" "$mem" "$(human_bytes $((rss * 1024)))" "$(fmt_duration "$et")" "${args:0:120}"
    done < <(sort -t "$TAB" -k4,4gr "$ps" | head -n 10)
    tbl_end 10
    tbl_new "Top Memory Consumers" "PID" "User" "CPU%" "MEM%" "RSS" "Running" "Command"
    while IFS="$TAB" read -r pid ppid user cpu mem rss et st nl args; do
        tbl_row "$pid" "$user" "$cpu" "$mem" "$(human_bytes $((rss * 1024)))" "$(fmt_duration "$et")" "${args:0:120}"
    done < <(sort -t "$TAB" -k6,6nr "$ps" | head -n 10)
    tbl_end 10

    # Executable of every process (other users' processes need root)
    local -A exe_of=()
    local d target visible=0
    while IFS="$TAB" read -r d target; do
        [[ -n "$target" ]] || continue
        exe_of[${d#/proc/}]="$target"
        visible=$((visible + 1))
    done < <(find /proc -mindepth 2 -maxdepth 2 -name exe -printf '%h\t%l\n' 2>/dev/null)
    print_stat "Executables inspected" "$visible of $total$([[ "$IS_ROOT" -eq 0 ]] && echo " (root sees all)")"

    local exe reason lvl
    local -a upgraded=()
    local -i s_count=0
    tbl_new "Suspicious Processes" "PID" "User" "Executable" "Command" "Reason"
    while IFS="$TAB" read -r pid ppid user cpu mem rss et st nl args; do
        exe="${exe_of[$pid]:-}"
        reason=""; lvl=0
        if [[ "$args" =~ $MINER_RE || "${exe##*/}" =~ $MINER_RE ]]; then
            reason="crypto-miner signature"; lvl=4
        elif [[ "$exe" == /memfd:* && "$exe" != *runc* ]]; then
            reason="fileless execution from memory (memfd)"; lvl=3
        elif [[ "$exe" =~ ^/(tmp|var/tmp|dev/shm)/ ]]; then
            reason="running from a temp directory"; lvl=3
            [[ "$exe" == *" (deleted)" ]] && { reason+=", binary deleted"; lvl=4; }
        elif [[ "$exe" == *" (deleted)" ]]; then
            if [[ "$exe" =~ ^/(usr|lib|lib64|bin|sbin|opt|snap)/ ]]; then
                upgraded+=("$pid:${exe%% (deleted)}")
            else
                reason="executable deleted after start"; lvl=3
            fi
        elif [[ "$args" == "["* && -n "$exe" ]]; then
            reason="user process disguised as a kernel thread"; lvl=3
        elif [[ "$args" =~ $REVSHELL_RE ]]; then
            reason="reverse-shell pattern"; lvl=3
        fi
        if [[ "$lvl" -gt 0 ]]; then
            s_count=$((s_count + 1))
            tbl_row "$pid" "$user" "${exe:-?}" "${args:0:150}" "$reason"
            add_finding "$lvl" processes "PID $pid ($user): $reason - $(sanitize "${args:0:100}")"
        fi
    done < "$ps"
    tbl_end
    stat_set processes_suspicious "$s_count"
    stat_set processes_outdated_binary "${#upgraded[@]}"
    if [[ ${#upgraded[@]} -gt 0 ]]; then
        print_stat "Processes running replaced binaries" "${#upgraded[@]}"
        add_rec "Restart ${#upgraded[@]} process(es) still running pre-update binaries (see 'sudo needrestart' or reboot)"
    fi
    return 0
}

# ┌────────────────────────────────────────────────────────────────────────────┐
# │ Deep Scan: Rootkit Scanners & Lynis                                        │
# └────────────────────────────────────────────────────────────────────────────┘

section_rootkit() {
    print_header "ROOTKIT SCANNERS & LYNIS AUDIT" "$SYM_SKULL"

    if [[ "$DEEP_SCAN" -eq 0 ]]; then
        SEC_STATUS[$SECTION_CUR]="skipped"
        print_alert 0 "Skipped - run with --deep (takes several minutes)"
        return 0
    fi
    if [[ "$IS_ROOT" -eq 0 ]]; then
        SEC_STATUS[$SECTION_CUR]="skipped"
        print_alert 0 "Skipped - rkhunter, chkrootkit and lynis need root"
        return 0
    fi

    local tool
    if [[ "$INSTALL_TOOLS" -eq 1 ]] && have apt-get; then
        local -a missing=()
        for tool in rkhunter chkrootkit lynis; do
            have "$tool" || missing+=("$tool")
        done
        if [[ ${#missing[@]} -gt 0 ]]; then
            print_line "Installing: $(join ' ' "${missing[@]}")"
            DEBIAN_FRONTEND=noninteractive timeout 600 apt-get install -y -qq "${missing[@]}" >/dev/null 2>&1 ||
                warn "Could not install $(join ' ' "${missing[@]}")"
        fi
    fi

    tbl_new "Scanner Availability" "Tool" "Installed"
    for tool in rkhunter chkrootkit lynis; do
        tbl_row "$tool" "$(have "$tool" && echo yes || echo "no (apt install $tool, or --online --install-tools)")"
    done
    tbl_end

    if have rkhunter; then
        if [[ "$ONLINE" -eq 1 ]]; then
            timeout 300 rkhunter --update --nocolors >/dev/null 2>&1 || true
        fi
        local out warnings
        out="$WORKDIR/rkhunter.out"
        timeout 1200 rkhunter --check --skip-keypress --nocolors --report-warnings-only --noappend-log > "$out" 2>&1 || true
        warnings=$(grep -c '^Warning:' "$out") || warnings=0
        stat_set rkhunter_warnings "$warnings"
        tbl_new "rkhunter Warnings" "Warning"
        while IFS= read -r line; do
            tbl_row "${line#Warning: }"
        done < <(grep '^Warning:' "$out")
        tbl_end 30
        if [[ "$warnings" -gt 0 ]]; then
            add_finding 2 rootkit "rkhunter reported $warnings warning(s) - review (false positives are common after updates)"
        fi
    fi

    if have chkrootkit; then
        local out infected
        out="$WORKDIR/chkrootkit.out"
        timeout 1200 chkrootkit -q > "$out" 2>&1 || true
        infected=$(grep -ciE 'INFECTED|Vulnerable' "$out") || infected=0
        stat_set chkrootkit_infected "$infected"
        tbl_new "chkrootkit Output" "Line"
        while IFS= read -r line; do
            [[ -n "${line// /}" ]] && tbl_row "$line"
        done < "$out"
        tbl_end 30
        if [[ "$infected" -gt 0 ]]; then
            add_finding 3 rootkit "chkrootkit reported $infected INFECTED/vulnerable item(s)"
        fi
    fi

    if have lynis; then
        local rep="$WORKDIR/lynis-report.dat" idx lw ls
        timeout 1800 lynis audit system --quick --no-colors --quiet --report-file "$rep" \
            --logfile "$WORKDIR/lynis.log" >/dev/null 2>&1 || true
        if [[ -s "$rep" ]]; then
            idx=$(awk -F= '$1 == "hardening_index" { print $2 }' "$rep")
            lw=$(grep -c '^warning\[\]=' "$rep") || lw=0
            ls=$(grep -c '^suggestion\[\]=' "$rep") || ls=0
            print_subheader "Lynis"
            print_stat "Hardening index" "${idx:-?} / 100"
            print_stat "Warnings" "$lw"
            print_stat "Suggestions" "$ls"
            stat_set lynis_hardening_index "${idx:-0}"
            stat_set lynis_warnings "$lw"
            tbl_new "Lynis Warnings & Suggestions" "Type" "Test" "Details"
            awk -F'=' '/^(warning|suggestion)\[\]=/ { t = ($1 ~ /^warning/) ? "warning" : "suggestion"
                        v = substr($0, index($0, "=") + 1); n = split(v, a, "|")
                        print t "\t" a[1] "\t" a[2] }' "$rep" > "$WORKDIR/lynis.tsv"
            local t id det
            while IFS="$TAB" read -r t id det; do
                tbl_row "$t" "$id" "$det"
            done < "$WORKDIR/lynis.tsv"
            tbl_end 30
            if [[ "$lw" -gt 0 ]]; then
                add_finding 2 rootkit "Lynis reported $lw warning(s)"
            fi
            if [[ "${idx:-100}" =~ ^[0-9]+$ && "${idx:-100}" -lt 60 ]]; then
                add_finding 1 rootkit "Lynis hardening index is low (${idx}/100)"
            fi
        else
            warn "Lynis did not produce a report"
        fi
    fi
    return 0
}

# ┌────────────────────────────────────────────────────────────────────────────┐
# │ Summary & Reporting                                                        │
# └────────────────────────────────────────────────────────────────────────────┘

block_command() {
    case "$FW_KIND" in
        ufw)       echo "sudo ufw insert 1 deny from <IP>" ;;
        firewalld) echo "sudo firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address=<IP> drop' && sudo firewall-cmd --reload" ;;
        nftables)  echo "sudo nft add rule inet filter input ip saddr <IP> drop" ;;
        *)         echo "sudo iptables -I INPUT -s <IP> -j DROP" ;;
    esac
}

# section_result <name> — sets REPLY to OK/LOW/.../skipped/incomplete
section_result() {
    local name="$1"
    case "${SEC_STATUS[$name]:-}" in
        skipped) REPLY="skipped" ;;
        incomplete) REPLY="incomplete" ;;
        *) REPLY="${LEVEL_NAMES[${SEC_LEVEL[$name]:-0}]}" ;;
    esac
}

print_threat_summary() {
    SECTION_CUR=""
    print_header "THREAT SUMMARY" "$SYM_STAR"

    local alert_color alert_text
    case "$ALERT_LEVEL" in
        0) alert_color="$C_GREEN"; alert_text="OK - No significant threats" ;;
        1) alert_color="$C_YELLOW"; alert_text="LOW - Minor issues detected" ;;
        2) alert_color="$C_ORANGE"; alert_text="MEDIUM - Attention required" ;;
        3) alert_color="${C_RED}"; alert_text="HIGH - Immediate attention needed" ;;
        4) alert_color="${C_RED}${C_BOLD}"; alert_text="CRITICAL - Possible security incident!" ;;
        *) alert_color="$C_WHITE"; alert_text="UNKNOWN" ;;
    esac

    echo
    printf '  %b╭──────────────────────────────────────────────────────────────────────╮%b\n' "$alert_color" "$C_RESET"
    printf '  %b│%b  THREAT LEVEL: %b%-52s%b %b│%b\n' \
        "$alert_color" "$C_RESET" "${alert_color}${C_BOLD}" "$alert_text" "$C_RESET" "$alert_color" "$C_RESET"
    printf '  %b╰──────────────────────────────────────────────────────────────────────╯%b\n' "$alert_color" "$C_RESET"

    print_subheader "Section Summary"
    local sname res rcolor
    printf '    %b%-12s %-38s %-10s %8s %8s%b\n' "$C_GREY" "Section" "Title" "Result" "Findings" "Time" "$C_RESET"
    for sname in "${SECTIONS_RUN[@]}"; do
        section_result "$sname"
        res="$REPLY"
        case "$res" in
            OK) rcolor="$C_GREEN" ;; LOW) rcolor="$C_YELLOW" ;; MEDIUM) rcolor="$C_ORANGE" ;;
            HIGH|CRITICAL) rcolor="$C_RED" ;; *) rcolor="$C_GREY" ;;
        esac
        printf '    %-12s %-38s %b%-10s%b %8d %7.1fs\n' "$sname" "${SEC_TITLE[$sname]:-$sname}" "$rcolor" "$res" "$C_RESET" \
            "${SEC_NFIND[$sname]:-0}" "$(awk -v m="${SEC_MS[$sname]:-0}" 'BEGIN { printf "%.1f", m / 1000 }')"
    done

    print_subheader "Key Statistics"
    print_stat "Window" "$WINDOW_LABEL"
    print_stat "Failed SSH authentications" "$TOTAL_FAILED_LOGINS" \
        "$([[ $TOTAL_FAILED_LOGINS -ge 100 ]] && echo "$C_RED" || echo "$C_WHITE")"
    print_stat "IPs banned by fail2ban" "$TOTAL_BLOCKED_IPS"
    print_stat "Firewall blocks" "$TOTAL_FIREWALL_BLOCKS"
    print_stat "Suspicious events" "$TOTAL_SUSPICIOUS" \
        "$([[ $TOTAL_SUSPICIOUS -ge 10 ]] && echo "$C_ORANGE" || echo "$C_WHITE")"
    print_stat "Findings" "${#F_MSG[@]}"
    local k
    for k in packages_installed updates_security kernel_modules_loaded net_listening_exposed net_established \
             users_login_shell suid_sgid_files processes_total; do
        if [[ -n "${STATS[$k]:-}" ]]; then
            print_stat "${k//_/ }" "${STATS[$k]}"
        fi
    done

    if [[ ${#F_MSG[@]} -gt 0 ]]; then
        print_subheader "Findings (most severe first)"
        local lvl i
        for lvl in 4 3 2 1; do
            for i in "${!F_MSG[@]}"; do
                if [[ "${F_LEVEL[$i]}" -eq "$lvl" ]]; then
                    print_alert "$lvl" "[${LEVEL_NAMES[$lvl]}] ${F_CAT[$i]}: ${F_MSG[$i]}"
                fi
            done
        done
    fi

    if [[ ${#SUSP_IPS[@]} -gt 0 ]]; then
        print_subheader "High-Risk IPs to Consider Blocking (${#SUSP_IPS[@]})"
        local ip n=0
        while IFS= read -r ip; do
            if [[ "$n" -ge 20 ]]; then
                print_line "... and $(( ${#SUSP_IPS[@]} - 20 )) more (see ${REPORT_BLOCKLIST##*/})"
                break
            fi
            printf '    %b%s%b %-39s %b%s%b\n' "$C_RED" "$SYM_CROSS" "$C_RESET" "$ip" "$C_GREY" "${SUSP_IPS[$ip]//$US/; }" "$C_RESET"
            n=$((n + 1))
        done < <(printf '%s\n' "${!SUSP_IPS[@]}" | sort -V)
        echo
        printf '  %bSuggested action:%b review, then block at the perimeter or host firewall\n' "$C_YELLOW" "$C_RESET"
        printf '  %bCommand:%b %s\n' "$C_GREY" "$C_RESET" "$(block_command)"
    fi

    if [[ ${#RECOMMENDATIONS[@]} -gt 0 ]]; then
        print_subheader "Recommendations"
        local rec
        for rec in "${RECOMMENDATIONS[@]}"; do
            printf '    %b%s%b %s\n' "$C_YELLOW" "$SYM_ARROW" "$C_RESET" "$rec"
        done
    fi

    print_subheader "Data Sources"
    local src
    for src in auth syslog kern fw f2b web; do
        if [[ -n "${SOURCE_DESC[$src]:-}" ]]; then
            print_stat "$src" "${SOURCE_DESC[$src]}"
        fi
    done

    if [[ ${#WARNINGS[@]} -gt 0 ]]; then
        print_subheader "Warnings"
        local w
        for w in "${WARNINGS[@]}"; do
            printf '    %b%s%b %s\n' "$C_YELLOW" "$SYM_WARN" "$C_RESET" "$w"
        done
    fi

    echo
    printf '  %b%s Text report:%b %s\n' "$C_CYAN" "$SYM_INFO" "$C_RESET" "$REPORT_TXT"
    printf '  %b%s JSON report:%b %s\n' "$C_CYAN" "$SYM_INFO" "$C_RESET" "$REPORT_JSON"
    if [[ "$HTML_REPORT" -eq 1 ]]; then
        printf '  %b%s HTML report:%b %s\n' "$C_CYAN" "$SYM_INFO" "$C_RESET" "$REPORT_HTML"
    fi
    if [[ ${#SUSP_IPS[@]} -gt 0 ]]; then
        printf '  %b%s Blocklist:%b   %s\n' "$C_CYAN" "$SYM_INFO" "$C_RESET" "$REPORT_BLOCKLIST"
    fi

    echo
    printf '%b╭──────────────────────────────────────────────────────────────────────────╮%b\n' "${C_GREEN}${C_BOLD}" "$C_RESET"
    printf '%b│%b                   %b%s  ANALYSIS COMPLETED  %s%b                       %b│%b\n' \
        "${C_GREEN}${C_BOLD}" "$C_RESET" "${C_WHITE}${C_BOLD}" "$SYM_CHECK" "$SYM_CHECK" "$C_RESET" "${C_GREEN}${C_BOLD}" "$C_RESET"
    printf '%b╰──────────────────────────────────────────────────────────────────────────╯%b\n' "${C_GREEN}${C_BOLD}" "$C_RESET"
    echo
}

write_json() {
    local sep i ip k
    {
        printf '{\n'
        printf '  "tool": "secmon",\n'
        printf '  "version": %s,\n' "$(json_str "$SCRIPT_VERSION")"
        printf '  "host": %s,\n' "$(json_str "$HOSTNAME_FQDN")"
        printf '  "generated_at": %s,\n' "$(json_str "$(date -Iseconds)")"
        printf '  "window": { "since": %s, "hours": %d },\n' "$(json_str "$(date -d "@$CUTOFF_EPOCH" -Iseconds)")" "$HOURS"
        printf '  "run_as_root": %s,\n' "$([[ "$IS_ROOT" -eq 1 ]] && echo true || echo false)"
        printf '  "threat_level": %d,\n' "$ALERT_LEVEL"
        printf '  "threat_level_name": %s,\n' "$(json_str "${LEVEL_NAMES[$ALERT_LEVEL]}")"

        printf '  "sections": ['
        sep=""
        for k in "${SECTIONS_RUN[@]}"; do
            section_result "$k"
            printf '%s\n    { "name": %s, "title": %s, "result": %s, "findings": %d, "duration_ms": %d }' "$sep" \
                "$(json_str "$k")" "$(json_str "${SEC_TITLE[$k]:-$k}")" "$(json_str "$REPLY")" "${SEC_NFIND[$k]:-0}" "${SEC_MS[$k]:-0}"
            sep=","
        done
        printf '\n  ],\n'

        printf '  "sources": {'
        sep=""
        for k in auth syslog kern fw f2b web; do
            if [[ -n "${SOURCE_DESC[$k]:-}" ]]; then
                printf '%s\n    %s: %s' "$sep" "$(json_str "$k")" "$(json_str "${SOURCE_DESC[$k]}")"
                sep=","
            fi
        done
        printf '\n  },\n'

        printf '  "stats": {'
        sep=""
        for k in "${STAT_ORDER[@]}"; do
            printf '%s\n    %s: %s' "$sep" "$(json_str "$k")" "${STATS[$k]}"
            sep=","
        done
        printf '\n  },\n'

        printf '  "findings": ['
        sep=""
        for i in "${!F_MSG[@]}"; do
            printf '%s\n    { "severity": %d, "level": %s, "section": %s, "category": %s, "message": %s }' "$sep" \
                "${F_LEVEL[$i]}" "$(json_str "${LEVEL_NAMES[${F_LEVEL[$i]}]}")" "$(json_str "${F_SEC[$i]}")" \
                "$(json_str "${F_CAT[$i]}")" "$(json_str "${F_MSG[$i]}")"
            sep=","
        done
        printf '\n  ],\n'

        printf '  "suspicious_ips": ['
        sep=""
        if [[ ${#SUSP_IPS[@]} -gt 0 ]]; then
            while IFS= read -r ip; do
                local -a reasons=()
                local r rsep=""
                IFS="$US" read -r -a reasons <<< "${SUSP_IPS[$ip]}"
                printf '%s\n    { "ip": %s, "reasons": [' "$sep" "$(json_str "$ip")"
                for r in "${reasons[@]}"; do printf '%s%s' "$rsep" "$(json_str "$r")"; rsep=", "; done
                printf '] }'
                sep=","
            done < <(printf '%s\n' "${!SUSP_IPS[@]}" | sort -V)
        fi
        printf '\n  ],\n'

        printf '  "recommendations": ['
        sep=""
        for k in "${RECOMMENDATIONS[@]}"; do printf '%s\n    %s' "$sep" "$(json_str "$k")"; sep=","; done
        printf '\n  ],\n'

        printf '  "warnings": ['
        sep=""
        for k in "${WARNINGS[@]}"; do printf '%s\n    %s' "$sep" "$(json_str "$k")"; sep=","; done
        printf '\n  ],\n'

        # Inventory and detail tables: rows are arrays in column order
        printf '  "tables": ['
        sep=""
        for i in "${!T_FILE[@]}"; do
            printf '%s\n' "$sep"
            awk -F'\t' -v sec="${T_SEC[$i]}" -v kind="${T_KIND[$i]}" -v maxrows=2000 '
                function j(s) { gsub(/\\/, "&&", s); gsub(/"/, "\\\\&", s); return "\"" s "\"" }
                NR == 1 { printf "    { \"section\": %s, \"kind\": %s, \"title\": %s, ", j(sec), j(kind), j($0); next }
                NR == 2 { printf "\"columns\": ["; for (i = 1; i <= NF; i++) printf "%s%s", (i > 1 ? ", " : ""), j($i); printf "], \"rows\": ["; next }
                NR - 2 <= maxrows { printf "%s[", (NR > 3 ? ", " : ""); for (i = 1; i <= NF; i++) printf "%s%s", (i > 1 ? ", " : ""), j($i); printf "]" }
                END { if (NR < 2) printf "\"columns\": [], \"rows\": ["; printf "] }" }' "${T_FILE[$i]}"
            sep=","
        done
        printf '\n  ]\n'
        printf '}\n'
    } > "$REPORT_JSON"
}

write_blocklist() {
    if [[ ${#SUSP_IPS[@]} -eq 0 ]]; then
        return 0
    fi
    {
        printf '# secmon blocklist for %s generated %s (%s)\n' "$HOSTNAME_FQDN" "$(date -Iseconds)" "$WINDOW_LABEL"
        printf '# Review before use. One IP per line; reasons in trailing comment.\n'
        local ip
        while IFS= read -r ip; do
            printf '%s\t# %s\n' "$ip" "${SUSP_IPS[$ip]//$US/; }"
        done < <(printf '%s\n' "${!SUSP_IPS[@]}" | sort -V)
    } > "$REPORT_BLOCKLIST"
}

nagios_output() {
    local state code
    case "$ALERT_LEVEL" in
        0|1) state="OK"; code=0 ;;
        2)   state="WARNING"; code=1 ;;
        *)   state="CRITICAL"; code=2 ;;
    esac

    local top="" i lvl
    for lvl in 4 3 2 1; do
        for i in "${!F_MSG[@]}"; do
            if [[ -z "$top" && "${F_LEVEL[$i]}" -eq "$lvl" ]]; then
                top="${F_MSG[$i]}"
            fi
        done
    done

    printf 'SECMON %s - threat level %s, %d finding(s)%s | failed_logins=%d;;; fail2ban_banned=%d;;; firewall_blocks=%d;;; suspicious=%d;;; high_risk_ips=%d;;;\n' \
        "$state" "${LEVEL_NAMES[$ALERT_LEVEL]}" "${#F_MSG[@]}" "${top:+: $top}" \
        "$TOTAL_FAILED_LOGINS" "$TOTAL_BLOCKED_IPS" "$TOTAL_FIREWALL_BLOCKS" "$TOTAL_SUSPICIOUS" "${#SUSP_IPS[@]}" >&"$REAL_OUT"
    return "$code"
}

# ┌────────────────────────────────────────────────────────────────────────────┐
# │ HTML Report                                                                │
# └────────────────────────────────────────────────────────────────────────────┘

# html_esc <string> — sets REPLY to the HTML-escaped string (no subshell)
html_esc() {
    local s="$1"
    s="${s//&/&amp;}"
    s="${s//</&lt;}"
    s="${s//>/&gt;}"
    s="${s//\"/&quot;}"
    REPLY="$s"
}

# TSV table file -> HTML. Cells holding a status word are colored.
HTML_TABLE_AWK=$(cat <<'AWK'
function esc(s) { gsub(/&/, "\\&amp;", s); gsub(/</, "\\&lt;", s); gsub(/>/, "\\&gt;", s); gsub(/"/, "\\&quot;", s); return s }
function cell(s,    c) {
    c = ""
    if (s ~ /^(OK|PASS|OK \(.*\))$/) c = "st ok"
    else if (s ~ /^(WARN|REVIEW|LOW|MEDIUM|NOT FOUND|NOT banned|NOT encrypted)$/) c = "st warn"
    else if (s ~ /^(FAIL|HIGH|CRITICAL|EMPTY|CONTENT CHANGED)$/ || s ~ /\(weak\)$/) c = "st bad"
    else if (s ~ /^(INFO|N\/A|n\/a|-)$/) c = "st muted"
    else if (s ~ /^-?[0-9][0-9,.]*( ?[KMGTP]?i?B(\/s)?| ?%)?$/) c = "num"
    return "<td" (c == "" ? "" : " class=\"" c "\"") ">" esc(s) "</td>"
}
BEGIN { FS = "\t" }
NR == 1 { title = $0; next }
NR == 2 { nc = NF; for (i = 1; i <= NF; i++) h[i] = $i; next }
{ rows++; if (rows <= maxrows) { for (i = 1; i <= nc; i++) v[rows, i] = $i } }
END {
    shown = (rows < maxrows) ? rows : maxrows
    printf "<div class=\"tbl\">"
    if (title != "") printf "<h4>%s%s</h4>", esc(title), (kind == "table" ? " <span class=\"cnt\">" rows "</span>" : "")
    if (rows == 0) { print "<p class=\"none\">none</p></div>"; exit }
    if (kind == "kv") {
        printf "<table class=\"kv\"><tbody>"
        for (r = 1; r <= shown; r++) printf "<tr><th>%s</th>%s</tr>", esc(v[r, 1]), cell(v[r, 2])
        print "</tbody></table></div>"
        exit
    }
    printf "<div class=\"scroll\"><table class=\"data\"><thead><tr>"
    for (i = 1; i <= nc; i++) printf "<th>%s</th>", esc(h[i])
    printf "</tr></thead><tbody>"
    for (r = 1; r <= shown; r++) { printf "<tr>"; for (i = 1; i <= nc; i++) printf "%s", cell(v[r, i]); printf "</tr>\n" }
    printf "</tbody></table></div>"
    if (rows > shown) printf "<p class=\"none\">%d more rows omitted (see JSON report)</p>", rows - shown
    print "</div>"
}
AWK
)
readonly HTML_TABLE_AWK

# Statistics shown in the "Key figures" column (default: the first four)
declare -A HEADLINE_STATS=(
    [system]="uptime_days cpu_cores memory_total_mib journal_errors_boot"
    [packages]="packages_installed updates_pending updates_security packages_changed_window"
    [modules]="kernel_modules_loaded kernel_modules_tainted kernel_taint_value"
    [network]="net_listening_sockets net_listening_exposed net_established net_remote_peers"
    [services]="services_running services_enabled services_failed"
    [users]="users_total users_login_shell sudo_nopasswd_rules ssh_authorized_keys"
    [filesystem]="suid_sgid_files world_writable_files unowned_files system_binaries_changed"
    [processes]="processes_total processes_suspicious processes_zombie"
    [ssh]="ssh_failure_events ssh_attacking_ips ssh_accepted ssh_root_logins"
)

html_badge() {
    local res="$1" cls
    case "$res" in
        OK) cls="l0" ;; LOW) cls="l1" ;; MEDIUM) cls="l2" ;; HIGH) cls="l3" ;; CRITICAL) cls="l4" ;; *) cls="lx" ;;
    esac
    printf '<span class="badge %s">%s</span>' "$cls" "$res"
}

html_card() {
    local label="$1" value="$2" sub="${3:-}" cls="${4:-}"
    html_esc "$label"; local l="$REPLY"
    html_esc "$value"; local v="$REPLY"
    html_esc "$sub"; local s="$REPLY"
    printf '<div class="card %s"><div class="cl">%s</div><div class="cv">%s</div><div class="cs">%s</div></div>\n' "$cls" "$l" "$v" "$s"
}

write_html() {
    local i k lvl name res
    local -a lvcount=(0 0 0 0 0)
    for i in "${!F_LEVEL[@]}"; do
        lvl="${F_LEVEL[$i]}"
        lvcount[$lvl]=$(( lvcount[lvl] + 1 ))
    done

    {
        cat <<'HTML'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:">
<meta name="referrer" content="no-referrer">
<meta name="robots" content="noindex, nofollow">
HTML
        html_esc "Security report - $HOSTNAME_FQDN - $(date '+%Y-%m-%d %H:%M')"
        printf '<title>%s</title>\n' "$REPLY"
        cat <<'CSS'
<style>
:root{--bg:#f6f7f9;--fg:#1c2330;--mut:#5f6b7a;--card:#fff;--line:#e2e6eb;--head:#eef1f5;--acc:#2563eb;
--l0:#15803d;--l1:#a16207;--l2:#c2410c;--l3:#dc2626;--l4:#991b1b;--l0b:#dcfce7;--l1b:#fef9c3;--l2b:#ffedd5;--l3b:#fee2e2;--l4b:#fecaca}
@media (prefers-color-scheme:dark){:root{--bg:#0f141a;--fg:#e3e8ef;--mut:#95a1b2;--card:#171e27;--line:#2a3441;--head:#1d2631;--acc:#60a5fa;
--l0:#4ade80;--l1:#facc15;--l2:#fb923c;--l3:#f87171;--l4:#fca5a5;--l0b:#12301f;--l1b:#3a3210;--l2b:#3d2412;--l3b:#401818;--l4b:#5a1616}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,Ubuntu,sans-serif}
.wrap{max-width:1280px;margin:0 auto;padding:0 20px}
header.top{background:#111827;color:#f3f4f6;padding:22px 0 18px}
header.top h1{margin:4px 0 10px;font-size:24px;font-weight:650}
.brand{font:600 12px/1 ui-monospace,Menlo,Consolas,monospace;letter-spacing:.08em;text-transform:uppercase;color:#93c5fd}
.meta{display:flex;flex-wrap:wrap;gap:6px 22px;color:#cbd5e1;font-size:13px}.meta b{color:#fff;font-weight:600}
nav.toc{position:sticky;top:0;z-index:5;background:var(--card);border-bottom:1px solid var(--line)}
nav.toc .wrap{display:flex;gap:4px;overflow-x:auto;padding:8px 20px;white-space:nowrap}
nav.toc a{color:var(--fg);text-decoration:none;padding:4px 10px;border-radius:6px;font-size:13px}
nav.toc a:hover{background:var(--head)}
section{margin:26px 0}h2{font-size:18px;margin:0 0 12px}h4{font-size:13px;margin:16px 0 6px;color:var(--mut);text-transform:uppercase;letter-spacing:.04em}
.level{display:flex;align-items:center;gap:18px;padding:18px 22px;border-radius:12px;border-left:8px solid;background:var(--card)}
.level .ln{font-size:28px;font-weight:750}.level .lt{color:var(--mut)}
.lv0{border-color:var(--l0)}.lv0 .ln{color:var(--l0)}.lv1{border-color:var(--l1)}.lv1 .ln{color:var(--l1)}
.lv2{border-color:var(--l2)}.lv2 .ln{color:var(--l2)}.lv3{border-color:var(--l3)}.lv3 .ln{color:var(--l3)}.lv4{border-color:var(--l4)}.lv4 .ln{color:var(--l4)}
.sev{margin-left:auto;display:flex;gap:8px;flex-wrap:wrap}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(170px,1fr));gap:12px;margin-top:16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.cl{font-size:12px;color:var(--mut)}.cv{font-size:22px;font-weight:700;margin:2px 0}.cs{font-size:12px;color:var(--mut)}
.card.warn .cv{color:var(--l2)}.card.bad .cv{color:var(--l3)}
.badge{display:inline-block;min-width:74px;text-align:center;padding:2px 8px;border-radius:999px;font-size:12px;font-weight:650}
.l0{background:var(--l0b);color:var(--l0)}.l1{background:var(--l1b);color:var(--l1)}.l2{background:var(--l2b);color:var(--l2)}
.l3{background:var(--l3b);color:var(--l3)}.l4{background:var(--l4b);color:var(--l4)}.lx{background:var(--head);color:var(--mut)}
.scroll{overflow-x:auto;border:1px solid var(--line);border-radius:8px;background:var(--card)}
table{border-collapse:collapse;width:100%}
table.data th,table.data td{padding:6px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
table.data th{background:var(--head);font-weight:600;font-size:12px;cursor:pointer;user-select:none;position:sticky;top:0}
table.data th:hover{color:var(--acc)}table.data tbody tr:hover{background:var(--head)}
table.data td{word-break:break-word;max-width:640px}
table.kv{width:auto;min-width:50%;background:var(--card);border:1px solid var(--line);border-radius:8px;border-collapse:separate;border-spacing:0}
table.kv th,table.kv td{padding:5px 12px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
table.kv th{font-weight:500;color:var(--mut);white-space:nowrap;width:1%}
td.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
td.st{font-weight:650;white-space:nowrap}td.ok{color:var(--l0)}td.warn{color:var(--l2)}td.bad{color:var(--l3)}td.muted{color:var(--mut);font-weight:400}
.cnt{background:var(--head);color:var(--mut);border-radius:999px;padding:0 7px;font-size:11px;margin-left:4px}
.none{color:var(--mut);font-style:italic;margin:4px 0}
details.sec{background:var(--card);border:1px solid var(--line);border-radius:10px;margin:10px 0}
details.sec>summary{cursor:pointer;padding:12px 16px;display:flex;gap:12px;align-items:center;font-weight:600;list-style:none}
details.sec>summary::-webkit-details-marker{display:none}
details.sec>summary::before{content:"\25B8";color:var(--mut);transition:transform .15s}
details.sec[open]>summary::before{transform:rotate(90deg)}
details.sec>summary .sm{margin-left:auto;font-weight:400;color:var(--mut);font-size:13px}
.body{padding:0 16px 16px}
ul.find{list-style:none;padding:0;margin:8px 0}ul.find li{padding:6px 0;border-bottom:1px dashed var(--line);display:flex;gap:10px;align-items:baseline}
ul.notes{color:var(--mut);margin:6px 0;padding-left:18px}
details.raw summary{cursor:pointer;color:var(--acc);margin-top:14px;font-size:13px}
pre{background:#0b1016;color:#d1d9e2;padding:14px;border-radius:8px;overflow:auto;font:12px/1.45 ui-monospace,Menlo,Consolas,monospace;max-height:560px}
.toolbar{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:0 0 10px}
.toolbar label{display:flex;gap:4px;align-items:center;font-size:13px;background:var(--card);border:1px solid var(--line);border-radius:6px;padding:3px 8px}
.toolbar button,.filter{font:inherit;font-size:13px;padding:4px 10px;border:1px solid var(--line);border-radius:6px;background:var(--card);color:var(--fg)}
.toolbar button{cursor:pointer}.filter{margin:0 0 6px;width:260px;max-width:100%}
ul.recs{padding-left:20px}ul.recs li{margin:4px 0}
footer{color:var(--mut);font-size:12px;padding:24px 0 40px;border-top:1px solid var(--line);margin-top:30px}
a{color:var(--acc)}
@media print{nav.toc,.toolbar,.filter{display:none}details.sec{break-inside:avoid}pre{max-height:none;white-space:pre-wrap}body{background:#fff}}
</style>
</head>
<body>
CSS

        # Header
        local root_txt="root"
        [[ "$IS_ROOT" -eq 1 ]] || root_txt="NOT root - results incomplete"
        printf '<header class="top"><div class="wrap"><div class="brand">secmon %s</div><h1>Security Audit Report</h1><div class="meta">\n' "$SCRIPT_VERSION"
        for k in "Host|$HOSTNAME_FQDN" "OS|${SYS_OS:-unknown}" "Kernel|$SYS_KERNEL" "Uptime|${SYS_UPTIME:-unknown}" \
                 "Generated|$(date '+%Y-%m-%d %H:%M:%S %Z')" "Log window|$WINDOW_LABEL" "Privileges|$root_txt"; do
            html_esc "${k%%|*}"; local lab="$REPLY"
            html_esc "${k#*|}"
            printf '<span>%s <b>%s</b></span>\n' "$lab" "$REPLY"
        done
        printf '</div></div></header>\n'

        # Navigation
        printf '<nav class="toc"><div class="wrap"><a href="#summary">Summary</a><a href="#findings">Findings</a><a href="#actions">Actions</a>'
        for name in "${SECTIONS_RUN[@]}"; do
            printf '<a href="#sec-%s">%s</a>' "$name" "$name"
        done
        printf '<a href="#run">Run info</a></div></nav>\n<main class="wrap">\n'

        # Threat level and cards
        local texts=("No significant threats" "Minor issues detected" "Attention required" "Immediate attention needed" "Possible security incident")
        printf '<section id="summary"><div class="level lv%d"><div><div class="ln">%s</div><div class="lt">Threat level &middot; %s</div></div><div class="sev">' \
            "$ALERT_LEVEL" "${LEVEL_NAMES[$ALERT_LEVEL]}" "${texts[$ALERT_LEVEL]}"
        for lvl in 4 3 2 1; do
            printf '<span class="badge l%d">%d %s</span>' "$lvl" "${lvcount[$lvl]}" "${LEVEL_NAMES[$lvl]}"
        done
        printf '</div></div>\n<div class="cards">\n'
        html_card "Findings" "${#F_MSG[@]}" "${lvcount[4]} critical, ${lvcount[3]} high" "$([[ $((lvcount[3] + lvcount[4])) -gt 0 ]] && echo bad)"
        if [[ -n "${STATS[packages_installed]:-}" ]]; then
            html_card "Installed packages" "${STATS[packages_installed]}" "dpkg ${STATS[packages_dpkg]:-0}, snap ${STATS[packages_snap]:-0}"
        fi
        if [[ -n "${STATS[updates_pending]:-}" ]]; then
            html_card "Pending updates" "${STATS[updates_pending]}" "${STATS[updates_security]:-0} security" "$([[ ${STATS[updates_security]:-0} -gt 0 ]] && echo warn)"
        fi
        if [[ -n "${STATS[kernel_modules_loaded]:-}" ]]; then
            html_card "Kernel modules" "${STATS[kernel_modules_loaded]}" "taint ${STATS[kernel_taint_value]:-0}, ${STATS[kernel_modules_tainted]:-0} tainted"
        fi
        if [[ -n "${STATS[net_listening_sockets]:-}" ]]; then
            html_card "Listening sockets" "${STATS[net_listening_sockets]}" "${STATS[net_listening_exposed]:-0} reachable from network"
            html_card "Established TCP" "${STATS[net_established]:-0}" "${STATS[net_remote_peers]:-0} remote peers"
            html_card "Traffic since boot" "$(human_bytes "${STATS[net_rx_bytes]:-0}")" "received; sent $(human_bytes "${STATS[net_tx_bytes]:-0}")"
        fi
        if [[ -n "${STATS[services_running]:-}" ]]; then
            html_card "Running services" "${STATS[services_running]}" "${STATS[services_failed]:-0} failed units" "$([[ ${STATS[services_failed]:-0} -gt 0 ]] && echo warn)"
        fi
        if [[ -n "${STATS[users_login_shell]:-}" ]]; then
            html_card "Login-capable accounts" "${STATS[users_login_shell]}" "${STATS[users_total]:-0} accounts total"
        fi
        if [[ -n "${STATS[processes_total]:-}" ]]; then
            html_card "Processes" "${STATS[processes_total]}" "${STATS[processes_suspicious]:-0} suspicious" "$([[ ${STATS[processes_suspicious]:-0} -gt 0 ]] && echo bad)"
        fi
        if [[ -n "${STATS[suid_sgid_files]:-}" ]]; then
            html_card "SUID/SGID files" "${STATS[suid_sgid_files]}" "${STATS[world_writable_files]:-0} world-writable files"
        fi
        if [[ -n "${STATS[ssh_failure_events]:-}" ]]; then
            html_card "Failed SSH logins" "$TOTAL_FAILED_LOGINS" "${STATS[ssh_attacking_ips]:-0} source IPs" "$([[ $TOTAL_FAILED_LOGINS -ge 100 ]] && echo warn)"
        fi
        html_card "High-risk IPs" "${#SUSP_IPS[@]}" "blocklist candidates" "$([[ ${#SUSP_IPS[@]} -gt 0 ]] && echo warn)"
        printf '</div>\n'

        # Section summary table
        printf '<h2 style="margin-top:22px">Summary by section</h2><div class="scroll"><table class="data"><thead><tr><th>Section</th><th>Result</th><th>Findings</th><th>Key figures</th><th>Time</th></tr></thead><tbody>\n'
        for name in "${SECTIONS_RUN[@]}"; do
            section_result "$name"
            res="$REPLY"
            local figs="" n=0
            local -a keys=()
            if [[ -n "${HEADLINE_STATS[$name]:-}" ]]; then
                IFS=' ' read -r -a keys <<< "${HEADLINE_STATS[$name]}"
            else
                keys=("${STAT_ORDER[@]}")
            fi
            for k in "${keys[@]}"; do
                [[ "${STAT_SEC[$k]:-}" == "$name" && -n "${STATS[$k]:-}" ]] || continue
                figs+="${figs:+ &middot; }${k//_/ }: <b>${STATS[$k]}</b>"
                n=$((n + 1))
                [[ "$n" -ge 4 ]] && break
            done
            html_esc "${SEC_TITLE[$name]:-$name}"
            printf '<tr><td><a href="#sec-%s">%s</a></td><td>%s</td><td class="num">%d</td><td>%s</td><td class="num">%s s</td></tr>\n' \
                "$name" "$REPLY" "$(html_badge "$res")" "${SEC_NFIND[$name]:-0}" "${figs:-&ndash;}" \
                "$(awk -v m="${SEC_MS[$name]:-0}" 'BEGIN { printf "%.1f", m / 1000 }')"
        done
        printf '</tbody></table></div></section>\n'

        # Findings
        printf '<section id="findings"><h2>Findings (%d)</h2>\n' "${#F_MSG[@]}"
        if [[ ${#F_MSG[@]} -gt 0 ]]; then
            printf '<div class="toolbar">'
            for lvl in 4 3 2 1; do
                printf '<label><input type="checkbox" class="fl" value="%d" checked> %s</label>' "$lvl" "${LEVEL_NAMES[$lvl]}"
            done
            printf '</div><div class="scroll"><table class="data" id="ftable"><thead><tr><th>Severity</th><th>Section</th><th>Finding</th></tr></thead><tbody>\n'
            for lvl in 4 3 2 1; do
                for i in "${!F_MSG[@]}"; do
                    [[ "${F_LEVEL[$i]}" -eq "$lvl" ]] || continue
                    html_esc "${F_MSG[$i]}"
                    printf '<tr data-level="%d"><td data-sort="%d">%s</td><td><a href="#sec-%s">%s</a></td><td>%s</td></tr>\n' \
                        "$lvl" "$lvl" "$(html_badge "${LEVEL_NAMES[$lvl]}")" "${F_SEC[$i]}" "${F_SEC[$i]}" "$REPLY"
                done
            done
            printf '</tbody></table></div>\n'
        else
            printf '<p class="none">No findings.</p>\n'
        fi
        printf '</section>\n'

        # Recommendations and IPs
        printf '<section id="actions"><h2>Recommended actions</h2>\n'
        if [[ ${#RECOMMENDATIONS[@]} -gt 0 ]]; then
            printf '<ul class="recs">\n'
            for k in "${RECOMMENDATIONS[@]}"; do
                html_esc "$k"
                printf '<li>%s</li>\n' "$REPLY"
            done
            printf '</ul>\n'
        else
            printf '<p class="none">None.</p>\n'
        fi
        if [[ ${#SUSP_IPS[@]} -gt 0 ]]; then
            local ip
            printf '<h4>High-risk IPs to consider blocking <span class="cnt">%d</span></h4><div class="scroll"><table class="data"><thead><tr><th>IP</th><th>Reasons</th></tr></thead><tbody>\n' "${#SUSP_IPS[@]}"
            while IFS= read -r ip; do
                html_esc "${SUSP_IPS[$ip]//$US/; }"
                printf '<tr><td>%s</td><td>%s</td></tr>\n' "$ip" "$REPLY"
            done < <(printf '%s\n' "${!SUSP_IPS[@]}" | sort -V)
            html_esc "$(block_command)"
            printf '</tbody></table></div><p>Review first, then block, e.g. <code>%s</code></p>\n' "$REPLY"
        fi
        printf '</section>\n'

        # Section details
        printf '<section id="details"><div class="toolbar"><h2 style="margin:0 12px 0 0">Details</h2><button type="button" id="expand">Expand all</button><button type="button" id="collapse">Collapse all</button></div>\n'
        for name in "${SECTIONS_RUN[@]}"; do
            section_result "$name"
            res="$REPLY"
            html_esc "${SEC_TITLE[$name]:-$name}"
            printf '<details class="sec" id="sec-%s"%s><summary>%s %s<span class="sm">%d finding(s) &middot; %s s</span></summary><div class="body">\n' \
                "$name" "$([[ "${SEC_LEVEL[$name]:-0}" -ge 2 ]] && echo " open")" "$(html_badge "$res")" "$REPLY" \
                "${SEC_NFIND[$name]:-0}" "$(awk -v m="${SEC_MS[$name]:-0}" 'BEGIN { printf "%.1f", m / 1000 }')"
            if [[ "${SEC_NFIND[$name]:-0}" -gt 0 ]]; then
                printf '<ul class="find">\n'
                for lvl in 4 3 2 1; do
                    for i in "${!F_MSG[@]}"; do
                        [[ "${F_SEC[$i]}" == "$name" && "${F_LEVEL[$i]}" -eq "$lvl" ]] || continue
                        html_esc "${F_MSG[$i]}"
                        printf '<li>%s <span>%s</span></li>\n' "$(html_badge "${LEVEL_NAMES[$lvl]}")" "$REPLY"
                    done
                done
                printf '</ul>\n'
            fi
            local notes=""
            for i in "${!N_MSG[@]}"; do
                if [[ "${N_SEC[$i]}" == "$name" ]]; then
                    html_esc "${N_MSG[$i]}"
                    notes+="<li>$REPLY</li>"
                fi
            done
            [[ -n "$notes" ]] && printf '<ul class="notes">%s</ul>\n' "$notes"
            for i in "${!T_FILE[@]}"; do
                [[ "${T_SEC[$i]}" == "$name" ]] || continue
                awk -v kind="${T_KIND[$i]}" -v maxrows=1000 "$HTML_TABLE_AWK" "${T_FILE[$i]}"
            done
            if [[ -s "$WORKDIR/sections/$name.ansi" ]]; then
                printf '<details class="raw"><summary>Console output</summary><pre>'
                sed -e 's/\x1b\[[0-9;]*m//g' -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' "$WORKDIR/sections/$name.ansi"
                printf '</pre></details>\n'
            fi
            printf '</div></details>\n'
        done
        printf '</section>\n'

        # Run information
        printf '<section id="run"><h2>Run information</h2><table class="kv"><tbody>\n'
        local src
        for src in auth syslog kern fw f2b web; do
            if [[ -n "${SOURCE_DESC[$src]:-}" ]]; then
                html_esc "${SOURCE_DESC[$src]}"
                printf '<tr><th>Log source: %s</th><td>%s</td></tr>\n' "$src" "$REPLY"
            fi
        done
        for k in "Text report|$REPORT_TXT" "JSON report|$REPORT_JSON" "Deep scan|$([[ $DEEP_SCAN -eq 1 ]] && echo yes || echo no)" \
                 "Network access allowed|$([[ $ONLINE -eq 1 ]] && echo yes || echo no)" \
                 "File system scan|$([[ $FS_SCAN -eq 1 ]] && echo yes || echo no)" "Sections|$(join ', ' "${SECTIONS_RUN[@]}")"; do
            html_esc "${k#*|}"
            printf '<tr><th>%s</th><td>%s</td></tr>\n' "${k%%|*}" "$REPLY"
        done
        printf '</tbody></table>\n'
        if [[ ${#WARNINGS[@]} -gt 0 ]]; then
            printf '<h4>Warnings</h4><ul class="notes">\n'
            for k in "${WARNINGS[@]}"; do
                html_esc "$k"
                printf '<li>%s</li>\n' "$REPLY"
            done
            printf '</ul>\n'
        fi
        printf '</section>\n</main>\n'
        printf '<footer class="wrap">Generated locally by secmon %s on %s. This file is self-contained and loads no external resources. It contains sensitive details about this host: store and share it accordingly.</footer>\n' \
            "$SCRIPT_VERSION" "$(html_esc "$HOSTNAME_FQDN"; printf '%s' "$REPLY")"

        cat <<'JS'
<script>
(function () {
  function key(td) {
    var s = td.getAttribute('data-sort'); if (s !== null) return parseFloat(s);
    var t = td.textContent.trim(), m = t.match(/^-?[\d.,]+\s*([KMGTP]?i?B)?/);
    if (m && /^-?[\d.,]+/.test(t)) {
      var n = parseFloat(t.replace(/,/g, '')), u = {B:1,KiB:1024,MiB:1048576,GiB:1073741824,TiB:1099511627776}[m[1]];
      return u ? n * u : n;
    }
    return t.toLowerCase();
  }
  document.querySelectorAll('table.data').forEach(function (tbl) {
    var body = tbl.tBodies[0]; if (!body) return;
    tbl.querySelectorAll('thead th').forEach(function (th, idx) {
      th.title = 'Sort';
      th.addEventListener('click', function () {
        var asc = th.getAttribute('data-dir') !== 'asc';
        tbl.querySelectorAll('thead th').forEach(function (o) { o.removeAttribute('data-dir'); });
        th.setAttribute('data-dir', asc ? 'asc' : 'desc');
        var rows = Array.prototype.slice.call(body.rows);
        rows.sort(function (a, b) {
          var x = key(a.cells[idx]), y = key(b.cells[idx]);
          if (typeof x === 'number' && typeof y === 'number') return asc ? x - y : y - x;
          return asc ? String(x).localeCompare(String(y)) : String(y).localeCompare(String(x));
        });
        rows.forEach(function (r) { body.appendChild(r); });
      });
    });
    if (body.rows.length > 15) {
      var f = document.createElement('input');
      f.type = 'search'; f.className = 'filter'; f.placeholder = 'Filter ' + body.rows.length + ' rows...';
      f.addEventListener('input', function () {
        var q = f.value.toLowerCase();
        Array.prototype.forEach.call(body.rows, function (r) { r.style.display = r.textContent.toLowerCase().indexOf(q) >= 0 ? '' : 'none'; });
      });
      var wrap = tbl.closest('.scroll') || tbl; wrap.parentNode.insertBefore(f, wrap);
    }
  });
  document.querySelectorAll('input.fl').forEach(function (cb) {
    cb.addEventListener('change', function () {
      var on = {}; document.querySelectorAll('input.fl').forEach(function (c) { on[c.value] = c.checked; });
      document.querySelectorAll('#ftable tbody tr').forEach(function (r) { r.style.display = on[r.getAttribute('data-level')] ? '' : 'none'; });
    });
  });
  function all(open) { document.querySelectorAll('details.sec').forEach(function (d) { d.open = open; }); }
  var e = document.getElementById('expand'), c = document.getElementById('collapse');
  if (e) e.addEventListener('click', function () { all(true); });
  if (c) c.addEventListener('click', function () { all(false); });
  if (location.hash && location.hash.indexOf('#sec-') === 0) { var d = document.querySelector(location.hash); if (d) d.open = true; }
  document.querySelectorAll('a[href^="#sec-"]').forEach(function (a) {
    a.addEventListener('click', function () { var d = document.querySelector(a.getAttribute('href')); if (d) d.open = true; });
  });
})();
</script>
</body>
</html>
JS
    } > "$REPORT_HTML"
}

# ┌────────────────────────────────────────────────────────────────────────────┐
# │ Alerting                                                                   │
# └────────────────────────────────────────────────────────────────────────────┘

syslog_priority() {
    case "$1" in
        4) echo crit ;;
        3) echo err ;;
        2) echo warning ;;
        1) echo notice ;;
        *) echo info ;;
    esac
}

send_email() {
    local subject="$1" body="$2"
    if command -v mail >/dev/null 2>&1; then
        printf '%s\n' "$body" | mail -s "$subject" "$EMAIL_ALERT" || warn "Failed to send e-mail to $EMAIL_ALERT"
    elif command -v sendmail >/dev/null 2>&1; then
        printf 'To: %s\nSubject: %s\n\n%s\n' "$EMAIL_ALERT" "$subject" "$body" | sendmail -t || warn "Failed to send e-mail to $EMAIL_ALERT"
    else
        warn "E-mail alert skipped: neither 'mail' nor 'sendmail' is installed"
    fi
}

send_webhook() {
    local subject="$1" body="$2" level="$3"
    if ! command -v curl >/dev/null 2>&1; then
        warn "Webhook alert skipped: curl is not installed"
        return 0
    fi
    local payload
    payload=$(printf '{"text": %s, "host": %s, "level": %s, "severity": %d}' \
        "$(json_str "$subject"$'\n'"$body")" "$(json_str "$HOSTNAME_FQDN")" "$(json_str "${LEVEL_NAMES[$level]}")" "$level")
    curl -fsS -m 10 -H 'Content-Type: application/json' --data-binary @- -- "$WEBHOOK_URL" <<< "$payload" >/dev/null 2>&1 ||
        warn "Failed to deliver webhook alert"
}

# SIEM: one key=value line per finding plus a run summary
log_findings_to_syslog() {
    if ! command -v logger >/dev/null 2>&1; then
        warn "Syslog output skipped: logger is not installed"
        return 0
    fi
    local i
    for i in "${!F_MSG[@]}"; do
        logger -t secmon -p "authpriv.$(syslog_priority "${F_LEVEL[$i]}")" -- \
            "level=${LEVEL_NAMES[${F_LEVEL[$i]}]} category=${F_CAT[$i]} host=$HOSTNAME_SHORT msg=\"${F_MSG[$i]//\"/\'}\"" || true
    done
    logger -t secmon -p "authpriv.$(syslog_priority "$ALERT_LEVEL")" -- \
        "summary threat_level=${LEVEL_NAMES[$ALERT_LEVEL]} findings=${#F_MSG[@]} failed_logins=$TOTAL_FAILED_LOGINS high_risk_ips=${#SUSP_IPS[@]} report=$REPORT_JSON" || true
}

send_notifications() {
    if [[ "$SYSLOG_ALERT" -eq 1 ]]; then
        log_findings_to_syslog
    fi
    if [[ "$ALERT_LEVEL" -lt "$NOTIFY_LEVEL" ]] || [[ -z "$EMAIL_ALERT" && -z "$WEBHOOK_URL" ]]; then
        return 0
    fi

    local subject body lvl i n=0
    subject="[secmon] ${LEVEL_NAMES[$ALERT_LEVEL]} on $HOSTNAME_FQDN: ${#F_MSG[@]} finding(s)"
    body="Host:         $HOSTNAME_FQDN"$'\n'"Window:       $WINDOW_LABEL"$'\n'"Threat level: ${LEVEL_NAMES[$ALERT_LEVEL]}"$'\n\n'"Findings:"
    for lvl in 4 3 2 1; do
        for i in "${!F_MSG[@]}"; do
            if [[ "${F_LEVEL[$i]}" -eq "$lvl" && "$n" -lt 20 ]]; then
                body+=$'\n'"  [${LEVEL_NAMES[$lvl]}] ${F_CAT[$i]}: ${F_MSG[$i]}"
                n=$((n + 1))
            fi
        done
    done
    body+=$'\n\n'"High-risk IPs: ${#SUSP_IPS[@]}"$'\n'"Report: $REPORT_TXT"

    if [[ -n "$EMAIL_ALERT" ]]; then
        send_email "$subject" "$body"
    fi
    if [[ -n "$WEBHOOK_URL" ]]; then
        send_webhook "$subject" "$body" "$ALERT_LEVEL"
    fi
}

# After "sudo secmon.sh" let the invoking user open the reports in a browser
hand_reports_to_sudo_user() {
    [[ "$IS_ROOT" -eq 1 && -n "${SUDO_UID:-}" && "${SUDO_UID}" != 0 ]] || return 0
    local f
    for f in "$REPORT_TXT" "$REPORT_JSON" "$REPORT_BLOCKLIST" "$REPORT_HTML"; do
        [[ -e "$f" ]] && chown -- "$SUDO_UID:${SUDO_GID:-$SUDO_UID}" "$f" 2>/dev/null
    done
    if [[ "$REPORT_DIR" == "$SCRIPT_DIR/logs" ]]; then
        chown -- "$SUDO_UID:${SUDO_GID:-$SUDO_UID}" "$REPORT_DIR" 2>/dev/null
    fi
    return 0
}

prune_reports() {
    if [[ "$REPORT_RETENTION_DAYS" -gt 0 ]]; then
        find "$REPORT_DIR" -maxdepth 1 -type f -name 'security_monitor_*' -mtime +"$REPORT_RETENTION_DAYS" -delete 2>/dev/null || true
    fi
}

# ┌────────────────────────────────────────────────────────────────────────────┐
# │ Watch Mode                                                                 │
# └────────────────────────────────────────────────────────────────────────────┘

readonly RE_SSH_FAIL=': Failed [^ ]+ for (invalid user )?(.*) from ([0-9a-fA-F:.]+) port'
readonly RE_SSH_INVALID=': Invalid user (.*) from ([0-9a-fA-F:.]+) port'
readonly RE_SSH_ACCEPT=': Accepted ([^ ]+) for (.*) from ([0-9a-fA-F:.]+) port'
readonly RE_SUDO_DENIED='sudo(\[[0-9]+\])?: +([^ ]+) : .*(NOT in sudoers|not in the sudoers file)'
readonly RE_NEW_USER='(useradd|adduser)(\[[0-9]+\])?: new user: name=([^,]+)'
readonly RE_PRIV_GROUP="(add '([^']+)' to group|user ([^ ]+) added by [^ ]+ to group) '?($PRIV_GROUPS_RE)'?( |$|,)"
readonly RE_FW_BLOCK='\[UFW BLOCK\]|FINAL_(REJECT|DROP)|_(REJECT|DROP):? IN='

watch_alert() {
    local level="$1" message="$2"
    printf '%b[%s]%b ' "$C_GREY" "$(date '+%H:%M:%S')" "$C_RESET"
    print_alert "$level" "[${LEVEL_NAMES[$level]}] $message"
    if [[ "$SYSLOG_ALERT" -eq 1 ]] && command -v logger >/dev/null 2>&1; then
        logger -t secmon -p "authpriv.$(syslog_priority "$level")" -- "watch level=${LEVEL_NAMES[$level]} host=$HOSTNAME_SHORT msg=\"$message\"" || true
    fi
    if [[ "$level" -ge "$NOTIFY_LEVEL" ]]; then
        local subject="[secmon] ${LEVEL_NAMES[$level]} on $HOSTNAME_FQDN (watch)"
        [[ -n "$EMAIL_ALERT" ]] && send_email "$subject" "$message"
        [[ -n "$WEBHOOK_URL" ]] && send_webhook "$subject" "$message" "$level"
    fi
    return 0
}

watch_mode() {
    local -a cmd=()
    local auth_file="" fw_file=""

    if [[ "$USE_JOURNAL" != "yes" ]]; then
        auth_file=$(first_existing "$AUTH_LOG" /var/log/auth.log /var/log/secure) || true
        fw_file=$(first_existing "$UFW_LOG" /var/log/ufw.log "$KERN_LOG" /var/log/kern.log) || true
    fi
    if [[ -n "$auth_file" ]]; then
        cmd=(tail -n 0 -q -F -- "$auth_file")
        [[ -n "$fw_file" ]] && cmd+=("$fw_file")
    elif journal_ok; then
        cmd=(journalctl --no-pager -q -f -n 0 -o short-iso SYSLOG_FACILITY=4 SYSLOG_FACILITY=10 + _TRANSPORT=kernel)
    else
        die 3 "No log source available for watch mode"
    fi

    printf '%b┌─ WATCH MODE ─────────────────────────────────────────────────────────────┐%b\n' "${C_CYAN}${C_BOLD}" "$C_RESET"
    printf '%b│%b  Following: %s\n' "${C_CYAN}${C_BOLD}" "$C_WHITE" "${auth_file:-journald}${fw_file:+, $fw_file}"
    printf '%b│%b  Brute-force alert at %s failures/IP/hour. Status every %ss. Ctrl+C to stop.\n' \
        "${C_CYAN}${C_BOLD}" "$C_WHITE" "$ALERT_THRESHOLD" "$WATCH_INTERVAL"
    printf '%b└──────────────────────────────────────────────────────────────────────────┘%b\n\n' "${C_CYAN}${C_BOLD}" "$C_RESET"

    local -A fails=() ports=() nports=() alerted=()
    local line ip user method port key rc
    local last_beat=$SECONDS window_start=$SECONDS
    local n_fail=0 n_block=0 n_accept=0

    while true; do
        if IFS= read -r -t "$WATCH_INTERVAL" line; then
            if [[ "$line" =~ $RE_SSH_FAIL ]] || [[ "$line" =~ $RE_SSH_INVALID ]]; then
                if [[ "$line" =~ $RE_SSH_FAIL ]]; then
                    user="${BASH_REMATCH[2]}"; ip="${BASH_REMATCH[3]}"
                else
                    user="${BASH_REMATCH[1]}"; ip="${BASH_REMATCH[2]}"
                fi
                n_fail=$((n_fail + 1))
                fails[$ip]=$(( ${fails[$ip]:-0} + 1 ))
                if [[ "$VERBOSE" -eq 1 ]]; then
                    printf '%b[%s]%b %bSSH failure%b user=%s from %b%s%b (%d this hour)\n' "$C_GREY" "$(date '+%H:%M:%S')" "$C_RESET" \
                        "$C_RED" "$C_RESET" "$(sanitize "$user")" "$C_CYAN" "$ip" "$C_RESET" "${fails[$ip]}"
                fi
                if [[ "${fails[$ip]}" -ge "$ALERT_THRESHOLD" && -z "${alerted[bf:$ip]:-}" ]] && ! is_whitelisted "$ip"; then
                    alerted[bf:$ip]=1
                    watch_alert 2 "SSH brute force from $ip (${fails[$ip]} failures this hour)"
                fi
            elif [[ "$line" =~ $RE_SSH_ACCEPT ]]; then
                method="${BASH_REMATCH[1]}"; user="$(sanitize "${BASH_REMATCH[2]}")"; ip="${BASH_REMATCH[3]}"
                n_accept=$((n_accept + 1))
                printf '%b[%s]%b %bSSH login%b %s from %b%s%b (%s)\n' "$C_GREY" "$(date '+%H:%M:%S')" "$C_RESET" \
                    "$C_GREEN" "$C_RESET" "$user" "$C_CYAN" "$ip" "$C_RESET" "$method"
                if [[ "${fails[$ip]:-0}" -ge "$SUCCESS_AFTER_FAIL_THRESHOLD" ]] && ! is_whitelisted "$ip"; then
                    watch_alert 4 "Successful SSH login as '$user' from $ip after ${fails[$ip]} failures - possible compromise"
                fi
            elif [[ "$line" =~ $RE_SUDO_DENIED ]]; then
                watch_alert 3 "sudo attempt by '$(sanitize "${BASH_REMATCH[2]}")' who is not in sudoers"
            elif [[ "$line" =~ $RE_NEW_USER ]]; then
                watch_alert 2 "New user account created: $(sanitize "${BASH_REMATCH[3]}")"
                if [[ "$line" == *", UID=0,"* ]]; then
                    watch_alert 4 "New account with UID 0: $(sanitize "${BASH_REMATCH[3]}")"
                fi
            elif [[ "$line" =~ $RE_PRIV_GROUP ]]; then
                watch_alert 3 "User added to privileged group: $(sanitize "${BASH_REMATCH[0]}")"
            elif [[ "$line" =~ $RE_FW_BLOCK ]]; then
                n_block=$((n_block + 1))
                if [[ "$line" =~ SRC=([0-9a-fA-F:.]+) ]]; then
                    ip="${BASH_REMATCH[1]}"
                    if [[ "$line" =~ DPT=([0-9]+) ]]; then
                        port="${BASH_REMATCH[1]}"
                        key="$ip:$port"
                        if [[ -z "${ports[$key]:-}" ]]; then
                            ports[$key]=1
                            nports[$ip]=$(( ${nports[$ip]:-0} + 1 ))
                        fi
                        if [[ "${nports[$ip]}" -ge "$SCAN_PORT_THRESHOLD" && -z "${alerted[scan:$ip]:-}" ]] && ! is_whitelisted "$ip"; then
                            alerted[scan:$ip]=1
                            watch_alert 2 "Port scan from $ip (${nports[$ip]} distinct ports blocked)"
                        fi
                    fi
                fi
            fi
        else
            rc=$?
            if [[ "$rc" -le 128 ]]; then
                warn "Log stream ended"
                break
            fi
        fi

        if (( SECONDS - last_beat >= WATCH_INTERVAL )); then
            if (( n_fail + n_block + n_accept > 0 )); then
                printf '%b[%s] last %ss: %d SSH failure(s), %d login(s), %d firewall block(s)%b\n' \
                    "$C_GREY" "$(date '+%H:%M:%S')" "$(( SECONDS - last_beat ))" "$n_fail" "$n_accept" "$n_block" "$C_RESET"
            fi
            n_fail=0; n_block=0; n_accept=0
            last_beat=$SECONDS
        fi
        if (( SECONDS - window_start >= 3600 )); then
            fails=(); ports=(); nports=(); alerted=()
            window_start=$SECONDS
        fi
    done < <("${cmd[@]}" 2>/dev/null)
}

# ┌────────────────────────────────────────────────────────────────────────────┐
# │ Main                                                                       │
# └────────────────────────────────────────────────────────────────────────────┘

progress() {
    if [[ "$PROGRESS" -eq 1 ]]; then
        printf '\r\033[K  %s running %s ...' "$SYM_GEAR" "$1" >&2
    fi
    return 0
}

progress_done() {
    if [[ "$PROGRESS" -eq 1 ]]; then
        printf '\r\033[K' >&2
    fi
    return 0
}

now_ms() {
    local t="${EPOCHREALTIME/[.,]/}"
    echo $(( t / 1000 ))
}

# Each section writes to its own file, so its console output can be embedded
# in the HTML report, and is then copied to the terminal/report stream.
run_section() {
    local name="$1" fn="$2" out start
    section_enabled "$name" || return 0
    SECTIONS_RUN+=("$name")
    SECTION_CUR="$name"
    SUB_CUR=""
    TBL_REC_SEQ=-1
    SEC_LEVEL[$name]=0
    SEC_NFIND[$name]=0
    SEC_STATUS[$name]="completed"
    out="$WORKDIR/sections/$name.ansi"
    progress "$name"
    start=$(now_ms)
    # Running in a || context keeps one failing check from aborting the report
    if ! "$fn" > "$out"; then
        SEC_STATUS[$name]="incomplete"
        warn "Section '$name' did not complete cleanly"
    fi
    SEC_MS[$name]=$(( $(now_ms) - start ))
    progress_done
    cat -- "$out"
    SECTION_CUR=""
    SUB_CUR=""
}

setup_output() {
    exec 3>&1
    REAL_OUT=3
    if [[ "$QUIET" -eq 1 || "$JSON_OUTPUT" -eq 1 || "$NAGIOS_MODE" -eq 1 ]]; then
        exec 1>"$WORKDIR/report.ansi"
    else
        exec 1> >(tee "$WORKDIR/report.ansi")
        TEE_PID=$!
    fi
}

finish_output() {
    exec 1>&3
    if [[ -n "$TEE_PID" ]]; then
        wait "$TEE_PID" 2>/dev/null || true
    fi
    sed 's/\x1b\[[0-9;]*m//g' "$WORKDIR/report.ansi" > "$REPORT_TXT"
}

main() {
    preload_config "$@"
    parse_args "$@"
    validate_settings

    local use_color=0
    if [[ "$COLOR_MODE" != "never" && "$JSON_OUTPUT" -eq 0 && "$NAGIOS_MODE" -eq 0 && -t 1 && "${TERM:-}" != "dumb" && -z "${NO_COLOR:-}" ]]; then
        use_color=1
    fi
    setup_colors "$use_color"
    build_whitelist
    check_privileges

    mkdir -p -- "$REPORT_DIR" || die 3 "Cannot create report directory $REPORT_DIR"
    chmod 700 -- "$REPORT_DIR" 2>/dev/null || true

    if [[ "$WATCH_MODE" -eq 1 ]]; then
        acquire_lock secmon-watch
        print_banner
        watch_mode
        exit 0
    fi

    acquire_lock secmon
    compute_window
    WORKDIR=$(mktemp -d "${TMPDIR:-/tmp}/secmon.XXXXXXXX") || die 3 "Cannot create temporary directory"
    mkdir -p -- "$WORKDIR/tables" "$WORKDIR/sections"
    if [[ -t 2 && "$NAGIOS_MODE" -eq 0 ]]; then
        PROGRESS=1
    fi
    REPORT_BASE="${REPORT_DIR}/security_monitor_${HOSTNAME_SHORT}_${TIMESTAMP}"
    REPORT_TXT="${REPORT_BASE}.log"
    REPORT_JSON="${REPORT_BASE}.json"
    REPORT_BLOCKLIST="${REPORT_BASE}.blocklist"
    REPORT_HTML="${REPORT_BASE}.html"

    setup_output
    print_banner

    run_section system      section_system
    run_section packages    section_packages
    run_section modules     section_modules
    run_section network     section_network
    run_section services    section_services
    run_section users       section_users
    run_section hardening   section_hardening
    run_section filesystem  section_filesystem
    run_section processes   section_processes
    run_section ssh         section_ssh
    run_section bruteforce  section_bruteforce
    run_section fail2ban    section_fail2ban
    run_section firewall    section_firewall
    run_section privesc     section_privesc
    run_section accounts    section_accounts
    run_section web         section_web
    run_section persistence section_persistence
    run_section kernel      section_kernel
    run_section rootkit     section_rootkit

    local summary_offset
    summary_offset=$(stat -c %s "$WORKDIR/report.ansi")
    print_threat_summary
    finish_output

    write_json
    write_blocklist
    if [[ "$HTML_REPORT" -eq 1 ]]; then
        write_html
    fi
    hand_reports_to_sudo_user

    if [[ "$JSON_OUTPUT" -eq 1 ]]; then
        cat -- "$REPORT_JSON"
    elif [[ "$QUIET" -eq 1 && "$NAGIOS_MODE" -eq 0 ]]; then
        tail -c +"$((summary_offset + 1))" -- "$WORKDIR/report.ansi"
    fi

    send_notifications
    prune_reports

    if [[ "$NAGIOS_MODE" -eq 1 ]]; then
        local rc=0
        nagios_output || rc=$?
        exit "$rc"
    fi
    exit 0
}

main "$@"

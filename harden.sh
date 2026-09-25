#!/usr/bin/env bash
#
# harden.sh — Ubuntu Security Audit & Hardening Suite
#
# Audits an Ubuntu server against a CIS-inspired baseline and, when asked,
# applies hardening that keeps an internet-facing web server usable:
#
#   * SSH password logins are only turned off once every login user has a key
#   * the firewall always allows the SSH port(s) and the web ports
#   * user umasks, /tmp mount options, IP forwarding and IPv6 router
#     advertisements are left alone, so web apps, containers and cloud
#     networking keep working
#
# Every change is backed up and recorded in a manifest, and --rollback
# reverts a run. Each run writes an HTML report, a JSON report and a log.
#
# Supported: Ubuntu 22.04 LTS and newer.
# Author:    Cezary Kos
# License:   MIT

set -Eeuo pipefail
shopt -s nullglob
# Bash 5.2+ would treat "&" in ${var//x/y} replacements as the match; the
# HTML escaping below needs a literal "&".
shopt -u patsub_replacement 2>/dev/null || true
export LC_ALL=C.UTF-8

readonly SCRIPT_VERSION="3.0.0"
readonly SCRIPT_NAME="${0##*/}"
SCRIPT_PATH="$(readlink -f "$0" 2>/dev/null || printf '%s' "$0")"
readonly SCRIPT_PATH
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
readonly TIMESTAMP
HOST_SHORT="$(hostname -s 2>/dev/null || hostname)"
readonly HOST_SHORT
FQDN="$(hostname -f 2>/dev/null || hostname)"
readonly FQDN
readonly LOCK_FILE="/run/ubuntu-hardening.lock"
readonly MANAGED_TAG="Managed by ubuntu-hardening (harden.sh v${SCRIPT_VERSION})"

readonly SSHD_CONFIG="/etc/ssh/sshd_config"
readonly SSHD_DROPIN="/etc/ssh/sshd_config.d/00-ubuntu-hardening.conf"
readonly SYSCTL_FILE="/etc/sysctl.d/99-ubuntu-hardening.conf"
readonly MODPROBE_FILE="/etc/modprobe.d/ubuntu-hardening.conf"
readonly F2B_JAIL="/etc/fail2ban/jail.d/zz-ubuntu-hardening.local"
readonly AUDIT_RULES="/etc/audit/rules.d/50-ubuntu-hardening.rules"
readonly JOURNALD_DROPIN="/etc/systemd/journald.conf.d/50-ubuntu-hardening.conf"
readonly COREDUMP_DROPIN="/etc/systemd/coredump.conf.d/50-ubuntu-hardening.conf"
readonly LIMITS_FILE="/etc/security/limits.d/50-ubuntu-hardening.conf"
readonly AUTOUPGRADE_FILE="/etc/apt/apt.conf.d/20auto-upgrades"
readonly UNATTENDED_FILE="/etc/apt/apt.conf.d/52ubuntu-hardening"
readonly PWQUALITY_CONF="/etc/security/pwquality.conf"
readonly NGINX_DROPIN="/etc/nginx/conf.d/00-ubuntu-hardening.conf"
readonly APACHE_CONF_NAME="zz-ubuntu-hardening"

readonly AREAS="updates,firewall,ssh,fail2ban,kernel,filesystem,accounts,logging,apparmor,time,web,tools"

# ─── Settings (override with --config FILE or command-line options) ─────────

MODE_HARDEN=0
DRY_RUN=0
ASSUME_YES=0
VERBOSE=0
QUIET=0
JSON_OUTPUT=0
NO_COLOR="${NO_COLOR:-}"

PROFILE="baseline"
SKIP_AREAS=""
SSH_PORT=""
SSH_CLOSE_OLD_PORT=0
SSH_PASSWORD_AUTH="auto"
SSH_ALLOW_FROM=""
SSH_BANNER=0
ADMIN_IPS=""
ALLOW_TCP="80,443"
ALLOW_UDP=""
ALLOW_DETECTED=0
WITH_AIDE=0
WITH_CLAMAV=0
RUN_LYNIS=0
AUTO_REBOOT_TIME=""
FAIL_ON=""
REPORT_ROOT="/var/log/ubuntu-hardening"
BACKUP_ROOT="/var/backups/ubuntu-hardening"
ROLLBACK_TARGET=""
LIST_BACKUPS=0

# Keys a --config file may set.
readonly CONFIG_KEYS=" PROFILE SKIP_AREAS SSH_PORT SSH_CLOSE_OLD_PORT SSH_PASSWORD_AUTH SSH_ALLOW_FROM SSH_BANNER ADMIN_IPS ALLOW_TCP ALLOW_UDP ALLOW_DETECTED WITH_AIDE WITH_CLAMAV RUN_LYNIS AUTO_REBOOT_TIME FAIL_ON REPORT_ROOT BACKUP_ROOT "

# ─── Run state ─────────────────────────────────────────────────────────────

RUN_DIR="" LOG_FILE="/dev/null" HTML_FILE="" JSON_FILE=""
BACKUP_DIR="" MANIFEST="" WORK_DIR=""
HARDEN_STARTED=0
CURRENT_AREA=""
LAST_WRITE=""
APT_UPDATED=0
SCORE_BEFORE="" SCORE_AFTER=""
LYNIS_INDEX=""
SSH_SESSION_NOTE=0

declare -a F_ID=() F_STATUS=() F_SEV=() F_AREA=() F_TITLE=() F_DETAIL=() F_FIX=()
declare -a A_STATUS=() A_AREA=() A_TEXT=()
declare -a SI_KEY=() SI_VAL=()
declare -a X_PROTO=() X_ADDR=() X_PORT=() X_PROC=() X_FW=()
declare -a L_PROTO=() L_ADDR=() L_PORT=() L_PROC=()
declare -a CURRENT_SSH_PORTS=() SSH_TARGET_PORTS=()
declare -A BACKED_UP=() SCAN_CACHE=()

SSHD_T=""
UFW_ACTIVE=0
UFW_STATUS=""

# ─── Terminal output ───────────────────────────────────────────────────────

setup_colors() {
    if [[ -t 1 && -z $NO_COLOR && ${TERM:-dumb} != dumb && $JSON_OUTPUT -eq 0 ]]; then
        C_RESET=$'\e[0m' C_BOLD=$'\e[1m'
        C_RED=$'\e[38;5;203m' C_ORANGE=$'\e[38;5;215m' C_YELLOW=$'\e[38;5;221m'
        C_GREEN=$'\e[38;5;114m' C_BLUE=$'\e[38;5;75m' C_CYAN=$'\e[38;5;80m'
        C_GREY=$'\e[38;5;245m'
    else
        C_RESET="" C_BOLD="" C_RED="" C_ORANGE="" C_YELLOW=""
        C_GREEN="" C_BLUE="" C_CYAN="" C_GREY=""
    fi
}

say() { [[ $QUIET -eq 1 ]] || printf '%s\n' "$*"; }

debug() {
    if [[ $VERBOSE -eq 1 ]]; then
        printf '  %s[debug] %s%s\n' "$C_GREY" "$*" "$C_RESET"
    fi
}

die() {
    printf '%sError:%s %s\n' "$C_RED$C_BOLD" "$C_RESET" "$1" >&2
    exit "${2:-1}"
}

usage_error() {
    printf '%sError:%s %s\nRun %s --help for usage.\n' "$C_RED$C_BOLD" "$C_RESET" "$1" "$SCRIPT_NAME" >&2
    exit 2
}

section() {
    CURRENT_AREA=$1
    [[ $QUIET -eq 1 ]] && return 0
    local rule
    printf -v rule '%*s' $((70 - ${#1})) ''
    printf '\n%s%s %s%s\n' "$C_BLUE$C_BOLD" "$1" "${rule// /─}" "$C_RESET"
}

_line() { # colour label text
    [[ $QUIET -eq 1 ]] && return 0
    printf '  %s%-8s%s %s\n' "$1" "$2" "$C_RESET" "$3"
}

_sub() { # grey, indented detail lines
    [[ $QUIET -eq 1 || -z $1 ]] && return 0
    local l
    while IFS= read -r l; do
        printf '           %s%s%s\n' "$C_GREY" "$l" "$C_RESET"
    done <<<"$1"
}

sev_color() {
    case $1 in
        critical) printf '%s' "$C_RED$C_BOLD" ;;
        high)     printf '%s' "$C_RED" ;;
        medium)   printf '%s' "$C_ORANGE" ;;
        low)      printf '%s' "$C_YELLOW" ;;
        *)        printf '%s' "$C_CYAN" ;;
    esac
}

sev_rank() {
    case $1 in critical) echo 4 ;; high) echo 3 ;; medium) echo 2 ;; low) echo 1 ;; *) echo 0 ;; esac
}

sev_weight() {
    case $1 in critical) echo 10 ;; high) echo 5 ;; medium) echo 3 ;; low) echo 1 ;; *) echo 0 ;; esac
}

# ─── Findings (audit results) and actions (hardening steps) ────────────────

# check STATUS SEVERITY ID TITLE [DETAIL] [REMEDIATION]
check() {
    local status=$1 sev=$2 id=$3 title=$4 detail=${5:-} fix=${6:-}
    F_ID+=("$id") F_STATUS+=("$status") F_SEV+=("$sev") F_AREA+=("$CURRENT_AREA")
    F_TITLE+=("$title") F_DETAIL+=("$detail") F_FIX+=("$fix")
    case $status in
        PASS) _line "$C_GREEN" "PASS" "$title" ;;
        FAIL) _line "$(sev_color "$sev")" "${sev^^}" "$title"; _sub "$detail" ;;
        INFO)
            _line "$C_CYAN" "INFO" "$title"
            if [[ $VERBOSE -eq 1 ]]; then _sub "$detail"; fi
            ;;
    esac
}

pass() { check PASS "$@"; }       # pass SEV ID TITLE [DETAIL]
fail() { check FAIL "$@"; }       # fail SEV ID TITLE DETAIL REMEDIATION
info() { check INFO info "$@"; }  # info ID TITLE [DETAIL]

# act STATUS TEXT — STATUS is CHANGED, OK, PLANNED, SKIPPED, NOTE or ERROR.
act() {
    A_STATUS+=("$1") A_AREA+=("$CURRENT_AREA") A_TEXT+=("$2")
    case $1 in
        CHANGED) _line "$C_GREEN$C_BOLD" "CHANGED" "$2" ;;
        OK)      _line "$C_GREEN" "OK" "$2" ;;
        PLANNED) _line "$C_CYAN" "PLAN" "$2" ;;
        SKIPPED) _line "$C_GREY" "SKIPPED" "$2" ;;
        NOTE)    _line "$C_YELLOW" "NOTE" "$2" ;;
        ERROR)   _line "$C_RED$C_BOLD" "ERROR" "$2" ;;
    esac
}

sysinfo() {
    SI_KEY+=("$1") SI_VAL+=("$2")
    [[ $QUIET -eq 1 ]] && return 0
    printf '  %s%-16s%s %s\n' "$C_GREY" "$1" "$C_RESET" "$2"
}

reset_findings() {
    F_ID=() F_STATUS=() F_SEV=() F_AREA=() F_TITLE=() F_DETAIL=() F_FIX=()
    SI_KEY=() SI_VAL=()
    X_PROTO=() X_ADDR=() X_PORT=() X_PROC=() X_FW=()
}

compute_score() {
    local i w earned=0 total=0
    for i in "${!F_ID[@]}"; do
        if [[ ${F_STATUS[i]} == INFO ]]; then continue; fi
        w=$(sev_weight "${F_SEV[i]}")
        total=$((total + w))
        if [[ ${F_STATUS[i]} == PASS ]]; then earned=$((earned + w)); fi
    done
    if [[ $total -eq 0 ]]; then echo 100; else echo $((earned * 100 / total)); fi
}

grade() {
    local s=$1
    if ((s >= 90)); then echo A; elif ((s >= 80)); then echo B; elif ((s >= 70)); then echo C
    elif ((s >= 60)); then echo D; else echo F; fi
}

count_findings() { # STATUS [SEVERITY]
    local i n=0
    for i in "${!F_ID[@]}"; do
        if [[ ${F_STATUS[i]} == "$1" && ( -z ${2:-} || ${F_SEV[i]} == "$2" ) ]]; then n=$((n + 1)); fi
    done
    echo "$n"
}

count_actions() {
    local s n=0
    for s in "${A_STATUS[@]}"; do
        if [[ $s == "$1" ]]; then n=$((n + 1)); fi
    done
    echo "$n"
}

# ─── Generic helpers ───────────────────────────────────────────────────────

area_enabled() { [[ ",$SKIP_AREAS," != *",$1,"* ]]; }

split_csv() { # STRING ARRAY_NAME — splits on commas and whitespace
    local -n _out=$2
    local _item
    _out=()
    for _item in ${1//,/ }; do
        _out+=("$_item")
    done
}

contains() { # NEEDLE ITEMS...
    local needle=$1 x
    shift
    for x in "$@"; do
        if [[ $x == "$needle" ]]; then return 0; fi
    done
    return 1
}

is_port() { [[ $1 =~ ^[0-9]{1,5}$ ]] && ((10#$1 >= 1 && 10#$1 <= 65535)); }

is_port_spec() {
    if [[ $1 == *:* ]]; then
        is_port "${1%%:*}" && is_port "${1#*:}" && ((10#${1%%:*} < 10#${1#*:}))
    else
        is_port "$1"
    fi
}

is_cidr() {
    local ip=${1%/*} bits="" o
    [[ $1 == */* ]] && bits=${1#*/}
    if [[ $ip =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]]; then
        for o in "${BASH_REMATCH[@]:1}"; do ((10#$o <= 255)) || return 1; done
        [[ -z $bits ]] || { [[ $bits =~ ^[0-9]+$ ]] && ((bits <= 32)); }
    elif [[ $ip == *:* && $ip =~ ^[0-9a-fA-F:]+$ ]]; then
        [[ -z $bits ]] || { [[ $bits =~ ^[0-9]+$ ]] && ((bits <= 128)); }
    else
        return 1
    fi
}

ip4_to_int() {
    local IFS=. o
    read -ra o <<<"$1"
    echo $(((10#${o[0]} << 24) + (10#${o[1]} << 16) + (10#${o[2]} << 8) + 10#${o[3]}))
}

ip_in_cidr() { # IP CIDR
    local ip=$1 net=${2%/*} bits=32 mask
    if [[ $ip == *:* || $net == *:* ]]; then
        [[ $ip == "$net" ]]
        return
    fi
    [[ $2 == */* ]] && bits=${2#*/}
    mask=$(((0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF))
    ((bits == 0)) && mask=0
    (( ($(ip4_to_int "$ip") & mask) == ($(ip4_to_int "$net") & mask) ))
}

pkg_installed() {
    local s
    s=$(dpkg-query -W -f='${Status}' "$1" 2>/dev/null) || return 1
    [[ $s == "install ok installed" ]]
}

service_active() { systemctl is-active --quiet "$1" 2>/dev/null; }

unit_exists() {
    local out
    out=$(systemctl list-unit-files --no-legend "$1" 2>/dev/null) || true
    [[ -n $out ]]
}

file_mtime_days() { # prints age in days, or nothing
    local m
    m=$(stat -c %Y "$1" 2>/dev/null) || return 0
    echo $((($(date +%s) - m) / 86400))
}

# Address of the SSH client this script runs under, if any.
ssh_client_ip() {
    local c=${SSH_CONNECTION:-${SSH_CLIENT:-}} who_out
    if [[ -n $c ]]; then
        printf '%s' "${c%% *}"
        return 0
    fi
    who_out=$(who -m 2>/dev/null) || true
    if [[ $who_out =~ \(([0-9a-fA-F:.]+)\) ]]; then printf '%s' "${BASH_REMATCH[1]}"; fi
}

# ─── Change management: confirmation, backups, manifest ────────────────────

confirm() {
    local reply
    while true; do
        printf '  %s?%s %s [Y/n] ' "$C_YELLOW$C_BOLD" "$C_RESET" "$1" >/dev/tty
        read -r reply </dev/tty || return 1
        case ${reply,,} in
            "" | y | yes) return 0 ;;
            n | no) return 1 ;;
        esac
    done
}

# Asks once per hardening area. Dry runs and --yes never prompt.
approve() {
    if [[ $DRY_RUN -eq 1 || $ASSUME_YES -eq 1 ]]; then return 0; fi
    if confirm "$1"; then return 0; fi
    act SKIPPED "$CURRENT_AREA hardening (declined)"
    return 1
}

manifest_add() { # KIND ARG1 [ARG2] [ARG3]
    [[ $DRY_RUN -eq 1 ]] && return 0
    printf '%s\t%s\t%s\t%s\n' "$1" "$2" "${3:-}" "${4:-}" >>"$MANIFEST"
}

backup_file() {
    local path=$1
    [[ -n ${BACKED_UP[$path]:-} ]] && return 0
    BACKED_UP[$path]=1
    if [[ -e $path || -L $path ]]; then
        mkdir -p "$BACKUP_DIR/files$(dirname "$path")"
        cp -a "$path" "$BACKUP_DIR/files$path"
        manifest_add modified "$path"
    else
        manifest_add created "$path"
    fi
}

# Restores a file changed during this run (used when validation fails).
revert_file() {
    local path=$1
    if [[ -e $BACKUP_DIR/files$path || -L $BACKUP_DIR/files$path ]]; then
        cp -a "$BACKUP_DIR/files$path" "$path"
    else
        rm -f -- "$path"
    fi
}

# write_config PATH MODE DESCRIPTION < content
# MODE may be "keep" to preserve an existing file's mode. Sets LAST_WRITE to
# changed, unchanged, planned or failed.
write_config() {
    local path=$1 mode=$2 desc=$3 tmp
    tmp=$(mktemp "$WORK_DIR/cfg.XXXXXX")
    cat >"$tmp"
    if [[ -f $path ]] && cmp -s "$tmp" "$path"; then
        act OK "$desc"
        LAST_WRITE=unchanged
        return 0
    fi
    if [[ $mode == keep ]]; then
        mode=$(stat -c %a "$path" 2>/dev/null || echo 644)
    fi
    if [[ $DRY_RUN -eq 1 ]]; then
        if [[ $desc == *"$path"* ]]; then act PLANNED "$desc"; else act PLANNED "$desc ($path)"; fi
        if [[ $VERBOSE -eq 1 && $QUIET -eq 0 ]]; then
            diff -u "$([[ -f $path ]] && echo "$path" || echo /dev/null)" "$tmp" 2>/dev/null |
                tail -n +3 | sed "s/^/           /" || true
        fi
        LAST_WRITE=planned
        return 0
    fi
    backup_file "$path"
    if install -D -m "$mode" -o root -g root "$tmp" "$path"; then
        act CHANGED "$desc"
        LAST_WRITE=changed
    else
        act ERROR "Could not write $path"
        LAST_WRITE=failed
    fi
}

# set_options FILE FORMAT DESCRIPTION KEY=VALUE|FLAG...
# Sets "key = value" style options (or bare flags) in place, keeping the rest
# of the file.
set_options() {
    local file=$1 fmt=$2 desc=$3 kv key value line tmp
    shift 3
    tmp=$(mktemp "$WORK_DIR/opt.XXXXXX")
    if [[ -f $file ]]; then cp "$file" "$tmp"; fi
    for kv in "$@"; do
        if [[ $kv == *=* ]]; then
            key=${kv%%=*} value=${kv#*=}
            # shellcheck disable=SC2059  # the format is supplied by the caller
            printf -v line "$fmt" "$key" "$value"
        else
            key=$kv line=$kv
        fi
        awk -v k="$key" -v line="$line" '
            $0 ~ "^[[:space:]]*" k "([[:space:]]*=|[[:space:]]*$)" { if (!done) { print line; done = 1 }; next }
            { print }
            END { if (!done) print line }' "$tmp" >"$tmp.new"
        mv "$tmp.new" "$tmp"
    done
    write_config "$file" keep "$desc" <"$tmp"
}

run_cmd() { # DESCRIPTION COMMAND... — runs a command, output goes to the log
    local desc=$1
    shift
    if [[ $DRY_RUN -eq 1 ]]; then
        act PLANNED "$desc"
        return 0
    fi
    debug "exec: $*"
    if "$@" >>"$LOG_FILE" 2>&1; then return 0; fi
    act ERROR "$desc failed (see log)"
    return 1
}

apt_update_once() {
    [[ $APT_UPDATED -eq 1 || $DRY_RUN -eq 1 ]] && return 0
    say "  ${C_GREY}…        refreshing package index${C_RESET}"
    if DEBIAN_FRONTEND=noninteractive apt-get update -q >>"$LOG_FILE" 2>&1; then
        APT_UPDATED=1
    else
        act ERROR "apt-get update failed (see log)"
    fi
}

# ensure_pkg PACKAGE DESCRIPTION — always returns 0; check pkg_installed after.
ensure_pkg() {
    local pkg=$1 desc=$2
    if pkg_installed "$pkg"; then
        act OK "$desc is installed"
        return 0
    fi
    if [[ $DRY_RUN -eq 1 ]]; then
        act PLANNED "Install $desc ($pkg)"
        return 0
    fi
    apt_update_once
    say "  ${C_GREY}…        installing $pkg${C_RESET}"
    if DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a \
        apt-get install -y -q --no-install-recommends "$pkg" >>"$LOG_FILE" 2>&1; then
        manifest_add package "$pkg"
        act CHANGED "Installed $desc"
    else
        act ERROR "Could not install $desc (see log)"
    fi
}

# True when a package is installed, or would be in a dry run.
pkg_ready() { pkg_installed "$1" || [[ $DRY_RUN -eq 1 ]]; }

ensure_service() { # UNIT DESCRIPTION
    local svc=$1 desc=$2
    if ! unit_exists "$svc.service"; then
        if [[ $DRY_RUN -eq 1 ]]; then act PLANNED "Enable and start $desc"; else act ERROR "$desc ($svc.service) not found"; fi
        return 0
    fi
    if systemctl is-enabled --quiet "$svc" 2>/dev/null && service_active "$svc"; then
        act OK "$desc is enabled and running"
        return 0
    fi
    if [[ $DRY_RUN -eq 1 ]]; then
        act PLANNED "Enable and start $desc"
        return 0
    fi
    if systemctl enable --now "$svc" >>"$LOG_FILE" 2>&1; then
        manifest_add service-enabled "$svc"
        act CHANGED "Enabled and started $desc"
    else
        act ERROR "Could not start $desc (see log)"
    fi
}

reload_service() { # UNIT — reload (or restart) a running service
    [[ $DRY_RUN -eq 1 ]] && return 0
    service_active "$1" || return 0
    systemctl reload-or-restart "$1" >>"$LOG_FILE" 2>&1
}

# ─── System state helpers ──────────────────────────────────────────────────

load_sshd_effective() {
    SSHD_T=""
    command -v sshd >/dev/null 2>&1 || return 0
    if [[ $EUID -eq 0 ]]; then mkdir -p /run/sshd 2>/dev/null || true; fi
    SSHD_T=$(sshd -T 2>/dev/null) || SSHD_T=""
}

# Static fallback when sshd -T can't run: drop-ins first, then the main file;
# the first value outside a Match block wins, as in sshd.
sshd_static_get() {
    local key=$1 files=("/etc/ssh/sshd_config.d/"*.conf "$SSHD_CONFIG")
    awk -v k="$key" '
        FNR == 1 { inmatch = 0 }
        tolower($1) == "match" { inmatch = 1; next }
        !inmatch && tolower($1) == k { $1 = ""; sub(/^ +/, ""); print; exit }' "${files[@]}" 2>/dev/null || true
}

ssh_default() {
    case $1 in
        permitrootlogin) echo prohibit-password ;;
        passwordauthentication | kbdinteractiveauthentication | usepam) echo yes ;;
        permitemptypasswords | x11forwarding | hostbasedauthentication | permituserenvironment) echo no ;;
        allowtcpforwarding | allowagentforwarding | ignorerhosts) echo yes ;;
        maxauthtries) echo 6 ;;
        logingracetime) echo 120 ;;
        clientaliveinterval) echo 0 ;;
        loglevel) echo INFO ;;
        port) echo 22 ;;
        authorizedkeysfile) echo ".ssh/authorized_keys .ssh/authorized_keys2" ;;
        *) echo "" ;;
    esac
}

ssh_get() { # KEY (lowercase) — effective value
    local v=""
    if [[ -n $SSHD_T ]]; then
        v=$(awk -v k="$1" '$1 == k { $1 = ""; sub(/^ +/, ""); print; exit }' <<<"$SSHD_T")
    else
        v=$(sshd_static_get "$1")
        [[ -n $v ]] || v=$(ssh_default "$1")
    fi
    printf '%s' "${v,,}"
}

ssh_ports() {
    local p
    if [[ -n $SSHD_T ]]; then
        awk '$1 == "port" { print $2 }' <<<"$SSHD_T" | sort -un
        return 0
    fi
    p=$(awk 'tolower($1) == "port" { print $2 }' "/etc/ssh/sshd_config.d/"*.conf "$SSHD_CONFIG" 2>/dev/null | sort -un) || true
    printf '%s\n' "${p:-22}"
}

user_has_ssh_key() { # USER HOME
    local user=$1 home=$2 pattern f
    local -a files
    pattern=$(ssh_get authorizedkeysfile)
    [[ -n $pattern && $pattern != none ]] || pattern=".ssh/authorized_keys .ssh/authorized_keys2"
    read -ra files <<<"$pattern"
    for f in "${files[@]}"; do
        f=${f//%h/$home} f=${f//%u/$user} f=${f//%%/%}
        [[ $f == /* ]] || f="$home/$f"
        if [[ -r $f ]] && grep -qE '^[[:space:]]*[^#[:space:]]' "$f" 2>/dev/null; then return 0; fi
    done
    return 1
}

# Prints "user<TAB>home<TAB>has_key<TAB>is_admin" for root and every account
# that can log in interactively.
list_login_users() {
    local admins user uid home shell has admin
    admins=$(getent group sudo admin 2>/dev/null | cut -d: -f4 | paste -sd, -) || true
    admins=",$admins,"
    while IFS=: read -r user _ uid _ _ home shell; do
        if [[ $user != root ]] && ((uid < 1000 || uid >= 60000)); then continue; fi
        case $shell in */nologin | */false | "") continue ;; esac
        has=0 admin=0
        if user_has_ssh_key "$user" "$home"; then has=1; fi
        if [[ $user == root || $admins == *",$user,"* ]]; then admin=1; fi
        printf '%s\t%s\t%s\t%s\n' "$user" "$home" "$has" "$admin"
    done < <(getent passwd)
}

is_loopback_addr() {
    case $1 in 127.* | ::1 | *%lo | localhost | ::ffff:127.*) return 0 ;; *) return 1 ;; esac
}

collect_listeners() {
    L_PROTO=() L_ADDR=() L_PORT=() L_PROC=()
    command -v ss >/dev/null 2>&1 || return 0
    local netid local_addr procs addr port name
    local -A seen=()
    while read -r netid _ _ _ local_addr _ procs; do
        [[ -n $local_addr ]] || continue
        port=${local_addr##*:} addr=${local_addr%:*}
        addr=${addr#[} addr=${addr%]}
        name="-"
        if [[ $procs =~ \(\(\"([^\"]+)\" ]]; then name=${BASH_REMATCH[1]}; fi
        [[ -z ${seen[$netid/$addr/$port]:-} ]] || continue
        seen[$netid/$addr/$port]=1
        L_PROTO+=("$netid") L_ADDR+=("$addr") L_PORT+=("$port") L_PROC+=("$name")
    done < <(ss -H -lntup 2>/dev/null || true)
}

port_listening_public() { # PORT PROTO
    local i
    for i in "${!L_PORT[@]}"; do
        if [[ ${L_PORT[i]} == "$1" && ${L_PROTO[i]} == "$2" ]] && ! is_loopback_addr "${L_ADDR[i]}"; then return 0; fi
    done
    return 1
}

port_listening() { # PORT — live check, used after restarting sshd
    local out
    out=$(ss -Hltn "sport = :$1" 2>/dev/null) || true
    [[ -n $out ]]
}

load_ufw_state() {
    UFW_ACTIVE=0 UFW_STATUS=""
    command -v ufw >/dev/null 2>&1 || return 0
    [[ $EUID -eq 0 ]] || return 0
    UFW_STATUS=$(ufw status verbose 2>/dev/null) || UFW_STATUS=""
    if [[ $UFW_STATUS == *"Status: active"* ]]; then UFW_ACTIVE=1; fi
}

ufw_allows() { # PORT PROTO — does an active UFW rule let this port in?
    local port=$1 proto=$2 line to spec protos item lo hi
    local -a items
    [[ $UFW_ACTIVE -eq 1 ]] || return 1
    while IFS= read -r line; do
        [[ $line =~ (ALLOW|LIMIT)[[:space:]]+IN ]] || continue
        to=${line%%  *}
        to=${to%% (*}
        to=${to##* }
        if [[ $to == Anywhere ]]; then return 0; fi
        spec=${to%/*} protos=any
        if [[ $to == */* ]]; then protos=${to#*/}; fi
        if [[ $protos != any && $protos != "$proto" ]]; then continue; fi
        IFS=, read -ra items <<<"$spec"
        for item in "${items[@]}"; do
            if [[ $item == *:* ]]; then lo=${item%%:*} hi=${item#*:}; else lo=$item hi=$item; fi
            [[ $lo =~ ^[0-9]+$ && $hi =~ ^[0-9]+$ ]] || continue
            if ((port >= lo && port <= hi)); then return 0; fi
        done
    done <<<"$UFW_STATUS"
    return 1
}

fail2ban_active() { service_active fail2ban; }

docker_published_ports() {
    command -v docker >/dev/null 2>&1 || return 0
    service_active docker || return 0
    timeout 10 docker ps --format '{{.Names}}: {{.Ports}}' 2>/dev/null |
        grep -E '(0\.0\.0\.0|\[::\]|:::):[0-9]+' || true
}

# ─── Audit: system information ─────────────────────────────────────────────

# shellcheck source=/dev/null
os_field() { (. /etc/os-release 2>/dev/null && eval "printf '%s' \"\${$1:-}\""); }

audit_system_info() {
    section "System"
    local mem disk virt uptime_s
    mem=$(free -h 2>/dev/null | awk '/^Mem:/ { print $2 }') || true
    disk=$(df -h / 2>/dev/null | awk 'NR == 2 { print $5 " of " $2 " used" }') || true
    virt=$(systemd-detect-virt 2>/dev/null) || virt="none"
    uptime_s=$(uptime -p 2>/dev/null) || true
    sysinfo "Hostname" "$FQDN"
    sysinfo "OS" "$(os_field PRETTY_NAME)"
    sysinfo "Kernel" "$(uname -r)"
    sysinfo "Architecture" "$(uname -m)"
    sysinfo "Virtualization" "${virt:-none}"
    sysinfo "CPU cores" "$(nproc 2>/dev/null || echo '?')"
    sysinfo "Memory" "${mem:-?}"
    sysinfo "Root disk" "${disk:-?}"
    sysinfo "IP addresses" "$(hostname -I 2>/dev/null | xargs || true)"
    sysinfo "Uptime" "${uptime_s#up }"
    sysinfo "Timezone" "$(timedatectl show -p Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null || echo '?')"
}

# ─── Audit: patch management ───────────────────────────────────────────────

audit_updates() {
    section "Patch management"

    local unattended
    unattended=$(apt-config dump APT::Periodic::Unattended-Upgrade 2>/dev/null | sed -n 's/.*"\(.*\)";/\1/p' | tail -1) || true
    if pkg_installed unattended-upgrades && [[ ${unattended:-0} != 0 ]]; then
        pass high UPD-001 "Automatic security updates are enabled"
    else
        fail high UPD-001 "Automatic security updates are not enabled" \
            "unattended-upgrades $(pkg_installed unattended-upgrades && echo installed || echo 'not installed'), APT::Periodic::Unattended-Upgrade=${unattended:-unset}" \
            "Install unattended-upgrades and enable it in $AUTOUPGRADE_FILE (--harden does this)."
    fi

    local sim pkgs n
    sim=$(apt-get -s -o Debug::NoLocking=true dist-upgrade 2>/dev/null) || true
    pkgs=$(awk '/^Inst / && /-security/ { print $2 }' <<<"$sim" | sort -u) || true
    n=$(grep -c . <<<"$pkgs" || true)
    if [[ ${n:-0} -gt 0 ]]; then
        fail high UPD-002 "$n security update(s) are waiting to be installed" \
            "$(head -15 <<<"$pkgs" | paste -sd' ' -)$( ((n > 15)) && echo ' …')" \
            "Run: sudo apt update && sudo apt upgrade"
    else
        pass high UPD-002 "No pending security updates"
    fi

    local age
    age=$(file_mtime_days /var/lib/apt/periodic/update-success-stamp)
    [[ -n $age ]] || age=$(file_mtime_days /var/cache/apt/pkgcache.bin)
    if [[ -z $age ]]; then
        info UPD-003 "Package index age unknown"
    elif ((age > 7)); then
        fail low UPD-003 "Package index is $age days old" "Update results above may be incomplete." "Run: sudo apt update"
    else
        pass low UPD-003 "Package index was refreshed $age day(s) ago"
    fi

    if [[ -f /run/reboot-required ]]; then
        fail medium UPD-004 "A reboot is required to finish installing updates" \
            "$(paste -sd' ' /run/reboot-required.pkgs 2>/dev/null || true)" \
            "Reboot during a maintenance window so the new kernel and libraries are used."
    else
        pass medium UPD-004 "No reboot pending"
    fi

    if command -v needrestart >/dev/null 2>&1 && [[ $EUID -eq 0 ]]; then
        local stale
        stale=$(needrestart -b -r l 2>/dev/null | sed -n 's/^NEEDRESTART-SVC: //p' | paste -sd' ' -) || true
        if [[ -n $stale ]]; then
            fail low UPD-005 "Services are still running outdated libraries" "$stale" \
                "Restart these services: sudo needrestart -r a"
        else
            pass low UPD-005 "No service is running outdated libraries"
        fi
    fi
}

# ─── Audit: accounts and authentication ────────────────────────────────────

audit_accounts() {
    section "Accounts"

    local uid0
    uid0=$(awk -F: '$3 == 0 { print $1 }' /etc/passwd | paste -sd' ' -)
    if [[ $uid0 == root ]]; then
        pass critical ACC-001 "Only root has UID 0"
    else
        fail critical ACC-001 "Several accounts have UID 0" "$uid0" "Give every account except root a unique non-zero UID."
    fi

    if [[ -r /etc/shadow ]]; then
        local empty
        empty=$(awk -F: '$2 == "" { print $1 }' /etc/shadow | paste -sd' ' -)
        if [[ -z $empty ]]; then
            pass critical ACC-002 "No account has an empty password"
        else
            fail critical ACC-002 "Accounts with an empty password" "$empty" "Set a password or lock them: sudo passwd -l USER"
        fi

        if awk -F: '$1 == "root" && $2 !~ /^[!*]/ { found = 1 } END { exit !found }' /etc/shadow; then
            info ACC-003 "Root has a password set" "Useful for console recovery; make sure it is long and unique."
        else
            pass low ACC-003 "Root password is locked"
        fi
    fi

    local sys_shells
    sys_shells=$(awk -F: '$3 > 0 && $3 < 1000 && $1 !~ /^(sync|shutdown|halt)$/ && $7 !~ /(nologin|false)$/ && $7 != "" { print $1 }' /etc/passwd | paste -sd' ' -)
    if [[ -z $sys_shells ]]; then
        pass medium ACC-004 "System accounts have no login shell"
    else
        fail medium ACC-004 "System accounts have a login shell" "$sys_shells" \
            "If they don't need one: sudo usermod -s /usr/sbin/nologin USER"
    fi

    local method
    method=$(awk '$1 == "ENCRYPT_METHOD" { print toupper($2) }' /etc/login.defs 2>/dev/null) || true
    if [[ $method == YESCRYPT || $method == SHA512 ]]; then
        pass medium ACC-005 "Passwords are hashed with $method"
    else
        fail medium ACC-005 "Weak password hashing (${method:-default})" "" "Set ENCRYPT_METHOD YESCRYPT in /etc/login.defs."
    fi

    local minlen
    minlen=$(grep -hE '^[[:space:]]*minlen[[:space:]]*=' "$PWQUALITY_CONF" /etc/security/pwquality.conf.d/*.conf 2>/dev/null |
        tail -1 | sed -E 's/.*=[[:space:]]*//') || true
    if pkg_installed libpam-pwquality && [[ ${minlen:-0} =~ ^[0-9]+$ ]] && ((${minlen:-0} >= 12)); then
        pass medium ACC-006 "Password quality rules require at least $minlen characters"
    else
        fail medium ACC-006 "No password strength rules" \
            "libpam-pwquality $(pkg_installed libpam-pwquality && echo installed || echo 'not installed'), minlen=${minlen:-default}" \
            "Install libpam-pwquality and set minlen = 12, minclass = 3 (--harden does this)."
    fi

    local max_days
    max_days=$(awk '$1 == "PASS_MAX_DAYS" { print $2 }' /etc/login.defs 2>/dev/null) || true
    info ACC-007 "Password expiry: ${max_days:-not set} days" \
        "NIST SP 800-63B advises against forced periodic changes; this script doesn't enforce expiry."

    local sudoers nopass
    sudoers=$(getent group sudo admin 2>/dev/null | cut -d: -f4 | tr ',' '\n' | sed '/^$/d' | sort -u | paste -sd' ' -) || true
    info ACC-008 "Administrators (sudo): ${sudoers:-none}"
    if [[ -r /etc/sudoers ]]; then
        nopass=$(grep -hsE '^[^#].*NOPASSWD' /etc/sudoers /etc/sudoers.d/* | sed 's/[[:space:]]\+/ /g' | head -5) || true
        if [[ -n $nopass ]]; then
            info ACC-009 "Passwordless sudo is configured" "$nopass"
        fi
    fi
}

# ─── Audit: SSH ────────────────────────────────────────────────────────────

audit_ssh() {
    section "SSH"
    if ! command -v sshd >/dev/null 2>&1; then
        info SSH-000 "OpenSSH server is not installed"
        return 0
    fi
    load_sshd_effective
    if [[ -z $SSHD_T ]]; then
        info SSH-000 "Using a static read of /etc/ssh (sshd -T needs root)"
    fi

    local v pw kbd pam sev
    v=$(ssh_get permitrootlogin)
    case $v in
        no) pass high SSH-001 "Root cannot log in over SSH" ;;
        prohibit-password | without-password | forced-commands-only)
            pass high SSH-001 "Root can only log in over SSH with a key" "PermitRootLogin $v" ;;
        *) fail high SSH-001 "Root can log in over SSH with a password" "PermitRootLogin $v" \
            "Set PermitRootLogin no (or prohibit-password if automation logs in as root with a key)." ;;
    esac

    pw=$(ssh_get passwordauthentication)
    kbd=$(ssh_get kbdinteractiveauthentication)
    [[ -n $kbd ]] || kbd=$(ssh_get challengeresponseauthentication)
    pam=$(ssh_get usepam)
    if [[ $pw == no && ($kbd == no || $pam == no) ]]; then
        pass high SSH-002 "SSH only accepts keys, not passwords"
    else
        sev=medium
        fail2ban_active || sev=high
        fail "$sev" SSH-002 "SSH accepts passwords" \
            "PasswordAuthentication $pw, KbdInteractiveAuthentication ${kbd:-?}; brute-force protection: $(fail2ban_active && echo fail2ban || echo none)" \
            "Give every login user an SSH key, then set PasswordAuthentication no. Keep fail2ban running until then."
    fi

    v=$(ssh_get permitemptypasswords)
    if [[ $v == no ]]; then pass critical SSH-003 "Empty SSH passwords are refused"
    else fail critical SSH-003 "SSH allows empty passwords" "PermitEmptyPasswords $v" "Set PermitEmptyPasswords no."; fi

    v=$(ssh_get maxauthtries)
    if [[ $v =~ ^[0-9]+$ ]] && ((v <= 5)); then pass low SSH-004 "SSH allows $v authentication attempts per connection"
    else fail low SSH-004 "SSH allows $v authentication attempts per connection" "" "Set MaxAuthTries 4 or 5."; fi

    v=$(ssh_get logingracetime)
    if [[ $v =~ ^[0-9]+$ ]] && ((v > 0 && v <= 60)); then pass low SSH-005 "Unauthenticated SSH connections time out after ${v}s"
    else fail low SSH-005 "Unauthenticated SSH connections stay open for ${v}s" "" "Set LoginGraceTime 30."; fi

    v=$(ssh_get x11forwarding)
    if [[ $v == no ]]; then pass low SSH-006 "X11 forwarding is disabled"
    else fail low SSH-006 "X11 forwarding is enabled" "" "Set X11Forwarding no unless graphical apps are forwarded."; fi

    v=$(ssh_get hostbasedauthentication)
    local rh; rh=$(ssh_get ignorerhosts)
    if [[ $v == no && $rh == yes ]]; then pass medium SSH-007 "Host-based and rhosts authentication are disabled"
    else fail medium SSH-007 "Host-based or rhosts authentication is enabled" "HostbasedAuthentication $v, IgnoreRhosts $rh" "Set HostbasedAuthentication no and IgnoreRhosts yes."; fi

    v=$(ssh_get permituserenvironment)
    if [[ $v == no ]]; then pass medium SSH-008 "Users cannot set environment variables for sshd"
    else fail medium SSH-008 "PermitUserEnvironment is enabled" "" "Set PermitUserEnvironment no."; fi

    v=$(ssh_get clientaliveinterval)
    if [[ $v =~ ^[0-9]+$ ]] && ((v > 0)); then pass low SSH-009 "Dead SSH sessions are detected (ClientAliveInterval $v)"
    else fail low SSH-009 "Dead SSH sessions are never cleaned up" "" "Set ClientAliveInterval 300 and ClientAliveCountMax 3."; fi

    v=$(ssh_get loglevel)
    if [[ $v == verbose || $v == debug* ]]; then pass low SSH-010 "SSH logs key fingerprints (LogLevel ${v^^})"
    else fail low SSH-010 "SSH doesn't log which key was used" "LogLevel ${v^^}" "Set LogLevel VERBOSE."; fi

    if [[ -n $SSHD_T ]]; then
        local weak="" kex macs ciphers
        kex=$(ssh_get kexalgorithms) macs=$(ssh_get macs) ciphers=$(ssh_get ciphers)
        weak+=$(tr ',' '\n' <<<"$kex" | grep -E 'group1-sha1|group14-sha1|group-exchange-sha1' | paste -sd' ' -) || true
        weak+=" "$(tr ',' '\n' <<<"$macs" | grep -E 'md5|hmac-sha1|umac-64|ripemd' | paste -sd' ' -) || true
        weak+=" "$(tr ',' '\n' <<<"$ciphers" | grep -E 'cbc|arcfour|3des' | paste -sd' ' -) || true
        weak=$(xargs <<<"$weak")
        if [[ -z $weak ]]; then pass medium SSH-011 "SSH offers only modern cryptography"
        else fail medium SSH-011 "SSH still offers legacy algorithms" "$weak" "Remove SHA-1 key exchange and MACs (--harden does this)."; fi
    fi

    local u h k a keyed="" unkeyed=""
    while IFS=$'\t' read -r u h k a; do
        [[ -n $u ]] || continue
        if [[ $k == 1 ]]; then keyed+="$u "; else unkeyed+="$u "; fi
    done < <(list_login_users)
    info SSH-012 "Login users with SSH keys: ${keyed:-none}" "Without keys: ${unkeyed:-none}"
    info SSH-013 "SSH listens on port(s): $(ssh_ports | paste -sd' ' -)"
}

# ─── Audit: firewall and intrusion prevention ──────────────────────────────

audit_firewall() {
    section "Firewall"
    load_ufw_state

    local nft_drop=0 out
    if [[ $UFW_ACTIVE -eq 0 && $EUID -eq 0 ]] && command -v nft >/dev/null 2>&1; then
        out=$(nft list ruleset 2>/dev/null) || true
        if grep -qE 'hook input .*policy drop' <<<"$out"; then nft_drop=1; fi
    fi

    if [[ $UFW_ACTIVE -eq 1 ]]; then
        pass critical FW-001 "Firewall (UFW) is active"
        if grep -q 'Default: deny (incoming)\|Default: reject (incoming)' <<<"$UFW_STATUS"; then
            pass high FW-002 "Incoming traffic is denied unless allowed"
        else
            fail high FW-002 "Firewall allows incoming traffic by default" "$(grep '^Default:' <<<"$UFW_STATUS")" "Run: sudo ufw default deny incoming"
        fi
        local p missing=""
        for p in $(ssh_ports); do
            ufw_allows "$p" tcp || missing+="$p "
        done
        if [[ -n $missing ]]; then
            fail critical FW-003 "Firewall blocks the SSH port(s) $missing" "New SSH connections will fail." "Run: sudo ufw allow <port>/tcp"
        else
            pass critical FW-003 "Firewall allows SSH"
        fi
        if grep -q '^IPV6=yes' /etc/default/ufw 2>/dev/null; then
            pass medium FW-004 "Firewall also filters IPv6"
        else
            fail medium FW-004 "Firewall doesn't filter IPv6" "IPV6 is not 'yes' in /etc/default/ufw" "Set IPV6=yes in /etc/default/ufw and run: sudo ufw reload"
        fi
    elif [[ $nft_drop -eq 1 ]]; then
        pass critical FW-001 "An nftables firewall with a default-drop input policy is active"
    elif [[ $EUID -ne 0 ]]; then
        info FW-001 "Firewall state unknown (needs root)"
    else
        fail critical FW-001 "No firewall is active" "Every listening service is reachable from the internet." \
            "Enable UFW with SSH and web ports allowed (--harden does this)."
    fi

    local published
    published=$(docker_published_ports)
    if [[ -n $published ]]; then
        fail high FW-005 "Docker publishes container ports that bypass UFW" "$published" \
            "Bind published ports to 127.0.0.1 (e.g. -p 127.0.0.1:8080:80) behind your reverse proxy, or filter them in the DOCKER-USER chain."
    fi

    if fail2ban_active; then
        local jails=""
        if [[ $EUID -eq 0 ]]; then
            jails=$(fail2ban-client status 2>/dev/null | sed -n 's/.*Jail list:[[:space:]]*//p') || true
        fi
        if [[ $EUID -ne 0 || $jails == *sshd* ]]; then
            pass high FW-010 "fail2ban is running${jails:+ (jails: $jails)}"
        else
            fail high FW-010 "fail2ban is running but the sshd jail is off" "Jails: ${jails:-none}" "Enable the [sshd] jail (--harden does this)."
        fi
    else
        fail high FW-010 "No brute-force protection (fail2ban is not running)" "" "Install fail2ban with an sshd jail (--harden does this)."
    fi
}

# ─── Audit: network exposure ───────────────────────────────────────────────

risky_port_name() { # PORT [PROCESS]
    case $1 in
        9000) [[ ${2:-} == php* ]] && echo "PHP-FPM/FastCGI" || echo "" ;;
        2375 | 2376) echo "Docker API" ;;
        3306) echo "MySQL/MariaDB" ;;
        5432) echo "PostgreSQL" ;;
        6379) echo "Redis" ;;
        11211) echo "Memcached" ;;
        27017) echo "MongoDB" ;;
        9200 | 9300) echo "Elasticsearch/OpenSearch" ;;
        5984) echo "CouchDB" ;;
        8086) echo "InfluxDB" ;;
        5672 | 15672) echo "RabbitMQ" ;;
        2049) echo "NFS" ;;
        111) echo "rpcbind" ;;
        445 | 139) echo "SMB" ;;
        23) echo "Telnet" ;;
        21) echo "FTP" ;;
        *) echo "" ;;
    esac
}

audit_network() {
    section "Network exposure"
    collect_listeners
    [[ -n $UFW_STATUS || $EUID -ne 0 ]] || load_ufw_state

    local i proto addr port proc fw name public=0 risky=0
    for i in "${!L_PORT[@]}"; do
        proto=${L_PROTO[i]} addr=${L_ADDR[i]} port=${L_PORT[i]} proc=${L_PROC[i]}
        is_loopback_addr "$addr" && continue
        public=$((public + 1))
        if [[ $UFW_ACTIVE -eq 1 ]]; then
            if ufw_allows "$port" "$proto"; then fw="allowed"; else fw="blocked"; fi
        else
            fw="no firewall"
        fi
        X_PROTO+=("$proto") X_ADDR+=("$addr") X_PORT+=("$port") X_PROC+=("$proc") X_FW+=("$fw")
        if [[ $QUIET -eq 0 ]]; then
            printf '  %s%-5s %-28s %-16s %s%s\n' "$C_GREY" "$proto" "$addr:$port" "$proc" "$fw" "$C_RESET"
        fi
        name=$(risky_port_name "$port" "$proc")
        if [[ -n $name ]]; then
            risky=$((risky + 1))
            if [[ $fw == blocked ]]; then
                fail medium "NET-$port" "$name ($port/$proto) listens on a public address" \
                    "The firewall blocks it today; one wrong rule would expose it." \
                    "Bind $name to 127.0.0.1 (or a private interface) in its configuration."
            else
                fail "$([[ $name == "Docker API" || $name == PHP-FPM/FastCGI ]] && echo critical || echo high)" "NET-$port" \
                    "$name ($port/$proto) is reachable from the internet" "Listening on $addr, firewall: $fw" \
                    "Bind $name to 127.0.0.1 or a private interface, and never expose it publicly."
            fi
        fi
    done
    if [[ ${#L_PORT[@]} -eq 0 ]]; then
        info NET-000 "Listening sockets could not be read"
    else
        info NET-001 "$public service(s) listen on public addresses"
        if [[ $risky -eq 0 ]]; then pass high NET-002 "No database, cache or admin service listens publicly"; fi
    fi

    local fwd
    fwd=$(sysctl -n net.ipv4.ip_forward 2>/dev/null) || true
    if [[ $fwd == 1 ]]; then
        info NET-003 "IP forwarding is on" "Needed for Docker, Kubernetes and VPNs; left unchanged by --harden."
    fi
}

# ─── Audit: web server ─────────────────────────────────────────────────────

audit_nginx() {
    local conf weak
    conf=$(nginx -T 2>/dev/null) || conf=""
    if [[ -z $conf ]]; then
        info WEB-100 "nginx is installed but its configuration could not be read"
        return 0
    fi
    conf=$(sed -E 's/#.*$//' <<<"$conf")
    if grep -qE '^[[:space:]]*server_tokens[[:space:]]+off[[:space:]]*;' <<<"$conf"; then
        pass low WEB-101 "nginx hides its version number"
    else
        fail low WEB-101 "nginx reveals its version number" "server_tokens is not off" "Add 'server_tokens off;' to the http block (--harden does this)."
    fi
    weak=$(grep -E '^[[:space:]]*ssl_protocols[[:space:]]' <<<"$conf" | grep -E 'TLSv1(\.1)?([[:space:];]|$)' | sed 's/^[[:space:]]*//' | sort -u | head -3) || true
    if [[ -n $weak ]]; then
        fail medium WEB-102 "nginx allows TLS 1.0/1.1" "$weak" "Use: ssl_protocols TLSv1.2 TLSv1.3;"
    else
        pass medium WEB-102 "nginx doesn't enable TLS 1.0/1.1"
    fi
    if grep -qE '^[[:space:]]*autoindex[[:space:]]+on' <<<"$conf"; then
        fail low WEB-103 "nginx directory listing (autoindex) is on somewhere" "" "Turn autoindex off unless a location needs it."
    fi
}

audit_apache() {
    local files=(/etc/apache2/apache2.conf /etc/apache2/conf-enabled/*.conf /etc/apache2/sites-enabled/* /etc/apache2/mods-enabled/*.conf)
    local conf tokens sig trace weak
    conf=$(cat "${files[@]}" 2>/dev/null | sed -E 's/^[[:space:]]*#.*$//') || true
    tokens=$(grep -iE '^[[:space:]]*ServerTokens[[:space:]]' <<<"$conf" | tail -1 | awk '{ print tolower($2) }') || true
    sig=$(grep -iE '^[[:space:]]*ServerSignature[[:space:]]' <<<"$conf" | tail -1 | awk '{ print tolower($2) }') || true
    trace=$(grep -iE '^[[:space:]]*TraceEnable[[:space:]]' <<<"$conf" | tail -1 | awk '{ print tolower($2) }') || true
    if [[ $tokens == prod* && $sig == off ]]; then
        pass low WEB-201 "Apache hides its version number"
    else
        fail low WEB-201 "Apache reveals its version number" "ServerTokens ${tokens:-default}, ServerSignature ${sig:-default}" \
            "Set ServerTokens Prod and ServerSignature Off (--harden does this)."
    fi
    if [[ $trace == off ]]; then pass low WEB-202 "Apache TRACE method is disabled"
    else fail low WEB-202 "Apache TRACE method is enabled" "" "Set TraceEnable Off (--harden does this)."; fi
    weak=$(grep -iE '^[[:space:]]*SSLProtocol[[:space:]]' <<<"$conf" | grep -iE '[[:space:]]\+?TLSv1(\.1)?([[:space:]]|$)' | sed 's/^[[:space:]]*//' | sort -u | head -3) || true
    if [[ -n $weak ]]; then fail medium WEB-203 "Apache allows TLS 1.0/1.1" "$weak" "Use: SSLProtocol -all +TLSv1.2 +TLSv1.3"
    else pass medium WEB-203 "Apache doesn't enable TLS 1.0/1.1"; fi
    if grep -iE '^[[:space:]]*Options[[:space:]]' <<<"$conf" | grep -qiE '([[:space:]]|\+)Indexes'; then
        fail low WEB-204 "Apache directory listing (Options Indexes) is on somewhere" "" "Use 'Options -Indexes' unless a directory needs it."
    fi
}

php_ini_value() { # DIR KEY — last value wins (php.ini, then conf.d in order)
    grep -hiE "^[[:space:]]*$2[[:space:]]*=" "$1/php.ini" "$1"/conf.d/*.ini 2>/dev/null |
        tail -1 | sed -E 's/^[^=]*=[[:space:]]*//; s/[[:space:]"]+$//; s/^"//' || true
}

audit_php() {
    local d expose display exposed="" displayed=""
    for d in "$@"; do
        expose=$(php_ini_value "$d" expose_php)
        display=$(php_ini_value "$d" display_errors)
        [[ ${expose,,} =~ ^(off|0|false|no)$ ]] || exposed+="$d "
        if [[ ${display,,} =~ ^(on|1|true|yes|stdout|stderr)$ ]]; then displayed+="$d "; fi
    done
    if [[ -z $exposed ]]; then pass low WEB-301 "PHP doesn't advertise its version"
    else fail low WEB-301 "PHP advertises its version (expose_php)" "$exposed" "Set expose_php = Off (--harden does this)."; fi
    if [[ -z $displayed ]]; then pass medium WEB-302 "PHP doesn't show errors to visitors"
    else fail medium WEB-302 "PHP shows errors to visitors (display_errors)" "$displayed" "Set display_errors = Off in production and log errors instead."; fi
}

audit_tls_cert() {
    command -v openssl >/dev/null 2>&1 || return 0
    local pem end end_epoch days subject issuer
    pem=$(timeout 8 openssl s_client -connect 127.0.0.1:443 -servername "$FQDN" </dev/null 2>/dev/null | openssl x509 2>/dev/null) || true
    if [[ -z $pem ]]; then
        info WEB-010 "Could not read the TLS certificate on port 443"
        return 0
    fi
    end=$(openssl x509 -noout -enddate <<<"$pem" | cut -d= -f2)
    subject=$(openssl x509 -noout -subject <<<"$pem" | sed 's/^subject= *//')
    issuer=$(openssl x509 -noout -issuer <<<"$pem" | sed 's/^issuer= *//')
    end_epoch=$(date -d "$end" +%s 2>/dev/null) || return 0
    days=$(((end_epoch - $(date +%s)) / 86400))
    if ((days < 0)); then
        fail critical WEB-011 "TLS certificate expired $((-days)) day(s) ago" "$subject" "Renew it (e.g. sudo certbot renew)."
    elif ((days < 14)); then
        fail high WEB-011 "TLS certificate expires in $days day(s)" "$subject" "Renew it now and check automatic renewal (systemctl list-timers | grep certbot)."
    elif ((days < 30)); then
        fail low WEB-011 "TLS certificate expires in $days days" "$subject" "Check automatic renewal is working."
    else
        pass high WEB-011 "TLS certificate is valid for $days more days" "$subject"
    fi
    if [[ $subject == "$issuer" ]]; then
        fail medium WEB-012 "TLS certificate on port 443 is self-signed" "$subject" "Use a certificate from a public CA such as Let's Encrypt."
    fi
}

audit_http_headers() {
    command -v curl >/dev/null 2>&1 || return 0
    local url hdrs server https=0
    if port_listening_public 443 tcp; then url="https://127.0.0.1/" https=1; else url="http://127.0.0.1/"; fi
    hdrs=$(curl -sk -o /dev/null -D - --max-time 5 -H "Host: $FQDN" "$url" 2>/dev/null | tr -d '\r') || true
    [[ -n $hdrs ]] || return 0
    server=$(grep -i '^server:' <<<"$hdrs" | head -1 | cut -d: -f2- | xargs) || true
    if [[ $server =~ [0-9]+\.[0-9]+ ]]; then
        fail low WEB-020 "HTTP Server header reveals a version" "Server: $server" "Hide version numbers (server_tokens off / ServerTokens Prod)."
    else
        pass low WEB-020 "HTTP Server header doesn't reveal a version" "${server:+Server: $server}"
    fi
    if [[ $https -eq 1 ]]; then
        if grep -qi '^strict-transport-security:' <<<"$hdrs"; then pass low WEB-021 "HTTPS responses send HSTS"
        else fail low WEB-021 "HTTPS responses don't send HSTS" "" "Add: Strict-Transport-Security \"max-age=31536000\" once the whole site works over HTTPS."; fi
    fi
    if grep -qi '^x-content-type-options:[[:space:]]*nosniff' <<<"$hdrs"; then pass low WEB-022 "Responses send X-Content-Type-Options: nosniff"
    else fail low WEB-022 "Responses don't send X-Content-Type-Options: nosniff" "" "Add the header in your site configuration."; fi
    if grep -qiE '^(x-frame-options:|content-security-policy:.*frame-ancestors)' <<<"$hdrs"; then pass low WEB-023 "Responses restrict framing (clickjacking)"
    else fail low WEB-023 "Responses don't restrict framing (clickjacking)" "" "Add X-Frame-Options: SAMEORIGIN or a CSP frame-ancestors directive."; fi
}

audit_web() {
    section "Web server"
    [[ ${#L_PORT[@]} -gt 0 ]] || collect_listeners
    local found=0
    local php_dirs=(/etc/php/*/fpm /etc/php/*/apache2)
    if command -v nginx >/dev/null 2>&1; then found=1; audit_nginx; fi
    if [[ -d /etc/apache2 ]]; then found=1; audit_apache; fi
    if [[ ${#php_dirs[@]} -gt 0 ]]; then found=1; audit_php "${php_dirs[@]}"; fi
    if port_listening_public 443 tcp; then found=1; audit_tls_cert; fi
    if port_listening_public 80 tcp || port_listening_public 443 tcp; then found=1; audit_http_headers; fi
    if [[ $found -eq 0 ]]; then info WEB-000 "No web server detected"; fi
    if [[ -d /var/www || -d /srv ]]; then
        local ww
        scan_filesystem
        ww=${SCAN_CACHE[webww]}
        if [[ -z $ww ]]; then
            pass high WEB-030 "No world-writable files under /var/www or /srv"
        else
            fail high WEB-030 "World-writable files in the web root" "$(head -20 <<<"$ww")" \
                "Any local user or compromised service can change these files: chmod o-w FILE"
        fi
    fi
}

# ─── Audit: kernel ─────────────────────────────────────────────────────────

# key|value|severity|description — the same list drives the audit and --harden.
SYSCTL_BASELINE=(
    "net.ipv4.tcp_syncookies|1|medium|SYN flood protection"
    "net.ipv4.conf.all.accept_redirects|0|medium|Ignore ICMP redirects"
    "net.ipv4.conf.default.accept_redirects|0|medium|Ignore ICMP redirects (new interfaces)"
    "net.ipv6.conf.all.accept_redirects|0|medium|Ignore ICMPv6 redirects"
    "net.ipv6.conf.default.accept_redirects|0|medium|Ignore ICMPv6 redirects (new interfaces)"
    "net.ipv4.conf.all.secure_redirects|0|low|Ignore gateway ICMP redirects"
    "net.ipv4.conf.default.secure_redirects|0|low|Ignore gateway ICMP redirects (new interfaces)"
    "net.ipv4.conf.all.send_redirects|0|medium|Don't send ICMP redirects"
    "net.ipv4.conf.default.send_redirects|0|medium|Don't send ICMP redirects (new interfaces)"
    "net.ipv4.conf.all.accept_source_route|0|medium|Refuse source-routed packets"
    "net.ipv4.conf.default.accept_source_route|0|medium|Refuse source-routed packets (new interfaces)"
    "net.ipv6.conf.all.accept_source_route|0|medium|Refuse source-routed IPv6 packets"
    "net.ipv6.conf.default.accept_source_route|0|medium|Refuse source-routed IPv6 packets (new interfaces)"
    "net.ipv4.conf.all.log_martians|1|low|Log packets with impossible addresses"
    "net.ipv4.conf.default.log_martians|1|low|Log packets with impossible addresses (new interfaces)"
    "net.ipv4.icmp_echo_ignore_broadcasts|1|low|Ignore broadcast pings"
    "net.ipv4.icmp_ignore_bogus_error_responses|1|low|Ignore bogus ICMP errors"
    "net.ipv4.tcp_rfc1337|1|low|Protect against TIME-WAIT assassination"
    "kernel.randomize_va_space|2|high|Full address space layout randomisation"
    "kernel.kptr_restrict|2|medium|Hide kernel pointers"
    "kernel.dmesg_restrict|1|low|Restrict kernel log to administrators"
    "kernel.yama.ptrace_scope|1|medium|Restrict ptrace to parent processes"
    "net.core.bpf_jit_harden|2|low|Harden the BPF JIT"
    "fs.suid_dumpable|0|medium|No core dumps from setuid programs"
    "fs.protected_hardlinks|1|medium|Protected hardlinks"
    "fs.protected_symlinks|1|medium|Protected symlinks"
    "fs.protected_fifos|1|low|Protected FIFOs in sticky directories"
    "fs.protected_regular|2|low|Protected regular files in sticky directories"
)
SYSCTL_STRICT=(
    "net.ipv4.conf.all.rp_filter|1|low|Strict reverse-path filtering"
    "net.ipv4.conf.default.rp_filter|1|low|Strict reverse-path filtering (new interfaces)"
    "kernel.yama.ptrace_scope|2|low|ptrace limited to administrators"
    "kernel.sysrq|0|low|Magic SysRq key disabled"
    "kernel.perf_event_paranoid|3|low|perf events restricted to administrators"
)

sysctl_items() {
    local -A seen=()
    local item key i
    local -a all=("${SYSCTL_BASELINE[@]}")
    if [[ $PROFILE == strict ]]; then all+=("${SYSCTL_STRICT[@]}"); fi
    # Later entries override earlier ones with the same key.
    for ((i = ${#all[@]} - 1; i >= 0; i--)); do
        key=${all[i]%%|*}
        [[ -z ${seen[$key]:-} ]] || continue
        seen[$key]=1
        item=${all[i]}
        printf '%s\n' "$item"
    done | tac
}

KERNEL_MODULES_BASELINE=(cramfs freevxfs jffs2 hfs hfsplus dccp rds tipc)
KERNEL_MODULES_STRICT=(sctp)

kernel_modules() {
    printf '%s\n' "${KERNEL_MODULES_BASELINE[@]}"
    if [[ $PROFILE == strict ]]; then printf '%s\n' "${KERNEL_MODULES_STRICT[@]}"; fi
}

audit_kernel() {
    section "Kernel"
    local key want sev desc cur bad=0 item
    while IFS='|' read -r key want sev desc; do
        cur=$(sysctl -n "$key" 2>/dev/null) || continue
        cur=$(xargs <<<"$cur")
        if [[ $cur == "$want" ]]; then
            pass "$sev" "KRN-$key" "$desc"
        else
            fail "$sev" "KRN-$key" "$desc: not enforced" "$key = $cur (expected $want)" "Set $key = $want in /etc/sysctl.d (--harden does this)."
            bad=$((bad + 1))
        fi
    done < <(sysctl_items)

    local mod out loaded="" enabled=""
    while read -r mod; do
        if grep -qE "^${mod}[[:space:]]" /proc/modules 2>/dev/null; then loaded+="$mod "; continue; fi
        modinfo "$mod" >/dev/null 2>&1 || continue
        out=$(modprobe -n -v "$mod" 2>/dev/null) || true
        [[ $out == *"/bin/false"* || $out == *"/bin/true"* ]] || enabled+="$mod "
    done < <(kernel_modules)
    if [[ -n $loaded ]]; then
        fail medium KRN-MOD-1 "Rarely needed kernel modules are loaded" "$loaded" "Unload them if unused and block them in /etc/modprobe.d (--harden blocks them)."
    else
        pass medium KRN-MOD-1 "No rarely needed filesystem or protocol modules are loaded"
    fi
    if [[ -n $enabled ]]; then
        fail low KRN-MOD-2 "Rarely needed kernel modules can be auto-loaded" "$enabled" "Block them in /etc/modprobe.d (--harden does this)."
    else
        pass low KRN-MOD-2 "Rarely needed kernel modules are blocked"
    fi

    local storage
    storage=$(grep -hsE '^[[:space:]]*Storage=' /etc/systemd/coredump.conf /etc/systemd/coredump.conf.d/*.conf | tail -1 | cut -d= -f2) || true
    if [[ $storage == none ]] || grep -qsE '^\*[[:space:]]+hard[[:space:]]+core[[:space:]]+0' /etc/security/limits.conf /etc/security/limits.d/*.conf; then
        pass low KRN-CORE "Core dumps are disabled"
    else
        fail low KRN-CORE "Core dumps are allowed" "Core dumps can contain passwords and keys from memory." "Disable them (--harden does this)."
    fi
}

# ─── Audit: file system ────────────────────────────────────────────────────

# path|max mode|owner|allowed groups (slash-separated)|severity
CRITICAL_PATHS=(
    "/etc/passwd|644|root|root|high"
    "/etc/group|644|root|root|high"
    "/etc/shadow|640|root|shadow/root|high"
    "/etc/gshadow|640|root|shadow/root|high"
    "/etc/sudoers|440|root|root|high"
    "/etc/ssh/sshd_config|600|root|root|medium"
    "/etc/crontab|600|root|root|low"
    "/etc/cron.d|700|root|root|low"
    "/etc/cron.hourly|700|root|root|low"
    "/etc/cron.daily|700|root|root|low"
    "/etc/cron.weekly|700|root|root|low"
    "/etc/cron.monthly|700|root|root|low"
)

critical_path_items() {
    local k
    printf '%s\n' "${CRITICAL_PATHS[@]}"
    for k in /etc/ssh/ssh_host_*_key; do printf '%s|600|root|root|high\n' "$k"; done
}

# One walk per file system collects world-writable directories without the
# sticky bit, unowned files (root file system only, as before), setuid/setgid
# programs and world-writable web files into SCAN_CACHE. Separate finds used
# to walk / twice more. /usr, /var/www and /srv get their own walk only when
# they are separate mounts. --harden never changes any of these, so the
# re-audit reuses the results.
scan_filesystem() {
    [[ -z ${SCAN_CACHE[scanned]+x} ]] || return 0
    local root_dev dir
    local -a roots=(/)
    root_dev=$(stat -c %d /)
    for dir in /usr /var/www /srv; do
        if [[ -d $dir && $(stat -c %d "$dir") != "$root_dev" ]]; then roots+=("$dir"); fi
    done
    # awk keeps only the lines the checks show, so a host with millions of
    # unowned files does not fill memory.
    local out
    out=$(timeout 240 find "${roots[@]}" -xdev \( \
        \( -type d -perm -0002 ! -perm -1000 -printf 'S\t%D\t%p\n' \) , \
        \( \( -nouser -o -nogroup \) -printf 'U\t%D\t%p\n' \) , \
        \( -type f -perm /6000 \( -path '/usr/*' -o -path '/bin/*' -o -path '/sbin/*' \) -printf 'X\t%D\t%p\n' \) , \
        \( -type f -perm -0002 \( -path '/var/www/*' -o -path '/srv/*' \) -printf 'W\t%D\t%p\n' \) \
        \) 2>/dev/null | awk -F'\t' -v d="$root_dev" '
            { p = $0; sub(/^[^\t]*\t[^\t]*\t/, "", p) }
            $1 == "S" && $2 == d && s++ < 20 { print "S\t" p }
            $1 == "U" && $2 == d && u++ < 21 { print "U\t" p }
            $1 == "W" && w++ < 21 { print "W\t" p }
            $1 == "X" { x++ }
            END { print "X\t" x + 0 }') || true
    SCAN_CACHE[sticky]=$(awk '/^S\t/ { print substr($0, 3) }' <<<"$out")
    SCAN_CACHE[unowned]=$(awk '/^U\t/ { print substr($0, 3) }' <<<"$out")
    SCAN_CACHE[webww]=$(awk '/^W\t/ { print substr($0, 3) }' <<<"$out")
    SCAN_CACHE[suid]=$(awk '/^X\t/ { print substr($0, 3) }' <<<"$out")
    SCAN_CACHE[scanned]=1
}

audit_filesystem() {
    section "File system"
    local path max owner groups sev st mode uid gid bad=""
    while IFS='|' read -r path max owner groups sev; do
        st=$(stat -c '%a %U %G' "$path" 2>/dev/null) || continue
        read -r mode uid gid <<<"$st"
        if (((8#$mode & ~8#$max & 8#7777) != 0)) || [[ $uid != "$owner" || "/$groups/" != *"/$gid/"* ]]; then
            fail "$sev" "FS-PERM-$path" "Loose permissions on $path" "$mode $uid:$gid (expected $max or stricter, $owner:${groups%%/*})" \
                "sudo chown $owner:${groups%%/*} $path && sudo chmod $max $path (--harden does this)."
            bad+=x
        fi
    done < <(critical_path_items)
    if [[ -z $bad ]]; then pass high FS-PERM "System files have correct owners and permissions"; fi

    local ww
    ww=$(find /etc -xdev -type f -perm -0002 2>/dev/null | head -20) || true
    if [[ -z $ww ]]; then pass high FS-001 "No world-writable files in /etc"
    else fail high FS-001 "World-writable files in /etc" "$ww" "Remove write access for others: sudo chmod o-w FILE"; fi

    scan_filesystem
    if [[ -z ${SCAN_CACHE[sticky]} ]]; then pass medium FS-002 "World-writable directories have the sticky bit"
    else fail medium FS-002 "World-writable directories without the sticky bit" "${SCAN_CACHE[sticky]}" "sudo chmod +t DIR (or remove world write access)."; fi

    if [[ -z ${SCAN_CACHE[unowned]} ]]; then pass low FS-003 "No files without an owner"
    else fail low FS-003 "Files owned by deleted users or groups" "$(head -20 <<<"${SCAN_CACHE[unowned]}")" "Give them a valid owner or delete them."; fi

    info FS-004 "${SCAN_CACHE[suid]} setuid/setgid programs"

    local homes=""
    local u h k a
    while IFS=$'\t' read -r u h k a; do
        [[ -n $u && -d $h ]] || continue
        mode=$(stat -c %a "$h" 2>/dev/null) || continue
        if (((8#$mode & 8#0002) != 0)); then homes+="$h ($mode) "; fi
    done < <(list_login_users)
    if [[ -z $homes ]]; then pass medium FS-005 "No world-writable home directories"
    else fail medium FS-005 "World-writable home directories" "$homes" "sudo chmod o-w DIR"; fi
}

# ─── Audit: services, logging, MAC, time, tools ────────────────────────────

RISKY_SERVICES=(
    "telnet.socket|Telnet server|high"
    "inetd|inetd super-server|high"
    "openbsd-inetd|inetd super-server|high"
    "xinetd|xinetd super-server|high"
    "rsh.socket|rsh server|high"
    "rlogin.socket|rlogin server|high"
    "tftpd-hpa|TFTP server|high"
    "nis|NIS|high"
    "vsftpd|FTP server|medium"
    "proftpd|FTP server|medium"
    "pure-ftpd|FTP server|medium"
    "rpcbind|RPC portmapper|medium"
    "nfs-server|NFS server|medium"
    "snmpd|SNMP agent|medium"
    "rsync|rsync daemon|medium"
    "avahi-daemon|Avahi mDNS|low"
    "cups|CUPS printing|low"
    "isc-dhcp-server|DHCP server|low"
)

audit_services() {
    section "Services"
    local unit desc sev found=0
    for item in "${RISKY_SERVICES[@]}"; do
        IFS='|' read -r unit desc sev <<<"$item"
        if service_active "$unit"; then
            fail "$sev" "SRV-$unit" "$desc is running ($unit)" "" "Disable it if it's not needed: sudo systemctl disable --now $unit"
            found=1
        fi
    done
    if [[ $found -eq 0 ]]; then pass medium SRV-001 "No legacy or unneeded network services are running"; fi

    local failed
    failed=$(systemctl --failed --no-legend --plain 2>/dev/null | awk '{ print $1 }' | paste -sd' ' -) || true
    if [[ -z $failed ]]; then pass low SRV-002 "No failed systemd units"
    else fail low SRV-002 "Failed systemd units" "$failed" "Check with: systemctl status UNIT"; fi
}

audit_logging() {
    section "Logging and auditing"
    local storage
    storage=$(grep -hsE '^[[:space:]]*Storage=' /etc/systemd/journald.conf /etc/systemd/journald.conf.d/*.conf | tail -1 | cut -d= -f2) || true
    if [[ $storage == persistent || ($storage != volatile && -d /var/log/journal) ]]; then
        pass low LOG-001 "System journal is kept across reboots"
    else
        fail low LOG-001 "System journal is lost on reboot" "Storage=${storage:-auto}, /var/log/journal missing" "Enable persistent journald storage (--harden does this)."
    fi

    if service_active auditd; then
        local rules=""
        if [[ $EUID -eq 0 ]]; then rules=$(auditctl -l 2>/dev/null | grep -vc '^No rules' || true); fi
        if [[ -n $rules && $rules -eq 0 ]]; then
            fail medium LOG-002 "auditd is running without rules" "" "Add audit rules (--harden does this)."
        else
            pass medium LOG-002 "auditd is recording security events${rules:+ ($rules rules)}"
        fi
    else
        fail medium LOG-002 "auditd is not running" "Changes to accounts, sudoers and SSH config aren't recorded." "Install auditd (--harden does this)."
    fi

    local log count top
    log=$(journalctl --since "24 hours ago" -t sshd -t sshd-session --no-pager -q -o cat 2>/dev/null) || true
    count=$(grep -cE 'Failed password|Invalid user|authentication failure|Failed publickey' <<<"$log" || true)
    top=$(grep -oE 'from [0-9a-fA-F:.]+ port' <<<"$log" | awk '{ print $2 }' | sort | uniq -c | sort -rn | head -5 | awk '{ printf "%s (%s) ", $2, $1 }') || true
    info LOG-003 "${count:-0} failed SSH login attempts in the last 24 hours" "${top:+Top sources: $top}"
}

audit_apparmor() {
    section "AppArmor"
    local enabled out enforce complain
    enabled=$(cat /sys/module/apparmor/parameters/enabled 2>/dev/null) || enabled=N
    if [[ $enabled == Y ]]; then
        pass high MAC-001 "AppArmor is enabled"
    else
        fail high MAC-001 "AppArmor is disabled" "" "Enable AppArmor (remove apparmor=0 from the kernel command line) and install the apparmor package."
    fi
    if [[ $EUID -eq 0 ]] && command -v aa-status >/dev/null 2>&1; then
        out=$(aa-status 2>/dev/null) || true
        enforce=$(sed -n 's/^\([0-9]\+\) profiles are in enforce mode.*/\1/p' <<<"$out" | head -1) || true
        complain=$(sed -n 's/^\([0-9]\+\) profiles are in complain mode.*/\1/p' <<<"$out" | head -1) || true
        info MAC-002 "AppArmor: ${enforce:-0} profiles enforced, ${complain:-0} in complain mode"
    fi
}

audit_time() {
    section "Time"
    local synced
    synced=$(timedatectl show -p NTPSynchronized --value 2>/dev/null) || true
    if [[ $synced == yes ]]; then
        pass medium TIME-001 "System clock is synchronised"
    else
        fail medium TIME-001 "System clock is not synchronised" "Wrong clocks break TLS, logs and TOTP." "Enable systemd-timesyncd or chrony (--harden does this)."
    fi
}

audit_tools() {
    section "Security tools"
    local item pkg desc sev missing
    for item in "lynis|Lynis auditor|low" "rkhunter|rkhunter rootkit scanner|low" "debsums|debsums package verifier|low" \
        "needrestart|needrestart|low" "aide|AIDE file integrity|info" "clamav|ClamAV antivirus|info"; do
        IFS='|' read -r pkg desc sev <<<"$item"
        if pkg_installed "$pkg"; then
            if [[ $sev == info ]]; then info "TOOL-$pkg" "$desc is installed"; else pass "$sev" "TOOL-$pkg" "$desc is installed"; fi
        elif [[ $sev == info ]]; then
            info "TOOL-$pkg" "$desc is not installed (optional)"
        else
            fail "$sev" "TOOL-$pkg" "$desc is not installed" "" "sudo apt install $pkg (--harden does this)."
        fi
    done
}

run_audit() {
    audit_system_info
    audit_updates
    audit_accounts
    audit_ssh
    audit_firewall
    audit_network
    audit_web
    audit_kernel
    audit_filesystem
    audit_services
    audit_logging
    audit_apparmor
    audit_time
    audit_tools
}

# ─── Hardening: updates ────────────────────────────────────────────────────

harden_updates() {
    section "Patch management"
    approve "Enable automatic security updates?" || return 0
    ensure_pkg unattended-upgrades "unattended-upgrades"
    pkg_ready unattended-upgrades || return 0

    write_config "$AUTOUPGRADE_FILE" 0644 "Daily security updates" <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF

    local reboot=false reboot_time="04:00"
    if [[ -n $AUTO_REBOOT_TIME ]]; then reboot=true reboot_time=$AUTO_REBOOT_TIME; fi
    write_config "$UNATTENDED_FILE" 0644 "Unattended-upgrades cleanup and reboot policy" <<EOF
// $MANAGED_TAG
// Only the distribution's default origins (security updates) are installed.
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "$reboot";
Unattended-Upgrade::Automatic-Reboot-Time "$reboot_time";
EOF
    if [[ $reboot == false ]]; then
        act NOTE "Automatic reboots stay off; use --auto-reboot HH:MM to allow them"
    fi
}

# ─── Hardening: firewall ───────────────────────────────────────────────────

ufw_rule_present() {
    local added
    added=$(ufw show added 2>/dev/null | sed -E "s/ comment '.*'\$//") || true
    grep -qxF -- "ufw $1" <<<"$added"
}

ufw_add() { # RULE COMMENT
    local rule=$1 comment=$2
    local -a args
    if ufw_rule_present "$rule"; then
        act OK "Firewall: $rule"
        return 0
    fi
    if [[ $DRY_RUN -eq 1 ]]; then
        act PLANNED "Firewall: ufw $rule"
        return 0
    fi
    read -ra args <<<"$rule"
    if ufw "${args[@]}" comment "$comment" >>"$LOG_FILE" 2>&1; then
        manifest_add ufw-rule "$rule" "$comment"
        act CHANGED "Firewall: $rule"
    else
        act ERROR "Firewall: could not add '$rule'"
    fi
}

ufw_remove() { # RULE
    local rule=$1
    local -a args
    ufw_rule_present "$rule" || return 0
    if [[ $DRY_RUN -eq 1 ]]; then
        act PLANNED "Firewall: ufw delete $rule"
        return 0
    fi
    read -ra args <<<"$rule"
    if ufw --force delete "${args[@]}" >>"$LOG_FILE" 2>&1; then
        manifest_add ufw-deleted "$rule"
        act CHANGED "Firewall: removed '$rule'"
    else
        act ERROR "Firewall: could not remove '$rule'"
    fi
}

ufw_default() { # incoming|outgoing allow|deny
    local dir=$1 want=$2 key cur
    [[ $dir == incoming ]] && key=DEFAULT_INPUT_POLICY || key=DEFAULT_OUTPUT_POLICY
    cur=$(sed -n "s/^$key=\"\?\([A-Z]*\)\"\?/\1/p" /etc/default/ufw 2>/dev/null) || true
    case $cur in DROP) cur=deny ;; ACCEPT) cur=allow ;; REJECT) cur=reject ;; esac
    if [[ $cur == "$want" ]]; then
        act OK "Firewall: default $want $dir"
        return 0
    fi
    if [[ $DRY_RUN -eq 1 ]]; then
        act PLANNED "Firewall: default $want $dir"
        return 0
    fi
    if ufw default "$want" "$dir" >>"$LOG_FILE" 2>&1; then
        manifest_add ufw-default "$dir" "${cur:-allow}"
        act CHANGED "Firewall: default $want $dir"
    else
        act ERROR "Firewall: could not set default $want $dir"
    fi
}

compute_ssh_ports() {
    load_sshd_effective
    mapfile -t CURRENT_SSH_PORTS < <(ssh_ports)
    if [[ -z $SSH_PORT ]]; then
        SSH_TARGET_PORTS=("${CURRENT_SSH_PORTS[@]}")
    elif [[ $SSH_CLOSE_OLD_PORT -eq 1 ]]; then
        SSH_TARGET_PORTS=("$SSH_PORT")
    else
        mapfile -t SSH_TARGET_PORTS < <(printf '%s\n' "${CURRENT_SSH_PORTS[@]}" "$SSH_PORT" | sort -un)
    fi
}

harden_firewall() {
    section "Firewall"
    local -a tcp udp cidrs=()
    local p i c client
    split_csv "$ALLOW_TCP" tcp
    split_csv "$ALLOW_UDP" udp

    if [[ $ALLOW_DETECTED -eq 1 ]]; then
        for i in "${!L_PORT[@]}"; do
            is_loopback_addr "${L_ADDR[i]}" && continue
            p=${L_PORT[i]}
            if [[ -n $(risky_port_name "$p" "${L_PROC[i]}") ]]; then continue; fi
            if [[ ${L_PROTO[i]} == tcp ]]; then
                contains "$p" "${tcp[@]}" "${SSH_TARGET_PORTS[@]}" || tcp+=("$p")
            else
                contains "$p" "${udp[@]}" || udp+=("$p")
            fi
        done
    fi

    if [[ -n $SSH_ALLOW_FROM ]]; then
        split_csv "$SSH_ALLOW_FROM" cidrs
        client=$(ssh_client_ip)
        if [[ -n $client ]]; then
            local ok=0
            for c in "${cidrs[@]}"; do
                if ip_in_cidr "$client" "$c" 2>/dev/null; then ok=1; break; fi
            done
            if [[ $ok -eq 0 ]]; then
                act ERROR "Your SSH client address $client is not in --ssh-allow-from; SSH stays open to all addresses"
                cidrs=()
            fi
        fi
    fi

    say "  Plan: allow SSH on ${SSH_TARGET_PORTS[*]}/tcp${cidrs:+ from ${cidrs[*]}}; TCP ${tcp[*]:-none}; UDP ${udp[*]:-none}; deny everything else incoming."
    local -A noted=()
    for i in "${!L_PORT[@]}"; do
        is_loopback_addr "${L_ADDR[i]}" && continue
        p=${L_PORT[i]}
        [[ -z ${noted[${L_PROTO[i]}/$p]:-} ]] || continue
        noted[${L_PROTO[i]}/$p]=1
        if [[ ${L_PROTO[i]} == tcp ]] && ! contains "$p" "${tcp[@]}" "${SSH_TARGET_PORTS[@]}" && ! ufw_allows "$p" tcp; then
            local who=${L_PROC[i]}
            [[ $who != - ]] || who="A service"
            act NOTE "$who listens on $p/tcp but won't be reachable from outside (add --allow-tcp $p if it should be)"
        fi
    done
    approve "Apply these firewall rules and enable UFW?" || return 0

    ensure_pkg ufw "UFW firewall"
    pkg_ready ufw || return 0

    if [[ -f /etc/default/ufw ]]; then
        set_options /etc/default/ufw '%s=%s' "Firewall filters IPv6 too" IPV6=yes
    fi

    local ssh_verb=allow
    [[ $PROFILE == strict ]] && ssh_verb=limit
    for p in "${SSH_TARGET_PORTS[@]}"; do
        if [[ ${#cidrs[@]} -gt 0 ]]; then
            for c in "${cidrs[@]}"; do ufw_add "allow from $c to any port $p proto tcp" "SSH (admin networks)"; done
            ufw_remove "allow $p/tcp"
            ufw_remove "limit $p/tcp"
            ufw_remove "allow OpenSSH"
        else
            ufw_add "$ssh_verb $p/tcp" "SSH"
        fi
    done
    for p in "${tcp[@]}"; do ufw_add "allow $p/tcp" "Public TCP"; done
    for p in "${udp[@]}"; do ufw_add "allow $p/udp" "Public UDP"; done

    ufw_default incoming deny
    ufw_default outgoing allow

    load_ufw_state
    if [[ $UFW_ACTIVE -eq 1 ]]; then
        act OK "UFW is active"
    elif [[ $DRY_RUN -eq 1 ]]; then
        act PLANNED "Enable UFW"
    elif ufw --force enable >>"$LOG_FILE" 2>&1; then
        manifest_add ufw-enabled 1
        act CHANGED "Enabled UFW"
    else
        act ERROR "Could not enable UFW (see log)"
    fi
    if [[ $DRY_RUN -eq 0 ]]; then load_ufw_state; fi
}

# Called by harden_ssh once sshd is confirmed on the new port.
firewall_close_old_ssh_ports() {
    local p
    command -v ufw >/dev/null 2>&1 || return 0
    for p in "${CURRENT_SSH_PORTS[@]}"; do
        contains "$p" "${SSH_TARGET_PORTS[@]}" && continue
        ufw_remove "allow $p/tcp"
        ufw_remove "limit $p/tcp"
        ufw_remove "allow OpenSSH"
    done
}

# ─── Hardening: SSH ────────────────────────────────────────────────────────

ssh_supported_list() { # ssh -Q TYPE, filtered to the names given
    local type=$1 n
    local have
    have=$(ssh -Q "$type" 2>/dev/null) || return 0
    shift
    for n in "$@"; do
        if grep -qxF "$n" <<<"$have"; then printf '%s\n' "$n"; fi
    done | paste -sd, -
}

reload_ssh() { # PORT_CHANGED
    if systemctl is-active --quiet ssh.socket 2>/dev/null; then
        if [[ $1 -eq 1 ]]; then
            # Ubuntu's socket activation takes its ports from sshd_config via a
            # generator, so the socket has to be regenerated and restarted.
            systemctl daemon-reload && systemctl restart ssh.socket || return 1
            if service_active ssh.service; then systemctl restart ssh.service || return 1; fi
        elif service_active ssh.service; then
            systemctl reload ssh.service || return 1
        fi
    elif [[ $1 -eq 1 ]]; then
        systemctl restart ssh.service
    else
        systemctl reload ssh.service
    fi
}

wait_for_port() {
    local i
    for i in 1 2 3 4 5 6 7 8 9 10; do
        if port_listening "$1"; then return 0; fi
        sleep 0.5
    done
    return 1
}

harden_ssh() {
    section "SSH"
    if ! command -v sshd >/dev/null 2>&1; then
        act SKIPPED "OpenSSH server is not installed"
        return 0
    fi
    load_sshd_effective

    # Work out who logs in and how, so nobody is locked out.
    local p u h k a nokey="" admins=0 admin_keys=0 root_key=0 operator=${SUDO_USER:-root} operator_key=0
    while IFS=$'\t' read -r u h k a; do
        [[ -n $u ]] || continue
        if [[ $u == "$operator" ]]; then operator_key=$k; fi
        if [[ $u == root ]]; then root_key=$k; continue; fi
        if [[ $a == 1 ]]; then
            admins=$((admins + 1))
            if [[ $k == 1 ]]; then admin_keys=$((admin_keys + 1)); fi
        fi
        if [[ $k == 0 ]]; then nokey+="${nokey:+, }$u"; fi
    done < <(list_login_users)
    local remote=0 akc
    [[ -n $(ssh_client_ip) ]] && remote=1
    akc=$(ssh_get authorizedkeyscommand)
    [[ $akc == none ]] && akc=""

    local root_login="" root_why
    if [[ $root_key -eq 1 ]]; then
        if [[ $PROFILE == strict && $admin_keys -gt 0 ]]; then
            root_login=no root_why="administrators have their own keys"
        else
            root_login=prohibit-password root_why="root has an SSH key, so key-only root login is kept"
        fi
    elif [[ $operator == root && $remote -eq 1 ]]; then
        root_why="you are logged in as root without a key; left unchanged"
    elif [[ $admins -gt 0 ]]; then
        root_login=no root_why="administrators log in with their own accounts"
    else
        root_why="there is no other administrator account; left unchanged"
    fi

    local pw="" pw_why
    case $SSH_PASSWORD_AUTH in
        yes) pw=yes pw_why="requested with --ssh-password-auth yes" ;;
        no)
            if [[ $admin_keys -eq 0 && $root_key -eq 0 ]]; then
                pw_why="not changed: no administrator has an SSH key"
                act ERROR "Refusing to disable SSH passwords: no administrator has an SSH key"
            elif [[ $operator_key -eq 0 ]]; then
                pw_why="not changed: your account ($operator) has no SSH key"
                act ERROR "Refusing to disable SSH passwords: $operator has no SSH key"
            else
                pw=no pw_why="requested with --ssh-password-auth no"
            fi
            ;;
        auto)
            if [[ -n $akc ]]; then
                pw_why="left unchanged: keys come from AuthorizedKeysCommand and can't be checked"
            elif [[ $admin_keys -eq 0 && $root_key -eq 0 ]]; then
                pw_why="left unchanged: no administrator has an SSH key yet"
            elif [[ $operator_key -eq 0 ]]; then
                pw_why="left unchanged: your account ($operator) has no SSH key"
            elif [[ -n $nokey && $PROFILE != strict ]]; then
                pw_why="left unchanged: these users have no SSH key yet: $nokey"
            else
                pw=no pw_why="every administrator has an SSH key"
            fi
            ;;
    esac

    local kex macs
    kex=$(ssh_supported_list kex diffie-hellman-group14-sha1 diffie-hellman-group-exchange-sha1 diffie-hellman-group1-sha1)
    macs=$(ssh_supported_list mac hmac-sha1 hmac-sha1-etm@openssh.com umac-64@openssh.com umac-64-etm@openssh.com hmac-md5 hmac-md5-etm@openssh.com)

    say "  Root login:      ${root_login:-unchanged ($(ssh_get permitrootlogin))} — $root_why"
    say "  Password login:  ${pw:-unchanged ($(ssh_get passwordauthentication))} — $pw_why"
    [[ -z $SSH_PORT ]] || say "  Ports:           ${SSH_TARGET_PORTS[*]} (currently ${CURRENT_SSH_PORTS[*]})"
    if [[ $pw == no && -n $nokey ]]; then
        act NOTE "These users have no SSH key and will no longer be able to log in over SSH: $nokey"
    fi
    if [[ -z $pw && $(ssh_get passwordauthentication) != no ]]; then
        act NOTE "SSH passwords stay enabled; fail2ban and MaxAuthTries limit guessing"
    fi
    approve "Apply SSH hardening?" || return 0

    local conf
    conf=$(
        printf '# %s — profile %s\n' "$MANAGED_TAG" "$PROFILE"
        printf '# Files in sshd_config.d are read before sshd_config; the first value wins.\n'
        printf '# To undo: delete this file and run "systemctl reload ssh".\n\n'
        if [[ -n $root_login ]]; then printf '# %s\nPermitRootLogin %s\n' "$root_why" "$root_login"; fi
        if [[ -n $pw ]]; then
            printf '# %s\nPasswordAuthentication %s\n' "$pw_why" "$pw"
            if [[ $pw == no ]]; then printf 'KbdInteractiveAuthentication no\n'; fi
        fi
        printf 'PermitEmptyPasswords no\n'
        printf 'HostbasedAuthentication no\nIgnoreRhosts yes\nPermitUserEnvironment no\n'
        printf 'X11Forwarding no\n'
        printf 'MaxAuthTries %s\n' "$([[ $PROFILE == strict ]] && echo 4 || echo 5)"
        printf 'MaxStartups 10:30:60\nLoginGraceTime 30\n'
        printf '# Drop connections to clients that vanished; idle live sessions are kept.\n'
        printf 'ClientAliveInterval 300\nClientAliveCountMax 3\n'
        printf '# VERBOSE logs the fingerprint of the key used for each login.\nLogLevel VERBOSE\n'
        if [[ $PROFILE == strict ]]; then
            printf 'AllowTcpForwarding no\nAllowAgentForwarding no\n'
        fi
        if [[ -n $kex ]]; then printf '# Remove SHA-1 key exchange from the defaults.\nKexAlgorithms -%s\n' "$kex"; fi
        if [[ -n $macs ]]; then printf '# Remove SHA-1, MD5 and 64-bit MACs from the defaults.\nMACs -%s\n' "$macs"; fi
        if [[ $SSH_BANNER -eq 1 ]]; then printf 'Banner /etc/issue.net\n'; fi
        if [[ -n $SSH_PORT ]]; then
            for p in "${SSH_TARGET_PORTS[@]}"; do printf 'Port %s\n' "$p"; done
        fi
    )

    local -a touched=()
    if [[ $SSH_BANNER -eq 1 ]]; then
        write_config /etc/issue.net 0644 "SSH login banner" <<'EOF'
Authorised access only. Activity on this system is monitored and logged.
EOF
    fi

    write_config "$SSHD_DROPIN" 0600 "SSH hardening settings ($SSHD_DROPIN)" <<<"$conf"
    [[ $LAST_WRITE == changed ]] && touched+=("$SSHD_DROPIN")

    # The drop-in only works if sshd_config includes sshd_config.d, and Port
    # lines add up across files, so ports in the main file are commented out.
    local need_include=0 main_ports=0
    grep -qE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' "$SSHD_CONFIG" || need_include=1
    if [[ -n $SSH_PORT ]] && grep -qE '^[[:space:]]*Port[[:space:]]' "$SSHD_CONFIG"; then main_ports=1; fi
    if [[ $need_include -eq 1 || $main_ports -eq 1 ]]; then
        write_config "$SSHD_CONFIG" keep "sshd_config includes sshd_config.d and leaves ports to it" < <(
            if [[ $need_include -eq 1 ]]; then printf 'Include /etc/ssh/sshd_config.d/*.conf\n\n'; fi
            if [[ $main_ports -eq 1 ]]; then
                sed -E 's/^([[:space:]]*Port[[:space:]].*)$/# \1   # moved to sshd_config.d\/00-ubuntu-hardening.conf/' "$SSHD_CONFIG"
            else
                cat "$SSHD_CONFIG"
            fi
        )
        [[ $LAST_WRITE == changed ]] && touched+=("$SSHD_CONFIG")
    fi
    local f
    for f in /etc/ssh/sshd_config.d/*.conf; do
        [[ $f == "$SSHD_DROPIN" ]] && continue
        if [[ -n $SSH_PORT ]] && grep -qE '^[[:space:]]*Port[[:space:]]' "$f"; then
            act NOTE "$f also sets Port; sshd listens on those ports too"
        fi
    done

    [[ ${#touched[@]} -gt 0 ]] || return 0

    mkdir -p /run/sshd
    local err
    if ! err=$(sshd -t 2>&1); then
        for f in "${touched[@]}"; do revert_file "$f"; done
        act ERROR "sshd rejected the new configuration; changes reverted: $err"
        return 0
    fi
    act OK "sshd -t: configuration is valid"

    local port_changed=0
    [[ "${SSH_TARGET_PORTS[*]}" == "${CURRENT_SSH_PORTS[*]}" ]] || port_changed=1
    if ! reload_ssh "$port_changed" >>"$LOG_FILE" 2>&1; then
        act ERROR "Could not reload ssh (see log); the previous sshd keeps running"
    fi
    local missing=""
    for p in "${SSH_TARGET_PORTS[@]}"; do
        wait_for_port "$p" || missing+="$p "
    done
    if [[ -n $missing ]]; then
        for f in "${touched[@]}"; do revert_file "$f"; done
        reload_ssh "$port_changed" >>"$LOG_FILE" 2>&1 || true
        act ERROR "sshd isn't listening on port(s) $missing after the change; SSH configuration reverted"
        return 0
    fi
    act CHANGED "sshd reloaded; listening on port(s) ${SSH_TARGET_PORTS[*]}"
    SSH_SESSION_NOTE=1

    if [[ $port_changed -eq 1 ]]; then
        if [[ $SSH_CLOSE_OLD_PORT -eq 1 ]]; then firewall_close_old_ssh_ports; fi
        act NOTE "Open port ${SSH_PORT}/tcp in any cloud firewall or security group too"
        if [[ $SSH_CLOSE_OLD_PORT -eq 0 ]]; then
            act NOTE "The old port stays open. After testing port $SSH_PORT, run again with --ssh-port $SSH_PORT --ssh-close-old-port"
        fi
    fi
}

# ─── Hardening: fail2ban ───────────────────────────────────────────────────

harden_fail2ban() {
    section "Intrusion prevention"
    approve "Install fail2ban (ban an address after 5 failed logins in 10 minutes)?" || return 0
    ensure_pkg fail2ban "fail2ban"
    ensure_pkg python3-systemd "fail2ban journal support"
    pkg_ready fail2ban || return 0

    local ignore="127.0.0.1/8 ::1" c
    local -a admin=()
    split_csv "$ADMIN_IPS" admin
    for c in "${admin[@]}"; do ignore+=" $c"; done
    local ports
    ports=$(IFS=,; printf '%s' "${SSH_TARGET_PORTS[*]}")

    local extra_jails=""
    # recidive reads fail2ban's own log file, so it needs file logging.
    if [[ -f /var/log/fail2ban.log ]]; then
        extra_jails+=$'\n[recidive]\nenabled = true\n'
    fi
    local web_jails=""
    if [[ -f /var/log/nginx/error.log ]]; then
        web_jails+=$'\n[nginx-http-auth]\nenabled = true\n\n[nginx-botsearch]\nenabled = true\n'
    fi
    if [[ -f /var/log/apache2/error.log ]]; then
        web_jails+=$'\n[apache-auth]\nenabled = true\n\n[apache-botsearch]\nenabled = true\n'
    fi

    write_config "$F2B_JAIL" 0644 "fail2ban jails ($F2B_JAIL)" <<EOF
# $MANAGED_TAG
# Repeat offenders are banned for longer each time, up to a week.

[DEFAULT]
bantime = 1h
bantime.increment = true
bantime.maxtime = 1w
findtime = 10m
maxretry = 5
ignoreip = $ignore

[sshd]
enabled = true
port = $ports
mode = $([[ $PROFILE == strict ]] && echo aggressive || echo normal)
$extra_jails$web_jails
EOF
    if [[ $LAST_WRITE == changed ]]; then
        local err
        if ! err=$(fail2ban-client -t 2>&1); then
            revert_file "$F2B_JAIL"
            act ERROR "fail2ban rejected the configuration; reverted: $(tail -3 <<<"$err")"
            return 0
        fi
        if service_active fail2ban; then
            systemctl restart fail2ban >>"$LOG_FILE" 2>&1 || act ERROR "Could not restart fail2ban (see log)"
        fi
    fi
    ensure_service fail2ban "fail2ban"
    if [[ $DRY_RUN -eq 0 ]] && service_active fail2ban; then
        sleep 1
        if fail2ban-client status sshd >/dev/null 2>&1; then
            act OK "fail2ban sshd jail is active"
        else
            act ERROR "fail2ban is running but the sshd jail didn't start (see /var/log/fail2ban.log)"
        fi
    fi
    if [[ ${#admin[@]} -eq 0 ]]; then
        act NOTE "Tip: add --admin-ip <your IP> so fail2ban never bans your own address"
    fi
}

# ─── Hardening: kernel ─────────────────────────────────────────────────────

harden_kernel() {
    section "Kernel"
    approve "Apply kernel and network hardening (sysctl, module blocklist, no core dumps)?" || return 0

    local key want sev desc
    write_config "$SYSCTL_FILE" 0644 "Kernel and network parameters ($SYSCTL_FILE)" < <(
        printf '# %s — profile %s\n' "$MANAGED_TAG" "$PROFILE"
        printf '# IP forwarding, IPv6 router advertisements and (in the baseline profile)\n'
        printf '# rp_filter are left alone so containers, VPNs and cloud networking keep working.\n\n'
        while IFS='|' read -r key want sev desc; do
            printf '# %s\n%s = %s\n' "$desc" "$key" "$want"
        done < <(sysctl_items)
    )
    if [[ $LAST_WRITE == changed ]]; then
        if sysctl -e -p "$SYSCTL_FILE" >>"$LOG_FILE" 2>&1; then act OK "Kernel parameters loaded"
        else act ERROR "Some kernel parameters could not be applied (see log)"; fi
    fi

    local mod
    write_config "$MODPROBE_FILE" 0644 "Block rarely needed kernel modules" < <(
        printf '# %s\n' "$MANAGED_TAG"
        printf '# udf (cloud provisioning ISOs), usb-storage and squashfs (snaps) stay allowed.\n'
        while read -r mod; do printf 'install %s /bin/false\nblacklist %s\n' "$mod" "$mod"; done < <(kernel_modules)
    )

    write_config "$LIMITS_FILE" 0644 "Disable core dumps (limits)" <<EOF
# $MANAGED_TAG
* hard core 0
EOF
    write_config "$COREDUMP_DROPIN" 0644 "Disable core dumps (systemd-coredump)" <<EOF
# $MANAGED_TAG
[Coredump]
Storage=none
ProcessSizeMax=0
EOF
}

# ─── Hardening: file system ────────────────────────────────────────────────

fix_perm() { # PATH MODE OWNER GROUP
    local path=$1 max=$2 owner=$3 group=$4 st mode uid gid
    st=$(stat -c '%a %U %G' "$path" 2>/dev/null) || return 0
    read -r mode uid gid <<<"$st"
    if (((8#$mode & ~8#$max & 8#7777) == 0)) && [[ $uid == "$owner" && "/$group/" == *"/$gid/"* ]]; then
        return 0
    fi
    local target_group=${group%%/*}
    local new_mode
    new_mode=$(printf '%o' $((8#$mode & 8#$max)))
    if [[ $DRY_RUN -eq 1 ]]; then
        act PLANNED "$path: $mode $uid:$gid → $new_mode $owner:$target_group"
        return 0
    fi
    manifest_add perm "$path" "$mode" "$uid:$gid"
    if chown "$owner:$target_group" "$path" && chmod "$new_mode" "$path"; then
        act CHANGED "$path: $mode $uid:$gid → $new_mode $owner:$target_group"
    else
        act ERROR "Could not fix permissions on $path"
    fi
}

harden_filesystem() {
    section "File system"
    approve "Tighten permissions on system files (shadow, sudoers, cron, SSH keys)?" || return 0
    local path max owner groups sev changed_before
    changed_before=$(count_actions CHANGED)
    while IFS='|' read -r path max owner groups sev; do
        fix_perm "$path" "$max" "$owner" "$groups"
    done < <(critical_path_items)
    if [[ $(count_actions CHANGED) == "$changed_before" && $DRY_RUN -eq 0 ]]; then
        act OK "System file permissions are already correct"
    fi
    act NOTE "World-writable files and unowned files are reported, not changed; review them in the report"
}

# ─── Hardening: accounts ───────────────────────────────────────────────────

harden_accounts() {
    section "Accounts"
    approve "Require strong passwords for new password changes (12+ characters, 3 character classes)?" || return 0
    ensure_pkg libpam-pwquality "libpam-pwquality"
    pkg_ready libpam-pwquality || return 0
    local -a opts=(minlen=12 minclass=3 maxrepeat=3 dictcheck=1 usercheck=1 retry=3)
    # enforce_for_root would also stop root setting simple passwords for others.
    if [[ $PROFILE == strict ]]; then opts+=(enforce_for_root); fi
    set_options "$PWQUALITY_CONF" '%s = %s' "Password quality rules" "${opts[@]}"
    act NOTE "Existing passwords keep working; the rules apply when a password is next changed"
}

# ─── Hardening: logging and auditing ───────────────────────────────────────

# Watches configuration that attackers change to keep access. There is no
# execve logging, so busy web servers don't flood the audit log. Only paths
# that exist are watched, because auditctl stops at the first bad rule.
audit_rules() {
    local entry path key
    printf '## %s\n\n' "$MANAGED_TAG"
    for entry in \
        /etc/passwd:identity /etc/group:identity /etc/shadow:identity /etc/gshadow:identity \
        /etc/security/opasswd:identity /etc/sudoers:privilege /etc/sudoers.d/:privilege \
        /etc/ssh/sshd_config:sshd /etc/ssh/sshd_config.d/:sshd /root/.ssh/:ssh-keys \
        /etc/crontab:cron /etc/cron.d/:cron /var/spool/cron/:cron /etc/systemd/system/:systemd \
        /etc/hosts:network /etc/netplan/:network /etc/apparmor.d/:apparmor /etc/localtime:time-change; do
        path=${entry%:*} key=${entry##*:}
        [[ -e $path ]] || continue
        printf -- '-w %s -p wa -k %s\n' "$path" "$key"
    done
    case $(uname -m) in
        x86_64 | aarch64)
            printf -- '-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time-change\n'
            printf -- '-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k modules\n'
            ;;
    esac
}

harden_logging() {
    section "Logging and auditing"
    approve "Keep the system journal across reboots and record security events with auditd?" || return 0

    write_config "$JOURNALD_DROPIN" 0644 "Persistent system journal (max 1 GB)" <<EOF
# $MANAGED_TAG
[Journal]
Storage=persistent
Compress=yes
SystemMaxUse=1G
EOF
    if [[ $LAST_WRITE == changed ]]; then
        mkdir -p /var/log/journal
        systemd-tmpfiles --create --prefix /var/log/journal >>"$LOG_FILE" 2>&1 || true
        systemctl restart systemd-journald >>"$LOG_FILE" 2>&1 || act ERROR "Could not restart systemd-journald"
    fi

    ensure_pkg auditd "auditd"
    pkg_ready auditd || return 0
    write_config "$AUDIT_RULES" 0640 "Audit rules for identity, sudo, SSH, cron and kernel modules" < <(audit_rules)
    if [[ $LAST_WRITE == changed ]]; then
        if augenrules --load >>"$LOG_FILE" 2>&1; then act OK "Audit rules loaded"
        else act ERROR "augenrules could not load the rules (see log)"; fi
    fi
    ensure_service auditd "auditd"
}

# ─── Hardening: AppArmor, time ─────────────────────────────────────────────

harden_apparmor() {
    section "AppArmor"
    approve "Make sure AppArmor is installed and running?" || return 0
    ensure_pkg apparmor "AppArmor"
    ensure_pkg apparmor-utils "AppArmor utilities"
    ensure_service apparmor "AppArmor"
    local enabled
    enabled=$(cat /sys/module/apparmor/parameters/enabled 2>/dev/null) || enabled=N
    if [[ $enabled != Y ]]; then
        act NOTE "AppArmor is disabled in the kernel; remove apparmor=0 from GRUB_CMDLINE_LINUX and reboot"
    fi
}

harden_time() {
    section "Time"
    approve "Make sure the clock is synchronised?" || return 0
    if pkg_installed chrony; then
        ensure_service chrony "chrony"
    elif unit_exists systemd-timesyncd.service; then
        ensure_service systemd-timesyncd "systemd-timesyncd"
        if [[ $DRY_RUN -eq 0 ]]; then timedatectl set-ntp true >>"$LOG_FILE" 2>&1 || true; fi
    else
        ensure_pkg systemd-timesyncd "systemd-timesyncd"
        ensure_service systemd-timesyncd "systemd-timesyncd"
    fi
}

# ─── Hardening: web server ─────────────────────────────────────────────────

harden_web() {
    section "Web server"
    local php_dirs=(/etc/php/*/fpm /etc/php/*/apache2) have=0
    command -v nginx >/dev/null 2>&1 && have=1
    [[ -d /etc/apache2 ]] && have=1
    [[ ${#php_dirs[@]} -gt 0 ]] && have=1
    if [[ $have -eq 0 ]]; then
        act SKIPPED "No nginx, Apache or PHP found"
        return 0
    fi
    say "  Only version disclosure and the TRACE method are changed; sites, TLS and headers are left to you."
    approve "Hide web server and PHP version numbers?" || return 0

    if command -v nginx >/dev/null 2>&1; then
        local conf
        conf=$(nginx -T 2>/dev/null | sed -E 's/#.*$//') || true
        if grep -qE '^[[:space:]]*server_tokens[[:space:]]' <<<"$conf" && [[ ! -f $NGINX_DROPIN ]]; then
            act SKIPPED "nginx: server_tokens is already set in your configuration"
        elif ! grep -qE 'include[[:space:]]+/etc/nginx/conf\.d/\*\.conf' <<<"$conf"; then
            act SKIPPED "nginx: nginx.conf doesn't include conf.d/*.conf; add 'server_tokens off;' manually"
        else
            write_config "$NGINX_DROPIN" 0644 "nginx: hide version (server_tokens off)" <<EOF
# $MANAGED_TAG
server_tokens off;
EOF
            if [[ $LAST_WRITE == changed ]]; then
                local err
                if err=$(nginx -t 2>&1); then
                    reload_service nginx && act OK "nginx reloaded"
                else
                    revert_file "$NGINX_DROPIN"
                    act ERROR "nginx -t failed; change reverted: $(tail -2 <<<"$err")"
                fi
            fi
        fi
    fi

    if [[ -d /etc/apache2/conf-available ]]; then
        write_config "/etc/apache2/conf-available/$APACHE_CONF_NAME.conf" 0644 "Apache: hide version, disable TRACE" <<EOF
# $MANAGED_TAG
# Loaded after security.conf, so these values win.
ServerTokens Prod
ServerSignature Off
TraceEnable Off
EOF
        local link="/etc/apache2/conf-enabled/$APACHE_CONF_NAME.conf" changed=$LAST_WRITE
        if [[ ! -e $link ]]; then
            if [[ $DRY_RUN -eq 1 ]]; then
                act PLANNED "a2enconf $APACHE_CONF_NAME"
            else
                backup_file "$link"
                a2enconf -q "$APACHE_CONF_NAME" >>"$LOG_FILE" 2>&1 && changed=changed
            fi
        fi
        if [[ $changed == changed ]]; then
            local err
            if err=$(apache2ctl configtest 2>&1); then
                reload_service apache2 && act OK "Apache reloaded"
            else
                revert_file "$link"
                revert_file "/etc/apache2/conf-available/$APACHE_CONF_NAME.conf"
                act ERROR "apache2ctl configtest failed; change reverted: $(tail -2 <<<"$err")"
            fi
        fi
    fi

    local d any=0 unit
    for d in "${php_dirs[@]}"; do
        [[ -d $d/conf.d ]] || continue
        write_config "$d/conf.d/99-ubuntu-hardening.ini" 0644 "PHP ($d): expose_php = Off" <<EOF
; $MANAGED_TAG
expose_php = Off
EOF
        [[ $LAST_WRITE == changed ]] && any=1
    done
    if [[ $any -eq 1 ]]; then
        for unit in /lib/systemd/system/php*-fpm.service; do
            unit=${unit##*/}
            reload_service "${unit%.service}" || act ERROR "Could not reload ${unit%.service}"
        done
        if [[ -d /etc/apache2 ]]; then reload_service apache2 || true; fi
    fi
}

# ─── Hardening: security tools ─────────────────────────────────────────────

harden_tools() {
    section "Security tools"
    local list="lynis, rkhunter, chkrootkit, debsums, needrestart"
    [[ $WITH_AIDE -eq 1 ]] && list+=", aide"
    [[ $WITH_CLAMAV -eq 1 ]] && list+=", clamav"
    approve "Install security tools ($list)?" || return 0

    ensure_pkg lynis "Lynis"
    ensure_pkg rkhunter "rkhunter"
    ensure_pkg chkrootkit "chkrootkit"
    ensure_pkg debsums "debsums"
    ensure_pkg needrestart "needrestart"

    if pkg_installed rkhunter && [[ $DRY_RUN -eq 0 ]]; then
        if [[ ! -s /var/lib/rkhunter/db/rkhunter.dat ]]; then
            run_cmd "rkhunter file property baseline" rkhunter --propupd --quiet && act CHANGED "rkhunter baseline created"
        fi
    fi

    if [[ $WITH_AIDE -eq 1 ]]; then
        ensure_pkg aide "AIDE"
        if pkg_installed aide && [[ ! -f /var/lib/aide/aide.db ]]; then
            say "  ${C_GREY}…        building the AIDE database (this can take several minutes)${C_RESET}"
            run_cmd "AIDE database" aideinit -y -f && act CHANGED "AIDE database initialised"
        fi
    fi

    if [[ $WITH_CLAMAV -eq 1 ]]; then
        ensure_pkg clamav "ClamAV"
        ensure_pkg clamav-daemon "ClamAV daemon"
        ensure_pkg clamav-freshclam "ClamAV signature updates"
        if pkg_ready clamav-freshclam; then ensure_service clamav-freshclam "ClamAV signature updates"; fi
    fi
}

run_lynis() {
    section "Lynis"
    if ! command -v lynis >/dev/null 2>&1; then
        act SKIPPED "Lynis is not installed"
        return 0
    fi
    if [[ $DRY_RUN -eq 1 ]]; then
        act PLANNED "lynis audit system"
        return 0
    fi
    say "  ${C_GREY}…        running Lynis (a few minutes)${C_RESET}"
    lynis audit system --quick --no-colors >"$RUN_DIR/lynis.log" 2>&1 || true
    LYNIS_INDEX=$(sed -n 's/^hardening_index=//p' /var/log/lynis-report.dat 2>/dev/null | tail -1) || true
    act OK "Lynis hardening index: ${LYNIS_INDEX:-unknown} (full output: $RUN_DIR/lynis.log)"
}

run_hardening() {
    HARDEN_STARTED=1
    if [[ $DRY_RUN -eq 0 ]]; then
        mkdir -p "$BACKUP_DIR/files"
        chmod 0700 "$BACKUP_ROOT" "$BACKUP_DIR"
        printf '# ubuntu-hardening %s on %s at %s (profile %s)\n' "$SCRIPT_VERSION" "$FQDN" "$TIMESTAMP" "$PROFILE" >"$MANIFEST"
        ln -sfn "$BACKUP_DIR" "$BACKUP_ROOT/latest"
    fi
    compute_ssh_ports

    if area_enabled updates; then harden_updates; fi
    if area_enabled firewall; then harden_firewall; fi   # before SSH so a new port is open first
    if area_enabled ssh; then harden_ssh; fi
    if area_enabled fail2ban; then harden_fail2ban; fi
    if area_enabled kernel; then harden_kernel; fi
    if area_enabled filesystem; then harden_filesystem; fi
    if area_enabled accounts; then harden_accounts; fi
    if area_enabled logging; then harden_logging; fi
    if area_enabled apparmor; then harden_apparmor; fi
    if area_enabled time; then harden_time; fi
    if area_enabled web; then harden_web; fi
    if area_enabled tools; then harden_tools; fi
    if [[ $RUN_LYNIS -eq 1 ]]; then run_lynis; fi
}

# ─── Rollback ──────────────────────────────────────────────────────────────

resolve_backup() {
    local target=$1
    if [[ $target == latest ]]; then
        target=$(readlink -f "$BACKUP_ROOT/latest" 2>/dev/null) || true
        [[ -n $target ]] || die "No backups found in $BACKUP_ROOT" 1
    fi
    [[ -f $target/manifest.tsv ]] || die "$target is not a hardening backup (no manifest.tsv)" 1
    printf '%s' "$target"
}

list_backups() {
    local d n state
    [[ -d $BACKUP_ROOT ]] || { echo "No backups in $BACKUP_ROOT"; return 0; }
    printf '%-40s %8s  %s\n' "BACKUP" "CHANGES" "STATE"
    for d in "$BACKUP_ROOT"/*/; do
        d=${d%/}
        [[ -f $d/manifest.tsv && ! -L $d ]] || continue
        n=$(grep -vc '^#' "$d/manifest.tsv" || true)
        state="can be rolled back"
        [[ -f $d/rolled-back ]] && state="rolled back $(cat "$d/rolled-back")"
        printf '%-40s %8s  %s\n' "$d" "$n" "$state"
    done
}

do_rollback() {
    local dir kind a b c
    dir=$(resolve_backup "$ROLLBACK_TARGET")
    CURRENT_AREA="Rollback"
    section "Rollback"
    say "  Backup: $dir"
    if [[ -f $dir/rolled-back ]]; then
        say "  ${C_YELLOW}This backup was already rolled back on $(cat "$dir/rolled-back").${C_RESET}"
    fi
    say "  Restores changed files, removes files the run created, and undoes firewall"
    say "  rules, permission and service changes. Installed packages are left in place."
    if [[ $ASSUME_YES -eq 0 ]]; then
        confirm "Roll back these changes?" || { say "  Cancelled."; return 0; }
    fi

    local -a packages=()
    while IFS=$'\t' read -r kind a b c; do
        case $kind in
            modified)
                if cp -a "$dir/files$a" "$a"; then act CHANGED "Restored $a"; else act ERROR "Could not restore $a"; fi ;;
            created)
                rm -f -- "$a" && act CHANGED "Removed $a" ;;
            perm)
                chmod "$b" "$a" && chown "$c" "$a" && act CHANGED "Restored $b $c on $a" ;;
            ufw-rule)
                local -a args; read -ra args <<<"$a"
                ufw --force delete "${args[@]}" >/dev/null 2>&1 && act CHANGED "Firewall: removed '$a'" ;;
            ufw-deleted)
                local -a args; read -ra args <<<"$a"
                ufw "${args[@]}" >/dev/null 2>&1 && act CHANGED "Firewall: re-added '$a'" ;;
            ufw-default)
                ufw default "$b" "$a" >/dev/null 2>&1 && act CHANGED "Firewall: default $b $a" ;;
            ufw-enabled)
                ufw --force disable >/dev/null 2>&1 && act CHANGED "Firewall: UFW disabled again" ;;
            service-enabled)
                systemctl disable --now "$a" >/dev/null 2>&1 && act CHANGED "Stopped and disabled $a" ;;
            package)
                packages+=("$a") ;;
        esac
    done < <(grep -v '^#' "$dir/manifest.tsv" | tac)

    systemctl daemon-reload >/dev/null 2>&1 || true
    mkdir -p /run/sshd
    if sshd -t >/dev/null 2>&1; then
        if reload_ssh 1 >/dev/null 2>&1; then act OK "ssh reloaded"; else act ERROR "Could not reload ssh"; fi
    else
        act ERROR "sshd -t fails after rollback; check /etc/ssh before closing this session"
    fi
    sysctl --system >/dev/null 2>&1 || true
    if service_active fail2ban; then systemctl restart fail2ban >/dev/null 2>&1 || true; fi
    if command -v augenrules >/dev/null 2>&1; then augenrules --load >/dev/null 2>&1 || true; fi
    systemctl restart systemd-journald >/dev/null 2>&1 || true
    if command -v nginx >/dev/null 2>&1 && nginx -t >/dev/null 2>&1; then reload_service nginx || true; fi
    if command -v apache2ctl >/dev/null 2>&1 && apache2ctl configtest >/dev/null 2>&1; then reload_service apache2 || true; fi

    date '+%Y-%m-%d %H:%M:%S' >"$dir/rolled-back"
    if [[ ${#packages[@]} -gt 0 ]]; then
        act NOTE "Packages installed by that run were kept. To remove them: sudo apt remove ${packages[*]}"
    fi
    say ""
    say "  Rollback finished: $(count_actions CHANGED) change(s) reverted, $(count_actions ERROR) error(s)."
}

# ─── Reports ───────────────────────────────────────────────────────────────

esc() {
    local s=$1
    s=${s//&/&amp;} s=${s//</&lt;} s=${s//>/&gt;} s=${s//\"/&quot;} s=${s//\'/&#39;}
    printf '%s' "${s//$'\n'/<br>}"
}

json_str() {
    local s=$1
    s=${s//\\/\\\\} s=${s//\"/\\\"} s=${s//$'\n'/\\n} s=${s//$'\r'/\\r} s=${s//$'\t'/\\t}
    s=${s//[$'\001'-$'\037']/}
    printf '"%s"' "$s"
}

mode_label() {
    if [[ $MODE_HARDEN -eq 0 ]]; then echo "Audit only"
    elif [[ $DRY_RUN -eq 1 ]]; then echo "Hardening preview (dry run)"
    else echo "Audit and hardening"; fi
}

write_json() {
    local i first score=${SCORE_AFTER:-$SCORE_BEFORE}
    {
        printf '{\n'
        printf '  "tool": "ubuntu-hardening",\n  "version": %s,\n' "$(json_str "$SCRIPT_VERSION")"
        printf '  "host": %s,\n  "generated": %s,\n' "$(json_str "$FQDN")" "$(json_str "$(date -Iseconds)")"
        printf '  "mode": %s,\n  "profile": %s,\n' "$(json_str "$(mode_label)")" "$(json_str "$PROFILE")"
        printf '  "score": { "before": %s, "after": %s, "grade": %s },\n' \
            "${SCORE_BEFORE:-null}" "${SCORE_AFTER:-null}" "$(json_str "$(grade "$score")")"
        printf '  "summary": { "critical": %s, "high": %s, "medium": %s, "low": %s, "passed": %s, "info": %s, "changes": %s, "errors": %s },\n' \
            "$(count_findings FAIL critical)" "$(count_findings FAIL high)" "$(count_findings FAIL medium)" \
            "$(count_findings FAIL low)" "$(count_findings PASS)" "$(count_findings INFO)" \
            "$(count_actions CHANGED)" "$(count_actions ERROR)"
        printf '  "lynis_hardening_index": %s,\n' "${LYNIS_INDEX:-null}"
        printf '  "system": {'
        first=1
        for i in "${!SI_KEY[@]}"; do
            [[ $first -eq 1 ]] || printf ','
            printf '\n    %s: %s' "$(json_str "${SI_KEY[i]}")" "$(json_str "${SI_VAL[i]}")"
            first=0
        done
        printf '\n  },\n  "findings": ['
        first=1
        for i in "${!F_ID[@]}"; do
            [[ $first -eq 1 ]] || printf ','
            printf '\n    { "id": %s, "status": %s, "severity": %s, "area": %s, "title": %s, "detail": %s, "remediation": %s }' \
                "$(json_str "${F_ID[i]}")" "$(json_str "${F_STATUS[i]}")" "$(json_str "${F_SEV[i]}")" \
                "$(json_str "${F_AREA[i]}")" "$(json_str "${F_TITLE[i]}")" "$(json_str "${F_DETAIL[i]}")" \
                "$(json_str "${F_FIX[i]}")"
            first=0
        done
        printf '\n  ],\n  "actions": ['
        first=1
        for i in "${!A_STATUS[@]}"; do
            [[ ${A_STATUS[i]} == OK ]] && continue
            [[ $first -eq 1 ]] || printf ','
            printf '\n    { "status": %s, "area": %s, "description": %s }' \
                "$(json_str "${A_STATUS[i]}")" "$(json_str "${A_AREA[i]}")" "$(json_str "${A_TEXT[i]}")"
            first=0
        done
        printf '\n  ],\n  "exposure": ['
        first=1
        for i in "${!X_PORT[@]}"; do
            [[ $first -eq 1 ]] || printf ','
            printf '\n    { "proto": %s, "address": %s, "port": %s, "process": %s, "firewall": %s }' \
                "$(json_str "${X_PROTO[i]}")" "$(json_str "${X_ADDR[i]}")" "${X_PORT[i]}" \
                "$(json_str "${X_PROC[i]}")" "$(json_str "${X_FW[i]}")"
            first=0
        done
        printf '\n  ]\n}\n'
    } >"$JSON_FILE"
}

html_badge() { # STATUS SEVERITY
    case $1 in
        PASS) printf '<span class="badge b-pass">Pass</span>' ;;
        INFO) printf '<span class="badge b-info">Info</span>' ;;
        FAIL) printf '<span class="badge b-%s">%s</span>' "$2" "${2^}" ;;
    esac
}

html_action_badge() {
    case $1 in
        CHANGED) printf '<span class="badge b-pass">Changed</span>' ;;
        PLANNED) printf '<span class="badge b-info">Planned</span>' ;;
        SKIPPED) printf '<span class="badge b-muted">Skipped</span>' ;;
        NOTE)    printf '<span class="badge b-medium">Note</span>' ;;
        ERROR)   printf '<span class="badge b-critical">Error</span>' ;;
    esac
}

write_html() {
    local score=${SCORE_AFTER:-$SCORE_BEFORE} g i sev area n_changes
    g=$(grade "$score")
    n_changes=$(count_actions CHANGED)
    local ring_color="var(--pass)"
    case $g in C | D) ring_color="var(--medium)" ;; F) ring_color="var(--critical)" ;; esac

    {
        cat <<EOF
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security report · $(esc "$HOST_SHORT")</title>
<style>
:root {
  --bg: #f5f6f8; --surface: #ffffff; --fg: #17191c; --muted: #5d6570; --border: #e1e4e8;
  --accent: #2458c6; --pass: #1a7f37; --info: #2458c6;
  --critical: #b42318; --high: #d1453b; --medium: #b54708; --low: #8a6d00;
  --pass-bg: #e7f5ea; --info-bg: #e8effc; --critical-bg: #fde8e6; --high-bg: #fdeceb;
  --medium-bg: #fdf0e3; --low-bg: #fbf5dc; --muted-bg: #eef0f3;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0e1116; --surface: #161a21; --fg: #e5e8ec; --muted: #9aa3ae; --border: #2a3039;
    --accent: #7aa7ff; --pass: #4fc26b; --info: #7aa7ff;
    --critical: #ff6b61; --high: #ff8a80; --medium: #f5a55c; --low: #e3c65a;
    --pass-bg: #14301d; --info-bg: #17264a; --critical-bg: #3d1614; --high-bg: #3a1b19;
    --medium-bg: #3a2814; --low-bg: #332d12; --muted-bg: #222831;
  }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--fg);
  font: 14px/1.55 system-ui, -apple-system, "Segoe UI", Roboto, Ubuntu, sans-serif; }
.wrap { max-width: 1160px; margin: 0 auto; padding: 32px 16px 64px; }
header.top { display: flex; gap: 24px; align-items: center; justify-content: space-between; flex-wrap: wrap;
  background: var(--surface); border: 1px solid var(--border); border-radius: 14px; padding: 24px; }
.eyebrow { color: var(--muted); font-size: 12px; letter-spacing: .08em; text-transform: uppercase; font-weight: 600; }
h1 { margin: 4px 0 6px; font-size: 26px; line-height: 1.2; word-break: break-all; }
h2 { font-size: 18px; margin: 36px 0 12px; }
h3 { font-size: 13px; margin: 22px 0 8px; color: var(--muted); text-transform: uppercase; letter-spacing: .06em; }
.meta { color: var(--muted); display: flex; gap: 6px 18px; flex-wrap: wrap; }
.score { display: flex; align-items: center; gap: 16px; }
.score svg { width: 104px; height: 104px; transform: rotate(-90deg); }
.score .num { font-size: 34px; font-weight: 700; line-height: 1; }
.score .sub { color: var(--muted); font-size: 13px; margin-top: 4px; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; margin-top: 16px; }
.card { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 14px 16px; }
.card .v { font-size: 26px; font-weight: 700; }
.card .k { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .06em; }
.card.critical .v { color: var(--critical); } .card.high .v { color: var(--high); }
.card.medium .v { color: var(--medium); } .card.low .v { color: var(--low); } .card.pass .v { color: var(--pass); }
.panel { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; overflow: hidden; }
.scroll { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; padding: 10px 14px; border-bottom: 1px solid var(--border); vertical-align: top; }
th { font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: .05em; font-weight: 600; background: var(--muted-bg); }
tr:last-child td { border-bottom: 0; }
td.id { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; color: var(--muted); white-space: nowrap; }
.detail { color: var(--muted); font-size: 13px; margin-top: 4px; word-break: break-word; }
.fix { font-size: 13px; margin-top: 6px; }
.fix::before { content: "Fix: "; font-weight: 600; }
code, .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12.5px; }
.badge { display: inline-block; padding: 2px 9px; border-radius: 999px; font-size: 12px; font-weight: 600; white-space: nowrap; }
.b-pass { color: var(--pass); background: var(--pass-bg); } .b-info { color: var(--info); background: var(--info-bg); }
.b-critical { color: var(--critical); background: var(--critical-bg); } .b-high { color: var(--high); background: var(--high-bg); }
.b-medium { color: var(--medium); background: var(--medium-bg); } .b-low { color: var(--low); background: var(--low-bg); }
.b-muted { color: var(--muted); background: var(--muted-bg); }
.toolbar { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; margin-bottom: 12px; }
.toolbar button { font: inherit; font-size: 13px; padding: 6px 12px; border-radius: 8px; border: 1px solid var(--border);
  background: var(--surface); color: var(--fg); cursor: pointer; }
.toolbar button[aria-pressed="true"] { background: var(--accent); border-color: var(--accent); color: #fff; }
.toolbar input { font: inherit; font-size: 13px; padding: 6px 10px; border-radius: 8px; border: 1px solid var(--border);
  background: var(--surface); color: var(--fg); min-width: 200px; flex: 1; max-width: 320px; }
tr.area td { background: var(--muted-bg); font-weight: 600; font-size: 13px; }
dl.kv { display: grid; grid-template-columns: max-content 1fr; gap: 8px 20px; margin: 0; padding: 16px; }
dl.kv dt { color: var(--muted); } dl.kv dd { margin: 0; word-break: break-word; }
.note { background: var(--surface); border: 1px solid var(--border); border-left: 4px solid var(--accent);
  border-radius: 10px; padding: 14px 16px; margin-top: 12px; }
footer { color: var(--muted); font-size: 12px; margin-top: 40px; text-align: center; }
.empty { padding: 18px; color: var(--muted); }
@media (max-width: 640px) {
  header.top { padding: 18px; } h1 { font-size: 22px; }
  th, td { padding: 8px 10px; } dl.kv { grid-template-columns: 1fr; gap: 2px 0; } dl.kv dd { margin-bottom: 8px; }
}
@media print {
  body { background: #fff; } .toolbar { display: none; } .panel, header.top, .card { break-inside: avoid; }
  tr[hidden] { display: table-row !important; }
}
</style>
</head>
<body>
<div class="wrap">
<header class="top">
  <div>
    <div class="eyebrow">Ubuntu Security Audit &amp; Hardening</div>
    <h1>$(esc "$FQDN")</h1>
    <div class="meta">
      <span>$(esc "$(date '+%Y-%m-%d %H:%M %Z')")</span>
      <span>$(esc "$(mode_label)")</span>
      <span>Profile: $(esc "$PROFILE")</span>
      <span>v$(esc "$SCRIPT_VERSION")</span>
    </div>
  </div>
  <div class="score" role="img" aria-label="Security score $score out of 100, grade $g">
    <svg viewBox="0 0 120 120" aria-hidden="true">
      <circle cx="60" cy="60" r="52" fill="none" stroke="var(--border)" stroke-width="12"/>
      <circle cx="60" cy="60" r="52" fill="none" stroke="$ring_color" stroke-width="12" stroke-linecap="round"
        pathLength="100" stroke-dasharray="$score 100"/>
    </svg>
    <div>
      <div class="num">$score<span style="font-size:16px;color:var(--muted)">/100</span></div>
      <div class="sub">Grade $g$( [[ -n $SCORE_AFTER ]] && printf ' · was %s before hardening' "$SCORE_BEFORE")</div>
      $( [[ -n $LYNIS_INDEX ]] && printf '<div class="sub">Lynis index %s</div>' "$(esc "$LYNIS_INDEX")")
    </div>
  </div>
</header>

<section class="cards" aria-label="Summary">
  <div class="card critical"><div class="v">$(count_findings FAIL critical)</div><div class="k">Critical</div></div>
  <div class="card high"><div class="v">$(count_findings FAIL high)</div><div class="k">High</div></div>
  <div class="card medium"><div class="v">$(count_findings FAIL medium)</div><div class="k">Medium</div></div>
  <div class="card low"><div class="v">$(count_findings FAIL low)</div><div class="k">Low</div></div>
  <div class="card pass"><div class="v">$(count_findings PASS)</div><div class="k">Passed</div></div>
  <div class="card"><div class="v">$n_changes</div><div class="k">Changes applied</div></div>
</section>
EOF

        # Priority findings
        printf '<h2>Open findings by priority</h2>\n'
        if [[ $(count_findings FAIL) -eq 0 ]]; then
            printf '<div class="panel"><div class="empty">No open findings.</div></div>\n'
        else
            printf '<div class="panel scroll"><table>\n<thead><tr><th>Severity</th><th>Finding</th><th>Area</th><th>ID</th></tr></thead><tbody>\n'
            for sev in critical high medium low; do
                for i in "${!F_ID[@]}"; do
                    [[ ${F_STATUS[i]} == FAIL && ${F_SEV[i]} == "$sev" ]] || continue
                    printf '<tr><td>%s</td><td><div>%s</div>' "$(html_badge FAIL "$sev")" "$(esc "${F_TITLE[i]}")"
                    [[ -n ${F_DETAIL[i]} ]] && printf '<div class="detail mono">%s</div>' "$(esc "${F_DETAIL[i]}")"
                    [[ -n ${F_FIX[i]} ]] && printf '<div class="fix">%s</div>' "$(esc "${F_FIX[i]}")"
                    printf '</td><td>%s</td><td class="id">%s</td></tr>\n' "$(esc "${F_AREA[i]}")" "$(esc "${F_ID[i]}")"
                done
            done
            printf '</tbody></table></div>\n'
        fi

        # Changes
        if [[ $MODE_HARDEN -eq 1 ]]; then
            printf '<h2>%s</h2>\n' "$([[ $DRY_RUN -eq 1 ]] && echo 'Planned changes' || echo 'Changes made')"
            local shown=0
            printf '<div class="panel scroll"><table>\n<thead><tr><th>Status</th><th>Change</th><th>Area</th></tr></thead><tbody>\n'
            for i in "${!A_STATUS[@]}"; do
                [[ ${A_STATUS[i]} == OK ]] && continue
                printf '<tr><td>%s</td><td>%s</td><td>%s</td></tr>\n' "$(html_action_badge "${A_STATUS[i]}")" "$(esc "${A_TEXT[i]}")" "$(esc "${A_AREA[i]}")"
                shown=1
            done
            [[ $shown -eq 1 ]] || printf '<tr><td colspan="3" class="empty">Nothing needed changing.</td></tr>\n'
            printf '</tbody></table></div>\n'
            if [[ $DRY_RUN -eq 0 ]]; then
                printf '<div class="note"><strong>Undo.</strong> Backups and a change manifest are in <code>%s</code>. To revert this run: <code>sudo %s --rollback %s</code></div>\n' \
                    "$(esc "$BACKUP_DIR")" "$(esc "$SCRIPT_PATH")" "$(esc "$BACKUP_DIR")"
            fi
        fi

        # Exposure
        printf '<h2>Network exposure</h2>\n'
        if [[ ${#X_PORT[@]} -eq 0 ]]; then
            printf '<div class="panel"><div class="empty">No services listening on public addresses were found.</div></div>\n'
        else
            printf '<div class="panel scroll"><table>\n<thead><tr><th>Protocol</th><th>Address</th><th>Port</th><th>Process</th><th>Firewall</th></tr></thead><tbody>\n'
            for i in "${!X_PORT[@]}"; do
                local fwb
                case ${X_FW[i]} in allowed) fwb='<span class="badge b-medium">Allowed</span>' ;; blocked) fwb='<span class="badge b-pass">Blocked</span>' ;; *) fwb='<span class="badge b-critical">No firewall</span>' ;; esac
                printf '<tr><td>%s</td><td class="mono">%s</td><td class="mono">%s</td><td>%s</td><td>%s</td></tr>\n' \
                    "$(esc "${X_PROTO[i]}")" "$(esc "${X_ADDR[i]}")" "$(esc "${X_PORT[i]}")" "$(esc "${X_PROC[i]}")" "$fwb"
            done
            printf '</tbody></table></div>\n'
        fi

        # All checks
        cat <<'EOF'
<h2>All checks</h2>
<div class="toolbar" role="group" aria-label="Filter checks">
  <button type="button" data-filter="all" aria-pressed="true">All</button>
  <button type="button" data-filter="FAIL" aria-pressed="false">Open</button>
  <button type="button" data-filter="PASS" aria-pressed="false">Passed</button>
  <button type="button" data-filter="INFO" aria-pressed="false">Info</button>
  <input type="search" id="q" placeholder="Search checks" aria-label="Search checks">
</div>
<div class="panel scroll"><table id="checks">
<thead><tr><th>Result</th><th>Check</th><th>ID</th></tr></thead><tbody>
EOF
        local -a areas=()
        for i in "${!F_ID[@]}"; do contains "${F_AREA[i]}" "${areas[@]}" || areas+=("${F_AREA[i]}"); done
        for area in "${areas[@]}"; do
            printf '<tr class="area"><td colspan="3">%s</td></tr>\n' "$(esc "$area")"
            for i in "${!F_ID[@]}"; do
                [[ ${F_AREA[i]} == "$area" ]] || continue
                printf '<tr data-status="%s"><td>%s</td><td><div>%s</div>' "${F_STATUS[i]}" "$(html_badge "${F_STATUS[i]}" "${F_SEV[i]}")" "$(esc "${F_TITLE[i]}")"
                [[ -n ${F_DETAIL[i]} ]] && printf '<div class="detail">%s</div>' "$(esc "${F_DETAIL[i]}")"
                [[ ${F_STATUS[i]} == FAIL && -n ${F_FIX[i]} ]] && printf '<div class="fix">%s</div>' "$(esc "${F_FIX[i]}")"
                printf '</td><td class="id">%s</td></tr>\n' "$(esc "${F_ID[i]}")"
            done
        done
        printf '</tbody></table></div>\n'

        # System
        printf '<h2>System</h2>\n<div class="panel"><dl class="kv">\n'
        for i in "${!SI_KEY[@]}"; do
            printf '<dt>%s</dt><dd>%s</dd>\n' "$(esc "${SI_KEY[i]}")" "$(esc "${SI_VAL[i]}")"
        done
        printf '</dl></div>\n'

        cat <<EOF
<div class="note"><strong>About the score.</strong> Each check is weighted by severity (critical 10, high 5, medium 3, low 1).
The score is the weighted share of checks that pass. Informational items don't count.</div>
<footer>Generated by harden.sh v$(esc "$SCRIPT_VERSION") · $(esc "$FQDN") · run $(esc "$TIMESTAMP"). This report describes the host's security configuration; keep it private.</footer>
</div>
<script>
(function () {
  var buttons = document.querySelectorAll('.toolbar button');
  var q = document.getElementById('q');
  var filter = 'all';
  function apply() {
    var term = (q.value || '').toLowerCase();
    var rows = document.querySelectorAll('#checks tbody tr');
    var lastArea = null, areaVisible = false;
    rows.forEach(function (r) {
      if (r.classList.contains('area')) {
        if (lastArea) lastArea.hidden = !areaVisible;
        lastArea = r; areaVisible = false; return;
      }
      var show = (filter === 'all' || r.dataset.status === filter) &&
                 (!term || r.textContent.toLowerCase().indexOf(term) !== -1);
      r.hidden = !show;
      if (show) areaVisible = true;
    });
    if (lastArea) lastArea.hidden = !areaVisible;
  }
  buttons.forEach(function (b) {
    b.addEventListener('click', function () {
      filter = b.dataset.filter;
      buttons.forEach(function (x) { x.setAttribute('aria-pressed', x === b ? 'true' : 'false'); });
      apply();
    });
  });
  q.addEventListener('input', apply);
})();
</script>
</body>
</html>
EOF
    } >"$HTML_FILE"
}

# ─── Summary ───────────────────────────────────────────────────────────────

print_summary() {
    local score=${SCORE_AFTER:-$SCORE_BEFORE} i sev shown=0
    [[ $QUIET -eq 1 ]] && return 0
    section "Summary"
    if [[ -n $SCORE_AFTER ]]; then
        printf '  %-16s %s%s/100 (%s)%s, up from %s/100 (%s)\n' "Security score" "$C_BOLD" "$SCORE_AFTER" "$(grade "$SCORE_AFTER")" "$C_RESET" "$SCORE_BEFORE" "$(grade "$SCORE_BEFORE")"
    else
        printf '  %-16s %s%s/100 (%s)%s\n' "Security score" "$C_BOLD" "$score" "$(grade "$score")" "$C_RESET"
    fi
    printf '  %-16s %s critical · %s high · %s medium · %s low\n' "Open findings" \
        "$(count_findings FAIL critical)" "$(count_findings FAIL high)" "$(count_findings FAIL medium)" "$(count_findings FAIL low)"
    printf '  %-16s %s\n' "Passed checks" "$(count_findings PASS)"
    if [[ $MODE_HARDEN -eq 1 ]]; then
        if [[ $DRY_RUN -eq 1 ]]; then
            printf '  %-16s %s planned\n' "Changes" "$(count_actions PLANNED)"
        else
            printf '  %-16s %s applied · %s error(s)\n' "Changes" "$(count_actions CHANGED)" "$(count_actions ERROR)"
        fi
    fi
    [[ -z $LYNIS_INDEX ]] || printf '  %-16s %s\n' "Lynis index" "$LYNIS_INDEX"

    if [[ $(count_findings FAIL) -gt 0 ]]; then
        printf '\n  %sTop findings%s\n' "$C_BOLD" "$C_RESET"
        for sev in critical high medium; do
            for i in "${!F_ID[@]}"; do
                [[ ${F_STATUS[i]} == FAIL && ${F_SEV[i]} == "$sev" && $shown -lt 8 ]] || continue
                _line "$(sev_color "$sev")" "${sev^^}" "${F_TITLE[i]}"
                shown=$((shown + 1))
            done
        done
    fi

    printf '\n  %sReports%s\n' "$C_BOLD" "$C_RESET"
    printf '  %-16s %s\n' "HTML" "$HTML_FILE" "JSON" "$JSON_FILE" "Log" "$LOG_FILE"
    if [[ $MODE_HARDEN -eq 1 && $DRY_RUN -eq 0 ]]; then
        printf '  %-16s %s\n' "Backup" "$BACKUP_DIR"
        printf '  %-16s sudo %s --rollback latest\n' "Undo" "$SCRIPT_PATH"
    fi
    if [[ $MODE_HARDEN -eq 1 && $DRY_RUN -eq 1 ]]; then
        printf '\n  Nothing was changed. Run with --harden (without --dry-run) to apply.\n'
    fi
    if [[ $SSH_SESSION_NOTE -eq 1 && -n $(ssh_client_ip) ]]; then
        printf '\n  %s%sKeep this SSH session open.%s Test a new login from another terminal before you log out.\n' "$C_YELLOW" "$C_BOLD" "$C_RESET"
    fi
    printf '\n'
}

# ─── Arguments and configuration ───────────────────────────────────────────

usage() {
    cat <<EOF
Ubuntu Security Audit & Hardening Suite v$SCRIPT_VERSION

Usage: sudo $SCRIPT_NAME [options]

By default the script only audits and changes nothing. Add --harden to fix
what it finds, or --dry-run to preview the fixes. Hardening is safe for an
internet-facing web server with interactive users: SSH and web ports stay
open, and SSH passwords are only disabled when every login user has a key.

Modes
  --harden                  Apply hardening after the audit
  -n, --dry-run             Preview hardening without changing anything
  -y, --yes                 Don't ask for confirmation (unattended runs)
  --rollback DIR|latest     Revert the changes recorded in a backup
  --list-backups            List backups that can be rolled back

Scope
  --profile NAME            baseline (default): safe for multi-user web servers
                            strict: also disables SSH TCP/agent forwarding,
                            rate-limits SSH, strict rp_filter, ptrace, SysRq
  --skip AREAS              Comma-separated areas to leave alone:
                            $AREAS
  --no-web                  Same as --skip web
  --no-tools                Same as --skip tools

SSH
  --ssh-port PORT           Also listen on PORT (the old port keeps working)
  --ssh-close-old-port      With --ssh-port: stop listening on other ports
  --ssh-password-auth MODE  auto (default): disable passwords only when every
                            login user has a key; no: disable if admins have
                            keys; yes: leave passwords enabled
  --ssh-allow-from CIDRS    Only accept SSH from these networks (firewall)
  --ssh-banner              Show a legal warning before login

Firewall and brute-force protection
  --allow-tcp PORTS         Public TCP ports (default: 80,443); ranges: 8000:8100
  --allow-udp PORTS         Public UDP ports (e.g. 443 for HTTP/3)
  --allow-detected          Also allow ports that services already listen on
                            (databases and admin services are never included)
  --admin-ip CIDRS          Addresses fail2ban must never ban

Optional components
  --with-aide               Install AIDE and build its database (slow)
  --with-clamav             Install ClamAV (needs about 1.5 GB of RAM)
  --run-lynis               Run a Lynis audit and include its index
  --auto-reboot HH:MM       Let unattended-upgrades reboot at this time

Output
  --report-dir DIR          Reports (default: $REPORT_ROOT)
  --backup-dir DIR          Backups (default: $BACKUP_ROOT)
  --json                    Print the JSON report on stdout
  --fail-on SEVERITY        Exit with 5 if a finding at or above SEVERITY
                            remains (critical, high, medium, low)
  -q, --quiet               Only print the summary
  -v, --verbose             Show details and planned file diffs
  --no-color                Disable colours (NO_COLOR is honoured too)
  --trace                   Bash execution trace (debugging)
  --config FILE             Read KEY=VALUE settings (see hardening.conf.example)
  -h, --help                Show this help
  --version                 Show the version

Exit codes
  0 success  1 error  2 bad arguments  3 not root  4 already running
  5 findings at or above --fail-on remain

Examples
  sudo ./$SCRIPT_NAME                                    # audit only
  sudo ./$SCRIPT_NAME --harden --dry-run                 # preview changes
  sudo ./$SCRIPT_NAME --harden --admin-ip 203.0.113.10   # harden interactively
  sudo ./$SCRIPT_NAME --harden --yes --no-tools          # unattended
  sudo ./$SCRIPT_NAME --fail-on high --quiet             # CI / compliance gate
  sudo ./$SCRIPT_NAME --rollback latest                  # undo the last run
EOF
}

load_config() {
    local file=$1 line key value n=0
    [[ -r $file ]] || usage_error "Cannot read config file: $file"
    while IFS= read -r line || [[ -n $line ]]; do
        n=$((n + 1))
        line=${line%%#*}
        line=$(xargs <<<"$line" 2>/dev/null) || usage_error "$file:$n: unbalanced quotes"
        [[ -n $line ]] || continue
        [[ $line == *=* ]] || usage_error "$file:$n: expected KEY=VALUE"
        key=${line%%=*} value=${line#*=}
        [[ $CONFIG_KEYS == *" $key "* ]] || usage_error "$file:$n: unknown setting '$key'"
        printf -v "$key" '%s' "$value"
    done <"$file"
}

parse_args() {
    local i next
    # Apply --config first so options on the command line override it.
    for ((i = 1; i <= $#; i++)); do
        if [[ ${!i} == --config ]]; then
            next=$((i + 1))
            [[ $next -le $# ]] || usage_error "--config needs a file"
            load_config "${!next}"
        elif [[ ${!i} == --config=* ]]; then
            load_config "${!i#--config=}"
        fi
    done

    while [[ $# -gt 0 ]]; do
        local opt=$1 val=""
        if [[ $opt == --*=* ]]; then
            val=${opt#*=} opt=${opt%%=*}
            shift
            set -- "$opt" "$val" "$@"
        fi
        case $opt in
            --rollback | --profile | --skip | --ssh-port | --ssh-password-auth | --ssh-allow-from | \
                --allow-tcp | --allow-udp | --admin-ip | --auto-reboot | --report-dir | --backup-dir | \
                --fail-on | --config)
                [[ $# -ge 2 && $2 != -* ]] || usage_error "$opt needs a value"
                ;;
        esac
        case $opt in
            --harden) MODE_HARDEN=1 ;;
            -n | --dry-run) DRY_RUN=1 MODE_HARDEN=1 ;;
            -y | --yes) ASSUME_YES=1 ;;
            --rollback) ROLLBACK_TARGET=$2; shift ;;
            --list-backups) LIST_BACKUPS=1 ;;
            --profile) PROFILE=${2:-}; shift ;;
            --skip) SKIP_AREAS+="${SKIP_AREAS:+,}${2:-}"; shift ;;
            --no-web) SKIP_AREAS+="${SKIP_AREAS:+,}web" ;;
            --no-tools) SKIP_AREAS+="${SKIP_AREAS:+,}tools" ;;
            --ssh-port) SSH_PORT=${2:-}; shift ;;
            --ssh-close-old-port) SSH_CLOSE_OLD_PORT=1 ;;
            --ssh-password-auth) SSH_PASSWORD_AUTH=${2:-}; shift ;;
            --ssh-allow-from) SSH_ALLOW_FROM=${2:-}; shift ;;
            --ssh-banner) SSH_BANNER=1 ;;
            --allow-tcp) ALLOW_TCP=${2:-}; shift ;;
            --allow-udp) ALLOW_UDP=${2:-}; shift ;;
            --allow-detected) ALLOW_DETECTED=1 ;;
            --admin-ip) ADMIN_IPS=${2:-}; shift ;;
            --with-aide) WITH_AIDE=1 ;;
            --with-clamav) WITH_CLAMAV=1 ;;
            --run-lynis) RUN_LYNIS=1 ;;
            --auto-reboot) AUTO_REBOOT_TIME=${2:-}; shift ;;
            --report-dir) REPORT_ROOT=${2:-}; shift ;;
            --backup-dir) BACKUP_ROOT=${2:-}; shift ;;
            --json) JSON_OUTPUT=1 ;;
            --fail-on) FAIL_ON=${2:-}; shift ;;
            -q | --quiet) QUIET=1 ;;
            -v | --verbose) VERBOSE=1 ;;
            --no-color) NO_COLOR=1 ;;
            --trace) set -x ;;
            --config) shift ;;
            -h | --help) usage; exit 0 ;;
            --version) printf '%s %s\n' "$SCRIPT_NAME" "$SCRIPT_VERSION"; exit 0 ;;
            *) usage_error "Unknown option: $opt" ;;
        esac
        shift
    done
}

validate_settings() {
    local x
    local -a list
    [[ $PROFILE == baseline || $PROFILE == strict ]] || usage_error "--profile must be baseline or strict"
    [[ $SSH_PASSWORD_AUTH =~ ^(auto|yes|no)$ ]] || usage_error "--ssh-password-auth must be auto, yes or no"
    [[ -z $SSH_PORT ]] || is_port "$SSH_PORT" || usage_error "Invalid --ssh-port: $SSH_PORT"
    [[ $SSH_CLOSE_OLD_PORT -eq 0 || -n $SSH_PORT ]] || usage_error "--ssh-close-old-port needs --ssh-port"
    split_csv "$ALLOW_TCP" list
    for x in "${list[@]}"; do is_port_spec "$x" || usage_error "Invalid TCP port: $x"; done
    split_csv "$ALLOW_UDP" list
    for x in "${list[@]}"; do is_port_spec "$x" || usage_error "Invalid UDP port: $x"; done
    split_csv "$SSH_ALLOW_FROM" list
    for x in "${list[@]}"; do is_cidr "$x" || usage_error "Invalid address or network: $x"; done
    split_csv "$ADMIN_IPS" list
    for x in "${list[@]}"; do is_cidr "$x" || usage_error "Invalid address or network: $x"; done
    split_csv "$SKIP_AREAS" list
    for x in "${list[@]}"; do [[ ",$AREAS," == *",$x,"* ]] || usage_error "Unknown area '$x' (valid: $AREAS)"; done
    [[ -z $FAIL_ON || $FAIL_ON =~ ^(critical|high|medium|low)$ ]] || usage_error "--fail-on must be critical, high, medium or low"
    [[ -z $AUTO_REBOOT_TIME || $AUTO_REBOOT_TIME =~ ^([01][0-9]|2[0-3]):[0-5][0-9]$ ]] || usage_error "--auto-reboot needs HH:MM"
    [[ $REPORT_ROOT == /* && $BACKUP_ROOT == /* ]] || usage_error "--report-dir and --backup-dir must be absolute paths"
}

# ─── Main ──────────────────────────────────────────────────────────────────

on_error() {
    local rc=$? line=$1 cmd=$2
    # Failures inside subshells are reported by the command that ran them.
    if ((BASH_SUBSHELL > 0)); then exit "$rc"; fi
    printf '\n%sFATAL:%s "%s" failed with exit code %s (line %s)\n' "$C_RED$C_BOLD" "$C_RESET" "$cmd" "$rc" "$line" >&2
    [[ $LOG_FILE == /dev/null ]] || printf 'Log: %s\n' "$LOG_FILE" >&2
    if [[ $HARDEN_STARTED -eq 1 && $DRY_RUN -eq 0 ]]; then
        printf 'Changes made so far can be reverted with: sudo %s --rollback %s\n' "$SCRIPT_PATH" "$BACKUP_DIR" >&2
    fi
    exit "$rc"
}

cleanup() {
    [[ -z $WORK_DIR ]] || rm -rf -- "$WORK_DIR"
}

setup_run() {
    RUN_DIR="$REPORT_ROOT/${HOST_SHORT}_$TIMESTAMP"
    LOG_FILE="$RUN_DIR/run.log"
    HTML_FILE="$RUN_DIR/report.html"
    JSON_FILE="$RUN_DIR/report.json"
    BACKUP_DIR="$BACKUP_ROOT/$TIMESTAMP"
    MANIFEST="$BACKUP_DIR/manifest.tsv"

    # Reports describe the host's weaknesses, so only root may read them.
    mkdir -p "$RUN_DIR"
    chmod 0700 "$REPORT_ROOT" "$RUN_DIR"
    install -m 0600 /dev/null "$LOG_FILE"
    install -m 0600 /dev/null "$HTML_FILE"
    install -m 0600 /dev/null "$JSON_FILE"
    WORK_DIR=$(mktemp -d)

    if [[ $JSON_OUTPUT -eq 1 ]]; then
        exec 3>&1
        exec >>"$LOG_FILE"
    else
        exec > >(tee >(sed -u 's/\x1b\[[0-9;]*m//g' >>"$LOG_FILE")) 2>&1
    fi
}

print_banner() {
    [[ $QUIET -eq 1 ]] && return 0
    printf '\n%sUbuntu Security Audit & Hardening Suite%s  v%s\n' "$C_BOLD" "$C_RESET" "$SCRIPT_VERSION"
    printf '%s%s%s\n' "$C_GREY" "──────────────────────────────────────────────────────────────────────────" "$C_RESET"
    printf '  %-10s %s (%s)\n' "Host" "$FQDN" "$(os_field PRETTY_NAME)"
    printf '  %-10s %s\n' "Mode" "$(mode_label)"
    printf '  %-10s %s\n' "Profile" "$PROFILE"
    [[ -z $SKIP_AREAS ]] || printf '  %-10s %s\n' "Skipping" "$SKIP_AREAS"
    printf '  %-10s %s\n' "Reports" "$RUN_DIR"
    if [[ -n $(ssh_client_ip) && $MODE_HARDEN -eq 1 && $DRY_RUN -eq 0 ]]; then
        printf '\n  %sYou are connected over SSH.%s SSH changes are validated and rolled back\n' "$C_YELLOW$C_BOLD" "$C_RESET"
        printf '  automatically if sshd fails, but keep a second session or console access ready.\n'
    fi
}

preflight() {
    [[ $EUID -eq 0 ]] || die "Run this as root: sudo $SCRIPT_NAME $*" 3
    local id version
    id=$(os_field ID) version=$(os_field VERSION_ID)
    if [[ $id != ubuntu ]]; then
        [[ $MODE_HARDEN -eq 0 ]] || die "Hardening is only supported on Ubuntu (found: ${id:-unknown})" 1
        printf 'Warning: this script is written for Ubuntu (found: %s)\n' "${id:-unknown}" >&2
    elif [[ -n $version ]] && dpkg --compare-versions "$version" lt 22.04; then
        [[ $MODE_HARDEN -eq 0 ]] || die "Hardening needs Ubuntu 22.04 or newer (found $version)" 1
    fi
    if [[ $MODE_HARDEN -eq 1 && $DRY_RUN -eq 0 && $ASSUME_YES -eq 0 ]] && ! { : </dev/tty; } 2>/dev/null; then
        die "No terminal for confirmation prompts; use --yes for unattended hardening" 2
    fi
    exec 9>"$LOCK_FILE"
    flock -n 9 || die "Another instance is already running" 4
}

exit_code() {
    local i threshold
    [[ -n $FAIL_ON ]] || { echo 0; return; }
    threshold=$(sev_rank "$FAIL_ON")
    for i in "${!F_ID[@]}"; do
        if [[ ${F_STATUS[i]} == FAIL ]] && (($(sev_rank "${F_SEV[i]}") >= threshold)); then echo 5; return; fi
    done
    echo 0
}

main() {
    umask 022
    setup_colors
    parse_args "$@"
    validate_settings
    setup_colors
    trap 'on_error "$LINENO" "$BASH_COMMAND"' ERR
    trap cleanup EXIT

    if [[ $LIST_BACKUPS -eq 1 ]]; then
        [[ $EUID -eq 0 ]] || die "Run this as root" 3
        list_backups
        return 0
    fi
    if [[ -n $ROLLBACK_TARGET ]]; then
        [[ $EUID -eq 0 ]] || die "Run this as root" 3
        exec 9>"$LOCK_FILE"
        flock -n 9 || die "Another instance is already running" 4
        do_rollback
        return 0
    fi

    preflight "$@"
    setup_run
    print_banner

    run_audit
    SCORE_BEFORE=$(compute_score)

    if [[ $MODE_HARDEN -eq 1 ]]; then
        say ""
        say "${C_BOLD}Hardening${C_RESET}${C_GREY} — each area asks before changing anything${C_RESET}"
        run_hardening
        if [[ $DRY_RUN -eq 0 ]]; then
            # Re-audit so the report shows the hardened state.
            local quiet_saved=$QUIET
            QUIET=1
            reset_findings
            run_audit
            QUIET=$quiet_saved
            SCORE_AFTER=$(compute_score)
        fi
    fi

    write_json
    write_html
    ln -sfn "$RUN_DIR" "$REPORT_ROOT/latest"
    print_summary

    if [[ $JSON_OUTPUT -eq 1 ]]; then cat "$JSON_FILE" >&3; fi
    # exit, not return: a non-zero return would trip errexit and the ERR trap.
    exit "$(exit_code)"
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    main "$@"
fi

#!/usr/bin/env bash
# =============================================================================
# ZLT — ZavetSec Linux Triage v1.1
# DFIR telemetry collection + built-in detection rules
# Requires: bash 4+, root/sudo recommended
# Output: self-contained HTML report (+ optional CSV/JSON export)
# Usage: ./ZLT.sh [--csv] [--json] [--all]
# =============================================================================

set -uo pipefail
IFS=$'\n\t'

# ── Config ───────────────────────────────────────────────────────────────────
TOOL_VERSION="1.1"
TOOL_NAME="ZLT"
HOSTNAME_VAL=$(hostname 2>/dev/null || echo "unknown")
START_TS=$(date '+%Y-%m-%d %H:%M:%S')
START_EPOCH=$(date +%s)

# Resolve script directory (works with symlinks, relative paths, direct execution)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPORT_BASE="${SCRIPT_DIR}/ZLT_${HOSTNAME_VAL}_$(date +%Y%m%d_%H%M%S)"
REPORT_FILE="${REPORT_BASE}.html"

# ── Export flags (CLI args) ───────────────────────────────────────────────────
EXPORT_CSV=0
EXPORT_JSON=0
for _arg in "$@"; do
    case "$_arg" in
        --csv)  EXPORT_CSV=1  ;;
        --json) EXPORT_JSON=1 ;;
        --all)  EXPORT_CSV=1; EXPORT_JSON=1 ;;
        --help|-help|-h)
            echo ""
            echo "  ZLT v1.1 — ZavetSec Linux Triage"
            echo ""
            echo "  Usage: $0 [OPTIONS]"
            echo ""
            echo "  Options:"
            echo "    --csv      Export findings to CSV alongside HTML report"
            echo "    --json     Export findings to JSON alongside HTML report"
            echo "    --all      Export both CSV and JSON"
            echo "    --help     Show this help message"
            echo ""
            echo "  Output files are saved in the same directory as the script."
            echo ""
            echo "  Examples:"
            echo "    sudo ./ZLT.sh                  # HTML report only"
            echo "    sudo ./ZLT.sh --csv            # HTML + CSV"
            echo "    sudo ./ZLT.sh --json           # HTML + JSON"
            echo "    sudo ./ZLT.sh --all            # HTML + CSV + JSON"
            echo ""
            exit 0 ;;
    esac
done

# Colors for terminal
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

# ── Counters ─────────────────────────────────────────────────────────────────
FINDINGS_CRITICAL=0
FINDINGS_HIGH=0
FINDINGS_MEDIUM=0
FINDINGS_LOW=0
FINDINGS_INFO=0

# ── Storage for findings ─────────────────────────────────────────────────────
declare -a FINDINGS_ARR=()

# ── Helpers ──────────────────────────────────────────────────────────────────
log_info()  { echo -e "${CYAN}[*]${NC} $*"; }
log_ok()    { echo -e "${GREEN}[+]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
log_crit()  { echo -e "${RED}[!!]${NC} $*"; }

html_esc() {
    local s="$*"
    s="${s//&/&amp;}"; s="${s//</&lt;}"; s="${s//>/&gt;}"
    s="${s//\"/&quot;}"; printf '%s' "$s"
}

safe_run() { "$@" 2>/dev/null || true; }

add_finding() {
    # add_finding SEVERITY MITRE_TACTIC RULE_ID TITLE DETAIL
    local sev="$1" tactic="$2" rule="$3" title="$4" detail="$5"
    case "$sev" in
        CRITICAL) ((FINDINGS_CRITICAL++)) ;;
        HIGH)     ((FINDINGS_HIGH++)) ;;
        MEDIUM)   ((FINDINGS_MEDIUM++)) ;;
        LOW)      ((FINDINGS_LOW++)) ;;
        INFO)     ((FINDINGS_INFO++)) ;;
    esac
    # Use ASCII unit separator (0x1F) as delimiter - never appears in text
    FINDINGS_ARR+=("${sev}"$'\x1f'"${tactic}"$'\x1f'"${rule}"$'\x1f'"${title}"$'\x1f'"${detail}")
}

section_output() {
    # Collect command output safely, truncate if huge
    local out
    out=$(safe_run "$@" | head -200 | sed 's/[[:cntrl:]]//g') || true
    printf '%s' "$out"
}

# ── Check root ───────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    log_warn "Not running as root. Some modules will have limited output."
    IS_ROOT=0
else
    IS_ROOT=1
fi

echo -e "${BOLD}${GREEN}"
cat << 'BANNER'
  ______                 _   _____           
 |___  /                | | / ____|          
    / /  __ ___   ____ _| || (___   ___  ___ 
   / /  / _` \ \ / / _ \| __\___ \ / _ \/ __|
  / /__| (_| |\ V /  __/| |_ ____) |  __/ (__ 
 /_____|\__,_| \_/ \___| \__|_____/ \___|\___|
                                                
 ZLT v1.1 | ZavetSec Linux Triage | DFIR Telemetry + Detection
BANNER
echo -e "${NC}"

log_info "Target: ${HOSTNAME_VAL}"
log_info "Start:  ${START_TS}"
log_info "Output: ${REPORT_FILE}"
[[ "$EXPORT_CSV"  -eq 1 ]] && log_info "Export: ${REPORT_BASE}.csv"
[[ "$EXPORT_JSON" -eq 1 ]] && log_info "Export: ${REPORT_BASE}.json"
echo ""

# =============================================================================
# MODULE 1: System Info
# =============================================================================
log_info "Module 1/12: System Information"
M_SYSINFO=""
M_SYSINFO+="<tr><td>Hostname</td><td>$(html_esc "$HOSTNAME_VAL")</td></tr>"
M_SYSINFO+="<tr><td>OS</td><td>$(html_esc "$(safe_run cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2 | tr -d '"')")</td></tr>"
M_SYSINFO+="<tr><td>Kernel</td><td>$(html_esc "$(uname -r)")</td></tr>"
M_SYSINFO+="<tr><td>Architecture</td><td>$(html_esc "$(uname -m)")</td></tr>"
M_SYSINFO+="<tr><td>Uptime</td><td>$(html_esc "$(safe_run uptime -p)")</td></tr>"
M_SYSINFO+="<tr><td>Date/Time (UTC)</td><td>$(html_esc "$(date -u)")</td></tr>"
M_SYSINFO+="<tr><td>Timezone</td><td>$(html_esc "$(safe_run cat /etc/timezone || timedatectl | grep 'Time zone' | awk '{print $3}')")</td></tr>"
M_SYSINFO+="<tr><td>Root access</td><td>$([ "$IS_ROOT" -eq 1 ] && echo 'Yes' || echo 'No (limited)')</td></tr>"

# Detection: kernel version check (old kernels)
KERNEL_VER=$(uname -r | grep -oE '^[0-9]+\.[0-9]+' || echo "0.0")
KERNEL_MAJOR=$(echo "$KERNEL_VER" | cut -d. -f1)
KERNEL_MINOR=$(echo "$KERNEL_VER" | cut -d. -f2)
if [[ "$KERNEL_MAJOR" -lt 4 ]] || [[ "$KERNEL_MAJOR" -eq 4 && "$KERNEL_MINOR" -lt 15 ]]; then
    add_finding "MEDIUM" "Initial Access" "SYS-001" "Outdated Linux kernel" \
        "Kernel $(uname -r) may contain known vulnerabilities. Upgrade recommended."
fi

# =============================================================================
# MODULE 2: Users & Accounts
# =============================================================================
log_info "Module 2/12: Users & Accounts"

# All users with shell
M_USERS_SHELL=$(safe_run grep -v '/nologin\|/false' /etc/passwd | head -50)

# Sudoers
M_SUDOERS=$(safe_run getent group sudo wheel 2>/dev/null | tr ':' '\n' | tail -2)

# Users with UID 0
UID0_USERS=$(safe_run awk -F: '$3==0{print $1}' /etc/passwd)
M_UID0="$UID0_USERS"

# Recently modified /etc/passwd
PASSWD_MTIME=$(safe_run stat -c '%y' /etc/passwd 2>/dev/null | cut -d. -f1)

# Detections
if echo "$UID0_USERS" | grep -qv '^root$'; then
    NON_ROOT_UID0=$(echo "$UID0_USERS" | grep -v '^root$' | tr '\n' ' ')
    add_finding "CRITICAL" "Privilege Escalation" "USR-001" \
        "Users with UID 0 other than root" \
        "Accounts with UID=0 detected: ${NON_ROOT_UID0}. Possible backdoor account creation."
fi

# Check for new users (created/modified in last 7 days via shadow mtime)
if [[ "$IS_ROOT" -eq 1 ]]; then
    SHADOW_MTIME_DAYS=$(safe_run find /etc/shadow -mtime -7 2>/dev/null | wc -l)
    if [[ "$SHADOW_MTIME_DAYS" -gt 0 ]]; then
        add_finding "MEDIUM" "Persistence" "USR-002" \
            "/etc/shadow modified within the last 7 days" \
            "/etc/shadow was modified recently. Possible account addition or password change."
    fi
fi

# Check for empty/locked password hash — only for interactive users (real shell)
# Service accounts legitimately have !! (locked). Cross-reference with /etc/passwd shell.
if [[ "$IS_ROOT" -eq 1 ]]; then
    # Get interactive users: those with a real shell (not nologin/false/sync/halt/shutdown)
    INTERACTIVE_USERS=$(safe_run awk -F: '$7 !~ /(nologin|false|sync|halt|shutdown|git-shell)$/ {print $1}' /etc/passwd 2>/dev/null)
    # Find users with truly empty password (not locked !! which is normal for service accounts)
    EMPTY_PASS=""
    while IFS= read -r usr; do
        [[ -z "$usr" ]] && continue
        shadow_hash=$(safe_run awk -F: -v u="$usr" '$1==u{print $2}' /etc/shadow 2>/dev/null || echo "")
        if [[ "$shadow_hash" == "" ]]; then
            # Truly empty password — any account, this is critical
            EMPTY_PASS="${EMPTY_PASS}${usr}(empty) "
        fi
    done <<< "$INTERACTIVE_USERS"
    if [[ -n "$EMPTY_PASS" ]]; then
        add_finding "HIGH" "Initial Access" "USR-003" \
            "Interactive accounts with empty password (empty hash)" \
            "Users: ${EMPTY_PASS}"
    fi
fi

# =============================================================================
# MODULE 3: Network Connections
# =============================================================================
log_info "Module 3/12: Network Connections"

M_NETSTAT=$(safe_run ss -tulnp 2>/dev/null || netstat -tulnp 2>/dev/null || echo "N/A")
M_ESTABLISHED=$(safe_run ss -tnp state established 2>/dev/null || netstat -tnp 2>/dev/null | grep ESTABLISHED || echo "N/A")
M_INTERFACES=$(safe_run ip addr 2>/dev/null || ifconfig 2>/dev/null || echo "N/A")
M_ROUTES=$(safe_run ip route 2>/dev/null || route -n 2>/dev/null || echo "N/A")

# Detection: listening on all interfaces (0.0.0.0)
# Exclude: loopback addresses including 127.0.0.x%iface variants (systemd-resolved)
WIDE_OPEN=$(echo "$M_NETSTAT" | grep '0\.0\.0\.0:' | \
    grep -v '127\.0\.0\.' | grep -v '::1' || true)
if [[ -n "$WIDE_OPEN" ]]; then
    PORTS_LIST=$(echo "$WIDE_OPEN" | awk '{print $5}' | tr '\n' ' ' | head -c 300)
    add_finding "LOW" "Discovery" "NET-001" \
        "Services listening on all interfaces (0.0.0.0)" \
        "Ports: ${PORTS_LIST}"
fi

# Detection: unusual high ports listening
# Exclude known desktop service ports: KDE Connect (1716), mDNS (5353), NTP (123),
# Avahi (5353), and common ephemeral KDE/GNOME service ports
HIGH_PORTS=$(echo "$M_NETSTAT" | grep -E ':([4-9][0-9]{4}|[1-9][0-9]{4})' | grep '0\.0\.0\.0\|:::' | \
    grep -vE ':(5353|1716|4713|32000|32768|49152)' | \
    grep -viE 'kdeconnect|avahi|mdns|pulseaudio|systemd-timesyn|timesyncd' || true)
if [[ -n "$HIGH_PORTS" ]]; then
    add_finding "MEDIUM" "Command and Control" "NET-002" \
        "Listening services on non-standard high ports (>40000)" \
        "$(echo "$HIGH_PORTS" | head -10 | tr '\n' '; ')"
fi

# Detection: established connections to non-local IPs
# Skip the ss header line (starts with Recv-Q)
EXTERNAL_CONNS=$(echo "$M_ESTABLISHED" | grep -v '^Recv-Q\|^State' | grep -vE '127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.' | grep -vE '::(1|[0-9a-f]{1,4}:)' | grep -v '^$' | head -20 || true)
if [[ -n "$EXTERNAL_CONNS" ]]; then
    add_finding "INFO" "Command and Control" "NET-003" \
        "Active connections to external IP addresses" \
        "$(echo "$EXTERNAL_CONNS" | head -5 | tr '\n' '; ')"
fi

# =============================================================================
# MODULE 4: Running Processes
# =============================================================================
log_info "Module 4/12: Running Processes"

M_PROCESSES=$(safe_run ps auxf 2>/dev/null | head -100)
M_PROC_TREE=$(safe_run pstree -p 2>/dev/null | head -80 || echo "pstree not available")

# Detection: processes running from /tmp, /dev/shm, /run
SUSPICIOUS_PATHS=$(safe_run ps aux 2>/dev/null | awk '$11 ~ /\/(tmp|dev\/shm|run|var\/tmp)/ {print $0}' | grep -v grep || true)
if [[ -n "$SUSPICIOUS_PATHS" ]]; then
    add_finding "HIGH" "Execution" "PROC-001" \
        "Processes running from suspicious directories (/tmp, /dev/shm, /run, /var/tmp)" \
        "$(echo "$SUSPICIOUS_PATHS" | head -10 | tr '\n' '; ')"
fi

# Detection: processes with deleted binary
if [[ "$IS_ROOT" -eq 1 ]] || [[ -r /proc ]]; then
    DELETED_BIN=$(safe_run ls -la /proc/*/exe 2>/dev/null | grep '(deleted)' | head -10 || true)
    if [[ -n "$DELETED_BIN" ]]; then
        add_finding "HIGH" "Defense Evasion" "PROC-002" \
            "Processes with deleted executable files" \
            "A running process whose exe has been removed from disk — classic malware indicator: $(echo "$DELETED_BIN" | head -3 | tr '\n' '; ')"
    fi
fi

# Detection: crypto miners (process names)
MINER_PROCS=$(safe_run ps aux 2>/dev/null | grep -iE 'xmrig|minerd|cpuminer|ethminer|t-rex|lolminer|nbminer' | grep -v grep || true)
if [[ -n "$MINER_PROCS" ]]; then
    add_finding "CRITICAL" "Impact" "PROC-003" \
        "Cryptominer process detected" \
        "$(echo "$MINER_PROCS" | head -5 | tr '\n' '; ')"
fi

# Detection: high CPU single process
HIGH_CPU=$(safe_run ps aux --sort=-%cpu 2>/dev/null | awk 'NR>1 && $3>80 {print $0}' | head -5 || true)
if [[ -n "$HIGH_CPU" ]]; then
    add_finding "MEDIUM" "Impact" "PROC-004" \
        "Process with abnormally high CPU usage (>80%)" \
        "$(echo "$HIGH_CPU" | head -3 | tr '\n' '; ')"
fi

# =============================================================================
# PROC-005: Processes whose binary is NOT owned by any installed package
# Catches: manually dropped binaries, compiled implants, Go/Rust backdoors,
#          fileless-ish malware written to /opt /srv /var/lib without packaging
# Logic: resolve /proc/PID/exe → check dpkg -S or rpm -qf → flag if unowned
# Skips: kernel threads, interpreters with script args, /tmp /dev/shm (PROC-001),
#        home directories, known safe unpackaged paths
# =============================================================================
log_info "PROC-005: checking processes vs package database..."
M_UNPACKAGED_PROCS=""
_UNPACK_TMP="/tmp/_zavetsec_unpack_$$"
_UNPACK_RESULTS="/tmp/_zavetsec_results_$$"
> "$_UNPACK_RESULTS"

if command -v dpkg &>/dev/null || command -v rpm &>/dev/null; then

    # Step 1: collect unique real exe paths from /proc — only standard system dirs
    # Exclude: kernel threads, /tmp /dev/shm /home /run (other rules cover those),
    #          and paths clearly belonging to containers/snaps/flatpaks
    safe_run ls /proc/*/exe 2>/dev/null | head -300 | while read -r exelink; do
        rp=$(safe_run readlink -f "$exelink" 2>/dev/null || true)
        [[ -z "$rp" ]] && continue
        # Skip kernel threads and pseudo-paths
        echo "$rp"
    done 2>/dev/null | \
        grep -vE '^\[|^\s*$|\(deleted\)' | \
        grep -E '^/(usr|bin|sbin|opt|srv|app|var/lib|var/opt|usr/local)' | \
        grep -vE '^/(usr/lib/(snapd|flatpak)|opt/(snap|homebrew))' | \
        grep -vE '/(fusermount3?|mount\.fuse|snap|flatpak-spawn|bwrap)$' | \
        sort -u > "$_UNPACK_TMP" 2>/dev/null || true

    # Step 2: for each unique binary, check package ownership
    if [[ -s "$_UNPACK_TMP" ]]; then
        while IFS= read -r binpath; do
            [[ -z "$binpath" ]] && continue
            [[ ! -f "$binpath" ]] && continue   # skip if file disappeared

            owned=0

            # dpkg check (Debian/Ubuntu/Kali)
            if command -v dpkg &>/dev/null; then
                if dpkg -S "$binpath" &>/dev/null 2>&1; then
                    owned=1
                fi
            fi

            # rpm check (RHEL/CentOS/Fedora) — only if dpkg didn't find it
            if [[ "$owned" -eq 0 ]] && command -v rpm &>/dev/null; then
                if rpm -qf "$binpath" &>/dev/null 2>&1; then
                    owned=1
                fi
            fi

            # If not owned by any package — find which PIDs are running it
            if [[ "$owned" -eq 0 ]]; then
                # Collect PID/name info
                proc_info=""
                for exelink in /proc/*/exe; do
                    [[ ! -L "$exelink" ]] && continue
                    rp2=$(safe_run readlink -f "$exelink" 2>/dev/null || true)
                    if [[ "$rp2" == "$binpath" ]]; then
                        pid=$(echo "$exelink" | grep -oE '[0-9]+')
                        name=$(safe_run cat "/proc/${pid}/comm" 2>/dev/null | tr -d '\n' || echo "?")
                        user=$(safe_run stat -c '%U' "/proc/${pid}" 2>/dev/null || echo "?")
                        proc_info="${proc_info}PID=${pid}(${name},user=${user}) "
                    fi
                done 2>/dev/null
                [[ -z "$proc_info" ]] && proc_info="(no running PIDs found)"
                echo "${binpath} | ${proc_info}" >> "$_UNPACK_RESULTS"
            fi

        done < "$_UNPACK_TMP"
    fi

    rm -f "$_UNPACK_TMP" 2>/dev/null

    # Step 3: report findings
    if [[ -s "$_UNPACK_RESULTS" ]]; then
        M_UNPACKAGED_PROCS=$(cat "$_UNPACK_RESULTS")
        UNPACKAGED_COUNT=$(wc -l < "$_UNPACK_RESULTS")
        UNPACKAGED_SNIPPET=$(head -5 "$_UNPACK_RESULTS" | tr '\n' '; ')
        add_finding "HIGH" "Defense Evasion" "PROC-005" \
            "Processes with binaries not owned by any package — possible implant/malware (${UNPACKAGED_COUNT} found)" \
            "${UNPACKAGED_SNIPPET}"
    else
        M_UNPACKAGED_PROCS="All running binaries are owned by installed packages"
    fi

    rm -f "$_UNPACK_RESULTS" 2>/dev/null

else
    M_UNPACKAGED_PROCS="(dpkg/rpm not available — check skipped)"
    rm -f "$_UNPACK_RESULTS" 2>/dev/null
fi

# =============================================================================
# MODULE 5: Persistence Mechanisms
# =============================================================================
log_info "Module 5/12: Persistence Mechanisms"

# Cron jobs
M_CRONTAB_ROOT=$(safe_run crontab -l 2>/dev/null || echo "(empty)")
M_CRON_ETC=$(safe_run ls -la /etc/cron* /var/spool/cron* 2>/dev/null | head -40 || echo "N/A")
M_CRON_CONTENT=$(safe_run find /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /var/spool/cron -type f 2>/dev/null | head -20 | while read -r f; do echo "=== $f ==="; cat "$f" 2>/dev/null; done)

# Systemd units
M_SYSTEMD_UNITS=$(safe_run systemctl list-units --type=service --state=running 2>/dev/null | head -60 || echo "N/A")
M_SYSTEMD_ENABLED=$(safe_run systemctl list-unit-files --state=enabled 2>/dev/null | head -60 || echo "N/A")

# ~/.bashrc, ~/.bash_profile, /etc/profile.d
M_PROFILE_D=$(safe_run ls -la /etc/profile.d/ 2>/dev/null | head -20)
M_BASHRC=$(safe_run cat /root/.bashrc 2>/dev/null | head -30 || echo "N/A")

# SSH authorized_keys
M_SSH_KEYS=$(safe_run find /root /home -name 'authorized_keys' -exec ls -la {} \; 2>/dev/null | head -20 || echo "N/A")

# Detection: cron entries with base64/curl/wget/nc
SUSP_CRON=$(safe_run grep -r 'base64\|curl\|wget\|nc \|bash -i\|/dev/tcp\|python.*socket' /etc/cron* /var/spool/cron 2>/dev/null | head -10 || true)
if [[ -n "$SUSP_CRON" ]]; then
    add_finding "CRITICAL" "Persistence" "PERS-001" \
        "Suspicious commands in cron (base64/curl/wget/nc/reverse shell)" \
        "$(echo "$SUSP_CRON" | head -5 | tr '\n' '; ')"
fi

# Detection: recently modified systemd units (last 7 days)
RECENT_UNITS=$(safe_run find /etc/systemd /lib/systemd /usr/lib/systemd -name '*.service' -mtime -7 2>/dev/null | head -10 || true)
if [[ -n "$RECENT_UNITS" ]]; then
    add_finding "MEDIUM" "Persistence" "PERS-002" \
        "Systemd unit files modified within the last 7 days" \
        "$(echo "$RECENT_UNITS" | tr '\n' '; ')"
fi

# Detection: SSH authorized_keys in unexpected locations
UNEXP_SSH=$(safe_run find /tmp /var/tmp /dev/shm -name 'authorized_keys' 2>/dev/null | head -5 || true)
if [[ -n "$UNEXP_SSH" ]]; then
    add_finding "CRITICAL" "Persistence" "PERS-003" \
        "authorized_keys found in non-standard location (/tmp, /var/tmp, /dev/shm)" \
        "$(echo "$UNEXP_SSH" | tr '\n' '; ')"
fi

# Detection: .bashrc/.profile with suspicious content
# Require actual execution indicators, not just tool names in aliases or config
# Patterns: piping to shell, /dev/tcp reverse shells, base64-encoded payloads, bash -i
SUSP_RC=$(safe_run grep -rE \
    'curl[^|]*\|[[:space:]]*(bash|sh)|wget[^|]*\|[[:space:]]*(bash|sh)|base64[[:space:]]+(-d|-D|--decode)|/dev/tcp/|bash[[:space:]]+-i|exec[[:space:]]+[0-9]+<>' \
    /root/.bashrc /root/.bash_profile /etc/profile.d/ /home/*/.bashrc /home/*/.bash_profile 2>/dev/null | \
    grep -v '^[[:space:]]*#' | head -10 || true)
if [[ -n "$SUSP_RC" ]]; then
    add_finding "HIGH" "Persistence" "PERS-004" \
        "Suspicious code in .bashrc/.profile (possible backdoor)" \
        "$(echo "$SUSP_RC" | head -5 | tr '\n' '; ')"
fi

# =============================================================================
# MODULE 6: File System Anomalies
# =============================================================================
log_info "Module 6/12: File System Anomalies"

# SUID/SGID binaries
M_SUID=$(safe_run find / -perm -4000 -type f 2>/dev/null | head -50)
M_SGID=$(safe_run find / -perm -2000 -type f 2>/dev/null | head -30)

# World-writable directories
M_WORLD_WRITE=$(safe_run find / -xdev -type d -perm -0002 2>/dev/null | grep -v '/proc\|/sys\|/dev' | head -30)

# Recently modified files (last 24h) — only actual executables, not configs
# Exclude /etc entirely (resolv.conf, NetworkManager updates are normal)
M_RECENT_FILES=$(safe_run find /usr/bin /usr/sbin /bin /sbin /usr/lib/x86_64-linux-gnu /usr/lib64 \
    -mtime -1 -type f -perm /111 2>/dev/null | \
    grep -vE '\.(py|rb|pl|sh|conf|cfg|log)$' | head -30 || echo "N/A")

# Files in /tmp /dev/shm
M_TMP_FILES=$(safe_run ls -laR /tmp /dev/shm /var/tmp 2>/dev/null | head -60)

# Detection: non-standard SUID binaries
# Base whitelist — standard on most Linux distros
KNOWN_SUID="ping|sudo|su|passwd|newgrp|chfn|chsh|gpasswd|mount|umount|fusermount|fusermount3|at|newuidmap|newgidmap|pkexec|Xorg|Xorg\.wrap|ssh-keysign|pppd|traceroute6|ntfs-3g|mount\.cifs|mount\.nfs|rsh|rlogin|dbus-daemon-launch-helper|polkit-agent-helper-1|chrome-sandbox|auth_pam_tool"

# Detect if running on Kali/Parrot/offensive distro — extend whitelist with known pentool SUIDs
OS_ID=$(safe_run grep '^ID=' /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"' || echo "unknown")
OS_ID_LIKE=$(safe_run grep '^ID_LIKE=' /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"' || echo "")
if echo "$OS_ID $OS_ID_LIKE" | grep -qiE 'kali|parrot|blackarch|pentoo'; then
    # On offensive security distros these are expected:
    # kismet capture helpers, chrome-sandbox, polkit-agent, dbus-daemon-launch-helper, mysql auth_pam
    KNOWN_SUID="${KNOWN_SUID}|kismet_cap|chrome-sandbox|polkit-agent-helper|dbus-daemon-launch-helper|auth_pam_tool|Xorg\.wrap|polkit-agent|vmware-user-suid-wrapper"
    SUID_DISTRO_NOTE=" (distro: ${OS_ID} — kismet/chrome/polkit/vmware excluded as expected)"
else
    SUID_DISTRO_NOTE=""
fi

# Match whitelist against basename of each SUID path
UNKNOWN_SUID=$(echo "$M_SUID" | while IFS= read -r suid_path; do
    bn=$(basename "$suid_path" 2>/dev/null)
    if ! echo "$bn" | grep -qE "^($KNOWN_SUID)$" && ! echo "$suid_path" | grep -qE "($KNOWN_SUID)"; then
        echo "$suid_path"
    fi
done | head -20 || true)
if [[ -n "$UNKNOWN_SUID" ]]; then
    add_finding "HIGH" "Privilege Escalation" "FS-001" \
        "Non-standard SUID binaries${SUID_DISTRO_NOTE}" \
        "$(echo "$UNKNOWN_SUID" | head -10 | tr '\n' '; ')"
fi

# Detection: executables in /tmp /dev/shm
EXEC_IN_TMP=$(safe_run find /tmp /dev/shm /var/tmp -type f -perm /111 2>/dev/null | head -10 || true)
if [[ -n "$EXEC_IN_TMP" ]]; then
    add_finding "HIGH" "Execution" "FS-002" \
        "Executable files found in /tmp, /dev/shm, /var/tmp" \
        "$(echo "$EXEC_IN_TMP" | head -10 | tr '\n' '; ')"
fi

# Detection: recently modified system binaries (executables only, not configs)
if [[ -n "$M_RECENT_FILES" && "$M_RECENT_FILES" != "N/A" ]]; then
    add_finding "MEDIUM" "Defense Evasion" "FS-003" \
        "System binaries modified within the last 24 hours" \
        "$(echo "$M_RECENT_FILES" | head -10 | tr '\n' '; ')"
fi

# Detection: suspicious hidden files — extended exclusions for known-benign runtime files
# Excludes: X11 locks/sockets, VBox PIDs, browser locks, standard dotfiles, ZLT reports
HIDDEN_SUSP=$(safe_run find /tmp /root /home -name '.*' -type f 2>/dev/null | \
    grep -vE '\.(bash|zsh|profile|ssh|gnupg|cache|config|local|face|zshrc|zprofile|vimrc|Xauthority|ICEauthority|xsession-errors|xfce|mozilla|thunderbird|lesshst|recently-used|dmrc|gtkrc|xinputrc)' | \
    grep -vE '(\.X[0-9]+-lock|\.xfsm-ICE-|\.X[0-9]+\.|\.ICE-unix|\.xsession-errors|vboxclient.*\.pid|parentlock|metadata-v2|remote-settings)' | \
    grep -vE '(node_modules|\.npm|\.gem|\.cargo|\.rustup|\.go|\.m2|\.gradle|eslint|prettier|npmrc|yarnrc)' | \
    grep -vE '(sudo_as_admin_successful|bash_logout|hushlogin|forward|rhosts|netrc|wgetrc|curlrc|inputrc|screenrc|tmux|byobu|pam_environment|wget-hsts|python_history|lesshst|dbshell|rediscli_history|psql_history|mysql_history|sqlite_history)' | \
    grep -vE '(\.emacs|\.emacs\.d|\.nanorc|\.viminfo|\.selected_editor|\.last-updated|\.bash_logout|\.dir_colors|\.gitconfig|\.gitignore)' | \
    grep -vE '(plasma|kde|dolphin|konsole|kwin|krunner|kderc|kdeglobals|baloofilerc|startkde|kio|baloo)' | \
    grep -vE '(/snap/|\.last_revision|\.snapshots|snapd|\.gnome|\.gtk|\.dbus|\.local/share/recently|\.local/share/gnome)' | \
    grep -vE '(\.ICEauthority|\.Xauthority|\.xsession|\.fonts|\.icons|\.themes|\.compiz|\.gconf|\.pulse|\.config/pulse)' | \
    grep -vE 'ZLT' | \
    head -20 || true)
if [[ -n "$HIDDEN_SUSP" ]]; then
    add_finding "MEDIUM" "Defense Evasion" "FS-004" \
        "Suspicious hidden files in /tmp, /root, /home" \
        "$(echo "$HIDDEN_SUSP" | head -10 | tr '\n' '; ')"
fi

# =============================================================================
# MODULE 7: Log Analysis
# =============================================================================
log_info "Module 7/12: Log Analysis"

# Auth log — try file first, fall back to journald
M_AUTH_TAIL=""
M_AUTH_SOURCE="none"
for logf in /var/log/auth.log /var/log/secure; do
    if [[ -r "$logf" ]]; then
        M_AUTH_TAIL=$(safe_run tail -100 "$logf")
        M_AUTH_SOURCE="$logf"
        break
    fi
done
# Fallback: journald
# NOTE: sudo/su/sshd write to journald via _COMM= facility, not as systemd units.
# Combine multiple journalctl queries: ssh unit + _COMM filters for pam/sudo/su/sshd
if [[ -z "$M_AUTH_TAIL" ]] && command -v journalctl &>/dev/null; then
    JCT_SSH=$(safe_run journalctl -u ssh -u sshd --no-pager -n 100 --output=short 2>/dev/null || true)
    JCT_AUTH=$(safe_run journalctl _COMM=sudo _COMM=su _COMM=sshd _COMM=login _COMM=passwd \
        --no-pager -n 100 --output=short 2>/dev/null || true)
    JCT_PAM=$(safe_run journalctl SYSLOG_FACILITY=10 --no-pager -n 100 --output=short 2>/dev/null || true)
    # Combine and deduplicate by timestamp
    M_AUTH_TAIL=$(printf '%s\n%s\n%s\n' "$JCT_SSH" "$JCT_AUTH" "$JCT_PAM" | \
        grep -v '^-- ' | sort -u | tail -100 || true)
    M_AUTH_SOURCE="journald (_COMM=sudo/su/sshd/login + FACILITY=auth)"
fi
[[ -z "$M_AUTH_TAIL" ]] && M_AUTH_TAIL="(not readable — no auth.log found and journald unavailable)"

# Failed logins
FAILED_LOGINS=$(echo "$M_AUTH_TAIL" | grep -i 'failed\|invalid\|authentication failure\|Failed password\|Invalid user' | tail -20 || true)

# Successful logins
SUCCESS_LOGINS=$(echo "$M_AUTH_TAIL" | grep -i 'accepted\|session opened\|Accepted password\|Accepted publickey' | tail -20 || true)

# Syslog — try file, fall back to journald
M_SYSLOG=""
for logf in /var/log/syslog /var/log/messages; do
    if [[ -r "$logf" ]]; then
        M_SYSLOG=$(safe_run tail -100 "$logf" | head -100)
        break
    fi
done
if [[ -z "$M_SYSLOG" ]] && command -v journalctl &>/dev/null; then
    M_SYSLOG=$(safe_run journalctl --no-pager -n 100 --output=short 2>/dev/null | head -100 || true)
fi
[[ -z "$M_SYSLOG" ]] && M_SYSLOG="N/A"

# Last logins from wtmp
M_LAST_LOGINS=$(safe_run last -n 30 2>/dev/null | head -30 || echo "N/A")

# Detection: brute force (>20 failed attempts)
BRUTE_COUNT=$(echo "$FAILED_LOGINS" | grep -c '.' || echo "0")
if [[ "$BRUTE_COUNT" -gt 20 ]]; then
    TOP_ATTACKER=$(echo "$FAILED_LOGINS" | grep -oE 'from [0-9.]+' | sort | uniq -c | sort -rn | head -3 | tr '\n' '; ' || true)
    add_finding "HIGH" "Credential Access" "LOG-001" \
        "Possible SSH brute-force (>20 failed attempts, source: ${M_AUTH_SOURCE})" \
        "Failed attempts: ${BRUTE_COUNT}. Top sources: ${TOP_ATTACKER}"
fi

# Detection: root login via SSH — must be sshd Accepted, not sudo/CRON
# Exclude: CRON sessions, sudo sessions, lightdm, pam session opened without sshd context
ROOT_SSH=$(echo "$M_AUTH_TAIL" | grep -iE 'sshd.*Accepted.*root|Accepted (password|publickey).*root' | head -5 || true)
if [[ -n "$ROOT_SSH" ]]; then
    add_finding "HIGH" "Initial Access" "LOG-002" \
        "Direct root SSH login detected (sshd Accepted, source: ${M_AUTH_SOURCE})" \
        "$(echo "$ROOT_SSH" | head -3 | tr '\n' '; ')"
fi

# Detection: su/sudo to root
SUDO_ROOT=$(echo "$M_AUTH_TAIL" | grep -iE 'sudo.*root|su.*root' | tail -10 || true)
if [[ -n "$SUDO_ROOT" ]]; then
    add_finding "INFO" "Privilege Escalation" "LOG-003" \
        "sudo/su used to obtain root privileges" \
        "$(echo "$SUDO_ROOT" | head -5 | tr '\n' '; ')"
fi

# =============================================================================
# MODULE 8: Network Config & Firewall
# =============================================================================
log_info "Module 8/12: Network Config & Firewall"

M_IPTABLES=$(safe_run iptables -L -n 2>/dev/null | head -60 || safe_run nft list ruleset 2>/dev/null | head -60 || echo "N/A (no iptables/nft access)")
M_UFW=$(safe_run ufw status verbose 2>/dev/null | head -30 || echo "UFW not installed")
M_HOSTS=$(safe_run cat /etc/hosts 2>/dev/null | head -30)
M_RESOLV=$(safe_run cat /etc/resolv.conf 2>/dev/null | head -20)
M_ARP=$(safe_run arp -a 2>/dev/null || ip neigh 2>/dev/null | head -30 || echo "N/A")

# Detection: /etc/hosts hijacking
# Exclude: standard loopback (127./::1/ff), standard IPv6 multicast/anycast defaults
# fe00::0 ip6-localnet, ff02::1 ip6-allnodes etc. are in Ubuntu's default /etc/hosts template
HOSTS_SUSP=$(safe_run grep -v '^#\|^$\|^127\.\|^::1\|^ff\|^fe00::0\|^fe80::' /etc/hosts 2>/dev/null | head -20 || true)
if [[ -n "$HOSTS_SUSP" ]]; then
    add_finding "MEDIUM" "Defense Evasion" "NET-004" \
        "Non-standard entries in /etc/hosts (possible DNS hijacking)" \
        "$(echo "$HOSTS_SUSP" | tr '\n' '; ')"
fi

# Detection: DNS pointing to non-standard servers
RESOLV_NS=$(grep '^nameserver' /etc/resolv.conf 2>/dev/null | awk '{print $2}' | tr '\n' ' ' || true)
if echo "$RESOLV_NS" | grep -vqE '8\.8\.8\.8|8\.8\.4\.4|1\.1\.1\.1|1\.0\.0\.1|9\.9\.9\.9|149\.112\.|208\.67\.|77\.88\.|64\.6\.|4\.2\.2\.|127\.|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.'; then
    add_finding "MEDIUM" "Command and Control" "NET-005" \
        "Non-standard DNS server in resolv.conf" \
        "Nameservers: ${RESOLV_NS}"
fi

# =============================================================================
# MODULE 9: Installed Software & Packages
# =============================================================================
log_info "Module 9/12: Installed Packages"

if command -v dpkg &>/dev/null; then
    M_PACKAGES=$(safe_run dpkg -l 2>/dev/null | grep '^ii' | awk '{print $2, $3}' | head -100)
    PKG_MGR="dpkg/apt"
elif command -v rpm &>/dev/null; then
    M_PACKAGES=$(safe_run rpm -qa --queryformat '%{NAME} %{VERSION}\n' 2>/dev/null | head -100)
    PKG_MGR="rpm/yum"
else
    M_PACKAGES="Package manager not found"
    PKG_MGR="unknown"
fi

# Detection: hacking tools installed
HACK_TOOLS=$(echo "$M_PACKAGES" | grep -iE 'nmap|masscan|metasploit|hydra|john|hashcat|sqlmap|nikto|aircrack|reaver|ettercap|bettercap|msfconsole' | head -10 || true)
if [[ -n "$HACK_TOOLS" ]]; then
    add_finding "HIGH" "Execution" "PKG-001" \
        "Offensive security / penetration testing tools installed" \
        "$(echo "$HACK_TOOLS" | tr '\n' '; ')"
fi

# Recently installed packages (last 7 days)
RECENT_PKG=""
if [[ -r /var/log/dpkg.log ]]; then
    RECENT_PKG=$(safe_run grep 'install\|upgrade' /var/log/dpkg.log | tail -30)
elif [[ -r /var/log/rpm/history.log ]]; then
    RECENT_PKG=$(safe_run tail -30 /var/log/rpm/history.log)
fi
M_RECENT_PKG="${RECENT_PKG:-N/A}"

# =============================================================================
# MODULE 10: Kernel Modules
# =============================================================================
log_info "Module 10/12: Kernel Modules"

M_LSMOD=$(safe_run lsmod 2>/dev/null | head -60 || echo "N/A")

# Detection: suspicious kernel modules (rootkit indicators)
SUSP_MODS=$(safe_run lsmod 2>/dev/null | awk '{print $1}' | grep -iE 'hide|rootkit|rkit|suterusu|diamorphine|azazel|reptile' || true)
if [[ -n "$SUSP_MODS" ]]; then
    add_finding "CRITICAL" "Defense Evasion" "KRN-001" \
        "Suspicious kernel modules detected (possible rootkit indicators)" \
        "$(echo "$SUSP_MODS" | tr '\n' ' ')"
fi

# Detection: modules not in standard locations
if [[ "$IS_ROOT" -eq 1 ]]; then
    NONSTAND_MODS=$(safe_run find /lib/modules /usr/lib/modules -name '*.ko' -newer /lib/modules/$(uname -r)/modules.dep 2>/dev/null | head -10 || true)
    if [[ -n "$NONSTAND_MODS" ]]; then
        add_finding "MEDIUM" "Defense Evasion" "KRN-002" \
            "Kernel modules newer than current kernel modules.dep (possibly injected)" \
            "$(echo "$NONSTAND_MODS" | head -5 | tr '\n' '; ')"
    fi
fi

# =============================================================================
# MODULE 11: Environment & Shell History
# =============================================================================
log_info "Module 11/12: Environment & Shell History"

M_ENV=$(safe_run env 2>/dev/null | grep -v 'LS_COLORS\|LESS_TERMCAP' | head -40 || echo "N/A")

# Detect which shell root uses
ROOT_SHELL=$(safe_run getent passwd root | cut -d: -f7 || echo "")
ROOT_SHELL_NAME=$(basename "$ROOT_SHELL" 2>/dev/null || echo "bash")

# Collect root history depending on shell
M_BASH_HISTORY_ROOT=""
ROOT_HIST_FILE=""
case "$ROOT_SHELL_NAME" in
    zsh)
        ROOT_HIST_FILE="/root/.zsh_history"
        M_BASH_HISTORY_ROOT=$(safe_run tail -50 /root/.zsh_history 2>/dev/null | strings | tail -50 || echo "N/A")
        ;;
    fish)
        ROOT_HIST_FILE="/root/.local/share/fish/fish_history"
        M_BASH_HISTORY_ROOT=$(safe_run tail -100 /root/.local/share/fish/fish_history 2>/dev/null | grep '^- cmd:' | tail -50 || echo "N/A")
        ;;
    *)
        ROOT_HIST_FILE="/root/.bash_history"
        M_BASH_HISTORY_ROOT=$(safe_run tail -50 /root/.bash_history 2>/dev/null || echo "N/A")
        ;;
esac
[[ -z "$M_BASH_HISTORY_ROOT" ]] && M_BASH_HISTORY_ROOT="(empty or unreadable: ${ROOT_HIST_FILE})"

# Collect user histories (bash + zsh + fish)
M_BASH_HISTORY_USERS=$(
    safe_run find /home -maxdepth 3 \( -name '.bash_history' -o -name '.zsh_history' \) 2>/dev/null | head -10 | \
    while read -r f; do
        echo "=== $f ==="
        if [[ "$f" == *.zsh_history ]]; then
            # zsh history may contain timestamps (:timestamp:0;cmd), strip them
            safe_run tail -20 "$f" 2>/dev/null | strings | grep -v '^: [0-9]' | head -20
        else
            safe_run tail -20 "$f" 2>/dev/null
        fi
    done
)

# Detection: suspicious history commands — check both bash and zsh
SUSP_HIST_FILES="/root/.bash_history /root/.zsh_history"
# Use strings if available (binutils), otherwise plain cat — history files are text anyway
if command -v strings &>/dev/null; then
    _HIST_READ="strings"
else
    _HIST_READ="cat"
fi
SUSP_HIST=$(safe_run cat $SUSP_HIST_FILES 2>/dev/null | $_HIST_READ | grep -iE 'base64|curl.*sh|wget.*sh|chmod.*777|nc -e|/dev/tcp|python.*socket|perl.*socket|bash -i|/tmp/.*\.(sh|py|pl|elf)|dd if=/dev/' | head -20 || true)
if [[ -n "$SUSP_HIST" ]]; then
    add_finding "HIGH" "Execution" "HIST-001" \
        "Suspicious commands found in root bash/zsh history" \
        "$(echo "$SUSP_HIST" | head -10 | tr '\n' '; ')"
fi

# Detection: history cleared / very short — check whichever file exists
ROOT_HIST_LEN=0
if [[ -f "/root/.zsh_history" ]]; then
    ROOT_HIST_LEN=$(safe_run wc -l < /root/.zsh_history 2>/dev/null || echo "0")
elif [[ -f "/root/.bash_history" ]]; then
    ROOT_HIST_LEN=$(safe_run wc -l < /root/.bash_history 2>/dev/null || echo "0")
fi
ROOT_HIST_LEN=${ROOT_HIST_LEN//[^0-9]/}
ROOT_HIST_LEN=${ROOT_HIST_LEN:-0}
if [[ "$ROOT_HIST_LEN" -lt 5 && "$IS_ROOT" -eq 1 ]]; then
    add_finding "LOW" "Defense Evasion" "HIST-002" \
        "Root command history is suspiciously short or has been cleared" \
        "Shell: ${ROOT_SHELL_NAME}, file: ${ROOT_HIST_FILE}, lines: ${ROOT_HIST_LEN}"
fi

# =============================================================================
# MODULE 12: Container / Cloud Metadata
# =============================================================================
log_info "Module 12/12: Container & Cloud Context"

M_CONTAINER=""
IS_CONTAINER=0
IS_CLOUD=0

if [[ -f /.dockerenv ]]; then
    M_CONTAINER="Running inside Docker container (/.dockerenv found)"
    IS_CONTAINER=1
    add_finding "INFO" "Discovery" "CNT-001" "Runtime environment: Docker container" "/.dockerenv file detected"
fi

# More precise container detection — check for known container runtime cgroup paths
# VirtualBox/VMware/KVM use different cgroup patterns, avoid false positives
CGROUP_CONTENT=$(safe_run cat /proc/1/cgroup 2>/dev/null || echo "")
if echo "$CGROUP_CONTENT" | grep -qE '/(docker|lxc)/[a-f0-9]{12,}'; then
    M_CONTAINER="${M_CONTAINER} (cgroup signature: docker/lxc container confirmed)"
    IS_CONTAINER=1
fi

# Detect virtualisation type (informational)
VIRT_TYPE="unknown"
if [[ -f /sys/class/dmi/id/product_name ]]; then
    DMI_PROD=$(safe_run cat /sys/class/dmi/id/product_name 2>/dev/null || echo "")
    case "$DMI_PROD" in
        *VirtualBox*)  VIRT_TYPE="VirtualBox VM" ;;
        *VMware*)      VIRT_TYPE="VMware VM" ;;
        *KVM*|*QEMU*)  VIRT_TYPE="KVM/QEMU VM" ;;
        *Hyper-V*)     VIRT_TYPE="Hyper-V VM" ;;
        *)             VIRT_TYPE="Physical or unknown ($DMI_PROD)" ;;
    esac
fi
if command -v systemd-detect-virt &>/dev/null; then
    VIRT_SYSTEMD=$(safe_run systemd-detect-virt 2>/dev/null || echo "none")
    VIRT_TYPE="${VIRT_TYPE} [systemd-detect-virt: ${VIRT_SYSTEMD}]"
fi

# Cloud metadata check (AWS/GCP/Azure)
AWS_META=$(safe_run curl -sf --connect-timeout 2 http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null || echo "")
GCP_META=$(safe_run curl -sf --connect-timeout 2 -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/id 2>/dev/null || echo "")
AZURE_META=$(safe_run curl -sf --connect-timeout 2 -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01" 2>/dev/null || echo "")

if [[ -n "$AWS_META" ]]; then
    M_CONTAINER="${M_CONTAINER}
AWS EC2 instance ID: ${AWS_META}"
    IS_CLOUD=1
    add_finding "INFO" "Discovery" "CNT-002" "Runtime environment: AWS EC2" "Instance ID: ${AWS_META}"
elif [[ -n "$GCP_META" ]]; then
    M_CONTAINER="${M_CONTAINER}
GCP instance ID: ${GCP_META}"
    IS_CLOUD=1
    add_finding "INFO" "Discovery" "CNT-003" "Runtime environment: Google Cloud" "Instance ID: ${GCP_META}"
elif [[ -n "$AZURE_META" ]]; then
    M_CONTAINER="${M_CONTAINER}
Azure instance metadata found"
    IS_CLOUD=1
    add_finding "INFO" "Discovery" "CNT-004" "Runtime environment: Azure VM" "Cloud instance metadata retrieved"
fi

if [[ -z "$M_CONTAINER" ]]; then
    M_CONTAINER="Bare metal / VM (no container runtime detected)
Virtualisation: ${VIRT_TYPE}"
else
    M_CONTAINER="${M_CONTAINER}
Virtualisation: ${VIRT_TYPE}"
fi

# =============================================================================
# BUILD HTML REPORT
# =============================================================================
log_info "Generating HTML report..."

END_TS=$(date '+%Y-%m-%d %H:%M:%S')
END_EPOCH=$(date +%s)
DURATION=$((END_EPOCH - START_EPOCH))
TOTAL_FINDINGS=$((FINDINGS_CRITICAL + FINDINGS_HIGH + FINDINGS_MEDIUM + FINDINGS_LOW + FINDINGS_INFO))

# Build findings table rows
FINDINGS_ROWS=""
for entry in "${FINDINGS_ARR[@]}"; do
    IFS=$'\x1f' read -r sev tactic rule title detail <<< "$entry"
    case "$sev" in
        CRITICAL) SEV_CLASS="sev-critical" ;;
        HIGH)     SEV_CLASS="sev-high" ;;
        MEDIUM)   SEV_CLASS="sev-medium" ;;
        LOW)      SEV_CLASS="sev-low" ;;
        *)        SEV_CLASS="sev-info" ;;
    esac
    FINDINGS_ROWS+="<tr class=\"finding-row\" data-sev=\"$(html_esc "$sev")\">
        <td><span class=\"badge ${SEV_CLASS}\">$(html_esc "$sev")</span></td>
        <td><code class=\"tag\">$(html_esc "$rule")</code></td>
        <td>$(html_esc "$title")</td>
        <td class=\"tactic-cell\">$(html_esc "$tactic")</td>
        <td class=\"detail-cell\">$(html_esc "$detail")</td>
    </tr>"
done

# Build telemetry sections helper
telem_section() {
    local id="$1" title="$2" content="$3"
    printf '<div class="telem-block" id="telem-%s"><div class="telem-header" onclick="toggleTelem(this)"><span class="telem-arrow">▶</span><span>%s</span></div><div class="telem-body"><pre class="telem-pre">%s</pre></div></div>' \
        "$id" "$(html_esc "$title")" "$(html_esc "$content")"
}

cat > "$REPORT_FILE" << HTMLEOF
<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ZLT | ${HOSTNAME_VAL}</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Rajdhani:wght@400;600;700&display=swap');

:root {
  --bg-primary:   #0a0d10;
  --bg-secondary: #0d1117;
  --bg-card:      #111720;
  --bg-code:      #0d1520;
  --accent:       #00ff88;
  --accent-dim:   #00cc6a;
  --accent-glow:  rgba(0,255,136,0.15);
  --critical:     #ff2244;
  --high:         #ff6600;
  --medium:       #ffaa00;
  --low:          #4488ff;
  --info:         #aabbcc;
  --text-main:    #c9d1d9;
  --text-dim:     #7a8694;
  --border:       #21262d;
  --font-mono:    'JetBrains Mono', 'Courier New', monospace;
  --font-ui:      'Rajdhani', 'Segoe UI', sans-serif;
}

* { box-sizing: border-box; margin: 0; padding: 0; }

body {
  background: var(--bg-primary);
  color: var(--text-main);
  font-family: var(--font-ui);
  font-size: 15px;
  min-height: 100vh;
  overflow-x: hidden;
}

body::before {
  content: '';
  position: fixed; top: 0; left: 0; right: 0; bottom: 0;
  background: repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,0,0,0.03) 2px, rgba(0,0,0,0.03) 4px);
  pointer-events: none; z-index: 0;
}

.container { max-width: 1400px; margin: 0 auto; padding: 0 24px; position: relative; z-index: 1; }

/* ── Header ── */
.header {
  background: linear-gradient(135deg, #0d1117 0%, #0a1628 50%, #0d1117 100%);
  border-bottom: 1px solid var(--border);
  padding: 32px 0 24px;
  position: relative;
  overflow: hidden;
}
.header::after {
  content: '';
  position: absolute; top: 0; left: 0; right: 0; bottom: 0;
  background: radial-gradient(ellipse at 60% 50%, var(--accent-glow) 0%, transparent 60%);
  pointer-events: none;
}
.header-inner { display: flex; align-items: center; gap: 20px; }
.logo-block { display: flex; flex-direction: column; gap: 4px; }
.logo-text {
  font-family: var(--font-mono);
  font-size: 26px; font-weight: 700;
  color: var(--accent);
  letter-spacing: 2px;
  text-shadow: 0 0 20px var(--accent), 0 0 40px rgba(0,255,136,0.3);
}
.logo-sub { font-size: 13px; color: var(--text-dim); letter-spacing: 1px; font-family: var(--font-mono); }
.header-meta { margin-left: auto; text-align: right; }
.header-meta p { font-family: var(--font-mono); font-size: 12px; color: var(--text-dim); line-height: 1.8; }
.header-meta span { color: var(--accent); }

/* ── Stat badges ── */
.stats-row {
  display: flex; gap: 12px; flex-wrap: wrap;
  padding: 20px 0;
  border-bottom: 1px solid var(--border);
}
.stat-badge {
  display: flex; flex-direction: column; align-items: center;
  padding: 12px 20px;
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 8px;
  min-width: 110px;
  position: relative;
  overflow: hidden;
  transition: transform .15s;
}
.stat-badge:hover { transform: translateY(-2px); }
.stat-badge::before {
  content: '';
  position: absolute; top: 0; left: 0; right: 0; height: 2px;
}
.stat-badge.stat-critical::before { background: var(--critical); }
.stat-badge.stat-high::before    { background: var(--high); }
.stat-badge.stat-medium::before  { background: var(--medium); }
.stat-badge.stat-low::before     { background: var(--low); }
.stat-badge.stat-info::before    { background: var(--info); }
.stat-badge.stat-total::before   { background: var(--accent); }

.stat-num {
  font-family: var(--font-mono); font-size: 28px; font-weight: 700;
  line-height: 1;
}
.stat-critical .stat-num { color: var(--critical); }
.stat-high .stat-num     { color: var(--high); }
.stat-medium .stat-num   { color: var(--medium); }
.stat-low .stat-num      { color: var(--low); }
.stat-info .stat-num     { color: var(--info); }
.stat-total .stat-num    { color: var(--accent); }

.stat-label { font-size: 11px; color: var(--text-dim); letter-spacing: 1px; margin-top: 4px; text-transform: uppercase; }

/* ── Tabs ── */
.tabs { display: flex; gap: 0; border-bottom: 1px solid var(--border); margin: 24px 0 0; }
.tab-btn {
  font-family: var(--font-ui); font-size: 14px; font-weight: 600;
  padding: 10px 22px;
  background: none; border: none; cursor: pointer;
  color: var(--text-dim);
  border-bottom: 2px solid transparent;
  transition: all .15s;
  letter-spacing: .5px;
}
.tab-btn:hover { color: var(--text-main); }
.tab-btn.active { color: var(--accent); border-bottom-color: var(--accent); }

.tab-pane { display: none; padding: 24px 0; }
.tab-pane.active { display: block; }

/* ── Findings table ── */
.filter-bar { display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 16px; align-items: center; }
.filter-btn {
  font-family: var(--font-mono); font-size: 12px; font-weight: 600;
  padding: 5px 14px;
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 4px; cursor: pointer; color: var(--text-dim);
  transition: all .15s;
}
.filter-btn:hover, .filter-btn.active { border-color: var(--accent); color: var(--accent); }
.filter-btn.fc-critical.active { border-color: var(--critical); color: var(--critical); }
.filter-btn.fc-high.active     { border-color: var(--high);     color: var(--high); }
.filter-btn.fc-medium.active   { border-color: var(--medium);   color: var(--medium); }
.filter-btn.fc-low.active      { border-color: var(--low);      color: var(--low); }

.findings-table { width: 100%; border-collapse: collapse; font-size: 13px; }
.findings-table th {
  font-family: var(--font-mono); font-size: 11px; font-weight: 600;
  color: var(--text-dim); text-transform: uppercase; letter-spacing: .8px;
  padding: 8px 12px; text-align: left;
  border-bottom: 1px solid var(--border);
  background: var(--bg-secondary);
}
.findings-table td {
  padding: 10px 12px;
  border-bottom: 1px solid rgba(33,38,45,0.6);
  vertical-align: top;
}
.finding-row:hover td { background: rgba(0,255,136,0.03); }

/* Severity badges */
.badge {
  display: inline-block;
  font-family: var(--font-mono); font-size: 10px; font-weight: 700;
  padding: 2px 8px; border-radius: 3px; letter-spacing: .5px;
}
.sev-critical { background: rgba(255,34,68,0.2);  color: var(--critical); border: 1px solid rgba(255,34,68,0.4); }
.sev-high     { background: rgba(255,102,0,0.2);  color: var(--high);     border: 1px solid rgba(255,102,0,0.4); }
.sev-medium   { background: rgba(255,170,0,0.2);  color: var(--medium);   border: 1px solid rgba(255,170,0,0.4); }
.sev-low      { background: rgba(68,136,255,0.2); color: var(--low);      border: 1px solid rgba(68,136,255,0.4); }
.sev-info     { background: rgba(170,187,204,0.1);color: var(--info);     border: 1px solid rgba(170,187,204,0.3); }

.tag {
  font-family: var(--font-mono); font-size: 11px;
  background: var(--bg-code); color: var(--accent-dim);
  padding: 2px 6px; border-radius: 3px;
}
.tactic-cell { color: var(--text-dim); font-size: 12px; white-space: nowrap; }
.detail-cell { color: var(--text-dim); font-size: 12px; max-width: 400px; word-break: break-word; }

/* ── Telemetry blocks ── */
.telem-block {
  border: 1px solid var(--border);
  border-radius: 6px;
  margin-bottom: 10px;
  overflow: hidden;
  background: var(--bg-card);
}
.telem-header {
  display: flex; align-items: center; gap: 10px;
  padding: 10px 16px;
  cursor: pointer;
  font-family: var(--font-mono); font-size: 13px;
  color: var(--text-main);
  transition: background .1s;
  user-select: none;
}
.telem-header:hover { background: rgba(0,255,136,0.05); }
.telem-arrow { color: var(--accent); transition: transform .2s; font-size: 10px; }
.telem-header.open .telem-arrow { transform: rotate(90deg); }
.telem-body { display: none; border-top: 1px solid var(--border); }
.telem-body.open { display: block; }
.telem-pre {
  font-family: var(--font-mono); font-size: 12px;
  color: var(--text-main);
  padding: 16px;
  white-space: pre-wrap; word-break: break-all;
  background: var(--bg-code);
  max-height: 400px; overflow-y: auto;
  line-height: 1.6;
}

/* ── Section headers ── */
.section-header {
  font-family: var(--font-ui); font-size: 18px; font-weight: 700;
  color: var(--accent); margin: 28px 0 16px;
  display: flex; align-items: center; gap: 10px;
}
.section-header::after {
  content: ''; flex: 1; height: 1px;
  background: linear-gradient(to right, var(--border), transparent);
}
.section-num {
  font-family: var(--font-mono); font-size: 11px;
  color: var(--text-dim); background: var(--bg-card);
  border: 1px solid var(--border);
  padding: 2px 8px; border-radius: 3px;
}

/* ── System info table ── */
.info-table { width: 100%; border-collapse: collapse; font-size: 13px; margin-bottom: 20px; }
.info-table td { padding: 8px 12px; border-bottom: 1px solid var(--border); }
.info-table td:first-child { width: 200px; color: var(--text-dim); font-family: var(--font-mono); font-size: 12px; }
.info-table td:last-child { color: var(--text-main); }

/* ── Footer ── */
.footer {
  border-top: 1px solid var(--border);
  padding: 20px 0;
  text-align: center;
  font-family: var(--font-mono); font-size: 11px;
  color: var(--text-dim);
  margin-top: 40px;
}
.footer span { color: var(--accent); }

/* ── Alert box ── */
.alert {
  display: flex; align-items: flex-start; gap: 12px;
  padding: 14px 16px;
  border-radius: 6px;
  border-left: 3px solid;
  margin-bottom: 16px;
  font-size: 13px;
}
.alert-warn  { background: rgba(255,170,0,0.08);  border-color: var(--medium); color: #ffd060; }
.alert-crit  { background: rgba(255,34,68,0.08);  border-color: var(--critical); color: #ff6680; }
.alert-info  { background: rgba(0,255,136,0.06);  border-color: var(--accent); color: var(--accent-dim); }

.no-findings { text-align: center; padding: 40px; color: var(--text-dim); font-family: var(--font-mono); font-size: 14px; }

@media (max-width: 768px) {
  .tactic-cell, .detail-cell { display: none; }
  .stats-row { gap: 8px; }
  .stat-badge { min-width: 80px; padding: 10px 12px; }
}
</style>
</head>
<body>

<div class="header">
  <div class="container">
    <div class="header-inner">
      <div class="logo-block">
        <div class="logo-text">&#9671; ZAVETSEC</div>
        <div class="logo-sub">ZLT &nbsp;&mdash;&nbsp; LINUX TRIAGE v${TOOL_VERSION} &nbsp;|&nbsp; DFIR TELEMETRY + DETECTION</div>
      </div>
      <div class="header-meta">
        <p>Host &nbsp;<span>${HOSTNAME_VAL}</span></p>
        <p>Start &nbsp;<span>${START_TS}</span></p>
        <p>End &nbsp;&nbsp;<span>${END_TS}</span></p>
        <p>Duration &nbsp;<span>${DURATION}s</span></p>
        <p>Root &nbsp;<span>$([ "$IS_ROOT" -eq 1 ] && echo 'Yes' || echo 'No')</span></p>
      </div>
    </div>

    <div class="stats-row">
      <div class="stat-badge stat-critical">
        <div class="stat-num">${FINDINGS_CRITICAL}</div>
        <div class="stat-label">Critical</div>
      </div>
      <div class="stat-badge stat-high">
        <div class="stat-num">${FINDINGS_HIGH}</div>
        <div class="stat-label">High</div>
      </div>
      <div class="stat-badge stat-medium">
        <div class="stat-num">${FINDINGS_MEDIUM}</div>
        <div class="stat-label">Medium</div>
      </div>
      <div class="stat-badge stat-low">
        <div class="stat-num">${FINDINGS_LOW}</div>
        <div class="stat-label">Low</div>
      </div>
      <div class="stat-badge stat-info">
        <div class="stat-num">${FINDINGS_INFO}</div>
        <div class="stat-label">Info</div>
      </div>
      <div class="stat-badge stat-total">
        <div class="stat-num">${TOTAL_FINDINGS}</div>
        <div class="stat-label">Total</div>
      </div>
    </div>
  </div>
</div>

<div class="container">

  <div class="tabs">
    <button class="tab-btn active" onclick="showTab('findings')">&#9432; Findings</button>
    <button class="tab-btn" onclick="showTab('telemetry')">&#9729; Telemetry</button>
    <button class="tab-btn" onclick="showTab('sysinfo')">&#9775; System Info</button>
  </div>

  <!-- ═══ TAB: FINDINGS ═══ -->
  <div id="tab-findings" class="tab-pane active">

    $(if [[ "$FINDINGS_CRITICAL" -gt 0 ]]; then
      echo "<div class=\"alert alert-crit\">&#9888; CRITICAL findings detected. Immediate investigation required.</div>"
    elif [[ "$FINDINGS_HIGH" -gt 0 ]]; then
      echo "<div class=\"alert alert-warn\">&#9888; HIGH findings detected. Priority analysis recommended.</div>"
    elif [[ "$TOTAL_FINDINGS" -eq 0 ]]; then
      echo "<div class=\"alert alert-info\">&#10003; No detection rules triggered. This does not guarantee a clean system — manual telemetry review is advised.</div>"
    fi)

    <div class="filter-bar">
      <span style="color:var(--text-dim);font-size:12px;font-family:var(--font-mono)">FILTER:</span>
      <button class="filter-btn active" onclick="filterFindings('ALL')">ALL</button>
      <button class="filter-btn fc-critical" onclick="filterFindings('CRITICAL')">CRITICAL</button>
      <button class="filter-btn fc-high"     onclick="filterFindings('HIGH')">HIGH</button>
      <button class="filter-btn fc-medium"   onclick="filterFindings('MEDIUM')">MEDIUM</button>
      <button class="filter-btn fc-low"      onclick="filterFindings('LOW')">LOW</button>
      <button class="filter-btn"             onclick="filterFindings('INFO')">INFO</button>
    </div>

    $(if [[ "$TOTAL_FINDINGS" -eq 0 ]]; then
      echo "<div class=\"no-findings\">&#10003; No findings triggered</div>"
    else
      echo "<table class=\"findings-table\">
        <thead><tr>
          <th>Severity</th>
          <th>Rule ID</th>
          <th>Title</th>
          <th>MITRE Tactic</th>
          <th>Detail</th>
        </tr></thead>
        <tbody>${FINDINGS_ROWS}</tbody>
      </table>"
    fi)
  </div>

  <!-- ═══ TAB: TELEMETRY ═══ -->
  <div id="tab-telemetry" class="tab-pane">

    <div class="section-header"><span class="section-num">01</span> Users & Accounts</div>
    $(telem_section "users-shell" "Users with login shell (/etc/passwd)" "$M_USERS_SHELL")
    $(telem_section "users-uid0"  "Accounts with UID 0" "$M_UID0")
    $(telem_section "users-sudo"  "Members of sudo/wheel groups" "$M_SUDOERS")

    <div class="section-header"><span class="section-num">02</span> Network</div>
    $(telem_section "net-listen"   "Listening ports (ss -tulnp)" "$M_NETSTAT")
    $(telem_section "net-est"      "Established connections" "$M_ESTABLISHED")
    $(telem_section "net-ifaces"   "Network interfaces" "$M_INTERFACES")
    $(telem_section "net-routes"   "Routing table" "$M_ROUTES")
    $(telem_section "net-arp"      "ARP table" "$M_ARP")
    $(telem_section "net-hosts"    "/etc/hosts" "$M_HOSTS")
    $(telem_section "net-resolv"   "/etc/resolv.conf" "$M_RESOLV")
    $(telem_section "net-fw"       "Firewall rules (iptables/nft)" "$M_IPTABLES")
    $(telem_section "net-ufw"      "UFW status" "$M_UFW")

    <div class="section-header"><span class="section-num">03</span> Processes</div>
    $(telem_section "proc-all"        "All processes (ps auxf)" "$M_PROCESSES")
    $(telem_section "proc-tree"       "Process tree (pstree)" "$M_PROC_TREE")
    $(telem_section "proc-unpackaged" "Processes not owned by any package (PROC-005)" "${M_UNPACKAGED_PROCS:-No suspicious processes / check not performed}")

    <div class="section-header"><span class="section-num">04</span> Persistence</div>
    $(telem_section "pers-cron"       "Root crontab" "$M_CRONTAB_ROOT")
    $(telem_section "pers-crondir"    "/etc/cron.* directory listing" "$M_CRON_ETC")
    $(telem_section "pers-croncont"   "/etc/cron.d and spool contents" "$M_CRON_CONTENT")
    $(telem_section "pers-systemd"    "Running systemd units" "$M_SYSTEMD_UNITS")
    $(telem_section "pers-systemd-en" "Enabled systemd units" "$M_SYSTEMD_ENABLED")
    $(telem_section "pers-profile"    "/etc/profile.d/ contents" "$M_PROFILE_D")
    $(telem_section "pers-bashrc"     "/root/.bashrc" "$M_BASHRC")
    $(telem_section "pers-ssh"        "authorized_keys (all found)" "$M_SSH_KEYS")

    <div class="section-header"><span class="section-num">05</span> File System</div>
    $(telem_section "fs-suid"         "SUID binaries" "$M_SUID")
    $(telem_section "fs-sgid"         "SGID binaries" "$M_SGID")
    $(telem_section "fs-worldwrite"   "World-writable directories" "$M_WORLD_WRITE")
    $(telem_section "fs-recent"       "System binaries modified in the last 24h" "$M_RECENT_FILES")
    $(telem_section "fs-tmp"          "/tmp, /dev/shm, /var/tmp contents" "$M_TMP_FILES")

    <div class="section-header"><span class="section-num">06</span> Logs</div>
    $(telem_section "log-source" "Log source" "Auth source: ${M_AUTH_SOURCE}")
    $(telem_section "log-auth"   "auth.log / secure / journald (last 100 lines)" "$M_AUTH_TAIL")
    $(telem_section "log-failed" "Failed login attempts" "$FAILED_LOGINS")
    $(telem_section "log-ok"     "Successful logins" "$SUCCESS_LOGINS")
    $(telem_section "log-last"   "Login history (last / wtmp)" "$M_LAST_LOGINS")
    $(telem_section "log-sys"    "syslog / journald (last 100 lines)" "$M_SYSLOG")

    <div class="section-header"><span class="section-num">07</span> Packages & Kernel</div>
    $(telem_section "pkg-all"     "Installed packages (first 100)" "$M_PACKAGES")
    $(telem_section "pkg-recent"  "Recently installed / upgraded packages" "$M_RECENT_PKG")
    $(telem_section "krn-modules" "Loaded kernel modules (lsmod)" "$M_LSMOD")

    <div class="section-header"><span class="section-num">08</span> Shell & Environment</div>
    $(telem_section "env-all"     "Environment variables" "$M_ENV")
    $(telem_section "hist-root"   "Root shell history (last 50 lines)" "$M_BASH_HISTORY_ROOT")
    $(telem_section "hist-users"  "User shell histories" "$M_BASH_HISTORY_USERS")

    <div class="section-header"><span class="section-num">09</span> Container / Cloud</div>
    $(telem_section "cnt-env" "Container / Cloud detection" "$M_CONTAINER")

  </div>

  <!-- ═══ TAB: SYSTEM INFO ═══ -->
  <div id="tab-sysinfo" class="tab-pane">
    <div class="section-header"><span class="section-num">SYS</span> System Overview</div>
    <table class="info-table">
      ${M_SYSINFO}
    </table>

    <div class="section-header"><span class="section-num">RUL</span> Detection Rules Summary</div>
    <table class="info-table">
      <tr><td>Category</td><td>Rules</td></tr>
      <tr><td>USR (Users)</td><td>USR-001 — USR-003</td></tr>
      <tr><td>NET (Network)</td><td>NET-001 — NET-005</td></tr>
      <tr><td>PROC (Processes)</td><td>PROC-001 — PROC-005</td></tr>
      <tr><td>PERS (Persistence)</td><td>PERS-001 — PERS-004</td></tr>
      <tr><td>FS (File System)</td><td>FS-001 — FS-004</td></tr>
      <tr><td>LOG (Logs)</td><td>LOG-001 — LOG-003</td></tr>
      <tr><td>NET (Net Config)</td><td>NET-004 — NET-005</td></tr>
      <tr><td>PKG (Packages)</td><td>PKG-001</td></tr>
      <tr><td>KRN (Kernel)</td><td>KRN-001 — KRN-002</td></tr>
      <tr><td>HIST (History)</td><td>HIST-001 — HIST-002</td></tr>
      <tr><td>CNT (Container)</td><td>CNT-001 — CNT-004</td></tr>
      <tr><td>SYS (System)</td><td>SYS-001</td></tr>
    </table>
  </div>

</div><!-- /container -->

<div class="footer">
  <div class="container">
    <p>
      <span>ZavetSec</span> ZLT v${TOOL_VERSION} &nbsp;|&nbsp;
      Generated: ${END_TS} &nbsp;|&nbsp;
      Host: ${HOSTNAME_VAL} &nbsp;|&nbsp;
      Duration: ${DURATION}s
    </p>
  </div>
</div>

<script>
function showTab(id) {
  document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.getElementById('tab-' + id).classList.add('active');
  event.target.classList.add('active');
}

function toggleTelem(header) {
  header.classList.toggle('open');
  const body = header.nextElementSibling;
  body.classList.toggle('open');
}

function filterFindings(sev) {
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  event.target.classList.add('active');
  document.querySelectorAll('.finding-row').forEach(row => {
    if (sev === 'ALL' || row.dataset.sev === sev) {
      row.style.display = '';
    } else {
      row.style.display = 'none';
    }
  });
}

// Auto-expand first non-empty telem block per section
document.querySelectorAll('.telem-header').forEach((h, i) => {
  if (i < 2) { h.classList.add('open'); h.nextElementSibling.classList.add('open'); }
});
</script>
</body>
</html>
HTMLEOF

# =============================================================================
# DONE
# =============================================================================

# ── Optional: CSV export ──────────────────────────────────────────────────────
if [[ "$EXPORT_CSV" -eq 1 ]]; then
    CSV_FILE="${REPORT_BASE}.csv"
    {
        printf '%s\n' "severity,rule_id,mitre_tactic,title,detail"
        for _entry in "${FINDINGS_ARR[@]+"${FINDINGS_ARR[@]}"}"; do
            IFS=$'\x1f' read -r _sev _tactic _rule _title _detail <<< "$_entry"
            # Escape CSV: wrap fields in double-quotes, double any internal quotes
            _sev_q="\"${_sev//\"/\"\"}\""
            _tactic_q="\"${_tactic//\"/\"\"}\""
            _rule_q="\"${_rule//\"/\"\"}\""
            _title_q="\"${_title//\"/\"\"}\""
            _detail_q="\"${_detail//\"/\"\"}\""
            printf '%s,%s,%s,%s,%s\n' "$_sev_q" "$_rule_q" "$_tactic_q" "$_title_q" "$_detail_q"
        done
    } > "$CSV_FILE"
    log_ok "CSV exported: ${CSV_FILE}"
fi

# ── Optional: JSON export ─────────────────────────────────────────────────────
if [[ "$EXPORT_JSON" -eq 1 ]]; then
    JSON_FILE="${REPORT_BASE}.json"
    json_escape() {
        local s="$*"
        s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; s="${s//$'\n'/\\n}"
        s="${s//$'\r'/\\r}"; s="${s//$'\t'/\\t}"
        printf '%s' "$s"
    }
    {
        printf '{\n'
        printf '  "tool": "ZLT",\n'
        printf '  "version": "%s",\n' "$(json_escape "$TOOL_VERSION")"
        printf '  "hostname": "%s",\n' "$(json_escape "$HOSTNAME_VAL")"
        printf '  "scan_start": "%s",\n' "$(json_escape "$START_TS")"
        printf '  "scan_end": "%s",\n' "$(json_escape "$END_TS")"
        printf '  "duration_seconds": %s,\n' "$DURATION"
        printf '  "summary": {\n'
        printf '    "critical": %d,\n' "$FINDINGS_CRITICAL"
        printf '    "high": %d,\n' "$FINDINGS_HIGH"
        printf '    "medium": %d,\n' "$FINDINGS_MEDIUM"
        printf '    "low": %d,\n' "$FINDINGS_LOW"
        printf '    "info": %d\n' "$FINDINGS_INFO"
        printf '  },\n'
        printf '  "findings": [\n'
        _total=${#FINDINGS_ARR[@]+"${#FINDINGS_ARR[@]}"}
        _total="${_total:-0}"
        _idx=0
        for _entry in "${FINDINGS_ARR[@]+"${FINDINGS_ARR[@]}"}"; do
            IFS=$'\x1f' read -r _sev _tactic _rule _title _detail <<< "$_entry"
            _idx=$((_idx + 1))
            _comma=','
            [[ "$_idx" -eq "$_total" ]] && _comma=''
            printf '    {\n'
            printf '      "severity": "%s",\n'    "$(json_escape "$_sev")"
            printf '      "rule_id": "%s",\n'     "$(json_escape "$_rule")"
            printf '      "mitre_tactic": "%s",\n' "$(json_escape "$_tactic")"
            printf '      "title": "%s",\n'       "$(json_escape "$_title")"
            printf '      "detail": "%s"\n'       "$(json_escape "$_detail")"
            printf '    }%s\n' "$_comma"
        done
        printf '  ]\n'
        printf '}\n'
    } > "$JSON_FILE"
    log_ok "JSON exported: ${JSON_FILE}"
fi

echo ""
log_ok "Collection complete!"
echo ""
echo -e "  ${BOLD}Findings:${NC}"
[[ "$FINDINGS_CRITICAL" -gt 0 ]] && echo -e "    ${RED}  CRITICAL: ${FINDINGS_CRITICAL}${NC}"
[[ "$FINDINGS_HIGH"     -gt 0 ]] && echo -e "    ${YELLOW}  HIGH:     ${FINDINGS_HIGH}${NC}"
[[ "$FINDINGS_MEDIUM"   -gt 0 ]] && echo -e "    ${YELLOW}  MEDIUM:   ${FINDINGS_MEDIUM}${NC}"
[[ "$FINDINGS_LOW"      -gt 0 ]] && echo -e "    ${CYAN}  LOW:      ${FINDINGS_LOW}${NC}"
[[ "$FINDINGS_INFO"     -gt 0 ]] && echo -e "    ${NC}  INFO:     ${FINDINGS_INFO}${NC}"
echo ""
echo -e "  ${BOLD}Report:${NC} ${GREEN}${REPORT_FILE}${NC}"
[[ "$EXPORT_CSV"  -eq 1 ]] && echo -e "  ${BOLD}CSV:${NC}    ${GREEN}${REPORT_BASE}.csv${NC}"
[[ "$EXPORT_JSON" -eq 1 ]] && echo -e "  ${BOLD}JSON:${NC}   ${GREEN}${REPORT_BASE}.json${NC}"
echo ""
echo -e "  ${BOLD}Open:${NC}"
echo -e "    xdg-open ${REPORT_FILE}"
echo -e "    # or copy to your workstation:"
echo -e "    scp root@\$(hostname):${REPORT_FILE} ./"
echo ""

# ── Offer HTTP server (useful on Snap-browser environments like Ubuntu 24 Desktop) ──
if command -v python3 &>/dev/null && [[ -t 0 ]]; then
    echo -e "  ${CYAN}[?]${NC} ${BOLD}Serve report via local HTTP server?${NC}"
    echo -e "      ${CYAN}(recommended on Ubuntu Desktop — avoids Snap file:// access issues)${NC}"
    echo ""
    printf "      Open in browser at http://localhost:18420 ? [Y/n]: "
    read -r _SERVE_ANS
    _SERVE_ANS="${_SERVE_ANS:-Y}"
    if [[ "$_SERVE_ANS" =~ ^[Yy]$ ]]; then
        _SERVE_PORT=18420
        _SERVE_URL="http://localhost:${_SERVE_PORT}/$(basename "$REPORT_FILE")"
        echo ""
        log_ok "Starting HTTP server on port ${_SERVE_PORT}..."
        log_info "Open: ${_SERVE_URL}"
        echo ""

        # ── Open browser as the real (non-root) user ──────────────────────────
        # Ubuntu 24 Desktop uses Wayland + Snap Firefox. Running via sudo means
        # we have no DISPLAY/WAYLAND_DISPLAY/DBUS — must harvest them from the
        # user's live processes in /proc or via loginctl.
        _REAL_USER="${SUDO_USER:-}"
        (
            sleep 1
            if [[ -n "$_REAL_USER" ]] && id "$_REAL_USER" &>/dev/null; then
                _REAL_UID=$(id -u "$_REAL_USER")

                # Scan /proc for any process owned by the real user and extract
                # session environment variables — works on both X11 and Wayland.
                _ENV_DISPLAY=""
                _ENV_WAYLAND=""
                _ENV_DBUS=""
                _ENV_XDG_RT=""
                for _pid_env in /proc/*/environ; do
                    [[ -r "$_pid_env" ]] || continue
                    _pid_uid=$(stat -c '%u' "$_pid_env" 2>/dev/null || echo "0")
                    [[ "$_pid_uid" != "$_REAL_UID" ]] && continue
                    _env_content=$(tr '\0' '\n' < "$_pid_env" 2>/dev/null) || continue
                    [[ -z "$_ENV_DISPLAY" ]] && _ENV_DISPLAY=$(echo "$_env_content" | grep '^DISPLAY='                  | head -1 | cut -d= -f2-)
                    [[ -z "$_ENV_WAYLAND" ]] && _ENV_WAYLAND=$(echo "$_env_content" | grep '^WAYLAND_DISPLAY='          | head -1 | cut -d= -f2-)
                    [[ -z "$_ENV_DBUS"    ]] && _ENV_DBUS=$(echo    "$_env_content" | grep '^DBUS_SESSION_BUS_ADDRESS=' | head -1 | cut -d= -f2-)
                    [[ -z "$_ENV_XDG_RT"  ]] && _ENV_XDG_RT=$(echo  "$_env_content" | grep '^XDG_RUNTIME_DIR='         | head -1 | cut -d= -f2-)
                    [[ -n "$_ENV_DBUS" ]] && { [[ -n "$_ENV_DISPLAY" ]] || [[ -n "$_ENV_WAYLAND" ]]; } && break
                done

                _OPEN_ENV=()
                [[ -n "$_ENV_DISPLAY" ]] && _OPEN_ENV+=("DISPLAY=$_ENV_DISPLAY")
                [[ -n "$_ENV_WAYLAND" ]] && _OPEN_ENV+=("WAYLAND_DISPLAY=$_ENV_WAYLAND")
                [[ -n "$_ENV_DBUS"    ]] && _OPEN_ENV+=("DBUS_SESSION_BUS_ADDRESS=$_ENV_DBUS")
                [[ -n "$_ENV_XDG_RT"  ]] && _OPEN_ENV+=("XDG_RUNTIME_DIR=$_ENV_XDG_RT")

                if [[ "${#_OPEN_ENV[@]}" -gt 0 ]]; then
                    sudo -u "$_REAL_USER" "${_OPEN_ENV[@]}" xdg-open "$_SERVE_URL" 2>/dev/null
                else
                    # Fallback: try loginctl + sensible defaults
                    _SESSION_ID=$(loginctl list-sessions --no-legend 2>/dev/null \
                        | awk -v u="$_REAL_USER" '$3==u{print $1; exit}')
                    [[ -n "$_SESSION_ID" ]] && loginctl activate "$_SESSION_ID" 2>/dev/null || true
                    sudo -u "$_REAL_USER" \
                        DISPLAY=":0" \
                        WAYLAND_DISPLAY="wayland-0" \
                        XDG_RUNTIME_DIR="/run/user/${_REAL_UID}" \
                        xdg-open "$_SERVE_URL" 2>/dev/null
                fi
            else
                xdg-open "$_SERVE_URL" 2>/dev/null
            fi
        ) &>/dev/null &

        log_info "If browser does not open automatically, navigate to:"
        log_info "  ${_SERVE_URL}"
        echo ""
        log_info "Press Ctrl+C to stop the server."
        echo ""
        cd "$(dirname "$REPORT_FILE")" && python3 -m http.server "$_SERVE_PORT" --bind 127.0.0.1
    else
        echo ""
        log_info "Skipped. Open manually:"
        log_info "  xdg-open ${REPORT_FILE}"
        echo ""
    fi
fi

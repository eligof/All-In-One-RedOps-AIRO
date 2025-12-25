# AIRO Operator Workflow Guide

This guide walks you through a practical, step-by-step workflow for using AIRO on a fresh Linux VM or host. It is written from a pentester's point of view: set up the environment, run reconnaissance, perform targeted scans, collect evidence, and generate reports.

## Table of Contents
- Setup (Debian/Ubuntu, Fedora/RHEL, Arch)
- Verify Install and First Run
- Pre-Engagement Checklist
- Workspace and Output Hygiene
- Recon and Scanning Workflows (Web, Network, Mobile)
- Reporting and Evidence
- Safety, Troubleshooting, Post-Engagement

## 1) Fresh VM/Host Setup (Debian/Ubuntu-based)
```bash
sudo apt update && sudo apt -y upgrade
sudo apt -y install git curl python3 python3-venv python3-pip
```

Clone the repo:
```bash
git clone https://github.com/eligof/All-In-One-RedOps-AIRO.git
cd All-In-One-RedOps-AIRO
```

Generate and install AIRO (installer prompts to install dependencies):
```bash
python airo-splitter.py
cd airo-redops-v3.3.0
chmod +x install.sh
./install.sh
source ~/.bashrc   # or ~/.zshrc
```

Optional: wordlists and PEAS helpers:
```bash
git clone https://github.com/danielmiessler/SecLists.git ~/SecLists
airo getpeas
```

## 1a) Fresh VM/Host Setup (Fedora/RHEL-based)
```bash
sudo dnf -y update
sudo dnf -y install git curl python3 python3-pip
```

Then follow the same clone/install steps above.

## 1b) Fresh VM/Host Setup (Arch-based)
```bash
sudo pacman -Syu --noconfirm git curl python python-pip
```

Then follow the same clone/install steps above.

## 1c) Verify Install and First Run
Confirm the launcher and version:
```bash
airo --help
airo --version
```

Dry-run a simple command:
```bash
airo --dry-run whoislookup example.com
```

## 1d) First Run Sanity Checks
- Ensure `airo` is on PATH (`which airo`).
- Confirm XDG paths exist and are writable:
  - `~/.config/airo`
  - `~/.local/share/airo`
  - `~/.cache/airo`
- If using wordlists, verify `~/SecLists` exists or set `WORDLIST_BASE`.

## 2) Pre-Engagement Checklist
- Confirm scope, authorization, and allowed time window.
- Verify targets (CIDR ranges, domains, and IPs).
- Decide safe vs fast mode (SAFE_MODE and rate limits).
- If required, set proxy or Tor flags.
- Prepare a reporting format and a findings taxonomy (critical/high/medium/low).
- Identify what evidence is required (screenshots, command output, hashes).

## 3) Create a Working Folder With Timestamp
```bash
ENGAGEMENT="acme-internal"
TS="$(date +"%Y%m%d_%H%M")"
WORKDIR="$HOME/engagements/${ENGAGEMENT}_${TS}"
mkdir -p "$WORKDIR"
cd "$WORKDIR"
```

Suggested structure:
```bash
mkdir -p "$WORKDIR"/{recon,web,network,mobile,findings,evidence,notes}
```

Optional one-liner setup (new engagement):
```bash
ENGAGEMENT="acme-internal"
BASE_DIR="$HOME/engagements"
TS="$(date +"%Y%m%d_%H%M")"
WORKDIR="${BASE_DIR}/${ENGAGEMENT}_${TS}"
mkdir -p "$WORKDIR"/{recon,web,network,mobile,findings,evidence,notes}
cd "$WORKDIR"
echo "Started engagement ${ENGAGEMENT} at $(date +"%F %T")" >> notes/ops.log
```

## 4) Configure AIRO (Optional)
AIRO supports XDG config and environment overrides:
- Config: `~/.config/airo/config.ini`
- Data: `~/.local/share/airo`
- Cache/Logs: `~/.cache/airo`

Example `config.ini`:
```ini
[defaults]
safe_mode = 1
scan_delay = 1
rate_limit = 50
```

Environment overrides (per session):
```bash
export AIRO_SAFE_MODE=1
export AIRO_RATE_LIMIT=50
export AIRO_SCAN_DELAY=1
```

## 5) Command Pattern and Output Hygiene
Most commands accept `--output` (or `-o`) for file output. Prefer writing all results into your engagement folder:
```bash
airo httpxprobe https://target.com --output "$WORKDIR/web/httpx.txt"
```

When running multiple tools, keep a short notes file with timestamps:
```bash
date +"%F %T" >> "$WORKDIR/notes/ops.log"
echo "Started web recon against target.com" >> "$WORKDIR/notes/ops.log"
```

## 5a) Standard Workflow Timeline (Example)
1) Passive recon and asset discovery.
2) Validate targets and prioritize.
3) Targeted scans with safety controls.
4) Manual verification of findings.
5) Evidence capture and report drafting.
6) Final report and cleanup.

## 6) Initial Recon (Low Impact)
Start with passive or light-touch checks:
```bash
airo whoislookup target.com > "$WORKDIR/whois.txt"
airo dnsenum target.com --output "$WORKDIR/dnsenum.txt"
airo subdomain target.com --output "$WORKDIR/subdomains.txt"
```

If you have multiple domains, loop and capture results:
```bash
while read -r domain; do
  airo subdomain "$domain" --output "$WORKDIR/recon/${domain}_subs.txt"
done < domains.txt
```

## 7) Web Recon Workflow
Probe and crawl:
```bash
airo httpxprobe https://target.com --output "$WORKDIR/httpx.txt"
airo katana https://target.com -o "$WORKDIR/katana.txt"
airo wayback target.com --output "$WORKDIR/wayback.txt"
```

Fuzz and scan:
```bash
airo dirscan https://target.com --threads 50 --output "$WORKDIR/dirscan.txt"
airo fuzzurl https://target.com --wordlist raft-medium --output "$WORKDIR/fuzz.txt"
airo nuclei https://target.com --severity=high --output "$WORKDIR/nuclei.txt"
```

Triage tips:
- Start with `--severity=high` and raise scope as needed.
- Use `--rate-limit` and `--delay` when testing production.
- Confirm findings with manual validation before reporting.

## 8) Network Recon Workflow
```bash
airo portscan 10.0.0.5 --top 100 --output "$WORKDIR/portscan.txt"
airo vulnscan 10.0.0.5 --nmap-opts "-sV" --out "$WORKDIR/vulnscan.txt"
```

If scanning ranges, keep results segmented by host:
```bash
for host in 10.0.0.5 10.0.0.6; do
  airo portscan "$host" --top 100 --output "$WORKDIR/network/${host}_ports.txt"
done
```

## 9) Mobile Workflow (APK Example)
```bash
airo apkdecompile app.apk "$WORKDIR/apk_out"
airo apkanalyze app.apk --output "$WORKDIR/apk_analyze.txt"
```

## 10) Reporting and Evidence
Create a report scaffold and capture findings:
```bash
airo reportgen
airo findings
airo evidence
```

Store raw results alongside notes:
```bash
cp "$WORKDIR"/* "$HOME/.local/share/airo/reports/"
```

Evidence tips:
- Record exact commands used and their outputs.
- Capture screenshots where UI evidence matters.
- Save hashes (e.g., APK or firmware) for integrity.

## 10a) Report Generation Walkthrough
1) Run `airo reportgen` to create a report template.
2) Add findings with clear impact, evidence, and remediation notes.
3) Reference output files by relative path in your report.
4) Keep a timeline of actions in `notes/ops.log`.

## 11) Safe vs Fast Mode
By default, AIRO runs with SAFE_MODE enabled. For speed, use per-run flags:
```bash
airo --fast portscan 10.0.0.5 --top 100
```

If you need explicit pacing:
```bash
airo --delay 2 --rate-limit 20 dirscan https://target.com
```

## 12) Proxy / Tor / Logging
```bash
airo --proxy http://127.0.0.1:8080 httpxprobe https://target.com
airo --tor nuclei https://target.com
```

Logs:
- Error log: `~/.cache/airo/logs/airo.log`
- JSON log: `~/.cache/airo/logs/commands.jsonl`

## 12a) Troubleshooting Quick Hits
- Missing tool: re-run `./scripts/install_airo_dependencies.sh` or install the tool manually.
- Wordlists not found: set `WORDLIST_BASE` or clone SecLists to `~/SecLists`.
- Permission issues: verify install location and shell profile sourcing.
- Slow scans: use `--fast` or adjust `--rate-limit` and `--delay`.
- Proxy/Tor not working: verify service is running and ports are open.

## 13) Post-Engagement Checklist
- Validate findings and remove false positives.
- Export results and notes for final report.
- Archive logs and evidence.
- If needed, uninstall:
```bash
./uninstall.sh
```

## Example One-Command Flow (Web)
```bash
TARGET="https://target.com"
TS="$(date +"%Y%m%d_%H%M")"
OUT="$HOME/engagements/web_${TS}"
mkdir -p "$OUT"

airo httpxprobe "$TARGET" --output "$OUT/httpx.txt"
airo katana "$TARGET" -o "$OUT/katana.txt"
airo nuclei "$TARGET" --severity=high --output "$OUT/nuclei.txt"
airo reportgen
```

## Common Checks to Remember
- Confirm rate limits and safe mode before large scans.
- Ensure output directories exist and are writable.
- Store sensitive data securely (credentials, tokens, dumps).
- Document scope changes and approvals.

## Operational Safety Reminders
- Use safe mode for production targets unless explicitly approved.
- Avoid disruptive scans during business hours.
- Never scan outside written scope.
- Treat credentials and dumps as sensitive data.

## Responsible Use
Only run AIRO against systems you own or have explicit written permission to test. Always follow your engagement scope and local laws. The operator is responsible for safe, compliant use.

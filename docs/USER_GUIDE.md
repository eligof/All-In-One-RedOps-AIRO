# AIRO User Guide

## Purpose
AIRO is a modular red/purple-team toolkit generator. You build once and install a portable framework with 150+ tasks across recon, scanning, web, mobile, OSINT, and reporting.

## Install
```bash
python airo-splitter.py
cd airo-redops-v3.2.0
chmod +x install.sh
./install.sh
source ~/.bashrc   # or ~/.zshrc
```

## Config Locations (XDG)
- Config: `$XDG_CONFIG_HOME/airo` (fallback `~/.config/airo`)
- Data: `$XDG_DATA_HOME/airo` (fallback `~/.local/share/airo`)
- Cache: `$XDG_CACHE_HOME/airo` (fallback `~/.cache/airo`)
- Logs: `$XDG_CACHE_HOME/airo/logs/`

## Configuration
AIRO loads configs in order:
1) `defaults.conf`
2) `main.conf`
3) `user.conf`
4) `config.ini` (optional)
5) Env overrides (e.g., `AIRO_SAFE_MODE=1`)

Key settings:
- `SAFE_MODE`, `SCAN_DELAY`, `RATE_LIMIT`, `MAX_HOSTS`, `TOOL_TIMEOUT`
- `WORDLIST_BASE`, `WORDLIST_DIRSCAN`, `WORDLIST_FUZZURL`
- `PROXY`, `TOR`, `USER_AGENT`, `JITTER`, `JSON_LOGGING`

## Runtime Flags (per run)
- `--fast` / `--unsafe` (requires `--force`)
- `--safe`
- `--no-delay`, `--delay=<s>`
- `--rate-limit=<pps>`
- `--dry-run`, `--verbose`
- `--debug`
- `--proxy <url>`, `--tor`, `--user-agent <ua>`, `--jitter <s>`
- `--json-log`

## Examples
```bash
airo myip
airo netscan 192.168.1.0/24
airo --fast --force portscan 10.0.0.10 --top 100
airo dirscan https://example.com --wordlist raft-medium --threads 40
airo nuclei https://example.com --severity high
airo --dry-run --verbose reconall example.com
```

## Updates and Rollback
Check for updates:
```bash
airo update --check
```

Apply update from a release tarball:
```bash
airo update --apply --url <tar.gz>
```

Rollback to the latest backup:
```bash
airo update --rollback
```

## Wordlists
AIRO defaults to SecLists:
```bash
git clone https://github.com/danielmiessler/SecLists.git ~/SecLists
```
Override paths via config or env:
```
WORDLIST_BASE=$HOME/SecLists
WORDLIST_DIRSCAN=$WORDLIST_BASE/Discovery/Web-Content/common.txt
WORDLIST_FUZZURL=$WORDLIST_BASE/Discovery/Web-Content/raft-medium-words.txt
```

## PEAS Helpers
```bash
airo getpeas
```
Downloads linPEAS/winPEAS to `$AIRO_HOME/tools/peas`. If SHA256 hashes exist in `vendors/tools.json`, downloads are verified.

## Safety Notes
- Keep `SAFE_MODE=1` for risky actions.
- Use `safescan` or `--delay` for sensitive targets.
- `--fast/--unsafe` needs `--force` to reduce accidental misuse.

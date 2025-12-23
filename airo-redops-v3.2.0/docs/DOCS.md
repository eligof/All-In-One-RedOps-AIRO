# All In One RedOps (AIRO) Splitter – Reference

Build the AIRO toolkit (v3.2.0) from one Python script. This reference explains what gets generated, how to install/uninstall, how to configure, key commands by module, dependencies, safety, packaging, and troubleshooting.

## What the Splitter Generates
- `airo-core.sh` – core loader (paths, logging, lazy-loading map, aliases, completion).
- `modules/` – bash modules grouped by domain (network, web, system, privesc, cloud, ad, wireless, mobile, osint, automation, utilities).
- `config/` – `defaults.conf` (baseline) and `user.conf.example` (override template).
- `plugins/` – placeholder for extensions.
- `docs/` – copies of `README.md` and this `DOCS.md`.
- `install.sh` / `uninstall.sh` – installer and remover (installer can be templated via `install.sh.template`).

## Quick Build / Install / Remove
1) Generate:
```bash
python airo-splitter.py
```
2) Install:
```bash
cd airo-redops-v3.2.0
sudo ./install.sh
source ~/.bashrc   # or ~/.zshrc
```
- Installs to `$HOME/.airo`, symlink at `/usr/local/bin/airo`.
3) Uninstall:
```bash
cd airo-redops-v3.2.0
./uninstall.sh
```
- Prompts, removes `$HOME/.airo`, and drops the symlink if it is a symlink.

## Using AIRO (basics)
- Pattern: `airo <command> [args]` (lazy-loads the right module).
- Discover: `airo help`, `airo modules`, `airo version`.
- Common: `airo myip`, `airo netscan 192.168.1.0/24`, `airo webscan https://example.com`.
- Aliases: many commands are available as direct aliases (e.g., `netscan` → `airo netscan`).

## Configuration
- Defaults live in `config/defaults.conf` (copied to `$HOME/.airo/config/main.conf` on install).
- User overrides: copy `config/user.conf.example` to `$HOME/.airo/config/user.conf` and edit.
- Key knobs: `SAFE_MODE` (prompts for risky actions), `SCAN_DELAY`, `RATE_LIMIT`, `MAX_HOSTS`, `TOOL_TIMEOUT`, `AUTO_LOAD_MODULES`, `AUDIT_LOGGING`.
- API keys: `SHODAN_API_KEY`, `CENSYS_API_ID`, `CENSYS_API_SECRET`, etc., go in your user config.
- Wordlists: `WORDLIST_BASE` defaults to `$HOME/SecLists`; set `WORDLIST_DIRSCAN` and `WORDLIST_FUZZURL` to choose lists. Clone SecLists: `git clone https://github.com/danielmiessler/SecLists.git $WORDLIST_BASE`.
- Flags: per-run toggles `--fast/--unsafe` (SAFE_MODE=0, SCAN_DELAY=0, RATE_LIMIT=10000), `--safe`, `--no-delay`, `--delay=<s>`, `--rate-limit=<pps>`.
- Command flags:
  - Network: `--ports`, `--top`, `--timeout`, `--output` (portscan/udpscan/netscan).
  - Web: `--wordlist <path|alias>`, `--threads <n>`, `--extensions ext,ext` (dirscan); `--wordlist`, `--threads` (fuzzurl).
  - Automation: `--out <dir/file>`, `--target <value>`, `--nmap-opts "<...>"`, `--nikto-opts "<...>"` (reconall/vulnscan).

## Modules Snapshot (high level)
- **Network**: netscan, portscan, udpscan, alivehosts, dnscan, safescan, lhost/myip, tracer, whoislookup, dnsdump, cidrcalc.
- **Web**: webscan, dirscan, fuzzurl, sqlcheck, xsscheck, takeover, wpscan, joomscan, sslscan, headerscan, httpxprobe, wayback, katana, nuclei.
- **System**: sysenum, sudofind, capfind, cronfind, procmon, libfind, serviceenum, userenum.
- **Privesc**: lpe/wpe, sudoexploit, kernelcheck, winprivesc/linprivesc, getpeas (downloads linPEAS/winPEAS).
- **Cloud**: awscheck, azcheck, gcpcheck, s3scan, ec2scan, dockerscan, kubescan, containerbreak.
- **AD**: adusers, adgroups, admachines, bloodhound, kerberoast, asreproast, goldenticket, silverticket, passpol, gpppass.
- **Wireless**: wifiscan, wifiattack, bluescan, blueattack, wpscrack, handshake, besside, blefind.
- **Mobile/IoT**: apkanalyze, apkdecompile, ipascan, androidscan, iotscan, firmwareextract, bleenum.
- **OSINT**: emailosint, userosint, phoneosint, domainosint, breachcheck, leaksearch, metadata, imageosint.
- **Automation**: reconall, vulnscan, reportgen, findings, evidence, timertrack, notify.
- **Utilities**: urldecode/urlencode, base64d/base64e, hexdump, filetype, calccidr, shodanscan, censysscan, fofascan.

## Dependency Checklist (install what you need)
- Core/common: bash, coreutils, curl, awk, sed, grep, ip/ifconfig, ping, dig/host.
- Network: nmap, whois.
- Web: nikto, gobuster or dirb, ffuf, sqlmap, wpscan, joomscan, sslscan or testssl.sh, httpx, katana, nuclei, gau/waybackurls.
- System: getcap, watch, ps, ss or netstat.
- Cloud/Container: awscli, az, gcloud, docker, kubectl.
- AD: enum4linux, ldapsearch, BloodHound collectors, roasting tools.
- Wireless: aircrack-ng suite, bluetoothctl; optional bettercap.
- Mobile/IoT: apktool, jadx, zipalign, adb, gatttool, firmware unpackers.
- OSINT: exiftool.
- Automation: subfinder, whatweb, nmap, nikto.
- Utilities: xxd or hexdump, file, strings; API keys for Shodan/Censys/Fofa.
- Wordlists: SecLists (`git clone https://github.com/danielmiessler/SecLists.git $HOME/SecLists`) or other packs.
- Privesc helpers: curl or wget for fetching linPEAS/winPEAS (`airo getpeas` downloads them to `$AIRO_HOME/tools/peas`).
- Optional: `grc` for colorized nmap output (netscan/portscan/udpscan/safescan use it if present).

## Safety and Tuning
- Keep `SAFE_MODE=1` for prompts; set to `0` only when you accept risk.
- Throttle with `RATE_LIMIT` and `SCAN_DELAY`; prefer `airo_safescan` on sensitive targets.
- Use `timeout` for long scans, e.g., `timeout 300 airo vulnscan target`.
- Redirect output when needed: `airo dnsdump example.com > dns.txt`.

## Outputs and Paths
- Framework installs to `$HOME/.airo`; modules live under `$HOME/.airo/modules`.
- `airo_reconall` writes to `~/recon/<domain>-YYYYMMDD/`.
- `airo_reportgen` writes to `~/pentest_reports/DATE/report_template.md`.

## Extending AIRO
- Add a module: implement `create_module_<name>` in `airo-splitter.py`, export functions, update loader mapping if needed, regenerate.
- Override installer: drop an `install.sh.template` beside `airo-splitter.py`; the script will use it.
- Adjust defaults: edit `create_config_files` or change `config/defaults.conf` then regenerate.

## Quick Examples
```bash
airo myip
airo netscan 192.168.1.0/24
airo webscan https://example.com
airo reconall example.com
```

## Troubleshooting
- Command not found: reinstall and reload shell; ensure `/usr/local/bin/airo` exists and is a symlink.
- Missing tool: install the dependency for that module (see checklist above).
- API placeholders: set keys in your user config; cloud scans need their CLIs.
- Permissions: installer may need sudo for `/usr/local/bin`; uninstaller skips non-symlinks.

## Packaging / Distribution Checklist
- Regenerate and archive: `python airo-splitter.py && tar -czf airo-redops-v3.2.0.tar.gz airo-redops-v3.2.0`.
- Verify executables: `find airo-redops-v3.2.0 -maxdepth 2 -type f -name "*.sh" -exec test -x {} \; -print`.
- Spot-check docs: ensure `README.md` and `DOCS.md` exist in both root and `docs/`.
- Sanity test installer: run `./install.sh` in a throwaway environment or container if you ship it.
- Clean secrets: confirm config files only contain placeholders.

## Support
- When reporting, include OS, shell, command, output/error, and dependency status.
- For extending, mirror patterns in `airo-splitter.py`, regenerate, and test.

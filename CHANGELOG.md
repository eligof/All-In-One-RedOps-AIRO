# Changelog

## 3.4.4 - 2025-12-28
- Allow bridged DHCP for Vagrant SSH, with optional static IP override.

## 3.4.3 - 2025-12-28
- Disable NAT entirely and require a bridged static IP for Vagrant SSH.

## 3.4.2 - 2025-12-28
- Set bridged networking as adapter 1 and move NAT to adapter 2 in Vagrant.

## 3.4.1 - 2025-12-28
- Vagrant now uses NAT DNS proxy/host resolver and disables vbguest auto-update when available.

## 3.4.0 - 2025-12-28
- Vagrant now adds a bridged primary NIC plus an internal network NIC.

## 3.3.9 - 2025-12-28
- Add Vagrant automation for cloning, building, installing, and running test commands with logs.

## 3.3.8 - 2025-12-28
- Add command output logging via --log/AIRO_LOG_FILE.
- Retry SSL scans with backoff; increase headerscan retry count.

## 3.3.7 - 2025-12-28
- Retry dirscan with gobuster exclude-length on wildcard 403 responses.
- Domain OSINT now emits live WHOIS/DNS data plus source checklist.

## 3.3.6 - 2025-12-28
- Skip Go tool installs when disk space is low and error early on no-space.
- Reportgen now fails cleanly when it cannot write output.

## 3.3.5 - 2025-12-28
- Add safer apt update handling and skip installs on signature failures.
- Handle PEP 668 by falling back to venv/pipx for Python package installs.
- Only attempt kubectl apt install when a candidate exists.

## 3.3.4 - 2025-12-28
- Prevent repeated dependency installs within a single shell session.
- Normalize wordlist paths to expand $HOME and avoid duplicate SecLists clones.

## 3.3.3 - 2025-12-28
- Capture dnscan output reliably and add sqlmap non-interactive defaults.
- Add draft findings to reportgen based on collected artifacts.

## 3.3.2 - 2025-12-28
- Ensure sudo runs use the invoking user's XDG paths for module loading.
- Prompt for scan impact once per session (per shell).
- Ship dependency installer into AIRO_HOME and auto-clone SecLists when missing.
- Improve portscan/udpscan output handling and use unprivileged TCP scans without sudo.
- Reportgen now links the latest runlist log when available.

## 3.3.1 - 2025-12-28
- Added VERSION file as the single source of truth for package versioning.
- Runlist now writes full output + summary to a log file by default.
- Auto-install missing tools by default and enforce required Go tool installs.
- Reduced banner noise (once per session) and added NO_PROMPT/QUIET config support.
- Improved web workflow robustness (301 normalization, better sql/xss checks, report linkage).

## 3.3.0 - 2025-12-24
- Modular splitter generates XDG‑aware package layout.
- Runtime flags for safety, dry‑run, debug, proxy/Tor, jitter, and JSON logs.
- Improved installer/uninstaller with manifest and rollback.
- Added documentation set, packaging artifacts, and GitHub Actions CI.

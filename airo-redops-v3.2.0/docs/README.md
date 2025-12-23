# All In One RedOps (AIRO) v3.2.0
## Modular Edition with 150+ Commands

### Overview
All In One RedOps (AIRO) is a comprehensive penetration testing framework with modular architecture. It provides 150+ commands across 12 specialized modules for all phases of penetration testing.

### Features
- **Modular Design**: Load only what you need
- **150+ Commands**: Covering all pentest phases
- **Lazy Loading**: Commands load on demand
- **Configurable**: Easy to customize
- **Safe Mode**: Confirmation for dangerous operations
- **Rate Limiting**: Configurable scan speed
- **Wordlists Ready**: Defaults point to SecLists under `$HOME/SecLists`; override via `WORDLIST_DIRSCAN` / `WORDLIST_FUZZURL`
- **PEAS Helper**: `airo getpeas` downloads linPEAS/winPEAS into `$AIRO_HOME/tools/peas`
- **Runtime Flags**: `--fast/--unsafe`, `--delay`, `--rate-limit`, `--safe` to toggle pacing and prompts per run

### Installation
```bash
# 1. Download and extract
unzip airo-redops-v3.2.0.zip
cd airo-redops-v3.2.0

# 2. Run installer
chmod +x install.sh
./install.sh

# 3. Restart terminal or run:
source ~/.bashrc  # or ~/.zshrc

# Optional: set up wordlists (SecLists) and PEAS helpers
git clone https://github.com/danielmiessler/SecLists.git ~/SecLists  # or point WORDLIST_BASE elsewhere
airo getpeas  # download linPEAS/winPEAS into $AIRO_HOME/tools/peas
# Flags (per run): --fast/--unsafe (SAFE_MODE=0, SCAN_DELAY=0, RATE_LIMIT=10000), --safe, --no-delay, --delay=<s>, --rate-limit=<pps>

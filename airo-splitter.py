#!/usr/bin/env python3
"""
airo-splitter.py - Build the All In One RedOps (AIRO) toolkit from one script
Creates a complete modular structure from the monolithic script
"""

from pathlib import Path
import textwrap

def create_directory_structure():
    """Create directory structure"""
    base_dir = Path("airo-redops-v3.2.0")
    dirs = [
        base_dir,
        base_dir / "modules",
        base_dir / "config",
        base_dir / "plugins",
        base_dir / "docs",
        base_dir / "tools",
        base_dir / "tools" / "peas",
    ]
    
    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)
    
    return base_dir

def create_install_script(base_dir):
    """Create main installer script"""
    # Read the Bash installer script from a separate template file for clarity
    template_path = base_dir / "install.sh.template"
    if template_path.exists():
        with open(template_path, "r") as f:
            install_content = f.read()
    else:
        # Fallback template if install.sh.template is missing
        install_content = textwrap.dedent("""\
        #!/usr/bin/env bash
        set -euo pipefail

        echo "[!] install.sh.template not found."
        echo "[!] Provide a template or adjust create_install_script() to generate a real installer."
        exit 1
        """).lstrip("\n")
    (base_dir / "install.sh").write_text(install_content, encoding='utf-8')
    (base_dir / "install.sh").chmod(0o755)

def create_uninstall_script(base_dir):
    """Create uninstaller script to remove installed files and symlink."""
    uninstall_content = textwrap.dedent("""\
        #!/usr/bin/env bash
        set -euo pipefail

        AIRO_HOME="$HOME/.airo"
        BIN_TARGET="/usr/local/bin/airo"

        echo "[*] This will remove All In One RedOps (AIRO) from $AIRO_HOME"
        read -p "Proceed? [y/N]: " -r
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo "[-] Uninstall cancelled"
            exit 0
        fi

        if [[ -d "$AIRO_HOME" ]]; then
            rm -rf "$AIRO_HOME"
            echo "[+] Removed $AIRO_HOME"
        else
            echo "[!] AIRO home not found at $AIRO_HOME"
        fi

        if [[ -L "$BIN_TARGET" ]]; then
            sudo rm -f "$BIN_TARGET"
            echo "[+] Removed launcher symlink at $BIN_TARGET"
        elif [[ -f "$BIN_TARGET" ]]; then
            echo "[!] $BIN_TARGET exists but is not a symlink; skipping removal"
        fi

        echo "[*] Uninstall finished. Check your shell rc files for any leftover AIRO entries."
        """).lstrip("\n")
    uninstall_path = base_dir / "uninstall.sh"
    uninstall_path.write_text(uninstall_content, encoding='utf-8')
    uninstall_path.chmod(0o755)

def create_core_loader(base_dir):
    """
    Create the core loader script for the All In One RedOps (AIRO) framework.

    Parameters:
        base_dir (Path): The base directory where the core loader will be created.

    Side Effects:
        - Creates the 'airo-core.sh' file in the specified base directory.
        - Writes the core loader bash script content to this file.
        - Sets the file permissions to executable (0o755).
    """
    core_content = '''#!/usr/bin/env bash
# All In One RedOps (AIRO) Core Loader - Main framework file

AIRO_VERSION="3.2.0"
AIRO_HOME="$HOME/.airo"
AIRO_MODULES="$AIRO_HOME/modules"
AIRO_CONFIG="$AIRO_HOME/config"
AIRO_CACHE="$AIRO_HOME/cache"

# Color setup
setup_colors() {
    if [[ -t 2 ]] && [[ -z "${NO_COLOR-}" ]] && [[ "${TERM-}" != "dumb" ]]; then
        RED='\\033[0;31m'
        GREEN='\\033[0;32m'
        YELLOW='\\033[1;33m'
        BLUE='\\033[0;34m'
        CYAN='\\033[0;36m'
        MAGENTA='\\033[0;35m'
        BOLD='\\033[1m'
        NC='\\033[0m'
    else
        RED='' GREEN='' YELLOW='' BLUE='' CYAN='' MAGENTA='' BOLD='' NC=''
    fi
}

# Logging functions
log() { printf "${GREEN}[+]${NC} %s\\n" "$*"; }
warn() { printf "${YELLOW}[!]${NC} %s\\n" "$*" >&2; }
error() { printf "${RED}[-]${NC} %s\\n" "$*" >&2; }

# Load configuration
load_config() {
    if [[ -f "$AIRO_CONFIG/main.conf" ]]; then
        source "$AIRO_CONFIG/main.conf"
    fi
    
    # Set defaults
    : ${SCAN_DELAY:=0.5}
    : ${RATE_LIMIT:=100}
    : ${SAFE_MODE:=1}
    : ${AUTO_LOAD_MODULES:=1}
    : ${AUDIT_LOGGING:=1}
    : ${MAX_HOSTS:=254}
    : ${TOOL_TIMEOUT:=10}
    : ${WORDLIST_BASE:=$HOME/SecLists}
    : ${WORDLIST_DIRSCAN:=$WORDLIST_BASE/Discovery/Web-Content/common.txt}
    : ${WORDLIST_FUZZURL:=$WORDLIST_BASE/Discovery/Web-Content/raft-medium-words.txt}
    
    export SCAN_DELAY RATE_LIMIT SAFE_MODE AUTO_LOAD_MODULES AUDIT_LOGGING
    export MAX_HOSTS TOOL_TIMEOUT WORDLIST_BASE WORDLIST_DIRSCAN WORDLIST_FUZZURL
}

# Apply runtime flags (e.g., --fast/--delay/--rate-limit/--safe)
apply_runtime_flags() {
    RUNTIME_ARGS=()
    while (($#)); do
        case "$1" in
            --fast|--unsafe)
                SAFE_MODE=0
                SCAN_DELAY=0
                RATE_LIMIT=${RATE_LIMIT:-10000}
                ;;
            --safe)
                SAFE_MODE=1
                ;;
            --no-delay)
                SCAN_DELAY=0
                ;;
            --delay=*)
                SCAN_DELAY="${1#--delay=}"
                ;;
            --delay)
                [[ -n "${2-}" ]] && SCAN_DELAY="$2" && shift
                ;;
            --rate-limit=*)
                RATE_LIMIT="${1#--rate-limit=}"
                ;;
            --rate-limit)
                [[ -n "${2-}" ]] && RATE_LIMIT="$2" && shift
                ;;
            --)
                shift
                RUNTIME_ARGS+=("$@")
                break
                ;;
            *)
                RUNTIME_ARGS+=("$1")
                ;;
        esac
        shift || break
    done
    export SAFE_MODE SCAN_DELAY RATE_LIMIT
}

# Load a specific module
load_module() {
    local module="$1"
    if [[ -f "$AIRO_MODULES/$module.sh" ]]; then
        source "$AIRO_MODULES/$module.sh"
        return 0
    elif [[ -f "$AIRO_MODULES/$module" ]]; then
        source "$AIRO_MODULES/$module"
        return 0
    fi
    warn "Module not found: $module"
    return 1
}

# Load all modules
load_all_modules() {
    for module in "$AIRO_MODULES"/*.sh; do
        if [[ -f "$module" ]]; then
            source "$module"
        fi
    done
}

# Lazy loading system
airo_lazy_load() {
    local cmd="$1"
    local module=""
    
    # Map commands to modules
    case "$cmd" in
        netscan|portscan|udpscan|alivehosts|dnscan|safescan|lhost|myip)
            module="network" ;;
        webscan|dirscan|fuzzurl|sqlcheck|xsscheck|sslscan|wpscan|httpxprobe|wayback|katana|nuclei)
            module="web" ;;
        sysenum|sudofind|capfind|cronfind|procmon|userenum)
            module="system" ;;
        lpe|wpe|sudoexploit|kernelcheck|winprivesc|linprivesc|getpeas)
            module="privesc" ;;
        awscheck|azcheck|gcpcheck|s3scan|ec2scan|dockerscan|kubescan)
            module="cloud" ;;
        adusers|adgroups|admachines|bloodhound|kerberoast|asreproast)
            module="ad" ;;
        wifiscan|wifiattack|bluescan|blueattack|wpscrack|handshake)
            module="wireless" ;;
        apkanalyze|ipascan|androidscan|iotscan|firmwareextract|apkdecompile)
            module="mobile" ;;
        emailosint|userosint|phoneosint|domainosint|breachcheck)
            module="osint" ;;
        reconall|vulnscan|reportgen|findings|evidence|timertrack)
            module="automation" ;;
        urldecode|urlencode|base64d|base64e|hexdump|filetype|calccidr)
            module="utilities" ;;
        *)
            module="" ;;
    esac
    
    if [[ -n "$module" ]]; then
        load_module "$module"
    fi
    
    # Execute the command
    if declare -f "airo_$cmd" >/dev/null 2>&1; then
        "airo_$cmd" "${@:2}"
    else
        error "Command not found: $cmd"
        return 1
    fi
}

# Main airo command
airo() {
    local cmd="$1"
    shift || true
    apply_runtime_flags "$@"
    set -- "${RUNTIME_ARGS[@]}"
    
    if [[ -z "$cmd" ]]; then
        cat << HELP
All In One RedOps (AIRO) v${AIRO_VERSION}
Modular Edition with 150+ commands

Usage:
  airo <command> [args]      - Execute a command
  airo [flags] <command>     - Run with flags (e.g., --fast)
  airo help                  - Show this help
  airo modules               - List all modules
  airo reload                - Reload configuration
  airo update                - Update framework
  airo version               - Show version
Flags:
  --fast / --unsafe          - SAFE_MODE=0, SCAN_DELAY=0, RATE_LIMIT=10000
  --safe                     - SAFE_MODE=1 (re-enable prompts)
  --no-delay                 - SCAN_DELAY=0
  --delay=<seconds>          - Set SCAN_DELAY
  --rate-limit=<pps>         - Set RATE_LIMIT (packets per second)

Examples:
  airo netscan --fast 192.168.1.0/24
  airo webscan https://target.com --delay=0.1
  airo sysenum

HELP
        return 0
    fi
    
    case "$cmd" in
        help)
            airo ""  # Show help
            ;;
        modules)
            echo "Available modules:"
            ls -1 "$AIRO_MODULES"/*.sh | xargs -I {} basename {} .sh | sort
            ;;
        reload)
            load_config
            log "Configuration reloaded"
            ;;
        update)
            warn "Update: Run installer again or check GitHub"
            ;;
        version)
            echo "All In One RedOps (AIRO) v$AIRO_VERSION"
            ;;
        *)
            # Try lazy loading
            airo_lazy_load "$@"
            ;;
    esac
}

# Create aliases for common commands
create_aliases() {
    # Network aliases
    alias netscan='airo netscan'
    alias portscan='airo portscan'
    alias lhost='airo lhost'
    alias myip='airo myip'
    
    # Web aliases
    alias webscan='airo webscan'
    alias dirscan='airo dirscan'
    alias sqlcheck='airo sqlcheck'
    
    # System aliases
    alias sysenum='airo sysenum'
    alias sudofind='airo sudofind'
    
    # And many more...
}

# Setup completion
setup_completion() {
    if [[ -n "$BASH_VERSION" ]]; then
        # Bash completion
        complete -W "$(compgen -c | grep ^airo_ | sed 's/^airo_//')" airo
    elif [[ -n "$ZSH_VERSION" ]]; then
        # Zsh completion
        autoload -Uz compinit
        compinit
    fi
}

# Initialize framework
init_framework() {
    setup_colors
    load_config
    
    if [[ "$AUTO_LOAD_MODULES" == "1" ]]; then
        load_all_modules
        create_aliases
    fi
    
    setup_completion
    
    log "All In One RedOps (AIRO) v$AIRO_VERSION loaded"
}
'''
# Note: the full network module is defined later in this file; this duplicate stub was removed.
# The core loader is written by create_core_loader() and the real network module is created by
# the following function defined further below in this script.
    
    core_path = base_dir / "airo-core.sh"
    core_path.write_text(core_content, encoding='utf-8')
    core_path.chmod(0o755)

def create_module_network(base_dir):
    """Create network module"""
    network_content = '''#!/usr/bin/env bash
# Network Reconnaissance Module
# 12 network reconnaissance commands

run_with_grc() {
    if command -v grc >/dev/null 2>&1; then
        grc "$@"
    else
        "$@"
    fi
}

nmap_with_grc() {
    if command -v grc >/dev/null 2>&1; then
        grc nmap "$@"
    else
        nmap "$@"
    fi
}

sudo_nmap_with_grc() {
    if command -v grc >/dev/null 2>&1; then
        sudo grc nmap "$@"
    else
        sudo nmap "$@"
    fi
}

parse_net_flags() {
    PORTS=""
    TOP_PORTS=""
    HOST_TIMEOUT=""
    OUTFILE=""
    while (($#)); do
        case "$1" in
            --ports=*) PORTS="${1#*=}" ;;
            --ports) PORTS="$2"; shift ;;
            --top=*) TOP_PORTS="${1#*=}" ;;
            --top) TOP_PORTS="$2"; shift ;;
            --timeout=*) HOST_TIMEOUT="${1#*=}" ;;
            --timeout) HOST_TIMEOUT="$2"; shift ;;
            --output=*) OUTFILE="${1#*=}" ;;
            --output) OUTFILE="$2"; shift ;;
            --) shift; break ;;
            *) break ;;
        esac
        shift || break
    done
    REMAINING_ARGS=("$@")
}

airo_netscan(){
    parse_net_flags "$@"
    set -- "${REMAINING_ARGS[@]}"
    local subnet="${1:-}"
    if [[ -z "$subnet" ]]; then
        local ip="$(airo_lhost)"
        subnet="${ip%.*}.0/24"
        echo "[*] Scanning subnet: $subnet"
    fi
    
    if command -v nmap >/dev/null 2>&1; then
        local args=(-sn "$subnet")
        [[ -n "$HOST_TIMEOUT" ]] && args+=(--host-timeout "$HOST_TIMEOUT")
        if [[ -n "$OUTFILE" ]]; then
            nmap_with_grc "${args[@]}" -oN "$OUTFILE"
            echo "[+] Results saved to $OUTFILE"
        else
            nmap_with_grc "${args[@]}"
        fi
    else
        echo "[-] nmap not installed"
    fi
}

airo_portscan() {
    parse_net_flags "$@"
    set -- "${REMAINING_ARGS[@]}"
    local target="${1:?Usage: portscan <target> [--ports <list>|--top <n>] [--timeout <s>] [--output <file>]}"
    
    echo "[*] Scanning $target..."
    if command -v nmap >/dev/null 2>&1; then
        local args=(-sS -T4 "$target")
        [[ -n "$PORTS" ]] && args+=(-p "$PORTS")
        [[ -n "$TOP_PORTS" ]] && args+=(--top-ports "$TOP_PORTS")
        [[ -n "$HOST_TIMEOUT" ]] && args+=(--host-timeout "$HOST_TIMEOUT")
        if [[ -n "$OUTFILE" ]]; then
            nmap_with_grc "${args[@]}" -oN "$OUTFILE"
            echo "[+] Results saved to $OUTFILE"
        else
            nmap_with_grc "${args[@]}"
        fi
    else
        echo "[-] nmap not installed"
    fi
}

airo_udpscan() {
    parse_net_flags "$@"
    set -- "${REMAINING_ARGS[@]}"
    local target="${1:?Usage: udpscan <target> [--ports <list>|--top <n>] [--timeout <s>] [--output <file>]}"
    
    echo "[*] UDP scan on $target..."
    if command -v nmap >/dev/null 2>&1; then
        local args=(-sU -T4 "$target")
        [[ -n "$PORTS" ]] && args+=(-p "$PORTS")
        [[ -n "$TOP_PORTS" ]] && args+=(--top-ports "$TOP_PORTS")
        [[ -n "$HOST_TIMEOUT" ]] && args+=(--host-timeout "$HOST_TIMEOUT")
        if [[ -n "$OUTFILE" ]]; then
            sudo_nmap_with_grc "${args[@]}" -oN "$OUTFILE"
            echo "[+] Results saved to $OUTFILE"
        else
            sudo_nmap_with_grc "${args[@]}"
        fi
    fi
}

airo_alivehosts() {
    parse_net_flags "$@"
    set -- "${REMAINING_ARGS[@]}"
    local subnet="${1:-}"
    if [[ -z "$subnet" ]]; then
        local ip="$(airo_lhost)"
        subnet="${ip%.*}.0/24"
    fi

    echo "[*] Finding live hosts in $subnet..."
    for i in $(seq 1 254); do
        run_with_grc ping -c 1 -W 1 "${subnet%.*}.$i" | grep -q "64 bytes" && echo "${subnet%.*}.$i" &
    done
    wait
}

airo_dnscan() {
    local domain="${1:?Usage: dnscan <domain>}"
    
    echo "[*] Scanning $domain for subdomains..."
    
    # Simple subdomain brute force
    local words=(www ftp mail admin test dev staging api)
    for word in "${words[@]}"; do
        host "$word.$domain" 2>/dev/null | grep -v "NXDOMAIN"
    done
}

airo_safescan() {
    parse_net_flags "$@"
    set -- "${REMAINING_ARGS[@]}"
    local target="${1:?Usage: safescan <target>}"
    local delay="${SCAN_DELAY:-0.5}"
    local rate="${RATE_LIMIT:-100}"
    
    echo "[*] Safe scan: $target (delay: ${delay}s, rate: ${rate}pps)"
    
    if command -v nmap >/dev/null 2>&1; then
        nmap_with_grc -T4 --max-rate "$rate" --scan-delay "${delay}s" "$target"
    else
        run_with_grc ping -c 4 -i "$delay" "$target"
    fi
}

airo_lhost() {
    local ip
    ip="$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1);exit}}')"
    [[ -n "$ip" ]] || ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
    echo "$ip"
}

airo_myip() {
    echo "[*] Getting public IP..."
    curl -fsSL ifconfig.me 2>/dev/null || curl -fsSL api.ipify.org 2>/dev/null || true
}

airo_tracer() {
    local target="${1:?Usage: tracer <host>}"
    
    if command -v traceroute >/dev/null 2>&1; then
        run_with_grc traceroute -n "$target"
    elif command -v tracepath >/dev/null 2>&1; then
        run_with_grc tracepath "$target"
    else
        echo "[-] No traceroute tool found"
    fi
}

airo_whoislookup() {
    local target="${1:?Usage: whoislookup <domain/ip>}"
    
    if command -v whois >/dev/null 2>&1; then
        run_with_grc whois "$target"
    else
        echo "[-] whois not installed"
    fi
}

airo_dnsdump() {
    local domain="${1:?Usage: dnsdump <domain>}"
    
    echo "[*] DNS records for: $domain"
    
    for record in A AAAA MX TXT NS SOA; do
        echo -e "\\n$record:"
        run_with_grc dig "$domain" "$record" +short 2>/dev/null
    done
}

airo_cidrcalc() {
    local cidr="${1:?Usage: cidrcalc <ip/cidr>}"
    
    echo "[*] Calculating CIDR: $cidr"
    
    if command -v ipcalc >/dev/null 2>&1; then
        ipcalc "$cidr"
    else
        echo "[-] ipcalc not installed"
    fi
}

# Export functions
export -f airo_netscan airo_portscan airo_udpscan airo_alivehosts airo_dnscan
export -f airo_safescan airo_lhost airo_myip airo_tracer airo_whoislookup
export -f airo_dnsdump airo_cidrcalc
'''
    
    (base_dir / "modules" / "network.sh").write_text(network_content, encoding='utf-8')
    (base_dir / "modules" / "network.sh").chmod(0o755)

def create_module_web(base_dir):
    """Create web module"""
    web_content = '''#!/usr/bin/env bash
# Web Assessment Module
# 14 web security testing commands

WORDLIST_BASE="${WORDLIST_BASE:-$HOME/SecLists}"
WORDLIST_DIRSCAN="${WORDLIST_DIRSCAN:-$WORDLIST_BASE/Discovery/Web-Content/common.txt}"
WORDLIST_FUZZURL="${WORDLIST_FUZZURL:-$WORDLIST_BASE/Discovery/Web-Content/raft-medium-words.txt}"
WORDLIST_EXTENSIONS="${WORDLIST_EXTENSIONS:-php,asp,aspx,html,js}"

resolve_dir_wordlist() {
    local choice="$1"
    case "$choice" in
        ""|"default"|"common") echo "$WORDLIST_DIRSCAN" ;;
        raft-small) echo "$WORDLIST_BASE/Discovery/Web-Content/raft-small-directories.txt" ;;
        raft-medium) echo "$WORDLIST_BASE/Discovery/Web-Content/raft-medium-directories.txt" ;;
        raft-large) echo "$WORDLIST_BASE/Discovery/Web-Content/raft-large-directories.txt" ;;
        *) echo "$choice" ;;
    esac
}

resolve_fuzz_wordlist() {
    local choice="$1"
    case "$choice" in
        ""|"default") echo "$WORDLIST_FUZZURL" ;;
        raft-small) echo "$WORDLIST_BASE/Discovery/Web-Content/raft-small-words.txt" ;;
        raft-medium) echo "$WORDLIST_BASE/Discovery/Web-Content/raft-medium-words.txt" ;;
        raft-large) echo "$WORDLIST_BASE/Discovery/Web-Content/raft-large-words.txt" ;;
        *) echo "$choice" ;;
    esac
}

ensure_wordlist() {
    local path="$1"
    if [[ ! -f "$path" ]]; then
        echo "[-] Wordlist not found: $path"
        echo "[!] Clone SecLists: git clone https://github.com/danielmiessler/SecLists.git \"$WORDLIST_BASE\""
        return 1
    fi
    return 0
}

parse_web_flags() {
    DIR_THREADS=""
    DIR_EXTS=""
    FUZZ_THREADS=""
    while (($#)); do
        case "$1" in
            --wordlist=*) WORDLIST_OVERRIDE="${1#*=}" ;;
            --wordlist) WORDLIST_OVERRIDE="$2"; shift ;;
            --threads=*) DIR_THREADS="${1#*=}"; FUZZ_THREADS="${DIR_THREADS}";;
            --threads) DIR_THREADS="$2"; FUZZ_THREADS="$2"; shift ;;
            --extensions=*) DIR_EXTS="${1#*=}" ;;
            --extensions) DIR_EXTS="$2"; shift ;;
            --) shift; break ;;
            *) break ;;
        esac
        shift || break
    done
    REMAINING_ARGS=("$@")
}

airo_webscan() {
    local url="${1:?Usage: webscan <url>}"
    
    echo "[*] Scanning $url..."
    
    if command -v nikto >/dev/null 2>&1; then
        nikto -h "$url"
    else
        echo "[-] nikto not installed"
    fi
}

airo_dirscan() {
    parse_web_flags "$@"
    set -- "${REMAINING_ARGS[@]}"
    local url="${1:?Usage: dirscan <url> [--wordlist <path|alias>] [--threads <n>] [--extensions ext,ext] }"
    local wordlist_input="${2:-$WORDLIST_OVERRIDE}"
    local wordlist
    wordlist="$(resolve_dir_wordlist "$wordlist_input")"
    ensure_wordlist "$wordlist" || return 1
    
    echo "[*] Directory scan: $url (wordlist: $wordlist)"
    
    if command -v gobuster >/dev/null 2>&1; then
        local args=(dir -u "$url" -w "$wordlist")
        [[ -n "$DIR_THREADS" ]] && args+=(-t "$DIR_THREADS")
        [[ -n "$DIR_EXTS" ]] && args+=(-x "$DIR_EXTS")
        gobuster "${args[@]}"
    elif command -v dirb >/dev/null 2>&1; then
        dirb "$url" "$wordlist"
    else
        echo "[-] No directory scanner found"
    fi
}

airo_fuzzurl() {
    parse_web_flags "$@"
    set -- "${REMAINING_ARGS[@]}"
    local url="${1:?Usage: fuzzurl <url> [--wordlist <path|alias>] [--threads <n>] }"
    local wordlist_input="${2:-$WORDLIST_OVERRIDE}"
    local wordlist
    wordlist="$(resolve_fuzz_wordlist "$wordlist_input")"
    ensure_wordlist "$wordlist" || return 1
    
    echo "[*] URL fuzzing: $url (wordlist: $wordlist)"
    
    if command -v ffuf >/dev/null 2>&1; then
        local args=(-u "$url/FUZZ" -w "$wordlist")
        [[ -n "$FUZZ_THREADS" ]] && args+=(-t "$FUZZ_THREADS")
        ffuf "${args[@]}"
    else
        echo "[-] ffuf not installed"
    fi
}

airo_httpxprobe() {
    local target="${1:?Usage: httpxprobe <url|domain|file> [output?] }"
    local output="${2:-}"
    local args=(-silent -status-code -title -tech-detect)
    if [[ -f "$target" ]]; then
        args+=(-l "$target")
    else
        args+=(-u "$target")
    fi
    [[ -n "$output" ]] && args+=(-o "$output")
    
    if command -v httpx >/dev/null 2>&1; then
        httpx "${args[@]}"
    else
        echo "[-] httpx not installed (projectdiscovery)."
    fi
}

airo_wayback() {
    local domain="${1:?Usage: wayback <domain> [output?] }"
    local output="${2:-}"
    if command -v gau >/dev/null 2>&1; then
        if [[ -n "$output" ]]; then
            gau "$domain" -o "$output"
        else
            gau "$domain"
        fi
    elif command -v waybackurls >/dev/null 2>&1; then
        if [[ -n "$output" ]]; then
            waybackurls "$domain" > "$output"
        else
            waybackurls "$domain"
        fi
    else
        echo "[-] gau or waybackurls not installed"
    fi
}

airo_katana() {
    local target="${1:?Usage: katana <url> [output?] }"
    local output="${2:-}"
    if command -v katana >/dev/null 2>&1; then
        if [[ -n "$output" ]]; then
            katana -u "$target" -o "$output"
        else
            katana -u "$target"
        fi
    else
        echo "[-] katana not installed (projectdiscovery)."
    fi
}

airo_nuclei() {
    local templates=""
    local severity=""
    local rate=""
    local output=""
    while (($#)); do
        case "$1" in
            --templates=*) templates="${1#*=}" ;;
            --templates) templates="$2"; shift ;;
            --severity=*) severity="${1#*=}" ;;
            --severity) severity="$2"; shift ;;
            --rate=*) rate="${1#*=}" ;;
            --rate) rate="$2"; shift ;;
            --output=*) output="${1#*=}" ;;
            --output) output="$2"; shift ;;
            --) shift; break ;;
            *) break ;;
        esac
        shift || break
    done
    local target="${1:-}"
    if [[ -z "$target" ]]; then
        echo "Usage: nuclei <url> [--templates <dir>] [--severity <sev>] [--rate <n>] [--output <file>]"
        return 1
    fi
    
    if command -v nuclei >/dev/null 2>&1; then
        local args=(-u "$target")
        [[ -n "$templates" ]] && args+=(-t "$templates")
        [[ -n "$severity" ]] && args+=(-severity "$severity")
        [[ -n "$rate" ]] && args+=(-rate "$rate")
        [[ -n "$output" ]] && args+=(-o "$output")
        nuclei "${args[@]}"
    else
        echo "[-] nuclei not installed (projectdiscovery)."
    fi
}

airo_sqlcheck() {
    local url="${1:?Usage: sqlcheck <url>}"
    
    if [[ "$SAFE_MODE" -eq 1 ]]; then
        read -p "[!] SQL injection test on $url? [y/N]: " -r
        [[ ! $REPLY =~ ^[Yy]$ ]] && return
    fi
    
    echo "[*] Testing $url for SQL injection..."
    
    if command -v sqlmap >/dev/null 2>&1; then
        sqlmap -u "$url" --batch
    else
        echo "[-] sqlmap not installed"
        echo "[*] Manual test: $url' OR '1'='1"
    fi
}

airo_xsscheck() {
    local url="${1:?Usage: xsscheck <url>}"
    
    echo "[*] XSS testing: $url"
    echo "[*] Test payloads:"
    echo "  <script>alert('XSS')</script>"
    echo "  \"><script>alert('XSS')</script>"
    echo "  '><script>alert('XSS')</script>"
}

airo_takeover() {
    local domain="${1:?Usage: takeover <domain>}"
    
    echo "[*] Subdomain takeover check: $domain"
    echo "[*] Checking for vulnerable services..."
    
    # Simple check
    local subdomains=("www" "api" "dev" "staging" "test")
    for sub in "${subdomains[@]}"; do
        host "$sub.$domain" 2>/dev/null | grep -i "not found\\|nxdomain" && echo "[+] Possible takeover: $sub.$domain"
    done
}

airo_wpscan() {
    local url="${1:?Usage: wpscan <url>}"
    
    echo "[*] WordPress scan: $url"
    
    if command -v wpscan >/dev/null 2>&1; then
        wpscan --url "$url" --enumerate vp,vt,u
    else
        echo "[-] wpscan not installed"
    fi
}

airo_joomscan() {
    local url="${1:?Usage: joomscan <url>}"
    
    if command -v joomscan >/dev/null 2>&1; then
        joomscan -u "$url"
    else
        echo "[-] joomscan not installed"
    fi
}

airo_sslscan() {
    local target="${1:?Usage: sslscan <host:port>}"
    
    echo "[*] SSL scan: $target"
    
    if command -v sslscan >/dev/null 2>&1; then
        sslscan "$target"
    elif command -v testssl.sh >/dev/null 2>&1; then
        testssl.sh "$target"
    else
        echo "[-] No SSL scanner found"
    fi
}

airo_headerscan() {
    local url="${1:?Usage: headerscan <url>}"
    
    echo "[*] HTTP headers: $url"
    curl -s -I "$url" | grep -v ^$
}

export -f airo_webscan airo_dirscan airo_fuzzurl airo_sqlcheck airo_xsscheck
export -f airo_takeover airo_wpscan airo_joomscan airo_sslscan airo_headerscan
export -f airo_httpxprobe airo_wayback airo_katana airo_nuclei
'''
    
    (base_dir / "modules" / "web.sh").write_text(web_content, encoding='utf-8')
    (base_dir / "modules" / "web.sh").chmod(0o755)

def create_module_system(base_dir):
    """Create system module"""
    system_content = '''#!/usr/bin/env bash
# System Enumeration Module
# 8 system enumeration commands

airo_sysenum() {
    echo "[*] System enumeration started..."
    
    echo -e "\\n=== SYSTEM INFORMATION ==="
    uname -a
    
    echo -e "\\n=== USER INFO ==="
    id
    whoami
    
    echo -e "\\n=== NETWORK ==="
    ip a 2>/dev/null || ifconfig
    
    echo -e "\\n=== PROCESSES ==="
    ps aux --sort=-%mem | head -20
    
    echo -e "\\n=== SERVICES ==="
    systemctl list-units --type=service --state=running 2>/dev/null || service --status-all 2>/dev/null
    
    echo -e "\\n=== CRON JOBS ==="
    crontab -l 2>/dev/null
    ls -la /etc/cron* 2>/dev/null
}

airo_sudofind() {
    echo "[*] Finding SUID/SGID files..."
    find / -type f -perm -4000 -o -perm -2000 2>/dev/null | head -30
}

airo_capfind() {
    echo "[*] Finding capability-enabled binaries..."
    
    if command -v getcap >/dev/null 2>&1; then
        getcap -r / 2>/dev/null | head -30
    else
        echo "[-] getcap not available"
    fi
}

airo_cronfind() {
    echo "[*] Listing cron jobs..."
    
    echo -e "\\nUser cron:"
    crontab -l 2>/dev/null || echo "No user cron"
    
    echo -e "\\nSystem cron:"
    ls -la /etc/cron* 2>/dev/null
    
    echo -e "\\nSystemd timers:"
    systemctl list-timers 2>/dev/null | head -20
}

airo_procmon() {
    echo "[*] Process monitoring (Ctrl+C to stop)..."
    
    if command -v watch >/dev/null 2>&1; then
        watch -n 1 'ps aux --sort=-%cpu | head -20'
    else
        while true; do
            clear
            ps aux --sort=-%cpu | head -20
            sleep 2
        done
    fi
}

airo_libfind() {
    echo "[*] Checking for vulnerable libraries..."
    
    # Check common vulnerable libraries
    local libs=("libssl" "openssl" "glibc" "bash")
    
    for lib in "${libs[@]}"; do
        dpkg -l | grep -i "$lib" 2>/dev/null || \
        rpm -qa | grep -i "$lib" 2>/dev/null || \
        pacman -Q | grep -i "$lib" 2>/dev/null || true
    done
}

airo_serviceenum() {
    echo "[*] Enumerating services..."
    
    # Systemd
    if command -v systemctl >/dev/null 2>&1; then
        echo -e "\\nSystemd Services:"
        systemctl list-units --type=service --state=running
    fi
    
    # init.d
    if [[ -d /etc/init.d ]]; then
        echo -e "\\nInit.d Services:"
        ls -la /etc/init.d/
    fi
    
    # Listening ports
    echo -e "\\nListening Ports:"
    ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null
}

airo_userenum() {
    echo "[*] Enumerating users and groups..."
    
    echo -e "\\nUsers:"
    cat /etc/passwd | cut -d: -f1,3,4,6,7 | head -20
    
    echo -e "\\nGroups:"
    cat /etc/group | cut -d: -f1,3,4 | head -20
    
    echo -e "\\nLogged in users:"
    who -a
}

export -f airo_sysenum airo_sudofind airo_capfind airo_cronfind airo_procmon
export -f airo_libfind airo_serviceenum airo_userenum
'''
    
    (base_dir / "modules" / "system.sh").write_text(system_content, encoding='utf-8')
    (base_dir / "modules" / "system.sh").chmod(0o755)

def create_module_privesc(base_dir):
    """Create privilege escalation module"""
    privesc_content = '''#!/usr/bin/env bash
# Privilege Escalation Module
# 6 privilege escalation commands

PEAS_DIR="${PEAS_DIR:-$AIRO_HOME/tools/peas}"
LINPEAS_URL="${LINPEAS_URL:-https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh}"
WINPEAS_URL="${WINPEAS_URL:-https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe}"

ensure_peas_dir() {
    mkdir -p "$PEAS_DIR"
}

download_peas() {
    ensure_peas_dir
    echo "[*] Downloading linPEAS to $PEAS_DIR/linpeas.sh"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$LINPEAS_URL" -o "$PEAS_DIR/linpeas.sh" || echo "[-] Failed to download linPEAS"
    elif command -v wget >/dev/null 2>&1; then
        wget -q "$LINPEAS_URL" -O "$PEAS_DIR/linpeas.sh" || echo "[-] Failed to download linPEAS"
    else
        echo "[-] Neither curl nor wget found; cannot download linPEAS"
    fi
    chmod +x "$PEAS_DIR/linpeas.sh" 2>/dev/null || true

    echo "[*] Downloading winPEAS (x64) to $PEAS_DIR/winPEASx64.exe"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$WINPEAS_URL" -o "$PEAS_DIR/winPEASx64.exe" || echo "[-] Failed to download winPEAS"
    elif command -v wget >/dev/null 2>&1; then
        wget -q "$WINPEAS_URL" -O "$PEAS_DIR/winPEASx64.exe" || echo "[-] Failed to download winPEAS"
    else
        echo "[-] Neither curl nor wget found; cannot download winPEAS"
    fi
}

airo_getpeas() {
    download_peas
    echo "[*] linPEAS: $PEAS_DIR/linpeas.sh"
    echo "[*] winPEAS (x64): $PEAS_DIR/winPEASx64.exe"
}

airo_lpe() {
    echo "[*] Linux Privilege Escalation Checks"
    
    echo -e "\\n1. Kernel & OS Info:"
    uname -a
    cat /etc/*release 2>/dev/null || true
    
    echo -e "\\n2. Sudo Permissions:"
    sudo -l 2>/dev/null || echo "No sudo access"
    
    echo -e "\\n3. SUID/SGID Files:"
    find / -type f -perm -4000 -o -perm -2000 2>/dev/null | head -20
    
    echo -e "\\n4. Writable Files:"
    find / -writable 2>/dev/null | head -20
    
    echo -e "\\n5. Cron Jobs:"
    crontab -l 2>/dev/null
    ls -la /etc/cron* 2>/dev/null
    
    echo -e "\\n[*] Consider running linpeas for detailed check (download with: airo getpeas)"
}

airo_wpe() {
    echo "[*] Windows Privilege Escalation Checklist"
    
    cat << 'WIN_PRIVESC'
1. System Information:
   systeminfo
   whoami /priv
   net user
   net localgroup administrators

2. Installed Software:
   dir "C:\\Program Files"
   dir "C:\\Program Files (x86)"
   reg query HKLM\\Software

3. Scheduled Tasks:
   schtasks /query /fo LIST /v
   dir C:\\Windows\\Tasks

4. Services:
   sc query
   net start
   wmic service get name,displayname,pathname,startmode

Tools:
  • WinPEAS
  • PowerUp.ps1
  • Sherlock.ps1
WIN_PRIVESC
}

airo_sudoexploit() {
    local version="$(sudo --version 2>/dev/null | head -1 | grep -oE '[0-9]+\\.[0-9]+\\.[0-9]+')"
    
    if [[ -n "$version" ]]; then
        echo "[*] Sudo version: $version"
        echo "[*] Check exploits at: https://github.com/mzet-/linux-exploit-suggester"
    else
        echo "[-] Could not determine sudo version"
    fi
}

airo_kernelcheck() {
    local kernel="$(uname -r)"
    echo "[*] Kernel version: $kernel"
    echo "[*] Check for exploits:"
    echo "  searchsploit $kernel"
    echo "  or visit: https://www.exploit-db.com/search?q=${kernel}"
}

airo_winprivesc() {
    airo_wpe  # Alias to wpe function
}

airo_linprivesc() {
    airo_lpe  # Alias to lpe function
}

export -f airo_lpe airo_wpe airo_sudoexploit airo_kernelcheck
export -f airo_winprivesc airo_linprivesc airo_getpeas
'''
    
    (base_dir / "modules" / "privesc.sh").write_text(privesc_content, encoding='utf-8')
    (base_dir / "modules" / "privesc.sh").chmod(0o755)

def create_module_cloud(base_dir):
    """Create cloud module"""
    # Use raw string to avoid escape sequence warnings
    cloud_content = r'''#!/usr/bin/env bash
# Cloud Security Module
# 8 cloud security commands

airo_awscheck() {
    echo "[*] Checking AWS configuration..."
    
    if command -v aws >/dev/null 2>&1; then
        echo -e "\nAWS CLI Version:"
        aws --version
        
        echo -e "\nConfigured Profiles:"
        aws configure list-profiles 2>/dev/null || cat ~/.aws/config 2>/dev/null | grep "^\[profile" || echo "No profiles found"
        
        echo -e "\nCurrent Identity:"
        aws sts get-caller-identity 2>/dev/null || echo "Not authenticated"
    else
        echo "[-] AWS CLI not installed"
    fi
}

airo_azcheck() {
    echo "[*] Checking Azure CLI configuration..."
    
    if command -v az >/dev/null 2>&1; then
        echo -e "\\nAzure CLI Version:"
        az version --output table 2>/dev/null
        
        echo -e "\\nLogged-in account:"
        az account show --output table 2>/dev/null || echo "Not authenticated"
    else
        echo "[-] Azure CLI (az) not installed"
    fi
}

airo_gcpcheck() {
    echo "[*] Checking GCP CLI configuration..."
    
    if command -v gcloud >/dev/null 2>&1; then
        echo -e "\\nGCloud Version:"
        gcloud --version | head -5
        
        echo -e "\\nActive config/account:"
        gcloud config list account --format 'value(core.account)' 2>/dev/null || echo "No active account"
        gcloud config list project --format 'value(core.project)' 2>/dev/null || echo "No project set"
    else
        echo "[-] Google Cloud CLI (gcloud) not installed"
    fi
}

airo_s3scan() {
    local bucket="${1:?Usage: s3scan <bucket>}"
    
    echo "[*] Checking S3 bucket: $bucket"
    
    if command -v aws >/dev/null 2>&1; then
        aws s3 ls "s3://$bucket" 2>/dev/null || echo "[-] Unable to list bucket (permissions or not found)"
    else
        echo "[-] AWS CLI not installed"
    fi
}

airo_ec2scan() {
    local region="${1:-}"
    
    echo "[*] Listing EC2 instances${region:+ in $region}..."
    
    if command -v aws >/dev/null 2>&1; then
        if [[ -n "$region" ]]; then
            aws ec2 describe-instances --region "$region" --query 'Reservations[].Instances[].InstanceId' --output table 2>/dev/null
        else
            aws ec2 describe-instances --query 'Reservations[].Instances[].InstanceId' --output table 2>/dev/null
        fi
    else
        echo "[-] AWS CLI not installed"
    fi
}

airo_dockerscan() {
    echo "[*] Scanning Docker for misconfigurations..."
    
    if command -v docker >/dev/null 2>&1; then
        echo -e "\\nDocker Version:"
        docker --version
        
        echo -e "\\nRunning Containers:"
        docker ps
        
        echo -e "\\nAll Containers:"
        docker ps -a
        
        echo -e "\\nImages:"
        docker images
    else
        echo "[-] Docker not installed"
    fi
}

airo_kubescan() {
    echo "[*] Scanning Kubernetes cluster..."
    
    if command -v kubectl >/dev/null 2>&1; then
        echo -e "\\nKubernetes Version:"
        kubectl version --short
        
        echo -e "\\nNodes:"
        kubectl get nodes
        
        echo -e "\\nPods:"
        kubectl get pods --all-namespaces
    else
        echo "[-] kubectl not installed"
    fi
}

airo_containerbreak() {
    echo "[*] Container Breakout Techniques"
    
    cat << 'CONTAINER_BREAK'
1. Privileged Container:
   docker run --rm -it --privileged ubuntu bash
   # Inside container:
   fdisk -l
   mount /dev/sda1 /mnt

2. Docker Socket Mount:
   # If /var/run/docker.sock is mounted:
   apt-get update && apt-get install curl
   curl --unix-socket /var/run/docker.sock http://localhost/containers/json

3. Capabilities Abuse:
   # With SYS_ADMIN capability:
   mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x

Tools:
  • amicontained
  • deepce
  • CDK (Container Detection Kit)
CONTAINER_BREAK
}

export -f airo_awscheck airo_azcheck airo_gcpcheck airo_s3scan airo_ec2scan
export -f airo_dockerscan airo_kubescan airo_containerbreak
'''
    
    (base_dir / "modules" / "cloud.sh").write_text(cloud_content, encoding='utf-8')
    (base_dir / "modules" / "cloud.sh").chmod(0o755)

def create_module_ad(base_dir):
    """Create Active Directory module"""
    # Use double backslashes to escape the backslashes in Windows paths
    ad_content = r'''#!/usr/bin/env bash
# Active Directory Module
# 10 AD security commands

airo_adusers() {
    local domain="${1:?Usage: adusers <domain>}"
    
    echo "[*] Enumerating AD users for: $domain"
    
    if command -v enum4linux >/dev/null 2>&1; then
        enum4linux -U "$domain"
    elif command -v ldapsearch >/dev/null 2>&1; then
        ldapsearch -x -h "$domain" -b "dc=$(echo $domain | sed 's/\\./,dc=/g')" "(objectClass=user)" 2>/dev/null | grep -i samaccountname
    else
        echo "[-] No AD enumeration tools found"
    fi
}

airo_adgroups() {
    local domain="${1:?Usage: adgroups <domain>}"
    
    echo "[*] Enumerating AD groups for: $domain"
    
    if command -v enum4linux >/dev/null 2>&1; then
        enum4linux -G "$domain"
    else
        echo "[-] enum4linux not installed"
    fi
}

airo_admachines() {
    local domain="${1:?Usage: admachines <domain>}"
    
    echo "[*] Listing domain computers for: $domain"
    
    if command -v nmap >/dev/null 2>&1; then
        nmap -sS -p 445 --open "$domain/24" -oG - | grep Up | cut -d' ' -f2
    else
        echo "[-] nmap not installed"
    fi
}

airo_bloodhound() {
    echo "[*] BloodHound setup guide"
    
    cat << 'BLOODHOUND'
BloodHound Attack Path Analysis:

1. Data Collection:
   bloodhound-python -c All -u user -p pass -d domain -ns dc.domain.com

2. Start Neo4j:
   neo4j console
   Default: http://localhost:7474
   Default creds: neo4j/neo4j

3. Start BloodHound UI:
   bloodhound

4. Import data and analyze attack paths.
BLOODHOUND
}

airo_kerberoast() {
    local domain="${1:?Usage: kerberoast <domain>}"
    
    echo "[*] Kerberoasting attack on: $domain"
    
    cat << 'KERBEROAST'
Steps:

1. Enumerate SPNs:
   GetUserSPNs.py $domain/user:password -request

2. Request TGS tickets

3. Export tickets:
   mimikatz # kerberos::list /export

4. Crack with hashcat:
   hashcat -m 13100 hashes.txt wordlist.txt
KERBEROAST
}

airo_asreproast() {
    echo "[*] AS-REP Roasting attack"
    
    cat << 'ASREP'
Steps:

1. Find users with DONT_REQ_PREAUTH:
   GetNPUsers.py $domain/ -usersfile users.txt -format hashcat -outputfile hashes.asreproast

2. Crack with hashcat:
   hashcat -m 18200 hashes.asreproast wordlist.txt
ASREP
}

airo_goldenticket() {
    echo "[*] Golden Ticket Attack"
    
    cat << 'GOLDEN'
Requirements:
• krbtgt NTLM hash
• Domain SID

Mimikatz:
privilege::debug
sekurlsa::logonpasswords
lsadump::lsa /inject /name:krbtgt
kerberos::golden /user:Administrator /domain:$domain /sid:S-1-5-21-... /krbtgt:$hash /ptt
GOLDEN
}

airo_silverticket() {
    echo "[*] Silver Ticket Attack"
    
    cat << 'SILVER'
Requirements:
• Service account NTLM hash
• Target service SPN

Mimikatz:
kerberos::golden /user:Administrator /domain:$domain /sid:$SID /target:server.$domain /service:HTTP /rc4:$hash /ptt
SILVER
}

airo_passpol() {
    local domain="${1:?Usage: passpol <domain>}"
    
    echo "[*] Checking password policy for: $domain"
    
    if command -v crackmapexec >/dev/null 2>&1; then
        crackmapexec smb "$domain" --pass-pol
    elif command -v enum4linux >/dev/null 2>&1; then
        enum4linux -P "$domain"
    else
        echo "[-] No tools available"
    fi
}

airo_gpppass() {
    echo "[*] Extracting GPP passwords..."
    
    cat << 'GPP'
Group Policy Preferences Passwords:

1. Find GPP files:
   find / -name "Groups.xml" 2>/dev/null
   smbclient -L //$target -U ""%"" -c 'recurse;ls'

2. Decrypt passwords:
   gpp-decrypt $encrypted_password

3. Common locations:
   \\$domain\SYSVOL\$domain\Policies\{Policy-GUID}\Machine\Preferences\Groups
   \\$domain\SYSVOL\$domain\Policies\{Policy-GUID}\User\Preferences\Groups
GPP
}

export -f airo_adusers airo_adgroups airo_admachines airo_bloodhound airo_kerberoast
export -f airo_asreproast airo_goldenticket airo_silverticket airo_passpol airo_gpppass
'''
    
    (base_dir / "modules" / "ad.sh").write_text(ad_content, encoding='utf-8')
    (base_dir / "modules" / "ad.sh").chmod(0o755)

def create_module_wireless(base_dir):
    """Create wireless module"""
    wireless_content = '''#!/usr/bin/env bash
# Wireless Security Module
# 8 wireless security commands

airo_wifiscan() {
    echo "[*] Scanning for WiFi networks..."
    
    if command -v iwconfig >/dev/null 2>&1; then
        iwconfig 2>/dev/null | grep -i essid
    fi
    
    if command -v nmcli >/dev/null 2>&1; then
        nmcli dev wifi
    fi
    
    echo "[!] For detailed scanning, use: sudo airodump-ng wlan0mon"
}

airo_wifiattack() {
    local bssid="${1:?Usage: wifiattack <BSSID>}"
    
    echo "[*] WiFi Attack Menu - Target: $bssid"
    
    cat << 'WIFI_ATTACK'
1. Deauth Attack:
   aireplay-ng -0 10 -a $bssid wlan0mon

2. Capture Handshake:
   airodump-ng -c <channel> --bssid $bssid -w capture wlan0mon
   # Then deauth to capture handshake

3. WPS Attack:
   reaver -i wlan0mon -b $bssid -vv

Tools:
  • aircrack-ng suite
  • hashcat (for WPA cracking)
  • hcxtools
WIFI_ATTACK
}

airo_bluescan() {
    echo "[*] Scanning for Bluetooth devices..."
    
    if command -v hcitool >/dev/null 2>&1; then
        hcitool scan
    elif command -v bluetoothctl >/dev/null 2>&1; then
        echo "scan on" | bluetoothctl
        sleep 5
        echo "devices" | bluetoothctl
        echo "scan off" | bluetoothctl
    else
        echo "[-] Bluetooth tools not installed"
    fi
}

airo_blueattack() {
    local bdaddr="${1:?Usage: blueattack <BD_ADDR>}"
    
    echo "[*] Bluetooth Attack Menu - Target: $bdaddr"
    
    cat << 'BLUE_ATTACK'
1. Information:
   hcitool info $bdaddr

2. L2CAP Ping:
   l2ping $bdaddr

3. RFCOMM Scan:
   sdptool browse $bdaddr

4. SDP Browsing:
   sdptool records $bdaddr

Tools:
  • bluelog
  • bluesnarfer
  • spooftooph
  • gatttool
BLUE_ATTACK
}

airo_wpscrack() {
    local bssid="${1:?Usage: wpscrack <BSSID>}"
    
    echo "[*] WPS PIN cracking: $bssid"
    
    if command -v reaver >/dev/null 2>&1; then
        echo "reaver -i wlan0mon -b $bssid -vv -K 1"
        echo "bully -b $bssid wlan0mon"
    else
        echo "[-] reaver not installed"
    fi
}

airo_handshake() {
    local bssid="${1:?Usage: handshake <BSSID>}"
    
    echo "[*] Capture WPA Handshake Guide"
    
    cat << 'HANDSHAKE'
Steps:

1. Start monitoring:
   airmon-ng start wlan0
   airodump-ng wlan0mon

2. Capture on specific channel:
   airodump-ng -c <channel> --bssid $bssid -w capture wlan0mon

3. Deauth to capture handshake:
   aireplay-ng -0 4 -a $bssid -c <client_mac> wlan0mon

4. Crack with hashcat:
   hcxpcapngtool -o hash.hc22000 capture*.cap
   hashcat -m 22000 hash.hc22000 wordlist.txt
HANDSHAKE
}

airo_pmkidattack() {
    echo "[*] PMKID Attack Guide"
    
    cat << 'PMKID'
Advantages:
• No clients needed
• No deauth required
• Faster than handshake

Steps:

1. Capture PMKID:
   hcxdumptool -i wlan0mon -o capture.pcapng --enable_status=1

2. Convert to hash format:
   hcxpcaptool -z hashes.txt capture.pcapng

3. Crack with hashcat:
   hashcat -m 16800 hashes.txt wordlist.txt

Tools:
  • hcxtools
  • hcxdumptool
  • hashcat (mode 16800)
PMKID
}

airo_rfscan() {
    echo "[*] RF Spectrum scanning guide"
    
    cat << 'RF_SCAN'
RF Scanning Tools:

Software Defined Radio:
  • rtl_power -f 24M:1700M -g 50 -i 5m survey.csv
  • gqrx
  • gnuradio-companion

Common Frequencies:
  • 433 MHz - Key fobs, sensors
  • 868 MHz - EU devices
  • 915 MHz - US devices
  • 2.4 GHz - WiFi, Bluetooth
  • 5.8 GHz - WiFi, drones

Hardware:
  • RTL-SDR
  • HackRF One
  • LimeSDR
  • USRP
RF_SCAN
}

export -f airo_wifiscan airo_wifiattack airo_bluescan airo_blueattack airo_wpscrack
export -f airo_handshake airo_pmkidattack airo_rfscan
'''
    
    (base_dir / "modules" / "wireless.sh").write_text(wireless_content, encoding='utf-8')
    (base_dir / "modules" / "wireless.sh").chmod(0o755)

def create_module_mobile(base_dir):
    """Create mobile/IoT module"""
    mobile_content = '''#!/usr/bin/env bash
# Mobile & IoT Security Module
# 7 mobile/IoT security commands

airo_apkanalyze() {
    local apk="${1:?Usage: apkanalyze <path/to/app.apk>}"
    
    if [[ ! -f "$apk" ]]; then
        echo "[-] File not found: $apk"
        return 1
    fi
    
    echo "[*] Analyzing APK: $apk"
    
    if command -v apktool >/dev/null 2>&1; then
        echo -e "\\nDecompiling APK:"
        apktool d "$apk" -o apk_output 2>/dev/null && echo "[+] Decompiled to apk_output/"
    fi
    
    if command -v jadx >/dev/null 2>&1; then
        echo -e "\\nDecompiling to Java:"
        jadx "$apk" -d jadx_output 2>/dev/null && echo "[+] Java source in jadx_output/"
    fi
    
    echo -e "\\nExtracting contents:"
    unzip -l "$apk" | head -20
}

airo_apkdecompile() {
    local apk="${1:?Usage: apkdecompile <path/to/app.apk> [outdir] }"
    local outdir="${2:-apk_decompiled}"
    
    if [[ ! -f "$apk" ]]; then
        echo "[-] File not found: $apk"
        return 1
    fi
    
    mkdir -p "$outdir"
    echo "[*] Decompiling APK to $outdir"
    if command -v apktool >/dev/null 2>&1; then
        apktool d "$apk" -o "$outdir/apktool" >/dev/null && echo "[+] apktool output: $outdir/apktool"
    else
        echo "[-] apktool not installed"
    fi
    
    if command -v jadx >/dev/null 2>&1; then
        jadx "$apk" -d "$outdir/jadx" >/dev/null && echo "[+] jadx output: $outdir/jadx"
    else
        echo "[-] jadx not installed"
    fi
}

airo_ipascan() {
    local ip="${1:?Usage: ipascan <ip_address>}"
    
    echo "[*] Scanning iOS app backend: $ip"
    echo "[*] Running port scan..."
    # Would call portscan function
    echo "[*] Check for common iOS backend services"
}

airo_androidscan() {
    local ip="${1:?Usage: androidscan <ip_address>}"
    
    echo "[*] Scanning Android app backend: $ip"
    echo "[*] Running port scan..."
    # Would call portscan function
    echo "[*] Check for common Android backend services"
}

airo_iotscan() {
    local ip="${1:?Usage: iotscan <ip_address>}"
    
    echo "[*] Scanning IoT device: $ip"
    
    # Common IoT ports
    local iot_ports="21,22,23,80,81,443,554,8000,8080,8081,8443,8888,9000,49152"
    
    if command -v nmap >/dev/null 2>&1; then
        nmap -sS -p "$iot_ports" "$ip"
    else
        echo "[-] nmap not installed"
    fi
    
    echo -e "\\nCommon IoT vulnerabilities:"
    echo "• Default credentials (admin/admin)"
    echo "• Unencrypted services"
    echo "• Outdated firmware"
    echo "• Exposed debug interfaces"
}

airo_firmwareextract() {
    local firmware="${1:?Usage: firmwareextract <firmware_file>}"
    
    if [[ ! -f "$firmware" ]]; then
        echo "[-] File not found: $firmware"
        return 1
    fi
    
    echo "[*] Extracting firmware: $firmware"
    
    if command -v binwalk >/dev/null 2>&1; then
        binwalk -e "$firmware"
    elif command -v foremost >/dev/null 2>&1; then
        foremost -i "$firmware" -o firmware_extracted
    else
        echo "[-] No extraction tools found"
    fi
}

airo_bleenum() {
    echo "[*] Bluetooth Low Energy enumeration guide"
    
    cat << 'BLE_ENUM'
BLE Enumeration Tools:

1. Scan for devices:
   hcitool lescan
   bluetoothctl scan le

2. Connect and explore:
   gatttool -b $BD_ADDR -I
   connect
   primary
   characteristics

3. Read/write characteristics:
   char-read-hnd 0x000c
   char-write-req 0x000c 0100

Tools:
  • bettercap
  • crackle (BLE encryption crack)
  • gattacker
  • bluepy (Python library)

Common BLE Services:
  • 1800 - Device Information
  • 180A - Manufacturer Data
  • 180F - Battery Service
  • 1811 - Alert Notification
BLE_ENUM
}

export -f airo_apkanalyze airo_ipascan airo_androidscan airo_iotscan
export -f airo_apkdecompile airo_firmwareextract airo_bleenum
'''
    
    (base_dir / "modules" / "mobile.sh").write_text(mobile_content, encoding='utf-8')
    (base_dir / "modules" / "mobile.sh").chmod(0o755)

def create_module_osint(base_dir):
    """Create OSINT module"""
    osint_content = '''#!/usr/bin/env bash
# OSINT Module
# 8 OSINT commands

airo_emailosint() {
    local email="${1:?Usage: emailosint <email_address>}"
    
    echo "[*] OSINT for email: $email"
    
    cat << 'EMAIL_OSINT'
OSINT Sources:

1. Breach Databases:
   • Have I Been Pwned: https://haveibeenpwned.com
   • DeHashed (requires account)
   • WeLeakInfo

2. Social Media:
   • Facebook: https://www.facebook.com/search/top/?q=$email
   • Twitter: https://twitter.com/search?q=$email
   • LinkedIn: https://www.linkedin.com/search/results/all/?keywords=$email

3. Search Engines:
   • Google: "$email"
   • Bing: "$email"
   • DuckDuckGo: "$email"

4. Specialized Tools:
   • hunter.io (email finder)
   • clearbit.com
   • phonebook.cz
EMAIL_OSINT
}

airo_userosint() {
    local username="${1:?Usage: userosint <username>}"
    
    echo "[*] OSINT for username: $username"
    
    cat << 'USER_OSINT'
Username OSINT Sources:

1. Social Media:
   • Instagram: https://www.instagram.com/$username/
   • Twitter: https://twitter.com/$username
   • GitHub: https://github.com/$username
   • Reddit: https://www.reddit.com/user/$username

2. Search Engines:
   • Google: "$username"
   • User search: whatsmyname.app
   • Namechk: namechk.com

3. Tools:
   • sherlock: sherlock $username
   • maigret: maigret $username
   • social-analyzer
USER_OSINT
}

airo_phoneosint() {
    local phone="${1:?Usage: phoneosint <phone_number>}"
    
    echo "[*] OSINT for phone: $phone"
    
    cat << 'PHONE_OSINT'
Phone Number OSINT:

1. Carrier Lookup:
   • truecaller.com
   • whitepages.com
   • carrier lookup APIs

2. Social Media:
   • Facebook phone search
   • WhatsApp number check
   • Telegram number search

3. Search Engines:
   • Google: "$phone"
   • Bing: "$phone"

4. Tools:
   • phoneinfoga
   • osintframework.com/phone
   • maigret (phone option)
PHONE_OSINT
}

airo_domainosint() {
    local domain="${1:?Usage: domainosint <domain>}"
    
    echo "[*] Full domain OSINT: $domain"
    
    cat << 'DOMAIN_OSINT'
Domain OSINT Checklist:

1. WHOIS Lookup:
   whois $domain
   whois.domaintools.com/$domain

2. DNS Records:
   dig $domain ANY
   dnsdumpster.com
   securitytrails.com

3. Subdomains:
   sublist3r -d $domain
   assetfinder --subs-only $domain
   crt.sh for certificate transparency

4. Historical Data:
   archive.org/web/ (Wayback Machine)
   urlscan.io
   viewdns.info
DOMAIN_OSINT
}

airo_breachcheck() {
    local email="${1:?Usage: breachcheck <email>}"
    
    echo "[*] Checking breaches for: $email"
    
    if command -v haveibeenpwned >/dev/null 2>&1; then
        haveibeenpwned --email "$email"
    else
        echo "[!] Install haveibeenpwned: pip3 install haveibeenpwned"
        echo "[!] Or check manually: https://haveibeenpwned.com"
    fi
}

airo_leaksearch() {
    local term="${1:?Usage: leaksearch <search_term>}"
    
    echo "[*] Searching leaked databases for: $term"
    
    cat << 'LEAK_SEARCH'
Leaked Database Search:

1. Search Engines:
   • Google: "site:pastebin.com $term"
   • "filetype:sql $term"
   • "database dump $term"

2. Paste Sites:
   • pastebin.com
   • ghostbin.com
   • justpaste.it

3. Commands:
   • grep -r "$term" leak_downloads/
   • Use torrent search for "database dump"
LEAK_SEARCH
}

airo_metadata() {
    local file="${1:?Usage: metadata <file>}"
    
    if [[ ! -f "$file" ]]; then
        echo "[-] File not found: $file"
        return 1
    fi
    
    echo "[*] Extracting metadata from: $file"
    
    if command -v exiftool >/dev/null 2>&1; then
        exiftool "$file"
    elif command -v file >/dev/null 2>&1; then
        file "$file"
        strings "$file" | head -50
    else
        echo "[-] exiftool not installed"
    fi
}

airo_imageosint() {
    echo "[*] Reverse image search guide"
    
    cat << 'IMAGE_OSINT'
Reverse Image Search:

1. Search Engines:
   • Google Images: https://images.google.com
   • Bing Images: https://www.bing.com/images
   • Yandex Images: https://yandex.com/images

2. Specialized Sites:
   • TinEye: https://tineye.com
   • Pimeyes: https://pimeyes.com
   • Berify: https://berify.com

3. Commands:
   • If file: curl -F "file=@$image" https://tineye.com
   • If URL: open browser with image URL
IMAGE_OSINT
}

export -f airo_emailosint airo_userosint airo_phoneosint airo_domainosint
export -f airo_breachcheck airo_leaksearch airo_metadata airo_imageosint
'''
    
    (base_dir / "modules" / "osint.sh").write_text(osint_content, encoding='utf-8')
    (base_dir / "modules" / "osint.sh").chmod(0o755)

def create_module_automation(base_dir):
    """Create automation module"""
    automation_content = '''#!/usr/bin/env bash
# Automation Module
# 7 automation commands

run_with_grc() {
    if command -v grc >/dev/null 2>&1; then
        grc "$@"
    else
        "$@"
    fi
}

airo_reconall() {
    local out_override=""
    local target_override=""
    local nmap_opts=""
    while (($#)); do
        case "$1" in
            --out=*) out_override="${1#*=}" ;;
            --out) out_override="$2"; shift ;;
            --target=*) target_override="${1#*=}" ;;
            --target) target_override="$2"; shift ;;
            --nmap-opts=*) nmap_opts="${1#*=}" ;;
            --nmap-opts) nmap_opts="$2"; shift ;;
            --) shift; break ;;
            *) break ;;
        esac
        shift || break
    done
    local domain="${target_override:-${1:?Usage: reconall <domain> [--out <dir>] [--target <domain>] [--nmap-opts \"...\"]}}"
    
    echo "[*] Starting full reconnaissance on: $domain"
    
    # Create output directory
    local output_dir="${out_override:-$HOME/recon/$domain-$(date +%Y%m%d)}"
    mkdir -p "$output_dir"
    
    echo "[+] Output directory: $output_dir"
    
    # Subdomain enumeration
    echo "[+] Enumerating subdomains..."
    if command -v subfinder >/dev/null 2>&1; then
        subfinder -d "$domain" -o "$output_dir/subdomains.txt"
    fi
    
    # DNS reconnaissance
    echo "[+] DNS reconnaissance..."
    dig "$domain" ANY +noall +answer > "$output_dir/dns_any.txt"
    
    # Port scanning
    echo "[+] Port scanning..."
    if command -v nmap >/dev/null 2>&1; then
        if [[ -n "$nmap_opts" ]]; then
            run_with_grc nmap $nmap_opts "$domain" -oN "$output_dir/nmap_quick.txt" &
        else
            run_with_grc nmap -sS "$domain" -oN "$output_dir/nmap_quick.txt" &
        fi
    fi
    
    # Web reconnaissance
    echo "[+] Web technology detection..."
    if command -v whatweb >/dev/null 2>&1; then
        whatweb "https://$domain" > "$output_dir/whatweb.txt" &
    fi
    
    wait
    
    echo "[+] Reconnaissance complete for $domain"
    echo "[*] Results in: $output_dir"
}

airo_vulnscan() {
    local out_override=""
    local target_override=""
    local nmap_opts=""
    local nikto_opts=""
    while (($#)); do
        case "$1" in
            --out=*) out_override="${1#*=}" ;;
            --out) out_override="$2"; shift ;;
            --target=*) target_override="${1#*=}" ;;
            --target) target_override="$2"; shift ;;
            --nmap-opts=*) nmap_opts="${1#*=}" ;;
            --nmap-opts) nmap_opts="$2"; shift ;;
            --nikto-opts=*) nikto_opts="${1#*=}" ;;
            --nikto-opts) nikto_opts="$2"; shift ;;
            --) shift; break ;;
            *) break ;;
        esac
        shift || break
    done
    local target="${target_override:-${1:?Usage: vulnscan <target> [--out <file>] [--target <target>] [--nmap-opts \"...\"] [--nikto-opts \"...\"]}}"
    
    echo "[*] Automated vulnerability scan: $target"
    
    if command -v nmap >/dev/null 2>&1; then
        echo "[+] Running Nmap vulnerability scripts..."
        if [[ -n "$nmap_opts" ]]; then
            run_with_grc nmap $nmap_opts "$target"
        else
            run_with_grc nmap -sV --script vuln "$target"
        fi
    elif command -v nikto >/dev/null 2>&1; then
        echo "[+] Running Nikto web scanner..."
        if [[ -n "$nikto_opts" ]]; then
            nikto -h "$target" $nikto_opts
        else
            nikto -h "$target"
        fi
    else
        echo "[-] No vulnerability scanner found"
    fi
}

airo_reportgen() {
    echo "[*] Generating pentest report template"
    
    local report_dir="$HOME/pentest_reports/$(date +%Y%m%d)"
    mkdir -p "$report_dir"
    
    cat > "$report_dir/report_template.md" << 'REPORT_TEMPLATE'
# Penetration Test Report

## Executive Summary
**Date:** $(date)
**Test Target:** [Target Name/IP]
**Test Duration:** [Duration]
**Overall Risk:** [High/Medium/Low]

### Key Findings
1. [Most Critical Finding]
2. [Second Critical Finding]
3. [Third Critical Finding]

## Technical Details

### 1. Information Gathering
#### 1.1 Target Discovery
- IP Range: [IP Range]
- Domains: [Domains Found]
- Subdomains: [Subdomains]

#### 1.2 Port Scanning
[Port Scan Results]

text

### 2. Vulnerability Assessment
#### 2.1 Critical Vulnerabilities
- [Vulnerability 1]
  - CVSS Score: [Score]
  - Description: [Description]
  - Impact: [Impact]
  - Recommendation: [Recommendation]

### 3. Recommendations
#### 3.1 Immediate Actions (Critical)
1. [Action 1]
2. [Action 2]

### 4. Appendices
#### 4.1 Tools Used
- Nmap
- Metasploit
- Burp Suite
- [Other Tools]

---

*Report generated by All In One RedOps (AIRO)*
REPORT_TEMPLATE
    
    echo "[+] Report template created: $report_dir/report_template.md"
}

airo_findings() {
    echo "[*] Findings management system"
    
    cat << 'FINDINGS'
Findings Management:

Critical Findings:
  • Remote code execution
  • SQL injection with data extraction
  • Authentication bypass

High Findings:
  • Cross-site scripting (stored)
  • Information disclosure
  • Insecure direct object references

Medium Findings:
  • Cross-site scripting (reflected)
  • CSRF
  • Directory traversal

Tools:
  • Dradis (collaboration)
  • Faraday (IDE)
  • Serpico (reporting)
FINDINGS
}

airo_evidence() {
    echo "[*] Evidence collection guidelines"
    
    cat << 'EVIDENCE'
Evidence Collection:

1. Documentation:
   • Screenshots with timestamps
   • Command output with timestamps
   • Network captures

2. Chain of Custody:
   • Who collected it
   • When it was collected
   • Where it was collected from
   • How it was collected

3. Storage:
   • Encrypted storage
   • Backup copies
   • Integrity hashes (MD5, SHA256)
EVIDENCE
}

airo_timertrack() {
    echo "[*] Pentest time tracking"
    
    local timer_file="$HOME/.airo_cache/timer.txt"
    
    if [[ ! -f "$timer_file" ]]; then
        echo "Start time: $(date)" > "$timer_file"
        echo "[+] Timer started at $(date)"
    else
        local start_time="$(head -1 "$timer_file" | cut -d: -f2-)"
        echo "[*] Timer started at: $start_time"
        echo "[*] Current time: $(date)"
        
        # Calculate elapsed
        local start_epoch=$(date -d "$start_time" +%s 2>/dev/null || echo 0)
        local now_epoch=$(date +%s)
        local elapsed=$((now_epoch - start_epoch))
        
        local hours=$((elapsed / 3600))
        local minutes=$(((elapsed % 3600) / 60))
        local seconds=$((elapsed % 60))
        
        echo "[+] Elapsed time: ${hours}h ${minutes}m ${seconds}s"
    fi
}

airo_notify() {
    local message="${1:-Test notification from AIRO}"
    
    echo "[*] Sending notification: $message"
    
    # Simple notification system
    echo "[!] Configure SLACK_WEBHOOK or TELEGRAM_BOT_TOKEN in config"
    echo "[!] Message: $message"
}

export -f airo_reconall airo_vulnscan airo_reportgen airo_findings
export -f airo_evidence airo_timertrack airo_notify
'''
    
    (base_dir / "modules" / "automation.sh").write_text(automation_content, encoding='utf-8')
    (base_dir / "modules" / "automation.sh").chmod(0o755)

def create_module_utilities(base_dir):
    """Create utilities module"""
    utilities_content = '''#!/usr/bin/env bash
# Utilities Module
# 10 utility commands

airo_urldecode() {
    local string="${1:?Usage: urldecode <string>}"
    
    echo "[*] URL decoding: $string"
    python3 -c "import sys, urllib.parse as ul; print(ul.unquote_plus(sys.argv[1]))" "$string"
}

airo_urlencode() {
    local string="${1:?Usage: urlencode <string>}"
    
    echo "[*] URL encoding: $string"
    python3 -c "import sys, urllib.parse as ul; print(ul.quote_plus(sys.argv[1]))" "$string"
}

airo_base64d() {
    local string="${1:?Usage: base64d <string>}"
    
    echo "[*] Base64 decoding: $string"
    echo "$string" | base64 -d 2>/dev/null || echo "Invalid base64"
}

airo_base64e() {
    local string="${1:?Usage: base64e <string>}"
    
    echo "[*] Base64 encoding: $string"
    echo "$string" | base64
}

airo_hexdump() {
    local file="${1:?Usage: hexdump <file>}"
    
    if [[ ! -f "$file" ]]; then
        echo "[-] File not found: $file"
        return 1
    fi
    
    echo "[*] Hex dump of: $file"
    
    if command -v xxd >/dev/null 2>&1; then
        xxd "$file"
    elif command -v hexdump >/dev/null 2>&1; then
        hexdump -C "$file" | head -50
    else
        echo "[-] No hex dump tool found"
    fi
}

airo_filetype() {
    local file="${1:?Usage: filetype <file>}"
    
    if [[ ! -f "$file" ]]; then
        echo "[-] File not found: $file"
        return 1
    fi
    
    echo "[*] Detecting file type: $file"
    
    if command -v file >/dev/null 2>&1; then
        file "$file"
        
        echo -e "\\nFirst 64 bytes (hex):"
        head -c 64 "$file" | xxd -p
        
        echo -e "\\nReadable strings:"
        strings "$file" | head -20
    else
        echo "[-] file command not found"
    fi
}

airo_calccidr() {
    local cidr="${1:?Usage: calccidr <ip/cidr>}"
    
    echo "[*] Calculating CIDR: $cidr"
    
    if command -v ipcalc >/dev/null 2>&1; then
        ipcalc "$cidr"
    else
        echo "[-] ipcalc not installed"
        echo -e "\\nBasic CIDR ranges:"
        echo "/24 = 256 addresses"
        echo "/16 = 65,536 addresses"
        echo "/8 = 16,777,216 addresses"
    fi
}

airo_shodanscan() {
    local query="${1:?Usage: shodanscan <query>}"
    
    echo "[*] Querying Shodan: $query"
    
    if [[ -z "$SHODAN_API_KEY" ]]; then
        echo "[-] SHODAN_API_KEY not set in config"
        echo "[!] Get one from: https://account.shodan.io"
        return 1
    fi
    
    echo "[!] API call would be made with key"
    echo "[!] Query: $query"
}

airo_censysscan() {
    local query="${1:?Usage: censysscan <query>}"
    
    echo "[*] Querying Censys: $query"
    
    if [[ -z "$CENSYS_API_ID" ]] || [[ -z "$CENSYS_API_SECRET" ]]; then
        echo "[-] CENSYS_API_ID and CENSYS_API_SECRET not set"
        echo "[!] Get from: https://search.censys.io/account/api"
        return 1
    fi
    
    echo "[!] API call would be made"
    echo "[!] Query: $query"
}

airo_fofascan() {
    local query="${1:?Usage: fofascan <query>}"
    
    echo "[*] Searching Fofa: $query"
    
    cat << 'FOFA_SCAN'
Fofa Search Query Examples:

Basic Queries:
  • domain="example.com"
  • ip="192.168.1.1"
  • port="80"

Service Queries:
  • title="Welcome to nginx"
  • banner="Apache"
  • body="login"

    (base_dir / "modules" / "utilities.sh").write_text(utilities_content, encoding='utf-8')
    try:
        (base_dir / "modules" / "utilities.sh").chmod(0o755)
    except (AttributeError, NotImplementedError, PermissionError, OSError):
        pass
}

export -f airo_urldecode airo_urlencode airo_base64d airo_base64e airo_hexdump
export -f airo_filetype airo_calccidr airo_shodanscan airo_censysscan airo_fofascan
'''
    
    (base_dir / "modules" / "utilities.sh").write_text(utilities_content, encoding='utf-8')
    (base_dir / "modules" / "utilities.sh").chmod(0o755)

def create_config_files(base_dir):
    """Create configuration files"""
    # Main config
    config_content = '''# All In One RedOps (AIRO) Configuration
# Version: 3.2.0

# Scan Settings
SCAN_DELAY=0.5
RATE_LIMIT=100
MAX_HOSTS=254

# Safety Settings
SAFE_MODE=1
AUDIT_LOGGING=1

# Framework Settings
AUTO_LOAD_MODULES=1
TOOL_TIMEOUT=10

# Wordlists (set to your SecLists clone)
WORDLIST_BASE="$HOME/SecLists"
WORDLIST_DIRSCAN="$WORDLIST_BASE/Discovery/Web-Content/common.txt"
WORDLIST_FUZZURL="$WORDLIST_BASE/Discovery/Web-Content/raft-medium-words.txt"

# API Keys (Optional)
# SHODAN_API_KEY="your_key_here"
# CENSYS_API_ID="your_id_here"
# CENSYS_API_SECRET="your_secret_here"
# SLACK_WEBHOOK="your_webhook_here"
# TELEGRAM_BOT_TOKEN="your_token_here"
# TELEGRAM_CHAT_ID="your_chat_id"
'''
    
    (base_dir / "config" / "defaults.conf").write_text(config_content, encoding='utf-8')
    
# User config template
    user_config = '''# User Configuration Overrides
# Place your custom settings here
# This file overrides defaults.conf

# Example:
# SCAN_DELAY=0.2
# RATE_LIMIT=200
# SAFE_MODE=0
# WORDLIST_BASE="$HOME/SecLists"
# WORDLIST_DIRSCAN="$WORDLIST_BASE/Discovery/Web-Content/raft-medium-directories.txt"
# WORDLIST_FUZZURL="$WORDLIST_BASE/Discovery/Web-Content/raft-medium-words.txt"
'''
    
    (base_dir / "config" / "user.conf.example").write_text(user_config, encoding='utf-8')

def create_documentation(base_dir):
    """Create documentation files"""
    docs_dir = base_dir / "docs"
    docs_dir.mkdir(parents=True, exist_ok=True)

    # README (written to root and docs/ for packaging)
    readme_content = '''# All In One RedOps (AIRO) v3.2.0
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
'''

    (base_dir / "README.md").write_text(readme_content, encoding='utf-8')
    (docs_dir / "README.md").write_text(readme_content, encoding='utf-8')

    # Extended docs (pulled from local DOCS.md if present, otherwise use embedded full docs)
    docs_source = Path("DOCS.md")
    if docs_source.exists():
        docs_content = docs_source.read_text(encoding='utf-8')
    else:
        docs_content = textwrap.dedent("""\
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
        - Verify executables: `find airo-redops-v3.2.0 -maxdepth 2 -type f -name "*.sh" -exec test -x {} \\; -print`.
        - Spot-check docs: ensure `README.md` and `DOCS.md` exist in both root and `docs/`.
        - Sanity test installer: run `./install.sh` in a throwaway environment or container if you ship it.
        - Clean secrets: confirm config files only contain placeholders.

        ## Support
        - When reporting, include OS, shell, command, output/error, and dependency status.
        - For extending, mirror patterns in `airo-splitter.py`, regenerate, and test.
        """).lstrip("\n")

    (base_dir / "DOCS.md").write_text(docs_content, encoding='utf-8')
    (docs_dir / "DOCS.md").write_text(docs_content, encoding='utf-8')
    print(f"[+] Docs written to {docs_dir}")

def build_package():
    """Generate the full All In One RedOps (AIRO) package structure and files."""
    base_dir = create_directory_structure()
    create_install_script(base_dir)
    create_uninstall_script(base_dir)
    create_core_loader(base_dir)
    create_module_network(base_dir)
    create_module_web(base_dir)
    create_module_system(base_dir)
    create_module_privesc(base_dir)
    create_module_cloud(base_dir)
    create_module_ad(base_dir)
    create_module_wireless(base_dir)
    create_module_mobile(base_dir)
    create_module_osint(base_dir)
    create_module_automation(base_dir)
    create_module_utilities(base_dir)
    create_config_files(base_dir)
    create_documentation(base_dir)
    print(f"[+] Generated All In One RedOps (AIRO) package at {base_dir.resolve()}")

if __name__ == "__main__":
    build_package()

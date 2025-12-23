#!/usr/bin/env bash
# All In One RedOps (AIRO) Core Loader - Main framework file

AIRO_VERSION="3.2.0"
AIRO_HOME="$HOME/.airo"
AIRO_MODULES="$AIRO_HOME/modules"
AIRO_CONFIG="$AIRO_HOME/config"
AIRO_CACHE="$AIRO_HOME/cache"

# Color setup
setup_colors() {
    if [[ -t 2 ]] && [[ -z "${NO_COLOR-}" ]] && [[ "${TERM-}" != "dumb" ]]; then
        RED='\033[0;31m'
        GREEN='\033[0;32m'
        YELLOW='\033[1;33m'
        BLUE='\033[0;34m'
        CYAN='\033[0;36m'
        MAGENTA='\033[0;35m'
        BOLD='\033[1m'
        NC='\033[0m'
    else
        RED='' GREEN='' YELLOW='' BLUE='' CYAN='' MAGENTA='' BOLD='' NC=''
    fi
}

# Logging functions
log() { printf "${GREEN}[+]${NC} %s\n" "$*"; }
warn() { printf "${YELLOW}[!]${NC} %s\n" "$*" >&2; }
error() { printf "${RED}[-]${NC} %s\n" "$*" >&2; }

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

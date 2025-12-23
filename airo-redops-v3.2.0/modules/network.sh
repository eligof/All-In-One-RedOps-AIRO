#!/usr/bin/env bash
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
        echo -e "\n$record:"
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

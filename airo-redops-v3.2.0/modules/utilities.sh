#!/usr/bin/env bash
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
        
        echo -e "\nFirst 64 bytes (hex):"
        head -c 64 "$file" | xxd -p
        
        echo -e "\nReadable strings:"
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
        echo -e "\nBasic CIDR ranges:"
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

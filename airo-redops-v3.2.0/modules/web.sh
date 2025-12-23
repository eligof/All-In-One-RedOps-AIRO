#!/usr/bin/env bash
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
        echo "[!] Clone SecLists: git clone https://github.com/danielmiessler/SecLists.git "$WORDLIST_BASE""
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
    echo "  "><script>alert('XSS')</script>"
    echo "  '><script>alert('XSS')</script>"
}

airo_takeover() {
    local domain="${1:?Usage: takeover <domain>}"
    
    echo "[*] Subdomain takeover check: $domain"
    echo "[*] Checking for vulnerable services..."
    
    # Simple check
    local subdomains=("www" "api" "dev" "staging" "test")
    for sub in "${subdomains[@]}"; do
        host "$sub.$domain" 2>/dev/null | grep -i "not found\|nxdomain" && echo "[+] Possible takeover: $sub.$domain"
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

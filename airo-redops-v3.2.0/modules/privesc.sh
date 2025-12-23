#!/usr/bin/env bash
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
    
    echo -e "\n1. Kernel & OS Info:"
    uname -a
    cat /etc/*release 2>/dev/null || true
    
    echo -e "\n2. Sudo Permissions:"
    sudo -l 2>/dev/null || echo "No sudo access"
    
    echo -e "\n3. SUID/SGID Files:"
    find / -type f -perm -4000 -o -perm -2000 2>/dev/null | head -20
    
    echo -e "\n4. Writable Files:"
    find / -writable 2>/dev/null | head -20
    
    echo -e "\n5. Cron Jobs:"
    crontab -l 2>/dev/null
    ls -la /etc/cron* 2>/dev/null
    
    echo -e "\n[*] Consider running linpeas for detailed check (download with: airo getpeas)"
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
   dir "C:\Program Files"
   dir "C:\Program Files (x86)"
   reg query HKLM\Software

3. Scheduled Tasks:
   schtasks /query /fo LIST /v
   dir C:\Windows\Tasks

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
    local version="$(sudo --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')"
    
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

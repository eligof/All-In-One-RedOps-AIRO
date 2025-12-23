#!/usr/bin/env bash
# System Enumeration Module
# 8 system enumeration commands

airo_sysenum() {
    echo "[*] System enumeration started..."
    
    echo -e "\n=== SYSTEM INFORMATION ==="
    uname -a
    
    echo -e "\n=== USER INFO ==="
    id
    whoami
    
    echo -e "\n=== NETWORK ==="
    ip a 2>/dev/null || ifconfig
    
    echo -e "\n=== PROCESSES ==="
    ps aux --sort=-%mem | head -20
    
    echo -e "\n=== SERVICES ==="
    systemctl list-units --type=service --state=running 2>/dev/null || service --status-all 2>/dev/null
    
    echo -e "\n=== CRON JOBS ==="
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
    
    echo -e "\nUser cron:"
    crontab -l 2>/dev/null || echo "No user cron"
    
    echo -e "\nSystem cron:"
    ls -la /etc/cron* 2>/dev/null
    
    echo -e "\nSystemd timers:"
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
        dpkg -l | grep -i "$lib" 2>/dev/null ||         rpm -qa | grep -i "$lib" 2>/dev/null ||         pacman -Q | grep -i "$lib" 2>/dev/null || true
    done
}

airo_serviceenum() {
    echo "[*] Enumerating services..."
    
    # Systemd
    if command -v systemctl >/dev/null 2>&1; then
        echo -e "\nSystemd Services:"
        systemctl list-units --type=service --state=running
    fi
    
    # init.d
    if [[ -d /etc/init.d ]]; then
        echo -e "\nInit.d Services:"
        ls -la /etc/init.d/
    fi
    
    # Listening ports
    echo -e "\nListening Ports:"
    ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null
}

airo_userenum() {
    echo "[*] Enumerating users and groups..."
    
    echo -e "\nUsers:"
    cat /etc/passwd | cut -d: -f1,3,4,6,7 | head -20
    
    echo -e "\nGroups:"
    cat /etc/group | cut -d: -f1,3,4 | head -20
    
    echo -e "\nLogged in users:"
    who -a
}

export -f airo_sysenum airo_sudofind airo_capfind airo_cronfind airo_procmon
export -f airo_libfind airo_serviceenum airo_userenum

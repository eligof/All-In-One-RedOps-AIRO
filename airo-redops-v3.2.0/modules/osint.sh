#!/usr/bin/env bash
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

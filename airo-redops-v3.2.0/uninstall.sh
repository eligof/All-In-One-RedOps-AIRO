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

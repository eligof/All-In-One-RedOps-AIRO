#!/usr/bin/env bash
set -euo pipefail

if ! command -v python3 >/dev/null 2>&1; then
  echo "[-] python3 not found. Install Python 3 and retry."
  exit 1
fi

python3 airo-splitter.py
cd airo-redops-v3.3.0

AIRO_YES=1 ./install.sh
echo "[+] Installed. Reload your shell (source ~/.zshrc)."

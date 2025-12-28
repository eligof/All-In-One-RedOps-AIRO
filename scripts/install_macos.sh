#!/usr/bin/env bash
set -euo pipefail

if ! command -v python3 >/dev/null 2>&1; then
  echo "[-] python3 not found. Install Python 3 and retry."
  exit 1
fi

python3 airo-splitter.py
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION_FILE="$ROOT_DIR/VERSION"
if [[ -f "$VERSION_FILE" ]]; then
  VERSION="$(tr -d '\r\n' < "$VERSION_FILE")"
  VERSION="${VERSION#v}"
else
  VERSION="3.3.0"
fi
cd "airo-redops-v${VERSION}"

AIRO_YES=1 ./install.sh
echo "[+] Installed. Reload your shell (source ~/.zshrc)."

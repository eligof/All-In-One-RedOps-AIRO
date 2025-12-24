#!/usr/bin/env bash
set -euo pipefail

VERSION="3.3.0"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAGE="$ROOT_DIR/packaging/debbuild"
OUT_DIR="$ROOT_DIR/packaging"

rm -rf "$STAGE"
mkdir -p "$STAGE/DEBIAN" "$STAGE/opt" "$STAGE/usr/local/bin"

cp "$ROOT_DIR/packaging/deb/DEBIAN/control" "$STAGE/DEBIAN/control"

python "$ROOT_DIR/airo-splitter.py"
cp -a "$ROOT_DIR/airo-redops-v${VERSION}" "$STAGE/opt/airo"
ln -s /opt/airo/airo-core.sh "$STAGE/usr/local/bin/airo"

dpkg-deb --build "$STAGE" "$OUT_DIR/airo_${VERSION}_all.deb"
echo "[+] Built $OUT_DIR/airo_${VERSION}_all.deb"

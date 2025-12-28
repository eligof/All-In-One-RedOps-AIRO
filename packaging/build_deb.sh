#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION_FILE="$ROOT_DIR/VERSION"
VERSION="3.3.0"
if [[ -f "$VERSION_FILE" ]]; then
  VERSION="$(tr -d '\r\n' < "$VERSION_FILE")"
  VERSION="${VERSION#v}"
fi
STAGE="$ROOT_DIR/packaging/debbuild"
OUT_DIR="$ROOT_DIR/packaging"

rm -rf "$STAGE"
mkdir -p "$STAGE/DEBIAN" "$STAGE/opt" "$STAGE/usr/local/bin"

sed -E "s/^Version:.*/Version: ${VERSION}/" \
  "$ROOT_DIR/packaging/deb/DEBIAN/control" > "$STAGE/DEBIAN/control"

python "$ROOT_DIR/airo-splitter.py"
cp -a "$ROOT_DIR/airo-redops-v${VERSION}" "$STAGE/opt/airo"
ln -s /opt/airo/airo-core.sh "$STAGE/usr/local/bin/airo"

dpkg-deb --build "$STAGE" "$OUT_DIR/airo_${VERSION}_all.deb"
echo "[+] Built $OUT_DIR/airo_${VERSION}_all.deb"

#!/usr/bin/env bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

REPO_URL="${AIRO_REPO_URL:-https://github.com/eligof/All-In-One-RedOps-AIRO.git}"
BRANCH="${AIRO_BRANCH:-main}"
TARGET="${AIRO_TARGET:-example.com}"
LOG_DIR="${AIRO_LOG_DIR:-/vagrant/airo-logs}"
AIRO_CI="${AIRO_CI:-0}"
DEST_DIR="/home/vagrant/All-In-One-RedOps-AIRO"
VAGRANT_HOME="/home/vagrant"
VAGRANT_GO_BIN="$VAGRANT_HOME/go/bin"
GO_MIN_VERSION="${AIRO_GO_MIN_VERSION:-1.20.0}"
GO_VERSION="${AIRO_GO_VERSION:-1.22.4}"
GO_ROOT="/usr/local/go"
GO_BIN="$GO_ROOT/bin"
GO_PATH_FILE="/etc/profile.d/airo-go-path.sh"
USE_SYNCED_REPO=0

log() { printf '[*] %s\n' "$*"; }
die() { printf '[-] %s\n' "$*" >&2; exit 1; }

ensure_log_dir() {
  if [[ "$LOG_DIR" == /vagrant/* ]]; then
    if ! grep -qs " /vagrant " /proc/mounts; then
      LOG_DIR="$VAGRANT_HOME/airo-logs"
      log "Synced folder /vagrant not mounted; using $LOG_DIR for logs"
    fi
  fi
}

version_lt() {
  local left="$1"
  local right="$2"
  [[ "$(printf '%s\n' "$left" "$right" | sort -V | head -n1)" == "$left" && "$left" != "$right" ]]
}

ensure_dns() {
  if getent hosts github.com >/dev/null 2>&1; then
    return
  fi

  log "DNS resolution failed; applying fallback /etc/resolv.conf"
  systemctl stop systemd-resolved >/dev/null 2>&1 || true
  systemctl disable systemd-resolved >/dev/null 2>&1 || true
  rm -f /etc/resolv.conf
  cat > /etc/resolv.conf <<'EOF'
nameserver 1.1.1.1
nameserver 8.8.8.8
EOF
}

ensure_dns
ensure_log_dir
if [[ -f /vagrant/airo-splitter.py ]]; then
  DEST_DIR="/vagrant"
  USE_SYNCED_REPO=1
  log "Using /vagrant as source repo"
fi

SPLITTER_LOG="$LOG_DIR/airo-splitter.log"
RUNLIST_LOG="$LOG_DIR/airo-runlist.log"
COMMAND_LOG="$LOG_DIR/airo-commands.log"
RUNLIST="$LOG_DIR/airo-runlist.txt"

log "Updating apt index"
apt-get update -y
log "Installing base packages"
apt-get install -y git python3 curl ca-certificates

current_go_version=""
if command -v go >/dev/null 2>&1; then
  current_go_version="$(go version | awk '{print $3}' | sed 's/^go//')"
fi
need_go=0
if [[ -z "$current_go_version" ]]; then
  need_go=1
elif version_lt "$current_go_version" "$GO_MIN_VERSION"; then
  need_go=1
fi
if [[ "$need_go" -eq 1 ]]; then
  log "Installing Go ${GO_VERSION} (current: ${current_go_version:-none})"
  tmp_go="$(mktemp)"
  curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -o "$tmp_go"
  rm -rf "$GO_ROOT"
  tar -C /usr/local -xzf "$tmp_go"
  rm -f "$tmp_go"
else
  log "Go ${current_go_version} meets minimum ${GO_MIN_VERSION}"
fi

cat > "$GO_PATH_FILE" <<EOF
export PATH="$GO_BIN:$VAGRANT_GO_BIN:\$PATH"
EOF

mkdir -p "$LOG_DIR"
chown -R vagrant:vagrant "$LOG_DIR"

if [[ "$USE_SYNCED_REPO" -eq 1 ]]; then
  log "Using synced repo at $DEST_DIR"
elif [[ -d "$DEST_DIR/.git" ]]; then
  log "Updating repo: $DEST_DIR"
  sudo -u vagrant -H git -C "$DEST_DIR" fetch --all --prune
  sudo -u vagrant -H git -C "$DEST_DIR" checkout "$BRANCH"
  sudo -u vagrant -H git -C "$DEST_DIR" pull --ff-only origin "$BRANCH"
elif [[ -e "$DEST_DIR" ]]; then
  die "Destination exists but is not a git repo: $DEST_DIR"
else
  log "Cloning repo to $DEST_DIR"
  sudo -u vagrant -H git clone --branch "$BRANCH" "$REPO_URL" "$DEST_DIR"
fi

log "Running splitter"
sudo -u vagrant -H bash -lc "cd \"$DEST_DIR\" && PYTHONWARNINGS=\"ignore:invalid escape sequence\" python3 airo-splitter.py" | tee "$SPLITTER_LOG"

VERSION="$(tr -d '\r\n' < "$DEST_DIR/VERSION")"
VERSION="${VERSION#v}"
PKG_DIR="$DEST_DIR/airo-redops-v${VERSION}"
[[ -d "$PKG_DIR" ]] || die "Generated package not found: $PKG_DIR"

log "Installing AIRO"
sudo -u vagrant -H bash -lc "export PATH=\"$GO_BIN:$VAGRANT_GO_BIN:\$PATH\"; AIRO_YES=1 AIRO_INSTALL_DEPS=1 bash \"$PKG_DIR/install.sh\"" | tee -a "$SPLITTER_LOG"
chown vagrant:vagrant "$SPLITTER_LOG"

AIRO_BIN="/usr/local/bin/airo"
if [[ ! -x "$AIRO_BIN" ]]; then
  AIRO_BIN="$PKG_DIR/airo-core.sh"
fi

if [[ "$AIRO_CI" -eq 1 ]]; then
  CI_SCRIPT="$DEST_DIR/scripts/ci_run_all.sh"
  [[ -x "$CI_SCRIPT" ]] || die "CI runner not found: $CI_SCRIPT"
  CI_LOG="$LOG_DIR/airo-ci.log"
  log "Running CI command suite (logs: $CI_LOG)"
  sudo -u vagrant -H bash -lc "export PATH=\"$GO_BIN:$VAGRANT_GO_BIN:\$PATH\"; \
export AIRO_TARGET=\"$TARGET\"; \
export AIRO_DOMAIN=\"${AIRO_DOMAIN:-}\"; \
export AIRO_SUBNET=\"${AIRO_SUBNET:-}\"; \
export AIRO_HTTP_URL=\"${AIRO_HTTP_URL:-}\"; \
export AIRO_HTTPS_URL=\"${AIRO_HTTPS_URL:-}\"; \
export AIRO_SQL_URL=\"${AIRO_SQL_URL:-}\"; \
export AIRO_XSS_URL=\"${AIRO_XSS_URL:-}\"; \
export AIRO_LOG_DIR=\"$LOG_DIR\"; \
export AIRO_CI_STRICT=\"${AIRO_CI_STRICT:-1}\"; \
export AIRO_CI_LOG_DIR=\"${AIRO_CI_LOG_DIR:-}\"; \
export AIRO_WORDLIST=\"${AIRO_WORDLIST:-}\"; \
export AIRO_FIXTURES_DIR=\"${AIRO_FIXTURES_DIR:-}\"; \
NO_PROMPT=1 \"$CI_SCRIPT\"" | tee "$CI_LOG"
  chown vagrant:vagrant "$CI_LOG"
else
  cat > "$RUNLIST" <<EOF
version
myip
whoislookup $TARGET
dnsdump $TARGET
dnscan $TARGET
subdomain $TARGET --output $LOG_DIR/subdomains.txt
headerscan http://$TARGET
headerscan https://$TARGET
sslscan $TARGET
webscan https://$TARGET
EOF
  chown vagrant:vagrant "$RUNLIST"

  log "Running test commands (logs: $COMMAND_LOG, $RUNLIST_LOG)"
  sudo -u vagrant -H bash -lc "export PATH=\"$GO_BIN:$VAGRANT_GO_BIN:\$PATH\"; NO_PROMPT=1 \"$AIRO_BIN\" runlist \"$RUNLIST\" --log \"$COMMAND_LOG\"" | tee "$RUNLIST_LOG"
  chown vagrant:vagrant "$RUNLIST_LOG" "$COMMAND_LOG"
fi

log "Done. Logs are in $LOG_DIR"

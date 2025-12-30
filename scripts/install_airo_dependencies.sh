#!/usr/bin/env bash
set -euo pipefail

# Dependency installer for AIRO on Debian/Ubuntu-like systems.
# Installs common tools, wordlists (SecLists), Python deps, and provides fallbacks
# when packages are not available in the default repositories.

APT_REQUIRED=(
  nmap whois nikto gobuster dirb ffuf sqlmap sslscan testssl.sh whatweb grc
  docker.io ldap-utils aircrack-ng bluetooth bluez bettercap
  apktool zipalign adb exiftool xxd file python3-pip python3-venv pipx git golang-go perl
  ruby-dev build-essential
  curl ca-certificates
)

APT_OPTIONAL=(
  wpscan joomscan subfinder awscli kubectl enum4linux gatttool jadx
)

GO_MIN_VERSION="${AIRO_GO_MIN_VERSION:-1.20.0}"
GO_VERSION="${AIRO_GO_VERSION:-1.22.4}"
GO_ROOT="${AIRO_GO_ROOT:-/usr/local/go}"
GO_BIN="${GO_ROOT}/bin"
GO_BOOTSTRAP="${AIRO_GO_BOOTSTRAP:-1}"

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

version_lt() {
  local left="$1"
  local right="$2"
  [[ "$(printf '%s\n' "$left" "$right" | sort -V | head -n1)" == "$left" && "$left" != "$right" ]]
}

add_go_path() {
  if [[ -d "$GO_BIN" ]]; then
    export PATH="$GO_BIN:$PATH"
  fi
  if command_exists go; then
    local gopath
    gopath="$(go env GOPATH 2>/dev/null || true)"
    if [[ -n "$gopath" ]]; then
      export PATH="$gopath/bin:$PATH"
    fi
  fi
}

APT_OK=1
MIN_TMP_GB="${AIRO_MIN_TMP_GB:-2}"
MIN_HOME_GB="${AIRO_MIN_HOME_GB:-6}"
SKIP_GO_INSTALL=0

disk_available_kb() {
  df -Pk "$1" 2>/dev/null | awk 'NR==2 {print $4}'
}

has_space_kb() {
  local path="$1"
  local min_kb="$2"
  local avail
  avail="$(disk_available_kb "$path")"
  [[ -n "$avail" && "$avail" -ge "$min_kb" ]]
}

apt_update_safe() {
  local output
  output="$(mktemp)"
  if ! sudo apt update 2>&1 | tee "$output"; then
    APT_OK=0
  fi
  if grep -qiE "failed to fetch|invalid signature|gpg error|at least one invalid signature" "$output"; then
    APT_OK=0
  fi
  rm -f "$output"
  if [[ "$APT_OK" -ne 1 ]]; then
    echo "[!] APT update reported errors; skipping APT installs."
  fi
}

ensure_go() {
  if [[ "$GO_BOOTSTRAP" != "1" ]]; then
    return 0
  fi

  add_go_path
  local current=""
  if command_exists go; then
    current="$(go version | awk '{print $3}' | sed 's/^go//')"
  fi
  if [[ -n "$current" ]] && ! version_lt "$current" "$GO_MIN_VERSION"; then
    echo "[*] Go $current meets minimum $GO_MIN_VERSION"
    return 0
  fi

  echo "[*] Installing Go $GO_VERSION (current: ${current:-none})"
  local tmp
  tmp="$(mktemp)"
  if command_exists curl; then
    curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -o "$tmp"
  elif command_exists wget; then
    wget -qO "$tmp" "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz"
  else
    if [[ "$APT_OK" -eq 1 ]]; then
      sudo apt install -y curl ca-certificates || true
    fi
    if command_exists curl; then
      curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -o "$tmp"
    elif command_exists wget; then
      wget -qO "$tmp" "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz"
    else
      echo "[!] curl/wget not available; skipping Go bootstrap."
      rm -f "$tmp"
      return 1
    fi
  fi

  if command_exists sudo; then
    sudo rm -rf "$GO_ROOT"
    sudo tar -C /usr/local -xzf "$tmp"
  else
    rm -rf "$GO_ROOT"
    tar -C /usr/local -xzf "$tmp"
  fi
  rm -f "$tmp"
  add_go_path
}

pip_install_user() {
  local pkg="$1"
  local output
  output="$(mktemp)"
  if pip3 install --user "$pkg" >"$output" 2>&1; then
    rm -f "$output"
    return 0
  fi
  if grep -qi "externally-managed-environment" "$output"; then
    rm -f "$output"
    echo "[!] pip user installs blocked (PEP 668). Trying venv/pipx for $pkg."
    if python3 -m venv "$HOME/.local/share/airo/venv" >/dev/null 2>&1; then
      "$HOME/.local/share/airo/venv/bin/pip" install "$pkg" || true
      if "$HOME/.local/share/airo/venv/bin/pip" show "$pkg" >/dev/null 2>&1; then
        return 0
      fi
    fi
    if command_exists pipx; then
      pipx install "$pkg" || true
      return 0
    fi
    echo "[!] Install pipx or python3-venv to enable Python package installs."
    return 1
  fi
  cat "$output" >&2
  rm -f "$output"
  return 1
}

install_available_apt_pkgs() {
  local pkgs=("$@")
  local available=()
  local missing=()
  if [[ "$APT_OK" -ne 1 ]]; then
    return 1
  fi
  for pkg in "${pkgs[@]}"; do
    if apt-cache policy "$pkg" 2>/dev/null | awk '/Candidate:/ {print $2}' | grep -vq "(none)"; then
      available+=("$pkg")
    else
      missing+=("$pkg")
    fi
  done
  if ((${#available[@]})); then
    echo "[*] Installing APT packages: ${available[*]}"
    sudo apt install -y "${available[@]}"
  fi
  if ((${#missing[@]})); then
    echo "[!] Missing from APT repos: ${missing[*]}"
  fi
}

echo "[*] Updating package index..."
apt_update_safe

install_available_apt_pkgs "${APT_REQUIRED[@]}"
install_available_apt_pkgs "${APT_OPTIONAL[@]}"

if ! command_exists exiftool; then
  if [[ "$APT_OK" -eq 1 ]] && apt-cache policy libimage-exiftool-perl 2>/dev/null | awk '/Candidate:/ {print $2}' | grep -vq "(none)"; then
    echo "[*] Installing exiftool via libimage-exiftool-perl"
    sudo apt install -y libimage-exiftool-perl || true
  else
    echo "[!] exiftool not available in default repos. Install libimage-exiftool-perl if supported."
  fi
fi

echo "[*] Installing Python deps (user scope)..."
pip_install_user haveibeenpwned || true

home_min_kb=$((MIN_HOME_GB * 1024 * 1024))
if [[ ! -d "$HOME/SecLists" ]]; then
  if ! has_space_kb "$HOME" "$home_min_kb"; then
    echo "[!] Not enough free space in $HOME for SecLists (need ~${MIN_HOME_GB}G). Skipping clone."
  else
    echo "[*] Cloning SecLists to $HOME/SecLists"
    git clone https://github.com/danielmiessler/SecLists.git "$HOME/SecLists"
  fi
else
  echo "[*] SecLists already present at $HOME/SecLists"
fi

tmp_min_kb=$((MIN_TMP_GB * 1024 * 1024))
tmp_dir="${TMPDIR:-/tmp}"
if ! has_space_kb "$tmp_dir" "$tmp_min_kb"; then
  echo "[!] Not enough free space in $tmp_dir for Go builds (need ~${MIN_TMP_GB}G). Skipping Go tool installs."
  SKIP_GO_INSTALL=1
fi

if [[ "$SKIP_GO_INSTALL" -eq 0 ]]; then
  ensure_go || true
fi

echo "[*] Installing Go-based tools (httpx, katana, nuclei, gau, waybackurls)..."
if [[ "$SKIP_GO_INSTALL" -eq 1 ]]; then
  echo "[!] Go tool install skipped."
elif command -v go >/dev/null 2>&1; then
  export GO111MODULE=on
  add_go_path
  GO_TOOLS=(
    "httpx:github.com/projectdiscovery/httpx/cmd/httpx@v1.6.0"
    "katana:github.com/projectdiscovery/katana/cmd/katana@v1.0.5"
    "nuclei:github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.2.0"
    "gau:github.com/lc/gau/v2/cmd/gau@v2.1.2"
    "waybackurls:github.com/tomnomnom/waybackurls@v0.1.0"
    "subfinder:github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  )
  missing_go=()
  for entry in "${GO_TOOLS[@]}"; do
    bin="${entry%%:*}"
    mod="${entry#*:}"
    echo "[*] Installing $bin..."
    out="$(mktemp)"
    if ! go install "$mod" >"$out" 2>&1; then
      cat "$out" >&2
      if grep -qi "no space left on device" "$out"; then
        rm -f "$out"
        echo "[!] Go install failed due to low disk space. Free space and rerun."
        exit 1
      fi
    fi
    rm -f "$out"
    if ! command_exists "$bin"; then
      missing_go+=("$bin")
    fi
  done
  if ((${#missing_go[@]})); then
    echo "[!] Missing Go tools after install: ${missing_go[*]}"
    echo "[!] Ensure $(go env GOPATH)/bin is on PATH and re-run this installer."
    exit 1
  fi
else
  echo "[-] Go toolchain not found; install golang-go and rerun to fetch httpx/katana/nuclei/gau/waybackurls."
  exit 1
fi

if ! command_exists aws; then
  echo "[*] awscli not found; attempting Python install"
  pip_install_user awscli || true
  if ! command_exists aws; then
    echo "[!] awscli still missing. Ensure ~/.local/bin is on PATH:"
    echo "    export PATH=\"$HOME/.local/bin:\$PATH\""
  fi
fi

if ! command_exists kubectl; then
  if [[ "$APT_OK" -eq 1 ]] && apt-cache policy kubernetes-client 2>/dev/null | awk '/Candidate:/ {print $2}' | grep -vq "(none)"; then
    echo "[*] Installing kubectl via kubernetes-client"
    sudo apt install -y kubernetes-client || true
  else
    echo "[!] kubectl not available in default repos. Install from https://kubernetes.io/docs/tasks/tools/."
  fi
fi

if ! command_exists wpscan; then
  echo "[*] wpscan not found; attempting Ruby install"
  if ! command_exists gem; then
    sudo apt install -y ruby-full || true
  fi
  if command_exists gem; then
    sudo gem install wpscan --no-document || true
  fi
fi

if ! command_exists joomscan; then
  echo "[*] joomscan not found; attempting git install"
  if command_exists git; then
    if command_exists sudo; then
      sudo mkdir -p /opt/joomscan
      if [[ ! -d /opt/joomscan/.git ]]; then
        sudo git clone https://github.com/rezasp/joomscan.git /opt/joomscan || true
      else
        sudo git -C /opt/joomscan pull || true
      fi
      sudo ln -sf /opt/joomscan/joomscan.pl /usr/local/bin/joomscan || true
    else
      mkdir -p "$HOME/.local/joomscan"
      if [[ ! -d "$HOME/.local/joomscan/.git" ]]; then
        git clone https://github.com/rezasp/joomscan.git "$HOME/.local/joomscan" || true
      else
        git -C "$HOME/.local/joomscan" pull || true
      fi
      mkdir -p "$HOME/.local/bin"
      ln -sf "$HOME/.local/joomscan/joomscan.pl" "$HOME/.local/bin/joomscan" || true
    fi
  fi
fi

if ! command_exists jadx; then
  echo "[!] jadx not found in PATH. Install from https://github.com/skylot/jadx/releases or your package manager."
fi

if ! command_exists gatttool; then
  if apt-cache show bluez-tools >/dev/null 2>&1; then
    sudo apt install -y bluez-tools || true
  fi
  if ! command_exists gatttool; then
    echo "[!] gatttool not available; BLE commands may be limited on newer distros."
  fi
fi

echo "[*] Done. Optional: run 'airo getpeas' after generating the package to fetch linPEAS/winPEAS."

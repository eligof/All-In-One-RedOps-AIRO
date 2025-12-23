#!/bin/bash

# ----------------------------
# Color definitions
# ----------------------------
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# ----------------------------
# Global variables
# ----------------------------
UPDATE_CMD=""
INSTALL_CMD=""
REBOOT_NEEDED=false

# ----------------------------
# Function: detect and run update
# ----------------------------
detect_package_manager() {
  if command -v pacman &>/dev/null; then
    UPDATE_CMD="sudo pacman -Syu --noconfirm"
    INSTALL_CMD="sudo pacman -S"
    $UPDATE_CMD > /dev/null 2>&1

  elif command -v apt &>/dev/null; then
    UPDATE_CMD="sudo apt update && sudo apt upgrade -y"
    INSTALL_CMD="sudo apt install -y"
    eval "$UPDATE_CMD" > /dev/null 2>&1

  elif command -v dnf &>/dev/null; then
    UPDATE_CMD="sudo dnf upgrade --refresh -y"
    INSTALL_CMD="sudo dnf install -y"
    $UPDATE_CMD > /dev/null 2>&1

  elif command -v yum &>/dev/null; then
    UPDATE_CMD="sudo yum update -y"
    INSTALL_CMD="sudo yum install -y"
    $UPDATE_CMD > /dev/null 2>&1

  elif command -v zypper &>/dev/null; then
    UPDATE_CMD="sudo zypper refresh && sudo zypper update -y"
    INSTALL_CMD="sudo zypper install -y"
    eval "$UPDATE_CMD" > /dev/null 2>&1

  else
    echo "❌ No supported package manager found."
    exit 1
  fi
}

# ----------------------------
# Function: check if reboot is needed
# ----------------------------
check_reboot_required() {
  CURRENT_KERNEL=$(uname -r)
  INSTALLED_KERNEL=$(find /lib/modules -maxdepth 1 -type d | sed 's|.*/||' | sort -V | tail -n 1)

  if [ "$CURRENT_KERNEL" != "$INSTALLED_KERNEL" ]; then
    REBOOT_NEEDED=true
  fi

  if [ -f /run/reboot-required ] || [ -f /var/run/reboot-required ] || [ -f /run/systemd/reboot-required ]; then
    REBOOT_NEEDED=true
  fi

  if grep -Ei 'upgraded (systemd|glibc|linux)' /var/log/pacman.log 2>/dev/null | tail -n 1 | grep -q "$(date +%Y-%m-%d)"; then
    REBOOT_NEEDED=true
  fi
}

# ----------------------------
# Main execution
# ----------------------------
main() {
  detect_package_manager
  check_reboot_required

  if [ "$REBOOT_NEEDED" = true ]; then
    echo -e "${YELLOW}🔁 System restart is recommended.${NC}"
    if command -v notify-send &>/dev/null; then
      notify-send "🔁 Reboot recommended!" "Reboot is recommended due to core package updates." --icon=system-reboot
    fi
  else
    echo -e "${GREEN}✅ No restart is needed.${NC}"
  fi

  echo -e "Update command used: ${GREEN}$UPDATE_CMD${NC}"
  echo -e "Install example: ${GREEN}$INSTALL_CMD <package>${NC}"
}

main
